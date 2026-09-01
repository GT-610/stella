//! Sequential authenticated control-request serving.

use std::{
    collections::{BTreeMap, BTreeSet},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use stella_common::{NetworkId, NodeId};
use stella_control::{
    ControlError, InboundSequence, MessageBuilder, OutboundSequence, RecordReader, RecordWriter,
};
use stella_crypto::IdentitySigningKey;
use stella_proto::{
    encode_network_revision_list, CodecError, ConnectivityGenerationView, ControlFieldType,
    ControlMessageType, Endpoint, EndpointSetView, MembershipGrantView, NetworkRevision,
    NetworkRevisionListView, ProtocolVersion,
};
use thiserror::Error;
use tokio::{
    net::TcpStream,
    time::{sleep_until, timeout, Instant},
};
use tokio_rustls::server::TlsStream;
use zeroize::Zeroizing;

use crate::{
    authority::{AuthorityError, AuthorityHandle},
    network_state::{encode_network_state, EncodedNetworkState, NetworkStateError},
    runtime::{AcceptedSession, SessionContext},
    session::{authenticate_session, AuthenticatedSession, AuthenticationError},
    store::{AuthorityRevision, BearerToken, MembershipStatus, NetworkRecord, StoreError},
};

const STATUS_OK: u16 = 0;
const STATUS_INVALID_STATE: u16 = 4;
const STATUS_NODE_DISABLED: u16 = 103;
const STATUS_NOT_AUTHORIZED: u16 = 110;
const STATUS_JOIN_TOKEN_INVALID: u16 = 111;
const STATUS_MEMBERSHIP_SUSPENDED: u16 = 112;
const STATUS_NETWORK_NOT_FOUND: u16 = 200;
const STATUS_NETWORK_FULL: u16 = 205;
const STATUS_CONNECTIVITY_GENERATION_INVALID: u16 = 305;
const STATUS_CONNECTIVITY_GENERATION_EXPIRED: u16 = 306;

/// Authenticates and then serves one complete control connection.
///
/// # Errors
///
/// Returns [`ControlSessionError`] when authentication or the active request
/// loop fails.
pub async fn serve_control_session(session: AcceptedSession) -> Result<(), ControlSessionError> {
    let authenticated = authenticate_session(session).await?;
    serve_authenticated_session(authenticated).await?;
    Ok(())
}

/// Serves ordered requests on an already authenticated control connection.
///
/// # Errors
///
/// Returns [`ActiveSessionError`] for timeout, shutdown, framing, protocol,
/// authority, state-encoding, clock, or carrier failure.
pub async fn serve_authenticated_session(
    authenticated: AuthenticatedSession,
) -> Result<(), ActiveSessionError> {
    let (stream, _peer_addr, context, node, protocol_version, inbound, outbound) =
        authenticated.into_parts();
    let mut shutdown = context.shutdown();
    let request_timeout = Duration::from_secs(context.limits().request_timeout_seconds);
    let mut state = ActiveSessionState {
        stream,
        context,
        node_id: node.node_id(),
        protocol_version,
        inbound,
        outbound,
        joined_networks: BTreeSet::new(),
        last_heartbeat: None,
        grant_refreshes: BTreeMap::new(),
    };

    loop {
        let refresh_deadline = state.grant_refreshes.values().min().copied();
        let wake = {
            let mut reader = RecordReader::new(&mut state.stream);
            if let Some(deadline) = refresh_deadline {
                tokio::select! {
                    _ = shutdown.changed() => SessionWake::Shutdown,
                    result = reader.read_message() => SessionWake::Message(result),
                    () = sleep_until(deadline) => SessionWake::GrantRefresh,
                }
            } else {
                tokio::select! {
                    _ = shutdown.changed() => SessionWake::Shutdown,
                    result = reader.read_message() => SessionWake::Message(result),
                }
            }
        };
        match wake {
            SessionWake::Shutdown => {
                send_shutdown(&mut state).await?;
                return Ok(());
            }
            SessionWake::Message(result) => {
                let Some(message) = result? else {
                    return Ok(());
                };
                match timeout(request_timeout, process_request(&mut state, message)).await {
                    Err(_) => return Err(ActiveSessionError::RequestTimeout),
                    Ok(Ok(())) => {}
                    Ok(Err(error)) => return Err(error),
                }
            }
            SessionWake::GrantRefresh => {
                match timeout(request_timeout, refresh_due_grants(&mut state)).await {
                    Err(_) => return Err(ActiveSessionError::RequestTimeout),
                    Ok(Ok(())) => {}
                    Ok(Err(error)) => return Err(error),
                }
            }
        }
    }
}

enum SessionWake {
    Shutdown,
    Message(Result<Option<stella_control::OwnedControlMessage>, ControlError>),
    GrantRefresh,
}

struct ActiveSessionState {
    stream: TlsStream<TcpStream>,
    context: SessionContext,
    node_id: NodeId,
    protocol_version: ProtocolVersion,
    inbound: InboundSequence,
    outbound: OutboundSequence,
    joined_networks: BTreeSet<NetworkId>,
    last_heartbeat: Option<u64>,
    grant_refreshes: BTreeMap<NetworkId, Instant>,
}

async fn process_request(
    state: &mut ActiveSessionState,
    message: stella_control::OwnedControlMessage,
) -> Result<(), ActiveSessionError> {
    let header = message.header()?;
    state.inbound.accept(header.message_id)?;
    if header.version != state.protocol_version {
        send_error(state, header.message_id, STATUS_INVALID_STATE).await?;
        return Err(ActiveSessionError::ProtocolVersionMismatch {
            expected: state.protocol_version,
            actual: header.version,
        });
    }
    if header.correlation_id != 0 {
        send_error(state, header.message_id, STATUS_INVALID_STATE).await?;
        return Err(ActiveSessionError::NonzeroRequestCorrelation {
            actual: header.correlation_id,
        });
    }

    match header.message_type {
        ControlMessageType::JoinRequest => {
            let request = parse_join_request(&message)?;
            handle_join(state, header.message_id, request).await?;
            Ok(())
        }
        ControlMessageType::LeaveRequest => {
            let network_id = parse_network_id(&message)?;
            handle_leave(state, header.message_id, network_id).await?;
            Ok(())
        }
        ControlMessageType::EndpointUpdate => {
            let request = parse_endpoint_update(&message)?;
            handle_endpoint_update(state, header.message_id, request).await?;
            Ok(())
        }
        ControlMessageType::ConnectivityUpdate => {
            let request = parse_connectivity_update(&message)?;
            handle_connectivity_update(state, header.message_id, request).await?;
            Ok(())
        }
        ControlMessageType::SnapshotRequest => {
            let request = parse_snapshot_request(&message)?;
            handle_snapshot_request(state, header.message_id, request).await?;
            Ok(())
        }
        ControlMessageType::Heartbeat => {
            let request = parse_heartbeat(&message)?;
            handle_heartbeat(state, header.message_id, request).await?;
            Ok(())
        }
        actual => {
            send_error(state, header.message_id, STATUS_INVALID_STATE).await?;
            Err(ActiveSessionError::UnexpectedMessage { actual })
        }
    }
}

struct JoinRequest {
    network_id: NetworkId,
    token: Option<Zeroizing<[u8; 32]>>,
}

struct EndpointUpdate {
    network_id: NetworkId,
    endpoints: Vec<Endpoint>,
}

struct ConnectivityUpdate {
    network_id: NetworkId,
    generation: Option<Zeroizing<Vec<u8>>>,
}

struct SnapshotRequest {
    network_id: NetworkId,
    _last_revision: u64,
}

struct HeartbeatRequest {
    counter: u64,
    revisions: Vec<NetworkRevision>,
}

fn parse_join_request(
    message: &stella_control::OwnedControlMessage,
) -> Result<JoinRequest, ActiveSessionError> {
    let view = message.view()?;
    let mut network_id = None;
    let mut token = None;
    for field in view.fields() {
        match field.field_type() {
            Some(ControlFieldType::NetworkId) => {
                network_id = Some(NetworkId::from_bytes(fixed_array(
                    field.value(),
                    "network ID",
                )?));
            }
            Some(ControlFieldType::JoinToken) => {
                token = Some(Zeroizing::new(fixed_array(field.value(), "join token")?));
            }
            _ => {}
        }
    }
    Ok(JoinRequest {
        network_id: network_id.ok_or(ActiveSessionError::ValidatedFieldMissing {
            field: ControlFieldType::NetworkId,
        })?,
        token,
    })
}

fn parse_network_id(
    message: &stella_control::OwnedControlMessage,
) -> Result<NetworkId, ActiveSessionError> {
    for field in message.view()?.fields() {
        if field.field_type() == Some(ControlFieldType::NetworkId) {
            return Ok(NetworkId::from_bytes(fixed_array(
                field.value(),
                "network ID",
            )?));
        }
    }
    Err(ActiveSessionError::ValidatedFieldMissing {
        field: ControlFieldType::NetworkId,
    })
}

fn parse_endpoint_update(
    message: &stella_control::OwnedControlMessage,
) -> Result<EndpointUpdate, ActiveSessionError> {
    let view = message.view()?;
    let mut network_id = None;
    let mut endpoints = None;
    for field in view.fields() {
        match field.field_type() {
            Some(ControlFieldType::NetworkId) => {
                network_id = Some(NetworkId::from_bytes(fixed_array(
                    field.value(),
                    "network ID",
                )?));
            }
            Some(ControlFieldType::EndpointSet) => {
                endpoints = Some(
                    EndpointSetView::decode(field.value())?
                        .endpoints()
                        .collect(),
                );
            }
            _ => {}
        }
    }
    Ok(EndpointUpdate {
        network_id: network_id.ok_or(ActiveSessionError::ValidatedFieldMissing {
            field: ControlFieldType::NetworkId,
        })?,
        endpoints: endpoints.ok_or(ActiveSessionError::ValidatedFieldMissing {
            field: ControlFieldType::EndpointSet,
        })?,
    })
}

fn parse_connectivity_update(
    message: &stella_control::OwnedControlMessage,
) -> Result<ConnectivityUpdate, ActiveSessionError> {
    let view = message.view()?;
    let mut network_id = None;
    let mut generation = None;
    for field in view.fields() {
        match field.field_type() {
            Some(ControlFieldType::NetworkId) => {
                network_id = Some(NetworkId::from_bytes(fixed_array(
                    field.value(),
                    "network ID",
                )?));
            }
            Some(ControlFieldType::ConnectivityGeneration) => {
                ConnectivityGenerationView::decode(field.value())?;
                generation = Some(Zeroizing::new(field.value().to_vec()));
            }
            _ => {}
        }
    }
    Ok(ConnectivityUpdate {
        network_id: network_id.ok_or(ActiveSessionError::ValidatedFieldMissing {
            field: ControlFieldType::NetworkId,
        })?,
        generation,
    })
}

fn parse_snapshot_request(
    message: &stella_control::OwnedControlMessage,
) -> Result<SnapshotRequest, ActiveSessionError> {
    let view = message.view()?;
    let mut network_id = None;
    let mut last_revision = None;
    for field in view.fields() {
        match field.field_type() {
            Some(ControlFieldType::NetworkId) => {
                network_id = Some(NetworkId::from_bytes(fixed_array(
                    field.value(),
                    "network ID",
                )?));
            }
            Some(ControlFieldType::SnapshotRevision) => {
                last_revision = Some(u64::from_be_bytes(fixed_array(
                    field.value(),
                    "snapshot revision",
                )?));
            }
            _ => {}
        }
    }
    Ok(SnapshotRequest {
        network_id: network_id.ok_or(ActiveSessionError::ValidatedFieldMissing {
            field: ControlFieldType::NetworkId,
        })?,
        _last_revision: last_revision.ok_or(ActiveSessionError::ValidatedFieldMissing {
            field: ControlFieldType::SnapshotRevision,
        })?,
    })
}

fn parse_heartbeat(
    message: &stella_control::OwnedControlMessage,
) -> Result<HeartbeatRequest, ActiveSessionError> {
    let view = message.view()?;
    let mut counter = None;
    let mut revisions = None;
    for field in view.fields() {
        match field.field_type() {
            Some(ControlFieldType::HeartbeatCounter) => {
                counter = Some(u64::from_be_bytes(fixed_array(
                    field.value(),
                    "heartbeat counter",
                )?));
            }
            Some(ControlFieldType::NetworkRevisions) => {
                revisions = Some(
                    NetworkRevisionListView::decode(field.value())?
                        .revisions()
                        .collect(),
                );
            }
            _ => {}
        }
    }
    Ok(HeartbeatRequest {
        counter: counter.ok_or(ActiveSessionError::ValidatedFieldMissing {
            field: ControlFieldType::HeartbeatCounter,
        })?,
        revisions: revisions.ok_or(ActiveSessionError::ValidatedFieldMissing {
            field: ControlFieldType::NetworkRevisions,
        })?,
    })
}

async fn handle_join(
    state: &mut ActiveSessionState,
    correlation_id: u64,
    request: JoinRequest,
) -> Result<(), ActiveSessionError> {
    match resolve_join(
        state.context.authority(),
        state.context.controller_identity(),
        state.node_id,
        request,
        unix_time()?,
        state.protocol_version,
    )
    .await?
    {
        JoinDecision::Accepted(encoded) => {
            send_join_result(state, correlation_id, STATUS_OK, &encoded).await?;
            send_peer_snapshot(state, 0, &encoded).await?;
            state.joined_networks.insert(encoded.network_id());
        }
        JoinDecision::Rejected {
            network,
            status,
            close,
        } => {
            send_join_rejection(state, correlation_id, status, &network).await?;
            if close {
                shutdown_writer(&mut state.stream).await?;
                return Err(ActiveSessionError::AuthorizationRevoked { status });
            }
        }
        JoinDecision::NetworkNotFound => {
            send_error(state, correlation_id, STATUS_NETWORK_NOT_FOUND).await?;
        }
    }
    Ok(())
}

enum JoinDecision {
    Accepted(Box<EncodedNetworkState>),
    Rejected {
        network: NetworkRecord,
        status: u16,
        close: bool,
    },
    NetworkNotFound,
}

async fn resolve_join(
    authority: &AuthorityHandle,
    controller_identity: &IdentitySigningKey,
    node_id: NodeId,
    request: JoinRequest,
    now: u64,
    version: ProtocolVersion,
) -> Result<JoinDecision, ActiveSessionError> {
    let Some(network) = authority.get_network(request.network_id).await? else {
        return Ok(JoinDecision::NetworkNotFound);
    };
    match authority
        .get_membership(node_id, request.network_id)
        .await?
    {
        Some(membership) if membership.status() == MembershipStatus::Active => {}
        Some(_) => {
            return Ok(JoinDecision::Rejected {
                network,
                status: STATUS_MEMBERSHIP_SUSPENDED,
                close: false,
            });
        }
        None => {
            let Some(raw_token) = request.token else {
                return Ok(JoinDecision::Rejected {
                    network,
                    status: STATUS_JOIN_TOKEN_INVALID,
                    close: false,
                });
            };
            let Ok(token) = BearerToken::from_bytes(*raw_token) else {
                return Ok(JoinDecision::Rejected {
                    network,
                    status: STATUS_JOIN_TOKEN_INVALID,
                    close: false,
                });
            };
            if let Err(error) = authority
                .join_with_token(&token, node_id, request.network_id, now)
                .await
            {
                return map_join_authority_error(error, network);
            }
        }
    }

    let view = authority
        .network_session_view(node_id, request.network_id)
        .await?;
    Ok(JoinDecision::Accepted(Box::new(encode_network_state(
        controller_identity,
        &view,
        now,
        version,
    )?)))
}

fn map_join_authority_error(
    error: AuthorityError,
    network: NetworkRecord,
) -> Result<JoinDecision, ActiveSessionError> {
    let decision = match &error {
        AuthorityError::Store(source) => match source.as_ref() {
            StoreError::InvalidBearerToken | StoreError::JoinTokenInvalid => {
                Some((STATUS_JOIN_TOKEN_INVALID, false))
            }
            StoreError::MembershipSuspended { .. } => Some((STATUS_MEMBERSHIP_SUSPENDED, false)),
            StoreError::NetworkFull { .. } => Some((STATUS_NETWORK_FULL, false)),
            StoreError::NodeDisabled { .. } => Some((STATUS_NODE_DISABLED, true)),
            _ => None,
        },
        _ => None,
    };
    if let Some((status, close)) = decision {
        Ok(JoinDecision::Rejected {
            network,
            status,
            close,
        })
    } else {
        Err(ActiveSessionError::Authority(error))
    }
}

async fn handle_leave(
    state: &mut ActiveSessionState,
    correlation_id: u64,
    network_id: NetworkId,
) -> Result<(), ActiveSessionError> {
    match resolve_leave(state.context.authority(), state.node_id, network_id).await? {
        LeaveDecision::Left(revision) => {
            send_leave_result(state, correlation_id, &revision).await?;
            forget_network(state, network_id);
        }
        LeaveDecision::NetworkNotFound => {
            forget_network(state, network_id);
            send_error(state, correlation_id, STATUS_NETWORK_NOT_FOUND).await?;
        }
    }
    Ok(())
}

enum LeaveDecision {
    Left(AuthorityRevision),
    NetworkNotFound,
}

async fn resolve_leave(
    authority: &AuthorityHandle,
    node_id: NodeId,
    network_id: NetworkId,
) -> Result<LeaveDecision, ActiveSessionError> {
    if authority.get_network(network_id).await?.is_none() {
        return Ok(LeaveDecision::NetworkNotFound);
    }
    Ok(LeaveDecision::Left(
        authority.leave_network(node_id, network_id).await?,
    ))
}

async fn handle_endpoint_update(
    state: &mut ActiveSessionState,
    correlation_id: u64,
    request: EndpointUpdate,
) -> Result<(), ActiveSessionError> {
    require_joined(state, correlation_id, request.network_id).await?;
    let network_id = request.network_id;
    match resolve_endpoint_update(
        state.context.authority(),
        state.node_id,
        request,
        unix_time()?,
    )
    .await?
    {
        EndpointDecision::Accepted(revision) => {
            send_endpoint_result(state, correlation_id, STATUS_OK, &revision).await?;
        }
        EndpointDecision::Rejected {
            revision,
            status,
            close,
        } => {
            forget_network(state, revision.network_id);
            send_endpoint_result(state, correlation_id, status, &revision).await?;
            if close {
                shutdown_writer(&mut state.stream).await?;
                return Err(ActiveSessionError::AuthorizationRevoked { status });
            }
        }
        EndpointDecision::NetworkNotFound => {
            forget_network(state, network_id);
            send_error(state, correlation_id, STATUS_NETWORK_NOT_FOUND).await?;
        }
    }
    Ok(())
}

enum EndpointDecision {
    Accepted(AuthorityRevision),
    Rejected {
        revision: AuthorityRevision,
        status: u16,
        close: bool,
    },
    NetworkNotFound,
}

async fn resolve_endpoint_update(
    authority: &AuthorityHandle,
    node_id: NodeId,
    request: EndpointUpdate,
    now: u64,
) -> Result<EndpointDecision, ActiveSessionError> {
    let Some(network) = authority.get_network(request.network_id).await? else {
        return Ok(EndpointDecision::NetworkNotFound);
    };
    match authority
        .publish_endpoints(node_id, request.network_id, request.endpoints, now)
        .await
    {
        Ok(revision) => Ok(EndpointDecision::Accepted(revision)),
        Err(error) => {
            if matches!(
                &error,
                AuthorityError::Store(source)
                    if matches!(source.as_ref(), StoreError::NetworkNotFound { .. })
            ) {
                return Ok(EndpointDecision::NetworkNotFound);
            }
            let Some((status, close)) = classify_authorization_error(&error) else {
                return Err(ActiveSessionError::Authority(error));
            };
            Ok(EndpointDecision::Rejected {
                revision: AuthorityRevision {
                    controller_epoch: network.controller_epoch(),
                    network_id: network.network_id(),
                    snapshot_revision: network.snapshot_revision(),
                },
                status,
                close,
            })
        }
    }
}

async fn handle_snapshot_request(
    state: &mut ActiveSessionState,
    correlation_id: u64,
    request: SnapshotRequest,
) -> Result<(), ActiveSessionError> {
    require_joined(state, correlation_id, request.network_id).await?;
    let view = match state
        .context
        .authority()
        .network_session_view(state.node_id, request.network_id)
        .await
    {
        Ok(view) => view,
        Err(error) => {
            let (status, close) = if matches!(
                &error,
                AuthorityError::Store(source)
                    if matches!(source.as_ref(), StoreError::NetworkNotFound { .. })
            ) {
                (STATUS_NETWORK_NOT_FOUND, false)
            } else if let Some(classified) = classify_authorization_error(&error) {
                classified
            } else {
                return Err(ActiveSessionError::Authority(error));
            };
            forget_network(state, request.network_id);
            send_error(state, correlation_id, status).await?;
            if close {
                shutdown_writer(&mut state.stream).await?;
                return Err(ActiveSessionError::AuthorizationRevoked { status });
            }
            return Ok(());
        }
    };
    let encoded = encode_network_state(
        state.context.controller_identity(),
        &view,
        unix_time()?,
        state.protocol_version,
    )?;
    send_peer_snapshot(state, correlation_id, &encoded).await
}

async fn handle_connectivity_update(
    state: &mut ActiveSessionState,
    correlation_id: u64,
    request: ConnectivityUpdate,
) -> Result<(), ActiveSessionError> {
    require_joined(state, correlation_id, request.network_id).await?;
    let network_id = request.network_id;
    match resolve_connectivity_update(
        state.context.authority(),
        state.node_id,
        request,
        unix_time()?,
    )
    .await?
    {
        ConnectivityDecision::Accepted(revision) => {
            send_connectivity_result(state, correlation_id, STATUS_OK, &revision).await?;
        }
        ConnectivityDecision::Rejected {
            revision,
            status,
            forget,
            close,
        } => {
            if forget {
                forget_network(state, revision.network_id);
            }
            send_connectivity_result(state, correlation_id, status, &revision).await?;
            if close {
                shutdown_writer(&mut state.stream).await?;
                return Err(ActiveSessionError::AuthorizationRevoked { status });
            }
        }
        ConnectivityDecision::NetworkNotFound => {
            forget_network(state, network_id);
            send_error(state, correlation_id, STATUS_NETWORK_NOT_FOUND).await?;
        }
    }
    Ok(())
}

enum ConnectivityDecision {
    Accepted(AuthorityRevision),
    Rejected {
        revision: AuthorityRevision,
        status: u16,
        forget: bool,
        close: bool,
    },
    NetworkNotFound,
}

async fn resolve_connectivity_update(
    authority: &AuthorityHandle,
    node_id: NodeId,
    request: ConnectivityUpdate,
    now: u64,
) -> Result<ConnectivityDecision, ActiveSessionError> {
    let Some(network) = authority.get_network(request.network_id).await? else {
        return Ok(ConnectivityDecision::NetworkNotFound);
    };
    let result = match request.generation {
        Some(generation) => {
            authority
                .publish_connectivity(node_id, request.network_id, generation, now)
                .await
        }
        None => {
            authority
                .withdraw_connectivity(node_id, request.network_id, now)
                .await
        }
    };
    match result {
        Ok(revision) => Ok(ConnectivityDecision::Accepted(revision)),
        Err(error) => {
            if matches!(
                &error,
                AuthorityError::Store(source)
                    if matches!(source.as_ref(), StoreError::NetworkNotFound { .. })
            ) {
                return Ok(ConnectivityDecision::NetworkNotFound);
            }
            let classified = match &error {
                AuthorityError::Store(source) => match source.as_ref() {
                    StoreError::Codec(_) => {
                        Some((STATUS_CONNECTIVITY_GENERATION_INVALID, false, false))
                    }
                    StoreError::ConnectivityGenerationExpired { .. } => {
                        Some((STATUS_CONNECTIVITY_GENERATION_EXPIRED, false, false))
                    }
                    _ => classify_authorization_error(&error)
                        .map(|(status, close)| (status, true, close)),
                },
                _ => None,
            };
            let Some((status, forget, close)) = classified else {
                return Err(ActiveSessionError::Authority(error));
            };
            Ok(ConnectivityDecision::Rejected {
                revision: AuthorityRevision {
                    controller_epoch: network.controller_epoch(),
                    network_id: network.network_id(),
                    snapshot_revision: network.snapshot_revision(),
                },
                status,
                forget,
                close,
            })
        }
    }
}

async fn handle_heartbeat(
    state: &mut ActiveSessionState,
    correlation_id: u64,
    request: HeartbeatRequest,
) -> Result<(), ActiveSessionError> {
    let counter_valid = match state.last_heartbeat {
        None => request.counter == 1,
        Some(previous) => previous.checked_add(1) == Some(request.counter),
    };
    if !counter_valid {
        send_error(state, correlation_id, STATUS_INVALID_STATE).await?;
        return Err(ActiveSessionError::HeartbeatCounterInvalid {
            previous: state.last_heartbeat,
            actual: request.counter,
        });
    }
    if let Some(unjoined) = request
        .revisions
        .iter()
        .find(|revision| !state.joined_networks.contains(&revision.network_id))
    {
        require_joined(state, correlation_id, unjoined.network_id).await?;
    }
    state.last_heartbeat = Some(request.counter);

    let authority = state.context.authority().clone();
    let joined_networks = state.joined_networks.iter().copied().collect::<Vec<_>>();
    let now = unix_time()?;
    let mut revisions = Vec::new();
    let mut snapshots = Vec::new();
    for network_id in joined_networks {
        let view = match authority
            .network_session_view(state.node_id, network_id)
            .await
        {
            Ok(view) => view,
            Err(error) => {
                handle_network_authority_failure(state, correlation_id, network_id, error).await?;
                return Ok(());
            }
        };
        if authority
            .get_endpoints(state.node_id, network_id)
            .await?
            .is_some()
        {
            if let Err(error) = authority
                .refresh_endpoint_lease(state.node_id, network_id, now)
                .await
            {
                handle_network_authority_failure(state, correlation_id, network_id, error).await?;
                return Ok(());
            }
        }
        let revision = NetworkRevision {
            network_id,
            controller_epoch: view.network().controller_epoch(),
            snapshot_revision: view.network().snapshot_revision(),
        };
        let client_current = request
            .revisions
            .iter()
            .any(|candidate| candidate == &revision);
        if !client_current {
            snapshots.push(encode_network_state(
                state.context.controller_identity(),
                &view,
                now,
                state.protocol_version,
            )?);
        }
        revisions.push(revision);
    }

    send_heartbeat_ack(state, correlation_id, request.counter, &revisions, now).await?;
    for snapshot in &snapshots {
        send_peer_snapshot(state, 0, snapshot).await?;
    }
    Ok(())
}

async fn refresh_due_grants(state: &mut ActiveSessionState) -> Result<(), ActiveSessionError> {
    let current = Instant::now();
    let due_networks = state
        .grant_refreshes
        .iter()
        .filter_map(|(network_id, deadline)| (*deadline <= current).then_some(*network_id))
        .collect::<Vec<_>>();
    let authority = state.context.authority().clone();
    let now = unix_time()?;
    for network_id in due_networks {
        let view = match authority
            .network_session_view(state.node_id, network_id)
            .await
        {
            Ok(view) => view,
            Err(error) => {
                handle_network_authority_failure(state, 0, network_id, error).await?;
                continue;
            }
        };
        let encoded = encode_network_state(
            state.context.controller_identity(),
            &view,
            now,
            state.protocol_version,
        )?;
        send_grant_refresh(state, &encoded).await?;
    }
    Ok(())
}

async fn handle_network_authority_failure(
    state: &mut ActiveSessionState,
    correlation_id: u64,
    network_id: NetworkId,
    error: AuthorityError,
) -> Result<(), ActiveSessionError> {
    let (status, close) = if matches!(
        &error,
        AuthorityError::Store(source)
            if matches!(source.as_ref(), StoreError::NetworkNotFound { .. })
    ) {
        (STATUS_NETWORK_NOT_FOUND, false)
    } else if let Some(classified) = classify_authorization_error(&error) {
        classified
    } else {
        return Err(ActiveSessionError::Authority(error));
    };
    forget_network(state, network_id);
    send_error(state, correlation_id, status).await?;
    if close {
        shutdown_writer(&mut state.stream).await?;
        return Err(ActiveSessionError::AuthorizationRevoked { status });
    }
    Ok(())
}

async fn require_joined(
    state: &mut ActiveSessionState,
    correlation_id: u64,
    network_id: NetworkId,
) -> Result<(), ActiveSessionError> {
    if state.joined_networks.contains(&network_id) {
        return Ok(());
    }
    send_error(state, correlation_id, STATUS_INVALID_STATE).await?;
    Err(ActiveSessionError::NetworkNotJoined { network_id })
}

fn forget_network(state: &mut ActiveSessionState, network_id: NetworkId) {
    state.joined_networks.remove(&network_id);
    state.grant_refreshes.remove(&network_id);
}

fn classify_authorization_error(error: &AuthorityError) -> Option<(u16, bool)> {
    match error {
        AuthorityError::Store(source) => match source.as_ref() {
            StoreError::NodeDisabled { .. } => Some((STATUS_NODE_DISABLED, true)),
            StoreError::MembershipNotFound { .. } => Some((STATUS_NOT_AUTHORIZED, false)),
            StoreError::MembershipSuspended { .. } => Some((STATUS_MEMBERSHIP_SUSPENDED, false)),
            _ => None,
        },
        _ => None,
    }
}

async fn send_join_result(
    state: &mut ActiveSessionState,
    correlation_id: u64,
    status: u16,
    encoded: &EncodedNetworkState,
) -> Result<(), ActiveSessionError> {
    let mut builder =
        MessageBuilder::new(ControlMessageType::JoinResult).with_correlation(correlation_id);
    builder.push_field(ControlFieldType::StatusCode, &status.to_be_bytes())?;
    builder.push_field(
        ControlFieldType::ControllerEpoch,
        &encoded.controller_epoch().to_be_bytes(),
    )?;
    builder.push_field(ControlFieldType::NetworkId, encoded.network_id().as_bytes())?;
    builder.push_field(ControlFieldType::MembershipGrant, encoded.local_grant())?;
    builder.push_field(ControlFieldType::NetworkPolicy, encoded.policy())?;
    builder.push_field(
        ControlFieldType::SnapshotRevision,
        &encoded.snapshot_revision().to_be_bytes(),
    )?;
    write_message(state, builder).await
}

async fn send_join_rejection(
    state: &mut ActiveSessionState,
    correlation_id: u64,
    status: u16,
    network: &NetworkRecord,
) -> Result<(), ActiveSessionError> {
    let mut builder =
        MessageBuilder::new(ControlMessageType::JoinResult).with_correlation(correlation_id);
    builder.push_field(ControlFieldType::StatusCode, &status.to_be_bytes())?;
    builder.push_field(
        ControlFieldType::ControllerEpoch,
        &network.controller_epoch().to_be_bytes(),
    )?;
    builder.push_field(ControlFieldType::NetworkId, network.network_id().as_bytes())?;
    write_message(state, builder).await
}

async fn send_peer_snapshot(
    state: &mut ActiveSessionState,
    correlation_id: u64,
    encoded: &EncodedNetworkState,
) -> Result<(), ActiveSessionError> {
    let mut builder =
        MessageBuilder::new(ControlMessageType::PeerSnapshot).with_correlation(correlation_id);
    builder.push_field(
        ControlFieldType::ControllerEpoch,
        &encoded.controller_epoch().to_be_bytes(),
    )?;
    builder.push_field(ControlFieldType::NetworkId, encoded.network_id().as_bytes())?;
    builder.push_field(ControlFieldType::MembershipGrant, encoded.local_grant())?;
    builder.push_field(ControlFieldType::NetworkPolicy, encoded.policy())?;
    builder.push_field(
        ControlFieldType::SnapshotRevision,
        &encoded.snapshot_revision().to_be_bytes(),
    )?;
    builder.push_field(ControlFieldType::PeerList, encoded.peer_list())?;
    if let Some(connectivity_list) = encoded.connectivity_list() {
        builder.push_field(ControlFieldType::ConnectivityList, connectivity_list)?;
    }
    write_message(state, builder).await?;
    schedule_grant_refresh(state, encoded)
}

async fn send_endpoint_result(
    state: &mut ActiveSessionState,
    correlation_id: u64,
    status: u16,
    revision: &AuthorityRevision,
) -> Result<(), ActiveSessionError> {
    let mut builder =
        MessageBuilder::new(ControlMessageType::EndpointResult).with_correlation(correlation_id);
    builder.push_field(ControlFieldType::StatusCode, &status.to_be_bytes())?;
    builder.push_field(
        ControlFieldType::ControllerEpoch,
        &revision.controller_epoch.to_be_bytes(),
    )?;
    builder.push_field(ControlFieldType::NetworkId, revision.network_id.as_bytes())?;
    builder.push_field(
        ControlFieldType::SnapshotRevision,
        &revision.snapshot_revision.to_be_bytes(),
    )?;
    write_message(state, builder).await
}

async fn send_connectivity_result(
    state: &mut ActiveSessionState,
    correlation_id: u64,
    status: u16,
    revision: &AuthorityRevision,
) -> Result<(), ActiveSessionError> {
    let mut builder = MessageBuilder::new(ControlMessageType::ConnectivityResult)
        .with_correlation(correlation_id);
    builder.push_field(ControlFieldType::StatusCode, &status.to_be_bytes())?;
    builder.push_field(
        ControlFieldType::ControllerEpoch,
        &revision.controller_epoch.to_be_bytes(),
    )?;
    builder.push_field(ControlFieldType::NetworkId, revision.network_id.as_bytes())?;
    builder.push_field(
        ControlFieldType::SnapshotRevision,
        &revision.snapshot_revision.to_be_bytes(),
    )?;
    write_message(state, builder).await
}

async fn send_heartbeat_ack(
    state: &mut ActiveSessionState,
    correlation_id: u64,
    counter: u64,
    revisions: &[NetworkRevision],
    server_time: u64,
) -> Result<(), ActiveSessionError> {
    let mut encoded = [0_u8; 4 + 32 * 256];
    let encoded_length = encode_network_revision_list(revisions, &mut encoded)?;
    let mut builder =
        MessageBuilder::new(ControlMessageType::HeartbeatAck).with_correlation(correlation_id);
    builder.push_field(ControlFieldType::HeartbeatCounter, &counter.to_be_bytes())?;
    builder.push_field(
        ControlFieldType::NetworkRevisions,
        &encoded[..encoded_length],
    )?;
    builder.push_field(ControlFieldType::ServerTime, &server_time.to_be_bytes())?;
    write_message(state, builder).await
}

async fn send_grant_refresh(
    state: &mut ActiveSessionState,
    encoded: &EncodedNetworkState,
) -> Result<(), ActiveSessionError> {
    let mut builder = MessageBuilder::new(ControlMessageType::GrantRefresh);
    builder.push_field(
        ControlFieldType::ControllerEpoch,
        &encoded.controller_epoch().to_be_bytes(),
    )?;
    builder.push_field(ControlFieldType::NetworkId, encoded.network_id().as_bytes())?;
    builder.push_field(ControlFieldType::MembershipGrant, encoded.local_grant())?;
    builder.push_field(ControlFieldType::NetworkPolicy, encoded.policy())?;
    builder.push_field(
        ControlFieldType::SnapshotRevision,
        &encoded.snapshot_revision().to_be_bytes(),
    )?;
    write_message(state, builder).await?;
    schedule_grant_refresh(state, encoded)
}

fn schedule_grant_refresh(
    state: &mut ActiveSessionState,
    encoded: &EncodedNetworkState,
) -> Result<(), ActiveSessionError> {
    let delay = grant_refresh_delay(encoded)?;
    let deadline = Instant::now()
        .checked_add(delay)
        .ok_or(ActiveSessionError::GrantRefreshDeadlineOverflow)?;
    state.grant_refreshes.insert(encoded.network_id(), deadline);
    Ok(())
}

fn grant_refresh_delay(encoded: &EncodedNetworkState) -> Result<Duration, ActiveSessionError> {
    let grant = MembershipGrantView::decode(encoded.local_grant())?.grant();
    let lifetime = grant
        .not_after
        .checked_sub(grant.not_before)
        .ok_or(ActiveSessionError::GrantLifetimeInvalid)?;
    Ok(Duration::from_secs(lifetime / 2))
}

async fn send_leave_result(
    state: &mut ActiveSessionState,
    correlation_id: u64,
    revision: &AuthorityRevision,
) -> Result<(), ActiveSessionError> {
    let mut builder =
        MessageBuilder::new(ControlMessageType::LeaveResult).with_correlation(correlation_id);
    builder.push_field(ControlFieldType::StatusCode, &STATUS_OK.to_be_bytes())?;
    builder.push_field(
        ControlFieldType::ControllerEpoch,
        &revision.controller_epoch.to_be_bytes(),
    )?;
    builder.push_field(ControlFieldType::NetworkId, revision.network_id.as_bytes())?;
    write_message(state, builder).await
}

async fn send_error(
    state: &mut ActiveSessionState,
    correlation_id: u64,
    status: u16,
) -> Result<(), ActiveSessionError> {
    let mut builder =
        MessageBuilder::new(ControlMessageType::Error).with_correlation(correlation_id);
    builder.push_field(ControlFieldType::StatusCode, &status.to_be_bytes())?;
    write_message(state, builder).await
}

async fn send_shutdown(state: &mut ActiveSessionState) -> Result<(), ActiveSessionError> {
    let deadline = unix_time()?
        .checked_add(state.context.limits().shutdown_timeout_seconds)
        .ok_or(ActiveSessionError::TimeOverflow)?;
    let mut builder = MessageBuilder::new(ControlMessageType::ServerShutdown);
    builder.push_field(ControlFieldType::ShutdownDeadline, &deadline.to_be_bytes())?;
    write_message(state, builder).await?;
    shutdown_writer(&mut state.stream).await
}

async fn write_message(
    state: &mut ActiveSessionState,
    builder: MessageBuilder,
) -> Result<(), ActiveSessionError> {
    let message = state
        .outbound
        .build(builder.with_version(state.protocol_version))?;
    let mut writer = RecordWriter::new(&mut state.stream);
    writer.write_message(&message).await?;
    writer.flush().await?;
    Ok(())
}

async fn shutdown_writer(stream: &mut TlsStream<TcpStream>) -> Result<(), ActiveSessionError> {
    RecordWriter::new(stream).shutdown().await?;
    Ok(())
}

fn fixed_array<const N: usize>(
    value: &[u8],
    field: &'static str,
) -> Result<[u8; N], ActiveSessionError> {
    value
        .try_into()
        .map_err(|_| ActiveSessionError::ValidatedLengthInvalid {
            field,
            expected: N,
            actual: value.len(),
        })
}

fn unix_time() -> Result<u64, ActiveSessionError> {
    Ok(SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| ActiveSessionError::ClockBeforeUnixEpoch)?
        .as_secs())
}

/// Complete authentication or active-loop failure.
#[derive(Debug, Error)]
pub enum ControlSessionError {
    /// Stella node authentication failed.
    #[error(transparent)]
    Authentication(#[from] AuthenticationError),
    /// An authenticated request or orderly shutdown failed.
    #[error(transparent)]
    Active(#[from] ActiveSessionError),
}

/// Failure while serving authenticated control requests.
#[derive(Debug, Error)]
pub enum ActiveSessionError {
    /// One request did not complete within the configured deadline.
    #[error("authenticated control request timed out")]
    RequestTimeout,
    /// Control framing, sequence, construction, or carrier I/O failed.
    #[error(transparent)]
    Control(#[from] ControlError),
    /// A codec-validated nested value could not be reconstructed.
    #[error(transparent)]
    Codec(#[from] CodecError),
    /// The serialized authority rejected or failed an operation.
    #[error(transparent)]
    Authority(#[from] AuthorityError),
    /// Coherent grants, policy, or peer-list state could not be encoded.
    #[error(transparent)]
    NetworkState(#[from] NetworkStateError),
    /// A client request incorrectly carried a response correlation.
    #[error("client request correlation ID must be zero, received {actual}")]
    NonzeroRequestCorrelation {
        /// Invalid request correlation ID.
        actual: u64,
    },
    /// A message type is not valid in the current active implementation.
    #[error("unexpected authenticated control message {actual:?}")]
    UnexpectedMessage {
        /// Received message type.
        actual: ControlMessageType,
    },
    /// An authenticated message changed version after negotiation.
    #[error("expected control version {expected:?}, received {actual:?}")]
    ProtocolVersionMismatch {
        /// Version selected during authentication.
        expected: ProtocolVersion,
        /// Version found in the active message header.
        actual: ProtocolVersion,
    },
    /// A request referred to a network not joined on this TLS connection.
    #[error("network {network_id} is not joined on this authenticated connection")]
    NetworkNotJoined {
        /// Network rejected by the session state machine.
        network_id: NetworkId,
    },
    /// The client heartbeat counter did not start at one or increment by one.
    #[error("heartbeat counter {actual} does not follow previous value {previous:?}")]
    HeartbeatCounterInvalid {
        /// Last accepted counter, or `None` before the first heartbeat.
        previous: Option<u64>,
        /// Invalid received counter.
        actual: u64,
    },
    /// A decoded grant unexpectedly had an inverted validity interval.
    #[error("validated membership grant lifetime is invalid")]
    GrantLifetimeInvalid,
    /// The monotonic clock could not represent the next refresh deadline.
    #[error("membership grant refresh deadline overflows monotonic time")]
    GrantRefreshDeadlineOverflow,
    /// A codec-validated message unexpectedly lacked a required field.
    #[error("validated control message is missing required field {field:?}")]
    ValidatedFieldMissing {
        /// Field required by the codec schema.
        field: ControlFieldType,
    },
    /// A codec-validated fixed-width field unexpectedly had another length.
    #[error("validated {field} length is {actual}, expected {expected}")]
    ValidatedLengthInvalid {
        /// Stable field name.
        field: &'static str,
        /// Required byte length.
        expected: usize,
        /// Observed byte length.
        actual: usize,
    },
    /// Administrative revocation requires this authenticated connection close.
    #[error("authenticated authorization was revoked with status {status}")]
    AuthorizationRevoked {
        /// Status already sent to the client.
        status: u16,
    },
    /// The host wall clock is earlier than the Unix epoch.
    #[error("system clock is before the Unix epoch")]
    ClockBeforeUnixEpoch,
    /// A shutdown deadline could not be represented.
    #[error("controller shutdown deadline overflows Unix time")]
    TimeOverflow,
}

#[cfg(test)]
mod tests {
    use std::{
        net::Ipv4Addr,
        num::NonZeroUsize,
        path::PathBuf,
        sync::atomic::{AtomicU64, Ordering},
        time::Duration,
    };

    use stella_common::{ControllerId, NetworkId};
    use stella_crypto::{derive_controller_id, IdentitySeed, IdentitySigningKey};
    use stella_proto::{
        encode_connectivity_generation, ConfidentialityPolicy, ConnectivityCarrier,
        ConnectivityGenerationRef, Endpoint, IceCandidate, IceCandidateClass, NetworkPolicy,
        ProtocolVersion,
    };
    use zeroize::Zeroizing;

    use super::{
        grant_refresh_delay, resolve_connectivity_update, resolve_endpoint_update, resolve_join,
        resolve_leave, ConnectivityDecision, ConnectivityUpdate, EndpointDecision, EndpointUpdate,
        JoinDecision, JoinRequest, LeaveDecision,
    };
    use crate::{
        authority::AuthorityThread,
        store::{AuthorityStore, BearerToken, MembershipStatus, NetworkRecord, NodeRecord},
    };

    static TEMP_SEQUENCE: AtomicU64 = AtomicU64::new(1);

    fn signing_key(seed: u8) -> IdentitySigningKey {
        IdentitySigningKey::from_seed(&IdentitySeed::from_bytes([seed; 32]))
    }

    fn network_policy(network_id: NetworkId) -> NetworkPolicy {
        NetworkPolicy {
            confidentiality: ConfidentialityPolicy::Encrypt,
            max_frame_size: 1_514,
            max_flood_peers: 8,
            flood_rate: 1_000,
            flood_burst: 2_000,
            mac_age_seconds: 300,
            heartbeat_seconds: 10,
            peer_lease_seconds: 30,
            session_lifetime_seconds: 900,
            reassembly_timeout_ms: 3_000,
            network_id,
            policy_revision: 1,
        }
    }

    fn connectivity_generation(generation_id: u64, created_at: u64) -> Vec<u8> {
        let candidates = [IceCandidate {
            class: IceCandidateClass::Host,
            carrier: ConnectivityCarrier::DirectUdp,
            priority: u32::MAX - 1,
            foundation: 1,
            max_datagram_size: 1_200,
            address: "192.0.2.10:4242".parse().expect("candidate address"),
            related_address: None,
            relay_id: None,
        }];
        let generation = ConnectivityGenerationRef::new(
            generation_id,
            generation_id + 100,
            created_at,
            created_at + 600,
            b"Abcd1234",
            b"Abcdefghijklmnopqrstuv",
            &candidates,
        )
        .expect("valid connectivity generation");
        let mut encoded = vec![0; generation.encoded_len().expect("generation length")];
        encode_connectivity_generation(generation, &mut encoded).expect("encode generation");
        encoded
    }

    #[allow(clippy::too_many_lines)]
    #[tokio::test(flavor = "current_thread")]
    async fn join_is_token_gated_idempotent_and_leave_is_repeatable() {
        let sequence = TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        let directory: PathBuf = std::env::temp_dir().join(format!(
            "stella-active-session-{}-{sequence}",
            std::process::id()
        ));
        std::fs::create_dir(&directory).expect("create test directory");
        let controller = signing_key(101);
        let controller_id: ControllerId = derive_controller_id(controller.public_key());
        let store = AuthorityStore::initialize(&directory.join("controller.redb"), controller_id)
            .expect("initialize authority store");
        let node =
            NodeRecord::new(signing_key(102).public_key(), "Active node", 100).expect("valid node");
        let node_id = node.node_id();
        store.create_node(&node).expect("create node");
        let network_id = NetworkId::from_bytes([103; 16]);
        store
            .create_network(
                &NetworkRecord::new(network_policy(network_id), "Active LAN", 100)
                    .expect("valid network"),
            )
            .expect("create network");
        let token = store
            .issue_join_token(network_id, 100, 1_000)
            .expect("issue join token");
        let token_bytes = *token.expose_secret();
        drop(store);
        let worker = AuthorityThread::spawn(
            AuthorityStore::open(&directory.join("controller.redb"), controller_id)
                .expect("reopen authority store"),
            NonZeroUsize::new(8).expect("non-zero queue"),
        )
        .expect("spawn authority thread");
        let authority = worker.handle();

        assert!(matches!(
            resolve_join(
                &authority,
                &controller,
                node_id,
                JoinRequest {
                    network_id,
                    token: None,
                },
                200,
                ProtocolVersion::V0_1,
            )
            .await
            .expect("resolve missing token"),
            JoinDecision::Rejected { status: 111, .. }
        ));
        let accepted = resolve_join(
            &authority,
            &controller,
            node_id,
            JoinRequest {
                network_id,
                token: Some(Zeroizing::new(token_bytes)),
            },
            200,
            ProtocolVersion::V0_1,
        )
        .await
        .expect("resolve valid join");
        let encoded = match accepted {
            JoinDecision::Accepted(encoded) => encoded,
            JoinDecision::Rejected { .. } | JoinDecision::NetworkNotFound => {
                panic!("valid join should be accepted")
            }
        };
        assert_eq!(
            grant_refresh_delay(&encoded).expect("derive refresh delay"),
            Duration::from_secs(450)
        );
        let repeated = resolve_join(
            &authority,
            &controller,
            node_id,
            JoinRequest {
                network_id,
                token: Some(Zeroizing::new(token_bytes)),
            },
            201,
            ProtocolVersion::V0_1,
        )
        .await
        .expect("resolve repeated join");
        assert!(matches!(repeated, JoinDecision::Accepted(_)));

        let endpoint = Endpoint::UdpIpv4 {
            priority: 10,
            port: 4_242,
            max_datagram_size: 1_200,
            address: Ipv4Addr::new(192, 0, 2, 10),
        };
        let endpoint_revision = resolve_endpoint_update(
            &authority,
            node_id,
            EndpointUpdate {
                network_id,
                endpoints: vec![endpoint],
            },
            201,
        )
        .await
        .expect("publish endpoint");
        assert!(matches!(endpoint_revision, EndpointDecision::Accepted(_)));
        assert_eq!(
            authority
                .get_endpoints(node_id, network_id)
                .await
                .expect("read endpoint lease")
                .expect("endpoint lease exists")
                .endpoints(),
            &[endpoint]
        );

        let connectivity = connectivity_generation(104, 201);
        let connectivity_revision = resolve_connectivity_update(
            &authority,
            node_id,
            ConnectivityUpdate {
                network_id,
                generation: Some(Zeroizing::new(connectivity.clone())),
            },
            201,
        )
        .await
        .expect("publish connectivity");
        assert!(matches!(
            connectivity_revision,
            ConnectivityDecision::Accepted(_)
        ));
        assert_eq!(
            authority
                .get_connectivity(node_id, network_id)
                .await
                .expect("read connectivity")
                .expect("connectivity exists")
                .encoded_generation(),
            connectivity
        );
        assert!(matches!(
            resolve_connectivity_update(
                &authority,
                node_id,
                ConnectivityUpdate {
                    network_id,
                    generation: Some(Zeroizing::new(connectivity_generation(105, 100))),
                },
                701,
            )
            .await
            .expect("reject expired connectivity"),
            ConnectivityDecision::Rejected {
                status: 306,
                forget: false,
                close: false,
                ..
            }
        ));
        assert!(matches!(
            resolve_connectivity_update(
                &authority,
                node_id,
                ConnectivityUpdate {
                    network_id,
                    generation: None,
                },
                202,
            )
            .await
            .expect("withdraw connectivity"),
            ConnectivityDecision::Accepted(_)
        ));
        assert!(authority
            .get_connectivity(node_id, network_id)
            .await
            .expect("read withdrawn connectivity")
            .is_none());

        authority
            .set_membership_status(node_id, network_id, MembershipStatus::Suspended)
            .await
            .expect("suspend membership");
        assert!(matches!(
            resolve_join(
                &authority,
                &controller,
                node_id,
                JoinRequest {
                    network_id,
                    token: Some(Zeroizing::new(token_bytes)),
                },
                202,
                ProtocolVersion::V0_1,
            )
            .await
            .expect("resolve suspended join"),
            JoinDecision::Rejected { status: 112, .. }
        ));
        assert!(matches!(
            resolve_endpoint_update(
                &authority,
                node_id,
                EndpointUpdate {
                    network_id,
                    endpoints: Vec::new(),
                },
                202,
            )
            .await
            .expect("resolve suspended endpoint update"),
            EndpointDecision::Rejected { status: 112, .. }
        ));
        authority
            .set_membership_status(node_id, network_id, MembershipStatus::Active)
            .await
            .expect("resume membership");
        let left = resolve_leave(&authority, node_id, network_id)
            .await
            .expect("resolve leave");
        let first_revision = match left {
            LeaveDecision::Left(revision) => revision,
            LeaveDecision::NetworkNotFound => panic!("network should exist"),
        };
        let repeated_leave = resolve_leave(&authority, node_id, network_id)
            .await
            .expect("resolve repeated leave");
        match repeated_leave {
            LeaveDecision::Left(revision) => assert_eq!(revision, first_revision),
            LeaveDecision::NetworkNotFound => panic!("network should exist"),
        }

        drop(BearerToken::from_bytes(token_bytes).expect("test token remains non-zero"));
        worker.shutdown().await.expect("shutdown authority worker");
        std::fs::remove_dir_all(directory).expect("remove test directory");
    }
}
