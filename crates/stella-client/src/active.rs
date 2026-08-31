//! Authenticated network join and initial state activation.

use std::{
    collections::{BTreeMap, BTreeSet},
    time::{SystemTime, UNIX_EPOCH},
};

use stella_common::NetworkId;
use stella_control::{MessageBuilder, OwnedControlMessage};
use stella_proto::{
    encode_endpoint_set, encode_network_revision_list, ControlFieldType, ControlMessageType,
    Endpoint, NetworkRevision, NetworkRevisionListView,
};

use crate::{AuthenticatedControl, BearerCredential, ClientError, NetworkState, SnapshotInput};

const MAX_ENDPOINT_SET_LENGTH: usize = 4 + 8 * 28;
const MAX_NETWORK_REVISION_LIST_LENGTH: usize = 4 + 256 * 32;

/// Single owner of one authenticated connection and all active network views.
pub struct ActiveControl {
    connection: AuthenticatedControl,
    networks: BTreeMap<NetworkId, NetworkState>,
    heartbeat_counter: u64,
}

impl ActiveControl {
    /// Starts with an authenticated connection and no active forwarding state.
    #[must_use]
    pub const fn new(connection: AuthenticatedControl) -> Self {
        Self {
            connection,
            networks: BTreeMap::new(),
            heartbeat_counter: 0,
        }
    }

    /// Returns the authenticated controller connection metadata.
    #[must_use]
    pub const fn connection(&self) -> &AuthenticatedControl {
        &self.connection
    }

    /// Returns all atomically active network states in stable ID order.
    #[must_use]
    pub const fn networks(&self) -> &BTreeMap<NetworkId, NetworkState> {
        &self.networks
    }

    /// Returns one active network state.
    #[must_use]
    pub fn network(&self, network_id: NetworkId) -> Option<&NetworkState> {
        self.networks.get(&network_id)
    }

    /// Joins and activates one network, replacing any prior view only after
    /// the complete new snapshot validates.
    ///
    /// # Errors
    ///
    /// Returns [`ClientError`] for any join, carrier, or state-validation
    /// failure and preserves the prior active view.
    pub async fn join_network(
        &mut self,
        network_id: NetworkId,
        credential: Option<&BearerCredential>,
    ) -> Result<&NetworkState, ClientError> {
        let state = self.connection.join_network(network_id, credential).await?;
        self.networks.insert(network_id, state);
        self.networks
            .get(&network_id)
            .ok_or(ClientError::NetworkNotActive { network_id })
    }

    /// Publishes the complete receive-ready endpoint set and reconciles the
    /// resulting authoritative snapshot before returning.
    ///
    /// # Errors
    ///
    /// Returns [`ClientError`] for an inactive network, invalid endpoint set,
    /// request rejection, carrier failure, or inconsistent response/snapshot.
    pub async fn publish_endpoints(
        &mut self,
        network_id: NetworkId,
        endpoints: &[Endpoint],
    ) -> Result<&NetworkState, ClientError> {
        let current = self
            .networks
            .get(&network_id)
            .ok_or(ClientError::NetworkNotActive { network_id })?;
        let previous_epoch = current.controller_epoch();
        let previous_revision = current.snapshot_revision();
        let mut encoded = [0_u8; MAX_ENDPOINT_SET_LENGTH];
        let encoded_length = encode_endpoint_set(endpoints, &mut encoded)?;
        let mut request = MessageBuilder::new(ControlMessageType::EndpointUpdate);
        request.push_field(ControlFieldType::NetworkId, network_id.as_bytes())?;
        request.push_field(ControlFieldType::EndpointSet, &encoded[..encoded_length])?;
        let request_id = self.connection.write_message(request).await?;
        let result = self.connection.read_message().await?;
        require_network_response(
            &result,
            ControlMessageType::EndpointResult,
            request_id,
            "endpoint publication",
            network_id,
        )?;
        let result_epoch = decode_u64(
            field_value(&result, ControlFieldType::ControllerEpoch)?,
            "controller epoch",
        )?;
        let result_revision = decode_u64(
            field_value(&result, ControlFieldType::SnapshotRevision)?,
            "snapshot revision",
        )?;
        ensure_control_field(
            result_epoch >= previous_epoch,
            "ENDPOINT_RESULT",
            "controller epoch",
        )?;
        ensure_control_field(
            result_epoch > previous_epoch || result_revision >= previous_revision,
            "ENDPOINT_RESULT",
            "snapshot revision",
        )?;
        self.request_snapshot(network_id, result_epoch, result_revision)
            .await
    }

    /// Sends the next heartbeat and applies every snapshot named as stale by
    /// the authoritative acknowledgement.
    ///
    /// # Errors
    ///
    /// Returns [`ClientError`] for counter exhaustion, construction, carrier,
    /// correlation, network-set, revision, or snapshot inconsistency.
    pub async fn heartbeat(&mut self) -> Result<HeartbeatReport, ClientError> {
        let counter = self
            .heartbeat_counter
            .checked_add(1)
            .ok_or(ClientError::HeartbeatCounterExhausted)?;
        let revisions = self
            .networks
            .values()
            .map(|state| NetworkRevision {
                network_id: state.network_id(),
                controller_epoch: state.controller_epoch(),
                snapshot_revision: state.snapshot_revision(),
            })
            .collect::<Vec<_>>();
        let mut encoded = [0_u8; MAX_NETWORK_REVISION_LIST_LENGTH];
        let encoded_length = encode_network_revision_list(&revisions, &mut encoded)?;
        let mut request = MessageBuilder::new(ControlMessageType::Heartbeat);
        request.push_field(ControlFieldType::HeartbeatCounter, &counter.to_be_bytes())?;
        request.push_field(
            ControlFieldType::NetworkRevisions,
            &encoded[..encoded_length],
        )?;
        let request_id = self.connection.write_message(request).await?;
        let acknowledgement = self.connection.read_message().await?;
        require_direct_response(
            &acknowledgement,
            ControlMessageType::HeartbeatAck,
            request_id,
        )?;
        ensure_control_field(
            decode_u64(
                field_value(&acknowledgement, ControlFieldType::HeartbeatCounter)?,
                "heartbeat counter",
            )? == counter,
            "HEARTBEAT_ACK",
            "heartbeat counter",
        )?;
        let server_time = decode_u64(
            field_value(&acknowledgement, ControlFieldType::ServerTime)?,
            "server time",
        )?;
        let authoritative = NetworkRevisionListView::decode(field_value(
            &acknowledgement,
            ControlFieldType::NetworkRevisions,
        )?)?;
        let expected_updates = self.reconcile_ack_revisions(authoritative.revisions())?;
        self.heartbeat_counter = counter;
        let updated_networks = self.read_reconciled_snapshots(&expected_updates).await?;
        Ok(HeartbeatReport {
            counter,
            server_time,
            updated_networks,
        })
    }

    async fn request_snapshot(
        &mut self,
        network_id: NetworkId,
        minimum_epoch: u64,
        minimum_revision: u64,
    ) -> Result<&NetworkState, ClientError> {
        let last_revision = self
            .network(network_id)
            .ok_or(ClientError::NetworkNotActive { network_id })?
            .snapshot_revision();
        let mut request = MessageBuilder::new(ControlMessageType::SnapshotRequest);
        request.push_field(ControlFieldType::NetworkId, network_id.as_bytes())?;
        request.push_field(
            ControlFieldType::SnapshotRevision,
            &last_revision.to_be_bytes(),
        )?;
        let request_id = self.connection.write_message(request).await?;
        let snapshot = self.connection.read_message().await?;
        require_correlation(&snapshot, request_id)?;
        if snapshot.header()?.message_type == ControlMessageType::Error {
            return Err(network_rejection(
                &snapshot,
                "snapshot request",
                network_id,
            )?);
        }
        let state = decode_snapshot(&self.connection, &snapshot, request_id)?;
        ensure_control_field(
            state.network_id() == network_id,
            "requested PEER_SNAPSHOT",
            "network ID",
        )?;
        ensure_control_field(
            state.controller_epoch() > minimum_epoch
                || (state.controller_epoch() == minimum_epoch
                    && state.snapshot_revision() >= minimum_revision),
            "requested PEER_SNAPSHOT",
            "authority revision",
        )?;
        self.networks.insert(network_id, state);
        self.networks
            .get(&network_id)
            .ok_or(ClientError::NetworkNotActive { network_id })
    }

    fn reconcile_ack_revisions(
        &mut self,
        authoritative: impl Iterator<Item = NetworkRevision>,
    ) -> Result<BTreeMap<NetworkId, NetworkRevision>, ClientError> {
        let mut seen = BTreeSet::new();
        let mut updates = BTreeMap::new();
        for revision in authoritative {
            let Some(local) = self.networks.get(&revision.network_id) else {
                return Err(ClientError::InconsistentControlField {
                    context: "HEARTBEAT_ACK",
                    field: "network set",
                });
            };
            seen.insert(revision.network_id);
            ensure_control_field(
                revision.controller_epoch >= local.controller_epoch(),
                "HEARTBEAT_ACK",
                "controller epoch",
            )?;
            if revision.controller_epoch != local.controller_epoch()
                || revision.snapshot_revision != local.snapshot_revision()
            {
                updates.insert(revision.network_id, revision);
            }
        }
        ensure_control_field(
            seen.len() == self.networks.len(),
            "HEARTBEAT_ACK",
            "network set",
        )?;
        for (network_id, revision) in &updates {
            if self
                .networks
                .get(network_id)
                .is_some_and(|state| revision.controller_epoch > state.controller_epoch())
            {
                self.networks.remove(network_id);
            }
        }
        Ok(updates)
    }

    async fn read_reconciled_snapshots(
        &mut self,
        expected: &BTreeMap<NetworkId, NetworkRevision>,
    ) -> Result<Vec<NetworkId>, ClientError> {
        let mut remaining = expected.clone();
        let mut updated = Vec::new();
        while !remaining.is_empty() {
            let snapshot = self.connection.read_message().await?;
            let state = decode_snapshot(&self.connection, &snapshot, 0)?;
            let Some(authoritative) = remaining.remove(&state.network_id()) else {
                return Err(ClientError::InconsistentControlField {
                    context: "heartbeat reconciliation snapshot",
                    field: "network ID",
                });
            };
            ensure_control_field(
                state.controller_epoch() == authoritative.controller_epoch,
                "heartbeat reconciliation snapshot",
                "controller epoch",
            )?;
            ensure_control_field(
                state.snapshot_revision() == authoritative.snapshot_revision,
                "heartbeat reconciliation snapshot",
                "snapshot revision",
            )?;
            let network_id = state.network_id();
            self.networks.insert(network_id, state);
            updated.push(network_id);
        }
        Ok(updated)
    }
}

impl std::fmt::Debug for ActiveControl {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ActiveControl")
            .field("connection", &self.connection)
            .field("active_networks", &self.networks.len())
            .field("heartbeat_counter", &self.heartbeat_counter)
            .finish_non_exhaustive()
    }
}

/// Result of one validated heartbeat acknowledgement and reconciliation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HeartbeatReport {
    counter: u64,
    server_time: u64,
    updated_networks: Vec<NetworkId>,
}

impl HeartbeatReport {
    /// Returns the acknowledged heartbeat counter.
    #[must_use]
    pub const fn counter(&self) -> u64 {
        self.counter
    }

    /// Returns the controller's diagnostic Unix time.
    #[must_use]
    pub const fn server_time(&self) -> u64 {
        self.server_time
    }

    /// Returns networks replaced by reconciliation snapshots.
    #[must_use]
    pub fn updated_networks(&self) -> &[NetworkId] {
        &self.updated_networks
    }
}

impl AuthenticatedControl {
    /// Joins one network and atomically validates its initial peer snapshot.
    ///
    /// `credential` is required only when the authenticated node does not
    /// already have an active membership. A successful `JOIN_RESULT` does not
    /// activate forwarding by itself; this method returns only after the
    /// following unsolicited complete snapshot validates and exactly matches
    /// the join result.
    ///
    /// # Errors
    ///
    /// Returns [`ClientError`] for construction, I/O, direction, correlation,
    /// status, clock, identity, signature, policy, grant, or snapshot failure.
    pub async fn join_network(
        &mut self,
        network_id: NetworkId,
        credential: Option<&BearerCredential>,
    ) -> Result<NetworkState, ClientError> {
        let mut request = MessageBuilder::new(ControlMessageType::JoinRequest);
        request.push_field(ControlFieldType::NetworkId, network_id.as_bytes())?;
        if let Some(credential) = credential {
            request.push_field(ControlFieldType::JoinToken, credential.expose_secret())?;
        }
        let request_id = self.write_message(request).await?;
        let result = self.read_message().await?;
        let pending = PendingJoin::parse(&result, request_id, network_id)?;
        let snapshot = self.read_message().await?;
        pending.activate(self, &snapshot)
    }
}

struct PendingJoin {
    network_id: NetworkId,
    controller_epoch: u64,
    snapshot_revision: u64,
    local_grant: Vec<u8>,
    policy: Vec<u8>,
}

impl PendingJoin {
    fn parse(
        message: &OwnedControlMessage,
        request_id: u64,
        network_id: NetworkId,
    ) -> Result<Self, ClientError> {
        require_correlation(message, request_id)?;
        match message.header()?.message_type {
            ControlMessageType::JoinResult => {}
            ControlMessageType::Error => return Err(join_rejection(message, network_id)?),
            actual => {
                return Err(ClientError::UnexpectedMessage {
                    expected: ControlMessageType::JoinResult,
                    actual,
                });
            }
        }
        ensure_control_field(
            decode_network_id(message)? == network_id,
            "JOIN_RESULT",
            "network ID",
        )?;
        let status = decode_u16(
            field_value(message, ControlFieldType::StatusCode)?,
            "join status",
        )?;
        if status != 0 {
            return Err(ClientError::NetworkRequestRejected {
                operation: "join",
                network_id,
                status,
            });
        }
        Ok(Self {
            network_id,
            controller_epoch: decode_u64(
                field_value(message, ControlFieldType::ControllerEpoch)?,
                "controller epoch",
            )?,
            snapshot_revision: decode_u64(
                field_value(message, ControlFieldType::SnapshotRevision)?,
                "snapshot revision",
            )?,
            local_grant: field_value(message, ControlFieldType::MembershipGrant)?.to_vec(),
            policy: field_value(message, ControlFieldType::NetworkPolicy)?.to_vec(),
        })
    }

    fn activate(
        self,
        control: &AuthenticatedControl,
        snapshot: &OwnedControlMessage,
    ) -> Result<NetworkState, ClientError> {
        require_unsolicited(snapshot, ControlMessageType::PeerSnapshot)?;
        ensure_control_field(
            decode_network_id(snapshot)? == self.network_id,
            "PEER_SNAPSHOT after JOIN_RESULT",
            "network ID",
        )?;
        let controller_epoch = decode_u64(
            field_value(snapshot, ControlFieldType::ControllerEpoch)?,
            "controller epoch",
        )?;
        let snapshot_revision = decode_u64(
            field_value(snapshot, ControlFieldType::SnapshotRevision)?,
            "snapshot revision",
        )?;
        let local_grant = field_value(snapshot, ControlFieldType::MembershipGrant)?;
        let policy = field_value(snapshot, ControlFieldType::NetworkPolicy)?;
        ensure_control_field(
            controller_epoch == self.controller_epoch,
            "PEER_SNAPSHOT after JOIN_RESULT",
            "controller epoch",
        )?;
        ensure_control_field(
            snapshot_revision == self.snapshot_revision,
            "PEER_SNAPSHOT after JOIN_RESULT",
            "snapshot revision",
        )?;
        ensure_control_field(
            local_grant == self.local_grant,
            "PEER_SNAPSHOT after JOIN_RESULT",
            "membership grant",
        )?;
        ensure_control_field(
            policy == self.policy,
            "PEER_SNAPSHOT after JOIN_RESULT",
            "network policy",
        )?;
        Ok(NetworkState::from_snapshot(&SnapshotInput {
            controller_id: control.controller_id(),
            controller_public_key: control.controller_public_key(),
            local_node_id: control.node_id(),
            local_public_key: control.node_public_key(),
            network_id: self.network_id,
            controller_epoch,
            snapshot_revision,
            local_grant_bytes: local_grant,
            policy_bytes: policy,
            peer_list_bytes: field_value(snapshot, ControlFieldType::PeerList)?,
            now: unix_time()?,
        })?)
    }
}

fn join_rejection(
    message: &OwnedControlMessage,
    network_id: NetworkId,
) -> Result<ClientError, ClientError> {
    Ok(ClientError::NetworkRequestRejected {
        operation: "join",
        network_id,
        status: decode_u16(
            field_value(message, ControlFieldType::StatusCode)?,
            "join error status",
        )?,
    })
}

fn require_correlation(message: &OwnedControlMessage, request_id: u64) -> Result<(), ClientError> {
    let header = message.header()?;
    if header.correlation_id != request_id {
        return Err(ClientError::UnexpectedCorrelation {
            expected: request_id,
            actual: header.correlation_id,
        });
    }
    Ok(())
}

fn require_direct_response(
    message: &OwnedControlMessage,
    expected: ControlMessageType,
    request_id: u64,
) -> Result<(), ClientError> {
    require_correlation(message, request_id)?;
    let actual = message.header()?.message_type;
    if actual != expected {
        return Err(ClientError::UnexpectedMessage { expected, actual });
    }
    Ok(())
}

fn require_network_response(
    message: &OwnedControlMessage,
    expected: ControlMessageType,
    request_id: u64,
    operation: &'static str,
    network_id: NetworkId,
) -> Result<(), ClientError> {
    require_correlation(message, request_id)?;
    if message.header()?.message_type == ControlMessageType::Error {
        return Err(network_rejection(message, operation, network_id)?);
    }
    require_direct_response(message, expected, request_id)?;
    ensure_control_field(
        decode_network_id(message)? == network_id,
        "network response",
        "network ID",
    )?;
    let status = decode_u16(
        field_value(message, ControlFieldType::StatusCode)?,
        "network request status",
    )?;
    if status != 0 {
        return Err(ClientError::NetworkRequestRejected {
            operation,
            network_id,
            status,
        });
    }
    Ok(())
}

fn network_rejection(
    message: &OwnedControlMessage,
    operation: &'static str,
    network_id: NetworkId,
) -> Result<ClientError, ClientError> {
    Ok(ClientError::NetworkRequestRejected {
        operation,
        network_id,
        status: decode_u16(
            field_value(message, ControlFieldType::StatusCode)?,
            "network request error status",
        )?,
    })
}

fn decode_snapshot(
    control: &AuthenticatedControl,
    message: &OwnedControlMessage,
    correlation_id: u64,
) -> Result<NetworkState, ClientError> {
    let header = message.header()?;
    if header.message_type != ControlMessageType::PeerSnapshot {
        return Err(ClientError::UnexpectedMessage {
            expected: ControlMessageType::PeerSnapshot,
            actual: header.message_type,
        });
    }
    if header.correlation_id != correlation_id {
        return Err(ClientError::UnexpectedCorrelation {
            expected: correlation_id,
            actual: header.correlation_id,
        });
    }
    Ok(NetworkState::from_snapshot(&SnapshotInput {
        controller_id: control.controller_id(),
        controller_public_key: control.controller_public_key(),
        local_node_id: control.node_id(),
        local_public_key: control.node_public_key(),
        network_id: decode_network_id(message)?,
        controller_epoch: decode_u64(
            field_value(message, ControlFieldType::ControllerEpoch)?,
            "controller epoch",
        )?,
        snapshot_revision: decode_u64(
            field_value(message, ControlFieldType::SnapshotRevision)?,
            "snapshot revision",
        )?,
        local_grant_bytes: field_value(message, ControlFieldType::MembershipGrant)?,
        policy_bytes: field_value(message, ControlFieldType::NetworkPolicy)?,
        peer_list_bytes: field_value(message, ControlFieldType::PeerList)?,
        now: unix_time()?,
    })?)
}

fn require_unsolicited(
    message: &OwnedControlMessage,
    expected: ControlMessageType,
) -> Result<(), ClientError> {
    let header = message.header()?;
    if header.message_type != expected {
        return Err(ClientError::UnexpectedMessage {
            expected,
            actual: header.message_type,
        });
    }
    if header.correlation_id != 0 {
        return Err(ClientError::UnexpectedCorrelation {
            expected: 0,
            actual: header.correlation_id,
        });
    }
    Ok(())
}

fn field_value(
    message: &OwnedControlMessage,
    field: ControlFieldType,
) -> Result<&[u8], ClientError> {
    let view = message.view()?;
    for candidate in view.fields() {
        if candidate.field_type() == Some(field) {
            return Ok(candidate.value());
        }
    }
    Err(ClientError::MissingField {
        message_type: view.header().message_type,
        field,
    })
}

fn decode_network_id(message: &OwnedControlMessage) -> Result<NetworkId, ClientError> {
    Ok(NetworkId::from_bytes(fixed_array(
        field_value(message, ControlFieldType::NetworkId)?,
        "network ID",
    )?))
}

fn fixed_array<const N: usize>(value: &[u8], field: &'static str) -> Result<[u8; N], ClientError> {
    value
        .try_into()
        .map_err(|_| ClientError::InvalidFieldWidth { field })
}

fn decode_u16(value: &[u8], field: &'static str) -> Result<u16, ClientError> {
    Ok(u16::from_be_bytes(fixed_array(value, field)?))
}

fn decode_u64(value: &[u8], field: &'static str) -> Result<u64, ClientError> {
    Ok(u64::from_be_bytes(fixed_array(value, field)?))
}

fn ensure_control_field(
    matches: bool,
    context: &'static str,
    field: &'static str,
) -> Result<(), ClientError> {
    if !matches {
        return Err(ClientError::InconsistentControlField { context, field });
    }
    Ok(())
}

fn unix_time() -> Result<u64, ClientError> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .map_err(|_| ClientError::SystemTimeBeforeUnixEpoch)
}
