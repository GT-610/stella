//! Authenticated network join and initial state activation.

use std::{
    collections::{BTreeMap, BTreeSet},
    time::{SystemTime, UNIX_EPOCH},
};

use stella_common::{NetworkId, NodeId};
use stella_control::{MessageBuilder, OwnedControlMessage};
use stella_proto::{
    encode_connectivity_generation, encode_endpoint_set, encode_network_revision_list,
    ConnectivityGenerationRef, ControlFieldType, ControlMessageType, Endpoint, NetworkRevision,
    NetworkRevisionListView, PeerRecordView, ProtocolVersion,
};
use tokio::time::Instant;
use zeroize::Zeroizing;

use crate::{
    control_field::{decode_u16, decode_u64, field_value, fixed_array, optional_field_value},
    AuthenticatedControl, BearerCredential, ClientError, ConnectivityConfigState,
    GrantRefreshInput, NetworkState, PeerDeltaInput, PeerDeltaOperation, SnapshotInput,
};

const MAX_ENDPOINT_SET_LENGTH: usize = 4 + 8 * 28;
const MAX_NETWORK_REVISION_LIST_LENGTH: usize = 4 + 256 * 32;

/// Single owner of one authenticated connection and all active network views.
pub struct ActiveControl {
    connection: AuthenticatedControl,
    networks: BTreeMap<NetworkId, NetworkState>,
    connectivity_config: Option<ConnectivityConfigState>,
    heartbeat_counter: u64,
}

impl ActiveControl {
    /// Starts with an authenticated connection and no active forwarding state.
    #[must_use]
    pub fn new(mut connection: AuthenticatedControl) -> Self {
        let connectivity_config = connection.take_connectivity_config();
        Self {
            connection,
            networks: BTreeMap::new(),
            connectivity_config,
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

    /// Returns the latest atomically validated deployment connectivity configuration.
    #[must_use]
    pub const fn connectivity_config(&self) -> Option<&ConnectivityConfigState> {
        self.connectivity_config.as_ref()
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

    /// Stops local forwarding state before authoritatively leaving one
    /// network and keeps the network inactive even if the request fails.
    ///
    /// # Errors
    ///
    /// Returns [`ClientError`] for construction, carrier, correlation,
    /// rejection, or inconsistent response failure.
    pub async fn leave_network(&mut self, network_id: NetworkId) -> Result<u64, ClientError> {
        self.networks.remove(&network_id);
        self.connection.leave_network(network_id).await
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
        let result = self
            .read_response_while_applying_updates(request_id)
            .await?;
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
        self.request_snapshot(network_id, previous_revision, result_epoch, result_revision)
            .await
    }

    /// Publishes or withdraws the complete version 0.2 connectivity generation
    /// and reconciles the resulting authoritative snapshot before returning.
    ///
    /// Passing `None` withdraws only automatic reachability; membership and
    /// any version 0.1 endpoint set remain unchanged.
    ///
    /// # Errors
    ///
    /// Returns [`ClientError`] for an inactive network, version mismatch,
    /// invalid generation, request rejection, carrier failure, or inconsistent
    /// response/snapshot.
    pub async fn publish_connectivity(
        &mut self,
        network_id: NetworkId,
        generation: Option<ConnectivityGenerationRef<'_>>,
    ) -> Result<&NetworkState, ClientError> {
        let current = self
            .networks
            .get(&network_id)
            .ok_or(ClientError::NetworkNotActive { network_id })?;
        let negotiated = self.connection.protocol_version();
        if negotiated != ProtocolVersion::V0_2 {
            return Err(ClientError::ProtocolFeatureUnavailable {
                feature: "automatic connectivity publication",
                required: ProtocolVersion::V0_2,
                negotiated,
            });
        }
        let previous_epoch = current.controller_epoch();
        let previous_revision = current.snapshot_revision();
        let mut encoded_generation = generation
            .map(|generation| {
                let length = generation.encoded_len()?;
                let mut encoded = Zeroizing::new(vec![0; length]);
                encode_connectivity_generation(generation, &mut encoded)?;
                Ok::<_, ClientError>(encoded)
            })
            .transpose()?;
        let mut request = MessageBuilder::new(ControlMessageType::ConnectivityUpdate);
        request.push_field(ControlFieldType::NetworkId, network_id.as_bytes())?;
        if let Some(encoded) = encoded_generation.as_deref_mut() {
            request.push_field(ControlFieldType::ConnectivityGeneration, encoded)?;
        }
        let request_id = self.connection.write_message(request).await?;
        let result = self
            .read_response_while_applying_updates(request_id)
            .await?;
        require_network_response(
            &result,
            ControlMessageType::ConnectivityResult,
            request_id,
            "connectivity publication",
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
            "CONNECTIVITY_RESULT",
            "controller epoch",
        )?;
        ensure_control_field(
            result_epoch > previous_epoch || result_revision >= previous_revision,
            "CONNECTIVITY_RESULT",
            "snapshot revision",
        )?;
        self.request_snapshot(network_id, previous_revision, result_epoch, result_revision)
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
        let acknowledgement = self
            .read_response_while_applying_updates(request_id)
            .await?;
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

    /// Reads and applies one unsolicited controller update.
    ///
    /// Invalid deltas preserve same-epoch state and automatically request a
    /// complete replacement snapshot. A higher delta epoch clears the old
    /// network before recovery so stale authorization cannot keep forwarding.
    ///
    /// # Errors
    ///
    /// Returns [`ClientError`] for wrong direction/correlation, an unknown
    /// network, malformed fields, carrier failure, or failed state recovery.
    pub async fn receive_update(&mut self) -> Result<ControlUpdate, ClientError> {
        let message = self.connection.read_message().await?;
        self.apply_update_message(&message).await
    }

    /// Waits for one unsolicited update until a monotonic deadline.
    ///
    /// `None` means the deadline elapsed without consuming or cancelling a
    /// partially read control record.
    ///
    /// # Errors
    ///
    /// Returns [`ClientError`] for carrier, sequence, direction, correlation,
    /// state validation, or recovery failure.
    pub async fn receive_update_until(
        &mut self,
        deadline: Instant,
    ) -> Result<Option<ControlUpdate>, ClientError> {
        tokio::select! {
            message = self.connection.read_message() => {
                let message = message?;
                self.apply_update_message(&message).await.map(Some)
            }
            () = tokio::time::sleep_until(deadline) => Ok(None),
        }
    }

    async fn apply_update_message(
        &mut self,
        message: &OwnedControlMessage,
    ) -> Result<ControlUpdate, ClientError> {
        require_unsolicited_correlation(message)?;
        match message.header()?.message_type {
            ControlMessageType::PeerSnapshot => self.apply_unsolicited_snapshot(message),
            ControlMessageType::PeerDelta => self.apply_peer_delta(message).await,
            ControlMessageType::GrantRefresh => self.apply_grant_refresh(message),
            ControlMessageType::ConnectivityConfig => self.apply_connectivity_config(message),
            ControlMessageType::ServerShutdown => Ok(ControlUpdate::ServerShutdown {
                deadline: decode_u64(
                    field_value(message, ControlFieldType::ShutdownDeadline)?,
                    "shutdown deadline",
                )?,
            }),
            ControlMessageType::Error => Ok(ControlUpdate::ControllerError {
                status: decode_u16(
                    field_value(message, ControlFieldType::StatusCode)?,
                    "controller error status",
                )?,
                retry_after_ms: optional_u32(message, ControlFieldType::RetryAfterMs)?,
            }),
            actual => Err(ClientError::UnexpectedActiveMessage { actual }),
        }
    }

    fn apply_connectivity_config(
        &mut self,
        message: &OwnedControlMessage,
    ) -> Result<ControlUpdate, ClientError> {
        let received = ConnectivityConfigState::from_wire(
            decode_u64(
                field_value(message, ControlFieldType::ConnectivityConfigRevision)?,
                "connectivity configuration revision",
            )?,
            field_value(message, ControlFieldType::StunServerList)?,
            field_value(message, ControlFieldType::RelayServiceList)?,
            unix_time()?,
        )?;
        if let Some(current) = &self.connectivity_config {
            if received.revision() <= current.revision() {
                return Err(ClientError::ConnectivityConfigRevisionNotAdvanced {
                    current: current.revision(),
                    received: received.revision(),
                });
            }
        }
        let revision = received.revision();
        self.connectivity_config = Some(received);
        Ok(ControlUpdate::ConnectivityConfigReplaced { revision })
    }

    async fn read_response_while_applying_updates(
        &mut self,
        request_id: u64,
    ) -> Result<OwnedControlMessage, ClientError> {
        loop {
            let message = self.connection.read_message().await?;
            if message.header()?.correlation_id == 0 {
                self.apply_update_message(&message).await?;
                continue;
            }
            require_correlation(&message, request_id)?;
            return Ok(message);
        }
    }

    async fn request_snapshot(
        &mut self,
        network_id: NetworkId,
        last_revision: u64,
        minimum_epoch: u64,
        minimum_revision: u64,
    ) -> Result<&NetworkState, ClientError> {
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

    fn apply_unsolicited_snapshot(
        &mut self,
        message: &OwnedControlMessage,
    ) -> Result<ControlUpdate, ClientError> {
        let network_id = decode_network_id(message)?;
        let incoming_epoch = decode_u64(
            field_value(message, ControlFieldType::ControllerEpoch)?,
            "controller epoch",
        )?;
        let current_epoch = self
            .networks
            .get(&network_id)
            .ok_or(ClientError::NetworkNotActive { network_id })?
            .controller_epoch();
        ensure_control_field(
            incoming_epoch >= current_epoch,
            "unsolicited PEER_SNAPSHOT",
            "controller epoch",
        )?;
        if incoming_epoch > current_epoch {
            self.networks.remove(&network_id);
        }
        let state = decode_snapshot(&self.connection, message, 0)?;
        if let Some(current) = self.networks.get(&network_id) {
            ensure_control_field(
                state.controller_epoch() > current.controller_epoch()
                    || (state.controller_epoch() == current.controller_epoch()
                        && state.snapshot_revision() >= current.snapshot_revision()),
                "unsolicited PEER_SNAPSHOT",
                "authority revision",
            )?;
        }
        self.networks.insert(network_id, state);
        Ok(ControlUpdate::SnapshotReplaced { network_id })
    }

    fn apply_grant_refresh(
        &mut self,
        message: &OwnedControlMessage,
    ) -> Result<ControlUpdate, ClientError> {
        let network_id = decode_network_id(message)?;
        let controller_id = self.connection.controller_id();
        let controller_public_key = self.connection.controller_public_key();
        let local_node_id = self.connection.node_id();
        let local_public_key = self.connection.node_public_key();
        let state = self
            .networks
            .get_mut(&network_id)
            .ok_or(ClientError::NetworkNotActive { network_id })?;
        let prior_serial = state.local_grant().grant_serial;
        state.refresh_local_grant(&GrantRefreshInput {
            controller_id,
            controller_public_key,
            local_node_id,
            local_public_key,
            controller_epoch: decode_u64(
                field_value(message, ControlFieldType::ControllerEpoch)?,
                "controller epoch",
            )?,
            snapshot_revision: decode_u64(
                field_value(message, ControlFieldType::SnapshotRevision)?,
                "snapshot revision",
            )?,
            grant_bytes: field_value(message, ControlFieldType::MembershipGrant)?,
            policy_bytes: field_value(message, ControlFieldType::NetworkPolicy)?,
            now: unix_time()?,
        })?;
        Ok(ControlUpdate::GrantRefreshed {
            network_id,
            serial_changed: state.local_grant().grant_serial != prior_serial,
        })
    }

    async fn apply_peer_delta(
        &mut self,
        message: &OwnedControlMessage,
    ) -> Result<ControlUpdate, ClientError> {
        let network_id = decode_network_id(message)?;
        let controller_epoch = decode_u64(
            field_value(message, ControlFieldType::ControllerEpoch)?,
            "controller epoch",
        )?;
        let snapshot_revision = decode_u64(
            field_value(message, ControlFieldType::SnapshotRevision)?,
            "snapshot revision",
        )?;
        let (last_revision, current_epoch) = self
            .networks
            .get(&network_id)
            .map(|state| (state.snapshot_revision(), state.controller_epoch()))
            .ok_or(ClientError::NetworkNotActive { network_id })?;
        let (operation, changed_node, removed) = decode_delta_operation(message)?;
        let input = PeerDeltaInput {
            controller_id: self.connection.controller_id(),
            controller_public_key: self.connection.controller_public_key(),
            local_node_id: self.connection.node_id(),
            network_id,
            controller_epoch,
            snapshot_revision,
            operation,
            now: unix_time()?,
        };
        let applied = self
            .networks
            .get_mut(&network_id)
            .ok_or(ClientError::NetworkNotActive { network_id })?
            .apply_peer_delta(&input);
        if applied.is_ok() {
            return Ok(ControlUpdate::PeerChanged {
                network_id,
                node_id: changed_node,
                removed,
            });
        }
        if controller_epoch > current_epoch {
            self.networks.remove(&network_id);
        }
        self.request_snapshot(
            network_id,
            last_revision,
            current_epoch.max(controller_epoch),
            last_revision,
        )
        .await?;
        Ok(ControlUpdate::SnapshotRecovered { network_id })
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
            .field(
                "connectivity_config_revision",
                &self
                    .connectivity_config
                    .as_ref()
                    .map(ConnectivityConfigState::revision),
            )
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

/// One successfully processed unsolicited controller event.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum ControlUpdate {
    /// The complete deployment STUN and relay configuration was replaced.
    ConnectivityConfigReplaced {
        /// New deployment-scoped configuration revision.
        revision: u64,
    },
    /// A complete unsolicited snapshot replaced one network.
    SnapshotReplaced {
        /// Replaced network.
        network_id: NetworkId,
    },
    /// One valid add/replace or remove delta changed a peer.
    PeerChanged {
        /// Updated network.
        network_id: NetworkId,
        /// Added, replaced, or removed peer.
        node_id: NodeId,
        /// Whether the peer was removed rather than added/replaced.
        removed: bool,
    },
    /// An invalid or discontinuous delta was recovered with a full snapshot.
    SnapshotRecovered {
        /// Recovered network.
        network_id: NetworkId,
    },
    /// The local membership grant was atomically refreshed.
    GrantRefreshed {
        /// Refreshed network.
        network_id: NetworkId,
        /// Whether peer data sessions must rekey for a new grant serial.
        serial_changed: bool,
    },
    /// The controller announced a graceful shutdown deadline.
    ServerShutdown {
        /// Earliest Unix time at which reconnect should begin.
        deadline: u64,
    },
    /// The controller sent an unsolicited registered error notice.
    ControllerError {
        /// Registered status code.
        status: u16,
        /// Optional retry delay in milliseconds.
        retry_after_ms: Option<u32>,
    },
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

    /// Requests authoritative removal from one network and returns the new
    /// controller epoch after validating the complete direct response.
    ///
    /// # Errors
    ///
    /// Returns [`ClientError`] for construction, I/O, direction, correlation,
    /// status, network identity, or epoch inconsistency.
    pub async fn leave_network(&mut self, network_id: NetworkId) -> Result<u64, ClientError> {
        let mut request = MessageBuilder::new(ControlMessageType::LeaveRequest);
        request.push_field(ControlFieldType::NetworkId, network_id.as_bytes())?;
        let request_id = self.write_message(request).await?;
        let result = self.read_message().await?;
        require_network_response(
            &result,
            ControlMessageType::LeaveResult,
            request_id,
            "leave",
            network_id,
        )?;
        let controller_epoch = decode_u64(
            field_value(&result, ControlFieldType::ControllerEpoch)?,
            "leave controller epoch",
        )?;
        ensure_control_field(controller_epoch != 0, "LEAVE_RESULT", "controller epoch")?;
        Ok(controller_epoch)
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
            connectivity_list_bytes: optional_field_value(
                snapshot,
                ControlFieldType::ConnectivityList,
            )?,
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
        connectivity_list_bytes: optional_field_value(message, ControlFieldType::ConnectivityList)?,
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

fn require_unsolicited_correlation(message: &OwnedControlMessage) -> Result<(), ClientError> {
    let actual = message.header()?.correlation_id;
    if actual != 0 {
        return Err(ClientError::UnexpectedCorrelation {
            expected: 0,
            actual,
        });
    }
    Ok(())
}

fn decode_delta_operation(
    message: &OwnedControlMessage,
) -> Result<(PeerDeltaOperation<'_>, NodeId, bool), ClientError> {
    let operation = field_value(message, ControlFieldType::DeltaOperation)?;
    match operation.first().copied() {
        Some(1) => {
            let peer_bytes = field_value(message, ControlFieldType::PeerRecord)?;
            let node_id = PeerRecordView::decode(peer_bytes)?.node_id();
            Ok((PeerDeltaOperation::AddOrReplace(peer_bytes), node_id, false))
        }
        Some(2) => {
            let node_id = NodeId::from_bytes(fixed_array(
                field_value(message, ControlFieldType::NodeId)?,
                "peer delta node ID",
            )?);
            Ok((PeerDeltaOperation::Remove(node_id), node_id, true))
        }
        _ => Err(ClientError::InvalidPeerDeltaOperation),
    }
}

fn decode_network_id(message: &OwnedControlMessage) -> Result<NetworkId, ClientError> {
    Ok(NetworkId::from_bytes(fixed_array(
        field_value(message, ControlFieldType::NetworkId)?,
        "network ID",
    )?))
}

fn optional_u32(
    message: &OwnedControlMessage,
    field: ControlFieldType,
) -> Result<Option<u32>, ClientError> {
    for candidate in message.view()?.fields() {
        if candidate.field_type() == Some(field) {
            return Ok(Some(u32::from_be_bytes(fixed_array(
                candidate.value(),
                "optional u32 field",
            )?)));
        }
    }
    Ok(None)
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

#[cfg(test)]
mod tests {
    use stella_common::{NetworkId, NodeId};
    use stella_control::{MessageBuilder, OutboundSequence};
    use stella_proto::{ControlFieldType, ControlMessageType};

    use super::{decode_delta_operation, optional_u32, require_unsolicited_correlation};
    use crate::{ClientError, PeerDeltaOperation};

    #[test]
    fn remove_delta_decodes_target_and_requires_zero_correlation() {
        let node_id = NodeId::from_bytes([0x31; 16]);
        let mut builder = MessageBuilder::new(ControlMessageType::PeerDelta);
        builder
            .push_field(ControlFieldType::NodeId, node_id.as_bytes())
            .expect("node ID field");
        builder
            .push_field(ControlFieldType::ControllerEpoch, &2_u64.to_be_bytes())
            .expect("controller epoch field");
        builder
            .push_field(
                ControlFieldType::NetworkId,
                NetworkId::from_bytes([0x32; 16]).as_bytes(),
            )
            .expect("network ID field");
        builder
            .push_field(ControlFieldType::SnapshotRevision, &3_u64.to_be_bytes())
            .expect("snapshot revision field");
        builder
            .push_field(ControlFieldType::DeltaOperation, &[2])
            .expect("delta operation field");
        let message = OutboundSequence::new()
            .build(builder)
            .expect("build remove delta");

        require_unsolicited_correlation(&message).expect("zero correlation is unsolicited");
        assert_eq!(
            decode_delta_operation(&message).expect("decode remove operation"),
            (PeerDeltaOperation::Remove(node_id), node_id, true)
        );
    }

    #[test]
    fn optional_retry_delay_is_decoded_without_defaulting() {
        let mut builder = MessageBuilder::new(ControlMessageType::Error);
        builder
            .push_field(ControlFieldType::StatusCode, &401_u16.to_be_bytes())
            .expect("status field");
        builder
            .push_field(ControlFieldType::RetryAfterMs, &250_u32.to_be_bytes())
            .expect("retry field");
        let message = OutboundSequence::new()
            .build(builder)
            .expect("build controller error");
        assert_eq!(
            optional_u32(&message, ControlFieldType::RetryAfterMs)
                .expect("decode optional retry delay"),
            Some(250)
        );

        let mut correlated = MessageBuilder::new(ControlMessageType::Error).with_correlation(9);
        correlated
            .push_field(ControlFieldType::StatusCode, &401_u16.to_be_bytes())
            .expect("correlated status field");
        let correlated = OutboundSequence::new()
            .build(correlated)
            .expect("build correlated controller error");
        assert!(matches!(
            require_unsolicited_correlation(&correlated),
            Err(ClientError::UnexpectedCorrelation {
                expected: 0,
                actual: 9
            })
        ));
    }
}
