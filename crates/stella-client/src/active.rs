//! Authenticated network join and initial state activation.

use std::time::{SystemTime, UNIX_EPOCH};

use stella_common::NetworkId;
use stella_control::{MessageBuilder, OwnedControlMessage};
use stella_proto::{ControlFieldType, ControlMessageType};

use crate::{AuthenticatedControl, BearerCredential, ClientError, NetworkState, SnapshotInput};

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
