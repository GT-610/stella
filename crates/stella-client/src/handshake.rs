//! Authenticated peer-session handshake state machines.

use std::time::Duration;

use stella_common::{GrantSerial, NodeId};
use stella_crypto::{
    derive_node_id, derive_session_secrets, session_transcript_hash, sha256_segments,
    EphemeralPublicKey, EphemeralSecret, IdentityPublicKey, IdentitySigningKey, SessionProtectors,
    SessionRole,
};
use stella_proto::{
    encode_session_confirm, encode_session_init, encode_session_response, CommonHeader,
    HandshakeHeader, MembershipGrant, NetworkPolicy, PacketType, ProtocolVersion,
    SessionConfirmRef, SessionConfirmRole, SessionConfirmView, SessionInitRef, SessionInitView,
    SessionResponseRef, SessionResponseView, HANDSHAKE_FIXED_HEADER_LENGTH, HANDSHAKE_NONCE_LENGTH,
    MAX_ENDPOINT_DATAGRAM_SIZE, MEMBERSHIP_GRANT_LENGTH, MIN_ENDPOINT_DATAGRAM_SIZE,
    SESSION_CONFIRM_PAYLOAD_LENGTH, SESSION_CONFIRM_RESPONDER_FLAG, SESSION_INIT_PAYLOAD_LENGTH,
    SESSION_INIT_SIGNATURE_DOMAIN, SESSION_RESPONSE_PAYLOAD_LENGTH,
    SESSION_RESPONSE_SIGNATURE_DOMAIN,
};
use thiserror::Error;

use crate::{NetworkState, PeerDataSession};

const TIMESTAMP_TOLERANCE_SECONDS: u64 = 120;
const MAX_SESSION_LIFETIME: Duration = Duration::from_secs(60 * 60);
const HANDSHAKE_HEADER_LENGTH: u16 = 96;
const INIT_PAYLOAD_LENGTH: u32 = 392;
const RESPONSE_PAYLOAD_LENGTH: u32 = 408;
const CONFIRM_PAYLOAD_LENGTH: u32 = 56;

/// Failure while constructing or advancing an authenticated peer handshake.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum HandshakeError {
    /// Local authoritative state cannot support this peer exchange.
    #[error("invalid peer handshake configuration: {reason}")]
    InvalidConfiguration {
        /// Stable non-secret validation reason.
        reason: &'static str,
    },
    /// An incoming handshake names an unexpected authenticated context field.
    #[error("peer handshake has unexpected {field}")]
    ContextMismatch {
        /// Mismatched field name.
        field: &'static str,
    },
    /// The sender timestamp is outside the mandatory freshness window.
    #[error("peer handshake timestamp is outside the 120-second freshness window")]
    StaleTimestamp,
    /// The response or confirmation digest does not bind the expected datagram.
    #[error("peer handshake {digest} digest mismatch")]
    DigestMismatch {
        /// Digest relationship that failed.
        digest: &'static str,
    },
    /// This state machine received a message in the wrong phase.
    #[error("peer handshake is not awaiting {message}")]
    InvalidPhase {
        /// Expected phase description.
        message: &'static str,
    },
    /// A structurally encoded protocol object failed validation.
    #[error(transparent)]
    Codec(#[from] stella_proto::CodecError),
    /// Identity, signature, agreement, derivation, or confirmation failed.
    #[error(transparent)]
    Crypto(#[from] stella_crypto::CryptoError),
    /// An established data session could not be constructed.
    #[error(transparent)]
    DataPlane(#[from] crate::DataPlaneError),
}

/// Immutable authoritative inputs for one peer handshake.
#[derive(Clone, Debug)]
pub struct PeerHandshakeConfig {
    policy: NetworkPolicy,
    controller_epoch: u64,
    local_node_id: NodeId,
    peer_node_id: NodeId,
    local_grant: MembershipGrant,
    local_grant_bytes: [u8; MEMBERSHIP_GRANT_LENGTH],
    peer_grant: MembershipGrant,
    peer_grant_bytes: [u8; MEMBERSHIP_GRANT_LENGTH],
    peer_public_key: IdentityPublicKey,
    max_datagram_size: u32,
}

impl PeerHandshakeConfig {
    /// Builds peer handshake inputs from one already validated network snapshot.
    ///
    /// # Errors
    ///
    /// Returns [`HandshakeError`] when the peer is absent, the private identity
    /// does not match the local grant, permissions are insufficient, or the
    /// transport datagram bound is outside the interoperable range.
    pub fn from_network_state(
        network: &NetworkState,
        peer_node_id: NodeId,
        local_signing_key: &IdentitySigningKey,
        max_datagram_size: usize,
    ) -> Result<Self, HandshakeError> {
        let local_node_id = derive_node_id(local_signing_key.public_key());
        if local_node_id != network.local_grant().node_id {
            return Err(HandshakeError::InvalidConfiguration {
                reason: "local identity does not match membership grant",
            });
        }
        let peer =
            network
                .peers()
                .get(&peer_node_id)
                .ok_or(HandshakeError::InvalidConfiguration {
                    reason: "peer is absent from the active snapshot",
                })?;
        validate_permissions(network.local_grant())?;
        validate_permissions(peer.grant())?;
        let max_datagram_size =
            u32::try_from(max_datagram_size).map_err(|_| HandshakeError::InvalidConfiguration {
                reason: "transport datagram size is not representable",
            })?;
        if !(MIN_ENDPOINT_DATAGRAM_SIZE..=MAX_ENDPOINT_DATAGRAM_SIZE).contains(&max_datagram_size) {
            return Err(HandshakeError::InvalidConfiguration {
                reason: "transport datagram size is outside 1200..=65507",
            });
        }
        Ok(Self {
            policy: network.policy(),
            controller_epoch: network.controller_epoch(),
            local_node_id,
            peer_node_id,
            local_grant: network.local_grant(),
            local_grant_bytes: *network.local_grant_bytes(),
            peer_grant: peer.grant(),
            peer_grant_bytes: *peer.grant_bytes(),
            peer_public_key: peer.public_key(),
            max_datagram_size,
        })
    }

    /// Returns whether this node is the deterministic preferred initiator.
    #[must_use]
    pub fn is_preferred_initiator(&self) -> bool {
        self.local_node_id < self.peer_node_id
    }

    /// Returns the remote peer node ID.
    #[must_use]
    pub const fn peer_node_id(&self) -> NodeId {
        self.peer_node_id
    }
}

/// An initiator exchange retaining exact retransmission bytes.
pub struct InitiatorHandshake {
    config: PeerHandshakeConfig,
    header: HandshakeHeader,
    init_datagram: Vec<u8>,
    ephemeral: Option<EphemeralSecret>,
    confirmation: Option<InitiatorConfirmation>,
}

impl InitiatorHandshake {
    /// Creates and signs a fresh `SESSION_INIT` using operating-system randomness.
    ///
    /// # Errors
    ///
    /// Returns [`HandshakeError`] when randomness, encoding, or signing fails,
    /// or either local grant is outside its validity interval.
    pub fn start(
        config: PeerHandshakeConfig,
        local_signing_key: &IdentitySigningKey,
        timestamp: u64,
    ) -> Result<Self, HandshakeError> {
        validate_local_signing_key(&config, local_signing_key)?;
        validate_grant_time(config.local_grant, timestamp)?;
        validate_grant_time(config.peer_grant, timestamp)?;
        let ephemeral = EphemeralSecret::generate()?;
        let ephemeral_public = ephemeral.public_key().to_bytes();
        let nonce = random_nonzero_array::<HANDSHAKE_NONCE_LENGTH>()?;
        let handshake_id = random_nonzero_u64()?;
        let session_id = random_nonzero_u64()?;
        let header = handshake_header(
            PacketType::SessionInit,
            0,
            INIT_PAYLOAD_LENGTH,
            &config,
            timestamp,
            handshake_id,
            session_id,
        );
        let init_datagram = encode_signed_init(
            header,
            &config.local_grant_bytes,
            config.peer_grant.grant_serial,
            &ephemeral_public,
            &nonce,
            config.max_datagram_size,
            local_signing_key,
        )?;
        Ok(Self {
            config,
            header,
            init_datagram,
            ephemeral: Some(ephemeral),
            confirmation: None,
        })
    }

    /// Borrows the exact initiation bytes used for every retransmission.
    #[must_use]
    pub fn initiation_datagram(&self) -> &[u8] {
        &self.init_datagram
    }

    /// Validates a response, derives keys, and returns the cached initiator confirmation.
    ///
    /// # Errors
    ///
    /// Returns [`HandshakeError`] for a wrong phase, stale or mismatched
    /// response, invalid grant/signature/hash, or failed key agreement.
    pub fn accept_response(&mut self, datagram: &[u8], now: u64) -> Result<&[u8], HandshakeError> {
        if self.confirmation.is_some() {
            return Err(HandshakeError::InvalidPhase {
                message: "SESSION_RESPONSE",
            });
        }
        let response = SessionResponseView::decode(datagram)?;
        validate_header_pair(
            self.header,
            response.header(),
            PacketType::SessionResponse,
            true,
        )?;
        validate_timestamp(response.header().timestamp, now)?;
        validate_grant_time(self.config.local_grant, now)?;
        validate_grant_time(self.config.peer_grant, now)?;
        if response.responder_grant().grant() != self.config.peer_grant
            || response.signed_payload().get(..MEMBERSHIP_GRANT_LENGTH)
                != Some(self.config.peer_grant_bytes.as_slice())
        {
            return Err(HandshakeError::ContextMismatch {
                field: "responder membership grant",
            });
        }
        let init_hash = sha256_segments(&[&self.init_datagram]);
        if response.init_hash() != &init_hash {
            return Err(HandshakeError::DigestMismatch { digest: "init" });
        }
        self.config.peer_public_key.verify_segments(
            SESSION_RESPONSE_SIGNATURE_DOMAIN,
            &[response.signed_header(), response.signed_payload()],
            response.signature(),
        )?;

        let secret = self.ephemeral.take().ok_or(HandshakeError::InvalidPhase {
            message: "unused initiator ephemeral key",
        })?;
        let shared = secret.agree(EphemeralPublicKey::from_bytes(
            *response.responder_ephemeral(),
        ))?;
        let transcript_hash = session_transcript_hash(&self.init_datagram, datagram);
        let protectors = derive_session_secrets(shared, &transcript_hash, SessionRole::Initiator)?
            .into_protectors();
        let response_hash = sha256_segments(&[datagram]);
        let confirm_header = handshake_header(
            PacketType::SessionConfirm,
            0,
            CONFIRM_PAYLOAD_LENGTH,
            &self.config,
            now,
            self.header.handshake_id,
            self.header.session_id,
        );
        let confirm_datagram = encode_confirmation(
            confirm_header,
            &response_hash,
            SessionConfirmRole::Initiator,
            &transcript_hash,
            protectors.local_confirmation(),
        )?;
        let negotiated_datagram_size = self
            .config
            .max_datagram_size
            .min(response.max_datagram_size());
        self.confirmation = Some(InitiatorConfirmation {
            response_hash,
            transcript_hash,
            confirm_datagram,
            protectors,
            negotiated_datagram_size,
        });
        Ok(self
            .confirmation
            .as_ref()
            .map_or(&[], |confirmation| confirmation.confirm_datagram.as_slice()))
    }

    /// Borrows the exact initiator confirmation for loss recovery.
    #[must_use]
    pub fn confirmation_datagram(&self) -> Option<&[u8]> {
        self.confirmation
            .as_ref()
            .map(|confirmation| confirmation.confirm_datagram.as_slice())
    }

    /// Validates the responder confirmation and consumes the established session.
    ///
    /// # Errors
    ///
    /// Returns [`HandshakeError`] for a wrong phase, stale/mismatched header,
    /// response digest mismatch, or failed confirmation tag.
    pub fn accept_responder_confirmation(
        mut self,
        datagram: &[u8],
        now: u64,
    ) -> Result<EstablishedPeerSession, HandshakeError> {
        let confirmation = self
            .confirmation
            .take()
            .ok_or(HandshakeError::InvalidPhase {
                message: "responder SESSION_CONFIRM",
            })?;
        let view = SessionConfirmView::decode(datagram)?;
        validate_header_pair(self.header, view.header(), PacketType::SessionConfirm, true)?;
        validate_timestamp(view.header().timestamp, now)?;
        if view.role() != SessionConfirmRole::Responder {
            return Err(HandshakeError::ContextMismatch {
                field: "confirmation role",
            });
        }
        if view.response_hash() != &confirmation.response_hash {
            return Err(HandshakeError::DigestMismatch { digest: "response" });
        }
        confirmation.protectors.remote_confirmation().verify_tag(
            &confirmation.transcript_hash,
            view.authenticated_header(),
            view.authenticated_payload(),
            view.confirmation_tag(),
        )?;
        Ok(EstablishedPeerSession::new(
            self.config,
            self.header.session_id,
            confirmation.negotiated_datagram_size,
            confirmation.protectors,
            now,
        ))
    }
}

impl std::fmt::Debug for InitiatorHandshake {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("InitiatorHandshake")
            .field("peer_node_id", &self.config.peer_node_id)
            .field("handshake_id", &self.header.handshake_id)
            .field("session_id", &self.header.session_id)
            .field("awaiting_confirmation", &self.confirmation.is_some())
            .finish_non_exhaustive()
    }
}

struct InitiatorConfirmation {
    response_hash: [u8; 32],
    transcript_hash: [u8; 32],
    confirm_datagram: Vec<u8>,
    protectors: SessionProtectors,
    negotiated_datagram_size: u32,
}

/// A responder exchange retaining exact response and confirmation bytes.
pub struct ResponderHandshake {
    config: PeerHandshakeConfig,
    init_header: HandshakeHeader,
    response_datagram: Vec<u8>,
    response_hash: [u8; 32],
    transcript_hash: [u8; 32],
    protectors: Option<SessionProtectors>,
    negotiated_datagram_size: u32,
    initiator_confirmation: Option<Vec<u8>>,
    responder_confirmation: Option<Vec<u8>>,
}

impl ResponderHandshake {
    /// Authenticates an initiation and creates a fresh signed response.
    ///
    /// Structurally invalid or unauthenticated input returns an error and must
    /// be silently dropped by the caller rather than answered with a rejection.
    ///
    /// # Errors
    ///
    /// Returns [`HandshakeError`] for stale or mismatched context, grant or
    /// signature failure, randomness failure, or non-contributory agreement.
    pub fn respond(
        config: PeerHandshakeConfig,
        local_signing_key: &IdentitySigningKey,
        init_datagram: &[u8],
        now: u64,
    ) -> Result<Self, HandshakeError> {
        validate_local_signing_key(&config, local_signing_key)?;
        let init = SessionInitView::decode(init_datagram)?;
        validate_initiation_header(&config, init.header())?;
        validate_timestamp(init.header().timestamp, now)?;
        validate_grant_time(config.local_grant, now)?;
        validate_grant_time(config.peer_grant, now)?;
        if init.initiator_grant().grant() != config.peer_grant
            || init.signed_payload().get(..MEMBERSHIP_GRANT_LENGTH)
                != Some(config.peer_grant_bytes.as_slice())
        {
            return Err(HandshakeError::ContextMismatch {
                field: "initiator membership grant",
            });
        }
        if init.receiver_grant_serial() != config.local_grant.grant_serial {
            return Err(HandshakeError::ContextMismatch {
                field: "receiver grant serial",
            });
        }
        config.peer_public_key.verify_segments(
            SESSION_INIT_SIGNATURE_DOMAIN,
            &[init.signed_header(), init.signed_payload()],
            init.signature(),
        )?;

        let ephemeral = EphemeralSecret::generate()?;
        let ephemeral_public = ephemeral.public_key().to_bytes();
        let nonce = random_nonzero_array::<HANDSHAKE_NONCE_LENGTH>()?;
        let init_hash = sha256_segments(&[init_datagram]);
        let response_header = handshake_header(
            PacketType::SessionResponse,
            0,
            RESPONSE_PAYLOAD_LENGTH,
            &config,
            now,
            init.header().handshake_id,
            init.header().session_id,
        );
        let response_datagram = encode_signed_response(
            response_header,
            &config.local_grant_bytes,
            &init_hash,
            &ephemeral_public,
            &nonce,
            config.max_datagram_size,
            local_signing_key,
        )?;
        let transcript_hash = session_transcript_hash(init_datagram, &response_datagram);
        let shared =
            ephemeral.agree(EphemeralPublicKey::from_bytes(*init.initiator_ephemeral()))?;
        let protectors = derive_session_secrets(shared, &transcript_hash, SessionRole::Responder)?
            .into_protectors();
        let response_hash = sha256_segments(&[&response_datagram]);
        let negotiated_datagram_size = config.max_datagram_size.min(init.max_datagram_size());
        Ok(Self {
            config,
            init_header: init.header(),
            response_datagram,
            response_hash,
            transcript_hash,
            protectors: Some(protectors),
            negotiated_datagram_size,
            initiator_confirmation: None,
            responder_confirmation: None,
        })
    }

    /// Borrows the exact signed response used for retransmissions.
    #[must_use]
    pub fn response_datagram(&self) -> &[u8] {
        &self.response_datagram
    }

    /// Validates the initiator confirmation and returns a responder confirmation.
    ///
    /// Repeating an identical valid initiator confirmation returns the exact
    /// cached responder confirmation bytes.
    ///
    /// # Errors
    ///
    /// Returns [`HandshakeError`] for a wrong phase, stale or mismatched
    /// confirmation, response digest mismatch, or failed tag.
    pub fn accept_initiator_confirmation(
        &mut self,
        datagram: &[u8],
        now: u64,
    ) -> Result<&[u8], HandshakeError> {
        if self.responder_confirmation.is_some() {
            if self.initiator_confirmation.as_deref() != Some(datagram) {
                return Err(HandshakeError::ContextMismatch {
                    field: "retransmitted initiator confirmation",
                });
            }
            return self
                .responder_confirmation
                .as_deref()
                .ok_or(HandshakeError::InvalidPhase {
                    message: "cached responder SESSION_CONFIRM",
                });
        }
        let view = SessionConfirmView::decode(datagram)?;
        validate_header_pair(
            self.init_header,
            view.header(),
            PacketType::SessionConfirm,
            false,
        )?;
        validate_timestamp(view.header().timestamp, now)?;
        if view.role() != SessionConfirmRole::Initiator {
            return Err(HandshakeError::ContextMismatch {
                field: "confirmation role",
            });
        }
        if view.response_hash() != &self.response_hash {
            return Err(HandshakeError::DigestMismatch { digest: "response" });
        }
        let protectors = self
            .protectors
            .as_ref()
            .ok_or(HandshakeError::InvalidPhase {
                message: "initiator SESSION_CONFIRM",
            })?;
        protectors.remote_confirmation().verify_tag(
            &self.transcript_hash,
            view.authenticated_header(),
            view.authenticated_payload(),
            view.confirmation_tag(),
        )?;
        let response_header = handshake_header(
            PacketType::SessionConfirm,
            SESSION_CONFIRM_RESPONDER_FLAG,
            CONFIRM_PAYLOAD_LENGTH,
            &self.config,
            now,
            self.init_header.handshake_id,
            self.init_header.session_id,
        );
        let encoded = encode_confirmation(
            response_header,
            &self.response_hash,
            SessionConfirmRole::Responder,
            &self.transcript_hash,
            protectors.local_confirmation(),
        )?;
        self.initiator_confirmation = Some(datagram.to_vec());
        self.responder_confirmation = Some(encoded);
        Ok(self
            .responder_confirmation
            .as_ref()
            .map_or(&[], Vec::as_slice))
    }

    /// Consumes the responder state after its confirmation has been produced.
    ///
    /// # Errors
    ///
    /// Returns [`HandshakeError`] if no valid initiator confirmation has been accepted.
    pub fn into_established(mut self, now: u64) -> Result<EstablishedPeerSession, HandshakeError> {
        if self.responder_confirmation.is_none() {
            return Err(HandshakeError::InvalidPhase {
                message: "validated initiator SESSION_CONFIRM",
            });
        }
        let protectors = self.protectors.take().ok_or(HandshakeError::InvalidPhase {
            message: "available session protectors",
        })?;
        Ok(EstablishedPeerSession::new(
            self.config,
            self.init_header.session_id,
            self.negotiated_datagram_size,
            protectors,
            now,
        ))
    }
}

impl std::fmt::Debug for ResponderHandshake {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ResponderHandshake")
            .field("peer_node_id", &self.config.peer_node_id)
            .field("handshake_id", &self.init_header.handshake_id)
            .field("session_id", &self.init_header.session_id)
            .field("confirmed", &self.responder_confirmation.is_some())
            .finish_non_exhaustive()
    }
}

/// Confirmed peer-session material awaiting installation in a network runtime.
pub struct EstablishedPeerSession {
    config: PeerHandshakeConfig,
    session_id: u64,
    max_datagram_size: u32,
    protectors: SessionProtectors,
    established_at: u64,
    expires_at: u64,
}

impl EstablishedPeerSession {
    fn new(
        config: PeerHandshakeConfig,
        session_id: u64,
        max_datagram_size: u32,
        protectors: SessionProtectors,
        established_at: u64,
    ) -> Self {
        let policy_lifetime =
            Duration::from_secs(u64::from(config.policy.session_lifetime_seconds));
        let lifetime = policy_lifetime.min(MAX_SESSION_LIFETIME);
        let expires_at = established_at.saturating_add(lifetime.as_secs());
        Self {
            config,
            session_id,
            max_datagram_size,
            protectors,
            established_at,
            expires_at,
        }
    }

    /// Returns the confirmed random session ID.
    #[must_use]
    pub const fn session_id(&self) -> u64 {
        self.session_id
    }

    /// Returns the effective complete datagram bound for this path contract.
    #[must_use]
    pub const fn max_datagram_size(&self) -> u32 {
        self.max_datagram_size
    }

    /// Returns the establishment wall-clock timestamp.
    #[must_use]
    pub const fn established_at(&self) -> u64 {
        self.established_at
    }

    /// Returns the mandatory routine-rekey deadline.
    #[must_use]
    pub const fn expires_at(&self) -> u64 {
        self.expires_at
    }

    /// Consumes confirmed key material into a protected data session.
    ///
    /// # Errors
    ///
    /// Returns [`HandshakeError`] if the negotiated path contract cannot be
    /// represented by the data-session implementation.
    pub fn into_data_session(self) -> Result<PeerDataSession, HandshakeError> {
        Ok(PeerDataSession::new(
            self.config.policy,
            self.config.local_node_id,
            self.config.peer_node_id,
            self.session_id,
            self.config.controller_epoch,
            usize::try_from(self.max_datagram_size).map_err(|_| {
                HandshakeError::InvalidConfiguration {
                    reason: "negotiated datagram size is not representable",
                }
            })?,
            self.protectors,
        )?)
    }
}

impl std::fmt::Debug for EstablishedPeerSession {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("EstablishedPeerSession")
            .field("peer_node_id", &self.config.peer_node_id)
            .field("session_id", &self.session_id)
            .field("max_datagram_size", &self.max_datagram_size)
            .field("established_at", &self.established_at)
            .field("expires_at", &self.expires_at)
            .finish_non_exhaustive()
    }
}

fn validate_permissions(grant: MembershipGrant) -> Result<(), HandshakeError> {
    if !grant.permissions.can_send_data() || !grant.permissions.can_receive_data() {
        return Err(HandshakeError::InvalidConfiguration {
            reason: "membership grant lacks bidirectional data permission",
        });
    }
    Ok(())
}

fn validate_local_signing_key(
    config: &PeerHandshakeConfig,
    signing_key: &IdentitySigningKey,
) -> Result<(), HandshakeError> {
    if derive_node_id(signing_key.public_key()) != config.local_node_id {
        return Err(HandshakeError::InvalidConfiguration {
            reason: "signing key does not match local node ID",
        });
    }
    Ok(())
}

fn validate_grant_time(grant: MembershipGrant, now: u64) -> Result<(), HandshakeError> {
    if now < grant.not_before || now >= grant.not_after {
        return Err(HandshakeError::InvalidConfiguration {
            reason: "membership grant is outside its validity interval",
        });
    }
    Ok(())
}

fn validate_timestamp(timestamp: u64, now: u64) -> Result<(), HandshakeError> {
    if timestamp.abs_diff(now) > TIMESTAMP_TOLERANCE_SECONDS {
        return Err(HandshakeError::StaleTimestamp);
    }
    Ok(())
}

fn validate_initiation_header(
    config: &PeerHandshakeConfig,
    header: HandshakeHeader,
) -> Result<(), HandshakeError> {
    if header.common.network_id != config.policy.network_id {
        return Err(HandshakeError::ContextMismatch {
            field: "network ID",
        });
    }
    if header.sender_node_id != config.peer_node_id {
        return Err(HandshakeError::ContextMismatch {
            field: "sender node ID",
        });
    }
    if header.receiver_node_id != config.local_node_id {
        return Err(HandshakeError::ContextMismatch {
            field: "receiver node ID",
        });
    }
    if header.controller_epoch != config.controller_epoch {
        return Err(HandshakeError::ContextMismatch {
            field: "controller epoch",
        });
    }
    Ok(())
}

fn validate_header_pair(
    initiation: HandshakeHeader,
    candidate: HandshakeHeader,
    expected_type: PacketType,
    reverse_nodes: bool,
) -> Result<(), HandshakeError> {
    if candidate.common.packet_type != expected_type {
        return Err(HandshakeError::ContextMismatch {
            field: "packet type",
        });
    }
    if candidate.common.network_id != initiation.common.network_id {
        return Err(HandshakeError::ContextMismatch {
            field: "network ID",
        });
    }
    let (expected_sender, expected_receiver) = if reverse_nodes {
        (initiation.receiver_node_id, initiation.sender_node_id)
    } else {
        (initiation.sender_node_id, initiation.receiver_node_id)
    };
    if candidate.sender_node_id != expected_sender
        || candidate.receiver_node_id != expected_receiver
    {
        return Err(HandshakeError::ContextMismatch { field: "node IDs" });
    }
    if candidate.controller_epoch != initiation.controller_epoch {
        return Err(HandshakeError::ContextMismatch {
            field: "controller epoch",
        });
    }
    if candidate.handshake_id != initiation.handshake_id {
        return Err(HandshakeError::ContextMismatch {
            field: "handshake ID",
        });
    }
    if candidate.session_id != initiation.session_id {
        return Err(HandshakeError::ContextMismatch {
            field: "session ID",
        });
    }
    Ok(())
}

fn handshake_header(
    packet_type: PacketType,
    flags: u8,
    payload_length: u32,
    config: &PeerHandshakeConfig,
    timestamp: u64,
    handshake_id: u64,
    session_id: u64,
) -> HandshakeHeader {
    HandshakeHeader {
        common: CommonHeader {
            version: ProtocolVersion::CURRENT,
            packet_type,
            flags,
            header_length: HANDSHAKE_HEADER_LENGTH,
            payload_length,
            network_id: config.policy.network_id,
        },
        sender_node_id: config.local_node_id,
        receiver_node_id: config.peer_node_id,
        controller_epoch: config.controller_epoch,
        handshake_id,
        timestamp,
        session_id,
    }
}

fn encode_signed_init(
    header: HandshakeHeader,
    grant: &[u8; MEMBERSHIP_GRANT_LENGTH],
    receiver_grant_serial: GrantSerial,
    ephemeral: &[u8; 32],
    nonce: &[u8; 32],
    max_datagram_size: u32,
    signing_key: &IdentitySigningKey,
) -> Result<Vec<u8>, HandshakeError> {
    let mut encoded = vec![0_u8; HANDSHAKE_FIXED_HEADER_LENGTH + SESSION_INIT_PAYLOAD_LENGTH];
    encode_session_init(
        header,
        &[],
        SessionInitRef {
            initiator_grant: grant,
            receiver_grant_serial,
            initiator_ephemeral: ephemeral,
            initiator_nonce: nonce,
            max_datagram_size,
            signature: &[0; 64],
        },
        &mut encoded,
    )?;
    let draft = SessionInitView::decode(&encoded)?;
    let signature = signing_key.sign_segments(
        SESSION_INIT_SIGNATURE_DOMAIN,
        &[draft.signed_header(), draft.signed_payload()],
    )?;
    encode_session_init(
        header,
        &[],
        SessionInitRef {
            initiator_grant: grant,
            receiver_grant_serial,
            initiator_ephemeral: ephemeral,
            initiator_nonce: nonce,
            max_datagram_size,
            signature: &signature,
        },
        &mut encoded,
    )?;
    Ok(encoded)
}

fn encode_signed_response(
    header: HandshakeHeader,
    grant: &[u8; MEMBERSHIP_GRANT_LENGTH],
    init_hash: &[u8; 32],
    ephemeral: &[u8; 32],
    nonce: &[u8; 32],
    max_datagram_size: u32,
    signing_key: &IdentitySigningKey,
) -> Result<Vec<u8>, HandshakeError> {
    let mut encoded = vec![0_u8; HANDSHAKE_FIXED_HEADER_LENGTH + SESSION_RESPONSE_PAYLOAD_LENGTH];
    encode_session_response(
        header,
        &[],
        SessionResponseRef {
            responder_grant: grant,
            init_hash,
            responder_ephemeral: ephemeral,
            responder_nonce: nonce,
            max_datagram_size,
            signature: &[0; 64],
        },
        &mut encoded,
    )?;
    let draft = SessionResponseView::decode(&encoded)?;
    let signature = signing_key.sign_segments(
        SESSION_RESPONSE_SIGNATURE_DOMAIN,
        &[draft.signed_header(), draft.signed_payload()],
    )?;
    encode_session_response(
        header,
        &[],
        SessionResponseRef {
            responder_grant: grant,
            init_hash,
            responder_ephemeral: ephemeral,
            responder_nonce: nonce,
            max_datagram_size,
            signature: &signature,
        },
        &mut encoded,
    )?;
    Ok(encoded)
}

fn encode_confirmation(
    header: HandshakeHeader,
    response_hash: &[u8; 32],
    role: SessionConfirmRole,
    transcript_hash: &[u8; 32],
    authenticator: &stella_crypto::ConfirmationAuthenticator,
) -> Result<Vec<u8>, HandshakeError> {
    let mut encoded = vec![0_u8; HANDSHAKE_FIXED_HEADER_LENGTH + SESSION_CONFIRM_PAYLOAD_LENGTH];
    encode_session_confirm(
        header,
        &[],
        SessionConfirmRef {
            response_hash,
            role,
            confirmation_tag: &[0; 16],
        },
        &mut encoded,
    )?;
    let draft = SessionConfirmView::decode(&encoded)?;
    let tag = authenticator.create_tag(
        transcript_hash,
        draft.authenticated_header(),
        draft.authenticated_payload(),
    )?;
    encode_session_confirm(
        header,
        &[],
        SessionConfirmRef {
            response_hash,
            role,
            confirmation_tag: &tag,
        },
        &mut encoded,
    )?;
    Ok(encoded)
}

fn random_nonzero_u64() -> Result<u64, HandshakeError> {
    loop {
        let bytes = random_nonzero_array::<8>()?;
        let value = u64::from_be_bytes(bytes);
        if value != 0 {
            return Ok(value);
        }
    }
}

fn random_nonzero_array<const LENGTH: usize>() -> Result<[u8; LENGTH], HandshakeError> {
    loop {
        let mut bytes = [0_u8; LENGTH];
        getrandom::fill(&mut bytes)
            .map_err(|_| stella_crypto::CryptoError::RandomnessUnavailable)?;
        if bytes.iter().any(|byte| *byte != 0) {
            return Ok(bytes);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{HandshakeError, InitiatorHandshake, PeerHandshakeConfig, ResponderHandshake};
    use stella_common::{ControllerId, GrantSerial, NetworkId};
    use stella_crypto::{derive_node_id, IdentitySeed, IdentitySigningKey};
    use stella_proto::{
        encode_membership_grant, ConfidentialityPolicy, MembershipGrant, MembershipPermissions,
        NetworkPolicy, MEMBERSHIP_GRANT_LENGTH,
    };

    const NOW: u64 = 1_788_000_000;

    fn signing_key(byte: u8) -> IdentitySigningKey {
        IdentitySigningKey::from_seed(&IdentitySeed::from_bytes([byte; 32]))
    }

    fn policy() -> NetworkPolicy {
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
            network_id: NetworkId::from_bytes([3; 16]),
            policy_revision: 1,
        }
    }

    fn grant(key: &IdentitySigningKey, serial: u8) -> MembershipGrant {
        let public_key = key.public_key();
        MembershipGrant {
            confidentiality: ConfidentialityPolicy::Encrypt,
            permissions: MembershipPermissions::SEND_DATA | MembershipPermissions::RECEIVE_DATA,
            network_id: policy().network_id,
            node_id: derive_node_id(public_key),
            node_public_key: public_key.to_bytes(),
            controller_id: ControllerId::from_bytes([4; 16]),
            controller_epoch: 7,
            not_before: NOW - 60,
            not_after: NOW + 3_600,
            max_frame_size: 1_514,
            max_flood_peers: 8,
            flood_rate: 1_000,
            flood_burst: 2_000,
            policy_digest: [5; 32],
            grant_serial: GrantSerial::from_bytes([serial; 16]),
        }
    }

    fn grant_bytes(grant: MembershipGrant) -> [u8; MEMBERSHIP_GRANT_LENGTH] {
        let mut bytes = [0_u8; MEMBERSHIP_GRANT_LENGTH];
        encode_membership_grant(grant, &[6; 64], &mut bytes).expect("encode test grant");
        bytes
    }

    fn config(
        local_key: &IdentitySigningKey,
        peer_key: &IdentitySigningKey,
        local_serial: u8,
        peer_serial: u8,
    ) -> PeerHandshakeConfig {
        let local_grant = grant(local_key, local_serial);
        let peer_grant = grant(peer_key, peer_serial);
        PeerHandshakeConfig {
            policy: policy(),
            controller_epoch: 7,
            local_node_id: local_grant.node_id,
            peer_node_id: peer_grant.node_id,
            local_grant,
            local_grant_bytes: grant_bytes(local_grant),
            peer_grant,
            peer_grant_bytes: grant_bytes(peer_grant),
            peer_public_key: peer_key.public_key(),
            max_datagram_size: 1_200,
        }
    }

    fn frame(last_source: u8) -> Vec<u8> {
        let mut frame = vec![0_u8; 128];
        frame[..6].copy_from_slice(&[0xff; 6]);
        frame[6..12].copy_from_slice(&[0x02, 0, 0, 0, 0, last_source]);
        frame[12..14].copy_from_slice(&0x0800_u16.to_be_bytes());
        frame
    }

    #[test]
    fn four_message_handshake_establishes_bidirectional_data() {
        let alice_key = signing_key(11);
        let bob_key = signing_key(12);
        let alice_config = config(&alice_key, &bob_key, 21, 22);
        let bob_config = config(&bob_key, &alice_key, 22, 21);
        assert_ne!(
            alice_config.is_preferred_initiator(),
            bob_config.is_preferred_initiator()
        );

        let mut initiator =
            InitiatorHandshake::start(alice_config, &alice_key, NOW).expect("start initiation");
        let mut responder =
            ResponderHandshake::respond(bob_config, &bob_key, initiator.initiation_datagram(), NOW)
                .expect("authenticate initiation");
        let response = responder.response_datagram().to_vec();
        let initiator_confirm = initiator
            .accept_response(&response, NOW)
            .expect("authenticate response")
            .to_vec();
        let responder_confirm = responder
            .accept_initiator_confirmation(&initiator_confirm, NOW)
            .expect("confirm initiator keys")
            .to_vec();
        let bob_established = responder
            .into_established(NOW)
            .expect("establish responder");
        let alice_established = initiator
            .accept_responder_confirmation(&responder_confirm, NOW)
            .expect("confirm responder keys");
        assert_eq!(alice_established.session_id(), bob_established.session_id());
        assert_eq!(alice_established.max_datagram_size(), 1_200);

        let mut alice_data = alice_established.into_data_session().expect("alice data");
        let mut bob_data = bob_established.into_data_session().expect("bob data");
        let alice_frame = frame(1);
        let alice_packet = alice_data
            .protect_frame(&alice_frame)
            .expect("protect alice frame")
            .remove(0);
        assert_eq!(
            bob_data
                .accept_datagram(&alice_packet, std::time::Duration::ZERO)
                .expect("accept alice frame"),
            Some(alice_frame)
        );
        let bob_frame = frame(2);
        let bob_packet = bob_data
            .protect_frame(&bob_frame)
            .expect("protect bob frame")
            .remove(0);
        assert_eq!(
            alice_data
                .accept_datagram(&bob_packet, std::time::Duration::ZERO)
                .expect("accept bob frame"),
            Some(bob_frame)
        );
    }

    #[test]
    fn stale_and_mutated_initiations_fail_closed() {
        let alice_key = signing_key(31);
        let bob_key = signing_key(32);
        let alice_config = config(&alice_key, &bob_key, 41, 42);
        let bob_config = config(&bob_key, &alice_key, 42, 41);
        let initiation =
            InitiatorHandshake::start(alice_config, &alice_key, NOW).expect("start initiation");
        assert!(matches!(
            ResponderHandshake::respond(
                bob_config.clone(),
                &bob_key,
                initiation.initiation_datagram(),
                NOW + 121,
            ),
            Err(HandshakeError::StaleTimestamp)
        ));
        let mut mutated = initiation.initiation_datagram().to_vec();
        let signature_index = mutated.len() - 1;
        mutated[signature_index] ^= 1;
        assert!(matches!(
            ResponderHandshake::respond(bob_config, &bob_key, &mutated, NOW),
            Err(HandshakeError::Crypto(_))
        ));
    }
}
