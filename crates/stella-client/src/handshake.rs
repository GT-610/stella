//! Authenticated peer-session handshake state machines.

use std::{
    collections::{BTreeMap, BTreeSet},
    time::Duration,
};

use stella_common::{GrantSerial, NodeId};
use stella_crypto::{
    derive_node_id, derive_session_secrets, session_transcript_hash, sha256_segments,
    EphemeralPublicKey, EphemeralSecret, IdentityPublicKey, IdentitySigningKey, SessionProtectors,
    SessionRole,
};
use stella_proto::{
    encode_session_confirm, encode_session_init, encode_session_reject, encode_session_response,
    CommonHeader, HandshakeHeader, MembershipGrant, MembershipGrantView, NetworkPolicy, PacketType,
    ProtocolVersion, SessionConfirmRef, SessionConfirmRole, SessionConfirmView, SessionInitRef,
    SessionInitView, SessionRejectReason, SessionRejectRef, SessionRejectView, SessionResponseRef,
    SessionResponseView, HANDSHAKE_FIXED_HEADER_LENGTH, HANDSHAKE_NONCE_LENGTH,
    MAX_ENDPOINT_DATAGRAM_SIZE, MEMBERSHIP_GRANT_LENGTH, MEMBERSHIP_GRANT_SIGNATURE_DOMAIN,
    MIN_ENDPOINT_DATAGRAM_SIZE, SESSION_CONFIRM_PAYLOAD_LENGTH, SESSION_CONFIRM_RESPONDER_FLAG,
    SESSION_INIT_PAYLOAD_LENGTH, SESSION_INIT_SIGNATURE_DOMAIN, SESSION_REJECT_PAYLOAD_LENGTH,
    SESSION_REJECT_SIGNATURE_DOMAIN, SESSION_RESPONSE_PAYLOAD_LENGTH,
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
const REJECT_PAYLOAD_LENGTH: u32 = 104;
const INITIAL_RETRANSMIT_DELAY: Duration = Duration::from_millis(250);
const MAX_RETRANSMIT_DELAY: Duration = Duration::from_secs(2);
const HANDSHAKE_ATTEMPT_LIFETIME: Duration = Duration::from_secs(10);
const RESPONDER_CACHE_LIFETIME: Duration = Duration::from_secs(5 * 60);
const MAX_HANDSHAKES_PER_PEER: usize = 32;
const MAX_CACHED_HANDSHAKES: usize = 256;
const DEFAULT_REJECT_RETRY_DELAY: Duration = Duration::from_secs(1);

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
    controller_public_key: IdentityPublicKey,
    controller_epoch: u64,
    local_node_id: NodeId,
    peer_node_id: NodeId,
    local_grant: MembershipGrant,
    local_grant_bytes: [u8; MEMBERSHIP_GRANT_LENGTH],
    peer_grant: MembershipGrant,
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
            controller_public_key: network.controller_public_key(),
            controller_epoch: network.controller_epoch(),
            local_node_id,
            peer_node_id,
            local_grant: network.local_grant(),
            local_grant_bytes: *network.local_grant_bytes(),
            peer_grant: peer.grant(),
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
        if presented_grant_rejection(&self.config, &response.responder_grant(), now)?.is_some() {
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
        &mut self,
        datagram: &[u8],
        now: u64,
    ) -> Result<EstablishedPeerSession, HandshakeError> {
        let confirmation = self
            .confirmation
            .as_ref()
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
        let confirmation = self
            .confirmation
            .take()
            .ok_or(HandshakeError::InvalidPhase {
                message: "confirmed responder SESSION_CONFIRM",
            })?;
        Ok(EstablishedPeerSession::new(
            self.config.clone(),
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
        if presented_grant_rejection(&config, &init.initiator_grant(), now)?.is_some() {
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
        self.take_established(now)
    }

    /// Takes established key material while retaining cached handshake bytes.
    ///
    /// This is used by the replay cache so a lost responder confirmation can
    /// still be answered after the data session has been installed.
    ///
    /// # Errors
    ///
    /// Returns [`HandshakeError`] before confirmation or after material was already taken.
    pub fn take_established(&mut self, now: u64) -> Result<EstablishedPeerSession, HandshakeError> {
        if self.responder_confirmation.is_none() {
            return Err(HandshakeError::InvalidPhase {
                message: "validated initiator SESSION_CONFIRM",
            });
        }
        let protectors = self.protectors.take().ok_or(HandshakeError::InvalidPhase {
            message: "available session protectors",
        })?;
        Ok(EstablishedPeerSession::new(
            self.config.clone(),
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

/// One datagram selected by the handshake coordinator for transmission.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HandshakeTransmission {
    peer_node_id: NodeId,
    datagram: Vec<u8>,
}

impl HandshakeTransmission {
    fn new(peer_node_id: NodeId, datagram: Vec<u8>) -> Self {
        Self {
            peer_node_id,
            datagram,
        }
    }

    /// Returns the intended peer.
    #[must_use]
    pub const fn peer_node_id(&self) -> NodeId {
        self.peer_node_id
    }

    /// Borrows the exact datagram to send.
    #[must_use]
    pub fn datagram(&self) -> &[u8] {
        &self.datagram
    }

    /// Consumes the transmission into its destination peer and exact bytes.
    #[must_use]
    pub fn into_parts(self) -> (NodeId, Vec<u8>) {
        (self.peer_node_id, self.datagram)
    }
}

/// Result of dispatching one peer handshake datagram.
pub enum HandshakeEvent {
    /// The packet was a validly classifiable replay conflict or losing simultaneous initiation.
    Ignored,
    /// Send one response or confirmation to the named peer.
    Transmit(HandshakeTransmission),
    /// A signed rejection terminated the current outgoing attempt.
    Rejected {
        /// Authenticated rejecting peer.
        peer_node_id: NodeId,
        /// Authenticated diagnostic reason.
        reason: SessionRejectReason,
        /// Delay applied before a completely new initiation.
        retry_after: Duration,
    },
    /// Install a confirmed session, optionally after sending the included confirmation.
    Established {
        /// Confirmed remote peer.
        peer_node_id: NodeId,
        /// Final responder confirmation that must be sent before installation completes.
        transmission: Option<HandshakeTransmission>,
        /// Confirmed, non-cloneable session material.
        session: Box<EstablishedPeerSession>,
    },
}

impl std::fmt::Debug for HandshakeEvent {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Ignored => formatter.write_str("HandshakeEvent::Ignored"),
            Self::Transmit(transmission) => formatter
                .debug_tuple("HandshakeEvent::Transmit")
                .field(transmission)
                .finish(),
            Self::Rejected {
                peer_node_id,
                reason,
                retry_after,
            } => formatter
                .debug_struct("HandshakeEvent::Rejected")
                .field("peer_node_id", peer_node_id)
                .field("reason", reason)
                .field("retry_after", retry_after)
                .finish(),
            Self::Established {
                peer_node_id,
                transmission,
                session,
            } => formatter
                .debug_struct("HandshakeEvent::Established")
                .field("peer_node_id", peer_node_id)
                .field("transmission", transmission)
                .field("session", session)
                .finish(),
        }
    }
}

/// Bounded per-network handshake retries, replay cache, and simultaneous-initiation policy.
pub struct PeerHandshakeManager {
    local_node_id: NodeId,
    peers: BTreeMap<NodeId, PeerHandshakeConfig>,
    outgoing: BTreeMap<NodeId, OutgoingHandshake>,
    responders: BTreeMap<HandshakeCacheKey, CachedResponder>,
    active_session_ids: BTreeSet<(NodeId, u64)>,
    rejected_until: BTreeMap<NodeId, Duration>,
}

impl PeerHandshakeManager {
    /// Creates an empty manager for one local node and one network runtime.
    #[must_use]
    pub const fn new(local_node_id: NodeId) -> Self {
        Self {
            local_node_id,
            peers: BTreeMap::new(),
            outgoing: BTreeMap::new(),
            responders: BTreeMap::new(),
            active_session_ids: BTreeSet::new(),
            rejected_until: BTreeMap::new(),
        }
    }

    /// Adds or replaces authoritative configuration and clears stale exchange state.
    ///
    /// # Errors
    ///
    /// Returns [`HandshakeError`] when the configuration belongs to another local node.
    pub fn upsert_peer(&mut self, config: PeerHandshakeConfig) -> Result<(), HandshakeError> {
        if config.local_node_id != self.local_node_id {
            return Err(HandshakeError::InvalidConfiguration {
                reason: "peer configuration belongs to another local node",
            });
        }
        let peer_node_id = config.peer_node_id;
        if self.peers.get(&peer_node_id).is_some_and(|current| {
            current.controller_epoch != config.controller_epoch
                || current.local_grant.grant_serial != config.local_grant.grant_serial
                || current.peer_grant.grant_serial != config.peer_grant.grant_serial
                || current.policy != config.policy
                || current.max_datagram_size != config.max_datagram_size
        }) {
            self.clear_peer_exchange(peer_node_id);
        }
        self.rejected_until.remove(&peer_node_id);
        self.peers.insert(peer_node_id, config);
        Ok(())
    }

    /// Removes all configuration, handshakes, and session collision state for one peer.
    pub fn remove_peer(&mut self, peer_node_id: NodeId) {
        self.peers.remove(&peer_node_id);
        self.clear_peer_exchange(peer_node_id);
    }

    /// Returns whether this node already owns an in-progress initiator exchange.
    #[must_use]
    pub fn has_outgoing(&self, peer_node_id: NodeId) -> bool {
        self.outgoing.contains_key(&peer_node_id)
    }

    pub(crate) fn cancel_outgoing(&mut self, peer_node_id: NodeId) {
        self.outgoing.remove(&peer_node_id);
    }

    /// Returns whether rejection backoff permits a new initiation now.
    #[must_use]
    pub fn can_initiate(&self, peer_node_id: NodeId, now: Duration) -> bool {
        self.rejected_until
            .get(&peer_node_id)
            .is_none_or(|deadline| now >= *deadline)
    }

    /// Starts a fresh initiation and returns its first exact datagram.
    ///
    /// Repeated calls while an exchange is active return its current cached
    /// initiation or confirmation without creating new cryptographic state.
    ///
    /// # Errors
    ///
    /// Returns [`HandshakeError`] for an unknown peer or handshake construction failure.
    pub fn initiate(
        &mut self,
        peer_node_id: NodeId,
        signing_key: &IdentitySigningKey,
        wall_time: u64,
        monotonic_now: Duration,
    ) -> Result<HandshakeTransmission, HandshakeError> {
        if let Some(existing) = self.outgoing.get(&peer_node_id) {
            return Ok(HandshakeTransmission::new(
                peer_node_id,
                existing.current_datagram().to_vec(),
            ));
        }
        let config =
            self.peers
                .get(&peer_node_id)
                .cloned()
                .ok_or(HandshakeError::InvalidConfiguration {
                    reason: "cannot initiate to an unknown peer",
                })?;
        let handshake = InitiatorHandshake::start(config, signing_key, wall_time)?;
        let datagram = handshake.initiation_datagram().to_vec();
        self.outgoing.insert(
            peer_node_id,
            OutgoingHandshake {
                handshake,
                started_at: monotonic_now,
                next_send_at: monotonic_now.saturating_add(INITIAL_RETRANSMIT_DELAY),
                retransmit_delay: INITIAL_RETRANSMIT_DELAY,
            },
        );
        Ok(HandshakeTransmission::new(peer_node_id, datagram))
    }

    /// Returns due identical retransmissions and abandons attempts after ten seconds.
    #[must_use]
    pub fn poll_retransmissions(&mut self, now: Duration) -> Vec<HandshakeTransmission> {
        let expired: Vec<NodeId> = self
            .outgoing
            .iter()
            .filter_map(|(peer, outgoing)| {
                (now.saturating_sub(outgoing.started_at) >= HANDSHAKE_ATTEMPT_LIFETIME)
                    .then_some(*peer)
            })
            .collect();
        for peer in expired {
            self.outgoing.remove(&peer);
        }
        let mut transmissions = Vec::new();
        for (peer, outgoing) in &mut self.outgoing {
            if now < outgoing.next_send_at {
                continue;
            }
            transmissions.push(HandshakeTransmission::new(
                *peer,
                outgoing.current_datagram().to_vec(),
            ));
            outgoing.retransmit_delay = outgoing
                .retransmit_delay
                .saturating_mul(2)
                .min(MAX_RETRANSMIT_DELAY);
            outgoing.next_send_at = now.saturating_add(outgoing.retransmit_delay);
        }
        transmissions
    }

    /// Dispatches one structurally bounded handshake datagram.
    ///
    /// The caller must already have mapped the source endpoint to the claimed
    /// peer's current advertised endpoint set. Authentication remains mandatory
    /// here and endpoint mapping never substitutes for identity verification.
    ///
    /// # Errors
    ///
    /// Returns [`HandshakeError`] for malformed, stale, unauthenticated, unknown,
    /// or phase-inconsistent input. Replay conflicts are silently classified as ignored.
    pub fn handle_datagram(
        &mut self,
        datagram: &[u8],
        signing_key: &IdentitySigningKey,
        wall_time: u64,
        monotonic_now: Duration,
    ) -> Result<HandshakeEvent, HandshakeError> {
        self.expire_responders(monotonic_now);
        let common = CommonHeader::decode(datagram)?;
        match common.packet_type {
            PacketType::SessionInit => {
                self.handle_init(datagram, signing_key, wall_time, monotonic_now)
            }
            PacketType::SessionResponse => self.handle_response(datagram, wall_time),
            PacketType::SessionConfirm => self.handle_confirmation(datagram, wall_time),
            PacketType::SessionReject => self.handle_reject(datagram, wall_time, monotonic_now),
            PacketType::Data | PacketType::Keepalive => Err(HandshakeError::ContextMismatch {
                field: "handshake packet type",
            }),
        }
    }

    /// Forgets one retired data-session identifier so a future random value may reuse it.
    pub fn retire_session(&mut self, peer_node_id: NodeId, session_id: u64) {
        self.active_session_ids.remove(&(peer_node_id, session_id));
    }

    fn handle_init(
        &mut self,
        datagram: &[u8],
        signing_key: &IdentitySigningKey,
        wall_time: u64,
        monotonic_now: Duration,
    ) -> Result<HandshakeEvent, HandshakeError> {
        let init = SessionInitView::decode(datagram)?;
        let peer = init.header().sender_node_id;
        let key = HandshakeCacheKey {
            peer_node_id: peer,
            controller_epoch: init.header().controller_epoch,
            handshake_id: init.header().handshake_id,
        };
        if let Some(cached) = self.responders.get(&key) {
            if cached.init_datagram == datagram {
                return Ok(HandshakeEvent::Transmit(HandshakeTransmission::new(
                    peer,
                    cached.handshake.response_datagram().to_vec(),
                )));
            }
            return Ok(HandshakeEvent::Ignored);
        }
        let config =
            self.peers
                .get(&peer)
                .cloned()
                .ok_or(HandshakeError::InvalidConfiguration {
                    reason: "initiation came from an unknown peer",
                })?;
        if let Some(reason) = classify_authenticated_initiation(&config, &init, wall_time)? {
            let rejection = encode_signed_rejection(
                &config,
                init.header(),
                datagram,
                reason,
                0,
                signing_key,
                wall_time,
            )?;
            return Ok(HandshakeEvent::Transmit(HandshakeTransmission::new(
                peer, rejection,
            )));
        }
        if self
            .active_session_ids
            .contains(&(peer, init.header().session_id))
        {
            let rejection = encode_signed_rejection(
                &config,
                init.header(),
                datagram,
                SessionRejectReason::SessionCollision,
                0,
                signing_key,
                wall_time,
            )?;
            return Ok(HandshakeEvent::Transmit(HandshakeTransmission::new(
                peer, rejection,
            )));
        }
        if self.outgoing.contains_key(&peer) {
            if config.is_preferred_initiator() {
                return Ok(HandshakeEvent::Ignored);
            }
            self.outgoing.remove(&peer);
        }
        let handshake = ResponderHandshake::respond(config, signing_key, datagram, wall_time)?;
        let response = handshake.response_datagram().to_vec();
        self.make_responder_room(peer);
        self.responders.insert(
            key,
            CachedResponder {
                init_datagram: datagram.to_vec(),
                handshake,
                created_at: monotonic_now,
            },
        );
        Ok(HandshakeEvent::Transmit(HandshakeTransmission::new(
            peer, response,
        )))
    }

    fn handle_reject(
        &mut self,
        datagram: &[u8],
        wall_time: u64,
        monotonic_now: Duration,
    ) -> Result<HandshakeEvent, HandshakeError> {
        let rejection = SessionRejectView::decode(datagram)?;
        let peer = rejection.header().sender_node_id;
        let outgoing = self
            .outgoing
            .get(&peer)
            .ok_or(HandshakeError::InvalidPhase {
                message: "matching outgoing SESSION_INIT",
            })?;
        validate_header_pair(
            outgoing.handshake.header,
            rejection.header(),
            PacketType::SessionReject,
            true,
        )?;
        validate_timestamp(rejection.header().timestamp, wall_time)?;
        let expected_init_hash = sha256_segments(&[outgoing.handshake.initiation_datagram()]);
        if rejection.init_hash() != &expected_init_hash {
            return Err(HandshakeError::DigestMismatch { digest: "init" });
        }
        outgoing.handshake.config.peer_public_key.verify_segments(
            SESSION_REJECT_SIGNATURE_DOMAIN,
            &[rejection.signed_header(), rejection.signed_payload()],
            rejection.signature(),
        )?;
        let retry_after = if rejection.retry_after_ms() == 0 {
            DEFAULT_REJECT_RETRY_DELAY
        } else {
            Duration::from_millis(u64::from(rejection.retry_after_ms()))
        };
        self.outgoing.remove(&peer);
        self.rejected_until
            .insert(peer, monotonic_now.saturating_add(retry_after));
        Ok(HandshakeEvent::Rejected {
            peer_node_id: peer,
            reason: rejection.reason(),
            retry_after,
        })
    }

    fn handle_response(
        &mut self,
        datagram: &[u8],
        wall_time: u64,
    ) -> Result<HandshakeEvent, HandshakeError> {
        let response = SessionResponseView::decode(datagram)?;
        let peer = response.header().sender_node_id;
        let outgoing = self
            .outgoing
            .get_mut(&peer)
            .ok_or(HandshakeError::InvalidPhase {
                message: "matching outgoing SESSION_INIT",
            })?;
        let confirmation = outgoing
            .handshake
            .accept_response(datagram, wall_time)?
            .to_vec();
        Ok(HandshakeEvent::Transmit(HandshakeTransmission::new(
            peer,
            confirmation,
        )))
    }

    fn handle_confirmation(
        &mut self,
        datagram: &[u8],
        wall_time: u64,
    ) -> Result<HandshakeEvent, HandshakeError> {
        let confirmation = SessionConfirmView::decode(datagram)?;
        let peer = confirmation.header().sender_node_id;
        match confirmation.role() {
            SessionConfirmRole::Responder => {
                let outgoing =
                    self.outgoing
                        .get_mut(&peer)
                        .ok_or(HandshakeError::InvalidPhase {
                            message: "matching initiator confirmation state",
                        })?;
                let session = outgoing
                    .handshake
                    .accept_responder_confirmation(datagram, wall_time)?;
                self.outgoing.remove(&peer);
                self.active_session_ids.insert((peer, session.session_id()));
                Ok(HandshakeEvent::Established {
                    peer_node_id: peer,
                    transmission: None,
                    session: Box::new(session),
                })
            }
            SessionConfirmRole::Initiator => {
                let key = HandshakeCacheKey {
                    peer_node_id: peer,
                    controller_epoch: confirmation.header().controller_epoch,
                    handshake_id: confirmation.header().handshake_id,
                };
                let cached = self
                    .responders
                    .get_mut(&key)
                    .ok_or(HandshakeError::InvalidPhase {
                        message: "matching responder handshake state",
                    })?;
                let response = cached
                    .handshake
                    .accept_initiator_confirmation(datagram, wall_time)?
                    .to_vec();
                match cached.handshake.take_established(wall_time) {
                    Ok(session) => {
                        self.active_session_ids.insert((peer, session.session_id()));
                        Ok(HandshakeEvent::Established {
                            peer_node_id: peer,
                            transmission: Some(HandshakeTransmission::new(peer, response)),
                            session: Box::new(session),
                        })
                    }
                    Err(HandshakeError::InvalidPhase { .. }) => Ok(HandshakeEvent::Transmit(
                        HandshakeTransmission::new(peer, response),
                    )),
                    Err(error) => Err(error),
                }
            }
        }
    }

    fn make_responder_room(&mut self, peer: NodeId) {
        while self
            .responders
            .keys()
            .filter(|key| key.peer_node_id == peer)
            .count()
            >= MAX_HANDSHAKES_PER_PEER
            || self.responders.len() >= MAX_CACHED_HANDSHAKES
        {
            let peer_oldest = self
                .responders
                .iter()
                .filter(|(key, _)| key.peer_node_id == peer)
                .min_by_key(|(key, cached)| (cached.created_at, **key))
                .map(|(key, _)| *key);
            let oldest = peer_oldest.or_else(|| {
                self.responders
                    .iter()
                    .min_by_key(|(key, cached)| (cached.created_at, **key))
                    .map(|(key, _)| *key)
            });
            let Some(key) = oldest else {
                break;
            };
            self.responders.remove(&key);
        }
    }

    fn expire_responders(&mut self, now: Duration) {
        self.responders
            .retain(|_, cached| now.saturating_sub(cached.created_at) < RESPONDER_CACHE_LIFETIME);
    }

    fn clear_peer_exchange(&mut self, peer: NodeId) {
        self.outgoing.remove(&peer);
        self.responders.retain(|key, _| key.peer_node_id != peer);
        self.active_session_ids
            .retain(|(session_peer, _)| *session_peer != peer);
        self.rejected_until.remove(&peer);
    }
}

impl std::fmt::Debug for PeerHandshakeManager {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("PeerHandshakeManager")
            .field("local_node_id", &self.local_node_id)
            .field("configured_peers", &self.peers.len())
            .field("outgoing", &self.outgoing.len())
            .field("cached_responders", &self.responders.len())
            .field("active_session_ids", &self.active_session_ids.len())
            .field("rejection_backoffs", &self.rejected_until.len())
            .finish_non_exhaustive()
    }
}

struct OutgoingHandshake {
    handshake: InitiatorHandshake,
    started_at: Duration,
    next_send_at: Duration,
    retransmit_delay: Duration,
}

impl OutgoingHandshake {
    fn current_datagram(&self) -> &[u8] {
        self.handshake
            .confirmation_datagram()
            .unwrap_or_else(|| self.handshake.initiation_datagram())
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct HandshakeCacheKey {
    peer_node_id: NodeId,
    controller_epoch: u64,
    handshake_id: u64,
}

struct CachedResponder {
    init_datagram: Vec<u8>,
    handshake: ResponderHandshake,
    created_at: Duration,
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

fn classify_authenticated_initiation(
    config: &PeerHandshakeConfig,
    init: &SessionInitView<'_>,
    now: u64,
) -> Result<Option<SessionRejectReason>, HandshakeError> {
    let header = init.header();
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
    validate_timestamp(header.timestamp, now)?;
    config.peer_public_key.verify_segments(
        SESSION_INIT_SIGNATURE_DOMAIN,
        &[init.signed_header(), init.signed_payload()],
        init.signature(),
    )?;
    if header.controller_epoch != config.controller_epoch {
        return Ok(Some(SessionRejectReason::StaleEpoch));
    }
    if let Some(reason) = presented_grant_rejection(config, &init.initiator_grant(), now)? {
        return Ok(Some(reason));
    }
    if init.receiver_grant_serial() != config.local_grant.grant_serial {
        return Ok(Some(SessionRejectReason::PolicyMismatch));
    }
    if validate_grant_time(config.local_grant, now).is_err() {
        return Ok(Some(SessionRejectReason::GrantExpired));
    }
    Ok(None)
}

fn presented_grant_rejection(
    config: &PeerHandshakeConfig,
    view: &MembershipGrantView<'_>,
    now: u64,
) -> Result<Option<SessionRejectReason>, HandshakeError> {
    config.controller_public_key.verify_segments(
        MEMBERSHIP_GRANT_SIGNATURE_DOMAIN,
        &[view.signed_body()],
        view.signature(),
    )?;
    let supplied = view.grant();
    if now < supplied.not_before || now >= supplied.not_after {
        return Ok(Some(SessionRejectReason::GrantExpired));
    }
    if !same_grant_authority(supplied, config.peer_grant) {
        return Ok(Some(SessionRejectReason::PolicyMismatch));
    }
    Ok(None)
}

fn same_grant_authority(left: MembershipGrant, right: MembershipGrant) -> bool {
    left.confidentiality == right.confidentiality
        && left.permissions == right.permissions
        && left.network_id == right.network_id
        && left.node_id == right.node_id
        && left.node_public_key == right.node_public_key
        && left.controller_id == right.controller_id
        && left.controller_epoch == right.controller_epoch
        && left.max_frame_size == right.max_frame_size
        && left.max_flood_peers == right.max_flood_peers
        && left.flood_rate == right.flood_rate
        && left.flood_burst == right.flood_burst
        && left.policy_digest == right.policy_digest
        && left.grant_serial == right.grant_serial
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

fn encode_signed_rejection(
    config: &PeerHandshakeConfig,
    initiation: HandshakeHeader,
    init_datagram: &[u8],
    reason: SessionRejectReason,
    retry_after_ms: u32,
    signing_key: &IdentitySigningKey,
    timestamp: u64,
) -> Result<Vec<u8>, HandshakeError> {
    validate_local_signing_key(config, signing_key)?;
    let header = HandshakeHeader {
        common: CommonHeader {
            version: ProtocolVersion::CURRENT,
            packet_type: PacketType::SessionReject,
            flags: 0,
            header_length: HANDSHAKE_HEADER_LENGTH,
            payload_length: REJECT_PAYLOAD_LENGTH,
            network_id: initiation.common.network_id,
        },
        sender_node_id: config.local_node_id,
        receiver_node_id: config.peer_node_id,
        controller_epoch: initiation.controller_epoch,
        handshake_id: initiation.handshake_id,
        timestamp,
        session_id: initiation.session_id,
    };
    let init_hash = sha256_segments(&[init_datagram]);
    let mut encoded = vec![0_u8; HANDSHAKE_FIXED_HEADER_LENGTH + SESSION_REJECT_PAYLOAD_LENGTH];
    encode_session_reject(
        header,
        &[],
        SessionRejectRef {
            reason,
            retry_after_ms,
            init_hash: &init_hash,
            signature: &[0; 64],
        },
        &mut encoded,
    )?;
    let draft = SessionRejectView::decode(&encoded)?;
    let signature = signing_key.sign_segments(
        SESSION_REJECT_SIGNATURE_DOMAIN,
        &[draft.signed_header(), draft.signed_payload()],
    )?;
    encode_session_reject(
        header,
        &[],
        SessionRejectRef {
            reason,
            retry_after_ms,
            init_hash: &init_hash,
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
    use super::{
        encode_signed_init, encode_signed_rejection, HandshakeError, HandshakeEvent,
        HandshakeTransmission, InitiatorHandshake, PeerHandshakeConfig, PeerHandshakeManager,
        ResponderHandshake,
    };
    use stella_common::{GrantSerial, NetworkId};
    use stella_crypto::{derive_controller_id, derive_node_id, IdentitySeed, IdentitySigningKey};
    use stella_proto::{
        encode_membership_grant, ConfidentialityPolicy, MembershipGrant, MembershipPermissions,
        NetworkPolicy, SessionInitView, SessionRejectReason, SessionRejectView,
        MEMBERSHIP_GRANT_LENGTH, MEMBERSHIP_GRANT_SIGNATURE_DOMAIN,
        MEMBERSHIP_GRANT_SIGNED_BODY_LENGTH,
    };

    const NOW: u64 = 1_788_000_000;

    fn signing_key(byte: u8) -> IdentitySigningKey {
        IdentitySigningKey::from_seed(&IdentitySeed::from_bytes([byte; 32]))
    }

    fn controller_key() -> IdentitySigningKey {
        signing_key(99)
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
            controller_id: derive_controller_id(controller_key().public_key()),
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
        let mut signed_body = [0_u8; MEMBERSHIP_GRANT_SIGNED_BODY_LENGTH];
        grant
            .encode_signed_body(&mut signed_body)
            .expect("encode test grant body");
        let signature = controller_key()
            .sign_segments(MEMBERSHIP_GRANT_SIGNATURE_DOMAIN, &[&signed_body])
            .expect("sign test grant");
        let mut bytes = [0_u8; MEMBERSHIP_GRANT_LENGTH];
        encode_membership_grant(grant, &signature, &mut bytes).expect("encode test grant");
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
            controller_public_key: controller_key().public_key(),
            controller_epoch: 7,
            local_node_id: local_grant.node_id,
            peer_node_id: peer_grant.node_id,
            local_grant,
            local_grant_bytes: grant_bytes(local_grant),
            peer_grant,
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
        let mut alice_config = config(&alice_key, &bob_key, 21, 22);
        let mut bob_config = config(&bob_key, &alice_key, 22, 21);
        alice_config.peer_grant.not_before -= 30;
        bob_config.peer_grant.not_after += 30;
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

    fn transmitted(event: HandshakeEvent) -> HandshakeTransmission {
        match event {
            HandshakeEvent::Transmit(transmission) => transmission,
            other => panic!("expected transmission, got {other:?}"),
        }
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn manager_resolves_simultaneous_initiation_and_caches_replays() {
        let alice_key = signing_key(51);
        let bob_key = signing_key(52);
        let alice_config = config(&alice_key, &bob_key, 61, 62);
        let bob_config = config(&bob_key, &alice_key, 62, 61);
        let alice_id = alice_config.local_node_id;
        let bob_id = bob_config.local_node_id;
        let alice_preferred = alice_config.is_preferred_initiator();
        let mut alice = PeerHandshakeManager::new(alice_id);
        let mut bob = PeerHandshakeManager::new(bob_id);
        alice.upsert_peer(alice_config).expect("configure alice");
        bob.upsert_peer(bob_config).expect("configure bob");
        let alice_init = alice
            .initiate(bob_id, &alice_key, NOW, std::time::Duration::ZERO)
            .expect("alice initiation");
        let bob_init = bob
            .initiate(alice_id, &bob_key, NOW, std::time::Duration::ZERO)
            .expect("bob initiation");

        let (preferred, preferred_key, preferred_init, other, other_key, other_init) =
            if alice_preferred {
                (
                    &mut alice, &alice_key, alice_init, &mut bob, &bob_key, bob_init,
                )
            } else {
                (
                    &mut bob, &bob_key, bob_init, &mut alice, &alice_key, alice_init,
                )
            };
        assert!(matches!(
            preferred
                .handle_datagram(
                    other_init.datagram(),
                    preferred_key,
                    NOW,
                    std::time::Duration::ZERO,
                )
                .expect("classify losing initiation"),
            HandshakeEvent::Ignored
        ));
        let response = transmitted(
            other
                .handle_datagram(
                    preferred_init.datagram(),
                    other_key,
                    NOW,
                    std::time::Duration::ZERO,
                )
                .expect("respond to preferred initiation"),
        );
        let replay_response = transmitted(
            other
                .handle_datagram(
                    preferred_init.datagram(),
                    other_key,
                    NOW,
                    std::time::Duration::from_millis(1),
                )
                .expect("replay cached initiation"),
        );
        assert_eq!(response.datagram(), replay_response.datagram());

        let initiator_confirm = transmitted(
            preferred
                .handle_datagram(
                    response.datagram(),
                    preferred_key,
                    NOW,
                    std::time::Duration::from_millis(2),
                )
                .expect("accept response"),
        );
        let (responder_confirm, responder_session_id) = match other
            .handle_datagram(
                initiator_confirm.datagram(),
                other_key,
                NOW,
                std::time::Duration::from_millis(3),
            )
            .expect("accept initiator confirmation")
        {
            HandshakeEvent::Established {
                transmission: Some(transmission),
                session,
                ..
            } => (transmission, session.session_id()),
            event => panic!("expected responder establishment, got {event:?}"),
        };
        let initiator_session_id = match preferred
            .handle_datagram(
                responder_confirm.datagram(),
                preferred_key,
                NOW,
                std::time::Duration::from_millis(4),
            )
            .expect("accept responder confirmation")
        {
            HandshakeEvent::Established { session, .. } => session.session_id(),
            event => panic!("expected initiator establishment, got {event:?}"),
        };
        assert_eq!(initiator_session_id, responder_session_id);
        let repeated_confirm = transmitted(
            other
                .handle_datagram(
                    initiator_confirm.datagram(),
                    other_key,
                    NOW,
                    std::time::Duration::from_millis(5),
                )
                .expect("repeat cached confirmation"),
        );
        assert_eq!(repeated_confirm.datagram(), responder_confirm.datagram());

        let original_init =
            SessionInitView::decode(preferred_init.datagram()).expect("decode original init");
        let mut collision_header = original_init.header();
        collision_header.handshake_id = collision_header.handshake_id.wrapping_add(1).max(1);
        let preferred_config = preferred
            .peers
            .get(&other.local_node_id)
            .expect("preferred peer configuration");
        let collision_init = encode_signed_init(
            collision_header,
            &preferred_config.local_grant_bytes,
            preferred_config.peer_grant.grant_serial,
            original_init.initiator_ephemeral(),
            original_init.initiator_nonce(),
            original_init.max_datagram_size(),
            preferred_key,
        )
        .expect("signed colliding initiation");
        let collision_reject = transmitted(
            other
                .handle_datagram(
                    &collision_init,
                    other_key,
                    NOW,
                    std::time::Duration::from_millis(6),
                )
                .expect("reject session collision"),
        );
        assert_eq!(
            SessionRejectView::decode(collision_reject.datagram())
                .expect("decode collision rejection")
                .reason(),
            SessionRejectReason::SessionCollision
        );
    }

    #[test]
    fn manager_retransmits_with_backoff_and_abandons_at_deadline() {
        let alice_key = signing_key(71);
        let bob_key = signing_key(72);
        let alice_config = config(&alice_key, &bob_key, 81, 82);
        let bob_id = alice_config.peer_node_id;
        let alice_id = alice_config.local_node_id;
        let mut manager = PeerHandshakeManager::new(alice_id);
        manager.upsert_peer(alice_config).expect("configure peer");
        let first = manager
            .initiate(bob_id, &alice_key, NOW, std::time::Duration::ZERO)
            .expect("initiate");
        assert!(manager
            .poll_retransmissions(std::time::Duration::from_millis(249))
            .is_empty());
        let retry = manager.poll_retransmissions(std::time::Duration::from_millis(250));
        assert_eq!(retry.len(), 1);
        assert_eq!(retry[0].datagram(), first.datagram());
        assert!(manager
            .poll_retransmissions(std::time::Duration::from_millis(749))
            .is_empty());
        assert_eq!(
            manager
                .poll_retransmissions(std::time::Duration::from_millis(750))
                .len(),
            1
        );
        assert!(manager
            .poll_retransmissions(std::time::Duration::from_secs(10))
            .is_empty());
        let replacement = manager
            .initiate(
                bob_id,
                &alice_key,
                NOW + 10,
                std::time::Duration::from_secs(10),
            )
            .expect("new attempt after abandonment");
        assert_ne!(replacement.datagram(), first.datagram());
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn signed_rejections_are_classified_verified_and_backed_off() {
        let alice_key = signing_key(91);
        let bob_key = signing_key(92);
        let alice_config = config(&alice_key, &bob_key, 101, 102);
        let bob_config = config(&bob_key, &alice_key, 102, 101);
        let alice_id = alice_config.local_node_id;
        let bob_id = bob_config.local_node_id;
        let mut alice = PeerHandshakeManager::new(alice_id);
        alice
            .upsert_peer(alice_config.clone())
            .expect("configure alice");
        let initiation = alice
            .initiate(bob_id, &alice_key, NOW, std::time::Duration::ZERO)
            .expect("alice initiation");
        let init = SessionInitView::decode(initiation.datagram()).expect("decode initiation");
        let rejection = encode_signed_rejection(
            &bob_config,
            init.header(),
            initiation.datagram(),
            SessionRejectReason::SessionCollision,
            500,
            &bob_key,
            NOW,
        )
        .expect("signed rejection");
        match alice
            .handle_datagram(
                &rejection,
                &alice_key,
                NOW,
                std::time::Duration::from_secs(1),
            )
            .expect("verify rejection")
        {
            HandshakeEvent::Rejected {
                peer_node_id,
                reason,
                retry_after,
            } => {
                assert_eq!(peer_node_id, bob_id);
                assert_eq!(reason, SessionRejectReason::SessionCollision);
                assert_eq!(retry_after, std::time::Duration::from_millis(500));
            }
            event => panic!("expected authenticated rejection, got {event:?}"),
        }
        assert!(!alice.has_outgoing(bob_id));
        assert!(!alice.can_initiate(bob_id, std::time::Duration::from_millis(1_499)));
        assert!(alice.can_initiate(bob_id, std::time::Duration::from_millis(1_500)));

        let mut bob = PeerHandshakeManager::new(bob_id);
        bob.upsert_peer(bob_config.clone()).expect("configure bob");
        let mut stale_header = init.header();
        stale_header.controller_epoch -= 1;
        let mut stale_grant = alice_config.local_grant;
        stale_grant.controller_epoch -= 1;
        let stale_grant_bytes = grant_bytes(stale_grant);
        let stale_init = encode_signed_init(
            stale_header,
            &stale_grant_bytes,
            bob_config.local_grant.grant_serial,
            init.initiator_ephemeral(),
            init.initiator_nonce(),
            init.max_datagram_size(),
            &alice_key,
        )
        .expect("stale signed initiation");
        let stale_reject = transmitted(
            bob.handle_datagram(&stale_init, &bob_key, NOW, std::time::Duration::ZERO)
                .expect("reject stale epoch"),
        );
        assert_eq!(
            SessionRejectView::decode(stale_reject.datagram())
                .expect("decode stale rejection")
                .reason(),
            SessionRejectReason::StaleEpoch
        );

        let policy_init = encode_signed_init(
            init.header(),
            &alice_config.local_grant_bytes,
            GrantSerial::from_bytes([0xee; 16]),
            init.initiator_ephemeral(),
            init.initiator_nonce(),
            init.max_datagram_size(),
            &alice_key,
        )
        .expect("policy-mismatched signed initiation");
        let policy_reject = transmitted(
            bob.handle_datagram(
                &policy_init,
                &bob_key,
                NOW,
                std::time::Duration::from_millis(1),
            )
            .expect("reject policy mismatch"),
        );
        assert_eq!(
            SessionRejectView::decode(policy_reject.datagram())
                .expect("decode policy rejection")
                .reason(),
            SessionRejectReason::PolicyMismatch
        );
    }
}
