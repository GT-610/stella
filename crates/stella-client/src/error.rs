//! Client runtime error definitions.

use std::{io, net::SocketAddr};

use stella_common::{NetworkId, RelayId};
use stella_proto::{ControlFieldType, ControlMessageType, ProtocolVersion};
use thiserror::Error;

/// Failure while configuring or operating a Stella client.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum ClientError {
    /// No TLS trust anchor was configured.
    #[error("at least one controller SPKI pin is required")]
    NoSpkiPins,
    /// The configured TLS server name is not a valid DNS name or IP address.
    #[error("invalid controller TLS server name")]
    InvalidTlsServerName,
    /// The operating system could not establish the controller TCP connection.
    #[error("could not connect to Stella controller at {address}: {source}")]
    Connect {
        /// Numeric controller address.
        address: SocketAddr,
        /// Underlying socket failure.
        #[source]
        source: io::Error,
    },
    /// TLS setup or handshake I/O failed.
    #[error("controller TLS connection failed: {0}")]
    Tls(#[source] io::Error),
    /// The controller closed TLS at a control-record boundary.
    #[error("controller closed the control connection")]
    ConnectionClosed,
    /// A control record, sequence, or message construction failed.
    #[error(transparent)]
    Control(#[from] stella_control::ControlError),
    /// A protocol object outside framed control handling failed validation.
    #[error(transparent)]
    Codec(#[from] stella_proto::CodecError),
    /// A Stella identity or proof failed cryptographic validation.
    #[error(transparent)]
    Crypto(#[from] stella_crypto::CryptoError),
    /// Authenticated network state failed contextual or cryptographic checks.
    #[error(transparent)]
    State(#[from] crate::StateError),
    /// The operating-system random generator failed.
    #[error("operating-system randomness is unavailable")]
    RandomnessUnavailable,
    /// The controller selected or advertised no compatible secure protocol.
    #[error("controller does not advertise a supported Stella protocol and suite")]
    NoCompatibleVersion,
    /// A message changed the operational protocol version after negotiation.
    #[error("expected control version {expected:?}, received {actual:?}")]
    ProtocolVersionMismatch {
        /// Version selected during authentication.
        expected: ProtocolVersion,
        /// Version found in the message header.
        actual: ProtocolVersion,
    },
    /// A requested feature is not registered in the negotiated version.
    #[error("{feature} requires control version {required:?}, negotiated {negotiated:?}")]
    ProtocolFeatureUnavailable {
        /// Stable feature name.
        feature: &'static str,
        /// Minimum protocol version implementing the feature.
        required: ProtocolVersion,
        /// Version selected for this connection.
        negotiated: ProtocolVersion,
    },
    /// The controller hello did not match the configured controller identity.
    #[error("controller hello identity does not match configured controller ID")]
    ControllerIdentityMismatch,
    /// An expected field was absent after structural message validation.
    #[error("validated {message_type:?} message is missing {field:?}")]
    MissingField {
        /// Message schema being processed.
        message_type: ControlMessageType,
        /// Required field that was absent.
        field: ControlFieldType,
    },
    /// An inbound message had the wrong state-machine type.
    #[error("expected {expected:?}, received {actual:?}")]
    UnexpectedMessage {
        /// Required next message type.
        expected: ControlMessageType,
        /// Actual message type.
        actual: ControlMessageType,
    },
    /// A direct response did not name the request it answers.
    #[error("expected response correlation {expected}, received {actual}")]
    UnexpectedCorrelation {
        /// Required request message ID.
        expected: u64,
        /// Received correlation ID.
        actual: u64,
    },
    /// Controller authentication was rejected with a registered status.
    #[error("controller rejected node authentication with status {status}")]
    AuthenticationRejected {
        /// Protocol status code from `AUTH_RESULT`.
        status: u16,
    },
    /// An authenticated network-scoped request was rejected.
    #[error("controller rejected {operation} for network {network_id} with status {status}")]
    NetworkRequestRejected {
        /// Stable operation name.
        operation: &'static str,
        /// Requested virtual network.
        network_id: NetworkId,
        /// Registered controller status code.
        status: u16,
    },
    /// Two authenticated control objects disagree about one field.
    #[error("{context} has inconsistent {field}")]
    InconsistentControlField {
        /// Relationship being checked.
        context: &'static str,
        /// First inconsistent field.
        field: &'static str,
    },
    /// The local wall clock predates the Unix epoch.
    #[error("system time is before the Unix epoch")]
    SystemTimeBeforeUnixEpoch,
    /// An operation requires a network that has no validated active view.
    #[error("network {network_id} is not active")]
    NetworkNotActive {
        /// Requested network.
        network_id: NetworkId,
    },
    /// The heartbeat counter cannot advance without wrapping.
    #[error("heartbeat counter is exhausted")]
    HeartbeatCounterExhausted,
    /// An authenticated active-session message arrived in the wrong direction.
    #[error("unexpected active controller message {actual:?}")]
    UnexpectedActiveMessage {
        /// Message type rejected in the active client receive path.
        actual: ControlMessageType,
    },
    /// A structurally validated delta carried no registered operation.
    #[error("peer delta has an invalid operation")]
    InvalidPeerDeltaOperation,
    /// A fixed-width field could not be represented by its protocol type.
    #[error("validated {field} has an unexpected width")]
    InvalidFieldWidth {
        /// Stable non-secret field name.
        field: &'static str,
    },
    /// A decoded deployment connectivity configuration used revision zero.
    #[error("connectivity configuration revision must be non-zero")]
    InvalidConnectivityConfigRevision,
    /// A controller tried to replace connectivity configuration with an older revision.
    #[error(
        "connectivity configuration revision {received} does not advance current revision {current}"
    )]
    ConnectivityConfigRevisionNotAdvanced {
        /// Currently active deployment configuration revision.
        current: u64,
        /// Received non-advancing revision.
        received: u64,
    },
    /// A relay credential was already expired when the configuration arrived.
    #[error("relay {relay_id} credential expired at {expires_at}, evaluated at {now}")]
    RelayCredentialExpired {
        /// Relay service whose credential is stale.
        relay_id: RelayId,
        /// Client validation Unix time.
        now: u64,
        /// Exclusive credential expiry Unix time.
        expires_at: u64,
    },
}
