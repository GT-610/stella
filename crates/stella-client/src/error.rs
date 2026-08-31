//! Client runtime error definitions.

use std::{io, net::SocketAddr};

use stella_proto::{ControlFieldType, ControlMessageType};
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
    /// The operating-system random generator failed.
    #[error("operating-system randomness is unavailable")]
    RandomnessUnavailable,
    /// The controller selected or advertised no compatible secure protocol.
    #[error("controller does not advertise Stella version 0.1 suite 1")]
    NoCompatibleVersion,
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
    /// A fixed-width field could not be represented by its protocol type.
    #[error("validated {field} has an unexpected width")]
    InvalidFieldWidth {
        /// Stable non-secret field name.
        field: &'static str,
    },
}
