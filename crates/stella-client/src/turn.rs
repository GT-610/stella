//! Authenticated TURN UDP allocation and relayed datagram client.

use std::{
    collections::BTreeMap,
    fmt,
    net::{IpAddr, SocketAddr},
    sync::atomic::{AtomicBool, Ordering},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use hmac::{Hmac, KeyInit, Mac};
use sha2::Sha256;
use stella_common::RelayId;
use stella_crypto::sha256_segments;
use stella_proto::{
    decode_stun_xor_address, encode_stun_message, encode_stun_xor_address,
    encode_turn_channel_data, encode_turn_channel_data_stream, CodecError, RelayTrustRequirements,
    StunAttributeRef, StunAttributeType, StunClass, StunErrorCodeView, StunMessageRef,
    StunMessageType, StunMessageView, StunMethod, StunPasswordAlgorithm, StunTransactionId,
    TurnChannelDataView, TurnChannelNumber, MAX_RELAY_SPKI_PINS,
};
use stella_transport::{
    read_websocket_record, turn_websocket_config, write_websocket_record,
    Endpoint as TransportEndpoint, ReceivedDatagram, RelayCarrier, TransportCapabilities,
    TurnStream, TurnStreamError, WebSocketRecordError, MAX_TURN_STREAM_RECORD_SIZE,
    STELLA_TURN_WEBSOCKET_PATH, STELLA_TURN_WEBSOCKET_SUBPROTOCOL,
};
use thiserror::Error;
use tokio::{
    net::{TcpSocket, TcpStream, UdpSocket},
    sync::{mpsc, oneshot, Mutex},
    task::JoinHandle,
    time::{timeout_at, Instant},
};
use tokio_rustls::{client::TlsStream, rustls::pki_types::ServerName};
use tokio_tungstenite::{
    client_async_with_config,
    tungstenite::{
        client::IntoClientRequest,
        http::{
            header::{AUTHORIZATION, SEC_WEBSOCKET_EXTENSIONS, SEC_WEBSOCKET_PROTOCOL},
            HeaderValue, Request, Response,
        },
    },
    WebSocketStream,
};
use zeroize::Zeroizing;

use crate::tls;

type HmacSha256 = Hmac<Sha256>;

const TURN_UDP_COMMAND_CAPACITY: usize = 64;
const TURN_UDP_RECEIVE_CAPACITY: usize = 256;
const TURN_UDP_RECEIVE_BUFFER_SIZE: usize = u16::MAX as usize;
const INITIAL_RETRANSMIT_TIMEOUT: Duration = Duration::from_millis(250);
const MAX_RETRANSMIT_TIMEOUT: Duration = Duration::from_secs(1);
const DEFAULT_TRANSACTION_TIMEOUT: Duration = Duration::from_secs(5);
const PERMISSION_LIFETIME: Duration = Duration::from_secs(300);
const CHANNEL_LIFETIME: Duration = Duration::from_secs(600);
const MIN_REFRESH_INTERVAL: Duration = Duration::from_secs(1);
const MAX_TURN_UDP_DATAGRAM_SIZE: usize = 65_503;
const REQUESTED_TRANSPORT_UDP: [u8; 4] = [17, 0, 0, 0];

/// Configuration for one authenticated TURN allocation reached over UDP.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TurnUdpClientConfig {
    /// Stable identity of the configured relay service.
    pub relay_id: RelayId,
    /// Numeric TURN UDP listener address.
    pub server_address: SocketAddr,
    /// Local client socket address; port zero requests an ephemeral port.
    pub bind_address: SocketAddr,
    /// Largest complete Stella datagram carried through this allocation.
    pub max_datagram_size: usize,
    /// Requested allocation lifetime, capped by the relay.
    pub allocation_lifetime_seconds: u32,
    /// Advertised allocation inactivity timeout.
    pub idle_timeout_seconds: u32,
    /// Complete retransmitting transaction deadline.
    pub transaction_timeout: Duration,
}

impl TurnUdpClientConfig {
    /// Creates a conservative TURN UDP client configuration.
    #[must_use]
    pub const fn new(
        relay_id: RelayId,
        server_address: SocketAddr,
        bind_address: SocketAddr,
    ) -> Self {
        Self {
            relay_id,
            server_address,
            bind_address,
            max_datagram_size: 1_200,
            allocation_lifetime_seconds: 600,
            idle_timeout_seconds: 120,
            transaction_timeout: DEFAULT_TRANSACTION_TIMEOUT,
        }
    }

    fn validate(self) -> Result<(), TurnUdpError> {
        TurnClientConfig::from(self).validate()
    }
}

/// Configuration for one authenticated TURN allocation reached over TCP.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TurnTcpClientConfig {
    /// Stable identity of the configured relay service.
    pub relay_id: RelayId,
    /// Numeric TURN TCP listener address.
    pub server_address: SocketAddr,
    /// Local client socket address; port zero requests an ephemeral port.
    pub bind_address: SocketAddr,
    /// Largest complete Stella datagram carried through this allocation.
    pub max_datagram_size: usize,
    /// Requested allocation lifetime, capped by the relay.
    pub allocation_lifetime_seconds: u32,
    /// Advertised allocation inactivity timeout.
    pub idle_timeout_seconds: u32,
    /// Complete reliable transaction deadline.
    pub transaction_timeout: Duration,
}

impl TurnTcpClientConfig {
    /// Creates a conservative TURN TCP client configuration.
    #[must_use]
    pub const fn new(
        relay_id: RelayId,
        server_address: SocketAddr,
        bind_address: SocketAddr,
    ) -> Self {
        Self {
            relay_id,
            server_address,
            bind_address,
            max_datagram_size: 1_200,
            allocation_lifetime_seconds: 600,
            idle_timeout_seconds: 120,
            transaction_timeout: DEFAULT_TRANSACTION_TIMEOUT,
        }
    }

    fn validate(self) -> Result<(), TurnUdpError> {
        TurnClientConfig::from(self).validate()
    }
}

/// Configuration for one authenticated TURN allocation reached over TLS.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TurnTlsClientConfig {
    /// Stable identity of the configured relay service.
    pub relay_id: RelayId,
    /// Numeric TURN TLS listener address.
    pub server_address: SocketAddr,
    /// Local client socket address; port zero requests an ephemeral port.
    pub bind_address: SocketAddr,
    /// Canonical certificate server name, or empty for a pin-only numeric address.
    pub tls_server_name: String,
    /// Certificate checks required by the authenticated controller configuration.
    pub trust: RelayTrustRequirements,
    /// Canonically ordered accepted SHA-256 `SubjectPublicKeyInfo` digests.
    pub spki_pins: Vec<[u8; 32]>,
    /// Largest complete Stella datagram carried through this allocation.
    pub max_datagram_size: usize,
    /// Requested allocation lifetime, capped by the relay.
    pub allocation_lifetime_seconds: u32,
    /// Advertised allocation inactivity timeout.
    pub idle_timeout_seconds: u32,
    /// Complete reliable transaction deadline.
    pub transaction_timeout: Duration,
}

impl TurnTlsClientConfig {
    /// Creates a conservative TURN TLS client configuration.
    #[must_use]
    pub fn new(
        relay_id: RelayId,
        server_address: SocketAddr,
        bind_address: SocketAddr,
        tls_server_name: String,
        trust: RelayTrustRequirements,
        spki_pins: Vec<[u8; 32]>,
    ) -> Self {
        Self {
            relay_id,
            server_address,
            bind_address,
            tls_server_name,
            trust,
            spki_pins,
            max_datagram_size: 1_200,
            allocation_lifetime_seconds: 600,
            idle_timeout_seconds: 120,
            transaction_timeout: DEFAULT_TRANSACTION_TIMEOUT,
        }
    }

    fn validate(&self) -> Result<(), TurnUdpError> {
        TurnClientConfig::from(self).validate()?;
        if self.trust.is_empty() {
            return Err(TurnUdpError::InvalidConfig {
                field: "TURN TLS trust",
                reason: "must require Web PKI validation or an SPKI pin",
            });
        }
        if self.trust.contains(RelayTrustRequirements::WEB_PKI) && self.tls_server_name.is_empty() {
            return Err(TurnUdpError::InvalidConfig {
                field: "TURN TLS server name",
                reason: "must be present when Web PKI validation is required",
            });
        }
        if self.trust.contains(RelayTrustRequirements::SPKI_PIN) == self.spki_pins.is_empty() {
            return Err(TurnUdpError::InvalidConfig {
                field: "TURN TLS SPKI pins",
                reason: "must be present exactly when SPKI validation is required",
            });
        }
        if self.spki_pins.len() > usize::from(MAX_RELAY_SPKI_PINS) {
            return Err(TurnUdpError::InvalidConfig {
                field: "TURN TLS SPKI pins",
                reason: "exceeds the protocol maximum",
            });
        }
        if self.spki_pins.windows(2).any(|pair| pair[0] >= pair[1]) {
            return Err(TurnUdpError::InvalidConfig {
                field: "TURN TLS SPKI pins",
                reason: "must be unique and in canonical order",
            });
        }
        let _server_name = self.server_name()?;
        Ok(())
    }

    fn server_name(&self) -> Result<ServerName<'static>, TurnUdpError> {
        if self.tls_server_name.is_empty() {
            return Ok(ServerName::IpAddress(self.server_address.ip().into()));
        }
        ServerName::try_from(self.tls_server_name.clone()).map_err(|_| {
            TurnUdpError::InvalidConfig {
                field: "TURN TLS server name",
                reason: "must be a valid DNS name or IP address",
            }
        })
    }
}

/// Configuration for one authenticated TURN allocation reached over secure WebSocket.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TurnWebSocketClientConfig {
    /// Stable identity of the configured relay service.
    pub relay_id: RelayId,
    /// Numeric HTTPS WebSocket listener address.
    pub server_address: SocketAddr,
    /// Local client socket address; port zero requests an ephemeral port.
    pub bind_address: SocketAddr,
    /// Canonical certificate server name, or empty for a pin-only numeric address.
    pub tls_server_name: String,
    /// Certificate checks required by the authenticated controller configuration.
    pub trust: RelayTrustRequirements,
    /// Canonically ordered accepted SHA-256 `SubjectPublicKeyInfo` digests.
    pub spki_pins: Vec<[u8; 32]>,
    /// Largest complete Stella datagram carried through this allocation.
    pub max_datagram_size: usize,
    /// Requested allocation lifetime, capped by the relay.
    pub allocation_lifetime_seconds: u32,
    /// Advertised allocation inactivity timeout.
    pub idle_timeout_seconds: u32,
    /// Complete reliable transaction deadline.
    pub transaction_timeout: Duration,
}

impl TurnWebSocketClientConfig {
    /// Creates a conservative secure WebSocket TURN client configuration.
    #[must_use]
    pub fn new(
        relay_id: RelayId,
        server_address: SocketAddr,
        bind_address: SocketAddr,
        tls_server_name: String,
        trust: RelayTrustRequirements,
        spki_pins: Vec<[u8; 32]>,
    ) -> Self {
        Self {
            relay_id,
            server_address,
            bind_address,
            tls_server_name,
            trust,
            spki_pins,
            max_datagram_size: 1_200,
            allocation_lifetime_seconds: 600,
            idle_timeout_seconds: 120,
            transaction_timeout: DEFAULT_TRANSACTION_TIMEOUT,
        }
    }

    fn validate(&self) -> Result<(), TurnUdpError> {
        TurnClientConfig::from(self).validate()?;
        if self.trust.is_empty() {
            return Err(TurnUdpError::InvalidConfig {
                field: "TURN WebSocket TLS trust",
                reason: "must require Web PKI validation or an SPKI pin",
            });
        }
        if self.trust.contains(RelayTrustRequirements::WEB_PKI) && self.tls_server_name.is_empty() {
            return Err(TurnUdpError::InvalidConfig {
                field: "TURN WebSocket TLS server name",
                reason: "must be present when Web PKI validation is required",
            });
        }
        if self.trust.contains(RelayTrustRequirements::SPKI_PIN) == self.spki_pins.is_empty() {
            return Err(TurnUdpError::InvalidConfig {
                field: "TURN WebSocket TLS SPKI pins",
                reason: "must be present exactly when SPKI validation is required",
            });
        }
        if self.spki_pins.len() > usize::from(MAX_RELAY_SPKI_PINS) {
            return Err(TurnUdpError::InvalidConfig {
                field: "TURN WebSocket TLS SPKI pins",
                reason: "exceeds the protocol maximum",
            });
        }
        if self.spki_pins.windows(2).any(|pair| pair[0] >= pair[1]) {
            return Err(TurnUdpError::InvalidConfig {
                field: "TURN WebSocket TLS SPKI pins",
                reason: "must be unique and in canonical order",
            });
        }
        let _server_name = self.server_name()?;
        Ok(())
    }

    fn server_name(&self) -> Result<ServerName<'static>, TurnUdpError> {
        if self.tls_server_name.is_empty() {
            return Ok(ServerName::IpAddress(self.server_address.ip().into()));
        }
        ServerName::try_from(self.tls_server_name.clone()).map_err(|_| {
            TurnUdpError::InvalidConfig {
                field: "TURN WebSocket TLS server name",
                reason: "must be a valid DNS name or IP address",
            }
        })
    }

    fn authority(&self) -> String {
        if self.tls_server_name.is_empty() {
            return self.server_address.to_string();
        }
        match self.tls_server_name.parse::<IpAddr>() {
            Ok(IpAddr::V6(address)) => format!("[{address}]:{}", self.server_address.port()),
            _ => format!("{}:{}", self.tls_server_name, self.server_address.port()),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct TurnClientConfig {
    carrier: RelayCarrier,
    relay_id: RelayId,
    server_address: SocketAddr,
    bind_address: SocketAddr,
    max_datagram_size: usize,
    allocation_lifetime_seconds: u32,
    idle_timeout_seconds: u32,
    transaction_timeout: Duration,
}

impl TurnClientConfig {
    fn validate(self) -> Result<(), TurnUdpError> {
        if self.relay_id.is_zero() {
            return Err(TurnUdpError::InvalidConfig {
                field: "relay ID",
                reason: "must be non-zero",
            });
        }
        if self.server_address.port() == 0 || self.server_address.ip().is_unspecified() {
            return Err(TurnUdpError::InvalidConfig {
                field: "server address",
                reason: "must use a specified address and non-zero port",
            });
        }
        if self.server_address.is_ipv4() != self.bind_address.is_ipv4() {
            return Err(TurnUdpError::InvalidConfig {
                field: "bind address",
                reason: "must use the TURN server address family",
            });
        }
        if !(1_200..=MAX_TURN_UDP_DATAGRAM_SIZE).contains(&self.max_datagram_size) {
            return Err(TurnUdpError::InvalidConfig {
                field: "maximum datagram size",
                reason: "must be between 1200 and 65503 bytes",
            });
        }
        if self.allocation_lifetime_seconds == 0 {
            return Err(TurnUdpError::InvalidConfig {
                field: "allocation lifetime",
                reason: "must be non-zero",
            });
        }
        if self.idle_timeout_seconds == 0 {
            return Err(TurnUdpError::InvalidConfig {
                field: "idle timeout",
                reason: "must be non-zero",
            });
        }
        if self.transaction_timeout < INITIAL_RETRANSMIT_TIMEOUT {
            return Err(TurnUdpError::InvalidConfig {
                field: "transaction timeout",
                reason: "must be at least 250 milliseconds",
            });
        }
        Ok(())
    }
}

impl From<TurnUdpClientConfig> for TurnClientConfig {
    fn from(config: TurnUdpClientConfig) -> Self {
        Self {
            carrier: RelayCarrier::TurnUdp,
            relay_id: config.relay_id,
            server_address: config.server_address,
            bind_address: config.bind_address,
            max_datagram_size: config.max_datagram_size,
            allocation_lifetime_seconds: config.allocation_lifetime_seconds,
            idle_timeout_seconds: config.idle_timeout_seconds,
            transaction_timeout: config.transaction_timeout,
        }
    }
}

impl From<TurnTcpClientConfig> for TurnClientConfig {
    fn from(config: TurnTcpClientConfig) -> Self {
        Self {
            carrier: RelayCarrier::TurnTcp,
            relay_id: config.relay_id,
            server_address: config.server_address,
            bind_address: config.bind_address,
            max_datagram_size: config.max_datagram_size,
            allocation_lifetime_seconds: config.allocation_lifetime_seconds,
            idle_timeout_seconds: config.idle_timeout_seconds,
            transaction_timeout: config.transaction_timeout,
        }
    }
}

impl From<&TurnTlsClientConfig> for TurnClientConfig {
    fn from(config: &TurnTlsClientConfig) -> Self {
        Self {
            carrier: RelayCarrier::TurnTls,
            relay_id: config.relay_id,
            server_address: config.server_address,
            bind_address: config.bind_address,
            max_datagram_size: config.max_datagram_size,
            allocation_lifetime_seconds: config.allocation_lifetime_seconds,
            idle_timeout_seconds: config.idle_timeout_seconds,
            transaction_timeout: config.transaction_timeout,
        }
    }
}

impl From<&TurnWebSocketClientConfig> for TurnClientConfig {
    fn from(config: &TurnWebSocketClientConfig) -> Self {
        Self {
            carrier: RelayCarrier::SecureWebSocket,
            relay_id: config.relay_id,
            server_address: config.server_address,
            bind_address: config.bind_address,
            max_datagram_size: config.max_datagram_size,
            allocation_lifetime_seconds: config.allocation_lifetime_seconds,
            idle_timeout_seconds: config.idle_timeout_seconds,
            transaction_timeout: config.transaction_timeout,
        }
    }
}

/// Controller-issued TURN long-term credentials owned and redacted by the client.
#[derive(Clone, Eq, PartialEq)]
pub struct TurnCredentials {
    username: Zeroizing<Vec<u8>>,
    password: Zeroizing<Vec<u8>>,
    expires_at: u64,
}

impl TurnCredentials {
    /// Creates credentials with an exclusive Unix expiry.
    ///
    /// # Errors
    ///
    /// Returns [`TurnUdpError`] when either value is empty or expiry is zero.
    pub fn new(
        username: Vec<u8>,
        password: Vec<u8>,
        expires_at: u64,
    ) -> Result<Self, TurnUdpError> {
        if username.is_empty() || password.is_empty() {
            return Err(TurnUdpError::InvalidConfig {
                field: "TURN credentials",
                reason: "username and password must be non-empty",
            });
        }
        if expires_at == 0 {
            return Err(TurnUdpError::InvalidConfig {
                field: "TURN credential expiry",
                reason: "must be non-zero",
            });
        }
        Ok(Self {
            username: Zeroizing::new(username),
            password: Zeroizing::new(password),
            expires_at,
        })
    }

    /// Borrows the exact TURN `USERNAME` value.
    #[must_use]
    pub fn username(&self) -> &[u8] {
        &self.username
    }

    /// Returns the exclusive credential expiry Unix time.
    #[must_use]
    pub const fn expires_at(&self) -> u64 {
        self.expires_at
    }

    fn validate_time(&self, now: u64) -> Result<(), TurnUdpError> {
        if self.expires_at <= now {
            return Err(TurnUdpError::CredentialExpired {
                expires_at: self.expires_at,
                now,
            });
        }
        Ok(())
    }
}

impl fmt::Debug for TurnCredentials {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("TurnCredentials")
            .field("username_length", &self.username.len())
            .field("password_length", &self.password.len())
            .field("expires_at", &self.expires_at)
            .finish_non_exhaustive()
    }
}

/// Failure while creating or operating one TURN client allocation.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum TurnUdpError {
    /// A stable client configuration bound is invalid.
    #[error("invalid TURN client configuration for {field}: {reason}")]
    InvalidConfig {
        /// Stable field name.
        field: &'static str,
        /// Stable non-secret rule description.
        reason: &'static str,
    },
    /// Controller-issued credentials are no longer valid.
    #[error("TURN credentials expired at {expires_at}, evaluated at {now}")]
    CredentialExpired {
        /// Exclusive expiry Unix time.
        expires_at: u64,
        /// Current Unix time.
        now: u64,
    },
    /// Operating-system randomness was unavailable.
    #[error("operating-system randomness is unavailable for TURN transaction ID")]
    RandomnessUnavailable,
    /// A local socket operation failed.
    #[error("TURN {operation} failed")]
    Io {
        /// Stable operation name.
        operation: &'static str,
        /// Original operating-system error.
        #[source]
        source: std::io::Error,
    },
    /// A STUN or TURN record was structurally invalid.
    #[error(transparent)]
    Codec(#[from] CodecError),
    /// Reliable TURN record framing or byte-stream I/O failed.
    #[error(transparent)]
    Stream(#[from] TurnStreamError),
    /// Secure WebSocket record framing, protocol handling, or I/O failed.
    #[error(transparent)]
    WebSocket(#[from] WebSocketRecordError),
    /// The HTTPS upgrade did not select the exact Stella WebSocket profile.
    #[error("TURN WebSocket upgrade response is invalid: {detail}")]
    InvalidWebSocketUpgrade {
        /// Stable non-secret rule description.
        detail: &'static str,
    },
    /// A retransmitting request received no matching response before its deadline.
    #[error("TURN {method:?} transaction timed out")]
    TransactionTimeout {
        /// Timed-out TURN method.
        method: StunMethod,
    },
    /// A matching response had an unexpected class, method, or transaction context.
    #[error("TURN {method:?} response is inconsistent with its request")]
    UnexpectedResponse {
        /// Requested method.
        method: StunMethod,
    },
    /// The relay rejected an authenticated request.
    #[error("TURN relay rejected {method:?} with status {code}")]
    Rejected {
        /// Rejected method.
        method: StunMethod,
        /// Registered STUN/TURN error code.
        code: u16,
    },
    /// A required response attribute was absent or duplicated.
    #[error("TURN response has invalid {attribute:?} cardinality")]
    InvalidAttributeCardinality {
        /// Affected attribute.
        attribute: StunAttributeType,
    },
    /// A response attribute had invalid semantics.
    #[error("TURN response attribute is invalid: {detail}")]
    InvalidAttribute {
        /// Stable non-secret rule description.
        detail: &'static str,
    },
    /// An authenticated response failed HMAC verification.
    #[error("TURN response MESSAGE-INTEGRITY-SHA256 verification failed")]
    ResponseIntegrity,
    /// A caller attempted to send a datagram larger than the allocation limit.
    #[error("TURN datagram length {actual} exceeds configured maximum {maximum}")]
    DatagramTooLarge {
        /// Attempted datagram length.
        actual: usize,
        /// Configured maximum.
        maximum: usize,
    },
    /// Caller storage cannot hold a complete relayed datagram.
    #[error("receive output has {remaining} bytes but relayed datagram needs {needed}")]
    ReceiveBufferTooSmall {
        /// Complete relayed datagram length.
        needed: usize,
        /// Caller buffer capacity.
        remaining: usize,
    },
    /// A concrete client method received an endpoint for another carrier.
    #[error("endpoint does not match this TURN allocation carrier or relay")]
    UnsupportedEndpoint,
    /// The allocation actor stopped before completing an operation.
    #[error("TURN allocation actor stopped")]
    ActorStopped,
    /// The allocation actor task panicked or was cancelled unexpectedly.
    #[error("TURN allocation actor task failed")]
    TaskFailed,
    /// Time arithmetic overflowed a monotonic deadline.
    #[error("TURN deadline overflowed for {field}")]
    DeadlineOverflow {
        /// Stable deadline field name.
        field: &'static str,
    },
    /// The dynamic TURN channel number space was exhausted.
    #[error("TURN channel number space is exhausted")]
    ChannelSpaceExhausted,
}

/// TURN TCP client error type shared with the carrier-neutral TURN state machine.
pub type TurnTcpError = TurnUdpError;

/// TURN TLS client error type shared with the carrier-neutral TURN state machine.
pub type TurnTlsError = TurnUdpError;

/// Secure WebSocket TURN client error shared with the carrier-neutral TURN state machine.
pub type TurnWebSocketError = TurnUdpError;

enum ClientIo {
    Udp {
        socket: UdpSocket,
        receive_buffer: Vec<u8>,
    },
    Tcp(TurnStream<TcpStream>),
    Tls(Box<TurnStream<TlsStream<TcpStream>>>),
    WebSocket(Box<WebSocketStream<TlsStream<TcpStream>>>),
}

impl ClientIo {
    const fn carrier(&self) -> RelayCarrier {
        match self {
            Self::Udp { .. } => RelayCarrier::TurnUdp,
            Self::Tcp(_) => RelayCarrier::TurnTcp,
            Self::Tls(_) => RelayCarrier::TurnTls,
            Self::WebSocket(_) => RelayCarrier::SecureWebSocket,
        }
    }

    const fn is_reliable(&self) -> bool {
        matches!(self, Self::Tcp(_) | Self::Tls(_) | Self::WebSocket(_))
    }

    async fn send_record(&mut self, record: &[u8]) -> Result<(), TurnUdpError> {
        match self {
            Self::Udp { socket, .. } => {
                socket
                    .send(record)
                    .await
                    .map_err(|source| TurnUdpError::Io {
                        operation: "send record",
                        source,
                    })?;
                Ok(())
            }
            Self::Tcp(stream) => stream.write_record(record).await.map_err(Into::into),
            Self::Tls(stream) => stream.write_record(record).await.map_err(Into::into),
            Self::WebSocket(stream) => {
                write_websocket_record(stream.as_mut(), record, MAX_TURN_STREAM_RECORD_SIZE)
                    .await
                    .map_err(Into::into)
            }
        }
    }

    async fn send_channel_data(
        &mut self,
        channel: TurnChannelNumber,
        datagram: &[u8],
    ) -> Result<(), TurnUdpError> {
        let padding = usize::from(self.is_reliable()) * 3;
        let mut encoded = vec![0_u8; datagram.len().saturating_add(4).saturating_add(padding)];
        let length = if self.is_reliable() {
            encode_turn_channel_data_stream(channel, datagram, &mut encoded)?
        } else {
            encode_turn_channel_data(channel, datagram, &mut encoded)?
        };
        self.send_record(&encoded[..length]).await
    }

    async fn receive_record(&mut self) -> Result<Vec<u8>, TurnUdpError> {
        match self {
            Self::Udp {
                socket,
                receive_buffer,
            } => {
                let length =
                    socket
                        .recv(receive_buffer)
                        .await
                        .map_err(|source| TurnUdpError::Io {
                            operation: "receive record",
                            source,
                        })?;
                Ok(receive_buffer[..length].to_vec())
            }
            Self::Tcp(stream) => stream.read_record().await.map_err(Into::into),
            Self::Tls(stream) => stream.read_record().await.map_err(Into::into),
            Self::WebSocket(stream) => {
                read_websocket_record(stream.as_mut(), MAX_TURN_STREAM_RECORD_SIZE)
                    .await
                    .map_err(Into::into)
            }
        }
    }
}

/// One live authenticated TURN UDP allocation with bounded command and receive queues.
pub struct TurnUdpClient {
    carrier: RelayCarrier,
    relay_id: RelayId,
    relayed_address: SocketAddr,
    mapped_address: SocketAddr,
    local_address: SocketAddr,
    capabilities: TransportCapabilities,
    commands: mpsc::Sender<Command>,
    inbound: Mutex<mpsc::Receiver<InboundEvent>>,
    task: Mutex<Option<JoinHandle<()>>>,
    shutdown: AtomicBool,
}

impl TurnUdpClient {
    /// Authenticates, allocates a relayed UDP address, and starts the socket actor.
    ///
    /// # Errors
    ///
    /// Returns [`TurnUdpError`] for configuration, credentials, socket I/O,
    /// authentication challenge, transaction, integrity, or allocation response failures.
    pub async fn allocate(
        config: TurnUdpClientConfig,
        credentials: TurnCredentials,
    ) -> Result<Self, TurnUdpError> {
        config.validate()?;
        credentials.validate_time(unix_time()?)?;
        let socket = UdpSocket::bind(config.bind_address)
            .await
            .map_err(|source| TurnUdpError::Io {
                operation: "bind",
                source,
            })?;
        socket
            .connect(config.server_address)
            .await
            .map_err(|source| TurnUdpError::Io {
                operation: "connect",
                source,
            })?;
        let local_address = socket.local_addr().map_err(|source| TurnUdpError::Io {
            operation: "query local address",
            source,
        })?;
        let config = TurnClientConfig::from(config);
        let io = ClientIo::Udp {
            socket,
            receive_buffer: vec![0_u8; TURN_UDP_RECEIVE_BUFFER_SIZE],
        };
        Self::allocate_connected(config, credentials, io, local_address).await
    }

    async fn allocate_connected(
        config: TurnClientConfig,
        credentials: TurnCredentials,
        mut io: ClientIo,
        local_address: SocketAddr,
    ) -> Result<Self, TurnUdpError> {
        let expected_realm = format!("stella-relay:{}", config.relay_id).into_bytes();
        let challenge = initial_challenge(&mut io, config, &expected_realm).await?;
        let mut actor = Actor::new(io, config, credentials, challenge)?;
        let allocation = actor.allocate().await?;
        let relayed_address = allocation.relayed_address;
        let mapped_address = allocation.mapped_address;
        actor.schedule_allocation_refresh(allocation.lifetime)?;
        let (commands, command_receiver) = mpsc::channel(TURN_UDP_COMMAND_CAPACITY);
        let (inbound_sender, inbound) = mpsc::channel(TURN_UDP_RECEIVE_CAPACITY);
        actor.commands = Some(command_receiver);
        actor.inbound = Some(inbound_sender);
        let task = tokio::spawn(actor.run());
        Ok(Self {
            carrier: config.carrier,
            relay_id: config.relay_id,
            relayed_address,
            mapped_address,
            local_address,
            capabilities: TransportCapabilities {
                max_datagram_size: config.max_datagram_size,
            },
            commands,
            inbound: Mutex::new(inbound),
            task: Mutex::new(Some(task)),
            shutdown: AtomicBool::new(false),
        })
    }

    /// Returns the relay identity attached to this local allocation.
    #[must_use]
    pub const fn relay_id(&self) -> RelayId {
        self.relay_id
    }

    /// Returns the public relayed candidate address.
    #[must_use]
    pub const fn relayed_address(&self) -> SocketAddr {
        self.relayed_address
    }

    /// Returns the client address observed by the TURN server.
    #[must_use]
    pub const fn mapped_address(&self) -> SocketAddr {
        self.mapped_address
    }

    /// Returns the local UDP socket address used for the allocation.
    #[must_use]
    pub const fn local_address(&self) -> SocketAddr {
        self.local_address
    }

    /// Returns the enforced complete Stella datagram limit.
    #[must_use]
    pub const fn capabilities(&self) -> TransportCapabilities {
        self.capabilities
    }

    /// Returns the local relay candidate published to authorized peers.
    #[must_use]
    pub const fn local_endpoint(&self) -> TransportEndpoint {
        match self.carrier {
            RelayCarrier::TurnUdp => TransportEndpoint::TurnUdp {
                relay_id: self.relay_id,
                address: self.relayed_address,
            },
            RelayCarrier::TurnTcp => TransportEndpoint::TurnTcp {
                relay_id: self.relay_id,
                address: self.relayed_address,
            },
            RelayCarrier::TurnTls => TransportEndpoint::TurnTls {
                relay_id: self.relay_id,
                address: self.relayed_address,
            },
            RelayCarrier::SecureWebSocket => TransportEndpoint::SecureWebSocket {
                relay_id: self.relay_id,
                address: self.relayed_address,
            },
        }
    }

    /// Creates or refreshes a peer permission and channel binding.
    ///
    /// # Errors
    ///
    /// Returns [`TurnUdpError`] for endpoint, transaction, rejection, actor, or I/O failure.
    pub async fn prepare_peer(&self, endpoint: &TransportEndpoint) -> Result<(), TurnUdpError> {
        let endpoint = endpoint.clone();
        self.command(|response| Command::PreparePeer { endpoint, response })
            .await
    }

    /// Creates or refreshes only the TURN permission for a peer candidate.
    ///
    /// This keeps the standard Send/Data indication path available before a
    /// channel is selected or when a caller deliberately avoids `ChannelData`.
    ///
    /// # Errors
    ///
    /// Returns [`TurnUdpError`] for endpoint, transaction, rejection, actor, or I/O failure.
    pub async fn permit_peer(&self, endpoint: &TransportEndpoint) -> Result<(), TurnUdpError> {
        let endpoint = endpoint.clone();
        self.command(|response| Command::PermitPeer { endpoint, response })
            .await
    }

    /// Sends one complete datagram through a prepared or automatically prepared relay path.
    ///
    /// # Errors
    ///
    /// Returns [`TurnUdpError`] for endpoint mismatch, size, permission,
    /// channel binding, actor, or socket failure.
    pub async fn send_to(
        &self,
        endpoint: &TransportEndpoint,
        datagram: &[u8],
    ) -> Result<(), TurnUdpError> {
        if datagram.len() > self.capabilities.max_datagram_size {
            return Err(TurnUdpError::DatagramTooLarge {
                actual: datagram.len(),
                maximum: self.capabilities.max_datagram_size,
            });
        }
        let endpoint = endpoint.clone();
        let datagram = datagram.to_vec();
        self.command(|response| Command::Send {
            endpoint,
            datagram,
            response,
        })
        .await
    }

    /// Sends one complete datagram as a TURN Send indication.
    ///
    /// The actor automatically creates or refreshes the required permission;
    /// the peer receives the datagram as a TURN Data indication when it has no
    /// channel binding for this address.
    ///
    /// # Errors
    ///
    /// Returns [`TurnUdpError`] for endpoint mismatch, size, permission,
    /// actor, codec, or socket failure.
    pub async fn send_indication_to(
        &self,
        endpoint: &TransportEndpoint,
        datagram: &[u8],
    ) -> Result<(), TurnUdpError> {
        if datagram.len() > self.capabilities.max_datagram_size {
            return Err(TurnUdpError::DatagramTooLarge {
                actual: datagram.len(),
                maximum: self.capabilities.max_datagram_size,
            });
        }
        let endpoint = endpoint.clone();
        let datagram = datagram.to_vec();
        self.command(|response| Command::SendIndication {
            endpoint,
            datagram,
            response,
        })
        .await
    }

    /// Replaces short-lived controller credentials and verifies them with an allocation refresh.
    ///
    /// # Errors
    ///
    /// Returns [`TurnUdpError`] when credentials are expired or the refresh fails.
    pub async fn replace_credentials(
        &self,
        credentials: TurnCredentials,
    ) -> Result<(), TurnUdpError> {
        credentials.validate_time(unix_time()?)?;
        self.command(|response| Command::ReplaceCredentials {
            credentials,
            response,
        })
        .await
    }

    /// Receives one complete relayed datagram without exposing partial data.
    ///
    /// # Errors
    ///
    /// Returns [`TurnUdpError`] for insufficient output, actor failure, or shutdown.
    pub async fn receive(&self, output: &mut [u8]) -> Result<ReceivedDatagram, TurnUdpError> {
        let mut inbound = self.inbound.lock().await;
        match inbound.recv().await.ok_or(TurnUdpError::ActorStopped)? {
            InboundEvent::Datagram { endpoint, data } => {
                if output.len() < data.len() {
                    return Err(TurnUdpError::ReceiveBufferTooSmall {
                        needed: data.len(),
                        remaining: output.len(),
                    });
                }
                let length = data.len();
                output[..length].copy_from_slice(&data);
                Ok(ReceivedDatagram {
                    source: endpoint,
                    length,
                })
            }
            InboundEvent::Failed(error) => Err(error),
        }
    }

    /// Deletes the allocation, stops the actor, and cancels pending receives.
    ///
    /// Shutdown is idempotent.
    ///
    /// # Errors
    ///
    /// Returns [`TurnUdpError`] when deletion or actor joining fails.
    pub async fn shutdown(&self) -> Result<(), TurnUdpError> {
        if !self.shutdown.swap(true, Ordering::AcqRel) {
            let result = self.command_allow_shutdown(Command::shutdown).await;
            let join = self.join_task().await;
            return result.and(join);
        }
        self.join_task().await
    }

    async fn command<F>(&self, create: F) -> Result<(), TurnUdpError>
    where
        F: FnOnce(oneshot::Sender<Result<(), TurnUdpError>>) -> Command,
    {
        if self.shutdown.load(Ordering::Acquire) {
            return Err(TurnUdpError::ActorStopped);
        }
        let (response, receiver) = oneshot::channel();
        self.commands
            .send(create(response))
            .await
            .map_err(|_| TurnUdpError::ActorStopped)?;
        receiver.await.map_err(|_| TurnUdpError::ActorStopped)?
    }

    async fn command_allow_shutdown(
        &self,
        create: fn(oneshot::Sender<Result<(), TurnUdpError>>) -> Command,
    ) -> Result<(), TurnUdpError> {
        let (response, receiver) = oneshot::channel();
        self.commands
            .send(create(response))
            .await
            .map_err(|_| TurnUdpError::ActorStopped)?;
        receiver.await.map_err(|_| TurnUdpError::ActorStopped)?
    }

    async fn join_task(&self) -> Result<(), TurnUdpError> {
        let task = self.task.lock().await.take();
        if let Some(task) = task {
            task.await.map_err(|_| TurnUdpError::TaskFailed)?;
        }
        Ok(())
    }
}

impl fmt::Debug for TurnUdpClient {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("TurnUdpClient")
            .field("carrier", &self.carrier)
            .field("relay_id", &self.relay_id)
            .field("relayed_address", &self.relayed_address)
            .field("mapped_address", &self.mapped_address)
            .field("local_address", &self.local_address)
            .field("capabilities", &self.capabilities)
            .field("shutdown", &self.shutdown.load(Ordering::Acquire))
            .finish_non_exhaustive()
    }
}

impl Drop for TurnUdpClient {
    fn drop(&mut self) {
        self.shutdown.store(true, Ordering::Release);
        if let Some(task) = self.task.get_mut().take() {
            task.abort();
        }
    }
}

/// One live authenticated TURN TCP allocation with bounded command and receive queues.
pub struct TurnTcpClient {
    inner: TurnUdpClient,
}

impl TurnTcpClient {
    /// Connects, authenticates, allocates a relayed UDP address, and starts the stream actor.
    ///
    /// # Errors
    ///
    /// Returns [`TurnTcpError`] for configuration, credentials, TCP I/O,
    /// framing, authentication, transaction, integrity, or allocation failures.
    pub async fn allocate(
        config: TurnTcpClientConfig,
        credentials: TurnCredentials,
    ) -> Result<Self, TurnTcpError> {
        config.validate()?;
        credentials.validate_time(unix_time()?)?;
        let socket = if config.server_address.is_ipv4() {
            TcpSocket::new_v4()
        } else {
            TcpSocket::new_v6()
        }
        .map_err(|source| TurnUdpError::Io {
            operation: "create TCP socket",
            source,
        })?;
        socket
            .bind(config.bind_address)
            .map_err(|source| TurnUdpError::Io {
                operation: "bind TCP socket",
                source,
            })?;
        let stream = socket
            .connect(config.server_address)
            .await
            .map_err(|source| TurnUdpError::Io {
                operation: "connect TCP socket",
                source,
            })?;
        stream
            .set_nodelay(true)
            .map_err(|source| TurnUdpError::Io {
                operation: "configure TCP no-delay",
                source,
            })?;
        let local_address = stream.local_addr().map_err(|source| TurnUdpError::Io {
            operation: "query local TCP address",
            source,
        })?;
        let io = ClientIo::Tcp(TurnStream::new(stream, MAX_TURN_STREAM_RECORD_SIZE)?);
        let inner = TurnUdpClient::allocate_connected(
            TurnClientConfig::from(config),
            credentials,
            io,
            local_address,
        )
        .await?;
        Ok(Self { inner })
    }

    /// Returns the relay identity attached to this local allocation.
    #[must_use]
    pub const fn relay_id(&self) -> RelayId {
        self.inner.relay_id()
    }

    /// Returns the public relayed candidate address.
    #[must_use]
    pub const fn relayed_address(&self) -> SocketAddr {
        self.inner.relayed_address()
    }

    /// Returns the client TCP address observed by the TURN server.
    #[must_use]
    pub const fn mapped_address(&self) -> SocketAddr {
        self.inner.mapped_address()
    }

    /// Returns the local TCP socket address used for the allocation.
    #[must_use]
    pub const fn local_address(&self) -> SocketAddr {
        self.inner.local_address()
    }

    /// Returns the enforced complete Stella datagram limit.
    #[must_use]
    pub const fn capabilities(&self) -> TransportCapabilities {
        self.inner.capabilities()
    }

    /// Returns the local TURN TCP relay candidate published to authorized peers.
    #[must_use]
    pub const fn local_endpoint(&self) -> TransportEndpoint {
        self.inner.local_endpoint()
    }

    /// Creates or refreshes a peer permission and channel binding.
    ///
    /// # Errors
    ///
    /// Returns [`TurnTcpError`] for endpoint, transaction, rejection, actor, or I/O failure.
    pub async fn prepare_peer(&self, endpoint: &TransportEndpoint) -> Result<(), TurnTcpError> {
        self.inner.prepare_peer(endpoint).await
    }

    /// Creates or refreshes only the TURN permission for a peer candidate.
    ///
    /// # Errors
    ///
    /// Returns [`TurnTcpError`] for endpoint, transaction, rejection, actor, or I/O failure.
    pub async fn permit_peer(&self, endpoint: &TransportEndpoint) -> Result<(), TurnTcpError> {
        self.inner.permit_peer(endpoint).await
    }

    /// Sends one complete datagram through a prepared TURN TCP path.
    ///
    /// # Errors
    ///
    /// Returns [`TurnTcpError`] for endpoint mismatch, size, permission,
    /// channel binding, actor, framing, or stream failure.
    pub async fn send_to(
        &self,
        endpoint: &TransportEndpoint,
        datagram: &[u8],
    ) -> Result<(), TurnTcpError> {
        self.inner.send_to(endpoint, datagram).await
    }

    /// Sends one complete datagram as a TURN Send indication over TCP.
    ///
    /// # Errors
    ///
    /// Returns [`TurnTcpError`] for endpoint mismatch, size, permission,
    /// actor, codec, framing, or stream failure.
    pub async fn send_indication_to(
        &self,
        endpoint: &TransportEndpoint,
        datagram: &[u8],
    ) -> Result<(), TurnTcpError> {
        self.inner.send_indication_to(endpoint, datagram).await
    }

    /// Replaces short-lived credentials and verifies them with an allocation refresh.
    ///
    /// # Errors
    ///
    /// Returns [`TurnTcpError`] when credentials are expired or the refresh fails.
    pub async fn replace_credentials(
        &self,
        credentials: TurnCredentials,
    ) -> Result<(), TurnTcpError> {
        self.inner.replace_credentials(credentials).await
    }

    /// Receives one complete relayed datagram without exposing partial data.
    ///
    /// # Errors
    ///
    /// Returns [`TurnTcpError`] for insufficient output, actor failure, or shutdown.
    pub async fn receive(&self, output: &mut [u8]) -> Result<ReceivedDatagram, TurnTcpError> {
        self.inner.receive(output).await
    }

    /// Deletes the allocation, stops the actor, and cancels pending receives.
    ///
    /// # Errors
    ///
    /// Returns [`TurnTcpError`] when deletion or actor joining fails.
    pub async fn shutdown(&self) -> Result<(), TurnTcpError> {
        self.inner.shutdown().await
    }
}

impl fmt::Debug for TurnTcpClient {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("TurnTcpClient")
            .field("relay_id", &self.inner.relay_id)
            .field("relayed_address", &self.inner.relayed_address)
            .field("mapped_address", &self.inner.mapped_address)
            .field("local_address", &self.inner.local_address)
            .field("capabilities", &self.inner.capabilities)
            .field("shutdown", &self.inner.shutdown.load(Ordering::Acquire))
            .finish_non_exhaustive()
    }
}

/// One live authenticated TURN TLS allocation with bounded command and receive queues.
pub struct TurnTlsClient {
    inner: TurnUdpClient,
}

impl TurnTlsClient {
    /// Connects with TLS 1.3, authenticates, allocates a relayed UDP address, and starts the actor.
    ///
    /// # Errors
    ///
    /// Returns [`TurnTlsError`] for configuration, credentials, TCP or TLS I/O,
    /// certificate validation, framing, authentication, transaction, integrity,
    /// or allocation failures.
    pub async fn allocate(
        config: TurnTlsClientConfig,
        credentials: TurnCredentials,
    ) -> Result<Self, TurnTlsError> {
        config.validate()?;
        credentials.validate_time(unix_time()?)?;
        let socket = if config.server_address.is_ipv4() {
            TcpSocket::new_v4()
        } else {
            TcpSocket::new_v6()
        }
        .map_err(|source| TurnUdpError::Io {
            operation: "create TURN TLS socket",
            source,
        })?;
        socket
            .bind(config.bind_address)
            .map_err(|source| TurnUdpError::Io {
                operation: "bind TURN TLS socket",
                source,
            })?;
        let stream = socket
            .connect(config.server_address)
            .await
            .map_err(|source| TurnUdpError::Io {
                operation: "connect TURN TLS socket",
                source,
            })?;
        stream
            .set_nodelay(true)
            .map_err(|source| TurnUdpError::Io {
                operation: "configure TURN TLS no-delay",
                source,
            })?;
        let local_address = stream.local_addr().map_err(|source| TurnUdpError::Io {
            operation: "query local TURN TLS address",
            source,
        })?;
        let server_name = config.server_name()?;
        let connector =
            tls::relay_connector(config.trust, &config.spki_pins).map_err(|source| {
                TurnUdpError::Io {
                    operation: "configure TURN TLS trust",
                    source,
                }
            })?;
        let stream = connector
            .connect(server_name, stream)
            .await
            .map_err(|source| TurnUdpError::Io {
                operation: "complete TURN TLS handshake",
                source,
            })?;
        let io = ClientIo::Tls(Box::new(TurnStream::new(
            stream,
            MAX_TURN_STREAM_RECORD_SIZE,
        )?));
        let inner = TurnUdpClient::allocate_connected(
            TurnClientConfig::from(&config),
            credentials,
            io,
            local_address,
        )
        .await?;
        Ok(Self { inner })
    }

    /// Returns the relay identity attached to this local allocation.
    #[must_use]
    pub const fn relay_id(&self) -> RelayId {
        self.inner.relay_id()
    }

    /// Returns the public relayed candidate address.
    #[must_use]
    pub const fn relayed_address(&self) -> SocketAddr {
        self.inner.relayed_address()
    }

    /// Returns the client TCP address observed beneath TLS by the TURN server.
    #[must_use]
    pub const fn mapped_address(&self) -> SocketAddr {
        self.inner.mapped_address()
    }

    /// Returns the local TCP socket address used for the TLS allocation.
    #[must_use]
    pub const fn local_address(&self) -> SocketAddr {
        self.inner.local_address()
    }

    /// Returns the enforced complete Stella datagram limit.
    #[must_use]
    pub const fn capabilities(&self) -> TransportCapabilities {
        self.inner.capabilities()
    }

    /// Returns the local TURN TLS relay candidate published to authorized peers.
    #[must_use]
    pub const fn local_endpoint(&self) -> TransportEndpoint {
        self.inner.local_endpoint()
    }

    /// Creates or refreshes a peer permission and channel binding.
    ///
    /// # Errors
    ///
    /// Returns [`TurnTlsError`] for endpoint, transaction, rejection, actor, or I/O failure.
    pub async fn prepare_peer(&self, endpoint: &TransportEndpoint) -> Result<(), TurnTlsError> {
        self.inner.prepare_peer(endpoint).await
    }

    /// Creates or refreshes only the TURN permission for a peer candidate.
    ///
    /// # Errors
    ///
    /// Returns [`TurnTlsError`] for endpoint, transaction, rejection, actor, or I/O failure.
    pub async fn permit_peer(&self, endpoint: &TransportEndpoint) -> Result<(), TurnTlsError> {
        self.inner.permit_peer(endpoint).await
    }

    /// Sends one complete datagram through a prepared TURN TLS path.
    ///
    /// # Errors
    ///
    /// Returns [`TurnTlsError`] for endpoint mismatch, size, permission,
    /// channel binding, actor, framing, or stream failure.
    pub async fn send_to(
        &self,
        endpoint: &TransportEndpoint,
        datagram: &[u8],
    ) -> Result<(), TurnTlsError> {
        self.inner.send_to(endpoint, datagram).await
    }

    /// Sends one complete datagram as a TURN Send indication over TLS.
    ///
    /// # Errors
    ///
    /// Returns [`TurnTlsError`] for endpoint mismatch, size, permission,
    /// actor, codec, framing, or stream failure.
    pub async fn send_indication_to(
        &self,
        endpoint: &TransportEndpoint,
        datagram: &[u8],
    ) -> Result<(), TurnTlsError> {
        self.inner.send_indication_to(endpoint, datagram).await
    }

    /// Replaces short-lived credentials and verifies them with an allocation refresh.
    ///
    /// # Errors
    ///
    /// Returns [`TurnTlsError`] when credentials are expired or the refresh fails.
    pub async fn replace_credentials(
        &self,
        credentials: TurnCredentials,
    ) -> Result<(), TurnTlsError> {
        self.inner.replace_credentials(credentials).await
    }

    /// Receives one complete relayed datagram without exposing partial data.
    ///
    /// # Errors
    ///
    /// Returns [`TurnTlsError`] for insufficient output, actor failure, or shutdown.
    pub async fn receive(&self, output: &mut [u8]) -> Result<ReceivedDatagram, TurnTlsError> {
        self.inner.receive(output).await
    }

    /// Deletes the allocation, stops the actor, and cancels pending receives.
    ///
    /// # Errors
    ///
    /// Returns [`TurnTlsError`] when deletion or actor joining fails.
    pub async fn shutdown(&self) -> Result<(), TurnTlsError> {
        self.inner.shutdown().await
    }
}

impl fmt::Debug for TurnTlsClient {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("TurnTlsClient")
            .field("relay_id", &self.inner.relay_id)
            .field("relayed_address", &self.inner.relayed_address)
            .field("mapped_address", &self.inner.mapped_address)
            .field("local_address", &self.inner.local_address)
            .field("capabilities", &self.inner.capabilities)
            .field("shutdown", &self.inner.shutdown.load(Ordering::Acquire))
            .finish_non_exhaustive()
    }
}

/// One live authenticated secure WebSocket TURN allocation with bounded queues.
pub struct TurnWebSocketClient {
    inner: TurnUdpClient,
}

impl TurnWebSocketClient {
    /// Connects with TLS 1.3, authenticates the HTTP upgrade, allocates, and starts the actor.
    ///
    /// # Errors
    ///
    /// Returns [`TurnWebSocketError`] for configuration, credentials, TCP, TLS,
    /// HTTP upgrade, WebSocket, TURN authentication, integrity, or allocation failure.
    pub async fn allocate(
        config: TurnWebSocketClientConfig,
        credentials: TurnCredentials,
    ) -> Result<Self, TurnWebSocketError> {
        config.validate()?;
        credentials.validate_time(unix_time()?)?;
        let request = websocket_upgrade_request(&config, &credentials)?;
        let socket = if config.server_address.is_ipv4() {
            TcpSocket::new_v4()
        } else {
            TcpSocket::new_v6()
        }
        .map_err(|source| TurnUdpError::Io {
            operation: "create TURN WebSocket socket",
            source,
        })?;
        socket
            .bind(config.bind_address)
            .map_err(|source| TurnUdpError::Io {
                operation: "bind TURN WebSocket socket",
                source,
            })?;
        let stream = socket
            .connect(config.server_address)
            .await
            .map_err(|source| TurnUdpError::Io {
                operation: "connect TURN WebSocket socket",
                source,
            })?;
        stream
            .set_nodelay(true)
            .map_err(|source| TurnUdpError::Io {
                operation: "configure TURN WebSocket no-delay",
                source,
            })?;
        let local_address = stream.local_addr().map_err(|source| TurnUdpError::Io {
            operation: "query local TURN WebSocket address",
            source,
        })?;
        let server_name = config.server_name()?;
        let connector =
            tls::relay_connector(config.trust, &config.spki_pins).map_err(|source| {
                TurnUdpError::Io {
                    operation: "configure TURN WebSocket TLS trust",
                    source,
                }
            })?;
        let stream = connector
            .connect(server_name, stream)
            .await
            .map_err(|source| TurnUdpError::Io {
                operation: "complete TURN WebSocket TLS handshake",
                source,
            })?;
        let websocket_config = turn_websocket_config(MAX_TURN_STREAM_RECORD_SIZE)?;
        let (stream, response) = client_async_with_config(request, stream, Some(websocket_config))
            .await
            .map_err(WebSocketRecordError::from)?;
        validate_websocket_upgrade_response(&response)?;
        let io = ClientIo::WebSocket(Box::new(stream));
        let inner = TurnUdpClient::allocate_connected(
            TurnClientConfig::from(&config),
            credentials,
            io,
            local_address,
        )
        .await?;
        Ok(Self { inner })
    }

    /// Returns the relay identity attached to this local allocation.
    #[must_use]
    pub const fn relay_id(&self) -> RelayId {
        self.inner.relay_id()
    }

    /// Returns the public relayed candidate address.
    #[must_use]
    pub const fn relayed_address(&self) -> SocketAddr {
        self.inner.relayed_address()
    }

    /// Returns the client TCP address observed beneath TLS and WebSocket.
    #[must_use]
    pub const fn mapped_address(&self) -> SocketAddr {
        self.inner.mapped_address()
    }

    /// Returns the local TCP socket address used for the WebSocket allocation.
    #[must_use]
    pub const fn local_address(&self) -> SocketAddr {
        self.inner.local_address()
    }

    /// Returns the enforced complete Stella datagram limit.
    #[must_use]
    pub const fn capabilities(&self) -> TransportCapabilities {
        self.inner.capabilities()
    }

    /// Returns the local secure WebSocket relay candidate published to authorized peers.
    #[must_use]
    pub const fn local_endpoint(&self) -> TransportEndpoint {
        self.inner.local_endpoint()
    }

    /// Creates or refreshes a peer permission and channel binding.
    ///
    /// # Errors
    ///
    /// Returns [`TurnWebSocketError`] for endpoint, transaction, rejection, actor, or I/O failure.
    pub async fn prepare_peer(
        &self,
        endpoint: &TransportEndpoint,
    ) -> Result<(), TurnWebSocketError> {
        self.inner.prepare_peer(endpoint).await
    }

    /// Creates or refreshes only the TURN permission for a peer candidate.
    ///
    /// # Errors
    ///
    /// Returns [`TurnWebSocketError`] for endpoint, transaction, rejection, actor, or I/O failure.
    pub async fn permit_peer(
        &self,
        endpoint: &TransportEndpoint,
    ) -> Result<(), TurnWebSocketError> {
        self.inner.permit_peer(endpoint).await
    }

    /// Sends one complete datagram through a prepared secure WebSocket relay path.
    ///
    /// # Errors
    ///
    /// Returns [`TurnWebSocketError`] for endpoint mismatch, size, permission,
    /// channel binding, actor, framing, or WebSocket failure.
    pub async fn send_to(
        &self,
        endpoint: &TransportEndpoint,
        datagram: &[u8],
    ) -> Result<(), TurnWebSocketError> {
        self.inner.send_to(endpoint, datagram).await
    }

    /// Sends one complete datagram as a TURN Send indication over WebSocket.
    ///
    /// # Errors
    ///
    /// Returns [`TurnWebSocketError`] for endpoint mismatch, size, permission,
    /// actor, codec, framing, or WebSocket failure.
    pub async fn send_indication_to(
        &self,
        endpoint: &TransportEndpoint,
        datagram: &[u8],
    ) -> Result<(), TurnWebSocketError> {
        self.inner.send_indication_to(endpoint, datagram).await
    }

    /// Replaces short-lived credentials and verifies them with an allocation refresh.
    ///
    /// # Errors
    ///
    /// Returns [`TurnWebSocketError`] when credentials are expired or the refresh fails.
    pub async fn replace_credentials(
        &self,
        credentials: TurnCredentials,
    ) -> Result<(), TurnWebSocketError> {
        self.inner.replace_credentials(credentials).await
    }

    /// Receives one complete relayed datagram without exposing partial data.
    ///
    /// # Errors
    ///
    /// Returns [`TurnWebSocketError`] for insufficient output, actor failure, or shutdown.
    pub async fn receive(&self, output: &mut [u8]) -> Result<ReceivedDatagram, TurnWebSocketError> {
        self.inner.receive(output).await
    }

    /// Deletes the allocation, stops the actor, and cancels pending receives.
    ///
    /// # Errors
    ///
    /// Returns [`TurnWebSocketError`] when deletion or actor joining fails.
    pub async fn shutdown(&self) -> Result<(), TurnWebSocketError> {
        self.inner.shutdown().await
    }
}

impl fmt::Debug for TurnWebSocketClient {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("TurnWebSocketClient")
            .field("relay_id", &self.inner.relay_id)
            .field("relayed_address", &self.inner.relayed_address)
            .field("mapped_address", &self.inner.mapped_address)
            .field("local_address", &self.inner.local_address)
            .field("capabilities", &self.inner.capabilities)
            .field("shutdown", &self.inner.shutdown.load(Ordering::Acquire))
            .finish_non_exhaustive()
    }
}

fn websocket_upgrade_request(
    config: &TurnWebSocketClientConfig,
    credentials: &TurnCredentials,
) -> Result<Request<()>, TurnUdpError> {
    let uri = format!("wss://{}{}", config.authority(), STELLA_TURN_WEBSOCKET_PATH);
    let mut request = uri
        .into_client_request()
        .map_err(WebSocketRecordError::from)?;
    request.headers_mut().insert(
        SEC_WEBSOCKET_PROTOCOL,
        HeaderValue::from_static(STELLA_TURN_WEBSOCKET_SUBPROTOCOL),
    );
    let encoded_username = Zeroizing::new(URL_SAFE_NO_PAD.encode(credentials.username.as_slice()));
    let encoded_secret = Zeroizing::new(URL_SAFE_NO_PAD.encode(credentials.password.as_slice()));
    let authorization = Zeroizing::new(format!(
        "Stella {}.{}",
        encoded_username.as_str(),
        encoded_secret.as_str()
    ));
    request.headers_mut().insert(
        AUTHORIZATION,
        HeaderValue::from_str(authorization.as_str()).map_err(|_| TurnUdpError::InvalidConfig {
            field: "TURN WebSocket authorization",
            reason: "must encode as one valid HTTP field value",
        })?,
    );
    Ok(request)
}

fn validate_websocket_upgrade_response<B>(response: &Response<B>) -> Result<(), TurnUdpError> {
    let mut protocols = response.headers().get_all(SEC_WEBSOCKET_PROTOCOL).iter();
    let selected = protocols.next().and_then(|value| value.to_str().ok());
    if selected != Some(STELLA_TURN_WEBSOCKET_SUBPROTOCOL) || protocols.next().is_some() {
        return Err(TurnUdpError::InvalidWebSocketUpgrade {
            detail: "must select exactly the stella-turn.v1 subprotocol",
        });
    }
    if response.headers().contains_key(SEC_WEBSOCKET_EXTENSIONS) {
        return Err(TurnUdpError::InvalidWebSocketUpgrade {
            detail: "must not negotiate WebSocket extensions",
        });
    }
    Ok(())
}

enum Command {
    PermitPeer {
        endpoint: TransportEndpoint,
        response: oneshot::Sender<Result<(), TurnUdpError>>,
    },
    PreparePeer {
        endpoint: TransportEndpoint,
        response: oneshot::Sender<Result<(), TurnUdpError>>,
    },
    Send {
        endpoint: TransportEndpoint,
        datagram: Vec<u8>,
        response: oneshot::Sender<Result<(), TurnUdpError>>,
    },
    SendIndication {
        endpoint: TransportEndpoint,
        datagram: Vec<u8>,
        response: oneshot::Sender<Result<(), TurnUdpError>>,
    },
    ReplaceCredentials {
        credentials: TurnCredentials,
        response: oneshot::Sender<Result<(), TurnUdpError>>,
    },
    Shutdown {
        response: oneshot::Sender<Result<(), TurnUdpError>>,
    },
}

impl Command {
    fn shutdown(response: oneshot::Sender<Result<(), TurnUdpError>>) -> Self {
        Self::Shutdown { response }
    }
}

enum InboundEvent {
    Datagram {
        endpoint: TransportEndpoint,
        data: Vec<u8>,
    },
    Failed(TurnUdpError),
}

struct AuthContext {
    realm: Vec<u8>,
    nonce: Zeroizing<Vec<u8>>,
}

struct AllocationResult {
    relayed_address: SocketAddr,
    mapped_address: SocketAddr,
    lifetime: u32,
}

struct Permission {
    expires_at: Instant,
}

struct ChannelBinding {
    channel: TurnChannelNumber,
    endpoint: TransportEndpoint,
    expires_at: Instant,
}

struct Actor {
    io: ClientIo,
    config: TurnClientConfig,
    credentials: TurnCredentials,
    auth: AuthContext,
    commands: Option<mpsc::Receiver<Command>>,
    inbound: Option<mpsc::Sender<InboundEvent>>,
    allocation_refresh_at: Instant,
    permissions: BTreeMap<IpAddr, Permission>,
    peers: BTreeMap<SocketAddr, TransportEndpoint>,
    channels: BTreeMap<SocketAddr, ChannelBinding>,
    channel_peers: BTreeMap<TurnChannelNumber, SocketAddr>,
    next_channel: u16,
}

impl Actor {
    fn new(
        io: ClientIo,
        config: TurnClientConfig,
        credentials: TurnCredentials,
        auth: AuthContext,
    ) -> Result<Self, TurnUdpError> {
        if io.carrier() != config.carrier {
            return Err(TurnUdpError::InvalidConfig {
                field: "TURN carrier",
                reason: "I/O carrier does not match client configuration",
            });
        }
        Ok(Self {
            io,
            config,
            credentials,
            auth,
            commands: None,
            inbound: None,
            allocation_refresh_at: deadline_after(MIN_REFRESH_INTERVAL, "initial refresh")?,
            permissions: BTreeMap::new(),
            peers: BTreeMap::new(),
            channels: BTreeMap::new(),
            channel_peers: BTreeMap::new(),
            next_channel: 0x4000,
        })
    }

    async fn allocate(&mut self) -> Result<AllocationResult, TurnUdpError> {
        let lifetime = self.config.allocation_lifetime_seconds.to_be_bytes();
        let response = self
            .authenticated_request(
                StunMethod::Allocate,
                &[
                    OwnedAttribute::new(
                        StunAttributeType::REQUESTED_TRANSPORT,
                        REQUESTED_TRANSPORT_UDP.to_vec(),
                    ),
                    OwnedAttribute::new(StunAttributeType::LIFETIME, lifetime.to_vec()),
                ],
            )
            .await?;
        let message = StunMessageView::decode(&response)?;
        let relayed_address = decode_stun_xor_address(
            required_attribute(&message, StunAttributeType::XOR_RELAYED_ADDRESS)?,
            message.transaction_id(),
        )?;
        let mapped_address = decode_stun_xor_address(
            required_attribute(&message, StunAttributeType::XOR_MAPPED_ADDRESS)?,
            message.transaction_id(),
        )?;
        let lifetime = decode_lifetime(&message)?;
        if lifetime == 0 {
            return Err(TurnUdpError::InvalidAttribute {
                detail: "Allocate response lifetime must be non-zero",
            });
        }
        Ok(AllocationResult {
            relayed_address,
            mapped_address,
            lifetime,
        })
    }

    async fn run(mut self) {
        let Some(mut commands) = self.commands.take() else {
            return;
        };
        loop {
            tokio::select! {
                command = commands.recv() => {
                    let Some(command) = command else {
                        break;
                    };
                    if self.handle_command(command).await {
                        break;
                    }
                }
                received = self.io.receive_record() => {
                    match received {
                        Ok(record) => self.handle_inbound_record(&record),
                        Err(error) => {
                            self.fail(error).await;
                            break;
                        }
                    }
                }
                () = tokio::time::sleep_until(self.allocation_refresh_at) => {
                    if let Err(error) = self.refresh_allocation(self.config.allocation_lifetime_seconds).await {
                        self.fail(error).await;
                        break;
                    }
                }
            }
        }
    }

    async fn handle_command(&mut self, command: Command) -> bool {
        match command {
            Command::PermitPeer { endpoint, response } => {
                let result = self.permit_peer(&endpoint).await;
                let _result = response.send(result);
                false
            }
            Command::PreparePeer { endpoint, response } => {
                let result = self.prepare_peer(&endpoint).await;
                let _result = response.send(result);
                false
            }
            Command::SendIndication {
                endpoint,
                datagram,
                response,
            } => {
                let result = self.send_indication_to_peer(&endpoint, &datagram).await;
                let _result = response.send(result);
                false
            }
            Command::Send {
                endpoint,
                datagram,
                response,
            } => {
                let result = self.send_to_peer(&endpoint, &datagram).await;
                let _result = response.send(result);
                false
            }
            Command::ReplaceCredentials {
                credentials,
                response,
            } => {
                self.credentials = credentials;
                let result = self
                    .refresh_allocation(self.config.allocation_lifetime_seconds)
                    .await;
                let _result = response.send(result);
                false
            }
            Command::Shutdown { response } => {
                let result = self.refresh_allocation(0).await;
                let _result = response.send(result);
                true
            }
        }
    }

    async fn prepare_peer(&mut self, endpoint: &TransportEndpoint) -> Result<(), TurnUdpError> {
        let peer = self.peer_address(endpoint)?;
        self.ensure_permission(endpoint, peer).await?;
        self.ensure_channel(endpoint, peer).await?;
        Ok(())
    }

    async fn permit_peer(&mut self, endpoint: &TransportEndpoint) -> Result<(), TurnUdpError> {
        let peer = self.peer_address(endpoint)?;
        self.ensure_permission(endpoint, peer).await
    }

    async fn send_to_peer(
        &mut self,
        endpoint: &TransportEndpoint,
        datagram: &[u8],
    ) -> Result<(), TurnUdpError> {
        if datagram.len() > self.config.max_datagram_size {
            return Err(TurnUdpError::DatagramTooLarge {
                actual: datagram.len(),
                maximum: self.config.max_datagram_size,
            });
        }
        let peer = self.peer_address(endpoint)?;
        self.prepare_peer(endpoint).await?;
        let channel = self
            .channels
            .get(&peer)
            .map(|binding| binding.channel)
            .ok_or(TurnUdpError::InvalidAttribute {
                detail: "prepared peer has no channel binding",
            })?;
        self.io.send_channel_data(channel, datagram).await
    }

    async fn send_indication_to_peer(
        &mut self,
        endpoint: &TransportEndpoint,
        datagram: &[u8],
    ) -> Result<(), TurnUdpError> {
        if datagram.len() > self.config.max_datagram_size {
            return Err(TurnUdpError::DatagramTooLarge {
                actual: datagram.len(),
                maximum: self.config.max_datagram_size,
            });
        }
        let peer = self.peer_address(endpoint)?;
        self.ensure_permission(endpoint, peer).await?;
        let transaction_id = random_transaction_id()?;
        let encoded = encode_message(
            StunMethod::Send,
            StunClass::Indication,
            transaction_id,
            &[
                OwnedAttribute::new(
                    StunAttributeType::XOR_PEER_ADDRESS,
                    xor_address_value(peer, transaction_id)?,
                ),
                OwnedAttribute::new(StunAttributeType::DATA, datagram.to_vec()),
            ],
        )?;
        self.io.send_record(&encoded).await
    }

    fn peer_address(&self, endpoint: &TransportEndpoint) -> Result<SocketAddr, TurnUdpError> {
        let (carrier, relay_id, peer) = endpoint
            .as_relay()
            .ok_or(TurnUdpError::UnsupportedEndpoint)?;
        if carrier != self.config.carrier || relay_id != self.config.relay_id {
            return Err(TurnUdpError::UnsupportedEndpoint);
        }
        Ok(peer)
    }

    async fn ensure_permission(
        &mut self,
        endpoint: &TransportEndpoint,
        peer: SocketAddr,
    ) -> Result<(), TurnUdpError> {
        self.peers.insert(peer, endpoint.clone());
        let now = Instant::now();
        if self
            .permissions
            .get(&peer.ip())
            .is_some_and(|permission| permission.expires_at > now + PERMISSION_LIFETIME / 2)
        {
            return Ok(());
        }
        let transaction_id = random_transaction_id()?;
        let peer_value = xor_address_value(peer, transaction_id)?;
        self.authenticated_request_with_transaction(
            StunMethod::CreatePermission,
            transaction_id,
            &[OwnedAttribute::new(
                StunAttributeType::XOR_PEER_ADDRESS,
                peer_value,
            )],
        )
        .await?;
        self.permissions.insert(
            peer.ip(),
            Permission {
                expires_at: deadline_after(PERMISSION_LIFETIME, "permission lifetime")?,
            },
        );
        Ok(())
    }

    async fn ensure_channel(
        &mut self,
        endpoint: &TransportEndpoint,
        peer: SocketAddr,
    ) -> Result<(), TurnUdpError> {
        let now = Instant::now();
        if let Some(binding) = self.channels.get_mut(&peer) {
            binding.endpoint = endpoint.clone();
            if binding.expires_at > now + CHANNEL_LIFETIME / 2 {
                return Ok(());
            }
        }
        let channel = if let Some(binding) = self.channels.get(&peer) {
            binding.channel
        } else {
            self.allocate_channel()?
        };
        let transaction_id = random_transaction_id()?;
        let peer_value = xor_address_value(peer, transaction_id)?;
        let mut channel_value = [0_u8; 4];
        channel_value[..2].copy_from_slice(&channel.get().to_be_bytes());
        self.authenticated_request_with_transaction(
            StunMethod::ChannelBind,
            transaction_id,
            &[
                OwnedAttribute::new(StunAttributeType::CHANNEL_NUMBER, channel_value.to_vec()),
                OwnedAttribute::new(StunAttributeType::XOR_PEER_ADDRESS, peer_value),
            ],
        )
        .await?;
        self.channel_peers.insert(channel, peer);
        self.channels.insert(
            peer,
            ChannelBinding {
                channel,
                endpoint: endpoint.clone(),
                expires_at: deadline_after(CHANNEL_LIFETIME, "channel lifetime")?,
            },
        );
        Ok(())
    }

    fn allocate_channel(&mut self) -> Result<TurnChannelNumber, TurnUdpError> {
        for _attempt in 0..=0x3fff_u16 {
            let candidate = self.next_channel;
            self.next_channel = if candidate == 0x7fff {
                0x4000
            } else {
                candidate + 1
            };
            let channel =
                TurnChannelNumber::new(candidate).ok_or(TurnUdpError::ChannelSpaceExhausted)?;
            if !self.channel_peers.contains_key(&channel) {
                return Ok(channel);
            }
        }
        Err(TurnUdpError::ChannelSpaceExhausted)
    }

    async fn refresh_allocation(&mut self, lifetime: u32) -> Result<(), TurnUdpError> {
        let response = self
            .authenticated_request(
                StunMethod::Refresh,
                &[OwnedAttribute::new(
                    StunAttributeType::LIFETIME,
                    lifetime.to_be_bytes().to_vec(),
                )],
            )
            .await?;
        let message = StunMessageView::decode(&response)?;
        let granted = decode_lifetime(&message)?;
        if lifetime == 0 {
            if granted != 0 {
                return Err(TurnUdpError::InvalidAttribute {
                    detail: "Refresh deletion response lifetime must be zero",
                });
            }
            return Ok(());
        }
        if granted == 0 {
            return Err(TurnUdpError::InvalidAttribute {
                detail: "Refresh response lifetime must be non-zero",
            });
        }
        self.schedule_allocation_refresh(granted)
    }

    fn schedule_allocation_refresh(&mut self, lifetime: u32) -> Result<(), TurnUdpError> {
        let allocation_half = Duration::from_secs(u64::from(lifetime)).div_f64(2.0);
        let idle_half =
            Duration::from_secs(u64::from(self.config.idle_timeout_seconds)).div_f64(2.0);
        let interval = allocation_half
            .max(MIN_REFRESH_INTERVAL)
            .min(idle_half.max(MIN_REFRESH_INTERVAL));
        self.allocation_refresh_at = deadline_after(interval, "allocation refresh")?;
        Ok(())
    }

    async fn authenticated_request(
        &mut self,
        method: StunMethod,
        method_attributes: &[OwnedAttribute],
    ) -> Result<Vec<u8>, TurnUdpError> {
        let transaction_id = random_transaction_id()?;
        self.authenticated_request_with_transaction(method, transaction_id, method_attributes)
            .await
    }

    async fn authenticated_request_with_transaction(
        &mut self,
        method: StunMethod,
        transaction_id: StunTransactionId,
        method_attributes: &[OwnedAttribute],
    ) -> Result<Vec<u8>, TurnUdpError> {
        self.credentials.validate_time(unix_time()?)?;
        let request = signed_request(
            method,
            transaction_id,
            &self.credentials,
            &self.auth,
            method_attributes,
        )?;
        let response = self.transact(method, transaction_id, &request).await?;
        match classify_authenticated_response(
            &response,
            method,
            transaction_id,
            &self.credentials,
            &self.auth.realm,
        )? {
            AuthenticatedResponse::Success => Ok(response),
            AuthenticatedResponse::StaleNonce(challenge) => {
                self.auth = challenge;
                let retry_transaction = random_transaction_id()?;
                let retry = signed_request(
                    method,
                    retry_transaction,
                    &self.credentials,
                    &self.auth,
                    method_attributes,
                )?;
                let response = self.transact(method, retry_transaction, &retry).await?;
                match classify_authenticated_response(
                    &response,
                    method,
                    retry_transaction,
                    &self.credentials,
                    &self.auth.realm,
                )? {
                    AuthenticatedResponse::Success => Ok(response),
                    AuthenticatedResponse::StaleNonce(_) => {
                        Err(TurnUdpError::Rejected { method, code: 438 })
                    }
                }
            }
        }
    }

    async fn transact(
        &mut self,
        method: StunMethod,
        transaction_id: StunTransactionId,
        request: &[u8],
    ) -> Result<Vec<u8>, TurnUdpError> {
        let deadline = deadline_after(self.config.transaction_timeout, "transaction timeout")?;
        let mut retransmit = INITIAL_RETRANSMIT_TIMEOUT;
        let reliable = self.io.is_reliable();
        loop {
            self.io.send_record(request).await?;
            let attempt_deadline = if reliable {
                deadline
            } else {
                deadline.min(Instant::now().checked_add(retransmit).ok_or(
                    TurnUdpError::DeadlineOverflow {
                        field: "retransmission timeout",
                    },
                )?)
            };
            loop {
                match timeout_at(attempt_deadline, self.io.receive_record()).await {
                    Ok(Ok(record)) => {
                        if response_matches(&record, method, transaction_id) {
                            return Ok(record);
                        }
                        self.handle_inbound_record(&record);
                    }
                    Ok(Err(error)) => return Err(error),
                    Err(_elapsed) => break,
                }
            }
            if reliable || Instant::now() >= deadline {
                return Err(TurnUdpError::TransactionTimeout { method });
            }
            retransmit = retransmit.saturating_mul(2).min(MAX_RETRANSMIT_TIMEOUT);
        }
    }

    fn handle_inbound_record(&mut self, record: &[u8]) {
        if record.first().is_some_and(|byte| byte & 0xc0 == 0x40) {
            let channel_data = if self.io.is_reliable() {
                TurnChannelDataView::decode_stream(record)
            } else {
                TurnChannelDataView::decode_datagram(record)
            };
            let Ok(channel_data) = channel_data else {
                return;
            };
            let Some(peer) = self.channel_peers.get(&channel_data.channel()).copied() else {
                return;
            };
            let Some(binding) = self.channels.get(&peer) else {
                return;
            };
            self.emit_datagram(binding.endpoint.clone(), channel_data.data().to_vec());
            return;
        }
        let Ok(message) = StunMessageView::decode(record) else {
            return;
        };
        if message.message_type() != StunMessageType::new(StunMethod::Data, StunClass::Indication) {
            return;
        }
        let Ok(peer) =
            required_attribute(&message, StunAttributeType::XOR_PEER_ADDRESS).and_then(|value| {
                decode_stun_xor_address(value, message.transaction_id()).map_err(Into::into)
            })
        else {
            return;
        };
        let Ok(data) = required_attribute(&message, StunAttributeType::DATA) else {
            return;
        };
        if data.len() > self.config.max_datagram_size {
            return;
        }
        let endpoint = self.peers.get(&peer).cloned();
        if let Some(endpoint) = endpoint {
            self.emit_datagram(endpoint, data.to_vec());
        }
    }

    fn emit_datagram(&self, endpoint: TransportEndpoint, data: Vec<u8>) {
        if let Some(inbound) = &self.inbound {
            let _result = inbound.try_send(InboundEvent::Datagram { endpoint, data });
        }
    }

    async fn fail(&self, error: TurnUdpError) {
        if let Some(inbound) = &self.inbound {
            let _result = inbound.send(InboundEvent::Failed(error)).await;
        }
    }
}

enum AuthenticatedResponse {
    Success,
    StaleNonce(AuthContext),
}

struct OwnedAttribute {
    attribute_type: StunAttributeType,
    value: Vec<u8>,
}

impl OwnedAttribute {
    fn new(attribute_type: StunAttributeType, value: Vec<u8>) -> Self {
        Self {
            attribute_type,
            value,
        }
    }
}

async fn initial_challenge(
    io: &mut ClientIo,
    config: TurnClientConfig,
    expected_realm: &[u8],
) -> Result<AuthContext, TurnUdpError> {
    let transaction_id = random_transaction_id()?;
    let lifetime = config.allocation_lifetime_seconds.to_be_bytes();
    let request = encode_message(
        StunMethod::Allocate,
        StunClass::Request,
        transaction_id,
        &[
            OwnedAttribute::new(
                StunAttributeType::REQUESTED_TRANSPORT,
                REQUESTED_TRANSPORT_UDP.to_vec(),
            ),
            OwnedAttribute::new(StunAttributeType::LIFETIME, lifetime.to_vec()),
        ],
    )?;
    let response = transact_initial(
        io,
        StunMethod::Allocate,
        transaction_id,
        &request,
        config.transaction_timeout,
    )
    .await?;
    parse_challenge(
        &response,
        StunMethod::Allocate,
        transaction_id,
        401,
        expected_realm,
    )
}

async fn transact_initial(
    io: &mut ClientIo,
    method: StunMethod,
    transaction_id: StunTransactionId,
    request: &[u8],
    transaction_timeout: Duration,
) -> Result<Vec<u8>, TurnUdpError> {
    let deadline = deadline_after(transaction_timeout, "initial transaction timeout")?;
    let mut retransmit = INITIAL_RETRANSMIT_TIMEOUT;
    let reliable = io.is_reliable();
    loop {
        io.send_record(request).await?;
        let attempt_deadline = if reliable {
            deadline
        } else {
            deadline.min(Instant::now().checked_add(retransmit).ok_or(
                TurnUdpError::DeadlineOverflow {
                    field: "initial retransmission timeout",
                },
            )?)
        };
        loop {
            match timeout_at(attempt_deadline, io.receive_record()).await {
                Ok(Ok(record)) => {
                    if response_matches(&record, method, transaction_id) {
                        return Ok(record);
                    }
                }
                Ok(Err(error)) => return Err(error),
                Err(_elapsed) => break,
            }
        }
        if reliable || Instant::now() >= deadline {
            return Err(TurnUdpError::TransactionTimeout { method });
        }
        retransmit = retransmit.saturating_mul(2).min(MAX_RETRANSMIT_TIMEOUT);
    }
}

fn signed_request(
    method: StunMethod,
    transaction_id: StunTransactionId,
    credentials: &TurnCredentials,
    auth: &AuthContext,
    method_attributes: &[OwnedAttribute],
) -> Result<Vec<u8>, TurnUdpError> {
    let mut algorithm = [0_u8; 4];
    StunPasswordAlgorithm::Sha256.encode(&mut algorithm)?;
    let zero_integrity = [0_u8; 32];
    let mut attributes = vec![
        OwnedAttribute::new(StunAttributeType::USERNAME, credentials.username.to_vec()),
        OwnedAttribute::new(StunAttributeType::REALM, auth.realm.clone()),
        OwnedAttribute::new(StunAttributeType::NONCE, auth.nonce.to_vec()),
        OwnedAttribute::new(StunAttributeType::PASSWORD_ALGORITHM, algorithm.to_vec()),
    ];
    attributes.extend(
        method_attributes.iter().map(|attribute| {
            OwnedAttribute::new(attribute.attribute_type, attribute.value.clone())
        }),
    );
    attributes.push(OwnedAttribute::new(
        StunAttributeType::MESSAGE_INTEGRITY_SHA256,
        zero_integrity.to_vec(),
    ));
    let mut encoded = encode_message(method, StunClass::Request, transaction_id, &attributes)?;
    sign_message(&mut encoded, credentials, &auth.realm)?;
    Ok(encoded)
}

fn encode_message(
    method: StunMethod,
    class: StunClass,
    transaction_id: StunTransactionId,
    attributes: &[OwnedAttribute],
) -> Result<Vec<u8>, TurnUdpError> {
    let references = attributes
        .iter()
        .map(|attribute| StunAttributeRef {
            attribute_type: attribute.attribute_type,
            value: &attribute.value,
        })
        .collect::<Vec<_>>();
    let message = StunMessageRef {
        message_type: StunMessageType::new(method, class),
        transaction_id,
        attributes: &references,
    };
    let mut encoded = vec![0_u8; message.encoded_len()?];
    let length = encode_stun_message(message, &mut encoded)?;
    encoded.truncate(length);
    Ok(encoded)
}

fn sign_message(
    encoded: &mut [u8],
    credentials: &TurnCredentials,
    realm: &[u8],
) -> Result<(), TurnUdpError> {
    let (offset, tag) = {
        let message = StunMessageView::decode(encoded)?;
        let integrity = message.message_integrity_sha256()?;
        let key = long_term_key(credentials, realm);
        let mut mac = <HmacSha256 as KeyInit>::new_from_slice(key.as_ref())
            .map_err(|_| TurnUdpError::ResponseIntegrity)?;
        mac.update(integrity.message_type_bytes());
        mac.update(&integrity.adjusted_body_length().to_be_bytes());
        mac.update(integrity.bytes_after_length());
        (integrity.value_offset(), mac.finalize().into_bytes())
    };
    let destination = encoded
        .get_mut(offset..offset.saturating_add(tag.len()))
        .ok_or(TurnUdpError::ResponseIntegrity)?;
    destination.copy_from_slice(&tag);
    Ok(())
}

fn verify_message_integrity(
    message: &StunMessageView<'_>,
    credentials: &TurnCredentials,
    realm: &[u8],
) -> Result<(), TurnUdpError> {
    let integrity = message
        .message_integrity_sha256()
        .map_err(|_| TurnUdpError::ResponseIntegrity)?;
    let key = long_term_key(credentials, realm);
    let mut mac = <HmacSha256 as KeyInit>::new_from_slice(key.as_ref())
        .map_err(|_| TurnUdpError::ResponseIntegrity)?;
    mac.update(integrity.message_type_bytes());
    mac.update(&integrity.adjusted_body_length().to_be_bytes());
    mac.update(integrity.bytes_after_length());
    mac.verify_slice(integrity.value())
        .map_err(|_| TurnUdpError::ResponseIntegrity)
}

fn long_term_key(credentials: &TurnCredentials, realm: &[u8]) -> Zeroizing<[u8; 32]> {
    Zeroizing::new(sha256_segments(&[
        &credentials.username,
        b":",
        realm,
        b":",
        &credentials.password,
    ]))
}

fn classify_authenticated_response(
    encoded: &[u8],
    method: StunMethod,
    transaction_id: StunTransactionId,
    credentials: &TurnCredentials,
    realm: &[u8],
) -> Result<AuthenticatedResponse, TurnUdpError> {
    let message = StunMessageView::decode(encoded)?;
    if message.message_type().method != method || message.transaction_id() != transaction_id {
        return Err(TurnUdpError::UnexpectedResponse { method });
    }
    verify_message_integrity(&message, credentials, realm)?;
    match message.message_type().class {
        StunClass::SuccessResponse => Ok(AuthenticatedResponse::Success),
        StunClass::ErrorResponse => {
            let code = response_error_code(&message)?;
            if code == 438 {
                let challenge = parse_challenge(encoded, method, transaction_id, 438, realm)?;
                Ok(AuthenticatedResponse::StaleNonce(challenge))
            } else {
                Err(TurnUdpError::Rejected { method, code })
            }
        }
        StunClass::Request | StunClass::Indication => {
            Err(TurnUdpError::UnexpectedResponse { method })
        }
    }
}

fn parse_challenge(
    encoded: &[u8],
    method: StunMethod,
    transaction_id: StunTransactionId,
    expected_code: u16,
    expected_realm: &[u8],
) -> Result<AuthContext, TurnUdpError> {
    let message = StunMessageView::decode(encoded)?;
    if message.message_type() != StunMessageType::new(method, StunClass::ErrorResponse)
        || message.transaction_id() != transaction_id
        || response_error_code(&message)? != expected_code
    {
        return Err(TurnUdpError::UnexpectedResponse { method });
    }
    let realm = required_attribute(&message, StunAttributeType::REALM)?;
    if realm != expected_realm {
        return Err(TurnUdpError::InvalidAttribute {
            detail: "challenge realm does not match configured relay",
        });
    }
    let nonce = required_attribute(&message, StunAttributeType::NONCE)?;
    if nonce.is_empty() {
        return Err(TurnUdpError::InvalidAttribute {
            detail: "challenge nonce must be non-empty",
        });
    }
    let algorithm = required_attribute(&message, StunAttributeType::PASSWORD_ALGORITHM)?;
    if StunPasswordAlgorithm::decode(algorithm)? != StunPasswordAlgorithm::Sha256 {
        return Err(TurnUdpError::InvalidAttribute {
            detail: "challenge password algorithm is unsupported",
        });
    }
    Ok(AuthContext {
        realm: realm.to_vec(),
        nonce: Zeroizing::new(nonce.to_vec()),
    })
}

fn response_matches(encoded: &[u8], method: StunMethod, transaction_id: StunTransactionId) -> bool {
    if encoded.first().is_none_or(|byte| byte & 0xc0 != 0) {
        return false;
    }
    let message = match StunMessageView::decode(encoded) {
        Ok(message) => message,
        Err(_error) => return false,
    };
    message.message_type().method == method
        && message.transaction_id() == transaction_id
        && matches!(
            message.message_type().class,
            StunClass::SuccessResponse | StunClass::ErrorResponse
        )
}

fn response_error_code(message: &StunMessageView<'_>) -> Result<u16, TurnUdpError> {
    Ok(
        StunErrorCodeView::decode(required_attribute(message, StunAttributeType::ERROR_CODE)?)?
            .code(),
    )
}

fn decode_lifetime(message: &StunMessageView<'_>) -> Result<u32, TurnUdpError> {
    let value = required_attribute(message, StunAttributeType::LIFETIME)?;
    let bytes = <[u8; 4]>::try_from(value).map_err(|_| TurnUdpError::InvalidAttribute {
        detail: "LIFETIME must contain four bytes",
    })?;
    Ok(u32::from_be_bytes(bytes))
}

fn required_attribute<'a>(
    message: &StunMessageView<'a>,
    requested: StunAttributeType,
) -> Result<&'a [u8], TurnUdpError> {
    let mut found = None;
    for attribute in message.attributes() {
        let attribute = attribute?;
        if attribute.attribute_type() == requested && found.replace(attribute.value()).is_some() {
            return Err(TurnUdpError::InvalidAttributeCardinality {
                attribute: requested,
            });
        }
    }
    found.ok_or(TurnUdpError::InvalidAttributeCardinality {
        attribute: requested,
    })
}

fn xor_address_value(
    address: SocketAddr,
    transaction_id: StunTransactionId,
) -> Result<Vec<u8>, TurnUdpError> {
    let mut value = vec![0_u8; if address.is_ipv4() { 8 } else { 20 }];
    let length = encode_stun_xor_address(address, transaction_id, &mut value)?;
    value.truncate(length);
    Ok(value)
}

fn random_transaction_id() -> Result<StunTransactionId, TurnUdpError> {
    let mut bytes = [0_u8; 12];
    getrandom::fill(&mut bytes).map_err(|_| TurnUdpError::RandomnessUnavailable)?;
    Ok(StunTransactionId::from_bytes(bytes))
}

fn deadline_after(duration: Duration, field: &'static str) -> Result<Instant, TurnUdpError> {
    Instant::now()
        .checked_add(duration)
        .ok_or(TurnUdpError::DeadlineOverflow { field })
}

fn unix_time() -> Result<u64, TurnUdpError> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .map_err(|_| TurnUdpError::InvalidConfig {
            field: "system time",
            reason: "must not predate the Unix epoch",
        })
}

#[cfg(test)]
mod tests {
    use std::{
        net::{IpAddr, Ipv4Addr, SocketAddr},
        time::{Duration, SystemTime, UNIX_EPOCH},
    };

    #[cfg(windows)]
    use std::{
        path::PathBuf,
        sync::atomic::{AtomicU64, Ordering},
    };

    use stella_common::{NodeId, RelayId};
    use stella_proto::RelayTrustRequirements;
    use stella_server::{
        relay_credentials::RelayCredentialAuthority,
        turn_relay::{TurnTcpRelay, TurnTcpRelayConfig, TurnUdpRelay, TurnUdpRelayConfig},
    };
    #[cfg(windows)]
    use stella_server::{
        tls::{create_self_signed_tls_identity, load_tls_server_config, DEFAULT_TLS_VALIDITY_DAYS},
        turn_relay::TurnTlsRelay,
    };
    use stella_transport::{
        Endpoint as TransportEndpoint, TurnStream, MAX_TURN_STREAM_RECORD_SIZE,
    };
    use tokio::{net::TcpListener, sync::oneshot, time::timeout};
    use tokio_tungstenite::tungstenite::http::{
        header::{AUTHORIZATION, SEC_WEBSOCKET_EXTENSIONS, SEC_WEBSOCKET_PROTOCOL},
        Response,
    };

    use super::{
        encode_message, transact_initial, validate_websocket_upgrade_response,
        websocket_upgrade_request, ClientIo, TurnCredentials, TurnTcpClient, TurnTcpClientConfig,
        TurnUdpClient, TurnUdpClientConfig, TurnUdpError, TurnWebSocketClientConfig,
    };
    #[cfg(windows)]
    use super::{TurnTlsClient, TurnTlsClientConfig};

    #[cfg(windows)]
    static TEMP_SEQUENCE: AtomicU64 = AtomicU64::new(1);

    #[tokio::test]
    async fn reliable_transactions_use_one_complete_framed_exchange() {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("bind TCP listener");
        let server_address = listener.local_addr().expect("TCP listener address");
        let transaction_id = stella_proto::StunTransactionId::from_bytes([0x33; 12]);
        let request = encode_message(
            stella_proto::StunMethod::Binding,
            stella_proto::StunClass::Request,
            transaction_id,
            &[],
        )
        .expect("encode request");
        let response = encode_message(
            stella_proto::StunMethod::Binding,
            stella_proto::StunClass::SuccessResponse,
            transaction_id,
            &[],
        )
        .expect("encode response");
        let expected_request = request.clone();
        let server = tokio::spawn(async move {
            let (stream, _client) = listener.accept().await.expect("accept TCP client");
            let mut stream =
                TurnStream::new(stream, MAX_TURN_STREAM_RECORD_SIZE).expect("frame server stream");
            assert_eq!(
                stream.read_record().await.expect("read request"),
                expected_request
            );
            stream
                .write_record(&response)
                .await
                .expect("write response");
        });
        let config = TurnTcpClientConfig::new(
            RelayId::from_bytes([0x44; 16]),
            server_address,
            SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
        );
        config.validate().expect("validate TCP client config");
        let stream = tokio::net::TcpStream::connect(server_address)
            .await
            .expect("connect TCP client");
        let mut io = ClientIo::Tcp(
            TurnStream::new(stream, MAX_TURN_STREAM_RECORD_SIZE).expect("frame client stream"),
        );
        let received = transact_initial(
            &mut io,
            stella_proto::StunMethod::Binding,
            transaction_id,
            &request,
            Duration::from_secs(1),
        )
        .await
        .expect("complete reliable transaction");
        assert_eq!(received.len(), 20);
        server.await.expect("server task");
    }

    #[tokio::test]
    #[allow(clippy::too_many_lines)]
    async fn allocations_authenticate_refresh_and_relay_channel_datagrams() {
        let relay_id = RelayId::from_bytes([0x11; 16]);
        let authority =
            RelayCredentialAuthority::new([0x42; 32], 300).expect("credential authority");
        let now = unix_time_for_test();
        let credential_a = authority
            .issue(relay_id, NodeId::from_bytes([0x21; 16]), now)
            .expect("issue A credential");
        let credential_b = authority
            .issue(relay_id, NodeId::from_bytes([0x22; 16]), now)
            .expect("issue B credential");
        let replacement = authority
            .issue(
                relay_id,
                NodeId::from_bytes([0x21; 16]),
                now.saturating_add(1),
            )
            .expect("replacement credential");
        let mut relay_config = TurnUdpRelayConfig::new(
            relay_id,
            SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            IpAddr::V4(Ipv4Addr::LOCALHOST),
        );
        relay_config.max_datagram_size = 1_200;
        let relay = TurnUdpRelay::bind(relay_config, authority)
            .await
            .expect("bind relay");
        let relay_address = relay.local_address().expect("relay address");
        let (shutdown_sender, shutdown_receiver) = oneshot::channel();
        let relay_task = tokio::spawn(relay.run(async move {
            let _result = shutdown_receiver.await;
        }));

        let client_config = TurnUdpClientConfig::new(
            relay_id,
            relay_address,
            SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
        );
        let client_a = TurnUdpClient::allocate(
            client_config,
            TurnCredentials::new(
                credential_a.username().to_vec(),
                credential_a.secret().to_vec(),
                credential_a.expires_at(),
            )
            .expect("A credentials"),
        )
        .await
        .expect("allocate A");
        let client_b = TurnUdpClient::allocate(
            client_config,
            TurnCredentials::new(
                credential_b.username().to_vec(),
                credential_b.secret().to_vec(),
                credential_b.expires_at(),
            )
            .expect("B credentials"),
        )
        .await
        .expect("allocate B");
        let endpoint_a = TransportEndpoint::TurnUdp {
            relay_id,
            address: client_a.relayed_address(),
        };
        let endpoint_b = TransportEndpoint::TurnUdp {
            relay_id,
            address: client_b.relayed_address(),
        };
        client_a
            .permit_peer(&endpoint_b)
            .await
            .expect("permit B from A");
        client_b
            .permit_peer(&endpoint_a)
            .await
            .expect("permit A from B");
        client_a
            .send_indication_to(&endpoint_b, b"A indication to B")
            .await
            .expect("send indication A to B");
        let mut received = [0_u8; 64];
        let metadata = timeout(Duration::from_secs(2), client_b.receive(&mut received))
            .await
            .expect("B indication timeout")
            .expect("B indication receive");
        assert_eq!(metadata.source, endpoint_a);
        assert_eq!(&received[..metadata.length], b"A indication to B");

        client_a
            .prepare_peer(&endpoint_b)
            .await
            .expect("prepare B from A");
        client_b
            .prepare_peer(&endpoint_a)
            .await
            .expect("prepare A from B");

        client_a
            .send_to(&endpoint_b, b"A to B")
            .await
            .expect("relay A to B");
        let metadata = timeout(Duration::from_secs(2), client_b.receive(&mut received))
            .await
            .expect("B receive timeout")
            .expect("B receive");
        assert_eq!(metadata.source, endpoint_a);
        assert_eq!(&received[..metadata.length], b"A to B");

        client_b
            .send_to(&endpoint_a, b"B to A")
            .await
            .expect("relay B to A");
        let metadata = timeout(Duration::from_secs(2), client_a.receive(&mut received))
            .await
            .expect("A receive timeout")
            .expect("A receive");
        assert_eq!(metadata.source, endpoint_b);
        assert_eq!(&received[..metadata.length], b"B to A");

        client_a
            .replace_credentials(
                TurnCredentials::new(
                    replacement.username().to_vec(),
                    replacement.secret().to_vec(),
                    replacement.expires_at(),
                )
                .expect("replacement credentials"),
            )
            .await
            .expect("refresh with replacement credential");

        client_a.shutdown().await.expect("shutdown A");
        client_b.shutdown().await.expect("shutdown B");
        let _result = shutdown_sender.send(());
        timeout(Duration::from_secs(2), relay_task)
            .await
            .expect("relay shutdown timeout")
            .expect("relay task join")
            .expect("relay run");
    }

    #[tokio::test]
    #[allow(clippy::too_many_lines)]
    async fn tcp_allocations_preserve_datagrams_in_both_directions() {
        let relay_id = RelayId::from_bytes([0x31; 16]);
        let authority =
            RelayCredentialAuthority::new([0x52; 32], 300).expect("credential authority");
        let now = unix_time_for_test();
        let credential_a = authority
            .issue(relay_id, NodeId::from_bytes([0x41; 16]), now)
            .expect("issue A credential");
        let credential_b = authority
            .issue(relay_id, NodeId::from_bytes([0x42; 16]), now)
            .expect("issue B credential");
        let mut relay_config = TurnTcpRelayConfig::new(
            relay_id,
            SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            IpAddr::V4(Ipv4Addr::LOCALHOST),
        );
        relay_config.max_datagram_size = 1_200;
        let relay = TurnTcpRelay::bind(relay_config, authority)
            .await
            .expect("bind TCP relay");
        let relay_address = relay.local_address().expect("TCP relay address");
        let (shutdown_sender, shutdown_receiver) = oneshot::channel();
        let relay_task = tokio::spawn(relay.run(async move {
            let _result = shutdown_receiver.await;
        }));

        let client_config = TurnTcpClientConfig::new(
            relay_id,
            relay_address,
            SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
        );
        let client_a = TurnTcpClient::allocate(
            client_config,
            TurnCredentials::new(
                credential_a.username().to_vec(),
                credential_a.secret().to_vec(),
                credential_a.expires_at(),
            )
            .expect("A credentials"),
        )
        .await
        .expect("allocate A over TCP");
        let client_b = TurnTcpClient::allocate(
            client_config,
            TurnCredentials::new(
                credential_b.username().to_vec(),
                credential_b.secret().to_vec(),
                credential_b.expires_at(),
            )
            .expect("B credentials"),
        )
        .await
        .expect("allocate B over TCP");
        assert_eq!(client_a.mapped_address(), client_a.local_address());
        assert_eq!(client_b.mapped_address(), client_b.local_address());
        let endpoint_a = TransportEndpoint::TurnTcp {
            relay_id,
            address: client_a.relayed_address(),
        };
        let endpoint_b = TransportEndpoint::TurnTcp {
            relay_id,
            address: client_b.relayed_address(),
        };
        client_a
            .prepare_peer(&endpoint_b)
            .await
            .expect("prepare B from A");
        client_b
            .prepare_peer(&endpoint_a)
            .await
            .expect("prepare A from B");

        let mut received = [0_u8; 64];
        client_a
            .send_to(&endpoint_b, b"A to B over TCP")
            .await
            .expect("relay A to B");
        let metadata = timeout(Duration::from_secs(2), client_b.receive(&mut received))
            .await
            .expect("B receive timeout")
            .expect("B receive");
        assert_eq!(metadata.source, endpoint_a);
        assert_eq!(&received[..metadata.length], b"A to B over TCP");

        client_b
            .send_to(&endpoint_a, b"B to A over TCP")
            .await
            .expect("relay B to A");
        let metadata = timeout(Duration::from_secs(2), client_a.receive(&mut received))
            .await
            .expect("A receive timeout")
            .expect("A receive");
        assert_eq!(metadata.source, endpoint_b);
        assert_eq!(&received[..metadata.length], b"B to A over TCP");

        client_a.shutdown().await.expect("shutdown A");
        client_b.shutdown().await.expect("shutdown B");
        let _result = shutdown_sender.send(());
        timeout(Duration::from_secs(2), relay_task)
            .await
            .expect("relay shutdown timeout")
            .expect("relay task join")
            .expect("relay run");
    }

    #[cfg(windows)]
    #[tokio::test]
    #[allow(clippy::too_many_lines)]
    async fn tls_allocations_validate_pins_and_preserve_datagrams() {
        let directory = temp_directory();
        std::fs::create_dir(&directory).expect("create TLS test directory");
        let certificate = directory.join("relay-cert.pem");
        let private_key = directory.join("relay-key.pem");
        let identity = create_self_signed_tls_identity(
            &certificate,
            &private_key,
            &[],
            DEFAULT_TLS_VALIDITY_DAYS,
        )
        .expect("create relay TLS identity");
        let tls_config =
            load_tls_server_config(&certificate, &private_key).expect("load relay TLS identity");

        let relay_id = RelayId::from_bytes([0x61; 16]);
        let authority =
            RelayCredentialAuthority::new([0x62; 32], 300).expect("credential authority");
        let now = unix_time_for_test();
        let credential_a = authority
            .issue(relay_id, NodeId::from_bytes([0x63; 16]), now)
            .expect("issue A credential");
        let credential_b = authority
            .issue(relay_id, NodeId::from_bytes([0x64; 16]), now)
            .expect("issue B credential");
        let mut relay_config = TurnTcpRelayConfig::new(
            relay_id,
            SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            IpAddr::V4(Ipv4Addr::LOCALHOST),
        );
        relay_config.max_datagram_size = 1_200;
        let relay = TurnTlsRelay::bind(relay_config, authority, tls_config, Duration::from_secs(2))
            .await
            .expect("bind TLS relay");
        let relay_address = relay.local_address().expect("TLS relay address");
        let (shutdown_sender, shutdown_receiver) = oneshot::channel();
        let relay_task = tokio::spawn(relay.run(async move {
            let _result = shutdown_receiver.await;
        }));

        let client_config = TurnTlsClientConfig::new(
            relay_id,
            relay_address,
            SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
            "localhost".to_owned(),
            RelayTrustRequirements::SPKI_PIN,
            vec![identity.spki_sha256],
        );
        let client_a = TurnTlsClient::allocate(
            client_config.clone(),
            TurnCredentials::new(
                credential_a.username().to_vec(),
                credential_a.secret().to_vec(),
                credential_a.expires_at(),
            )
            .expect("A credentials"),
        )
        .await
        .expect("allocate A over TLS");
        let client_b = TurnTlsClient::allocate(
            client_config,
            TurnCredentials::new(
                credential_b.username().to_vec(),
                credential_b.secret().to_vec(),
                credential_b.expires_at(),
            )
            .expect("B credentials"),
        )
        .await
        .expect("allocate B over TLS");
        let endpoint_a = TransportEndpoint::TurnTls {
            relay_id,
            address: client_a.relayed_address(),
        };
        let endpoint_b = TransportEndpoint::TurnTls {
            relay_id,
            address: client_b.relayed_address(),
        };
        client_a
            .prepare_peer(&endpoint_b)
            .await
            .expect("prepare B from A");
        client_b
            .prepare_peer(&endpoint_a)
            .await
            .expect("prepare A from B");

        let mut received = [0_u8; 64];
        client_a
            .send_to(&endpoint_b, b"A to B over TLS")
            .await
            .expect("relay A to B");
        let metadata = timeout(Duration::from_secs(2), client_b.receive(&mut received))
            .await
            .expect("B receive timeout")
            .expect("B receive");
        assert_eq!(metadata.source, endpoint_a);
        assert_eq!(&received[..metadata.length], b"A to B over TLS");

        client_b
            .send_to(&endpoint_a, b"B to A over TLS")
            .await
            .expect("relay B to A");
        let metadata = timeout(Duration::from_secs(2), client_a.receive(&mut received))
            .await
            .expect("A receive timeout")
            .expect("A receive");
        assert_eq!(metadata.source, endpoint_b);
        assert_eq!(&received[..metadata.length], b"B to A over TLS");

        client_a.shutdown().await.expect("shutdown A");
        client_b.shutdown().await.expect("shutdown B");
        let _result = shutdown_sender.send(());
        timeout(Duration::from_secs(2), relay_task)
            .await
            .expect("relay shutdown timeout")
            .expect("relay task join")
            .expect("relay run");
        std::fs::remove_dir_all(&directory).expect("remove TLS test directory");
    }

    #[test]
    fn websocket_upgrade_request_and_response_are_strict_and_canonical() {
        let config = TurnWebSocketClientConfig::new(
            RelayId::from_bytes([0x77; 16]),
            "192.0.2.30:443".parse().expect("relay address"),
            "0.0.0.0:0".parse().expect("bind address"),
            "relay.example.test".to_owned(),
            RelayTrustRequirements::SPKI_PIN,
            vec![[1; 32]],
        );
        let credentials =
            TurnCredentials::new(b"123:node".to_vec(), b"0123456789abcdef".to_vec(), 100)
                .expect("credentials");
        let request = websocket_upgrade_request(&config, &credentials).expect("upgrade request");
        assert_eq!(
            request.uri().to_string(),
            "wss://relay.example.test:443/stella/turn/v1"
        );
        assert_eq!(
            request
                .headers()
                .get(SEC_WEBSOCKET_PROTOCOL)
                .expect("subprotocol"),
            "stella-turn.v1"
        );
        assert_eq!(
            request.headers().get(AUTHORIZATION).expect("authorization"),
            "Stella MTIzOm5vZGU.MDEyMzQ1Njc4OWFiY2RlZg"
        );
        assert!(!request.headers().contains_key(SEC_WEBSOCKET_EXTENSIONS));

        let accepted = Response::builder()
            .header(SEC_WEBSOCKET_PROTOCOL, "stella-turn.v1")
            .body(())
            .expect("accepted response");
        validate_websocket_upgrade_response(&accepted).expect("valid response");
        let compressed = Response::builder()
            .header(SEC_WEBSOCKET_PROTOCOL, "stella-turn.v1")
            .header(SEC_WEBSOCKET_EXTENSIONS, "permessage-deflate")
            .body(())
            .expect("compressed response");
        assert!(matches!(
            validate_websocket_upgrade_response(&compressed),
            Err(TurnUdpError::InvalidWebSocketUpgrade { .. })
        ));
        let wrong_protocol = Response::builder()
            .header(SEC_WEBSOCKET_PROTOCOL, "other")
            .body(())
            .expect("wrong protocol response");
        assert!(matches!(
            validate_websocket_upgrade_response(&wrong_protocol),
            Err(TurnUdpError::InvalidWebSocketUpgrade { .. })
        ));
    }

    #[test]
    fn credentials_and_client_errors_do_not_expose_secrets() {
        let credentials =
            TurnCredentials::new(b"private-user".to_vec(), b"private-password".to_vec(), 100)
                .expect("credentials");
        let diagnostic = format!("{credentials:?}");
        assert!(!diagnostic.contains("private-user"));
        assert!(!diagnostic.contains("private-password"));
        assert!(matches!(
            TurnCredentials::new(Vec::new(), vec![1], 100),
            Err(TurnUdpError::InvalidConfig {
                field: "TURN credentials",
                ..
            })
        ));
    }

    fn unix_time_for_test() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("test clock")
            .as_secs()
    }

    #[cfg(windows)]
    fn temp_directory() -> PathBuf {
        let sequence = TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        std::env::temp_dir().join(format!("stella-turn-tls-{}-{sequence}", std::process::id()))
    }
}
