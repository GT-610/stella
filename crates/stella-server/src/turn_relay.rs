//! Bounded authenticated TURN relay runtimes over UDP and TCP.

use std::{
    collections::{HashMap, VecDeque},
    fmt,
    future::Future,
    net::{IpAddr, SocketAddr},
    sync::Arc,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use futures_util::StreamExt;
use stella_common::{NodeId, RelayId};
use stella_proto::{
    decode_stun_xor_address, encode_stun_error_code, encode_stun_message, encode_stun_xor_address,
    encode_turn_channel_data, encode_turn_channel_data_stream, CodecError, StunAttributeRef,
    StunAttributeType, StunClass, StunMessageRef, StunMessageType, StunMessageView, StunMethod,
    StunTransactionId, TurnChannelDataView, TurnChannelNumber,
};
use stella_transport::{
    read_websocket_record, turn_websocket_config, write_websocket_record, TurnStream,
    WebSocketRecordError, MAX_TURN_STREAM_RECORD_SIZE, STELLA_TURN_WEBSOCKET_PATH,
    STELLA_TURN_WEBSOCKET_SUBPROTOCOL,
};
use thiserror::Error;
use tokio::{
    io::{AsyncRead, AsyncWrite},
    net::{TcpListener, UdpSocket},
    sync::{mpsc, oneshot, Mutex},
    task::JoinSet,
    time::{timeout, MissedTickBehavior},
};
use tokio_rustls::{rustls::ServerConfig, TlsAcceptor};
use tokio_tungstenite::{
    accept_hdr_async_with_config,
    tungstenite::{
        handshake::server::{
            ErrorResponse, Request as WebSocketRequest, Response as WebSocketResponse,
        },
        http::{
            header::{AUTHORIZATION, SEC_WEBSOCKET_EXTENSIONS, SEC_WEBSOCKET_PROTOCOL},
            HeaderValue, StatusCode,
        },
        protocol::WebSocketConfig,
        Error as WebSocketError,
    },
    WebSocketStream,
};
use zeroize::Zeroizing;

use crate::{
    relay_credentials::{RelayCredentialAuthority, TurnNonceStatus},
    turn_auth::{AuthenticatedTurnRequest, TurnAuthenticationError, TurnAuthenticator},
};

const SOFTWARE: &[u8] = b"stella-server/0.1";
const REQUESTED_TRANSPORT_UDP: [u8; 4] = [17, 0, 0, 0];
const RESPONSE_CACHE_LIFETIME: Duration = Duration::from_secs(40);
const RESPONSE_CACHE_CAPACITY: usize = 4_096;
const RECEIVE_BUFFER_LENGTH: usize = u16::MAX as usize;
const ALLOCATION_COMMAND_CAPACITY: usize = 256;
const PERMISSION_LIFETIME: Duration = Duration::from_secs(300);
const CHANNEL_BINDING_LIFETIME: Duration = Duration::from_secs(600);
const MAX_TLS_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(60);

/// Runtime limits and addresses for one TURN UDP listener.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TurnUdpRelayConfig {
    /// Stable relay identity used by controller-issued credentials.
    pub relay_id: RelayId,
    /// Client-facing TURN UDP listener address.
    pub listen_address: SocketAddr,
    /// Local IP used when binding per-client allocation sockets.
    pub allocation_bind_address: IpAddr,
    /// Address returned to clients in XOR-RELAYED-ADDRESS.
    pub advertised_address: IpAddr,
    /// Largest relayed Stella datagram accepted by this deployment.
    pub max_datagram_size: usize,
    /// Maximum granted allocation lifetime.
    pub allocation_lifetime_seconds: u32,
    /// Allocation inactivity deadline.
    pub idle_timeout_seconds: u32,
    /// Global active allocation limit.
    pub max_allocations: usize,
    /// Active allocation limit for one authenticated node.
    pub max_allocations_per_node: usize,
    /// Maximum simultaneously permitted peer IPs per allocation.
    pub max_permissions_per_allocation: usize,
    /// Maximum live channel bindings per allocation.
    pub max_channels_per_allocation: usize,
}

impl TurnUdpRelayConfig {
    /// Creates conservative defaults around one listener and advertised IP.
    #[must_use]
    pub const fn new(
        relay_id: RelayId,
        listen_address: SocketAddr,
        allocation_bind_address: IpAddr,
        advertised_address: IpAddr,
    ) -> Self {
        Self {
            relay_id,
            listen_address,
            allocation_bind_address,
            advertised_address,
            max_datagram_size: 1_200,
            allocation_lifetime_seconds: 600,
            idle_timeout_seconds: 120,
            max_allocations: 1_024,
            max_allocations_per_node: 4,
            max_permissions_per_allocation: 128,
            max_channels_per_allocation: 128,
        }
    }

    fn validate(self) -> Result<(), TurnRelayError> {
        if self.relay_id.is_zero() {
            return Err(invalid_config("relay ID must be non-zero"));
        }
        let family = self.listen_address.is_ipv4();
        if self.allocation_bind_address.is_ipv4() != family
            || self.advertised_address.is_ipv4() != family
        {
            return Err(invalid_config(
                "listener, allocation bind, and advertised addresses must use one family",
            ));
        }
        if self.advertised_address.is_unspecified()
            || self.advertised_address.is_multicast()
            || self.max_datagram_size < 1_200
            || self.max_datagram_size > 65_507
        {
            return Err(invalid_config(
                "advertised address or maximum datagram size is invalid",
            ));
        }
        if !(60..=3_600).contains(&self.allocation_lifetime_seconds) {
            return Err(invalid_config(
                "allocation lifetime must be between 60 and 3600 seconds",
            ));
        }
        if !(30..=3_600).contains(&self.idle_timeout_seconds) {
            return Err(invalid_config(
                "idle timeout must be between 30 and 3600 seconds",
            ));
        }
        if self.max_allocations == 0
            || self.max_allocations > 65_535
            || self.max_allocations_per_node == 0
            || self.max_allocations_per_node > self.max_allocations
        {
            return Err(invalid_config("allocation count limits are invalid"));
        }
        if self.max_permissions_per_allocation == 0
            || self.max_permissions_per_allocation > 128
            || self.max_channels_per_allocation == 0
            || self.max_channels_per_allocation > self.max_permissions_per_allocation
        {
            return Err(invalid_config("permission or channel limits are invalid"));
        }
        Ok(())
    }
}

/// Runtime limits and addresses for one TURN TCP listener.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TurnTcpRelayConfig {
    /// Stable relay identity used by controller-issued credentials.
    pub relay_id: RelayId,
    /// Client-facing TURN TCP listener address.
    pub listen_address: SocketAddr,
    /// Local IP used when binding per-client allocation sockets.
    pub allocation_bind_address: IpAddr,
    /// Address returned to clients in XOR-RELAYED-ADDRESS.
    pub advertised_address: IpAddr,
    /// Largest relayed Stella datagram accepted by this deployment.
    pub max_datagram_size: usize,
    /// Maximum granted allocation lifetime.
    pub allocation_lifetime_seconds: u32,
    /// Allocation inactivity deadline.
    pub idle_timeout_seconds: u32,
    /// Global active allocation limit.
    pub max_allocations: usize,
    /// Active allocation limit for one authenticated node.
    pub max_allocations_per_node: usize,
    /// Maximum simultaneously permitted peer IPs per allocation.
    pub max_permissions_per_allocation: usize,
    /// Maximum live channel bindings per allocation.
    pub max_channels_per_allocation: usize,
}

impl TurnTcpRelayConfig {
    /// Creates conservative defaults around one TCP listener and advertised IP.
    #[must_use]
    pub const fn new(
        relay_id: RelayId,
        listen_address: SocketAddr,
        allocation_bind_address: IpAddr,
        advertised_address: IpAddr,
    ) -> Self {
        let udp = TurnUdpRelayConfig::new(
            relay_id,
            listen_address,
            allocation_bind_address,
            advertised_address,
        );
        Self {
            relay_id: udp.relay_id,
            listen_address: udp.listen_address,
            allocation_bind_address: udp.allocation_bind_address,
            advertised_address: udp.advertised_address,
            max_datagram_size: udp.max_datagram_size,
            allocation_lifetime_seconds: udp.allocation_lifetime_seconds,
            idle_timeout_seconds: udp.idle_timeout_seconds,
            max_allocations: udp.max_allocations,
            max_allocations_per_node: udp.max_allocations_per_node,
            max_permissions_per_allocation: udp.max_permissions_per_allocation,
            max_channels_per_allocation: udp.max_channels_per_allocation,
        }
    }

    fn validate(self) -> Result<(), TurnRelayError> {
        TurnRelayRuntimeConfig::from(self).validate(self.listen_address)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct TurnRelayRuntimeConfig {
    relay_id: RelayId,
    allocation_bind_address: IpAddr,
    advertised_address: IpAddr,
    max_datagram_size: usize,
    allocation_lifetime_seconds: u32,
    idle_timeout_seconds: u32,
    max_allocations: usize,
    max_allocations_per_node: usize,
    max_permissions_per_allocation: usize,
    max_channels_per_allocation: usize,
}

impl TurnRelayRuntimeConfig {
    fn validate(self, listen_address: SocketAddr) -> Result<(), TurnRelayError> {
        let config = TurnUdpRelayConfig {
            relay_id: self.relay_id,
            listen_address,
            allocation_bind_address: self.allocation_bind_address,
            advertised_address: self.advertised_address,
            max_datagram_size: self.max_datagram_size,
            allocation_lifetime_seconds: self.allocation_lifetime_seconds,
            idle_timeout_seconds: self.idle_timeout_seconds,
            max_allocations: self.max_allocations,
            max_allocations_per_node: self.max_allocations_per_node,
            max_permissions_per_allocation: self.max_permissions_per_allocation,
            max_channels_per_allocation: self.max_channels_per_allocation,
        };
        config.validate()
    }
}

impl From<TurnUdpRelayConfig> for TurnRelayRuntimeConfig {
    fn from(config: TurnUdpRelayConfig) -> Self {
        Self {
            relay_id: config.relay_id,
            allocation_bind_address: config.allocation_bind_address,
            advertised_address: config.advertised_address,
            max_datagram_size: config.max_datagram_size,
            allocation_lifetime_seconds: config.allocation_lifetime_seconds,
            idle_timeout_seconds: config.idle_timeout_seconds,
            max_allocations: config.max_allocations,
            max_allocations_per_node: config.max_allocations_per_node,
            max_permissions_per_allocation: config.max_permissions_per_allocation,
            max_channels_per_allocation: config.max_channels_per_allocation,
        }
    }
}

impl From<TurnTcpRelayConfig> for TurnRelayRuntimeConfig {
    fn from(config: TurnTcpRelayConfig) -> Self {
        Self {
            relay_id: config.relay_id,
            allocation_bind_address: config.allocation_bind_address,
            advertised_address: config.advertised_address,
            max_datagram_size: config.max_datagram_size,
            allocation_lifetime_seconds: config.allocation_lifetime_seconds,
            idle_timeout_seconds: config.idle_timeout_seconds,
            max_allocations: config.max_allocations,
            max_allocations_per_node: config.max_allocations_per_node,
            max_permissions_per_allocation: config.max_permissions_per_allocation,
            max_channels_per_allocation: config.max_channels_per_allocation,
        }
    }
}

/// One bound TURN UDP relay ready to serve requests.
pub struct TurnUdpRelay {
    config: TurnUdpRelayConfig,
    control: Arc<UdpSocket>,
    core: TurnRelayCore,
}

struct TurnRelayCore {
    config: TurnRelayRuntimeConfig,
    authenticator: TurnAuthenticator,
    allocations: HashMap<SocketAddr, Allocation>,
    allocation_counts: HashMap<NodeId, usize>,
    allocation_tasks: JoinSet<()>,
    response_cache: HashMap<ResponseCacheKey, CachedResponse>,
    response_cache_order: VecDeque<ResponseCacheKey>,
}

#[derive(Clone)]
enum ClientSink {
    Udp {
        control: Arc<UdpSocket>,
        client: SocketAddr,
    },
    Stream {
        client: SocketAddr,
        sender: mpsc::Sender<Vec<u8>>,
    },
}

struct ClientConnection {
    address: SocketAddr,
    sink: ClientSink,
}

impl ClientSink {
    const fn is_stream(&self) -> bool {
        matches!(self, Self::Stream { .. })
    }

    async fn send(&self, record: Vec<u8>) -> Result<(), TurnRelayError> {
        match self {
            Self::Udp { control, client } => {
                control.send_to(&record, *client).await.map_err(|source| {
                    TurnRelayError::SendControl {
                        client: *client,
                        source,
                    }
                })?;
                Ok(())
            }
            Self::Stream { client, sender } => sender
                .send(record)
                .await
                .map_err(|_| TurnRelayError::ClientStreamClosed { client: *client }),
        }
    }

    async fn send_data(&self, record: Vec<u8>) {
        match self {
            Self::Udp { control, client } => {
                let _result = control.send_to(&record, *client).await;
            }
            Self::Stream { sender, .. } => {
                let _result = sender.try_send(record);
            }
        }
    }
}

impl TurnUdpRelay {
    /// Validates configuration and binds the client-facing UDP socket.
    ///
    /// # Errors
    ///
    /// Returns [`TurnRelayError`] for invalid limits, credential scope, or an
    /// operating-system bind failure.
    pub async fn bind(
        config: TurnUdpRelayConfig,
        credentials: RelayCredentialAuthority,
    ) -> Result<Self, TurnRelayError> {
        config.validate()?;
        let control = UdpSocket::bind(config.listen_address)
            .await
            .map_err(|source| TurnRelayError::BindControl {
                address: config.listen_address,
                source,
            })?;
        Ok(Self {
            config,
            control: Arc::new(control),
            core: TurnRelayCore::new(config.into(), credentials)?,
        })
    }

    /// Returns the actual listener address, including an assigned port.
    ///
    /// # Errors
    ///
    /// Returns [`TurnRelayError`] if the operating system cannot report the
    /// bound socket address.
    pub fn local_address(&self) -> Result<SocketAddr, TurnRelayError> {
        self.control
            .local_addr()
            .map_err(|source| TurnRelayError::LocalAddress { source })
    }

    /// Serves TURN UDP until `shutdown` resolves.
    ///
    /// Malformed or one-way records are dropped locally; listener I/O failure
    /// terminates the runtime so the service manager can restart it.
    ///
    /// # Errors
    ///
    /// Returns [`TurnRelayError`] for clock or listener I/O failures and for
    /// internal response encoding failures.
    pub async fn run<F>(mut self, shutdown: F) -> Result<(), TurnRelayError>
    where
        F: Future<Output = ()> + Send,
    {
        let mut shutdown = std::pin::pin!(shutdown);
        let mut cleanup = tokio::time::interval(Duration::from_secs(1));
        cleanup.set_missed_tick_behavior(MissedTickBehavior::Delay);
        let mut receive_buffer = vec![0_u8; RECEIVE_BUFFER_LENGTH];
        loop {
            tokio::select! {
                () = &mut shutdown => break,
                _ = cleanup.tick() => self.core.remove_expired(Instant::now()),
                joined = self.core.allocation_tasks.join_next(), if !self.core.allocation_tasks.is_empty() => {
                    if let Some(result) = joined {
                        result.map_err(|source| TurnRelayError::AllocationTaskJoin { source })?;
                    }
                }
                received = self.control.recv_from(&mut receive_buffer) => {
                    let (length, client) = received.map_err(|source| TurnRelayError::ReceiveControl {
                        source,
                    })?;
                    let now_unix = unix_time()?;
                    let now = Instant::now();
                    let sink = ClientSink::Udp {
                        control: Arc::clone(&self.control),
                        client,
                    };
                    if let Some(response) = self.core
                        .handle_client_record(&receive_buffer[..length], client, sink.clone(), now_unix, now)
                        .await?
                    {
                        sink.send(response).await?;
                    }
                }
            }
        }
        self.core.shutdown().await
    }
}

/// One bound TURN TCP relay ready to serve reliable client sessions.
pub struct TurnTcpRelay {
    config: TurnTcpRelayConfig,
    listener: TcpListener,
    core: Arc<Mutex<TurnRelayCore>>,
}

impl TurnTcpRelay {
    /// Validates configuration and binds the client-facing TCP listener.
    ///
    /// # Errors
    ///
    /// Returns [`TurnRelayError`] for invalid limits, credential scope, or an
    /// operating-system bind failure.
    pub async fn bind(
        config: TurnTcpRelayConfig,
        credentials: RelayCredentialAuthority,
    ) -> Result<Self, TurnRelayError> {
        config.validate()?;
        let listener = TcpListener::bind(config.listen_address)
            .await
            .map_err(|source| TurnRelayError::BindTcp {
                address: config.listen_address,
                source,
            })?;
        let core = TurnRelayCore::new(config.into(), credentials)?;
        Ok(Self {
            config,
            listener,
            core: Arc::new(Mutex::new(core)),
        })
    }

    /// Returns the actual TCP listener address, including an assigned port.
    ///
    /// # Errors
    ///
    /// Returns [`TurnRelayError`] if the operating system cannot report the
    /// bound listener address.
    pub fn local_address(&self) -> Result<SocketAddr, TurnRelayError> {
        self.listener
            .local_addr()
            .map_err(|source| TurnRelayError::TcpLocalAddress { source })
    }

    /// Serves framed TURN TCP sessions until `shutdown` resolves.
    ///
    /// Malformed records close only their client session. Listener failure or
    /// an internal task panic terminates the runtime for service-manager restart.
    ///
    /// # Errors
    ///
    /// Returns [`TurnRelayError`] for listener, clock, or task failures.
    pub async fn run<F>(self, shutdown: F) -> Result<(), TurnRelayError>
    where
        F: Future<Output = ()> + Send,
    {
        let mut shutdown = std::pin::pin!(shutdown);
        let mut cleanup = tokio::time::interval(Duration::from_secs(1));
        cleanup.set_missed_tick_behavior(MissedTickBehavior::Delay);
        let mut sessions = JoinSet::new();
        loop {
            tokio::select! {
                () = &mut shutdown => break,
                _ = cleanup.tick() => {
                    self.core.lock().await.remove_expired(Instant::now());
                }
                accepted = self.listener.accept() => {
                    let (stream, client) = accepted.map_err(|source| TurnRelayError::AcceptTcp { source })?;
                    stream.set_nodelay(true).map_err(|source| TurnRelayError::ConfigureTcp {
                        client,
                        source,
                    })?;
                    let core = Arc::clone(&self.core);
                    let idle_timeout = Duration::from_secs(u64::from(self.config.idle_timeout_seconds));
                    sessions.spawn(async move {
                        (client, run_stream_client(stream, client, core, idle_timeout).await)
                    });
                }
                joined = sessions.join_next(), if !sessions.is_empty() => {
                    if let Some(result) = joined {
                        let (client, session) = result.map_err(|source| TurnRelayError::ClientTaskJoin { source })?;
                        if let Err(error) = session {
                            tracing::debug!(%client, %error, "TURN TCP client session closed");
                        }
                    }
                }
            }
        }
        sessions.abort_all();
        while let Some(result) = sessions.join_next().await {
            if let Err(source) = result {
                if !source.is_cancelled() {
                    return Err(TurnRelayError::ClientTaskJoin { source });
                }
            }
        }
        self.core.lock().await.shutdown().await
    }
}

impl fmt::Debug for TurnTcpRelay {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("TurnTcpRelay")
            .field("config", &self.config)
            .finish_non_exhaustive()
    }
}

/// One bound TURN TLS relay ready to serve authenticated TLS 1.3 sessions.
pub struct TurnTlsRelay {
    config: TurnTcpRelayConfig,
    listener: TcpListener,
    core: Arc<Mutex<TurnRelayCore>>,
    acceptor: TlsAcceptor,
    handshake_timeout: Duration,
}

impl TurnTlsRelay {
    /// Validates stream limits, binds the TCP listener, and installs one TLS identity.
    ///
    /// The shared [`TurnTcpRelayConfig`] describes the identical reliable TURN
    /// stream and UDP allocation limits. `tls_config` must disable early data;
    /// callers normally obtain it from [`crate::tls::load_tls_server_config`].
    ///
    /// # Errors
    ///
    /// Returns [`TurnRelayError`] for invalid limits, TLS policy, credential
    /// scope, handshake deadline, or an operating-system bind failure.
    pub async fn bind(
        config: TurnTcpRelayConfig,
        credentials: RelayCredentialAuthority,
        tls_config: Arc<ServerConfig>,
        handshake_timeout: Duration,
    ) -> Result<Self, TurnRelayError> {
        config.validate()?;
        if handshake_timeout.is_zero() || handshake_timeout > MAX_TLS_HANDSHAKE_TIMEOUT {
            return Err(invalid_config(
                "TLS handshake timeout must be between one nanosecond and 60 seconds",
            ));
        }
        if tls_config.max_early_data_size != 0 {
            return Err(invalid_config("TURN TLS early data must be disabled"));
        }
        let listener = TcpListener::bind(config.listen_address)
            .await
            .map_err(|source| TurnRelayError::BindTcp {
                address: config.listen_address,
                source,
            })?;
        let core = TurnRelayCore::new(config.into(), credentials)?;
        Ok(Self {
            config,
            listener,
            core: Arc::new(Mutex::new(core)),
            acceptor: TlsAcceptor::from(tls_config),
            handshake_timeout,
        })
    }

    /// Returns the actual TCP listener address, including an assigned port.
    ///
    /// # Errors
    ///
    /// Returns [`TurnRelayError`] if the operating system cannot report the
    /// bound listener address.
    pub fn local_address(&self) -> Result<SocketAddr, TurnRelayError> {
        self.listener
            .local_addr()
            .map_err(|source| TurnRelayError::TcpLocalAddress { source })
    }

    /// Serves framed TURN TLS sessions until `shutdown` resolves.
    ///
    /// TCP and TLS handshake failures close only their client session. Listener
    /// failure or an internal task panic terminates the runtime for restart.
    ///
    /// # Errors
    ///
    /// Returns [`TurnRelayError`] for listener, clock, or task failures.
    pub async fn run<F>(self, shutdown: F) -> Result<(), TurnRelayError>
    where
        F: Future<Output = ()> + Send,
    {
        let mut shutdown = std::pin::pin!(shutdown);
        let mut cleanup = tokio::time::interval(Duration::from_secs(1));
        cleanup.set_missed_tick_behavior(MissedTickBehavior::Delay);
        let mut sessions = JoinSet::new();
        loop {
            tokio::select! {
                () = &mut shutdown => break,
                _ = cleanup.tick() => {
                    self.core.lock().await.remove_expired(Instant::now());
                }
                accepted = self.listener.accept() => {
                    let (stream, client) = accepted.map_err(|source| TurnRelayError::AcceptTcp { source })?;
                    stream.set_nodelay(true).map_err(|source| TurnRelayError::ConfigureTcp {
                        client,
                        source,
                    })?;
                    let core = Arc::clone(&self.core);
                    let acceptor = self.acceptor.clone();
                    let handshake_timeout = self.handshake_timeout;
                    let idle_timeout = Duration::from_secs(u64::from(self.config.idle_timeout_seconds));
                    sessions.spawn(async move {
                        let session = async {
                            let stream = timeout(handshake_timeout, acceptor.accept(stream))
                                .await
                                .map_err(|_| TurnRelayError::TlsHandshakeTimeout { client })?
                                .map_err(|source| TurnRelayError::TlsHandshake { client, source })?;
                            run_stream_client(stream, client, core, idle_timeout).await
                        }
                        .await;
                        (client, session)
                    });
                }
                joined = sessions.join_next(), if !sessions.is_empty() => {
                    if let Some(result) = joined {
                        let (client, session) = result.map_err(|source| TurnRelayError::ClientTaskJoin { source })?;
                        if let Err(error) = session {
                            tracing::debug!(%client, %error, "TURN TLS client session closed");
                        }
                    }
                }
            }
        }
        sessions.abort_all();
        while let Some(result) = sessions.join_next().await {
            if let Err(source) = result {
                if !source.is_cancelled() {
                    return Err(TurnRelayError::ClientTaskJoin { source });
                }
            }
        }
        self.core.lock().await.shutdown().await
    }
}

impl fmt::Debug for TurnTlsRelay {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("TurnTlsRelay")
            .field("config", &self.config)
            .field("handshake_timeout", &self.handshake_timeout)
            .finish_non_exhaustive()
    }
}

/// One bound secure WebSocket TURN relay with pre-upgrade credential authentication.
pub struct TurnWebSocketRelay {
    config: TurnTcpRelayConfig,
    listener: TcpListener,
    core: Arc<Mutex<TurnRelayCore>>,
    acceptor: TlsAcceptor,
    credentials: Arc<RelayCredentialAuthority>,
    websocket_config: WebSocketConfig,
    handshake_timeout: Duration,
}

impl TurnWebSocketRelay {
    /// Validates limits, binds HTTPS, and installs TLS and WebSocket policy.
    ///
    /// The shared [`TurnTcpRelayConfig`] describes the reliable TURN and UDP
    /// allocation limits. `tls_config` must disable early data; callers normally
    /// obtain it from [`crate::tls::load_tls_server_config`].
    ///
    /// # Errors
    ///
    /// Returns [`TurnRelayError`] for invalid limits, TLS policy, credential
    /// scope, handshake deadline, WebSocket bounds, or listener bind failure.
    pub async fn bind(
        config: TurnTcpRelayConfig,
        credentials: RelayCredentialAuthority,
        tls_config: Arc<ServerConfig>,
        handshake_timeout: Duration,
    ) -> Result<Self, TurnRelayError> {
        config.validate()?;
        if handshake_timeout.is_zero() || handshake_timeout > MAX_TLS_HANDSHAKE_TIMEOUT {
            return Err(invalid_config(
                "WebSocket handshake timeout must be between one nanosecond and 60 seconds",
            ));
        }
        if tls_config.max_early_data_size != 0 {
            return Err(invalid_config(
                "TURN WebSocket TLS early data must be disabled",
            ));
        }
        let websocket_config = turn_websocket_config(MAX_TURN_STREAM_RECORD_SIZE)?;
        let listener = TcpListener::bind(config.listen_address)
            .await
            .map_err(|source| TurnRelayError::BindTcp {
                address: config.listen_address,
                source,
            })?;
        let credentials = Arc::new(credentials);
        let core = TurnRelayCore::new_shared(config.into(), Arc::clone(&credentials))?;
        Ok(Self {
            config,
            listener,
            core: Arc::new(Mutex::new(core)),
            acceptor: TlsAcceptor::from(tls_config),
            credentials,
            websocket_config,
            handshake_timeout,
        })
    }

    /// Returns the actual HTTPS listener address, including an assigned port.
    ///
    /// # Errors
    ///
    /// Returns [`TurnRelayError`] if the operating system cannot report the
    /// bound listener address.
    pub fn local_address(&self) -> Result<SocketAddr, TurnRelayError> {
        self.listener
            .local_addr()
            .map_err(|source| TurnRelayError::TcpLocalAddress { source })
    }

    /// Serves authenticated secure WebSocket TURN sessions until shutdown.
    ///
    /// TCP, TLS, HTTP upgrade, authentication, or record failures close only
    /// their client session. Listener failure or an internal task panic
    /// terminates the runtime for service-manager restart.
    ///
    /// # Errors
    ///
    /// Returns [`TurnRelayError`] for listener, clock, or task failures.
    pub async fn run<F>(self, shutdown: F) -> Result<(), TurnRelayError>
    where
        F: Future<Output = ()> + Send,
    {
        let mut shutdown = std::pin::pin!(shutdown);
        let mut cleanup = tokio::time::interval(Duration::from_secs(1));
        cleanup.set_missed_tick_behavior(MissedTickBehavior::Delay);
        let mut sessions = JoinSet::new();
        loop {
            tokio::select! {
                () = &mut shutdown => break,
                _ = cleanup.tick() => {
                    self.core.lock().await.remove_expired(Instant::now());
                }
                accepted = self.listener.accept() => {
                    let (stream, client) = accepted.map_err(|source| TurnRelayError::AcceptTcp { source })?;
                    stream.set_nodelay(true).map_err(|source| TurnRelayError::ConfigureTcp {
                        client,
                        source,
                    })?;
                    let core = Arc::clone(&self.core);
                    let acceptor = self.acceptor.clone();
                    let credentials = Arc::clone(&self.credentials);
                    let relay_id = self.config.relay_id;
                    let websocket_config = self.websocket_config;
                    let handshake_timeout = self.handshake_timeout;
                    let idle_timeout = Duration::from_secs(u64::from(self.config.idle_timeout_seconds));
                    sessions.spawn(async move {
                        let handshake = timeout(handshake_timeout, async {
                            let stream = acceptor
                                .accept(stream)
                                .await
                                .map_err(|source| TurnRelayError::TlsHandshake { client, source })?;
                            accept_websocket_client(
                                stream,
                                client,
                                relay_id,
                                credentials,
                                websocket_config,
                            )
                            .await
                        })
                        .await
                        .map_err(|_| TurnRelayError::WebSocketHandshakeTimeout { client });
                        let session = match handshake {
                            Ok(Ok(stream)) => {
                                run_websocket_client(stream, client, core, idle_timeout).await
                            }
                            Ok(Err(error)) | Err(error) => Err(error),
                        };
                        (client, session)
                    });
                }
                joined = sessions.join_next(), if !sessions.is_empty() => {
                    if let Some(result) = joined {
                        let (client, session) = result.map_err(|source| TurnRelayError::ClientTaskJoin { source })?;
                        if let Err(error) = session {
                            tracing::debug!(%client, %error, "TURN WebSocket client session closed");
                        }
                    }
                }
            }
        }
        sessions.abort_all();
        while let Some(result) = sessions.join_next().await {
            if let Err(source) = result {
                if !source.is_cancelled() {
                    return Err(TurnRelayError::ClientTaskJoin { source });
                }
            }
        }
        self.core.lock().await.shutdown().await
    }
}

impl fmt::Debug for TurnWebSocketRelay {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("TurnWebSocketRelay")
            .field("config", &self.config)
            .field("handshake_timeout", &self.handshake_timeout)
            .finish_non_exhaustive()
    }
}

#[allow(clippy::result_large_err)] // Tungstenite's callback API fixes ErrorResponse by value.
async fn accept_websocket_client<S>(
    stream: S,
    client: SocketAddr,
    relay_id: RelayId,
    credentials: Arc<RelayCredentialAuthority>,
    websocket_config: WebSocketConfig,
) -> Result<WebSocketStream<S>, TurnRelayError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    accept_hdr_async_with_config(
        stream,
        move |request: &WebSocketRequest, response: WebSocketResponse| {
            authorize_websocket_upgrade(request, response, relay_id, &credentials)
        },
        Some(websocket_config),
    )
    .await
    .map_err(|source| TurnRelayError::WebSocketHandshake { client, source })
}

#[allow(clippy::result_large_err)] // Required by Tungstenite's Callback result type.
fn authorize_websocket_upgrade(
    request: &WebSocketRequest,
    mut response: WebSocketResponse,
    relay_id: RelayId,
    credentials: &RelayCredentialAuthority,
) -> Result<WebSocketResponse, ErrorResponse> {
    if request.uri().path() != STELLA_TURN_WEBSOCKET_PATH || request.uri().query().is_some() {
        return Err(websocket_rejection(StatusCode::BAD_REQUEST));
    }
    if request.headers().contains_key(SEC_WEBSOCKET_EXTENSIONS) {
        return Err(websocket_rejection(StatusCode::BAD_REQUEST));
    }
    let mut protocols = request.headers().get_all(SEC_WEBSOCKET_PROTOCOL).iter();
    let protocol = protocols.next().map(HeaderValue::as_bytes);
    if protocol != Some(STELLA_TURN_WEBSOCKET_SUBPROTOCOL.as_bytes()) || protocols.next().is_some()
    {
        return Err(websocket_rejection(StatusCode::BAD_REQUEST));
    }
    let mut authorizations = request.headers().get_all(AUTHORIZATION).iter();
    let authorization = authorizations.next().and_then(|value| value.to_str().ok());
    if authorizations.next().is_some() {
        return Err(websocket_rejection(StatusCode::UNAUTHORIZED));
    }
    let Some(authorization) = authorization.and_then(decode_websocket_authorization) else {
        return Err(websocket_rejection(StatusCode::UNAUTHORIZED));
    };
    let now = match SystemTime::now().duration_since(UNIX_EPOCH) {
        Ok(duration) => duration.as_secs(),
        Err(_) => return Err(websocket_rejection(StatusCode::INTERNAL_SERVER_ERROR)),
    };
    if credentials
        .verify(
            relay_id,
            authorization.username.as_slice(),
            authorization.secret.as_slice(),
            now,
        )
        .is_none()
    {
        return Err(websocket_rejection(StatusCode::UNAUTHORIZED));
    }
    response.headers_mut().insert(
        SEC_WEBSOCKET_PROTOCOL,
        HeaderValue::from_static(STELLA_TURN_WEBSOCKET_SUBPROTOCOL),
    );
    Ok(response)
}

struct DecodedWebSocketAuthorization {
    username: Zeroizing<Vec<u8>>,
    secret: Zeroizing<Vec<u8>>,
}

fn decode_websocket_authorization(authorization: &str) -> Option<DecodedWebSocketAuthorization> {
    let (scheme, encoded) = authorization.split_once(' ')?;
    if !scheme.eq_ignore_ascii_case("stella") || encoded.contains(' ') {
        return None;
    }
    let (username, secret) = encoded.split_once('.')?;
    if secret.contains('.') {
        return None;
    }
    Some(DecodedWebSocketAuthorization {
        username: decode_websocket_credential_segment(username)?,
        secret: decode_websocket_credential_segment(secret)?,
    })
}

fn decode_websocket_credential_segment(encoded: &str) -> Option<Zeroizing<Vec<u8>>> {
    if encoded.is_empty() {
        return None;
    }
    let decoded = Zeroizing::new(URL_SAFE_NO_PAD.decode(encoded).ok()?);
    let canonical = Zeroizing::new(URL_SAFE_NO_PAD.encode(decoded.as_slice()));
    (canonical.as_str() == encoded).then_some(decoded)
}

fn websocket_rejection(status: StatusCode) -> ErrorResponse {
    let mut response = ErrorResponse::new(None);
    *response.status_mut() = status;
    response
}

async fn run_stream_client<S>(
    stream: S,
    client: SocketAddr,
    core: Arc<Mutex<TurnRelayCore>>,
    idle_timeout: Duration,
) -> Result<(), TurnRelayError>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let (reader, writer) = tokio::io::split(stream);
    let mut reader = TurnStream::new(reader, MAX_TURN_STREAM_RECORD_SIZE)?;
    let mut writer = TurnStream::new(writer, MAX_TURN_STREAM_RECORD_SIZE)?;
    let (sender, mut outbound) = mpsc::channel(256);
    let sink = ClientSink::Stream { client, sender };
    let mut writer_task = tokio::spawn(async move {
        while let Some(record) = outbound.recv().await {
            writer.write_record(&record).await?;
        }
        Ok::<_, TurnRelayError>(())
    });
    let mut writer_joined = false;
    let result = loop {
        tokio::select! {
            joined = &mut writer_task => {
                writer_joined = true;
                break joined.map_err(|source| TurnRelayError::ClientWriterTaskJoin { source })?;
            }
            record = timeout(idle_timeout, reader.read_record()) => {
                let record = match record {
                    Ok(Ok(record)) => record,
                    Ok(Err(error)) => break Err(error.into()),
                    Err(_) => break Err(TurnRelayError::ClientReadTimeout),
                };
                let now_unix = unix_time()?;
                let now = Instant::now();
                let response = core
                    .lock()
                    .await
                    .handle_client_record(&record, client, sink.clone(), now_unix, now)
                    .await?;
                if let Some(response) = response {
                    sink.send(response).await?;
                }
            }
        }
    };
    core.lock().await.remove_client(client);
    drop(sink);
    if !writer_joined {
        writer_task.abort();
        let _result = writer_task.await;
    }
    result
}

async fn run_websocket_client<S>(
    stream: WebSocketStream<S>,
    client: SocketAddr,
    core: Arc<Mutex<TurnRelayCore>>,
    idle_timeout: Duration,
) -> Result<(), TurnRelayError>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let (mut writer, mut reader) = stream.split();
    let (sender, mut outbound) = mpsc::channel(256);
    let sink = ClientSink::Stream { client, sender };
    let mut writer_task = tokio::spawn(async move {
        while let Some(record) = outbound.recv().await {
            write_websocket_record(&mut writer, &record, MAX_TURN_STREAM_RECORD_SIZE).await?;
        }
        Ok::<_, TurnRelayError>(())
    });
    let mut writer_joined = false;
    let result = loop {
        tokio::select! {
            joined = &mut writer_task => {
                writer_joined = true;
                break joined.map_err(|source| TurnRelayError::ClientWriterTaskJoin { source })?;
            }
            record = timeout(
                idle_timeout,
                read_websocket_record(&mut reader, MAX_TURN_STREAM_RECORD_SIZE),
            ) => {
                let record = match record {
                    Ok(Ok(record)) => record,
                    Ok(Err(error)) => break Err(error.into()),
                    Err(_) => break Err(TurnRelayError::ClientReadTimeout),
                };
                let now_unix = unix_time()?;
                let now = Instant::now();
                let response = core
                    .lock()
                    .await
                    .handle_client_record(&record, client, sink.clone(), now_unix, now)
                    .await?;
                if let Some(response) = response {
                    sink.send(response).await?;
                }
            }
        }
    };
    core.lock().await.remove_client(client);
    drop(sink);
    if !writer_joined {
        writer_task.abort();
        let _result = writer_task.await;
    }
    result
}

impl TurnRelayCore {
    fn new(
        config: TurnRelayRuntimeConfig,
        credentials: RelayCredentialAuthority,
    ) -> Result<Self, TurnRelayError> {
        Self::new_shared(config, Arc::new(credentials))
    }

    fn new_shared(
        config: TurnRelayRuntimeConfig,
        credentials: Arc<RelayCredentialAuthority>,
    ) -> Result<Self, TurnRelayError> {
        let authenticator = TurnAuthenticator::new_shared(credentials, config.relay_id)?;
        Ok(Self {
            config,
            authenticator,
            allocations: HashMap::new(),
            allocation_counts: HashMap::new(),
            allocation_tasks: JoinSet::new(),
            response_cache: HashMap::new(),
            response_cache_order: VecDeque::new(),
        })
    }

    async fn shutdown(&mut self) -> Result<(), TurnRelayError> {
        self.allocations.clear();
        self.allocation_counts.clear();
        while let Some(result) = self.allocation_tasks.join_next().await {
            result.map_err(|source| TurnRelayError::AllocationTaskJoin { source })?;
        }
        Ok(())
    }

    fn remove_client(&mut self, client: SocketAddr) {
        self.remove_allocation(client);
        self.response_cache
            .retain(|key, _response| key.client != client);
        self.response_cache_order.retain(|key| key.client != client);
    }

    async fn handle_client_record(
        &mut self,
        input: &[u8],
        client: SocketAddr,
        sink: ClientSink,
        now_unix: u64,
        now: Instant,
    ) -> Result<Option<Vec<u8>>, TurnRelayError> {
        if input.len() < 2 {
            return Ok(None);
        }
        if input[0] & 0xc0 == 0x40 {
            let channel_data = if sink.is_stream() {
                TurnChannelDataView::decode_stream(input)
            } else {
                TurnChannelDataView::decode_datagram(input)
            };
            let Ok(channel_data) = channel_data else {
                return Ok(None);
            };
            self.handle_channel_data(client, channel_data, now).await;
            return Ok(None);
        }
        if input[0] & 0xc0 != 0 {
            return Ok(None);
        }
        let Ok(message) = StunMessageView::decode(input) else {
            return Ok(None);
        };
        if message.message_type().class == StunClass::Indication
            && message.message_type().method == StunMethod::Send
        {
            self.handle_send_indication(&message, client, now).await;
            return Ok(None);
        }
        if message.message_type().class != StunClass::Request {
            return Ok(None);
        }
        let cache_key = ResponseCacheKey {
            client,
            transaction_id: message.transaction_id(),
        };
        if let Some(cached) = self.response_cache.get(&cache_key) {
            if cached.expires_at > now {
                return Ok(Some(cached.bytes.clone()));
            }
        }

        let response = match message.message_type().method {
            StunMethod::Binding => Self::handle_binding(&message, client)?,
            StunMethod::Allocate => {
                self.handle_allocate(&message, client, sink, now_unix, now)
                    .await?
            }
            StunMethod::Refresh => self.handle_refresh(&message, client, now_unix, now)?,
            StunMethod::CreatePermission => {
                self.handle_create_permission(&message, client, now_unix, now)
                    .await?
            }
            StunMethod::ChannelBind => {
                self.handle_channel_bind(&message, client, now_unix, now)
                    .await?
            }
            _ => Self::error_response(&message, 400, "Bad Request", None, None)?,
        };
        self.cache_response(cache_key, response.clone(), now)?;
        Ok(Some(response))
    }

    fn handle_binding(
        message: &StunMessageView<'_>,
        client: SocketAddr,
    ) -> Result<Vec<u8>, TurnRelayError> {
        let unknown = unknown_required_attributes(message)?;
        if !unknown.is_empty() {
            return Self::error_response(message, 420, "Unknown Attribute", None, Some(&unknown));
        }
        let mapped = xor_address_value(client, message.transaction_id())?;
        encode_response(
            message.message_type().method,
            StunClass::SuccessResponse,
            message.transaction_id(),
            vec![
                OwnedAttribute::new(StunAttributeType::XOR_MAPPED_ADDRESS, mapped),
                OwnedAttribute::new(StunAttributeType::SOFTWARE, SOFTWARE.to_vec()),
            ],
            None,
        )
    }

    async fn handle_allocate(
        &mut self,
        message: &StunMessageView<'_>,
        client: SocketAddr,
        sink: ClientSink,
        now_unix: u64,
        now: Instant,
    ) -> Result<Vec<u8>, TurnRelayError> {
        let authenticated = match self.authenticate(message, now_unix)? {
            AuthenticationDecision::Authenticated(value) => value,
            AuthenticationDecision::Response(response) => return Ok(response),
        };
        let unknown = unknown_required_attributes(message)?;
        if !unknown.is_empty() {
            return Self::error_response(
                message,
                420,
                "Unknown Attribute",
                Some(&authenticated),
                Some(&unknown),
            );
        }
        let requested_transport = match Self::validated_method_value(
            unique_attribute(message, StunAttributeType::REQUESTED_TRANSPORT),
            message,
            &authenticated,
        )? {
            Ok(value) => value,
            Err(response) => return Ok(response),
        };
        let Some(requested_transport) = requested_transport else {
            return Self::error_response(message, 400, "Bad Request", Some(&authenticated), None);
        };
        if requested_transport != REQUESTED_TRANSPORT_UDP {
            return Self::error_response(
                message,
                442,
                "Unsupported Transport Protocol",
                Some(&authenticated),
                None,
            );
        }
        let lifetime = match Self::validated_method_value(
            requested_lifetime(message, self.config.allocation_lifetime_seconds, false),
            message,
            &authenticated,
        )? {
            Ok(value) => value,
            Err(response) => return Ok(response),
        };
        if self.allocations.contains_key(&client) {
            return Self::error_response(
                message,
                437,
                "Allocation Mismatch",
                Some(&authenticated),
                None,
            );
        }
        let node_id = authenticated.node_id();
        if self.allocations.len() >= self.config.max_allocations
            || self.allocation_counts.get(&node_id).copied().unwrap_or(0)
                >= self.config.max_allocations_per_node
        {
            return Self::error_response(
                message,
                486,
                "Allocation Quota Reached",
                Some(&authenticated),
                None,
            );
        }
        let (allocation, response) = self
            .create_allocation(
                message,
                ClientConnection {
                    address: client,
                    sink,
                },
                node_id,
                lifetime,
                now,
                &authenticated,
            )
            .await?;
        self.insert_allocation(client, allocation);
        Ok(response)
    }

    async fn create_allocation(
        &mut self,
        message: &StunMessageView<'_>,
        client: ClientConnection,
        node_id: NodeId,
        lifetime: u32,
        now: Instant,
        authenticated: &AuthenticatedTurnRequest,
    ) -> Result<(Allocation, Vec<u8>), TurnRelayError> {
        let socket = UdpSocket::bind(SocketAddr::new(self.config.allocation_bind_address, 0))
            .await
            .map_err(|source| TurnRelayError::BindAllocation {
                address: self.config.allocation_bind_address,
                source,
            })?;
        let local = socket
            .local_addr()
            .map_err(|source| TurnRelayError::AllocationLocalAddress { source })?;
        let relayed_address = SocketAddr::new(self.config.advertised_address, local.port());
        let (command_sender, command_receiver) = mpsc::channel(ALLOCATION_COMMAND_CAPACITY);
        self.allocation_tasks.spawn(run_allocation_actor(
            socket,
            client.sink,
            self.config.max_datagram_size,
            self.config.max_permissions_per_allocation,
            self.config.max_channels_per_allocation,
            command_receiver,
        ));
        let allocation = Allocation {
            node_id,
            command_sender,
            relayed_address,
            expires_at: checked_deadline(now, lifetime, "allocation lifetime")?,
            idle_deadline: checked_deadline(
                now,
                self.config.idle_timeout_seconds,
                "allocation idle timeout",
            )?,
        };
        let response = encode_response(
            message.message_type().method,
            StunClass::SuccessResponse,
            message.transaction_id(),
            vec![
                OwnedAttribute::new(
                    StunAttributeType::XOR_RELAYED_ADDRESS,
                    xor_address_value(relayed_address, message.transaction_id())?,
                ),
                OwnedAttribute::new(
                    StunAttributeType::XOR_MAPPED_ADDRESS,
                    xor_address_value(client.address, message.transaction_id())?,
                ),
                OwnedAttribute::new(StunAttributeType::LIFETIME, lifetime.to_be_bytes().to_vec()),
                OwnedAttribute::new(StunAttributeType::SOFTWARE, SOFTWARE.to_vec()),
            ],
            Some(authenticated),
        )?;
        Ok((allocation, response))
    }

    fn handle_refresh(
        &mut self,
        message: &StunMessageView<'_>,
        client: SocketAddr,
        now_unix: u64,
        now: Instant,
    ) -> Result<Vec<u8>, TurnRelayError> {
        let authenticated = match self.authenticate(message, now_unix)? {
            AuthenticationDecision::Authenticated(value) => value,
            AuthenticationDecision::Response(response) => return Ok(response),
        };
        let unknown = unknown_required_attributes(message)?;
        if !unknown.is_empty() {
            return Self::error_response(
                message,
                420,
                "Unknown Attribute",
                Some(&authenticated),
                Some(&unknown),
            );
        }
        let lifetime = match Self::validated_method_value(
            requested_lifetime(message, self.config.allocation_lifetime_seconds, true),
            message,
            &authenticated,
        )? {
            Ok(value) => value,
            Err(response) => return Ok(response),
        };
        let Some(allocation) = self.allocations.get_mut(&client) else {
            return Self::error_response(
                message,
                437,
                "Allocation Mismatch",
                Some(&authenticated),
                None,
            );
        };
        if allocation.node_id != authenticated.node_id() {
            return Self::error_response(
                message,
                441,
                "Wrong Credentials",
                Some(&authenticated),
                None,
            );
        }
        if lifetime == 0 {
            self.remove_allocation(client);
        } else {
            allocation.expires_at = checked_deadline(now, lifetime, "allocation lifetime")?;
            allocation.idle_deadline = checked_deadline(
                now,
                self.config.idle_timeout_seconds,
                "allocation idle timeout",
            )?;
        }
        encode_response(
            message.message_type().method,
            StunClass::SuccessResponse,
            message.transaction_id(),
            vec![
                OwnedAttribute::new(StunAttributeType::LIFETIME, lifetime.to_be_bytes().to_vec()),
                OwnedAttribute::new(StunAttributeType::SOFTWARE, SOFTWARE.to_vec()),
            ],
            Some(&authenticated),
        )
    }

    #[allow(clippy::too_many_lines)]
    async fn handle_create_permission(
        &mut self,
        message: &StunMessageView<'_>,
        client: SocketAddr,
        now_unix: u64,
        now: Instant,
    ) -> Result<Vec<u8>, TurnRelayError> {
        let authenticated = match self.authenticate(message, now_unix)? {
            AuthenticationDecision::Authenticated(value) => value,
            AuthenticationDecision::Response(response) => return Ok(response),
        };
        let unknown = unknown_required_attributes(message)?;
        if !unknown.is_empty() {
            return Self::error_response(
                message,
                420,
                "Unknown Attribute",
                Some(&authenticated),
                Some(&unknown),
            );
        }
        let peers =
            match Self::validated_method_value(peer_addresses(message), message, &authenticated)? {
                Ok(peers) => peers,
                Err(response) => return Ok(response),
            };
        if peers.is_empty() || peers.len() > self.config.max_permissions_per_allocation {
            return Self::error_response(
                message,
                508,
                "Insufficient Capacity",
                Some(&authenticated),
                None,
            );
        }
        let Some(allocation) = self.allocations.get_mut(&client) else {
            return Self::error_response(
                message,
                437,
                "Allocation Mismatch",
                Some(&authenticated),
                None,
            );
        };
        if allocation.node_id != authenticated.node_id() {
            return Self::error_response(
                message,
                441,
                "Wrong Credentials",
                Some(&authenticated),
                None,
            );
        }
        allocation.idle_deadline = checked_deadline(
            now,
            self.config.idle_timeout_seconds,
            "allocation idle timeout",
        )?;
        let sender = allocation.command_sender.clone();
        let (response_sender, response_receiver) = oneshot::channel();
        if sender
            .send(AllocationCommand::CreatePermissions {
                peers,
                now,
                response: response_sender,
            })
            .await
            .is_err()
        {
            self.remove_allocation(client);
            return Self::error_response(
                message,
                437,
                "Allocation Mismatch",
                Some(&authenticated),
                None,
            );
        }
        match response_receiver.await {
            Ok(Ok(())) => encode_response(
                message.message_type().method,
                StunClass::SuccessResponse,
                message.transaction_id(),
                vec![OwnedAttribute::new(
                    StunAttributeType::SOFTWARE,
                    SOFTWARE.to_vec(),
                )],
                Some(&authenticated),
            ),
            Ok(Err(AllocationMutationError::Capacity)) => Self::error_response(
                message,
                508,
                "Insufficient Capacity",
                Some(&authenticated),
                None,
            ),
            Ok(Err(AllocationMutationError::Conflict)) => {
                Self::error_response(message, 400, "Bad Request", Some(&authenticated), None)
            }
            Ok(Err(AllocationMutationError::DeadlineOverflow)) => {
                Err(TurnRelayError::DeadlineOverflow {
                    field: "permission lifetime",
                })
            }
            Err(_closed) => {
                self.remove_allocation(client);
                Self::error_response(
                    message,
                    437,
                    "Allocation Mismatch",
                    Some(&authenticated),
                    None,
                )
            }
        }
    }

    #[allow(clippy::too_many_lines)]
    async fn handle_channel_bind(
        &mut self,
        message: &StunMessageView<'_>,
        client: SocketAddr,
        now_unix: u64,
        now: Instant,
    ) -> Result<Vec<u8>, TurnRelayError> {
        let authenticated = match self.authenticate(message, now_unix)? {
            AuthenticationDecision::Authenticated(value) => value,
            AuthenticationDecision::Response(response) => return Ok(response),
        };
        let unknown = unknown_required_attributes(message)?;
        if !unknown.is_empty() {
            return Self::error_response(
                message,
                420,
                "Unknown Attribute",
                Some(&authenticated),
                Some(&unknown),
            );
        }
        let channel =
            match Self::validated_method_value(channel_number(message), message, &authenticated)? {
                Ok(channel) => channel,
                Err(response) => return Ok(response),
            };
        let peers =
            match Self::validated_method_value(peer_addresses(message), message, &authenticated)? {
                Ok(peers) => peers,
                Err(response) => return Ok(response),
            };
        let Some(peer) = peers
            .as_slice()
            .first()
            .copied()
            .filter(|_| peers.len() == 1)
        else {
            return Self::error_response(message, 400, "Bad Request", Some(&authenticated), None);
        };
        let Some(allocation) = self.allocations.get_mut(&client) else {
            return Self::error_response(
                message,
                437,
                "Allocation Mismatch",
                Some(&authenticated),
                None,
            );
        };
        if allocation.node_id != authenticated.node_id() {
            return Self::error_response(
                message,
                441,
                "Wrong Credentials",
                Some(&authenticated),
                None,
            );
        }
        allocation.idle_deadline = checked_deadline(
            now,
            self.config.idle_timeout_seconds,
            "allocation idle timeout",
        )?;
        let sender = allocation.command_sender.clone();
        let (response_sender, response_receiver) = oneshot::channel();
        if sender
            .send(AllocationCommand::BindChannel {
                channel,
                peer,
                now,
                response: response_sender,
            })
            .await
            .is_err()
        {
            self.remove_allocation(client);
            return Self::error_response(
                message,
                437,
                "Allocation Mismatch",
                Some(&authenticated),
                None,
            );
        }
        match response_receiver.await {
            Ok(Ok(())) => encode_response(
                message.message_type().method,
                StunClass::SuccessResponse,
                message.transaction_id(),
                vec![OwnedAttribute::new(
                    StunAttributeType::SOFTWARE,
                    SOFTWARE.to_vec(),
                )],
                Some(&authenticated),
            ),
            Ok(Err(AllocationMutationError::Capacity)) => Self::error_response(
                message,
                508,
                "Insufficient Capacity",
                Some(&authenticated),
                None,
            ),
            Ok(Err(AllocationMutationError::Conflict)) => {
                Self::error_response(message, 400, "Bad Request", Some(&authenticated), None)
            }
            Ok(Err(AllocationMutationError::DeadlineOverflow)) => {
                Err(TurnRelayError::DeadlineOverflow {
                    field: "channel binding lifetime",
                })
            }
            Err(_closed) => {
                self.remove_allocation(client);
                Self::error_response(
                    message,
                    437,
                    "Allocation Mismatch",
                    Some(&authenticated),
                    None,
                )
            }
        }
    }

    async fn handle_send_indication(
        &mut self,
        message: &StunMessageView<'_>,
        client: SocketAddr,
        now: Instant,
    ) {
        let Ok(unknown) = unknown_required_attributes(message) else {
            return;
        };
        if !unknown.is_empty() {
            return;
        }
        let Ok(peers) = peer_addresses(message) else {
            return;
        };
        let Some(peer) = peers
            .as_slice()
            .first()
            .copied()
            .filter(|_| peers.len() == 1)
        else {
            return;
        };
        let Ok(Some(data)) = unique_attribute(message, StunAttributeType::DATA) else {
            return;
        };
        if data.len() > self.config.max_datagram_size {
            return;
        }
        let Some(allocation) = self.allocations.get_mut(&client) else {
            return;
        };
        let Ok(idle_deadline) = checked_deadline(
            now,
            self.config.idle_timeout_seconds,
            "allocation idle timeout",
        ) else {
            return;
        };
        allocation.idle_deadline = idle_deadline;
        let _result = allocation
            .command_sender
            .send(AllocationCommand::SendToPeer {
                peer,
                data: data.to_vec(),
                now,
            })
            .await;
    }

    async fn handle_channel_data(
        &mut self,
        client: SocketAddr,
        channel_data: TurnChannelDataView<'_>,
        now: Instant,
    ) {
        if channel_data.data().len() > self.config.max_datagram_size {
            return;
        }
        let Some(allocation) = self.allocations.get_mut(&client) else {
            return;
        };
        let Ok(idle_deadline) = checked_deadline(
            now,
            self.config.idle_timeout_seconds,
            "allocation idle timeout",
        ) else {
            return;
        };
        allocation.idle_deadline = idle_deadline;
        let _result = allocation
            .command_sender
            .send(AllocationCommand::SendChannelData {
                channel: channel_data.channel(),
                data: channel_data.data().to_vec(),
                now,
            })
            .await;
    }

    fn authenticate(
        &self,
        message: &StunMessageView<'_>,
        now_unix: u64,
    ) -> Result<AuthenticationDecision, TurnRelayError> {
        match self
            .authenticator
            .authenticate_including_stale(message, now_unix)
        {
            Ok((authenticated, TurnNonceStatus::Valid)) => {
                Ok(AuthenticationDecision::Authenticated(authenticated))
            }
            Ok((authenticated, TurnNonceStatus::Expired)) => {
                let challenge = self.authenticator.issue_challenge(now_unix)?;
                Ok(AuthenticationDecision::Response(Self::challenge_response(
                    message,
                    438,
                    "Stale Nonce",
                    &challenge,
                    Some(&authenticated),
                )?))
            }
            Ok((_authenticated, TurnNonceStatus::Invalid)) => {
                Err(TurnRelayError::InvalidAuthenticationState)
            }
            Err(TurnAuthenticationError::Malformed { .. }) => Ok(AuthenticationDecision::Response(
                Self::error_response(message, 400, "Bad Request", None, None)?,
            )),
            Err(TurnAuthenticationError::Unauthorized | TurnAuthenticationError::StaleNonce) => {
                let challenge = self.authenticator.issue_challenge(now_unix)?;
                Ok(AuthenticationDecision::Response(Self::challenge_response(
                    message,
                    401,
                    "Unauthorized",
                    &challenge,
                    None,
                )?))
            }
        }
    }

    fn validated_method_value<T>(
        result: Result<T, TurnRelayError>,
        message: &StunMessageView<'_>,
        authenticated: &AuthenticatedTurnRequest,
    ) -> Result<Result<T, Vec<u8>>, TurnRelayError> {
        match result {
            Ok(value) => Ok(Ok(value)),
            Err(TurnRelayError::MalformedRequest { .. }) => Ok(Err(Self::error_response(
                message,
                400,
                "Bad Request",
                Some(authenticated),
                None,
            )?)),
            Err(error) => Err(error),
        }
    }

    fn challenge_response(
        message: &StunMessageView<'_>,
        code: u16,
        reason: &str,
        challenge: &crate::turn_auth::TurnChallenge,
        authenticated: Option<&AuthenticatedTurnRequest>,
    ) -> Result<Vec<u8>, TurnRelayError> {
        let mut algorithm = [0_u8; 4];
        challenge.password_algorithm().encode(&mut algorithm)?;
        let mut error = vec![0_u8; 4 + reason.len()];
        let length = encode_stun_error_code(code, reason, &mut error)?;
        error.truncate(length);
        encode_response(
            message.message_type().method,
            StunClass::ErrorResponse,
            message.transaction_id(),
            vec![
                OwnedAttribute::new(StunAttributeType::ERROR_CODE, error),
                OwnedAttribute::new(StunAttributeType::REALM, challenge.realm().to_vec()),
                OwnedAttribute::new(StunAttributeType::NONCE, challenge.nonce().to_vec()),
                OwnedAttribute::new(StunAttributeType::PASSWORD_ALGORITHM, algorithm.to_vec()),
                OwnedAttribute::new(StunAttributeType::SOFTWARE, SOFTWARE.to_vec()),
            ],
            authenticated,
        )
    }

    fn error_response(
        message: &StunMessageView<'_>,
        code: u16,
        reason: &str,
        authenticated: Option<&AuthenticatedTurnRequest>,
        unknown_attributes: Option<&[u16]>,
    ) -> Result<Vec<u8>, TurnRelayError> {
        let mut error = vec![0_u8; 4 + reason.len()];
        let length = encode_stun_error_code(code, reason, &mut error)?;
        error.truncate(length);
        let mut attributes = vec![OwnedAttribute::new(StunAttributeType::ERROR_CODE, error)];
        if let Some(unknown) = unknown_attributes {
            let mut value = Vec::with_capacity(unknown.len().saturating_mul(2));
            for attribute_type in unknown {
                value.extend_from_slice(&attribute_type.to_be_bytes());
            }
            attributes.push(OwnedAttribute::new(
                StunAttributeType::UNKNOWN_ATTRIBUTES,
                value,
            ));
        }
        attributes.push(OwnedAttribute::new(
            StunAttributeType::SOFTWARE,
            SOFTWARE.to_vec(),
        ));
        encode_response(
            message.message_type().method,
            StunClass::ErrorResponse,
            message.transaction_id(),
            attributes,
            authenticated,
        )
    }

    fn cache_response(
        &mut self,
        key: ResponseCacheKey,
        bytes: Vec<u8>,
        now: Instant,
    ) -> Result<(), TurnRelayError> {
        let expires_at =
            now.checked_add(RESPONSE_CACHE_LIFETIME)
                .ok_or(TurnRelayError::DeadlineOverflow {
                    field: "response cache lifetime",
                })?;
        self.response_cache
            .insert(key, CachedResponse { bytes, expires_at });
        self.response_cache_order.push_back(key);
        while self.response_cache.len() > RESPONSE_CACHE_CAPACITY {
            let Some(oldest) = self.response_cache_order.pop_front() else {
                break;
            };
            self.response_cache.remove(&oldest);
        }
        Ok(())
    }

    fn remove_expired(&mut self, now: Instant) {
        let expired = self
            .allocations
            .iter()
            .filter_map(|(client, allocation)| {
                (allocation.expires_at <= now || allocation.idle_deadline <= now).then_some(*client)
            })
            .collect::<Vec<_>>();
        for client in expired {
            self.remove_allocation(client);
        }
        self.response_cache
            .retain(|_key, response| response.expires_at > now);
        while self
            .response_cache_order
            .front()
            .is_some_and(|key| !self.response_cache.contains_key(key))
        {
            self.response_cache_order.pop_front();
        }
    }

    fn insert_allocation(&mut self, client: SocketAddr, allocation: Allocation) {
        let node_id = allocation.node_id;
        let previous = self.allocations.insert(client, allocation);
        assert!(previous.is_none(), "allocation already exists for client");
        let count = self.allocation_counts.entry(node_id).or_default();
        *count = count.checked_add(1).expect("allocation count overflow");
    }

    fn remove_allocation(&mut self, client: SocketAddr) {
        let Some(allocation) = self.allocations.remove(&client) else {
            return;
        };
        let count = self
            .allocation_counts
            .get_mut(&allocation.node_id)
            .expect("allocation count is missing");
        *count = count.checked_sub(1).expect("allocation count is zero");
        if *count == 0 {
            self.allocation_counts.remove(&allocation.node_id);
        }
    }
}

impl fmt::Debug for TurnUdpRelay {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("TurnUdpRelay")
            .field("config", &self.config)
            .field("authenticator", &self.core.authenticator)
            .field("allocation_count", &self.core.allocations.len())
            .field("response_cache_count", &self.core.response_cache.len())
            .finish_non_exhaustive()
    }
}

struct Allocation {
    node_id: NodeId,
    command_sender: mpsc::Sender<AllocationCommand>,
    relayed_address: SocketAddr,
    expires_at: Instant,
    idle_deadline: Instant,
}

impl fmt::Debug for Allocation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Allocation")
            .field("node_id", &self.node_id)
            .field("relayed_address", &self.relayed_address)
            .field("expires_at", &self.expires_at)
            .field("idle_deadline", &self.idle_deadline)
            .finish_non_exhaustive()
    }
}

enum AllocationCommand {
    CreatePermissions {
        peers: Vec<SocketAddr>,
        now: Instant,
        response: oneshot::Sender<Result<(), AllocationMutationError>>,
    },
    BindChannel {
        channel: TurnChannelNumber,
        peer: SocketAddr,
        now: Instant,
        response: oneshot::Sender<Result<(), AllocationMutationError>>,
    },
    SendToPeer {
        peer: SocketAddr,
        data: Vec<u8>,
        now: Instant,
    },
    SendChannelData {
        channel: TurnChannelNumber,
        data: Vec<u8>,
        now: Instant,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum AllocationMutationError {
    Capacity,
    Conflict,
    DeadlineOverflow,
}

struct ChannelBinding {
    peer: SocketAddr,
    expires_at: Instant,
}

struct AllocationActor {
    socket: UdpSocket,
    sink: ClientSink,
    max_datagram_size: usize,
    max_permissions: usize,
    max_channels: usize,
    permissions: HashMap<IpAddr, Instant>,
    channels: HashMap<TurnChannelNumber, ChannelBinding>,
}

async fn run_allocation_actor(
    socket: UdpSocket,
    sink: ClientSink,
    max_datagram_size: usize,
    max_permissions: usize,
    max_channels: usize,
    mut commands: mpsc::Receiver<AllocationCommand>,
) {
    let mut actor = AllocationActor {
        socket,
        sink,
        max_datagram_size,
        max_permissions,
        max_channels,
        permissions: HashMap::new(),
        channels: HashMap::new(),
    };
    let mut receive_buffer = vec![0_u8; RECEIVE_BUFFER_LENGTH];
    loop {
        tokio::select! {
            command = commands.recv() => {
                let Some(command) = command else {
                    return;
                };
                actor.handle_command(command).await;
            }
            received = actor.socket.recv_from(&mut receive_buffer) => {
                let Ok((length, peer)) = received else {
                    return;
                };
                actor.handle_peer_datagram(peer, &receive_buffer[..length]).await;
            }
        }
    }
}

impl AllocationActor {
    async fn handle_command(&mut self, command: AllocationCommand) {
        match command {
            AllocationCommand::CreatePermissions {
                peers,
                now,
                response,
            } => {
                let result = self.create_permissions(&peers, now);
                let _result = response.send(result);
            }
            AllocationCommand::BindChannel {
                channel,
                peer,
                now,
                response,
            } => {
                let result = self.bind_channel(channel, peer, now);
                let _result = response.send(result);
            }
            AllocationCommand::SendToPeer { peer, data, now } => {
                self.send_to_peer(peer, &data, None, now).await;
            }
            AllocationCommand::SendChannelData { channel, data, now } => {
                self.cleanup(now);
                let Some(peer) = self.channels.get(&channel).map(|binding| binding.peer) else {
                    return;
                };
                self.send_to_peer(peer, &data, Some(channel), now).await;
            }
        }
    }

    fn create_permissions(
        &mut self,
        peers: &[SocketAddr],
        now: Instant,
    ) -> Result<(), AllocationMutationError> {
        self.cleanup(now);
        let expires_at = now
            .checked_add(PERMISSION_LIFETIME)
            .ok_or(AllocationMutationError::DeadlineOverflow)?;
        let mut new_ips = peers
            .iter()
            .map(SocketAddr::ip)
            .filter(|ip| !self.permissions.contains_key(ip))
            .collect::<Vec<_>>();
        new_ips.sort_unstable();
        new_ips.dedup();
        if self.permissions.len().saturating_add(new_ips.len()) > self.max_permissions {
            return Err(AllocationMutationError::Capacity);
        }
        for peer in peers {
            self.permissions.insert(peer.ip(), expires_at);
        }
        Ok(())
    }

    fn bind_channel(
        &mut self,
        channel: TurnChannelNumber,
        peer: SocketAddr,
        now: Instant,
    ) -> Result<(), AllocationMutationError> {
        self.cleanup(now);
        if self
            .channels
            .get(&channel)
            .is_some_and(|binding| binding.peer != peer)
            || self
                .channels
                .iter()
                .any(|(bound_channel, binding)| *bound_channel != channel && binding.peer == peer)
        {
            return Err(AllocationMutationError::Conflict);
        }
        let new_permission = !self.permissions.contains_key(&peer.ip());
        let new_channel = !self.channels.contains_key(&channel);
        if (new_permission && self.permissions.len() >= self.max_permissions)
            || (new_channel && self.channels.len() >= self.max_channels)
        {
            return Err(AllocationMutationError::Capacity);
        }
        let permission_expires = now
            .checked_add(PERMISSION_LIFETIME)
            .ok_or(AllocationMutationError::DeadlineOverflow)?;
        let channel_expires = now
            .checked_add(CHANNEL_BINDING_LIFETIME)
            .ok_or(AllocationMutationError::DeadlineOverflow)?;
        self.permissions.insert(peer.ip(), permission_expires);
        self.channels.insert(
            channel,
            ChannelBinding {
                peer,
                expires_at: channel_expires,
            },
        );
        Ok(())
    }

    async fn send_to_peer(
        &mut self,
        peer: SocketAddr,
        data: &[u8],
        required_channel: Option<TurnChannelNumber>,
        now: Instant,
    ) {
        self.cleanup(now);
        if data.len() > self.max_datagram_size
            || !self.permissions.contains_key(&peer.ip())
            || required_channel.is_some_and(|channel| {
                self.channels
                    .get(&channel)
                    .is_none_or(|binding| binding.peer != peer)
            })
        {
            return;
        }
        let _result = self.socket.send_to(data, peer).await;
    }

    async fn handle_peer_datagram(&mut self, peer: SocketAddr, data: &[u8]) {
        let now = Instant::now();
        self.cleanup(now);
        if data.len() > self.max_datagram_size || !self.permissions.contains_key(&peer.ip()) {
            return;
        }
        let channel = self
            .channels
            .iter()
            .find_map(|(channel, binding)| (binding.peer == peer).then_some(*channel));
        let encoded = if let Some(channel) = channel {
            let padding = usize::from(self.sink.is_stream()) * 3;
            let mut encoded = vec![0_u8; data.len().saturating_add(4).saturating_add(padding)];
            let length = if self.sink.is_stream() {
                encode_turn_channel_data_stream(channel, data, &mut encoded)
            } else {
                encode_turn_channel_data(channel, data, &mut encoded)
            };
            let Ok(length) = length else {
                return;
            };
            encoded.truncate(length);
            encoded
        } else {
            let Some(transaction_id) = random_transaction_id() else {
                return;
            };
            let Ok(peer_value) = xor_address_value(peer, transaction_id) else {
                return;
            };
            let Ok(encoded) = encode_response(
                StunMethod::Data,
                StunClass::Indication,
                transaction_id,
                vec![
                    OwnedAttribute::new(StunAttributeType::XOR_PEER_ADDRESS, peer_value),
                    OwnedAttribute::new(StunAttributeType::DATA, data.to_vec()),
                ],
                None,
            ) else {
                return;
            };
            encoded
        };
        self.sink.send_data(encoded).await;
    }

    fn cleanup(&mut self, now: Instant) {
        self.permissions
            .retain(|_peer_ip, expires_at| *expires_at > now);
        self.channels.retain(|_channel, binding| {
            binding.expires_at > now && self.permissions.contains_key(&binding.peer.ip())
        });
    }
}

enum AuthenticationDecision {
    Authenticated(AuthenticatedTurnRequest),
    Response(Vec<u8>),
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
struct ResponseCacheKey {
    client: SocketAddr,
    transaction_id: StunTransactionId,
}

struct CachedResponse {
    bytes: Vec<u8>,
    expires_at: Instant,
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

fn encode_response(
    method: StunMethod,
    class: StunClass,
    transaction_id: StunTransactionId,
    mut attributes: Vec<OwnedAttribute>,
    authenticated: Option<&AuthenticatedTurnRequest>,
) -> Result<Vec<u8>, TurnRelayError> {
    let zero_integrity = [0_u8; 32];
    if authenticated.is_some() {
        attributes.push(OwnedAttribute::new(
            StunAttributeType::MESSAGE_INTEGRITY_SHA256,
            zero_integrity.to_vec(),
        ));
    }
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
    if let Some(authenticated) = authenticated {
        authenticated
            .sign_encoded_message(&mut encoded)
            .map_err(|_error| TurnRelayError::ResponseIntegrity)?;
    }
    Ok(encoded)
}

fn xor_address_value(
    address: SocketAddr,
    transaction_id: StunTransactionId,
) -> Result<Vec<u8>, TurnRelayError> {
    let mut value = vec![0_u8; if address.is_ipv4() { 8 } else { 20 }];
    let length = encode_stun_xor_address(address, transaction_id, &mut value)?;
    value.truncate(length);
    Ok(value)
}

fn unique_attribute<'a>(
    message: &StunMessageView<'a>,
    requested: StunAttributeType,
) -> Result<Option<&'a [u8]>, TurnRelayError> {
    let mut found = None;
    for attribute in message.attributes() {
        let attribute = attribute?;
        if attribute.attribute_type() == requested && found.replace(attribute.value()).is_some() {
            return Err(TurnRelayError::MalformedRequest {
                detail: "duplicate method attribute",
            });
        }
    }
    Ok(found)
}

fn peer_addresses(message: &StunMessageView<'_>) -> Result<Vec<SocketAddr>, TurnRelayError> {
    let mut peers = Vec::new();
    for attribute in message.attributes() {
        let attribute = attribute?;
        if attribute.attribute_type() != StunAttributeType::XOR_PEER_ADDRESS {
            continue;
        }
        let peer = decode_stun_xor_address(attribute.value(), message.transaction_id())?;
        if peers.contains(&peer) {
            return Err(TurnRelayError::MalformedRequest {
                detail: "duplicate XOR-PEER-ADDRESS",
            });
        }
        peers.push(peer);
    }
    Ok(peers)
}

fn channel_number(message: &StunMessageView<'_>) -> Result<TurnChannelNumber, TurnRelayError> {
    let Some(value) = unique_attribute(message, StunAttributeType::CHANNEL_NUMBER)? else {
        return Err(TurnRelayError::MalformedRequest {
            detail: "missing CHANNEL-NUMBER",
        });
    };
    let bytes = <[u8; 4]>::try_from(value).map_err(|_| TurnRelayError::MalformedRequest {
        detail: "CHANNEL-NUMBER must contain four bytes",
    })?;
    if bytes[2..] != [0, 0] {
        return Err(TurnRelayError::MalformedRequest {
            detail: "CHANNEL-NUMBER reserved bytes must be zero",
        });
    }
    TurnChannelNumber::new(u16::from_be_bytes([bytes[0], bytes[1]])).ok_or(
        TurnRelayError::MalformedRequest {
            detail: "CHANNEL-NUMBER is outside the dynamic range",
        },
    )
}

fn random_transaction_id() -> Option<StunTransactionId> {
    let mut bytes = [0_u8; 12];
    getrandom::fill(&mut bytes).ok()?;
    Some(StunTransactionId::from_bytes(bytes))
}

fn requested_lifetime(
    message: &StunMessageView<'_>,
    maximum: u32,
    zero_allowed: bool,
) -> Result<u32, TurnRelayError> {
    let Some(value) = unique_attribute(message, StunAttributeType::LIFETIME)? else {
        return Ok(maximum);
    };
    let bytes = <[u8; 4]>::try_from(value).map_err(|_| TurnRelayError::MalformedRequest {
        detail: "LIFETIME must contain four bytes",
    })?;
    let requested = u32::from_be_bytes(bytes);
    if requested == 0 && !zero_allowed {
        return Err(TurnRelayError::MalformedRequest {
            detail: "Allocate lifetime must be non-zero",
        });
    }
    Ok(requested.min(maximum))
}

fn unknown_required_attributes(message: &StunMessageView<'_>) -> Result<Vec<u16>, TurnRelayError> {
    let mut unknown = Vec::new();
    for attribute in message.attributes() {
        let attribute = attribute?;
        let attribute_type = attribute.attribute_type();
        if attribute_type.comprehension_required()
            && !is_known_attribute(attribute_type)
            && !unknown.contains(&attribute_type.as_u16())
        {
            unknown.push(attribute_type.as_u16());
        }
    }
    unknown.sort_unstable();
    Ok(unknown)
}

fn is_known_attribute(attribute_type: StunAttributeType) -> bool {
    attribute_type == StunAttributeType::MAPPED_ADDRESS
        || attribute_type == StunAttributeType::USERNAME
        || attribute_type == StunAttributeType::MESSAGE_INTEGRITY
        || attribute_type == StunAttributeType::ERROR_CODE
        || attribute_type == StunAttributeType::UNKNOWN_ATTRIBUTES
        || attribute_type == StunAttributeType::CHANNEL_NUMBER
        || attribute_type == StunAttributeType::LIFETIME
        || attribute_type == StunAttributeType::XOR_PEER_ADDRESS
        || attribute_type == StunAttributeType::DATA
        || attribute_type == StunAttributeType::REALM
        || attribute_type == StunAttributeType::NONCE
        || attribute_type == StunAttributeType::XOR_RELAYED_ADDRESS
        || attribute_type == StunAttributeType::REQUESTED_TRANSPORT
        || attribute_type == StunAttributeType::DONT_FRAGMENT
        || attribute_type == StunAttributeType::MESSAGE_INTEGRITY_SHA256
        || attribute_type == StunAttributeType::PASSWORD_ALGORITHM
        || attribute_type == StunAttributeType::USERHASH
        || attribute_type == StunAttributeType::XOR_MAPPED_ADDRESS
        || attribute_type == StunAttributeType::SOFTWARE
        || attribute_type == StunAttributeType::ALTERNATE_SERVER
        || attribute_type == StunAttributeType::FINGERPRINT
}

fn checked_deadline(
    now: Instant,
    seconds: u32,
    field: &'static str,
) -> Result<Instant, TurnRelayError> {
    now.checked_add(Duration::from_secs(u64::from(seconds)))
        .ok_or(TurnRelayError::DeadlineOverflow { field })
}

fn unix_time() -> Result<u64, TurnRelayError> {
    Ok(SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| TurnRelayError::ClockBeforeUnixEpoch)?
        .as_secs())
}

fn invalid_config(reason: &'static str) -> TurnRelayError {
    TurnRelayError::InvalidConfig { reason }
}

/// TURN relay startup or runtime failure.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum TurnRelayError {
    /// A runtime address or resource limit is invalid.
    #[error("invalid TURN relay configuration: {reason}")]
    InvalidConfig {
        /// Stable configuration rule description.
        reason: &'static str,
    },
    /// Client-facing control socket bind failed.
    #[error("unable to bind TURN UDP listener {address}")]
    BindControl {
        /// Requested listener address.
        address: SocketAddr,
        /// Underlying socket failure.
        #[source]
        source: std::io::Error,
    },
    /// Client-facing TCP listener bind failed.
    #[error("unable to bind TURN TCP listener {address}")]
    BindTcp {
        /// Requested listener address.
        address: SocketAddr,
        /// Underlying socket failure.
        #[source]
        source: std::io::Error,
    },
    /// Bound listener address could not be queried.
    #[error("unable to query TURN UDP listener address")]
    LocalAddress {
        /// Underlying socket failure.
        #[source]
        source: std::io::Error,
    },
    /// Bound TCP listener address could not be queried.
    #[error("unable to query TURN TCP listener address")]
    TcpLocalAddress {
        /// Underlying socket failure.
        #[source]
        source: std::io::Error,
    },
    /// Accepting a TURN TCP client failed.
    #[error("TURN TCP listener accept failed")]
    AcceptTcp {
        /// Underlying socket failure.
        #[source]
        source: std::io::Error,
    },
    /// Configuring an accepted TURN TCP socket failed.
    #[error("unable to configure TURN TCP client {client}")]
    ConfigureTcp {
        /// Connected client transport address.
        client: SocketAddr,
        /// Underlying socket failure.
        #[source]
        source: std::io::Error,
    },
    /// A TURN TLS client did not complete its handshake before the configured deadline.
    #[error("TURN TLS handshake with {client} timed out")]
    TlsHandshakeTimeout {
        /// Connected client transport address.
        client: SocketAddr,
    },
    /// A TURN TLS client failed certificate-independent server-side negotiation.
    #[error("TURN TLS handshake with {client} failed")]
    TlsHandshake {
        /// Connected client transport address.
        client: SocketAddr,
        /// Underlying TLS I/O or protocol failure.
        #[source]
        source: std::io::Error,
    },
    /// A secure WebSocket client did not complete TLS and HTTP upgrade in time.
    #[error("TURN WebSocket handshake with {client} timed out")]
    WebSocketHandshakeTimeout {
        /// Connected client transport address.
        client: SocketAddr,
    },
    /// A secure WebSocket client failed its HTTP upgrade or pre-authentication.
    #[error("TURN WebSocket handshake with {client} failed")]
    WebSocketHandshake {
        /// Connected client transport address.
        client: SocketAddr,
        /// Underlying HTTP or WebSocket protocol failure.
        #[source]
        source: WebSocketError,
    },
    /// A per-client relay allocation socket could not be bound.
    #[error("unable to bind TURN allocation socket on {address}")]
    BindAllocation {
        /// Requested local allocation IP.
        address: IpAddr,
        /// Underlying socket failure.
        #[source]
        source: std::io::Error,
    },
    /// Bound allocation address could not be queried.
    #[error("unable to query TURN allocation socket address")]
    AllocationLocalAddress {
        /// Underlying socket failure.
        #[source]
        source: std::io::Error,
    },
    /// Client-facing receive failed.
    #[error("TURN UDP listener receive failed")]
    ReceiveControl {
        /// Underlying socket failure.
        #[source]
        source: std::io::Error,
    },
    /// Sending a response to a TURN client failed.
    #[error("unable to send TURN response to {client}")]
    SendControl {
        /// Client transport address.
        client: SocketAddr,
        /// Underlying socket failure.
        #[source]
        source: std::io::Error,
    },
    /// A reliable session ended before accepting another response record.
    #[error("TURN reliable client stream {client} is closed")]
    ClientStreamClosed {
        /// Connected client transport address.
        client: SocketAddr,
    },
    /// A reliable client did not complete another TURN record before its idle deadline.
    #[error("TURN reliable client stream timed out")]
    ClientReadTimeout,
    /// A TURN TCP session task panicked or was cancelled unexpectedly.
    #[error("TURN TCP client session task failed")]
    ClientTaskJoin {
        /// Tokio task join failure.
        #[source]
        source: tokio::task::JoinError,
    },
    /// A TURN TCP writer task panicked or was cancelled unexpectedly.
    #[error("TURN TCP client writer task failed")]
    ClientWriterTaskJoin {
        /// Tokio task join failure.
        #[source]
        source: tokio::task::JoinError,
    },
    /// A per-allocation actor panicked or was cancelled unexpectedly.
    #[error("TURN allocation task failed")]
    AllocationTaskJoin {
        /// Tokio task join failure.
        #[source]
        source: tokio::task::JoinError,
    },
    /// System wall clock precedes the Unix epoch.
    #[error("system clock is before the Unix epoch")]
    ClockBeforeUnixEpoch,
    /// A monotonic deadline could not be represented.
    #[error("TURN {field} deadline overflowed")]
    DeadlineOverflow {
        /// Deadline being calculated.
        field: &'static str,
    },
    /// A method-specific request attribute is malformed.
    #[error("malformed TURN request: {detail}")]
    MalformedRequest {
        /// Stable non-sensitive rule description.
        detail: &'static str,
    },
    /// Authentication returned an impossible nonce state.
    #[error("TURN authentication returned an invalid internal nonce state")]
    InvalidAuthenticationState,
    /// Relay credential or nonce creation failed.
    #[error(transparent)]
    Credential(#[from] crate::relay_credentials::RelayCredentialError),
    /// TURN wire encoding failed.
    #[error(transparent)]
    Codec(#[from] CodecError),
    /// Reliable TURN record framing or stream I/O failed.
    #[error(transparent)]
    Stream(#[from] stella_transport::TurnStreamError),
    /// Secure WebSocket record framing, protocol handling, or I/O failed.
    #[error(transparent)]
    WebSocket(#[from] WebSocketRecordError),
    /// Authenticated response signing failed.
    #[error("unable to sign TURN response integrity")]
    ResponseIntegrity,
}

#[cfg(test)]
mod tests {
    use std::{
        net::{IpAddr, Ipv4Addr, SocketAddr},
        sync::Arc,
        time::{Duration, Instant},
    };

    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
    use hmac::{Hmac, KeyInit, Mac};
    use sha2::{Digest, Sha256};
    use stella_common::{NodeId, RelayId};
    use stella_proto::{
        decode_stun_xor_address, encode_stun_message, encode_stun_xor_address,
        encode_turn_channel_data, StunAttributeRef, StunAttributeType, StunClass,
        StunErrorCodeView, StunMessageRef, StunMessageType, StunMessageView, StunMethod,
        StunPasswordAlgorithm, StunTransactionId, TurnChannelDataView, TurnChannelNumber,
    };
    use tokio::{
        io::{duplex, AsyncWriteExt},
        net::UdpSocket,
        sync::{mpsc, oneshot, Mutex},
        time::timeout,
    };
    use tokio_tungstenite::{
        tungstenite::{
            handshake::server::{Request as WebSocketRequest, Response as WebSocketResponse},
            http::{
                header::{AUTHORIZATION, SEC_WEBSOCKET_EXTENSIONS, SEC_WEBSOCKET_PROTOCOL},
                StatusCode,
            },
            protocol::Role,
        },
        WebSocketStream,
    };
    use zeroize::Zeroizing;

    use super::{
        authorize_websocket_upgrade, run_stream_client, run_websocket_client, Allocation,
        TurnRelayCore, TurnRelayError, TurnUdpRelay, TurnUdpRelayConfig,
    };
    use crate::relay_credentials::RelayCredentialAuthority;

    type HmacSha256 = Hmac<Sha256>;

    struct TestAllocation {
        realm: Vec<u8>,
        nonce: Vec<u8>,
        relayed_address: SocketAddr,
    }

    #[test]
    fn allocation_counts_follow_allocation_lifecycle() {
        let relay_id = RelayId::from_bytes([0x31; 16]);
        let config = TurnUdpRelayConfig::new(
            relay_id,
            SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            IpAddr::V4(Ipv4Addr::LOCALHOST),
        );
        let authority =
            RelayCredentialAuthority::new([0x32; 32], 300).expect("credential authority");
        let mut core =
            TurnRelayCore::new(config.into(), authority).expect("create TURN relay core");
        let node_a = NodeId::from_bytes([0x33; 16]);
        let node_b = NodeId::from_bytes([0x34; 16]);
        let client_a = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 40_001);
        let client_b = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 40_002);
        let client_c = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 40_003);
        let now = Instant::now();
        let future = now + Duration::from_secs(60);
        let (command_sender, _command_receiver) = mpsc::channel(1);
        let allocation = |node_id, expires_at| Allocation {
            node_id,
            command_sender: command_sender.clone(),
            relayed_address: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 50_000),
            expires_at,
            idle_deadline: future,
        };

        core.insert_allocation(client_a, allocation(node_a, future));
        core.insert_allocation(client_b, allocation(node_a, now));
        core.insert_allocation(client_c, allocation(node_b, future));
        assert_eq!(core.allocations.len(), 3);
        assert_eq!(core.allocation_counts.get(&node_a), Some(&2));
        assert_eq!(core.allocation_counts.get(&node_b), Some(&1));

        core.remove_allocation(client_a);
        core.remove_allocation(client_a);
        assert_eq!(core.allocations.len(), 2);
        assert_eq!(core.allocation_counts.get(&node_a), Some(&1));

        core.remove_expired(now);
        assert_eq!(core.allocations.len(), 1);
        assert!(!core.allocation_counts.contains_key(&node_a));
        assert_eq!(core.allocation_counts.get(&node_b), Some(&1));

        core.remove_client(client_c);
        assert!(core.allocations.is_empty());
        assert!(core.allocation_counts.is_empty());
    }

    #[tokio::test]
    async fn reliable_clients_time_out_incomplete_records() {
        let relay_id = RelayId::from_bytes([0x41; 16]);
        let config = TurnUdpRelayConfig::new(
            relay_id,
            SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            IpAddr::V4(Ipv4Addr::LOCALHOST),
        );
        let client = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 45_100);
        let idle_timeout = Duration::from_millis(25);

        let authority = RelayCredentialAuthority::new([0x42; 32], 300)
            .expect("create stream credential authority");
        let core = Arc::new(Mutex::new(
            TurnRelayCore::new(config.into(), authority).expect("create stream relay core"),
        ));
        let (mut raw_client, relay_stream) = duplex(64);
        raw_client
            .write_all(&[0, 1])
            .await
            .expect("write partial TURN prefix");
        let error = timeout(
            Duration::from_secs(1),
            run_stream_client(relay_stream, client, core, idle_timeout),
        )
        .await
        .expect("stream client reaches its idle deadline")
        .expect_err("partial TURN prefix times out");
        assert!(matches!(error, TurnRelayError::ClientReadTimeout));

        let authority = RelayCredentialAuthority::new([0x43; 32], 300)
            .expect("create WebSocket credential authority");
        let core = Arc::new(Mutex::new(
            TurnRelayCore::new(config.into(), authority).expect("create WebSocket relay core"),
        ));
        let (mut raw_client, relay_stream) = duplex(64);
        let websocket = WebSocketStream::from_raw_socket(relay_stream, Role::Server, None).await;
        raw_client
            .write_all(&[0x82, 0x80])
            .await
            .expect("write partial masked WebSocket frame");
        let error = timeout(
            Duration::from_secs(1),
            run_websocket_client(websocket, client, core, idle_timeout),
        )
        .await
        .expect("WebSocket client reaches its idle deadline")
        .expect_err("partial WebSocket frame times out");
        assert!(matches!(error, TurnRelayError::ClientReadTimeout));
    }

    #[test]
    fn websocket_upgrade_accepts_only_valid_canonical_credentials() {
        let relay_id = RelayId::from_bytes([0x51; 16]);
        let authority =
            RelayCredentialAuthority::new([0x52; 32], 300).expect("credential authority");
        let credential = authority
            .issue(
                relay_id,
                NodeId::from_bytes([0x53; 16]),
                unix_time_for_test(),
            )
            .expect("issue credential");
        let authorization = websocket_authorization(credential.username(), credential.secret());
        let accepted = authorize_websocket_upgrade(
            &websocket_request("/stella/turn/v1", &authorization, "stella-turn.v1", None),
            websocket_response(),
            relay_id,
            &authority,
        )
        .expect("authorize canonical credential");
        assert_eq!(
            accepted
                .headers()
                .get(SEC_WEBSOCKET_PROTOCOL)
                .expect("selected subprotocol"),
            "stella-turn.v1"
        );

        let wrong_secret = websocket_authorization(credential.username(), b"wrong secret");
        assert_eq!(
            authorize_websocket_upgrade(
                &websocket_request("/stella/turn/v1", &wrong_secret, "stella-turn.v1", None),
                websocket_response(),
                relay_id,
                &authority,
            )
            .expect_err("reject wrong secret")
            .status(),
            StatusCode::UNAUTHORIZED
        );

        let noncanonical = format!("{authorization}=");
        assert_eq!(
            authorize_websocket_upgrade(
                &websocket_request("/stella/turn/v1", &noncanonical, "stella-turn.v1", None),
                websocket_response(),
                relay_id,
                &authority,
            )
            .expect_err("reject padded credential")
            .status(),
            StatusCode::UNAUTHORIZED
        );
    }

    #[test]
    fn websocket_upgrade_rejects_ambiguous_or_wrong_profiles() {
        let relay_id = RelayId::from_bytes([0x54; 16]);
        let authority =
            RelayCredentialAuthority::new([0x55; 32], 300).expect("credential authority");
        let credential = authority
            .issue(
                relay_id,
                NodeId::from_bytes([0x56; 16]),
                unix_time_for_test(),
            )
            .expect("issue credential");
        let authorization = websocket_authorization(credential.username(), credential.secret());

        let duplicate = WebSocketRequest::builder()
            .uri("/stella/turn/v1")
            .header(SEC_WEBSOCKET_PROTOCOL, "stella-turn.v1")
            .header(AUTHORIZATION, &authorization)
            .header(AUTHORIZATION, &authorization)
            .body(())
            .expect("duplicate authorization request");
        assert_eq!(
            authorize_websocket_upgrade(&duplicate, websocket_response(), relay_id, &authority)
                .expect_err("reject duplicate authorization")
                .status(),
            StatusCode::UNAUTHORIZED
        );

        for request in [
            websocket_request("/wrong", &authorization, "stella-turn.v1", None),
            websocket_request("/stella/turn/v1", &authorization, "other", None),
            websocket_request(
                "/stella/turn/v1",
                &authorization,
                "stella-turn.v1",
                Some("permessage-deflate"),
            ),
        ] {
            assert_eq!(
                authorize_websocket_upgrade(&request, websocket_response(), relay_id, &authority)
                    .expect_err("reject wrong WebSocket profile")
                    .status(),
                StatusCode::BAD_REQUEST
            );
        }
    }

    #[tokio::test]
    #[allow(clippy::too_many_lines)]
    async fn binding_allocate_retransmit_refresh_and_delete_round_trip() {
        let relay_id = RelayId::from_bytes([0x61; 16]);
        let node_id = NodeId::from_bytes([0x62; 16]);
        let authority =
            RelayCredentialAuthority::new([0x63; 32], 300).expect("credential authority");
        let credential = authority
            .issue(relay_id, node_id, unix_time_for_test())
            .expect("issue credential");
        let config = TurnUdpRelayConfig::new(
            relay_id,
            SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            IpAddr::V4(Ipv4Addr::LOCALHOST),
        );
        let relay = TurnUdpRelay::bind(config, authority)
            .await
            .expect("bind TURN relay");
        let relay_address = relay.local_address().expect("relay address");
        let (shutdown_tx, shutdown_rx) = oneshot::channel();
        let task = tokio::spawn(relay.run(async move {
            let _result = shutdown_rx.await;
        }));
        let client = UdpSocket::bind(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0))
            .await
            .expect("bind client");

        let binding_tx = StunTransactionId::from_bytes([1; 12]);
        send_message(&client, relay_address, StunMethod::Binding, binding_tx, &[]).await;
        let binding = receive_message(&client).await;
        assert_eq!(binding.message_type().class, StunClass::SuccessResponse);
        let mapped = required_attribute(&binding, StunAttributeType::XOR_MAPPED_ADDRESS);
        assert_eq!(
            decode_stun_xor_address(mapped, binding_tx).expect("decode mapped address"),
            client.local_addr().expect("client local address")
        );

        let allocate_challenge_tx = StunTransactionId::from_bytes([2; 12]);
        let requested_transport = [17, 0, 0, 0];
        send_message(
            &client,
            relay_address,
            StunMethod::Allocate,
            allocate_challenge_tx,
            &[StunAttributeRef {
                attribute_type: StunAttributeType::REQUESTED_TRANSPORT,
                value: &requested_transport,
            }],
        )
        .await;
        let challenge = receive_owned_message(&client).await;
        let challenge_view = StunMessageView::decode(&challenge).expect("decode challenge");
        assert_error(&challenge_view, 401);
        let realm = required_attribute(&challenge_view, StunAttributeType::REALM).to_vec();
        let nonce = required_attribute(&challenge_view, StunAttributeType::NONCE).to_vec();

        let allocate_tx = StunTransactionId::from_bytes([4; 12]);
        let authenticated_allocate = signed_request(
            StunMethod::Allocate,
            allocate_tx,
            credential.username(),
            &realm,
            &nonce,
            credential.secret(),
            &[StunAttributeRef {
                attribute_type: StunAttributeType::REQUESTED_TRANSPORT,
                value: &requested_transport,
            }],
        );
        client
            .send_to(&authenticated_allocate, relay_address)
            .await
            .expect("send authenticated Allocate");
        let allocated_bytes = receive_owned_message(&client).await;
        let allocated =
            StunMessageView::decode(&allocated_bytes).expect("decode Allocate response");
        assert_eq!(allocated.message_type().class, StunClass::SuccessResponse);
        let relayed = decode_stun_xor_address(
            required_attribute(&allocated, StunAttributeType::XOR_RELAYED_ADDRESS),
            allocate_tx,
        )
        .expect("decode relayed address");
        assert_eq!(relayed.ip(), IpAddr::V4(Ipv4Addr::LOCALHOST));
        assert_ne!(relayed.port(), 0);

        client
            .send_to(&authenticated_allocate, relay_address)
            .await
            .expect("retransmit Allocate");
        assert_eq!(receive_owned_message(&client).await, allocated_bytes);

        let refresh_tx = StunTransactionId::from_bytes([3; 12]);
        let zero_lifetime = 0_u32.to_be_bytes();
        let refresh = signed_request(
            StunMethod::Refresh,
            refresh_tx,
            credential.username(),
            &realm,
            &nonce,
            credential.secret(),
            &[StunAttributeRef {
                attribute_type: StunAttributeType::LIFETIME,
                value: &zero_lifetime,
            }],
        );
        client
            .send_to(&refresh, relay_address)
            .await
            .expect("send delete Refresh");
        let deleted = receive_message(&client).await;
        assert_eq!(deleted.message_type().class, StunClass::SuccessResponse);
        assert_eq!(
            required_attribute(&deleted, StunAttributeType::LIFETIME),
            zero_lifetime
        );

        let _result = shutdown_tx.send(());
        timeout(Duration::from_secs(2), task)
            .await
            .expect("relay shutdown deadline")
            .expect("relay task join")
            .expect("relay runtime");
    }

    #[tokio::test]
    async fn per_node_allocation_quota_is_released_on_delete() {
        let relay_id = RelayId::from_bytes([0x65; 16]);
        let node_id = NodeId::from_bytes([0x66; 16]);
        let authority =
            RelayCredentialAuthority::new([0x67; 32], 300).expect("credential authority");
        let credential = authority
            .issue(relay_id, node_id, unix_time_for_test())
            .expect("issue credential");
        let mut config = TurnUdpRelayConfig::new(
            relay_id,
            SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            IpAddr::V4(Ipv4Addr::LOCALHOST),
        );
        config.max_allocations = 2;
        config.max_allocations_per_node = 1;
        let relay = TurnUdpRelay::bind(config, authority)
            .await
            .expect("bind TURN relay");
        let relay_address = relay.local_address().expect("relay address");
        let (shutdown_tx, shutdown_rx) = oneshot::channel();
        let task = tokio::spawn(relay.run(async move {
            let _result = shutdown_rx.await;
        }));
        let client_a = bind_test_client().await;
        let client_b = bind_test_client().await;
        let allocation_a = allocate_test_client(
            &client_a,
            relay_address,
            credential.username(),
            credential.secret(),
            10,
        )
        .await;

        let requested_transport = [17, 0, 0, 0];
        let rejected_request = signed_request(
            StunMethod::Allocate,
            StunTransactionId::from_bytes([20; 12]),
            credential.username(),
            &allocation_a.realm,
            &allocation_a.nonce,
            credential.secret(),
            &[StunAttributeRef {
                attribute_type: StunAttributeType::REQUESTED_TRANSPORT,
                value: &requested_transport,
            }],
        );
        client_b
            .send_to(&rejected_request, relay_address)
            .await
            .expect("send allocation above per-node quota");
        let rejected = receive_owned_message(&client_b).await;
        assert_error(
            &StunMessageView::decode(&rejected).expect("decode quota response"),
            486,
        );

        let zero_lifetime = 0_u32.to_be_bytes();
        let delete_request = signed_request(
            StunMethod::Refresh,
            StunTransactionId::from_bytes([21; 12]),
            credential.username(),
            &allocation_a.realm,
            &allocation_a.nonce,
            credential.secret(),
            &[StunAttributeRef {
                attribute_type: StunAttributeType::LIFETIME,
                value: &zero_lifetime,
            }],
        );
        client_a
            .send_to(&delete_request, relay_address)
            .await
            .expect("delete first allocation");
        let deleted = receive_owned_message(&client_a).await;
        assert_eq!(
            StunMessageView::decode(&deleted)
                .expect("decode delete response")
                .message_type()
                .class,
            StunClass::SuccessResponse
        );

        let _allocation_b = allocate_test_client(
            &client_b,
            relay_address,
            credential.username(),
            credential.secret(),
            30,
        )
        .await;

        let _result = shutdown_tx.send(());
        timeout(Duration::from_secs(2), task)
            .await
            .expect("relay shutdown deadline")
            .expect("relay task join")
            .expect("relay runtime");
    }

    #[tokio::test]
    #[allow(clippy::too_many_lines)]
    async fn permissions_send_data_and_channel_data_preserve_datagrams() {
        let relay_id = RelayId::from_bytes([0x71; 16]);
        let node_a = NodeId::from_bytes([0x72; 16]);
        let node_b = NodeId::from_bytes([0x73; 16]);
        let authority =
            RelayCredentialAuthority::new([0x74; 32], 300).expect("credential authority");
        let now = unix_time_for_test();
        let credential_a = authority
            .issue(relay_id, node_a, now)
            .expect("issue credential A");
        let credential_b = authority
            .issue(relay_id, node_b, now)
            .expect("issue credential B");
        let config = TurnUdpRelayConfig::new(
            relay_id,
            SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            IpAddr::V4(Ipv4Addr::LOCALHOST),
        );
        let relay = TurnUdpRelay::bind(config, authority)
            .await
            .expect("bind TURN relay");
        let relay_address = relay.local_address().expect("relay address");
        let (shutdown_tx, shutdown_rx) = oneshot::channel();
        let task = tokio::spawn(relay.run(async move {
            let _result = shutdown_rx.await;
        }));
        let client_a = bind_test_client().await;
        let client_b = bind_test_client().await;
        let allocation_a = allocate_test_client(
            &client_a,
            relay_address,
            credential_a.username(),
            credential_a.secret(),
            10,
        )
        .await;
        let allocation_b = allocate_test_client(
            &client_b,
            relay_address,
            credential_b.username(),
            credential_b.secret(),
            20,
        )
        .await;

        create_permission(
            &client_a,
            relay_address,
            credential_a.username(),
            credential_a.secret(),
            &allocation_a,
            allocation_b.relayed_address,
            30,
        )
        .await;
        create_permission(
            &client_b,
            relay_address,
            credential_b.username(),
            credential_b.secret(),
            &allocation_b,
            allocation_a.relayed_address,
            31,
        )
        .await;

        send_indication(
            &client_a,
            relay_address,
            allocation_b.relayed_address,
            b"first datagram",
            40,
        )
        .await;
        let first = receive_owned_message(&client_b).await;
        let first = StunMessageView::decode(&first).expect("decode Data indication");
        assert_eq!(first.message_type().method, StunMethod::Data);
        assert_eq!(first.message_type().class, StunClass::Indication);
        assert_eq!(
            required_attribute(&first, StunAttributeType::DATA),
            b"first datagram"
        );
        assert_eq!(
            decode_stun_xor_address(
                required_attribute(&first, StunAttributeType::XOR_PEER_ADDRESS),
                first.transaction_id(),
            )
            .expect("decode peer address"),
            allocation_a.relayed_address
        );

        let channel = TurnChannelNumber::new(0x4001).expect("channel number");
        bind_channel(
            &client_b,
            relay_address,
            credential_b.username(),
            credential_b.secret(),
            &allocation_b,
            channel,
            allocation_a.relayed_address,
            50,
        )
        .await;
        send_indication(
            &client_a,
            relay_address,
            allocation_b.relayed_address,
            b"channel receive",
            51,
        )
        .await;
        let channel_record = receive_owned_message(&client_b).await;
        let channel_record =
            TurnChannelDataView::decode_datagram(&channel_record).expect("decode ChannelData");
        assert_eq!(channel_record.channel(), channel);
        assert_eq!(channel_record.data(), b"channel receive");

        let mut outbound_channel = vec![0_u8; 64];
        let length = encode_turn_channel_data(channel, b"channel send", &mut outbound_channel)
            .expect("encode client ChannelData");
        client_b
            .send_to(&outbound_channel[..length], relay_address)
            .await
            .expect("send client ChannelData");
        let received_by_a = receive_owned_message(&client_a).await;
        let received_by_a =
            StunMessageView::decode(&received_by_a).expect("decode peer Data indication");
        assert_eq!(
            required_attribute(&received_by_a, StunAttributeType::DATA),
            b"channel send"
        );

        let _result = shutdown_tx.send(());
        timeout(Duration::from_secs(2), task)
            .await
            .expect("relay shutdown deadline")
            .expect("relay task join")
            .expect("relay runtime");
    }

    async fn bind_test_client() -> UdpSocket {
        UdpSocket::bind(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0))
            .await
            .expect("bind test client")
    }

    async fn allocate_test_client(
        client: &UdpSocket,
        relay: SocketAddr,
        username: &[u8],
        password: &[u8],
        seed: u8,
    ) -> TestAllocation {
        let requested_transport = [17, 0, 0, 0];
        send_message(
            client,
            relay,
            StunMethod::Allocate,
            StunTransactionId::from_bytes([seed; 12]),
            &[StunAttributeRef {
                attribute_type: StunAttributeType::REQUESTED_TRANSPORT,
                value: &requested_transport,
            }],
        )
        .await;
        let challenge = receive_owned_message(client).await;
        let challenge = StunMessageView::decode(&challenge).expect("decode Allocate challenge");
        assert_error(&challenge, 401);
        let realm = required_attribute(&challenge, StunAttributeType::REALM).to_vec();
        let nonce = required_attribute(&challenge, StunAttributeType::NONCE).to_vec();
        let transaction_id = StunTransactionId::from_bytes([seed.saturating_add(1); 12]);
        let request = signed_request(
            StunMethod::Allocate,
            transaction_id,
            username,
            &realm,
            &nonce,
            password,
            &[StunAttributeRef {
                attribute_type: StunAttributeType::REQUESTED_TRANSPORT,
                value: &requested_transport,
            }],
        );
        client
            .send_to(&request, relay)
            .await
            .expect("send authenticated Allocate");
        let response = receive_owned_message(client).await;
        let response = StunMessageView::decode(&response).expect("decode Allocate response");
        assert_eq!(response.message_type().class, StunClass::SuccessResponse);
        let relayed_address = decode_stun_xor_address(
            required_attribute(&response, StunAttributeType::XOR_RELAYED_ADDRESS),
            transaction_id,
        )
        .expect("decode relayed address");
        TestAllocation {
            realm,
            nonce,
            relayed_address,
        }
    }

    #[allow(clippy::too_many_arguments)]
    async fn create_permission(
        client: &UdpSocket,
        relay: SocketAddr,
        username: &[u8],
        password: &[u8],
        allocation: &TestAllocation,
        peer: SocketAddr,
        seed: u8,
    ) {
        let transaction_id = StunTransactionId::from_bytes([seed; 12]);
        let peer_value = encoded_xor_address(peer, transaction_id);
        let request = signed_request(
            StunMethod::CreatePermission,
            transaction_id,
            username,
            &allocation.realm,
            &allocation.nonce,
            password,
            &[StunAttributeRef {
                attribute_type: StunAttributeType::XOR_PEER_ADDRESS,
                value: &peer_value,
            }],
        );
        client
            .send_to(&request, relay)
            .await
            .expect("send CreatePermission");
        let response = receive_message(client).await;
        assert_eq!(response.message_type().class, StunClass::SuccessResponse);
    }

    #[allow(clippy::too_many_arguments)]
    async fn bind_channel(
        client: &UdpSocket,
        relay: SocketAddr,
        username: &[u8],
        password: &[u8],
        allocation: &TestAllocation,
        channel: TurnChannelNumber,
        peer: SocketAddr,
        seed: u8,
    ) {
        let transaction_id = StunTransactionId::from_bytes([seed; 12]);
        let peer_value = encoded_xor_address(peer, transaction_id);
        let mut channel_value = [0_u8; 4];
        channel_value[..2].copy_from_slice(&channel.get().to_be_bytes());
        let request = signed_request(
            StunMethod::ChannelBind,
            transaction_id,
            username,
            &allocation.realm,
            &allocation.nonce,
            password,
            &[
                StunAttributeRef {
                    attribute_type: StunAttributeType::CHANNEL_NUMBER,
                    value: &channel_value,
                },
                StunAttributeRef {
                    attribute_type: StunAttributeType::XOR_PEER_ADDRESS,
                    value: &peer_value,
                },
            ],
        );
        client
            .send_to(&request, relay)
            .await
            .expect("send ChannelBind");
        let response = receive_message(client).await;
        assert_eq!(response.message_type().class, StunClass::SuccessResponse);
    }

    async fn send_indication(
        client: &UdpSocket,
        relay: SocketAddr,
        peer: SocketAddr,
        data: &[u8],
        seed: u8,
    ) {
        let transaction_id = StunTransactionId::from_bytes([seed; 12]);
        let peer_value = encoded_xor_address(peer, transaction_id);
        let encoded = encode_message_with_class(
            StunMethod::Send,
            StunClass::Indication,
            transaction_id,
            &[
                StunAttributeRef {
                    attribute_type: StunAttributeType::XOR_PEER_ADDRESS,
                    value: &peer_value,
                },
                StunAttributeRef {
                    attribute_type: StunAttributeType::DATA,
                    value: data,
                },
            ],
        );
        client
            .send_to(&encoded, relay)
            .await
            .expect("send Send indication");
    }

    fn encoded_xor_address(address: SocketAddr, transaction_id: StunTransactionId) -> Vec<u8> {
        let mut value = vec![0_u8; if address.is_ipv4() { 8 } else { 20 }];
        let length = encode_stun_xor_address(address, transaction_id, &mut value)
            .expect("encode XOR peer address");
        value.truncate(length);
        value
    }

    fn signed_request(
        method: StunMethod,
        transaction_id: StunTransactionId,
        username: &[u8],
        realm: &[u8],
        nonce: &[u8],
        password: &[u8],
        method_attributes: &[StunAttributeRef<'_>],
    ) -> Vec<u8> {
        let mut algorithm = [0_u8; 4];
        StunPasswordAlgorithm::Sha256
            .encode(&mut algorithm)
            .expect("encode password algorithm");
        let zero_integrity = [0_u8; 32];
        let mut attributes = vec![
            StunAttributeRef {
                attribute_type: StunAttributeType::USERNAME,
                value: username,
            },
            StunAttributeRef {
                attribute_type: StunAttributeType::REALM,
                value: realm,
            },
            StunAttributeRef {
                attribute_type: StunAttributeType::NONCE,
                value: nonce,
            },
            StunAttributeRef {
                attribute_type: StunAttributeType::PASSWORD_ALGORITHM,
                value: &algorithm,
            },
        ];
        attributes.extend_from_slice(method_attributes);
        attributes.push(StunAttributeRef {
            attribute_type: StunAttributeType::MESSAGE_INTEGRITY_SHA256,
            value: &zero_integrity,
        });
        let mut encoded = encode_message(method, transaction_id, &attributes);
        let message = StunMessageView::decode(&encoded).expect("decode unsigned request");
        let integrity = message
            .message_integrity_sha256()
            .expect("integrity boundary");
        let key = long_term_key(username, realm, password);
        let mut mac =
            <HmacSha256 as KeyInit>::new_from_slice(key.as_ref()).expect("fixed HMAC key");
        mac.update(integrity.message_type_bytes());
        mac.update(&integrity.adjusted_body_length().to_be_bytes());
        mac.update(integrity.bytes_after_length());
        let tag = mac.finalize().into_bytes();
        let offset = integrity.value_offset();
        encoded[offset..offset + tag.len()].copy_from_slice(&tag);
        encoded
    }

    async fn send_message(
        client: &UdpSocket,
        relay: SocketAddr,
        method: StunMethod,
        transaction_id: StunTransactionId,
        attributes: &[StunAttributeRef<'_>],
    ) {
        client
            .send_to(&encode_message(method, transaction_id, attributes), relay)
            .await
            .expect("send STUN request");
    }

    fn encode_message(
        method: StunMethod,
        transaction_id: StunTransactionId,
        attributes: &[StunAttributeRef<'_>],
    ) -> Vec<u8> {
        encode_message_with_class(method, StunClass::Request, transaction_id, attributes)
    }

    fn encode_message_with_class(
        method: StunMethod,
        class: StunClass,
        transaction_id: StunTransactionId,
        attributes: &[StunAttributeRef<'_>],
    ) -> Vec<u8> {
        let message = StunMessageRef {
            message_type: StunMessageType::new(method, class),
            transaction_id,
            attributes,
        };
        let mut encoded = vec![0_u8; message.encoded_len().expect("message length")];
        encode_stun_message(message, &mut encoded).expect("encode STUN message");
        encoded
    }

    async fn receive_owned_message(socket: &UdpSocket) -> Vec<u8> {
        let mut buffer = vec![0_u8; u16::MAX as usize];
        let length = timeout(Duration::from_secs(2), socket.recv(&mut buffer))
            .await
            .expect("receive timeout")
            .expect("receive response");
        buffer.truncate(length);
        buffer
    }

    async fn receive_message(socket: &UdpSocket) -> StunMessageView<'static> {
        let bytes = receive_owned_message(socket).await.into_boxed_slice();
        let leaked = Box::leak(bytes);
        StunMessageView::decode(leaked).expect("decode STUN response")
    }

    fn required_attribute<'a>(
        message: &StunMessageView<'a>,
        attribute_type: StunAttributeType,
    ) -> &'a [u8] {
        message
            .attributes()
            .map(|attribute| attribute.expect("valid attribute"))
            .find(|attribute| attribute.attribute_type() == attribute_type)
            .expect("required attribute")
            .value()
    }

    fn assert_error(message: &StunMessageView<'_>, expected: u16) {
        assert_eq!(message.message_type().class, StunClass::ErrorResponse);
        assert_eq!(
            StunErrorCodeView::decode(required_attribute(message, StunAttributeType::ERROR_CODE))
                .expect("decode error")
                .code(),
            expected
        );
    }

    fn long_term_key(username: &[u8], realm: &[u8], password: &[u8]) -> Zeroizing<[u8; 32]> {
        let mut digest = Sha256::new();
        digest.update(username);
        digest.update(b":");
        digest.update(realm);
        digest.update(b":");
        digest.update(password);
        Zeroizing::new(digest.finalize().into())
    }

    fn websocket_authorization(username: &[u8], secret: &[u8]) -> String {
        format!(
            "Stella {}.{}",
            URL_SAFE_NO_PAD.encode(username),
            URL_SAFE_NO_PAD.encode(secret)
        )
    }

    fn websocket_request(
        path: &str,
        authorization: &str,
        subprotocol: &str,
        extension: Option<&str>,
    ) -> WebSocketRequest {
        let mut request = WebSocketRequest::builder()
            .uri(path)
            .header(SEC_WEBSOCKET_PROTOCOL, subprotocol)
            .header(AUTHORIZATION, authorization);
        if let Some(extension) = extension {
            request = request.header(SEC_WEBSOCKET_EXTENSIONS, extension);
        }
        request.body(()).expect("WebSocket request")
    }

    fn websocket_response() -> WebSocketResponse {
        WebSocketResponse::builder()
            .status(StatusCode::SWITCHING_PROTOCOLS)
            .body(())
            .expect("WebSocket response")
    }

    fn unix_time_for_test() -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("test clock")
            .as_secs()
    }
}
