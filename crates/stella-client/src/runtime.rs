//! Windows UDP and TAP execution runtime for active network data planes.

use std::{
    collections::BTreeMap,
    sync::{
        atomic::{AtomicBool, Ordering},
        mpsc::{sync_channel, Receiver as SyncReceiver, SyncSender, TryRecvError, TrySendError},
        Arc,
    },
    thread::{self, JoinHandle},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use stella_common::{MacAddress, NetworkId};
use stella_crypto::IdentitySigningKey;
use stella_proto::CommonHeader;
use stella_tap::{TapCancellationHandle, TapConfig, TapDevice, TapError, WindowsTapDevice};
use stella_transport::{
    DatagramTransport, Endpoint as TransportEndpoint, TransportError, UdpConfig, UdpTransport,
    DEFAULT_UDP_DATAGRAM_SIZE, MAX_UDP_DATAGRAM_SIZE,
};
use thiserror::Error;
use tokio::sync::mpsc;

use crate::{ClientConfig, NetworkDataError, NetworkDataPlane, NetworkOutput, NetworkState};

const TAP_WRITE_QUEUE_CAPACITY: usize = 64;
const TAP_EVENT_QUEUE_CAPACITY: usize = 256;
const ETHERNET_HEADER_LENGTH: u16 = 14;

/// Failure while owning the Windows client data-plane runtime.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum RuntimeError {
    /// The configured network has no matching TAP selector.
    #[error("network {network_id} has no durable TAP configuration")]
    MissingTapConfiguration {
        /// Active network missing local configuration.
        network_id: NetworkId,
    },
    /// The bounded TAP write queue cannot accept another frame.
    #[error("TAP write queue is full for network {network_id}")]
    TapWriteQueueFull {
        /// Congested virtual network.
        network_id: NetworkId,
    },
    /// The TAP worker has already stopped.
    #[error("TAP worker stopped for network {network_id}")]
    TapWorkerStopped {
        /// Stopped virtual network.
        network_id: NetworkId,
    },
    /// A TAP worker thread panicked while shutting down.
    #[error("TAP worker panicked for network {network_id}")]
    TapWorkerPanicked {
        /// Affected virtual network.
        network_id: NetworkId,
    },
    /// A TAP worker returned a redacted device error.
    #[error("TAP worker failed for network {network_id}: {message}")]
    TapWorkerFailed {
        /// Affected virtual network.
        network_id: NetworkId,
        /// Non-frame-bearing device diagnostic.
        message: String,
    },
    /// Every TAP event sender closed unexpectedly.
    #[error("all TAP workers stopped")]
    TapEventChannelClosed,
    /// System wall time cannot be represented as Unix seconds.
    #[error("system time is before the Unix epoch")]
    SystemTimeBeforeUnixEpoch,
    /// TAP device creation, I/O, cancellation, or cleanup failed.
    #[error(transparent)]
    Tap(#[from] TapError),
    /// UDP bind, send, receive, or shutdown failed.
    #[error(transparent)]
    Transport(#[from] TransportError),
    /// Per-network authenticated routing failed.
    #[error(transparent)]
    Network(#[from] NetworkDataError),
    /// A Stella datagram header was structurally malformed.
    #[error(transparent)]
    Codec(#[from] stella_proto::CodecError),
}

/// A complete Windows client data plane sharing one bounded UDP socket.
pub struct ClientDataRuntime {
    udp: UdpTransport,
    udp_buffer: Vec<u8>,
    networks: BTreeMap<NetworkId, ActiveNetwork>,
    tap_events: mpsc::Receiver<TapEvent>,
    tap_event_sender: mpsc::Sender<TapEvent>,
    started_at: std::time::Instant,
}

impl ClientDataRuntime {
    /// Binds UDP, opens one exact TAP adapter per active network, and starts handshakes.
    ///
    /// # Errors
    ///
    /// Returns [`RuntimeError`] for invalid local configuration, UDP bind,
    /// TAP setup, network construction, or initial handshake transmission failure.
    pub async fn start(
        config: &ClientConfig,
        states: &BTreeMap<NetworkId, NetworkState>,
        signing_key: &IdentitySigningKey,
    ) -> Result<Self, RuntimeError> {
        let max_datagram_size = configured_datagram_size(config);
        let udp = UdpTransport::bind(UdpConfig {
            bind_address: config.udp_bind,
            max_datagram_size,
        })
        .await?;
        let (tap_event_sender, tap_events) = mpsc::channel(TAP_EVENT_QUEUE_CAPACITY);
        let started_at = std::time::Instant::now();
        let mut runtime = Self {
            udp,
            udp_buffer: vec![0_u8; max_datagram_size],
            networks: BTreeMap::new(),
            tap_events,
            tap_event_sender,
            started_at,
        };
        for state in states.values().cloned() {
            runtime.insert_network(config, state, signing_key)?;
        }
        let wall_time = unix_time()?;
        let monotonic_now = runtime.monotonic_now();
        let network_ids: Vec<NetworkId> = runtime.networks.keys().copied().collect();
        for network_id in network_ids {
            let output = runtime
                .networks
                .get_mut(&network_id)
                .ok_or(RuntimeError::TapWorkerStopped { network_id })?
                .plane
                .start_handshakes(signing_key, wall_time, monotonic_now)?;
            runtime.apply_output(network_id, output).await?;
        }
        Ok(runtime)
    }

    /// Receives and processes one complete UDP datagram.
    ///
    /// # Errors
    ///
    /// Returns [`RuntimeError`] for UDP receive, malformed network dispatch,
    /// authenticated routing, response send, or TAP delivery failure.
    pub async fn receive_udp(
        &mut self,
        signing_key: &IdentitySigningKey,
    ) -> Result<(), RuntimeError> {
        let received = self.udp.receive(&mut self.udp_buffer).await?;
        let datagram = self
            .udp_buffer
            .get(..received.length)
            .ok_or(TransportError::ReceiveTruncated {
                source: std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    "validated UDP length exceeds receive buffer",
                ),
            })?
            .to_vec();
        let common = CommonHeader::decode(&datagram)?;
        let network_id = common.network_id;
        let source = received
            .source
            .as_udp()
            .ok_or(TransportError::UnsupportedEndpoint)?;
        let wall_time = unix_time()?;
        let monotonic_now = self.monotonic_now();
        let output = self
            .networks
            .get_mut(&network_id)
            .ok_or(NetworkDataError::WrongNetwork)?
            .plane
            .accept_udp_datagram(source, &datagram, signing_key, wall_time, monotonic_now)?;
        self.apply_output(network_id, output).await
    }

    /// Waits for and processes whichever UDP datagram or TAP event arrives first.
    ///
    /// This provides one cancellation-safe I/O future for the top-level control loop.
    ///
    /// # Errors
    ///
    /// Returns [`RuntimeError`] for receive, authentication, routing,
    /// transmission, TAP delivery, or worker failure.
    pub async fn receive_next(
        &mut self,
        signing_key: &IdentitySigningKey,
    ) -> Result<(), RuntimeError> {
        enum Ready {
            Udp(stella_transport::ReceivedDatagram),
            Tap(TapEvent),
        }
        let ready = tokio::select! {
            received = self.udp.receive(&mut self.udp_buffer) => Ready::Udp(received?),
            event = self.tap_events.recv() => {
                Ready::Tap(event.ok_or(RuntimeError::TapEventChannelClosed)?)
            }
        };
        match ready {
            Ready::Udp(received) => self.process_udp(received, signing_key).await,
            Ready::Tap(event) => self.process_tap_event(event).await,
        }
    }

    /// Receives and processes one complete frame or fatal event from any TAP worker.
    ///
    /// # Errors
    ///
    /// Returns [`RuntimeError`] for stopped TAP workers, frame routing, or UDP send failure.
    pub async fn receive_tap(&mut self) -> Result<(), RuntimeError> {
        let event = self
            .tap_events
            .recv()
            .await
            .ok_or(RuntimeError::TapEventChannelClosed)?;
        self.process_tap_event(event).await
    }

    async fn process_tap_event(&mut self, event: TapEvent) -> Result<(), RuntimeError> {
        match event {
            TapEvent::Frame { network_id, frame } => {
                let now = self.monotonic_now();
                let output = self
                    .networks
                    .get_mut(&network_id)
                    .ok_or(RuntimeError::TapWorkerStopped { network_id })?
                    .plane
                    .accept_tap_frame(&frame, now)?;
                self.apply_output(network_id, output).await
            }
            TapEvent::Failed {
                network_id,
                message,
            } => Err(RuntimeError::TapWorkerFailed {
                network_id,
                message,
            }),
            TapEvent::Stopped { network_id } => Err(RuntimeError::TapWorkerStopped { network_id }),
        }
    }

    async fn process_udp(
        &mut self,
        received: stella_transport::ReceivedDatagram,
        signing_key: &IdentitySigningKey,
    ) -> Result<(), RuntimeError> {
        let datagram = self
            .udp_buffer
            .get(..received.length)
            .ok_or(TransportError::ReceiveTruncated {
                source: std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    "validated UDP length exceeds receive buffer",
                ),
            })?
            .to_vec();
        let common = CommonHeader::decode(&datagram)?;
        let network_id = common.network_id;
        let source = received
            .source
            .as_udp()
            .ok_or(TransportError::UnsupportedEndpoint)?;
        let wall_time = unix_time()?;
        let monotonic_now = self.monotonic_now();
        let output = self
            .networks
            .get_mut(&network_id)
            .ok_or(NetworkDataError::WrongNetwork)?
            .plane
            .accept_udp_datagram(source, &datagram, signing_key, wall_time, monotonic_now)?;
        self.apply_output(network_id, output).await
    }

    /// Runs due handshake retransmissions, expiry, and routine rekey checks.
    ///
    /// # Errors
    ///
    /// Returns [`RuntimeError`] for clock, handshake, endpoint, UDP, or TAP failure.
    pub async fn maintain(&mut self, signing_key: &IdentitySigningKey) -> Result<(), RuntimeError> {
        let wall_time = unix_time()?;
        let now = self.monotonic_now();
        let network_ids: Vec<NetworkId> = self.networks.keys().copied().collect();
        for network_id in network_ids {
            let output = self
                .networks
                .get_mut(&network_id)
                .ok_or(RuntimeError::TapWorkerStopped { network_id })?
                .plane
                .maintain(signing_key, wall_time, now)?;
            self.apply_output(network_id, output).await?;
        }
        Ok(())
    }

    /// Reconciles all active control snapshots and tears down removed networks first.
    ///
    /// # Errors
    ///
    /// Returns [`RuntimeError`] for TAP shutdown/recreation or data-plane reconciliation failure.
    pub async fn reconcile(
        &mut self,
        config: &ClientConfig,
        states: &BTreeMap<NetworkId, NetworkState>,
        signing_key: &IdentitySigningKey,
    ) -> Result<(), RuntimeError> {
        let removed: Vec<NetworkId> = self
            .networks
            .keys()
            .filter(|network_id| !states.contains_key(network_id))
            .copied()
            .collect();
        for network_id in removed {
            if let Some(network) = self.networks.remove(&network_id) {
                network.tap.shutdown().await?;
            }
        }
        for (network_id, state) in states {
            if !self.networks.contains_key(network_id) {
                self.insert_network(config, state.clone(), signing_key)?;
                continue;
            }
            let recreate = self.networks.get(network_id).is_some_and(|active| {
                active.state.policy().max_frame_size != state.policy().max_frame_size
            });
            if recreate {
                if let Some(network) = self.networks.remove(network_id) {
                    network.tap.shutdown().await?;
                }
                self.insert_network(config, state.clone(), signing_key)?;
                continue;
            }
            let active =
                self.networks
                    .get_mut(network_id)
                    .ok_or(RuntimeError::TapWorkerStopped {
                        network_id: *network_id,
                    })?;
            if active.state != *state {
                active.plane.reconcile(
                    state.clone(),
                    signing_key,
                    active.primary_mac,
                    self.started_at.elapsed(),
                )?;
                active.state = state.clone();
            }
        }
        Ok(())
    }

    /// Stops UDP and every TAP worker, waiting for device cleanup.
    ///
    /// # Errors
    ///
    /// Returns the first transport or TAP shutdown failure after attempting all cleanup.
    pub async fn shutdown(mut self) -> Result<(), RuntimeError> {
        let mut first_error = self.udp.shutdown().await.err().map(RuntimeError::Transport);
        let networks = std::mem::take(&mut self.networks);
        for network in networks.into_values() {
            if let Err(error) = network.tap.shutdown().await {
                if first_error.is_none() {
                    first_error = Some(error);
                }
            }
        }
        match first_error {
            Some(error) => Err(error),
            None => Ok(()),
        }
    }

    /// Returns the actual numeric UDP address owned by this runtime.
    #[must_use]
    pub const fn local_udp_address(&self) -> std::net::SocketAddr {
        self.udp.local_address()
    }

    fn insert_network(
        &mut self,
        config: &ClientConfig,
        state: NetworkState,
        signing_key: &IdentitySigningKey,
    ) -> Result<(), RuntimeError> {
        let network_id = state.network_id();
        let configured = config
            .networks
            .iter()
            .find(|network| network.network_id == network_id)
            .ok_or(RuntimeError::MissingTapConfiguration { network_id })?;
        let mtu = state
            .policy()
            .max_frame_size
            .checked_sub(ETHERNET_HEADER_LENGTH)
            .ok_or(TapError::InvalidConfig {
                field: "mtu",
                reason: "maximum frame size is below Ethernet header length",
            })?;
        let tap_config = TapConfig {
            name: Some(configured.tap_adapter.clone()),
            mtu,
            max_frame_size: state.policy().max_frame_size,
        };
        let tap = TapWorker::spawn(network_id, &tap_config, self.tap_event_sender.clone())?;
        let primary_mac = tap.primary_mac();
        let plane = NetworkDataPlane::new(
            state.clone(),
            primary_mac,
            self.udp.local_address(),
            self.udp.capabilities().max_datagram_size,
            signing_key,
            self.monotonic_now(),
        )?;
        self.networks.insert(
            network_id,
            ActiveNetwork {
                state,
                primary_mac,
                plane,
                tap,
            },
        );
        Ok(())
    }

    async fn apply_output(
        &mut self,
        network_id: NetworkId,
        output: NetworkOutput,
    ) -> Result<(), RuntimeError> {
        let (datagrams, tap_frame) = output.into_parts();
        for datagram in datagrams {
            self.udp
                .send_to(
                    &TransportEndpoint::Udp(datagram.endpoint()),
                    datagram.bytes(),
                )
                .await?;
        }
        if let Some(frame) = tap_frame {
            self.networks
                .get(&network_id)
                .ok_or(RuntimeError::TapWorkerStopped { network_id })?
                .tap
                .write(frame)?;
        }
        Ok(())
    }

    fn monotonic_now(&self) -> Duration {
        self.started_at.elapsed()
    }
}

impl std::fmt::Debug for ClientDataRuntime {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ClientDataRuntime")
            .field("local_udp_address", &self.udp.local_address())
            .field("networks", &self.networks.len())
            .finish_non_exhaustive()
    }
}

struct ActiveNetwork {
    state: NetworkState,
    primary_mac: MacAddress,
    plane: NetworkDataPlane,
    tap: TapWorker,
}

struct TapWorker {
    network_id: NetworkId,
    primary_mac: MacAddress,
    writes: SyncSender<Vec<u8>>,
    cancellation: TapCancellationHandle,
    reading: Arc<AtomicBool>,
    shutdown: Arc<AtomicBool>,
    thread: Option<JoinHandle<Result<(), TapError>>>,
}

impl TapWorker {
    fn spawn(
        network_id: NetworkId,
        config: &TapConfig,
        events: mpsc::Sender<TapEvent>,
    ) -> Result<Self, RuntimeError> {
        let mut device = WindowsTapDevice::create(config)?;
        let primary_mac = MacAddress::from_bytes(device.mac_address()?);
        let cancellation = device.cancellation_handle();
        let (writes, write_receiver) = sync_channel(TAP_WRITE_QUEUE_CAPACITY);
        let reading = Arc::new(AtomicBool::new(false));
        let shutdown = Arc::new(AtomicBool::new(false));
        let worker_reading = Arc::clone(&reading);
        let worker_shutdown = Arc::clone(&shutdown);
        let maximum_frame_size = usize::from(config.max_frame_size);
        let thread = thread::Builder::new()
            .name(format!("stella-tap-{network_id}"))
            .spawn(move || {
                let result = run_tap_worker(
                    network_id,
                    &mut device,
                    &write_receiver,
                    &events,
                    &worker_reading,
                    &worker_shutdown,
                    maximum_frame_size,
                );
                let destroy_result = device.destroy();
                let final_result = result.and(destroy_result);
                if let Err(error) = &final_result {
                    let _ = events.try_send(TapEvent::Failed {
                        network_id,
                        message: error.to_string(),
                    });
                } else {
                    let _ = events.try_send(TapEvent::Stopped { network_id });
                }
                final_result
            })
            .map_err(|source| TapError::Io {
                operation: stella_tap::TapOperation::OpenDevice,
                source,
            })?;
        Ok(Self {
            network_id,
            primary_mac,
            writes,
            cancellation,
            reading,
            shutdown,
            thread: Some(thread),
        })
    }

    const fn primary_mac(&self) -> MacAddress {
        self.primary_mac
    }

    fn write(&self, frame: Vec<u8>) -> Result<(), RuntimeError> {
        match self.writes.try_send(frame) {
            Ok(()) => {}
            Err(TrySendError::Full(_)) => {
                return Err(RuntimeError::TapWriteQueueFull {
                    network_id: self.network_id,
                });
            }
            Err(TrySendError::Disconnected(_)) => {
                return Err(RuntimeError::TapWorkerStopped {
                    network_id: self.network_id,
                });
            }
        }
        while self.reading.load(Ordering::Acquire) && !self.shutdown.load(Ordering::Acquire) {
            self.cancellation.cancel_pending_io()?;
            thread::yield_now();
        }
        Ok(())
    }

    async fn shutdown(mut self) -> Result<(), RuntimeError> {
        self.shutdown.store(true, Ordering::Release);
        self.cancellation.cancel_pending_io()?;
        let network_id = self.network_id;
        let thread = self
            .thread
            .take()
            .ok_or(RuntimeError::TapWorkerStopped { network_id })?;
        tokio::task::spawn_blocking(move || thread.join())
            .await
            .map_err(|_| RuntimeError::TapWorkerPanicked { network_id })?
            .map_err(|_| RuntimeError::TapWorkerPanicked { network_id })??;
        Ok(())
    }
}

impl Drop for TapWorker {
    fn drop(&mut self) {
        self.shutdown.store(true, Ordering::Release);
        let _ = self.cancellation.cancel_pending_io();
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

fn run_tap_worker(
    network_id: NetworkId,
    device: &mut WindowsTapDevice,
    writes: &SyncReceiver<Vec<u8>>,
    events: &mpsc::Sender<TapEvent>,
    reading: &AtomicBool,
    shutdown: &AtomicBool,
    maximum_frame_size: usize,
) -> Result<(), TapError> {
    let mut buffer = vec![0_u8; maximum_frame_size];
    loop {
        if shutdown.load(Ordering::Acquire) {
            return Ok(());
        }
        loop {
            match writes.try_recv() {
                Ok(frame) => device.write_frame(&frame)?,
                Err(TryRecvError::Empty) => break,
                Err(TryRecvError::Disconnected) => return Ok(()),
            }
        }
        reading.store(true, Ordering::Release);
        match writes.try_recv() {
            Ok(frame) => {
                reading.store(false, Ordering::Release);
                device.write_frame(&frame)?;
                continue;
            }
            Err(TryRecvError::Disconnected) => {
                reading.store(false, Ordering::Release);
                return Ok(());
            }
            Err(TryRecvError::Empty) => {}
        }
        let result = device.read_frame(&mut buffer);
        reading.store(false, Ordering::Release);
        match result {
            Ok(length) => {
                let Some(frame) = buffer.get(..length) else {
                    return Err(TapError::ReceiveBufferTooSmall {
                        needed: length,
                        remaining: buffer.len(),
                    });
                };
                match events.try_send(TapEvent::Frame {
                    network_id,
                    frame: frame.to_vec(),
                }) {
                    Ok(()) | Err(mpsc::error::TrySendError::Full(_)) => {}
                    Err(mpsc::error::TrySendError::Closed(_)) => return Ok(()),
                }
            }
            Err(TapError::Cancelled) => {}
            Err(error) => return Err(error),
        }
    }
}

#[derive(Debug)]
enum TapEvent {
    Frame {
        network_id: NetworkId,
        frame: Vec<u8>,
    },
    Failed {
        network_id: NetworkId,
        message: String,
    },
    Stopped {
        network_id: NetworkId,
    },
}

fn configured_datagram_size(config: &ClientConfig) -> usize {
    config
        .advertised_endpoints
        .iter()
        .map(|endpoint| endpoint.max_datagram_size())
        .filter_map(|size| usize::try_from(size).ok())
        .max()
        .unwrap_or(DEFAULT_UDP_DATAGRAM_SIZE)
        .min(MAX_UDP_DATAGRAM_SIZE)
}

fn unix_time() -> Result<u64, RuntimeError> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .map_err(|_| RuntimeError::SystemTimeBeforeUnixEpoch)
}
