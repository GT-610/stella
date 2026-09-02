//! Windows direct, relayed, and TAP execution runtime for active network data planes.

use std::{
    collections::{BTreeMap, BTreeSet, VecDeque},
    future::{pending, Future},
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    sync::{
        atomic::{AtomicBool, Ordering},
        mpsc::{sync_channel, Receiver as SyncReceiver, SyncSender, TryRecvError, TrySendError},
        Arc,
    },
    thread::{self, JoinHandle},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use base64::{engine::general_purpose::STANDARD_NO_PAD, Engine as _};
use stella_common::{MacAddress, NetworkId};
use stella_crypto::IdentitySigningKey;
use stella_proto::{
    CommonHeader, ConnectivityCarrier, ConnectivityGenerationRef, IceCandidate, IceCandidateClass,
    RelayCarrierMask, RelayTrustRequirements, MAX_RELAY_ADDRESSES,
};
use stella_tap::{TapCancellationHandle, TapConfig, TapDevice, TapError, WindowsTapDevice};
use stella_transport::{
    DatagramTransport, Endpoint as TransportEndpoint, ReceivedDatagram, TransportError, UdpConfig,
    UdpTransport, DEFAULT_UDP_DATAGRAM_SIZE, MAX_UDP_DATAGRAM_SIZE,
};
use thiserror::Error;
use tokio::{
    net::lookup_host,
    sync::mpsc,
    time::{timeout, timeout_at, Instant},
};
use zeroize::Zeroizing;

use crate::{
    ice::looks_like_stun,
    stun::{
        discover_server_reflexive, gather_host_candidates, server_reflexive_candidate,
        DeferredUdpDatagram, StunDiscovery,
    },
    ClientConfig, ConnectivityConfigState, IceAgent, IceError, IceOutput, IcePeerConfig,
    NetworkDataError, NetworkDataPlane, NetworkOutput, NetworkState, StunDiscoveryError,
    TurnCredentials, TurnTcpClient, TurnTcpClientConfig, TurnTlsClient, TurnTlsClientConfig,
    TurnUdpClient, TurnUdpClientConfig, TurnUdpError, TurnWebSocketClient,
    TurnWebSocketClientConfig,
};

const TAP_WRITE_QUEUE_CAPACITY: usize = 64;
const TAP_EVENT_QUEUE_CAPACITY: usize = 256;
const ETHERNET_HEADER_LENGTH: u16 = 14;
const TURN_UDP_MAX_DATAGRAM_SIZE: usize = 65_503;
const ICE_GENERATION_MAX_LIFETIME: u64 = 600;
const ICE_GENERATION_REFRESH_LEAD: u64 = 120;
const ICE_USERNAME_RANDOM_LENGTH: usize = 6;
const ICE_PASSWORD_RANDOM_LENGTH: usize = 18;
const RELAY_CANDIDATE_PRIORITY: u32 = 1_000_000;
const RELAY_DNS_TIMEOUT: Duration = Duration::from_secs(5);
const RELAY_CARRIER_ESTABLISHMENT_TIMEOUT: Duration = Duration::from_secs(10);

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
    /// Operating-system randomness was unavailable for a local ICE generation.
    #[error("operating-system randomness is unavailable for connectivity generation")]
    RandomnessUnavailable,
    /// Connectivity generation expiry arithmetic overflowed.
    #[error("connectivity generation expiry overflowed")]
    ConnectivityExpiryOverflow,
    /// TAP device creation, I/O, cancellation, or cleanup failed.
    #[error(transparent)]
    Tap(#[from] TapError),
    /// UDP bind, send, receive, or shutdown failed.
    #[error(transparent)]
    Transport(#[from] TransportError),
    /// TURN allocation, authentication, refresh, or relay delivery failed.
    #[error(transparent)]
    Turn(#[from] TurnUdpError),
    /// Host-interface enumeration or same-socket STUN discovery failed.
    #[error(transparent)]
    Stun(#[from] StunDiscoveryError),
    /// A DNS-only relay hostname could not be resolved and had no numeric fallback.
    #[error("could not resolve relay hostname {hostname}")]
    RelayDnsResolution {
        /// Canonical controller-provided relay hostname.
        hostname: String,
        /// Operating-system resolver failure.
        #[source]
        source: std::io::Error,
    },
    /// A DNS-only relay hostname exceeded the bounded resolver deadline.
    #[error("relay hostname resolution timed out for {hostname}")]
    RelayDnsTimeout {
        /// Canonical controller-provided relay hostname.
        hostname: String,
    },
    /// A DNS-only relay hostname resolved without any usable address.
    #[error("relay hostname {hostname} resolved without a usable address")]
    RelayDnsEmpty {
        /// Canonical controller-provided relay hostname.
        hostname: String,
    },
    /// One relay carrier exhausted its complete establishment budget.
    #[error("relay {relay_id} {carrier:?} establishment timed out")]
    RelayCarrierTimeout {
        /// Controller-issued relay service identity.
        relay_id: stella_common::RelayId,
        /// Carrier whose shared establishment budget expired.
        carrier: ConnectivityCarrier,
    },
    /// Per-network authenticated routing failed.
    #[error(transparent)]
    Network(#[from] NetworkDataError),
    /// Per-network ICE configuration, checking, or nomination failed.
    #[error(transparent)]
    Ice(#[from] IceError),
    /// A Stella datagram header was structurally malformed.
    #[error(transparent)]
    Codec(#[from] stella_proto::CodecError),
    /// The network selected a transport endpoint this runtime does not implement.
    #[error("unsupported data-plane transport endpoint {endpoint}")]
    UnsupportedTransportEndpoint {
        /// Endpoint variant not implemented by this runtime version.
        endpoint: TransportEndpoint,
    },
}

/// A complete Windows client data plane sharing one bounded UDP socket.
pub struct ClientDataRuntime {
    udp: UdpTransport,
    udp_buffer: Vec<u8>,
    deferred_udp: VecDeque<DeferredUdpDatagram>,
    direct_candidates: Vec<IceCandidate>,
    https_proxy: Option<SocketAddr>,
    connectivity_revision: Option<u64>,
    relay: Option<WarmRelay>,
    relay_buffer: Vec<u8>,
    connectivity_generations: BTreeMap<NetworkId, LocalConnectivityGeneration>,
    ice_agents: BTreeMap<NetworkId, RuntimeIceAgent>,
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
        Self::start_with_connectivity(config, states, signing_key, None).await
    }

    /// Binds UDP and a preferred warm relay, opens TAP adapters, and starts handshakes.
    ///
    /// # Errors
    ///
    /// Returns [`RuntimeError`] for invalid local configuration, UDP or TURN
    /// allocation, TAP setup, network construction, or initial handshake
    /// transmission failure.
    pub async fn start_with_connectivity(
        config: &ClientConfig,
        states: &BTreeMap<NetworkId, NetworkState>,
        signing_key: &IdentitySigningKey,
        connectivity: Option<&ConnectivityConfigState>,
    ) -> Result<Self, RuntimeError> {
        let max_datagram_size = configured_datagram_size(config);
        let udp = UdpTransport::bind(UdpConfig {
            bind_address: config.udp_bind,
            max_datagram_size,
        })
        .await?;
        let excluded_interfaces = config
            .networks
            .iter()
            .map(|network| network.tap_adapter.clone())
            .collect::<BTreeSet<_>>();
        let candidate_datagram_size = u32::try_from(max_datagram_size).unwrap_or(65_507);
        let host_candidates = match gather_host_candidates(
            udp.local_address(),
            &excluded_interfaces,
            candidate_datagram_size,
        ) {
            Ok(candidates) => candidates,
            Err(error) => {
                tracing::warn!(%error, "could not enumerate host ICE candidates");
                Vec::new()
            }
        };
        let stun_servers = connectivity.map_or(&[][..], ConnectivityConfigState::stun_servers);
        let (discovery, relay) = tokio::join!(
            discover_server_reflexive(&udp, stun_servers),
            allocate_preferred_relay(config.udp_bind, config.https_proxy, connectivity,),
        );
        let discovery = match discovery {
            Ok(discovery) => discovery,
            Err(error) => {
                tracing::warn!(%error, "same-socket STUN discovery failed");
                StunDiscovery {
                    mapped_address: None,
                    base_address: None,
                    deferred: Vec::new(),
                }
            }
        };
        let relay = relay?;
        let mut direct_candidates = host_candidates;
        if let Some(candidate) = server_reflexive_candidate(&discovery, candidate_datagram_size) {
            direct_candidates.push(candidate);
        }
        direct_candidates.sort_by_key(|candidate| std::cmp::Reverse(candidate.priority));
        let relay_buffer_size = relay.as_ref().map_or(DEFAULT_UDP_DATAGRAM_SIZE, |relay| {
            relay.client.capabilities().max_datagram_size
        });
        let (tap_event_sender, tap_events) = mpsc::channel(TAP_EVENT_QUEUE_CAPACITY);
        let started_at = std::time::Instant::now();
        let mut runtime = Self {
            udp,
            udp_buffer: vec![0_u8; max_datagram_size],
            deferred_udp: discovery.deferred.into(),
            direct_candidates,
            https_proxy: config.https_proxy,
            connectivity_revision: connectivity.map(ConnectivityConfigState::revision),
            relay,
            relay_buffer: vec![0_u8; relay_buffer_size],
            connectivity_generations: BTreeMap::new(),
            ice_agents: BTreeMap::new(),
            networks: BTreeMap::new(),
            tap_events,
            tap_event_sender,
            started_at,
        };
        for state in states.values().cloned() {
            runtime.insert_network(config, state, signing_key)?;
        }
        runtime.replace_local_connectivity_generations(states)?;
        runtime.prepare_relay_paths().await?;
        let wall_time = unix_time()?;
        runtime.reconcile_ice_agents(states, wall_time)?;
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
        self.process_udp(received, signing_key).await
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
            Relay(ReceivedDatagram),
            Tap(TapEvent),
        }
        if let Some(deferred) = self.deferred_udp.pop_front() {
            return self
                .process_udp_bytes(deferred.source, &deferred.bytes, signing_key)
                .await;
        }
        let ready = tokio::select! {
            received = self.udp.receive(&mut self.udp_buffer) => Ready::Udp(received?),
            received = receive_relay(self.relay.as_ref(), &mut self.relay_buffer) => {
                Ready::Relay(received?)
            }
            event = self.tap_events.recv() => {
                Ready::Tap(event.ok_or(RuntimeError::TapEventChannelClosed)?)
            }
        };
        match ready {
            Ready::Udp(received) => self.process_udp(received, signing_key).await,
            Ready::Relay(received) => self.process_relay(received, signing_key).await,
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
        self.process_udp_bytes(received.source, &datagram, signing_key)
            .await
    }

    async fn process_udp_bytes(
        &mut self,
        source: TransportEndpoint,
        datagram: &[u8],
        signing_key: &IdentitySigningKey,
    ) -> Result<(), RuntimeError> {
        if let TransportEndpoint::Udp(address) = &source {
            if looks_like_stun(datagram) {
                self.process_ice_udp(*address, datagram, signing_key)
                    .await?;
                return Ok(());
            }
        }
        let common = CommonHeader::decode(datagram)?;
        let network_id = common.network_id;
        let wall_time = unix_time()?;
        let monotonic_now = self.monotonic_now();
        let output = self
            .networks
            .get_mut(&network_id)
            .ok_or(NetworkDataError::WrongNetwork)?
            .plane
            .accept_datagram(&source, datagram, signing_key, wall_time, monotonic_now)?;
        self.apply_output(network_id, output).await
    }

    async fn process_ice_udp(
        &mut self,
        source: SocketAddr,
        datagram: &[u8],
        signing_key: &IdentitySigningKey,
    ) -> Result<(), RuntimeError> {
        let now = self.monotonic_now();
        let network_ids = self.ice_agents.keys().copied().collect::<Vec<_>>();
        for network_id in network_ids {
            let Some(runtime_agent) = self.ice_agents.get_mut(&network_id) else {
                continue;
            };
            let accepted = runtime_agent.agent.accept(source, datagram, now);
            match accepted {
                Ok(Some(output)) => {
                    self.apply_ice_output(network_id, output, signing_key)
                        .await?;
                    return Ok(());
                }
                Ok(None) => {}
                Err(error) => {
                    tracing::debug!(%source, %error, "dropping invalid ICE STUN datagram");
                    return Ok(());
                }
            }
        }
        tracing::trace!(%source, "dropping unassociated STUN datagram");
        Ok(())
    }

    async fn process_relay(
        &mut self,
        received: ReceivedDatagram,
        signing_key: &IdentitySigningKey,
    ) -> Result<(), RuntimeError> {
        let datagram = self
            .relay_buffer
            .get(..received.length)
            .ok_or(TransportError::ReceiveTruncated {
                source: std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    "validated TURN length exceeds receive buffer",
                ),
            })?
            .to_vec();
        let common = CommonHeader::decode(&datagram)?;
        let network_id = common.network_id;
        let wall_time = unix_time()?;
        let monotonic_now = self.monotonic_now();
        let output = self
            .networks
            .get_mut(&network_id)
            .ok_or(NetworkDataError::WrongNetwork)?
            .plane
            .accept_datagram(
                &received.source,
                &datagram,
                signing_key,
                wall_time,
                monotonic_now,
            )?;
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
        let ice_network_ids = self.ice_agents.keys().copied().collect::<Vec<_>>();
        for network_id in ice_network_ids {
            let Some(runtime_agent) = self.ice_agents.get_mut(&network_id) else {
                continue;
            };
            let output = runtime_agent.agent.poll(now)?;
            self.apply_ice_output(network_id, output, signing_key)
                .await?;
        }
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
        self.reconcile_local_connectivity_generations(states)?;
        self.reconcile_ice_agents(states, unix_time()?)?;
        self.prepare_relay_paths().await?;
        Ok(())
    }

    /// Returns the current local automatic-connectivity generation for one network.
    ///
    /// # Errors
    ///
    /// Returns [`RuntimeError::Codec`] if the private generation invariant is violated.
    pub fn connectivity_generation(
        &self,
        network_id: NetworkId,
    ) -> Result<Option<ConnectivityGenerationRef<'_>>, RuntimeError> {
        self.connectivity_generations
            .get(&network_id)
            .map(LocalConnectivityGeneration::as_ref)
            .transpose()
            .map_err(RuntimeError::Codec)
    }

    /// Adds generations for new networks and rotates credentials before expiry.
    ///
    /// Returns `true` when the controller must receive a fresh publication.
    /// Relay-backed generations rotate only when the current relay credential
    /// can extend their expiry; a newer controller connectivity revision is
    /// otherwise required first.
    ///
    /// # Errors
    ///
    /// Returns [`RuntimeError`] for clock, randomness, credential, or generation
    /// validation failure.
    pub fn refresh_connectivity_generations(
        &mut self,
        states: &BTreeMap<NetworkId, NetworkState>,
    ) -> Result<bool, RuntimeError> {
        let before = self
            .connectivity_generations
            .iter()
            .map(|(network_id, generation)| (*network_id, generation.generation_id))
            .collect::<BTreeMap<_, _>>();
        self.reconcile_local_connectivity_generations(states)?;
        if self.connectivity_generations.is_empty() {
            return Ok(!before.is_empty());
        }
        let wall_time = unix_time()?;
        let refresh_deadline = wall_time.saturating_add(ICE_GENERATION_REFRESH_LEAD);
        let prospective_expiry =
            LocalConnectivityGeneration::expiry_at(wall_time, self.relay.as_ref())?;
        let due = self
            .connectivity_generations
            .iter()
            .filter_map(|(network_id, generation)| {
                (generation.expires_at <= refresh_deadline
                    && prospective_expiry > generation.expires_at)
                    .then_some(*network_id)
            })
            .collect::<Vec<_>>();
        for network_id in due {
            let replacement = LocalConnectivityGeneration::new_at(
                wall_time,
                self.relay.as_ref(),
                &self.direct_candidates,
            )?;
            self.connectivity_generations
                .insert(network_id, replacement);
        }
        let after = self
            .connectivity_generations
            .iter()
            .map(|(network_id, generation)| (*network_id, generation.generation_id))
            .collect::<BTreeMap<_, _>>();
        Ok(before != after)
    }

    /// Returns the deployment connectivity revision currently applied locally.
    #[must_use]
    pub const fn connectivity_revision(&self) -> Option<u64> {
        self.connectivity_revision
    }

    /// Applies a replacement controller relay configuration without dropping a healthy allocation.
    ///
    /// Matching service parameters update only short-lived credentials and
    /// refresh the allocation. Service removal or material endpoint changes
    /// create a replacement allocation before retiring the old one.
    ///
    /// # Errors
    ///
    /// Returns [`RuntimeError`] for allocation, credential, generation, path,
    /// or shutdown failure.
    pub async fn replace_connectivity_config(
        &mut self,
        connectivity: Option<&ConnectivityConfigState>,
        states: &BTreeMap<NetworkId, NetworkState>,
    ) -> Result<(), RuntimeError> {
        let revision = connectivity.map(ConnectivityConfigState::revision);
        if self.connectivity_revision == revision {
            return Ok(());
        }
        let selected =
            preferred_relay_settings(self.udp.local_address(), self.https_proxy, connectivity)
                .await?;
        match (self.relay.as_mut(), selected) {
            (Some(current), Some(selected)) if current.settings == selected.settings => {
                current
                    .client
                    .replace_credentials(selected.credentials)
                    .await?;
                current.credential_expires_at = selected.credential_expires_at;
            }
            (_, Some(selected)) => {
                let replacement = allocate_relay(selected).await?;
                let previous = self.relay.replace(replacement);
                if let Some(previous) = previous {
                    previous.client.shutdown().await?;
                }
            }
            (Some(_), None) => {
                if let Some(previous) = self.relay.take() {
                    previous.client.shutdown().await?;
                }
            }
            (None, None) => {}
        }
        for network in self.networks.values_mut() {
            for carrier in [
                ConnectivityCarrier::TurnUdp,
                ConnectivityCarrier::TurnTcp,
                ConnectivityCarrier::TurnTls,
                ConnectivityCarrier::SecureWebSocket,
            ] {
                let available = self
                    .relay
                    .as_ref()
                    .is_some_and(|relay| relay.settings.carrier.connectivity_carrier() == carrier);
                network
                    .plane
                    .set_relay_carrier_available(carrier, available)?;
            }
        }
        self.relay_buffer.resize(
            self.relay
                .as_ref()
                .map_or(DEFAULT_UDP_DATAGRAM_SIZE, |relay| {
                    relay.client.capabilities().max_datagram_size
                }),
            0,
        );
        self.replace_local_connectivity_generations(states)?;
        self.reconcile_ice_agents(states, unix_time()?)?;
        self.prepare_relay_paths().await?;
        self.connectivity_revision = revision;
        Ok(())
    }

    /// Stops UDP and every TAP worker, waiting for device cleanup.
    ///
    /// # Errors
    ///
    /// Returns the first transport or TAP shutdown failure after attempting all cleanup.
    pub async fn shutdown(mut self) -> Result<(), RuntimeError> {
        let mut first_error = if let Some(relay) = self.relay.take() {
            relay.client.shutdown().await.err().map(RuntimeError::Turn)
        } else {
            None
        };
        if let Err(error) = self.udp.shutdown().await {
            if first_error.is_none() {
                first_error = Some(RuntimeError::Transport(error));
            }
        }
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
        let installed_mtu = WindowsTapDevice::installed_adapters()?
            .into_iter()
            .find(|adapter| {
                adapter
                    .friendly_name
                    .eq_ignore_ascii_case(&configured.tap_adapter)
            })
            .ok_or_else(|| TapError::AdapterNotFound {
                selector: Some(configured.tap_adapter.clone()),
            })?
            .system_mtu;
        let mtu = effective_tap_mtu(mtu, installed_mtu)?;
        let tap_config = TapConfig {
            name: Some(configured.tap_adapter.clone()),
            mtu,
            max_frame_size: state.policy().max_frame_size,
        };
        let tap = TapWorker::spawn(network_id, &tap_config, self.tap_event_sender.clone())?;
        let primary_mac = tap.primary_mac();
        let mut plane = NetworkDataPlane::new(
            state.clone(),
            primary_mac,
            self.udp.local_address(),
            self.udp.capabilities().max_datagram_size,
            signing_key,
            self.monotonic_now(),
        )?;
        if let Some(relay) = &self.relay {
            plane
                .set_relay_carrier_available(relay.settings.carrier.connectivity_carrier(), true)?;
        }
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

    async fn apply_ice_output(
        &mut self,
        network_id: NetworkId,
        output: IceOutput,
        signing_key: &IdentitySigningKey,
    ) -> Result<(), RuntimeError> {
        let (transmissions, nominations, failures) = output.into_all_parts();
        for transmission in transmissions {
            self.udp
                .send_to(
                    &TransportEndpoint::Udp(transmission.target()),
                    transmission.bytes(),
                )
                .await?;
        }
        let mut path_changed = false;
        for nomination in nominations {
            self.networks
                .get_mut(&network_id)
                .ok_or(RuntimeError::TapWorkerStopped { network_id })?
                .plane
                .nominate_direct_path(nomination.peer_node_id, nomination.address)?;
            path_changed = true;
            tracing::info!(
                %network_id,
                peer_node_id = %nomination.peer_node_id,
                address = %nomination.address,
                "nominated direct UDP path"
            );
        }
        for failure in failures {
            let withdrawn = self
                .networks
                .get_mut(&network_id)
                .ok_or(RuntimeError::TapWorkerStopped { network_id })?
                .plane
                .withdraw_direct_path(failure.peer_node_id, failure.address);
            if withdrawn {
                path_changed = true;
                tracing::warn!(
                    %network_id,
                    peer_node_id = %failure.peer_node_id,
                    address = %failure.address,
                    "withdrew direct UDP path after ICE consent failure"
                );
            }
        }
        if !path_changed {
            return Ok(());
        }
        let wall_time = unix_time()?;
        let monotonic_now = self.monotonic_now();
        let handshakes = self
            .networks
            .get_mut(&network_id)
            .ok_or(RuntimeError::TapWorkerStopped { network_id })?
            .plane
            .start_handshakes(signing_key, wall_time, monotonic_now)?;
        self.apply_output(network_id, handshakes).await
    }

    async fn apply_output(
        &mut self,
        network_id: NetworkId,
        output: NetworkOutput,
    ) -> Result<(), RuntimeError> {
        let (datagrams, tap_frame) = output.into_parts();
        for datagram in datagrams {
            let endpoint = self
                .networks
                .get(&network_id)
                .ok_or(RuntimeError::TapWorkerStopped { network_id })?
                .plane
                .transport_endpoint(datagram.path_id())?
                .clone();
            match &endpoint {
                TransportEndpoint::Udp(_) => {
                    self.udp.send_to(&endpoint, datagram.bytes()).await?;
                }
                TransportEndpoint::TurnUdp { .. }
                | TransportEndpoint::TurnTcp { .. }
                | TransportEndpoint::TurnTls { .. } => {
                    self.relay
                        .as_ref()
                        .ok_or(TurnUdpError::ActorStopped)?
                        .client
                        .send_to(&endpoint, datagram.bytes())
                        .await?;
                }
                _ => {
                    return Err(RuntimeError::UnsupportedTransportEndpoint { endpoint });
                }
            }
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

    async fn prepare_relay_paths(&self) -> Result<(), RuntimeError> {
        let Some(relay) = &self.relay else {
            return Ok(());
        };
        let mut endpoints = self
            .networks
            .values()
            .flat_map(|network| network.plane.relay_endpoints())
            .collect::<Vec<_>>();
        endpoints.sort_by_key(ToString::to_string);
        endpoints.dedup();
        for endpoint in endpoints {
            relay.client.prepare_peer(&endpoint).await?;
        }
        Ok(())
    }

    fn replace_local_connectivity_generations(
        &mut self,
        states: &BTreeMap<NetworkId, NetworkState>,
    ) -> Result<(), RuntimeError> {
        self.connectivity_generations.clear();
        if self.relay.is_none() && self.direct_candidates.is_empty() {
            return Ok(());
        }
        for network_id in states.keys().copied() {
            self.connectivity_generations.insert(
                network_id,
                LocalConnectivityGeneration::new(self.relay.as_ref(), &self.direct_candidates)?,
            );
        }
        Ok(())
    }

    fn reconcile_local_connectivity_generations(
        &mut self,
        states: &BTreeMap<NetworkId, NetworkState>,
    ) -> Result<(), RuntimeError> {
        self.connectivity_generations
            .retain(|network_id, _| states.contains_key(network_id));
        if self.relay.is_none() && self.direct_candidates.is_empty() {
            self.connectivity_generations.clear();
            return Ok(());
        }
        for network_id in states.keys().copied() {
            if let std::collections::btree_map::Entry::Vacant(entry) =
                self.connectivity_generations.entry(network_id)
            {
                entry.insert(LocalConnectivityGeneration::new(
                    self.relay.as_ref(),
                    &self.direct_candidates,
                )?);
            }
        }
        Ok(())
    }

    fn reconcile_ice_agents(
        &mut self,
        states: &BTreeMap<NetworkId, NetworkState>,
        wall_time: u64,
    ) -> Result<(), RuntimeError> {
        let generations = &self.connectivity_generations;
        self.ice_agents.retain(|network_id, current| {
            states.contains_key(network_id)
                && generations.get(network_id).is_some_and(|generation| {
                    generation.generation_id == current.generation_id
                        && generation.expires_at > wall_time
                        && generation
                            .candidates
                            .iter()
                            .any(|candidate| candidate.carrier == ConnectivityCarrier::DirectUdp)
                })
        });
        for (network_id, state) in states {
            let Some(generation) = self.connectivity_generations.get(network_id) else {
                continue;
            };
            let direct_available = generation
                .candidates
                .iter()
                .any(|candidate| candidate.carrier == ConnectivityCarrier::DirectUdp);
            if generation.expires_at <= wall_time || !direct_available {
                self.ice_agents.remove(network_id);
                continue;
            }
            if !self.ice_agents.contains_key(network_id) {
                let agent = IceAgent::new(
                    state.local_grant().node_id,
                    generation.tie_breaker,
                    &generation.username_fragment,
                    &generation.password,
                    &generation.candidates,
                )?;
                self.ice_agents.insert(
                    *network_id,
                    RuntimeIceAgent {
                        generation_id: generation.generation_id,
                        agent,
                    },
                );
            }
            let Some(runtime_agent) = self.ice_agents.get_mut(network_id) else {
                continue;
            };
            let mut authorized = BTreeSet::new();
            for (peer_node_id, peer) in state.peers() {
                let Some(connectivity) = peer.connectivity() else {
                    continue;
                };
                if connectivity.expires_at() <= wall_time {
                    continue;
                }
                runtime_agent.agent.upsert_peer(IcePeerConfig {
                    node_id: *peer_node_id,
                    generation_id: connectivity.generation_id(),
                    tie_breaker: connectivity.tie_breaker(),
                    username_fragment: connectivity.username_fragment(),
                    password: connectivity.password(),
                    candidates: connectivity.candidates(),
                })?;
                authorized.insert(*peer_node_id);
            }
            runtime_agent.agent.retain_peers(&authorized);
        }
        Ok(())
    }
}

impl std::fmt::Debug for ClientDataRuntime {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ClientDataRuntime")
            .field("local_udp_address", &self.udp.local_address())
            .field(
                "relay_id",
                &self.relay.as_ref().map(|relay| relay.client.relay_id()),
            )
            .field("ice_agents", &self.ice_agents.len())
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

struct RuntimeIceAgent {
    generation_id: u64,
    agent: IceAgent,
}

struct WarmRelay {
    settings: RelaySettings,
    credential_expires_at: u64,
    client: WarmRelayClient,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct RelaySettings {
    carrier: RuntimeRelayCarrier,
    relay_id: stella_common::RelayId,
    server_address: SocketAddr,
    bind_address: SocketAddr,
    max_datagram_size: usize,
    allocation_lifetime_seconds: u32,
    idle_timeout_seconds: u32,
    tls_server_name: String,
    trust: RelayTrustRequirements,
    spki_pins: Vec<[u8; 32]>,
    proxy_address: Option<SocketAddr>,
    server_hostname: String,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum RuntimeRelayCarrier {
    Udp,
    Tcp,
    Tls,
    Websocket,
}

impl RuntimeRelayCarrier {
    const fn connectivity_carrier(self) -> ConnectivityCarrier {
        match self {
            Self::Udp => ConnectivityCarrier::TurnUdp,
            Self::Tcp => ConnectivityCarrier::TurnTcp,
            Self::Tls => ConnectivityCarrier::TurnTls,
            Self::Websocket => ConnectivityCarrier::SecureWebSocket,
        }
    }

    const fn mask(self) -> RelayCarrierMask {
        match self {
            Self::Udp => RelayCarrierMask::TURN_UDP,
            Self::Tcp => RelayCarrierMask::TURN_TCP,
            Self::Tls => RelayCarrierMask::TURN_TLS,
            Self::Websocket => RelayCarrierMask::SECURE_WEBSOCKET,
        }
    }

    const fn port(self, ports: stella_proto::RelayPorts) -> u16 {
        match self {
            Self::Udp => ports.turn_udp,
            Self::Tcp => ports.turn_tcp,
            Self::Tls => ports.turn_tls,
            Self::Websocket => ports.secure_websocket,
        }
    }

    const fn uses_tls(self) -> bool {
        matches!(self, Self::Tls | Self::Websocket)
    }
}

impl RelaySettings {
    const fn udp_client_config(&self) -> TurnUdpClientConfig {
        let mut config =
            TurnUdpClientConfig::new(self.relay_id, self.server_address, self.bind_address);
        config.max_datagram_size = self.max_datagram_size;
        config.allocation_lifetime_seconds = self.allocation_lifetime_seconds;
        config.idle_timeout_seconds = self.idle_timeout_seconds;
        config
    }

    const fn tcp_client_config(&self) -> TurnTcpClientConfig {
        let mut config =
            TurnTcpClientConfig::new(self.relay_id, self.server_address, self.bind_address);
        config.max_datagram_size = self.max_datagram_size;
        config.allocation_lifetime_seconds = self.allocation_lifetime_seconds;
        config.idle_timeout_seconds = self.idle_timeout_seconds;
        config
    }

    fn tls_client_config(&self) -> TurnTlsClientConfig {
        let mut config = TurnTlsClientConfig::new(
            self.relay_id,
            self.server_address,
            self.bind_address,
            self.tls_server_name.clone(),
            self.trust,
            self.spki_pins.clone(),
        );
        config.max_datagram_size = self.max_datagram_size;
        config.allocation_lifetime_seconds = self.allocation_lifetime_seconds;
        config.idle_timeout_seconds = self.idle_timeout_seconds;
        config
    }

    fn websocket_client_config(&self) -> TurnWebSocketClientConfig {
        let mut config = TurnWebSocketClientConfig::new(
            self.relay_id,
            self.server_address,
            self.bind_address,
            self.tls_server_name.clone(),
            self.trust,
            self.spki_pins.clone(),
        );
        config.max_datagram_size = self.max_datagram_size;
        config.allocation_lifetime_seconds = self.allocation_lifetime_seconds;
        config.idle_timeout_seconds = self.idle_timeout_seconds;
        config.proxy_address = self.proxy_address;
        config.server_hostname.clone_from(&self.server_hostname);
        config
    }
}

struct SelectedRelay {
    settings: RelaySettings,
    credentials: TurnCredentials,
    credential_expires_at: u64,
}

enum WarmRelayClient {
    Udp(TurnUdpClient),
    Tcp(TurnTcpClient),
    Tls(TurnTlsClient),
    Websocket(TurnWebSocketClient),
}

impl WarmRelayClient {
    const fn carrier(&self) -> ConnectivityCarrier {
        match self {
            Self::Udp(_) => ConnectivityCarrier::TurnUdp,
            Self::Tcp(_) => ConnectivityCarrier::TurnTcp,
            Self::Tls(_) => ConnectivityCarrier::TurnTls,
            Self::Websocket(_) => ConnectivityCarrier::SecureWebSocket,
        }
    }

    const fn relay_id(&self) -> stella_common::RelayId {
        match self {
            Self::Udp(client) => client.relay_id(),
            Self::Tcp(client) => client.relay_id(),
            Self::Tls(client) => client.relay_id(),
            Self::Websocket(client) => client.relay_id(),
        }
    }

    const fn relayed_address(&self) -> SocketAddr {
        match self {
            Self::Udp(client) => client.relayed_address(),
            Self::Tcp(client) => client.relayed_address(),
            Self::Tls(client) => client.relayed_address(),
            Self::Websocket(client) => client.relayed_address(),
        }
    }

    const fn mapped_address(&self) -> SocketAddr {
        match self {
            Self::Udp(client) => client.mapped_address(),
            Self::Tcp(client) => client.mapped_address(),
            Self::Tls(client) => client.mapped_address(),
            Self::Websocket(client) => client.mapped_address(),
        }
    }

    const fn capabilities(&self) -> stella_transport::TransportCapabilities {
        match self {
            Self::Udp(client) => client.capabilities(),
            Self::Tcp(client) => client.capabilities(),
            Self::Tls(client) => client.capabilities(),
            Self::Websocket(client) => client.capabilities(),
        }
    }

    async fn replace_credentials(&self, credentials: TurnCredentials) -> Result<(), TurnUdpError> {
        match self {
            Self::Udp(client) => client.replace_credentials(credentials).await,
            Self::Tcp(client) => client.replace_credentials(credentials).await,
            Self::Tls(client) => client.replace_credentials(credentials).await,
            Self::Websocket(client) => client.replace_credentials(credentials).await,
        }
    }

    async fn prepare_peer(&self, endpoint: &TransportEndpoint) -> Result<(), TurnUdpError> {
        match self {
            Self::Udp(client) => client.prepare_peer(endpoint).await,
            Self::Tcp(client) => client.prepare_peer(endpoint).await,
            Self::Tls(client) => client.prepare_peer(endpoint).await,
            Self::Websocket(client) => client.prepare_peer(endpoint).await,
        }
    }

    async fn send_to(
        &self,
        endpoint: &TransportEndpoint,
        datagram: &[u8],
    ) -> Result<(), TurnUdpError> {
        match self {
            Self::Udp(client) => client.send_to(endpoint, datagram).await,
            Self::Tcp(client) => client.send_to(endpoint, datagram).await,
            Self::Tls(client) => client.send_to(endpoint, datagram).await,
            Self::Websocket(client) => client.send_to(endpoint, datagram).await,
        }
    }

    async fn receive(&self, output: &mut [u8]) -> Result<ReceivedDatagram, TurnUdpError> {
        match self {
            Self::Udp(client) => client.receive(output).await,
            Self::Tcp(client) => client.receive(output).await,
            Self::Tls(client) => client.receive(output).await,
            Self::Websocket(client) => client.receive(output).await,
        }
    }

    async fn shutdown(&self) -> Result<(), TurnUdpError> {
        match self {
            Self::Udp(client) => client.shutdown().await,
            Self::Tcp(client) => client.shutdown().await,
            Self::Tls(client) => client.shutdown().await,
            Self::Websocket(client) => client.shutdown().await,
        }
    }
}

struct LocalConnectivityGeneration {
    generation_id: u64,
    tie_breaker: u64,
    created_at: u64,
    expires_at: u64,
    username_fragment: Zeroizing<Vec<u8>>,
    password: Zeroizing<Vec<u8>>,
    candidates: Vec<IceCandidate>,
}

impl LocalConnectivityGeneration {
    fn new(
        relay: Option<&WarmRelay>,
        direct_candidates: &[IceCandidate],
    ) -> Result<Self, RuntimeError> {
        let created_at = unix_time()?;
        Self::new_at(created_at, relay, direct_candidates)
    }

    fn new_at(
        created_at: u64,
        relay: Option<&WarmRelay>,
        direct_candidates: &[IceCandidate],
    ) -> Result<Self, RuntimeError> {
        let expires_at = Self::expiry_at(created_at, relay)?;
        let generation_id = random_nonzero_u64()?;
        let tie_breaker = random_nonzero_u64()?;
        let username_fragment = random_ice_credential(ICE_USERNAME_RANDOM_LENGTH)?;
        let password = random_ice_credential(ICE_PASSWORD_RANDOM_LENGTH)?;
        let mut candidates = direct_candidates.to_vec();
        if let Some(relay) = relay {
            let relay_id = relay.client.relay_id();
            let relay_bytes = relay_id.into_bytes();
            let foundation = u32::from_be_bytes([
                relay_bytes[0],
                relay_bytes[1],
                relay_bytes[2],
                relay_bytes[3],
            ])
            .max(1);
            candidates.push(IceCandidate {
                class: IceCandidateClass::Relay,
                carrier: relay.client.carrier(),
                priority: RELAY_CANDIDATE_PRIORITY,
                foundation,
                max_datagram_size: u32::try_from(relay.client.capabilities().max_datagram_size)
                    .unwrap_or(65_503),
                address: relay.client.relayed_address(),
                related_address: Some(relay.client.mapped_address()),
                relay_id: Some(relay_id),
            });
        }
        let generation = Self {
            generation_id,
            tie_breaker,
            created_at,
            expires_at,
            username_fragment,
            password,
            candidates,
        };
        generation.as_ref()?;
        Ok(generation)
    }

    fn expiry_at(created_at: u64, relay: Option<&WarmRelay>) -> Result<u64, RuntimeError> {
        let maximum_expiry = created_at
            .checked_add(ICE_GENERATION_MAX_LIFETIME)
            .ok_or(RuntimeError::ConnectivityExpiryOverflow)?;
        if let Some(relay) = relay {
            if relay.credential_expires_at <= created_at {
                return Err(TurnUdpError::CredentialExpired {
                    expires_at: relay.credential_expires_at,
                    now: created_at,
                }
                .into());
            }
            Ok(relay.credential_expires_at.min(maximum_expiry))
        } else {
            Ok(maximum_expiry)
        }
    }

    fn as_ref(&self) -> Result<ConnectivityGenerationRef<'_>, stella_proto::CodecError> {
        ConnectivityGenerationRef::new(
            self.generation_id,
            self.tie_breaker,
            self.created_at,
            self.expires_at,
            &self.username_fragment,
            &self.password,
            &self.candidates,
        )
    }
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

async fn allocate_preferred_relay(
    bind_address: SocketAddr,
    https_proxy: Option<SocketAddr>,
    connectivity: Option<&ConnectivityConfigState>,
) -> Result<Option<WarmRelay>, RuntimeError> {
    let selections = relay_selections(bind_address, https_proxy, connectivity).await?;
    allocate_relay_selections(
        selections,
        RELAY_CARRIER_ESTABLISHMENT_TIMEOUT,
        allocate_relay,
    )
    .await
}

async fn allocate_relay_selections<T, F, Fut>(
    selections: Vec<SelectedRelay>,
    carrier_timeout: Duration,
    mut allocator: F,
) -> Result<Option<T>, RuntimeError>
where
    F: FnMut(SelectedRelay) -> Fut,
    Fut: Future<Output = Result<T, RuntimeError>>,
{
    let mut last_error = None;
    let mut current_carrier = None;
    let mut carrier_deadline = Instant::now();
    let mut timed_out_carrier = None;
    for selected in selections {
        let carrier = selected.settings.carrier;
        if timed_out_carrier == Some(carrier) {
            continue;
        }
        if current_carrier != Some(carrier) {
            current_carrier = Some(carrier);
            carrier_deadline = Instant::now() + carrier_timeout;
        }
        let relay_id = selected.settings.relay_id;
        match timeout_at(carrier_deadline, allocator(selected)).await {
            Ok(Ok(relay)) => return Ok(Some(relay)),
            Ok(Err(error)) => last_error = Some(error),
            Err(_) => {
                timed_out_carrier = Some(carrier);
                last_error = Some(RuntimeError::RelayCarrierTimeout {
                    relay_id,
                    carrier: carrier.connectivity_carrier(),
                });
            }
        }
    }
    match last_error {
        Some(error) => Err(error),
        None => Ok(None),
    }
}

async fn preferred_relay_settings(
    bind_address: SocketAddr,
    https_proxy: Option<SocketAddr>,
    connectivity: Option<&ConnectivityConfigState>,
) -> Result<Option<SelectedRelay>, RuntimeError> {
    Ok(relay_selections(bind_address, https_proxy, connectivity)
        .await?
        .into_iter()
        .next())
}

async fn relay_selections(
    bind_address: SocketAddr,
    https_proxy: Option<SocketAddr>,
    connectivity: Option<&ConnectivityConfigState>,
) -> Result<Vec<SelectedRelay>, RuntimeError> {
    let Some(connectivity) = connectivity else {
        return Ok(Vec::new());
    };
    let (resolved_services, last_dns_error) =
        resolve_configured_relay_services(connectivity.relay_services(), https_proxy).await;
    let mut selections = Vec::new();
    for carrier in [
        RuntimeRelayCarrier::Udp,
        RuntimeRelayCarrier::Tcp,
        RuntimeRelayCarrier::Tls,
        RuntimeRelayCarrier::Websocket,
    ] {
        for (service, resolved_addresses) in resolved_services.iter().filter(|(service, _)| {
            service.carriers().contains(carrier.mask()) && carrier.port(service.ports()) != 0
        }) {
            let proxied_hostname = carrier == RuntimeRelayCarrier::Websocket
                && https_proxy.is_some()
                && !service.hostname().is_empty();
            let target_addresses = match (proxied_hostname, https_proxy) {
                (true, Some(proxy)) => vec![proxy.ip()],
                _ => resolved_addresses.clone(),
            };
            for relay_address in target_addresses {
                let server_address = SocketAddr::new(relay_address, carrier.port(service.ports()));
                let proxy_address = (carrier == RuntimeRelayCarrier::Websocket)
                    .then_some(https_proxy)
                    .flatten();
                let connection_address = proxy_address.unwrap_or(server_address);
                let Some(turn_bind) = turn_bind_address(bind_address, connection_address.ip())
                else {
                    continue;
                };
                selections.push(SelectedRelay {
                    settings: RelaySettings {
                        carrier,
                        relay_id: service.relay_id(),
                        server_address,
                        bind_address: turn_bind,
                        max_datagram_size: usize::try_from(service.max_datagram_size())
                            .unwrap_or(TURN_UDP_MAX_DATAGRAM_SIZE)
                            .min(TURN_UDP_MAX_DATAGRAM_SIZE),
                        allocation_lifetime_seconds: service.allocation_lifetime_seconds(),
                        idle_timeout_seconds: service.idle_timeout_seconds(),
                        tls_server_name: if carrier.uses_tls() {
                            service.tls_server_name().to_owned()
                        } else {
                            String::new()
                        },
                        trust: if carrier.uses_tls() {
                            service.trust()
                        } else {
                            RelayTrustRequirements::NONE
                        },
                        spki_pins: if carrier.uses_tls() {
                            service.spki_pins().to_vec()
                        } else {
                            Vec::new()
                        },
                        proxy_address,
                        server_hostname: if carrier == RuntimeRelayCarrier::Websocket {
                            service.hostname().to_owned()
                        } else {
                            String::new()
                        },
                    },
                    credentials: TurnCredentials::new(
                        service.credential_username().to_vec(),
                        service.credential_secret().to_vec(),
                        service.credential_expires_at(),
                    )?,
                    credential_expires_at: service.credential_expires_at(),
                });
            }
        }
    }
    match (selections.is_empty(), last_dns_error) {
        (true, Some(error)) => Err(error),
        _ => Ok(selections),
    }
}

async fn resolve_configured_relay_services(
    services: &[crate::RelayServiceState],
    https_proxy: Option<SocketAddr>,
) -> (
    Vec<(&crate::RelayServiceState, Vec<IpAddr>)>,
    Option<RuntimeError>,
) {
    let mut resolved_services = Vec::with_capacity(services.len());
    let mut last_dns_error = None;
    for service in services {
        let proxy_resolves_only_websocket = https_proxy.is_some()
            && service.carriers() == RelayCarrierMask::SECURE_WEBSOCKET
            && !service.hostname().is_empty();
        let addresses = if proxy_resolves_only_websocket {
            service
                .addresses()
                .iter()
                .map(|address| address.address)
                .collect()
        } else {
            match resolve_relay_addresses(service).await {
                Ok(addresses) => addresses,
                Err(error) => {
                    last_dns_error = Some(error);
                    Vec::new()
                }
            }
        };
        resolved_services.push((service, addresses));
    }
    (resolved_services, last_dns_error)
}

async fn resolve_relay_addresses(
    service: &crate::RelayServiceState,
) -> Result<Vec<IpAddr>, RuntimeError> {
    let mut addresses = service
        .addresses()
        .iter()
        .map(|address| address.address)
        .collect::<Vec<_>>();
    if service.hostname().is_empty() || addresses.len() == usize::from(MAX_RELAY_ADDRESSES) {
        return Ok(addresses);
    }
    let hostname = service.hostname().to_owned();
    let resolved = match timeout(RELAY_DNS_TIMEOUT, lookup_host((hostname.clone(), 1))).await {
        Ok(Ok(resolved)) => resolved,
        Ok(Err(source)) if addresses.is_empty() => {
            return Err(RuntimeError::RelayDnsResolution { hostname, source });
        }
        Ok(Err(source)) => {
            tracing::warn!(hostname, %source, "could not augment numeric relay addresses from DNS");
            return Ok(addresses);
        }
        Err(_) if addresses.is_empty() => {
            return Err(RuntimeError::RelayDnsTimeout { hostname });
        }
        Err(_) => {
            tracing::warn!(hostname, "relay DNS augmentation timed out");
            return Ok(addresses);
        }
    };
    let mut dns_addresses = resolved.map(|address| address.ip()).collect::<Vec<_>>();
    dns_addresses.sort_unstable();
    dns_addresses.dedup();
    for address in dns_addresses {
        if addresses.len() == usize::from(MAX_RELAY_ADDRESSES) {
            break;
        }
        if !addresses.contains(&address) && usable_relay_dns_address(address) {
            addresses.push(address);
        }
    }
    if addresses.is_empty() {
        return Err(RuntimeError::RelayDnsEmpty { hostname });
    }
    Ok(addresses)
}

const fn usable_relay_dns_address(address: IpAddr) -> bool {
    match address {
        IpAddr::V4(address) => {
            !address.is_unspecified() && !address.is_multicast() && !address.is_broadcast()
        }
        IpAddr::V6(address) => {
            !address.is_unspecified()
                && !address.is_multicast()
                && (address.segments()[0] & 0xffc0) != 0xfe80
                && address.to_ipv4_mapped().is_none()
        }
    }
}

async fn allocate_relay(selected: SelectedRelay) -> Result<WarmRelay, RuntimeError> {
    let client = match selected.settings.carrier {
        RuntimeRelayCarrier::Udp => WarmRelayClient::Udp(
            TurnUdpClient::allocate(selected.settings.udp_client_config(), selected.credentials)
                .await?,
        ),
        RuntimeRelayCarrier::Tcp => WarmRelayClient::Tcp(
            TurnTcpClient::allocate(selected.settings.tcp_client_config(), selected.credentials)
                .await?,
        ),
        RuntimeRelayCarrier::Tls => WarmRelayClient::Tls(
            TurnTlsClient::allocate(selected.settings.tls_client_config(), selected.credentials)
                .await?,
        ),
        RuntimeRelayCarrier::Websocket => WarmRelayClient::Websocket(
            TurnWebSocketClient::allocate(
                selected.settings.websocket_client_config(),
                selected.credentials,
            )
            .await?,
        ),
    };
    Ok(WarmRelay {
        settings: selected.settings,
        credential_expires_at: selected.credential_expires_at,
        client,
    })
}

const fn turn_bind_address(configured: SocketAddr, relay: IpAddr) -> Option<SocketAddr> {
    match (configured.ip(), relay) {
        (IpAddr::V4(configured_ip), IpAddr::V4(_)) => {
            Some(SocketAddr::new(IpAddr::V4(configured_ip), 0))
        }
        (IpAddr::V6(configured_ip), IpAddr::V6(_)) => {
            Some(SocketAddr::new(IpAddr::V6(configured_ip), 0))
        }
        (IpAddr::V4(configured_ip), IpAddr::V6(_)) if configured_ip.is_unspecified() => {
            Some(SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0))
        }
        (IpAddr::V6(configured_ip), IpAddr::V4(_)) if configured_ip.is_unspecified() => {
            Some(SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0))
        }
        _ => None,
    }
}

async fn receive_relay(
    relay: Option<&WarmRelay>,
    output: &mut [u8],
) -> Result<ReceivedDatagram, RuntimeError> {
    match relay {
        Some(relay) => relay
            .client
            .receive(output)
            .await
            .map_err(RuntimeError::Turn),
        None => pending().await,
    }
}

fn random_nonzero_u64() -> Result<u64, RuntimeError> {
    let mut bytes = [0_u8; 8];
    getrandom::fill(&mut bytes).map_err(|_| RuntimeError::RandomnessUnavailable)?;
    Ok(u64::from_le_bytes(bytes).max(1))
}

fn random_ice_credential(random_length: usize) -> Result<Zeroizing<Vec<u8>>, RuntimeError> {
    let mut random = Zeroizing::new(vec![0_u8; random_length]);
    getrandom::fill(&mut random).map_err(|_| RuntimeError::RandomnessUnavailable)?;
    Ok(Zeroizing::new(
        STANDARD_NO_PAD.encode(&*random).into_bytes(),
    ))
}

fn effective_tap_mtu(policy_mtu: u16, installed_mtu: u32) -> Result<u16, TapError> {
    u16::try_from(u32::from(policy_mtu).min(installed_mtu)).map_err(|_| TapError::InvalidConfig {
        field: "mtu",
        reason: "installed interface MTU cannot be represented",
    })
}

fn unix_time() -> Result<u64, RuntimeError> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .map_err(|_| RuntimeError::SystemTimeBeforeUnixEpoch)
}

#[cfg(test)]
mod tests {
    use std::{
        future::pending,
        net::SocketAddr,
        sync::{Arc, Mutex},
        time::{Duration, SystemTime},
    };

    use stella_common::RelayId;
    use stella_proto::{
        encode_relay_service_list, encode_stun_server_list, ConnectivityCarrier, IceCandidate,
        IceCandidateClass, RelayAddress, RelayCarrierMask, RelayPorts, RelayServiceRef,
        RelayTrustRequirements, StunServer, MAX_RELAY_ADDRESSES,
    };

    use super::{
        allocate_relay_selections, effective_tap_mtu, preferred_relay_settings,
        random_ice_credential, relay_selections, turn_bind_address, unix_time,
        ConnectivityConfigState, LocalConnectivityGeneration, RuntimeError, RuntimeRelayCarrier,
        ICE_PASSWORD_RANDOM_LENGTH, ICE_USERNAME_RANDOM_LENGTH, TURN_UDP_MAX_DATAGRAM_SIZE,
    };

    fn connectivity_config() -> ConnectivityConfigState {
        let now = SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("test clock")
            .as_secs();
        let stun_servers = [StunServer {
            priority: 0,
            address: "192.0.2.10:3478".parse().expect("STUN address"),
        }];
        let mut stun_bytes = vec![0_u8; 28];
        encode_stun_server_list(&stun_servers, &mut stun_bytes).expect("encode STUN list");
        let addresses = [
            RelayAddress {
                priority: 0,
                address: "192.0.2.20".parse().expect("IPv4 relay address"),
            },
            RelayAddress {
                priority: 1,
                address: "2001:db8::20".parse().expect("IPv6 relay address"),
            },
        ];
        let service = RelayServiceRef {
            relay_id: RelayId::from_bytes([0x52; 16]),
            carriers: RelayCarrierMask::from_bits(
                RelayCarrierMask::TURN_UDP.bits()
                    | RelayCarrierMask::TURN_TCP.bits()
                    | RelayCarrierMask::TURN_TLS.bits()
                    | RelayCarrierMask::SECURE_WEBSOCKET.bits(),
            )
            .expect("test relay carriers"),
            priority: 4,
            max_datagram_size: 65_507,
            allocation_lifetime_seconds: 600,
            idle_timeout_seconds: 120,
            credential_issued_at: now,
            credential_expires_at: now + 600,
            hostname: "",
            tls_server_name: "relay.example.test",
            credential_username: b"node-runtime-test",
            credential_secret: b"0123456789abcdef0123456789abcdef",
            region: "test",
            trust: RelayTrustRequirements::SPKI_PIN,
            ports: RelayPorts {
                turn_udp: 3_478,
                turn_tcp: 3_479,
                turn_tls: 443,
                secure_websocket: 8_443,
            },
            addresses: &addresses,
            spki_pins: &[[1; 32]],
        };
        let mut relay_bytes = vec![0_u8; 4 + service.encoded_len().expect("service length")];
        encode_relay_service_list(&[service], &mut relay_bytes).expect("encode relay list");
        ConnectivityConfigState::from_wire(9, &stun_bytes, &relay_bytes, now)
            .expect("decode connectivity config")
    }

    fn dns_only_websocket_config(hostname: &str) -> ConnectivityConfigState {
        let now = unix_time().expect("test time");
        let stun_servers = [StunServer {
            priority: 0,
            address: "192.0.2.10:3478".parse().expect("STUN address"),
        }];
        let mut stun_bytes = vec![0_u8; 28];
        encode_stun_server_list(&stun_servers, &mut stun_bytes).expect("encode STUN list");
        let service = RelayServiceRef {
            relay_id: stella_common::RelayId::from_bytes([0x92; 16]),
            carriers: RelayCarrierMask::SECURE_WEBSOCKET,
            priority: 0,
            max_datagram_size: 1_200,
            allocation_lifetime_seconds: 600,
            idle_timeout_seconds: 120,
            credential_issued_at: now,
            credential_expires_at: now + 600,
            hostname,
            tls_server_name: hostname,
            credential_username: b"node-dns-test",
            credential_secret: b"0123456789abcdef0123456789abcdef",
            region: "test",
            trust: RelayTrustRequirements::SPKI_PIN,
            ports: RelayPorts {
                turn_udp: 0,
                turn_tcp: 0,
                turn_tls: 0,
                secure_websocket: 8_443,
            },
            addresses: &[],
            spki_pins: &[[2; 32]],
        };
        let mut relay_bytes = vec![0_u8; 4 + service.encoded_len().expect("service length")];
        encode_relay_service_list(&[service], &mut relay_bytes).expect("encode DNS relay list");
        ConnectivityConfigState::from_wire(10, &stun_bytes, &relay_bytes, now)
            .expect("decode DNS connectivity config")
    }

    #[test]
    fn effective_mtu_preserves_lower_host_setting_and_caps_higher_setting() {
        assert_eq!(
            effective_tap_mtu(1_500, 1_340).expect("lower host MTU"),
            1_340
        );
        assert_eq!(effective_tap_mtu(1_500, 1_500).expect("equal MTU"), 1_500);
        assert_eq!(
            effective_tap_mtu(1_500, 9_000).expect("cap host MTU"),
            1_500
        );
    }

    #[tokio::test]
    async fn relay_selection_uses_udp_tcp_tls_then_websocket_with_family_binds() {
        let config = connectivity_config();
        let selections = relay_selections(
            "0.0.0.0:51820".parse().expect("wildcard bind"),
            None,
            Some(&config),
        )
        .await
        .expect("relay selections");
        assert_eq!(selections.len(), 8);
        assert_eq!(selections[0].settings.carrier, RuntimeRelayCarrier::Udp);
        assert_eq!(
            selections[0].settings.server_address,
            "192.0.2.20:3478"
                .parse::<SocketAddr>()
                .expect("IPv4 server")
        );
        assert_eq!(
            selections[0].settings.bind_address,
            "0.0.0.0:0".parse::<SocketAddr>().expect("IPv4 bind")
        );
        assert_eq!(
            selections[1].settings.bind_address,
            "[::]:0".parse::<SocketAddr>().expect("IPv6 bind")
        );
        assert_eq!(selections[2].settings.carrier, RuntimeRelayCarrier::Tcp);
        assert_eq!(
            selections[2].settings.server_address,
            "192.0.2.20:3479"
                .parse::<SocketAddr>()
                .expect("IPv4 TCP server")
        );
        assert_eq!(
            selections[0].settings.max_datagram_size,
            TURN_UDP_MAX_DATAGRAM_SIZE
        );
        assert_eq!(selections[4].settings.carrier, RuntimeRelayCarrier::Tls);
        assert_eq!(
            selections[4].settings.server_address,
            "192.0.2.20:443"
                .parse::<SocketAddr>()
                .expect("IPv4 TLS server")
        );
        assert_eq!(selections[5].settings.carrier, RuntimeRelayCarrier::Tls);
        assert_eq!(
            selections[5].settings.server_address,
            "[2001:db8::20]:443"
                .parse::<SocketAddr>()
                .expect("IPv6 TLS server")
        );
        assert_eq!(selections[4].settings.tls_server_name, "relay.example.test");
        assert_eq!(
            selections[4].settings.trust,
            RelayTrustRequirements::SPKI_PIN
        );
        assert_eq!(selections[4].settings.spki_pins, vec![[1; 32]]);
        assert_eq!(
            selections[6].settings.carrier,
            RuntimeRelayCarrier::Websocket
        );
        assert_eq!(
            selections[6].settings.server_address,
            "192.0.2.20:8443"
                .parse::<SocketAddr>()
                .expect("IPv4 WebSocket server")
        );
        assert_eq!(
            selections[7].settings.server_address,
            "[2001:db8::20]:8443"
                .parse::<SocketAddr>()
                .expect("IPv6 WebSocket server")
        );
        assert_eq!(selections[6].settings.tls_server_name, "relay.example.test");
        assert_eq!(
            selections[6].settings.trust,
            RelayTrustRequirements::SPKI_PIN
        );
        assert_eq!(selections[6].settings.spki_pins, vec![[1; 32]]);
        assert_eq!(selections[6].settings.proxy_address, None);
        assert_eq!(selections[0].settings.trust, RelayTrustRequirements::NONE);
        assert!(selections[0].settings.spki_pins.is_empty());
        let preferred = preferred_relay_settings(
            "0.0.0.0:51820".parse().expect("wildcard bind"),
            None,
            Some(&config),
        )
        .await
        .expect("preferred selection")
        .expect("configured relay service");
        assert_eq!(preferred.settings, selections[0].settings);
    }

    #[tokio::test]
    async fn websocket_relay_selection_uses_configured_proxy_family() {
        let config = connectivity_config();
        let proxy = "198.51.100.50:8080"
            .parse::<SocketAddr>()
            .expect("HTTP proxy");
        let proxied = relay_selections(
            "0.0.0.0:51820".parse().expect("wildcard bind"),
            Some(proxy),
            Some(&config),
        )
        .await
        .expect("proxied relay selections");
        assert_eq!(proxied[6].settings.proxy_address, Some(proxy));
        assert_eq!(proxied[7].settings.proxy_address, Some(proxy));
        assert_eq!(
            proxied[6].settings.bind_address,
            "0.0.0.0:0".parse::<SocketAddr>().expect("proxy bind")
        );
        assert_eq!(
            proxied[7].settings.bind_address,
            "0.0.0.0:0".parse::<SocketAddr>().expect("proxy bind")
        );
    }

    #[tokio::test]
    async fn dns_only_websocket_relays_resolve_or_delegate_to_proxy() {
        let direct = dns_only_websocket_config("localhost");
        let selections = relay_selections(
            "0.0.0.0:51820".parse().expect("wildcard bind"),
            None,
            Some(&direct),
        )
        .await
        .expect("resolve DNS-only relay");
        assert!(!selections.is_empty());
        assert!(selections.len() <= usize::from(MAX_RELAY_ADDRESSES));
        assert!(selections.iter().all(|selection| {
            selection.settings.server_address.ip().is_loopback()
                && selection.settings.server_address.port() == 8_443
                && selection.settings.server_hostname == "localhost"
        }));

        let proxy = "198.51.100.50:8080"
            .parse::<SocketAddr>()
            .expect("HTTP proxy");
        let delegated = dns_only_websocket_config("relay.invalid");
        let selections = relay_selections(
            "0.0.0.0:51820".parse().expect("wildcard bind"),
            Some(proxy),
            Some(&delegated),
        )
        .await
        .expect("delegate DNS-only relay to proxy");
        assert_eq!(selections.len(), 1);
        assert_eq!(selections[0].settings.proxy_address, Some(proxy));
        assert_eq!(selections[0].settings.server_address.ip(), proxy.ip());
        assert_eq!(selections[0].settings.server_address.port(), 8_443);
        assert_eq!(selections[0].settings.server_hostname, "relay.invalid");
    }

    #[tokio::test]
    async fn relay_carrier_timeout_skips_remaining_addresses_and_advances() {
        let selections = relay_selections(
            "0.0.0.0:51820".parse().expect("wildcard bind"),
            None,
            Some(&connectivity_config()),
        )
        .await
        .expect("relay selections");
        let attempts = Arc::new(Mutex::new(Vec::new()));
        let recorded_attempts = Arc::clone(&attempts);
        let selected = tokio::time::timeout(
            Duration::from_secs(1),
            allocate_relay_selections(selections, Duration::from_millis(20), move |selection| {
                let attempts = Arc::clone(&recorded_attempts);
                let carrier = selection.settings.carrier;
                async move {
                    attempts.lock().expect("attempt log").push(carrier);
                    if carrier == RuntimeRelayCarrier::Udp {
                        pending::<Result<RuntimeRelayCarrier, RuntimeError>>().await
                    } else {
                        Ok(carrier)
                    }
                }
            }),
        )
        .await
        .expect("bounded fallback")
        .expect("next carrier succeeds")
        .expect("selected relay carrier");
        assert_eq!(selected, RuntimeRelayCarrier::Tcp);
        assert_eq!(
            *attempts.lock().expect("attempt log"),
            [RuntimeRelayCarrier::Udp, RuntimeRelayCarrier::Tcp]
        );
    }

    #[tokio::test]
    async fn relay_fallback_returns_last_safe_timeout_after_all_carriers() {
        let selections = relay_selections(
            "0.0.0.0:51820".parse().expect("wildcard bind"),
            None,
            Some(&connectivity_config()),
        )
        .await
        .expect("relay selections");
        let attempts = Arc::new(Mutex::new(Vec::new()));
        let recorded_attempts = Arc::clone(&attempts);
        let error = tokio::time::timeout(
            Duration::from_secs(1),
            allocate_relay_selections(selections, Duration::from_millis(20), move |selection| {
                let attempts = Arc::clone(&recorded_attempts);
                let carrier = selection.settings.carrier;
                async move {
                    attempts.lock().expect("attempt log").push(carrier);
                    pending::<Result<(), RuntimeError>>().await
                }
            }),
        )
        .await
        .expect("bounded fallback")
        .expect_err("all carriers time out");
        match error {
            RuntimeError::RelayCarrierTimeout { relay_id, carrier } => {
                assert_eq!(relay_id, RelayId::from_bytes([0x52; 16]));
                assert_eq!(carrier, ConnectivityCarrier::SecureWebSocket);
            }
            other => panic!("unexpected fallback error: {other}"),
        }
        assert_eq!(
            *attempts.lock().expect("attempt log"),
            [
                RuntimeRelayCarrier::Udp,
                RuntimeRelayCarrier::Tcp,
                RuntimeRelayCarrier::Tls,
                RuntimeRelayCarrier::Websocket,
            ]
        );
    }

    #[test]
    fn turn_udp_family_selection_respects_specific_local_bind() {
        let configured = "192.0.2.5:45000"
            .parse::<SocketAddr>()
            .expect("specific bind");
        assert_eq!(
            turn_bind_address(configured, "198.51.100.10".parse().expect("IPv4 relay")),
            Some("192.0.2.5:0".parse().expect("ephemeral IPv4 bind"))
        );
        assert_eq!(
            turn_bind_address(configured, "2001:db8::10".parse().expect("IPv6 relay")),
            None
        );
    }

    #[test]
    fn generated_ice_credentials_are_canonical_and_secret_owned() {
        let username = random_ice_credential(ICE_USERNAME_RANDOM_LENGTH).expect("ICE username");
        let password = random_ice_credential(ICE_PASSWORD_RANDOM_LENGTH).expect("ICE password");
        assert_eq!(username.len(), 8);
        assert_eq!(password.len(), 24);
        assert!(username
            .iter()
            .chain(password.iter())
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'+' | b'/')));
    }

    #[test]
    fn direct_candidates_form_a_generation_without_a_relay() {
        let candidate = IceCandidate {
            class: IceCandidateClass::Host,
            carrier: ConnectivityCarrier::DirectUdp,
            priority: 2_130_706_431,
            foundation: 7,
            max_datagram_size: 1_200,
            address: "192.0.2.70:47000".parse().expect("host candidate"),
            related_address: None,
            relay_id: None,
        };
        let generation =
            LocalConnectivityGeneration::new(None, &[candidate]).expect("direct-only generation");
        let generation = generation.as_ref().expect("validated generation");
        assert_eq!(generation.candidates(), &[candidate]);
        assert!(generation.expires_at() > generation.created_at());
    }

    #[test]
    fn direct_only_generation_rotation_extends_expiry() {
        let candidate = IceCandidate {
            class: IceCandidateClass::Host,
            carrier: ConnectivityCarrier::DirectUdp,
            priority: 2_130_706_431,
            foundation: 8,
            max_datagram_size: 1_200,
            address: "192.0.2.71:47001".parse().expect("host candidate"),
            related_address: None,
            relay_id: None,
        };
        let initial = LocalConnectivityGeneration::new_at(100, None, &[candidate])
            .expect("initial direct generation");
        let replacement = LocalConnectivityGeneration::new_at(581, None, &[candidate])
            .expect("replacement direct generation");
        assert_eq!(initial.expires_at, 700);
        assert_eq!(replacement.expires_at, 1_181);
        assert!(replacement.expires_at > initial.expires_at);
    }
}
