//! Per-network routing between TAP frames, peer sessions, and UDP datagrams.

use std::{
    collections::{BTreeMap, BTreeSet},
    net::{IpAddr, SocketAddr},
    time::Duration,
};

use stella_common::{MacAddress, NetworkId, NodeId};
use stella_crypto::IdentitySigningKey;
use stella_proto::{CommonHeader, Endpoint, HandshakeHeader, PacketType};
use stella_transport::{Endpoint as TransportEndpoint, PathId};
use thiserror::Error;

use crate::{
    DataPlaneError, HandshakeError, HandshakeEvent, HandshakeTransmission, L2Switch, NetworkState,
    PeerDataSession, PeerHandshakeConfig, PeerHandshakeManager, PeerIngress, SwitchError,
    TapForwarding,
};

const ROUTINE_REKEY_PACKET_LIMIT: u64 = u32::MAX as u64;
const ROUTINE_REKEY_LEAD: u64 = 10;
const OLD_SESSION_RECEIVE_GRACE: Duration = Duration::from_secs(30);
const KEEPALIVE_INTERVAL: Duration = Duration::from_secs(15);
const MAX_UNANSWERED_KEEPALIVES: usize = 3;

/// Failure while routing one active virtual network.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum NetworkDataError {
    /// The network has no usable path for an authorized peer.
    #[error("peer {peer_node_id} has no usable path for this transport")]
    NoPeerPath {
        /// Peer without a compatible path.
        peer_node_id: NodeId,
    },
    /// A datagram source does not resolve to an authorized peer path.
    #[error("datagram source {endpoint} is not authorized for peer {peer_node_id}")]
    UnauthorizedEndpoint {
        /// Claimed authenticated peer.
        peer_node_id: NodeId,
        /// Transport source observed by the runtime.
        endpoint: TransportEndpoint,
    },
    /// An authenticated packet arrived through a different path than the confirmed session.
    #[error(
        "datagram path {actual} does not match pinned path {expected} for peer {peer_node_id}"
    )]
    SessionPathMismatch {
        /// Peer whose session is pinned.
        peer_node_id: NodeId,
        /// Path confirmed by the handshake.
        expected: PathId,
        /// Path that supplied this datagram.
        actual: PathId,
    },
    /// A routed datagram refers to a path no longer owned by this network.
    #[error("network does not own path {path_id}")]
    UnknownPath {
        /// Missing local path identifier.
        path_id: PathId,
    },
    /// The local path identifier space was exhausted.
    #[error("local path identifier space is exhausted")]
    PathIdExhausted,
    /// The datagram belongs to another virtual network.
    #[error("datagram belongs to an unexpected network")]
    WrongNetwork,
    /// No confirmed session matches an incoming protected data packet.
    #[error("no confirmed data session for peer {peer_node_id}")]
    NoPeerSession {
        /// Peer without a matching session.
        peer_node_id: NodeId,
    },
    /// A packet or header was structurally malformed.
    #[error(transparent)]
    Codec(#[from] stella_proto::CodecError),
    /// A peer handshake failed.
    #[error(transparent)]
    Handshake(#[from] HandshakeError),
    /// Protected Ethernet data failed validation.
    #[error(transparent)]
    DataPlane(#[from] DataPlaneError),
    /// Ethernet switching input was invalid.
    #[error(transparent)]
    Switch(#[from] SwitchError),
}

/// One complete datagram routed to an authorized peer path.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RoutedDatagram {
    peer_node_id: NodeId,
    path_id: PathId,
    bytes: Vec<u8>,
}

impl RoutedDatagram {
    /// Returns the destination peer.
    #[must_use]
    pub const fn peer_node_id(&self) -> NodeId {
        self.peer_node_id
    }

    /// Returns the selected validated path.
    #[must_use]
    pub const fn path_id(&self) -> PathId {
        self.path_id
    }

    /// Borrows the complete datagram bytes.
    #[must_use]
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }
}

/// Bounded routing output from one network operation.
#[derive(Debug, Default)]
pub struct NetworkOutput {
    datagrams: Vec<RoutedDatagram>,
    tap_frame: Option<Vec<u8>>,
}

impl NetworkOutput {
    /// Borrows all complete datagrams selected for transmission.
    #[must_use]
    pub fn datagrams(&self) -> &[RoutedDatagram] {
        &self.datagrams
    }

    /// Borrows one authenticated frame selected for local TAP delivery.
    #[must_use]
    pub fn tap_frame(&self) -> Option<&[u8]> {
        self.tap_frame.as_deref()
    }

    /// Consumes the output into owned datagrams and optional TAP frame.
    #[must_use]
    pub fn into_parts(self) -> (Vec<RoutedDatagram>, Option<Vec<u8>>) {
        (self.datagrams, self.tap_frame)
    }
}

struct InstalledSession {
    data: PeerDataSession,
    session_id: u64,
    expires_at: u64,
    path_id: PathId,
    last_activity_at: Duration,
    outstanding_probes: BTreeSet<u64>,
    highest_peer_probe: u64,
    pending_echo_probe: Option<u64>,
    rekeying: bool,
}

struct RetiredSession {
    data: PeerDataSession,
    path_id: PathId,
    remove_at: Duration,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct PeerPath {
    peer_node_id: NodeId,
    endpoint: TransportEndpoint,
}

/// Active, isolated state for one TAP-backed virtual network.
pub struct NetworkDataPlane {
    state: NetworkState,
    udp_family: IpFamily,
    max_datagram_size: usize,
    switch: L2Switch,
    handshakes: PeerHandshakeManager,
    paths: BTreeMap<PathId, PeerPath>,
    peer_paths: BTreeMap<NodeId, Vec<PathId>>,
    next_path_id: u64,
    sessions: BTreeMap<NodeId, InstalledSession>,
    retired_sessions: BTreeMap<(NodeId, u64), RetiredSession>,
}

impl NetworkDataPlane {
    /// Creates an inactive-session network router from authoritative control state.
    ///
    /// # Errors
    ///
    /// Returns [`NetworkDataError`] when the primary TAP MAC is invalid or a
    /// peer handshake configuration cannot be derived from validated state.
    pub fn new(
        state: NetworkState,
        primary_mac: MacAddress,
        udp_bind: SocketAddr,
        max_datagram_size: usize,
        signing_key: &IdentitySigningKey,
        now: Duration,
    ) -> Result<Self, NetworkDataError> {
        let local_node_id = state.local_grant().node_id;
        let mut handshakes = PeerHandshakeManager::new(local_node_id);
        for peer in state.peers().keys().copied() {
            handshakes.upsert_peer(PeerHandshakeConfig::from_network_state(
                &state,
                peer,
                signing_key,
                max_datagram_size,
            )?)?;
        }
        let switch = L2Switch::new(state.policy(), primary_mac, now)?;
        let mut plane = Self {
            state,
            udp_family: IpFamily::from(udp_bind.ip()),
            max_datagram_size,
            switch,
            handshakes,
            paths: BTreeMap::new(),
            peer_paths: BTreeMap::new(),
            next_path_id: 1,
            sessions: BTreeMap::new(),
            retired_sessions: BTreeMap::new(),
        };
        let peers: Vec<NodeId> = plane.state.peers().keys().copied().collect();
        for peer in peers {
            plane.install_peer_paths(peer)?;
        }
        Ok(plane)
    }

    /// Returns this isolated virtual network ID.
    #[must_use]
    pub const fn network_id(&self) -> NetworkId {
        self.state.network_id()
    }

    /// Returns the established peers currently eligible for forwarding.
    #[must_use]
    pub fn established_peers(&self) -> BTreeSet<NodeId> {
        self.sessions
            .iter()
            .filter_map(|(peer, session)| (!session.rekeying).then_some(*peer))
            .collect()
    }

    /// Starts preferred-initiator handshakes for peers without a session.
    ///
    /// # Errors
    ///
    /// Returns [`NetworkDataError`] if handshake construction or endpoint
    /// selection fails for any selected peer.
    pub fn start_handshakes(
        &mut self,
        signing_key: &IdentitySigningKey,
        wall_time: u64,
        monotonic_now: Duration,
    ) -> Result<NetworkOutput, NetworkDataError> {
        let peers: Vec<NodeId> = self
            .state
            .peers()
            .keys()
            .copied()
            .filter(|peer| {
                self.sessions
                    .get(peer)
                    .is_none_or(|session| session.rekeying)
                    && !self.handshakes.has_outgoing(*peer)
                    && self.handshakes.can_initiate(*peer, monotonic_now)
                    && self.select_peer_path(*peer).is_some()
            })
            .collect();
        let mut output = NetworkOutput::default();
        for peer in peers {
            let config = PeerHandshakeConfig::from_network_state(
                &self.state,
                peer,
                signing_key,
                self.max_datagram_size,
            )?;
            if !config.is_preferred_initiator() {
                continue;
            }
            let transmission =
                self.handshakes
                    .initiate(peer, signing_key, wall_time, monotonic_now)?;
            output.datagrams.push(self.route_handshake(transmission)?);
        }
        Ok(output)
    }

    /// Produces due handshake retries and starts routine rekeys when required.
    ///
    /// # Errors
    ///
    /// Returns [`NetworkDataError`] when a due peer has no usable endpoint or
    /// a replacement initiation cannot be constructed.
    pub fn maintain(
        &mut self,
        signing_key: &IdentitySigningKey,
        wall_time: u64,
        monotonic_now: Duration,
    ) -> Result<NetworkOutput, NetworkDataError> {
        let rekey: Vec<NodeId> = self
            .sessions
            .iter()
            .filter_map(|(peer, session)| {
                (!session.rekeying
                    && (wall_time.saturating_add(ROUTINE_REKEY_LEAD) >= session.expires_at
                        || session.data.sent_packet_count() >= ROUTINE_REKEY_PACKET_LIMIT))
                    .then_some(*peer)
            })
            .collect();
        for peer in rekey {
            if let Some(session) = self.sessions.get_mut(&peer) {
                session.rekeying = true;
            }
        }
        self.expire_retired_sessions(monotonic_now);
        let mut output = NetworkOutput::default();
        let keepalive_due: Vec<NodeId> = self
            .sessions
            .iter()
            .filter_map(|(peer, session)| {
                (!session.rekeying
                    && monotonic_now.saturating_sub(session.last_activity_at) >= KEEPALIVE_INTERVAL)
                    .then_some(*peer)
            })
            .collect();
        for peer in keepalive_due {
            let timed_out = self.sessions.get(&peer).is_some_and(|session| {
                session.outstanding_probes.len() >= MAX_UNANSWERED_KEEPALIVES
            });
            if timed_out {
                self.remove_session(peer);
                continue;
            }
            let session = self
                .sessions
                .get_mut(&peer)
                .ok_or(NetworkDataError::NoPeerSession { peer_node_id: peer })?;
            let path_id = session.path_id;
            let echo_probe_id = session.pending_echo_probe.take().unwrap_or(0);
            let bytes = session.data.protect_keepalive(echo_probe_id)?;
            let probe_id = session.data.sent_packet_count();
            session.outstanding_probes.insert(probe_id);
            session.last_activity_at = monotonic_now;
            output.datagrams.push(RoutedDatagram {
                peer_node_id: peer,
                path_id,
                bytes,
            });
        }
        for transmission in self.handshakes.poll_retransmissions(monotonic_now) {
            output.datagrams.push(self.route_handshake(transmission)?);
        }
        let starts = self.start_handshakes(signing_key, wall_time, monotonic_now)?;
        output.datagrams.extend(starts.datagrams);
        Ok(output)
    }

    /// Routes one local TAP frame to zero, one, or all established peers.
    ///
    /// # Errors
    ///
    /// Returns [`NetworkDataError`] for invalid Ethernet input, missing peer
    /// endpoint, or packet-protection failure.
    pub fn accept_tap_frame(
        &mut self,
        frame: &[u8],
        now: Duration,
    ) -> Result<NetworkOutput, NetworkDataError> {
        let eligible = self.established_peers();
        let forwarding = self.switch.forward_tap_frame(frame, &eligible, now)?;
        let peers = match forwarding {
            TapForwarding::Local | TapForwarding::RateLimited { .. } => Vec::new(),
            TapForwarding::Unicast(peer) => vec![peer],
            TapForwarding::Flood { peers, .. } => peers,
        };
        let mut output = NetworkOutput::default();
        for peer in peers {
            let session = self
                .sessions
                .get_mut(&peer)
                .ok_or(NetworkDataError::NoPeerSession { peer_node_id: peer })?;
            let path_id = session.path_id;
            for bytes in session.data.protect_frame(frame)? {
                output.datagrams.push(RoutedDatagram {
                    peer_node_id: peer,
                    path_id,
                    bytes,
                });
            }
            session.last_activity_at = now;
        }
        Ok(output)
    }

    /// Authenticates and routes one datagram from an authorized transport path.
    ///
    /// # Errors
    ///
    /// Returns [`NetworkDataError`] for malformed context, endpoint spoofing,
    /// handshake failure, unknown session, failed packet protection, or invalid
    /// authenticated Ethernet input.
    pub fn accept_datagram(
        &mut self,
        source: &TransportEndpoint,
        datagram: &[u8],
        signing_key: &IdentitySigningKey,
        wall_time: u64,
        monotonic_now: Duration,
    ) -> Result<NetworkOutput, NetworkDataError> {
        let common = CommonHeader::decode(datagram)?;
        if common.network_id != self.state.network_id() {
            return Err(NetworkDataError::WrongNetwork);
        }
        match common.packet_type {
            PacketType::Data => self.accept_data(source, datagram, monotonic_now),
            PacketType::SessionInit
            | PacketType::SessionResponse
            | PacketType::SessionConfirm
            | PacketType::SessionReject => {
                let header = HandshakeHeader::decode(datagram)?;
                let path_id = self.resolve_peer_path(header.sender_node_id, source)?;
                let event = self.handshakes.handle_datagram(
                    datagram,
                    signing_key,
                    wall_time,
                    monotonic_now,
                )?;
                self.apply_handshake_event(event, path_id, monotonic_now)
            }
            PacketType::Keepalive => self.accept_keepalive(source, datagram, monotonic_now),
        }
    }

    /// Authenticates and routes one UDP datagram from an authorized endpoint.
    ///
    /// This compatibility entry point wraps the endpoint in the generic
    /// transport-path representation used by [`Self::accept_datagram`].
    ///
    /// # Errors
    ///
    /// Returns [`NetworkDataError`] for the same conditions as
    /// [`Self::accept_datagram`].
    pub fn accept_udp_datagram(
        &mut self,
        source: SocketAddr,
        datagram: &[u8],
        signing_key: &IdentitySigningKey,
        wall_time: u64,
        monotonic_now: Duration,
    ) -> Result<NetworkOutput, NetworkDataError> {
        self.accept_datagram(
            &TransportEndpoint::Udp(source),
            datagram,
            signing_key,
            wall_time,
            monotonic_now,
        )
    }

    /// Replaces authoritative control state and invalidates affected sessions.
    ///
    /// Epoch, policy, local-grant, peer-grant, or endpoint changes immediately
    /// remove the corresponding data keys, replay state, and learned MACs.
    ///
    /// # Errors
    ///
    /// Returns [`NetworkDataError`] when replacement state belongs to another
    /// network or cannot produce valid peer handshake configuration.
    pub fn reconcile(
        &mut self,
        replacement: NetworkState,
        signing_key: &IdentitySigningKey,
        primary_mac: MacAddress,
        now: Duration,
    ) -> Result<(), NetworkDataError> {
        if replacement.network_id() != self.state.network_id() {
            return Err(NetworkDataError::WrongNetwork);
        }
        let reset_all = replacement.controller_epoch() != self.state.controller_epoch()
            || replacement.policy() != self.state.policy()
            || replacement.local_grant().grant_serial != self.state.local_grant().grant_serial;
        let old_peers = self.state.peers().clone();
        if reset_all {
            self.sessions.clear();
            self.retired_sessions.clear();
            self.paths.clear();
            self.peer_paths.clear();
            self.switch = L2Switch::new(replacement.policy(), primary_mac, now)?;
            self.handshakes = PeerHandshakeManager::new(replacement.local_grant().node_id);
        }
        self.state = replacement;
        let current_peers: Vec<NodeId> = self.state.peers().keys().copied().collect();
        for peer in old_peers.keys().copied() {
            if !self.state.peers().contains_key(&peer) {
                self.remove_session(peer);
                self.remove_peer_paths(peer);
                self.handshakes.remove_peer(peer);
            }
        }
        for peer in current_peers {
            let endpoints_changed = reset_all
                || old_peers.get(&peer).is_none_or(|old| {
                    self.state
                        .peers()
                        .get(&peer)
                        .is_none_or(|current| old.endpoints() != current.endpoints())
                });
            let changed = old_peers.get(&peer).is_none_or(|old| {
                self.state.peers().get(&peer).is_none_or(|current| {
                    old.grant().grant_serial != current.grant().grant_serial
                        || old.endpoints() != current.endpoints()
                })
            });
            if changed {
                self.remove_session(peer);
            }
            if endpoints_changed {
                self.remove_peer_paths(peer);
                self.install_peer_paths(peer)?;
            }
            self.handshakes
                .upsert_peer(PeerHandshakeConfig::from_network_state(
                    &self.state,
                    peer,
                    signing_key,
                    self.max_datagram_size,
                )?)?;
        }
        Ok(())
    }

    fn accept_data(
        &mut self,
        source: &TransportEndpoint,
        datagram: &[u8],
        now: Duration,
    ) -> Result<NetworkOutput, NetworkDataError> {
        let header = stella_proto::DataHeader::decode(datagram)?;
        let peer = header.sender_node_id;
        let path_id = self.resolve_peer_path(peer, source)?;
        let frame = if let Some(session) = self.sessions.get_mut(&peer) {
            if header.session_id == session.session_id {
                validate_pinned_path(peer, session.path_id, path_id)?;
                let frame = session.data.accept_datagram(datagram, now)?;
                session.last_activity_at = now;
                frame
            } else {
                self.accept_retired_data(peer, header.session_id, path_id, datagram, now)?
            }
        } else {
            self.accept_retired_data(peer, header.session_id, path_id, datagram, now)?
        };
        let Some(frame) = frame else {
            return Ok(NetworkOutput::default());
        };
        match self.switch.accept_peer_frame(peer, &frame, now)? {
            PeerIngress::DeliverToTap => Ok(NetworkOutput {
                datagrams: Vec::new(),
                tap_frame: Some(frame),
            }),
            PeerIngress::DropLocalMacConflict => Ok(NetworkOutput::default()),
        }
    }

    fn accept_retired_data(
        &mut self,
        peer: NodeId,
        session_id: u64,
        path_id: PathId,
        datagram: &[u8],
        now: Duration,
    ) -> Result<Option<Vec<u8>>, NetworkDataError> {
        let retired = self
            .retired_sessions
            .get_mut(&(peer, session_id))
            .ok_or(NetworkDataError::NoPeerSession { peer_node_id: peer })?;
        validate_pinned_path(peer, retired.path_id, path_id)?;
        Ok(retired.data.accept_datagram(datagram, now)?)
    }

    fn apply_handshake_event(
        &mut self,
        event: HandshakeEvent,
        path_id: PathId,
        now: Duration,
    ) -> Result<NetworkOutput, NetworkDataError> {
        match event {
            HandshakeEvent::Ignored | HandshakeEvent::Rejected { .. } => {
                Ok(NetworkOutput::default())
            }
            HandshakeEvent::Transmit(transmission) => Ok(NetworkOutput {
                datagrams: vec![route_handshake_to(transmission, path_id)],
                tap_frame: None,
            }),
            HandshakeEvent::Established {
                peer_node_id,
                transmission,
                session,
            } => {
                let mut output = NetworkOutput::default();
                if let Some(transmission) = transmission {
                    output
                        .datagrams
                        .push(route_handshake_to(transmission, path_id));
                }
                let session_id = session.session_id();
                let established_at = session.established_at();
                let expires_at = session.expires_at();
                let data = session.into_data_session()?;
                if let Some(previous) = self.sessions.insert(
                    peer_node_id,
                    InstalledSession {
                        data,
                        session_id,
                        expires_at,
                        path_id,
                        last_activity_at: now,
                        outstanding_probes: BTreeSet::new(),
                        highest_peer_probe: 0,
                        pending_echo_probe: None,
                        rekeying: false,
                    },
                ) {
                    if previous.expires_at > established_at {
                        self.retired_sessions.insert(
                            (peer_node_id, previous.session_id),
                            RetiredSession {
                                data: previous.data,
                                path_id: previous.path_id,
                                remove_at: now.saturating_add(OLD_SESSION_RECEIVE_GRACE),
                            },
                        );
                    } else {
                        self.handshakes
                            .retire_session(peer_node_id, previous.session_id);
                    }
                }
                Ok(output)
            }
        }
    }

    fn accept_keepalive(
        &mut self,
        source: &TransportEndpoint,
        datagram: &[u8],
        now: Duration,
    ) -> Result<NetworkOutput, NetworkDataError> {
        let header = stella_proto::KeepaliveHeader::decode(datagram)?;
        let peer = header.sender_node_id;
        let path_id = self.resolve_peer_path(peer, source)?;
        let Some(session) = self.sessions.get_mut(&peer) else {
            return self.accept_retired_keepalive(peer, header.session_id, path_id, datagram);
        };
        if header.session_id != session.session_id {
            return self.accept_retired_keepalive(peer, header.session_id, path_id, datagram);
        }
        validate_pinned_path(peer, session.path_id, path_id)?;
        let keepalive = session.data.accept_keepalive(datagram)?;
        let echo_probe_id = keepalive.echo_probe_id();
        if echo_probe_id != 0 && session.outstanding_probes.contains(&echo_probe_id) {
            session
                .outstanding_probes
                .retain(|probe_id| *probe_id > echo_probe_id);
        }
        if keepalive.probe_id() > session.highest_peer_probe {
            session.highest_peer_probe = keepalive.probe_id();
            session.pending_echo_probe = Some(keepalive.probe_id());
        }
        session.last_activity_at = now;
        Ok(NetworkOutput::default())
    }

    fn accept_retired_keepalive(
        &mut self,
        peer: NodeId,
        session_id: u64,
        path_id: PathId,
        datagram: &[u8],
    ) -> Result<NetworkOutput, NetworkDataError> {
        let retired = self
            .retired_sessions
            .get_mut(&(peer, session_id))
            .ok_or(NetworkDataError::NoPeerSession { peer_node_id: peer })?;
        validate_pinned_path(peer, retired.path_id, path_id)?;
        retired.data.accept_keepalive(datagram)?;
        Ok(NetworkOutput::default())
    }

    fn route_handshake(
        &self,
        transmission: HandshakeTransmission,
    ) -> Result<RoutedDatagram, NetworkDataError> {
        let (peer_node_id, bytes) = transmission.into_parts();
        Ok(RoutedDatagram {
            peer_node_id,
            path_id: self.peer_path(peer_node_id)?,
            bytes,
        })
    }

    /// Resolves one locally owned path to its transport-specific endpoint.
    ///
    /// # Errors
    ///
    /// Returns [`NetworkDataError::UnknownPath`] after path withdrawal or when
    /// a routed datagram belongs to another network plane.
    pub fn transport_endpoint(
        &self,
        path_id: PathId,
    ) -> Result<&TransportEndpoint, NetworkDataError> {
        self.paths
            .get(&path_id)
            .map(|path| &path.endpoint)
            .ok_or(NetworkDataError::UnknownPath { path_id })
    }

    fn peer_path(&self, peer: NodeId) -> Result<PathId, NetworkDataError> {
        self.select_peer_path(peer)
            .ok_or(NetworkDataError::NoPeerPath { peer_node_id: peer })
    }

    fn select_peer_path(&self, peer: NodeId) -> Option<PathId> {
        self.peer_paths
            .get(&peer)
            .and_then(|paths| paths.first())
            .copied()
    }

    fn resolve_peer_path(
        &self,
        peer: NodeId,
        source: &TransportEndpoint,
    ) -> Result<PathId, NetworkDataError> {
        self.peer_paths
            .get(&peer)
            .and_then(|path_ids| {
                path_ids.iter().copied().find(|path_id| {
                    self.paths
                        .get(path_id)
                        .is_some_and(|path| path.peer_node_id == peer && &path.endpoint == source)
                })
            })
            .ok_or_else(|| NetworkDataError::UnauthorizedEndpoint {
                peer_node_id: peer,
                endpoint: source.clone(),
            })
    }

    fn install_peer_paths(&mut self, peer: NodeId) -> Result<(), NetworkDataError> {
        let mut endpoints = self
            .state
            .peers()
            .get(&peer)
            .map(|state| {
                state
                    .endpoints()
                    .iter()
                    .copied()
                    .filter(|endpoint| self.udp_family.matches(*endpoint))
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();
        endpoints.sort_by_key(|endpoint| {
            (
                endpoint.priority(),
                endpoint_address(*endpoint),
                endpoint.port(),
            )
        });
        let mut path_ids = Vec::with_capacity(endpoints.len());
        for endpoint in endpoints {
            let path_id = self.allocate_path_id()?;
            self.paths.insert(
                path_id,
                PeerPath {
                    peer_node_id: peer,
                    endpoint: TransportEndpoint::Udp(endpoint_socket_address(endpoint)),
                },
            );
            path_ids.push(path_id);
        }
        self.peer_paths.insert(peer, path_ids);
        Ok(())
    }

    fn remove_peer_paths(&mut self, peer: NodeId) {
        if let Some(path_ids) = self.peer_paths.remove(&peer) {
            for path_id in path_ids {
                self.paths.remove(&path_id);
            }
        }
    }

    fn allocate_path_id(&mut self) -> Result<PathId, NetworkDataError> {
        let value = self.next_path_id;
        let path_id = PathId::new(value).ok_or(NetworkDataError::PathIdExhausted)?;
        self.next_path_id = value.checked_add(1).unwrap_or(0);
        Ok(path_id)
    }

    fn remove_session(&mut self, peer: NodeId) {
        if let Some(previous) = self.sessions.remove(&peer) {
            self.handshakes.retire_session(peer, previous.session_id);
        }
        let retired: Vec<(NodeId, u64)> = self
            .retired_sessions
            .keys()
            .filter(|(session_peer, _)| *session_peer == peer)
            .copied()
            .collect();
        for key @ (_, session_id) in retired {
            self.retired_sessions.remove(&key);
            self.handshakes.retire_session(peer, session_id);
        }
        self.switch.remove_peer(peer);
    }

    fn expire_retired_sessions(&mut self, now: Duration) {
        let expired: Vec<(NodeId, u64)> = self
            .retired_sessions
            .iter()
            .filter_map(|(key, session)| (now >= session.remove_at).then_some(*key))
            .collect();
        for key @ (peer, session_id) in expired {
            self.retired_sessions.remove(&key);
            self.handshakes.retire_session(peer, session_id);
        }
    }
}

impl std::fmt::Debug for NetworkDataPlane {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("NetworkDataPlane")
            .field("network_id", &self.state.network_id())
            .field("controller_epoch", &self.state.controller_epoch())
            .field("configured_peers", &self.state.peers().len())
            .field("established_peers", &self.sessions.len())
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum IpFamily {
    V4,
    V6,
}

impl IpFamily {
    const fn matches(self, endpoint: Endpoint) -> bool {
        matches!(
            (self, endpoint),
            (Self::V4, Endpoint::UdpIpv4 { .. }) | (Self::V6, Endpoint::UdpIpv6 { .. })
        )
    }
}

impl From<IpAddr> for IpFamily {
    fn from(address: IpAddr) -> Self {
        match address {
            IpAddr::V4(_) => Self::V4,
            IpAddr::V6(_) => Self::V6,
        }
    }
}

fn endpoint_socket_address(endpoint: Endpoint) -> SocketAddr {
    match endpoint {
        Endpoint::UdpIpv4 { address, port, .. } => SocketAddr::new(IpAddr::V4(address), port),
        Endpoint::UdpIpv6 { address, port, .. } => SocketAddr::new(IpAddr::V6(address), port),
    }
}

fn endpoint_address(endpoint: Endpoint) -> [u8; 16] {
    match endpoint {
        Endpoint::UdpIpv4 { address, .. } => {
            let mut bytes = [0_u8; 16];
            bytes[..4].copy_from_slice(&address.octets());
            bytes
        }
        Endpoint::UdpIpv6 { address, .. } => address.octets(),
    }
}

fn route_handshake_to(transmission: HandshakeTransmission, path_id: PathId) -> RoutedDatagram {
    let (peer_node_id, bytes) = transmission.into_parts();
    RoutedDatagram {
        peer_node_id,
        path_id,
        bytes,
    }
}

fn validate_pinned_path(
    peer_node_id: NodeId,
    expected: PathId,
    actual: PathId,
) -> Result<(), NetworkDataError> {
    if actual != expected {
        return Err(NetworkDataError::SessionPathMismatch {
            peer_node_id,
            expected,
            actual,
        });
    }
    Ok(())
}

#[cfg(all(test, windows))]
mod tests {
    use std::{
        net::{Ipv4Addr, SocketAddr},
        path::PathBuf,
        sync::atomic::{AtomicU64, Ordering},
        time::Duration,
    };

    use stella_common::{MacAddress, NetworkId};
    use stella_crypto::{derive_controller_id, derive_node_id, IdentitySeed, IdentitySigningKey};
    use stella_proto::{
        CommonHeader, ConfidentialityPolicy, Endpoint, NetworkPolicy, PacketType, ProtocolVersion,
    };
    use stella_server::{
        network_state::encode_network_state,
        store::{AuthorityStore, NetworkRecord, NodeRecord},
    };
    use stella_transport::Endpoint as TransportEndpoint;

    use super::{NetworkDataError, NetworkDataPlane};
    use crate::{NetworkState, SnapshotInput};

    static TEMP_SEQUENCE: AtomicU64 = AtomicU64::new(1);
    const WALL_TIME: u64 = 200;

    fn signing_key(seed: u8) -> IdentitySigningKey {
        IdentitySigningKey::from_seed(&IdentitySeed::from_bytes([seed; 32]))
    }

    fn fixture() -> (
        PathBuf,
        AuthorityStore,
        IdentitySigningKey,
        IdentitySigningKey,
        IdentitySigningKey,
        NetworkId,
    ) {
        let sequence = TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        let directory = std::env::temp_dir().join(format!(
            "stella-network-data-{}-{sequence}",
            std::process::id()
        ));
        std::fs::create_dir(&directory).expect("create fixture directory");
        let controller = signing_key(91);
        let store = AuthorityStore::initialize(
            &directory.join("controller.redb"),
            derive_controller_id(controller.public_key()),
        )
        .expect("initialize authority store");
        let network_id = NetworkId::from_bytes([92; 16]);
        let policy = NetworkPolicy {
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
            network_id,
            policy_revision: 1,
        };
        store
            .create_network(&NetworkRecord::new(policy, "Network data", 100).expect("network"))
            .expect("create network");
        let alice = signing_key(93);
        let bob = signing_key(94);
        let alice_record = NodeRecord::new(alice.public_key(), "Alice", 100).expect("alice");
        let bob_record = NodeRecord::new(bob.public_key(), "Bob", 100).expect("bob");
        store.create_node(&alice_record).expect("create alice");
        store.create_node(&bob_record).expect("create bob");
        store
            .add_member(alice_record.node_id(), network_id, 110)
            .expect("join alice");
        store
            .add_member(bob_record.node_id(), network_id, 110)
            .expect("join bob");
        store
            .publish_endpoints(
                alice_record.node_id(),
                network_id,
                &[
                    Endpoint::UdpIpv4 {
                        priority: 0,
                        port: 46_001,
                        max_datagram_size: 1_200,
                        address: Ipv4Addr::LOCALHOST,
                    },
                    Endpoint::UdpIpv4 {
                        priority: 1,
                        port: 46_003,
                        max_datagram_size: 1_200,
                        address: Ipv4Addr::LOCALHOST,
                    },
                ],
                120,
            )
            .expect("publish alice endpoint");
        store
            .publish_endpoints(
                bob_record.node_id(),
                network_id,
                &[Endpoint::UdpIpv4 {
                    priority: 0,
                    port: 46_002,
                    max_datagram_size: 1_200,
                    address: Ipv4Addr::LOCALHOST,
                }],
                121,
            )
            .expect("publish bob endpoint");
        (directory, store, controller, alice, bob, network_id)
    }

    fn state(
        store: &AuthorityStore,
        controller: &IdentitySigningKey,
        local: &IdentitySigningKey,
        network_id: NetworkId,
    ) -> NetworkState {
        let local_node_id = derive_node_id(local.public_key());
        let view = store
            .network_session_view(local_node_id, network_id)
            .expect("network session view");
        let encoded = encode_network_state(controller, &view, WALL_TIME, ProtocolVersion::V0_1)
            .expect("encode state");
        NetworkState::from_snapshot(&SnapshotInput {
            controller_id: derive_controller_id(controller.public_key()),
            controller_public_key: controller.public_key(),
            local_node_id,
            local_public_key: local.public_key(),
            network_id,
            controller_epoch: encoded.controller_epoch(),
            snapshot_revision: encoded.snapshot_revision(),
            local_grant_bytes: encoded.local_grant(),
            policy_bytes: encoded.policy(),
            peer_list_bytes: encoded.peer_list(),
            connectivity_list_bytes: None,
            now: WALL_TIME,
        })
        .expect("validate state")
    }

    fn ethernet_frame(source: MacAddress, destination: MacAddress, marker: u8) -> Vec<u8> {
        let mut frame = vec![marker; 128];
        frame[..6].copy_from_slice(destination.as_bytes());
        frame[6..12].copy_from_slice(source.as_bytes());
        frame[12..14].copy_from_slice(&0x0800_u16.to_be_bytes());
        frame
    }

    #[test]
    fn endpointless_preferred_peer_does_not_block_data_plane_startup() {
        let (directory, store, controller, alice_key, bob_key, network_id) = fixture();
        let alice_id = derive_node_id(alice_key.public_key());
        let bob_id = derive_node_id(bob_key.public_key());
        let (local_key, remote_id) = if alice_id < bob_id {
            (&alice_key, bob_id)
        } else {
            (&bob_key, alice_id)
        };
        store
            .publish_endpoints(remote_id, network_id, &[], 130)
            .expect("withdraw remote endpoints");
        let mut plane = NetworkDataPlane::new(
            state(&store, &controller, local_key, network_id),
            MacAddress::from_bytes([0x02, 0, 0, 0, 1, 3]),
            "127.0.0.1:46003".parse().expect("local address"),
            1_200,
            local_key,
            Duration::ZERO,
        )
        .expect("create endpointless-peer data plane");

        assert!(plane
            .start_handshakes(local_key, WALL_TIME, Duration::ZERO)
            .expect("skip endpointless peer")
            .datagrams()
            .is_empty());
        assert!(plane
            .maintain(local_key, WALL_TIME, Duration::from_secs(1))
            .expect("continue waiting for peer endpoint")
            .datagrams()
            .is_empty());
        std::fs::remove_dir_all(directory).expect("remove fixture directory");
    }

    #[test]
    fn authorized_udp_endpoints_receive_distinct_resolvable_paths() {
        let (directory, store, controller, alice_key, bob_key, network_id) = fixture();
        let alice_id = derive_node_id(alice_key.public_key());
        let bob_address: SocketAddr = "127.0.0.1:46002".parse().expect("bob address");
        let primary =
            TransportEndpoint::Udp("127.0.0.1:46001".parse().expect("primary alice address"));
        let alternate =
            TransportEndpoint::Udp("127.0.0.1:46003".parse().expect("alternate alice address"));
        let plane = NetworkDataPlane::new(
            state(&store, &controller, &bob_key, network_id),
            MacAddress::from_bytes([0x02, 0, 0, 0, 1, 4]),
            bob_address,
            1_200,
            &bob_key,
            Duration::ZERO,
        )
        .expect("bob data plane");

        let primary_path = plane
            .resolve_peer_path(alice_id, &primary)
            .expect("primary path");
        let alternate_path = plane
            .resolve_peer_path(alice_id, &alternate)
            .expect("alternate path");
        assert_ne!(primary_path, alternate_path);
        assert_eq!(
            plane
                .transport_endpoint(primary_path)
                .expect("resolve primary path"),
            &primary
        );
        assert_eq!(
            plane
                .transport_endpoint(alternate_path)
                .expect("resolve alternate path"),
            &alternate
        );

        drop(store);
        std::fs::remove_dir_all(directory).expect("remove fixture directory");
    }

    #[test]
    fn reconcile_preserves_paths_until_authoritative_endpoints_change() {
        let (directory, store, controller, alice_key, bob_key, network_id) = fixture();
        let alice_id = derive_node_id(alice_key.public_key());
        let bob_mac = MacAddress::from_bytes([0x02, 0, 0, 0, 1, 5]);
        let bob_address: SocketAddr = "127.0.0.1:46002".parse().expect("bob address");
        let old_endpoint =
            TransportEndpoint::Udp("127.0.0.1:46001".parse().expect("old alice address"));
        let new_address: SocketAddr = "127.0.0.1:46004".parse().expect("new alice address");
        let new_endpoint = TransportEndpoint::Udp(new_address);
        let mut plane = NetworkDataPlane::new(
            state(&store, &controller, &bob_key, network_id),
            bob_mac,
            bob_address,
            1_200,
            &bob_key,
            Duration::ZERO,
        )
        .expect("bob data plane");
        let old_path = plane
            .resolve_peer_path(alice_id, &old_endpoint)
            .expect("old path");

        plane
            .reconcile(
                state(&store, &controller, &bob_key, network_id),
                &bob_key,
                bob_mac,
                Duration::from_secs(1),
            )
            .expect("reconcile unchanged state");
        assert_eq!(
            plane
                .resolve_peer_path(alice_id, &old_endpoint)
                .expect("preserved path"),
            old_path
        );

        store
            .publish_endpoints(
                alice_id,
                network_id,
                &[Endpoint::UdpIpv4 {
                    priority: 0,
                    port: new_address.port(),
                    max_datagram_size: 1_200,
                    address: Ipv4Addr::LOCALHOST,
                }],
                130,
            )
            .expect("replace alice endpoints");
        plane
            .reconcile(
                state(&store, &controller, &bob_key, network_id),
                &bob_key,
                bob_mac,
                Duration::from_secs(2),
            )
            .expect("reconcile replacement state");

        assert!(matches!(
            plane.transport_endpoint(old_path),
            Err(NetworkDataError::UnknownPath { path_id }) if path_id == old_path
        ));
        assert!(matches!(
            plane.resolve_peer_path(alice_id, &old_endpoint),
            Err(NetworkDataError::UnauthorizedEndpoint { .. })
        ));
        let new_path = plane
            .resolve_peer_path(alice_id, &new_endpoint)
            .expect("replacement path");
        assert_ne!(new_path, old_path);
        assert_eq!(
            plane
                .transport_endpoint(new_path)
                .expect("resolve replacement path"),
            &new_endpoint
        );

        drop(store);
        std::fs::remove_dir_all(directory).expect("remove fixture directory");
    }

    #[allow(clippy::too_many_arguments)]
    fn establish(
        alice: &mut NetworkDataPlane,
        bob: &mut NetworkDataPlane,
        alice_key: &IdentitySigningKey,
        bob_key: &IdentitySigningKey,
        alice_address: SocketAddr,
        bob_address: SocketAddr,
        wall_time: u64,
        now: Duration,
    ) {
        let mut pending = alice
            .start_handshakes(alice_key, wall_time, now)
            .expect("start alice")
            .into_parts()
            .0;
        let mut from_alice = true;
        if pending.is_empty() {
            pending = bob
                .start_handshakes(bob_key, wall_time, now)
                .expect("start bob")
                .into_parts()
                .0;
            from_alice = false;
        }
        for _ in 0..8 {
            if pending.is_empty() {
                return;
            }
            let mut next = Vec::new();
            for datagram in pending {
                let output = if from_alice {
                    bob.accept_udp_datagram(
                        alice_address,
                        datagram.bytes(),
                        bob_key,
                        wall_time,
                        now,
                    )
                    .expect("bob accepts handshake")
                } else {
                    alice
                        .accept_udp_datagram(
                            bob_address,
                            datagram.bytes(),
                            alice_key,
                            wall_time,
                            now,
                        )
                        .expect("alice accepts handshake")
                };
                next.extend(output.into_parts().0);
            }
            pending = next;
            from_alice = !from_alice;
        }
        panic!("handshake did not converge within eight flights");
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn network_router_establishes_sessions_and_carries_broadcast_both_ways() {
        let (directory, store, controller, alice_key, bob_key, network_id) = fixture();
        let alice_address: SocketAddr = "127.0.0.1:46001".parse().expect("alice address");
        let bob_address: SocketAddr = "127.0.0.1:46002".parse().expect("bob address");
        let alice_mac = MacAddress::from_bytes([0x02, 0, 0, 0, 1, 1]);
        let bob_mac = MacAddress::from_bytes([0x02, 0, 0, 0, 1, 2]);
        let mut alice = NetworkDataPlane::new(
            state(&store, &controller, &alice_key, network_id),
            alice_mac,
            alice_address,
            1_200,
            &alice_key,
            Duration::ZERO,
        )
        .expect("alice data plane");
        let mut bob = NetworkDataPlane::new(
            state(&store, &controller, &bob_key, network_id),
            bob_mac,
            bob_address,
            1_200,
            &bob_key,
            Duration::ZERO,
        )
        .expect("bob data plane");

        establish(
            &mut alice,
            &mut bob,
            &alice_key,
            &bob_key,
            alice_address,
            bob_address,
            WALL_TIME,
            Duration::ZERO,
        );
        assert_eq!(alice.established_peers().len(), 1);
        assert_eq!(bob.established_peers().len(), 1);

        let broadcast = ethernet_frame(alice_mac, MacAddress::BROADCAST, 0xa1);
        let packets = alice
            .accept_tap_frame(&broadcast, Duration::from_secs(1))
            .expect("route broadcast")
            .into_parts()
            .0;
        assert_eq!(packets.len(), 1);
        assert_eq!(
            alice
                .transport_endpoint(packets[0].path_id())
                .expect("resolve routed datagram path"),
            &TransportEndpoint::Udp(bob_address)
        );
        let received = bob
            .accept_udp_datagram(
                alice_address,
                packets[0].bytes(),
                &bob_key,
                WALL_TIME,
                Duration::from_secs(1),
            )
            .expect("receive broadcast");
        assert_eq!(received.tap_frame(), Some(broadcast.as_slice()));

        let reverse = ethernet_frame(bob_mac, alice_mac, 0xb2);
        let packets = bob
            .accept_tap_frame(&reverse, Duration::from_secs(2))
            .expect("route learned unicast")
            .into_parts()
            .0;
        assert_eq!(packets.len(), 1);
        let received = alice
            .accept_udp_datagram(
                bob_address,
                packets[0].bytes(),
                &alice_key,
                WALL_TIME,
                Duration::from_secs(2),
            )
            .expect("receive reverse frame");
        assert_eq!(received.tap_frame(), Some(reverse.as_slice()));

        let alternate_alice_address: SocketAddr =
            "127.0.0.1:46003".parse().expect("alternate alice address");
        let alternate_frame = ethernet_frame(alice_mac, MacAddress::BROADCAST, 0xc3);
        let alternate_packet = alice
            .accept_tap_frame(&alternate_frame, Duration::from_secs(3))
            .expect("route alternate-source test")
            .into_parts()
            .0
            .remove(0);
        assert!(matches!(
            bob.accept_udp_datagram(
                alternate_alice_address,
                alternate_packet.bytes(),
                &bob_key,
                WALL_TIME,
                Duration::from_secs(3),
            ),
            Err(NetworkDataError::SessionPathMismatch {
                peer_node_id: _,
                expected,
                actual,
            }) if expected != actual
        ));

        let keepalive = alice
            .maintain(&alice_key, WALL_TIME, Duration::from_secs(18))
            .expect("alice keepalive")
            .into_parts()
            .0;
        assert_eq!(keepalive.len(), 1);
        assert_eq!(
            CommonHeader::decode(keepalive[0].bytes())
                .expect("keepalive header")
                .packet_type,
            PacketType::Keepalive
        );
        bob.accept_udp_datagram(
            alice_address,
            keepalive[0].bytes(),
            &bob_key,
            WALL_TIME,
            Duration::from_secs(18),
        )
        .expect("bob accepts keepalive");

        let echo = bob
            .maintain(&bob_key, WALL_TIME, Duration::from_secs(33))
            .expect("bob keepalive echo")
            .into_parts()
            .0;
        assert_eq!(echo.len(), 1);
        alice
            .accept_udp_datagram(
                bob_address,
                echo[0].bytes(),
                &alice_key,
                WALL_TIME,
                Duration::from_secs(33),
            )
            .expect("alice accepts keepalive echo");

        for second in [48, 63, 78] {
            let probes = alice
                .maintain(&alice_key, WALL_TIME, Duration::from_secs(second))
                .expect("unanswered keepalive")
                .into_parts()
                .0;
            assert_eq!(probes.len(), 1);
            assert_eq!(
                CommonHeader::decode(probes[0].bytes())
                    .expect("probe header")
                    .packet_type,
                PacketType::Keepalive
            );
        }
        alice
            .maintain(&alice_key, WALL_TIME, Duration::from_secs(93))
            .expect("keepalive timeout");
        assert!(alice.established_peers().is_empty());

        drop(store);
        std::fs::remove_dir_all(directory).expect("remove fixture directory");
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn routine_rekey_keeps_old_session_receive_only_for_thirty_seconds() {
        let (directory, store, controller, alice_key, bob_key, network_id) = fixture();
        let alice_address: SocketAddr = "127.0.0.1:46001".parse().expect("alice address");
        let bob_address: SocketAddr = "127.0.0.1:46002".parse().expect("bob address");
        let alice_mac = MacAddress::from_bytes([0x02, 0, 0, 0, 2, 1]);
        let bob_mac = MacAddress::from_bytes([0x02, 0, 0, 0, 2, 2]);
        let mut alice = NetworkDataPlane::new(
            state(&store, &controller, &alice_key, network_id),
            alice_mac,
            alice_address,
            1_200,
            &alice_key,
            Duration::ZERO,
        )
        .expect("alice data plane");
        let mut bob = NetworkDataPlane::new(
            state(&store, &controller, &bob_key, network_id),
            bob_mac,
            bob_address,
            1_200,
            &bob_key,
            Duration::ZERO,
        )
        .expect("bob data plane");
        establish(
            &mut alice,
            &mut bob,
            &alice_key,
            &bob_key,
            alice_address,
            bob_address,
            WALL_TIME,
            Duration::ZERO,
        );

        let first_old_frame = ethernet_frame(alice_mac, MacAddress::BROADCAST, 0xd1);
        let first_old_packet = alice
            .accept_tap_frame(&first_old_frame, Duration::from_secs(1))
            .expect("first old packet")
            .into_parts()
            .0
            .remove(0);
        let second_old_frame = ethernet_frame(alice_mac, MacAddress::BROADCAST, 0xd2);
        let second_old_packet = alice
            .accept_tap_frame(&second_old_frame, Duration::from_secs(2))
            .expect("second old packet")
            .into_parts()
            .0
            .remove(0);

        let rekey_wall_time = WALL_TIME + 890;
        let rekey_now = Duration::from_secs(10);
        let alice_start = alice
            .maintain(&alice_key, rekey_wall_time, rekey_now)
            .expect("alice starts rekey")
            .into_parts()
            .0;
        let bob_start = bob
            .maintain(&bob_key, rekey_wall_time, rekey_now)
            .expect("bob starts rekey")
            .into_parts()
            .0;
        let (mut pending, mut from_alice) = if alice_start.is_empty() {
            (bob_start, false)
        } else {
            assert!(bob_start.is_empty());
            (alice_start, true)
        };
        for _ in 0..8 {
            if pending.is_empty() {
                break;
            }
            let mut next = Vec::new();
            for datagram in pending {
                let output = if from_alice {
                    bob.accept_udp_datagram(
                        alice_address,
                        datagram.bytes(),
                        &bob_key,
                        rekey_wall_time,
                        rekey_now,
                    )
                    .expect("bob advances rekey")
                } else {
                    alice
                        .accept_udp_datagram(
                            bob_address,
                            datagram.bytes(),
                            &alice_key,
                            rekey_wall_time,
                            rekey_now,
                        )
                        .expect("alice advances rekey")
                };
                next.extend(output.into_parts().0);
            }
            pending = next;
            from_alice = !from_alice;
        }
        assert!(pending.is_empty());
        assert_eq!(alice.established_peers().len(), 1);
        assert_eq!(bob.established_peers().len(), 1);

        let delayed = bob
            .accept_udp_datagram(
                alice_address,
                first_old_packet.bytes(),
                &bob_key,
                rekey_wall_time,
                Duration::from_secs(11),
            )
            .expect("accept reordered old-session packet");
        assert_eq!(delayed.tap_frame(), Some(first_old_frame.as_slice()));

        bob.maintain(&bob_key, rekey_wall_time + 31, Duration::from_secs(41))
            .expect("expire old receive session");
        assert!(matches!(
            bob.accept_udp_datagram(
                alice_address,
                second_old_packet.bytes(),
                &bob_key,
                rekey_wall_time + 31,
                Duration::from_secs(41),
            ),
            Err(NetworkDataError::NoPeerSession { .. })
        ));

        drop(store);
        std::fs::remove_dir_all(directory).expect("remove fixture directory");
    }
}
