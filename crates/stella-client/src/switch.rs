//! Bounded per-network Ethernet learning and forwarding decisions.

use std::{
    collections::{BTreeMap, BTreeSet},
    time::Duration,
};

use stella_common::{EthernetDestination, MacAddress, NodeId};
use stella_proto::NetworkPolicy;
use thiserror::Error;

const ETHERNET_HEADER_LENGTH: usize = 14;
const MAX_LOCAL_DYNAMIC_MACS: usize = 32;
const MAX_REMOTE_MACS: usize = 4_096;
const MAX_REMOTE_MACS_PER_PEER: usize = 256;
const MAC_CONFLICT_DURATION: Duration = Duration::from_secs(30);
const TOKEN_SCALE: u128 = 1_000_000_000;

/// Invalid Ethernet input rejected before forwarding or learning.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
#[non_exhaustive]
pub enum SwitchError {
    /// The complete frame is outside the active signed policy bounds.
    #[error("Ethernet frame length {actual} is outside 14..={maximum}")]
    InvalidFrameLength {
        /// Supplied frame bytes.
        actual: usize,
        /// Signed network maximum.
        maximum: u16,
    },
    /// Ethernet source is zero, broadcast, or multicast.
    #[error("Ethernet source MAC {mac} is not valid unicast")]
    InvalidSourceMac {
        /// Rejected source address.
        mac: MacAddress,
    },
}

/// Flood class with an independent signed-policy token bucket.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FloodClass {
    /// All-ones Ethernet destination.
    Broadcast,
    /// Group destination other than all ones.
    Multicast,
    /// Unicast destination without a usable forwarding entry.
    UnknownUnicast,
}

/// Forwarding result for one valid TAP-originated Ethernet frame.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum TapForwarding {
    /// Destination is a currently learned local MAC.
    Local,
    /// One known eligible remote peer owns the destination.
    Unicast(NodeId),
    /// Replicate independently to the complete eligible peer snapshot.
    Flood {
        /// Ethernet flood classification.
        class: FloodClass,
        /// Stable complete replication set.
        peers: Vec<NodeId>,
    },
    /// The class-specific local-origin rate ceiling dropped the frame.
    RateLimited {
        /// Ethernet flood classification.
        class: FloodClass,
    },
}

/// Ingress result after an authenticated peer frame is considered for learning.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PeerIngress {
    /// Write the frame once to the local TAP and never forward it to peers.
    DeliverToTap,
    /// Drop a remote claim for a currently local source address.
    DropLocalMacConflict,
}

#[derive(Clone, Copy, Debug)]
struct LocalEntry {
    permanent: bool,
    last_seen: Duration,
}

#[derive(Clone, Copy, Debug)]
struct RemoteEntry {
    peer: NodeId,
    last_seen: Duration,
}

#[derive(Clone, Copy, Debug)]
struct TokenBucket {
    rate: u32,
    capacity: u32,
    tokens_scaled: u128,
    last_refill: Duration,
}

impl TokenBucket {
    fn new(rate: u32, capacity: u32, now: Duration) -> Self {
        Self {
            rate,
            capacity,
            tokens_scaled: u128::from(capacity) * TOKEN_SCALE,
            last_refill: now,
        }
    }

    fn take(&mut self, now: Duration) -> bool {
        let elapsed = now.saturating_sub(self.last_refill);
        let refill = elapsed.as_nanos().saturating_mul(u128::from(self.rate));
        let ceiling = u128::from(self.capacity) * TOKEN_SCALE;
        self.tokens_scaled = self.tokens_scaled.saturating_add(refill).min(ceiling);
        self.last_refill = now;
        if self.tokens_scaled < TOKEN_SCALE {
            return false;
        }
        self.tokens_scaled -= TOKEN_SCALE;
        true
    }
}

/// One isolated network's bounded local and remote forwarding state.
pub struct L2Switch {
    policy: NetworkPolicy,
    local: BTreeMap<MacAddress, LocalEntry>,
    remote: BTreeMap<MacAddress, RemoteEntry>,
    contested: BTreeMap<MacAddress, Duration>,
    broadcast: TokenBucket,
    multicast: TokenBucket,
    unknown_unicast: TokenBucket,
}

impl L2Switch {
    /// Creates an empty forwarding database with one permanent TAP MAC.
    ///
    /// # Errors
    ///
    /// Returns [`SwitchError::InvalidSourceMac`] when `primary_mac` is not a
    /// non-zero individual address.
    pub fn new(
        policy: NetworkPolicy,
        primary_mac: MacAddress,
        now: Duration,
    ) -> Result<Self, SwitchError> {
        validate_source(primary_mac)?;
        let mut local = BTreeMap::new();
        local.insert(
            primary_mac,
            LocalEntry {
                permanent: true,
                last_seen: now,
            },
        );
        Ok(Self {
            policy,
            local,
            remote: BTreeMap::new(),
            contested: BTreeMap::new(),
            broadcast: TokenBucket::new(policy.flood_rate, policy.flood_burst, now),
            multicast: TokenBucket::new(policy.flood_rate, policy.flood_burst, now),
            unknown_unicast: TokenBucket::new(policy.flood_rate, policy.flood_burst, now),
        })
    }

    /// Learns the local source and selects peers for one TAP-originated frame.
    ///
    /// `eligible_peers` must be one atomic established-session snapshot. Flood
    /// decisions preserve the entire set and never truncate it.
    ///
    /// # Errors
    ///
    /// Returns [`SwitchError`] for an invalid frame length or source address.
    pub fn forward_tap_frame(
        &mut self,
        frame: &[u8],
        eligible_peers: &BTreeSet<NodeId>,
        now: Duration,
    ) -> Result<TapForwarding, SwitchError> {
        let ethernet = EthernetFrame::parse(frame, self.policy.max_frame_size)?;
        self.expire(now);
        self.learn_local(ethernet.source, now)?;
        if self.local.contains_key(&ethernet.destination) {
            return Ok(TapForwarding::Local);
        }
        let class = match ethernet.destination.destination_class() {
            EthernetDestination::Broadcast => Some(FloodClass::Broadcast),
            EthernetDestination::Multicast => Some(FloodClass::Multicast),
            EthernetDestination::Unicast => None,
        };
        if let Some(class) = class {
            return Ok(self.flood(class, eligible_peers, now));
        }
        if !self.contested.contains_key(&ethernet.destination) {
            if let Some(entry) = self.remote.get(&ethernet.destination) {
                if eligible_peers.contains(&entry.peer) {
                    return Ok(TapForwarding::Unicast(entry.peer));
                }
            }
        }
        Ok(self.flood(FloodClass::UnknownUnicast, eligible_peers, now))
    }

    /// Learns one authenticated remote source before one-time TAP delivery.
    ///
    /// This method never returns a peer-forwarding result, enforcing mandatory
    /// split horizon for every transport-originated frame.
    ///
    /// # Errors
    ///
    /// Returns [`SwitchError`] for an invalid frame length or source address.
    pub fn accept_peer_frame(
        &mut self,
        peer: NodeId,
        frame: &[u8],
        now: Duration,
    ) -> Result<PeerIngress, SwitchError> {
        let ethernet = EthernetFrame::parse(frame, self.policy.max_frame_size)?;
        self.expire(now);
        validate_source(ethernet.source)?;
        if self.local.contains_key(&ethernet.source) {
            return Ok(PeerIngress::DropLocalMacConflict);
        }
        if self.contested.contains_key(&ethernet.source) {
            return Ok(PeerIngress::DeliverToTap);
        }
        if let Some(existing) = self.remote.get_mut(&ethernet.source) {
            if existing.peer == peer {
                existing.last_seen = now;
                return Ok(PeerIngress::DeliverToTap);
            }
            self.remote.remove(&ethernet.source);
            self.insert_contested(ethernet.source, now + MAC_CONFLICT_DURATION);
            return Ok(PeerIngress::DeliverToTap);
        }
        self.make_remote_capacity(peer);
        self.remote.insert(
            ethernet.source,
            RemoteEntry {
                peer,
                last_seen: now,
            },
        );
        Ok(PeerIngress::DeliverToTap)
    }

    /// Immediately removes every forwarding entry learned from one peer.
    pub fn remove_peer(&mut self, peer: NodeId) {
        self.remote.retain(|_, entry| entry.peer != peer);
    }

    /// Expires dynamic local, remote, and contested state at `now`.
    pub fn expire(&mut self, now: Duration) {
        let age = Duration::from_secs(u64::from(self.policy.mac_age_seconds));
        self.local
            .retain(|_, entry| entry.permanent || now.saturating_sub(entry.last_seen) < age);
        self.remote
            .retain(|_, entry| now.saturating_sub(entry.last_seen) < age);
        self.contested.retain(|_, deadline| *deadline > now);
    }

    /// Returns the peer currently selected for one remote MAC, if any.
    #[must_use]
    pub fn remote_peer(&self, mac: MacAddress) -> Option<NodeId> {
        self.remote.get(&mac).map(|entry| entry.peer)
    }

    /// Returns whether one MAC is currently under remote-claim quarantine.
    #[must_use]
    pub fn is_contested(&self, mac: MacAddress) -> bool {
        self.contested.contains_key(&mac)
    }

    fn learn_local(&mut self, source: MacAddress, now: Duration) -> Result<(), SwitchError> {
        validate_source(source)?;
        self.remote.remove(&source);
        self.contested.remove(&source);
        if let Some(entry) = self.local.get_mut(&source) {
            entry.last_seen = now;
            return Ok(());
        }
        let dynamic_count = self.local.values().filter(|entry| !entry.permanent).count();
        if dynamic_count >= MAX_LOCAL_DYNAMIC_MACS {
            if let Some(oldest) = self
                .local
                .iter()
                .filter(|(_, entry)| !entry.permanent)
                .min_by_key(|(mac, entry)| (entry.last_seen, **mac))
                .map(|(mac, _)| *mac)
            {
                self.local.remove(&oldest);
            }
        }
        self.local.insert(
            source,
            LocalEntry {
                permanent: false,
                last_seen: now,
            },
        );
        Ok(())
    }

    fn flood(
        &mut self,
        class: FloodClass,
        eligible_peers: &BTreeSet<NodeId>,
        now: Duration,
    ) -> TapForwarding {
        let bucket = match class {
            FloodClass::Broadcast => &mut self.broadcast,
            FloodClass::Multicast => &mut self.multicast,
            FloodClass::UnknownUnicast => &mut self.unknown_unicast,
        };
        if !bucket.take(now) {
            return TapForwarding::RateLimited { class };
        }
        TapForwarding::Flood {
            class,
            peers: eligible_peers.iter().copied().collect(),
        }
    }

    fn make_remote_capacity(&mut self, peer: NodeId) {
        let peer_count = self
            .remote
            .values()
            .filter(|entry| entry.peer == peer)
            .count();
        if peer_count >= MAX_REMOTE_MACS_PER_PEER {
            self.remove_oldest_remote(Some(peer));
        }
        if self.remote.len() >= MAX_REMOTE_MACS {
            self.remove_oldest_remote(None);
        }
    }

    fn remove_oldest_remote(&mut self, peer: Option<NodeId>) {
        if let Some(oldest) = self
            .remote
            .iter()
            .filter(|(_, entry)| peer.is_none_or(|peer| entry.peer == peer))
            .min_by_key(|(mac, entry)| (entry.last_seen, **mac))
            .map(|(mac, _)| *mac)
        {
            self.remote.remove(&oldest);
        }
    }

    fn insert_contested(&mut self, mac: MacAddress, deadline: Duration) {
        if self.contested.len() >= MAX_REMOTE_MACS && !self.contested.contains_key(&mac) {
            if let Some(oldest) = self
                .contested
                .iter()
                .min_by_key(|(address, expiry)| (**expiry, **address))
                .map(|(address, _)| *address)
            {
                self.contested.remove(&oldest);
            }
        }
        self.contested.insert(mac, deadline);
    }
}

#[derive(Clone, Copy, Debug)]
struct EthernetFrame {
    destination: MacAddress,
    source: MacAddress,
}

impl EthernetFrame {
    fn parse(frame: &[u8], maximum: u16) -> Result<Self, SwitchError> {
        if frame.len() < ETHERNET_HEADER_LENGTH || frame.len() > usize::from(maximum) {
            return Err(SwitchError::InvalidFrameLength {
                actual: frame.len(),
                maximum,
            });
        }
        let destination = MacAddress::from_bytes(frame[..6].try_into().map_err(|_| {
            SwitchError::InvalidFrameLength {
                actual: frame.len(),
                maximum,
            }
        })?);
        let source = MacAddress::from_bytes(frame[6..12].try_into().map_err(|_| {
            SwitchError::InvalidFrameLength {
                actual: frame.len(),
                maximum,
            }
        })?);
        Ok(Self {
            destination,
            source,
        })
    }
}

fn validate_source(source: MacAddress) -> Result<(), SwitchError> {
    if !source.is_valid_unicast() {
        return Err(SwitchError::InvalidSourceMac { mac: source });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::{collections::BTreeSet, time::Duration};

    use stella_common::{MacAddress, NetworkId, NodeId};
    use stella_proto::{ConfidentialityPolicy, NetworkPolicy};

    use super::{FloodClass, L2Switch, PeerIngress, TapForwarding};

    fn policy() -> NetworkPolicy {
        NetworkPolicy {
            confidentiality: ConfidentialityPolicy::Encrypt,
            max_frame_size: 1_514,
            max_flood_peers: 8,
            flood_rate: 2,
            flood_burst: 2,
            mac_age_seconds: 30,
            heartbeat_seconds: 10,
            peer_lease_seconds: 30,
            session_lifetime_seconds: 900,
            reassembly_timeout_ms: 3_000,
            network_id: NetworkId::from_bytes([1; 16]),
            policy_revision: 1,
        }
    }

    fn mac(last: u8) -> MacAddress {
        MacAddress::from_bytes([0x02, 0, 0, 0, 0, last])
    }

    fn indexed_mac(index: u16) -> MacAddress {
        let [high, low] = index.to_be_bytes();
        MacAddress::from_bytes([0x02, 0, 0, 1, high, low])
    }

    fn frame(source: MacAddress, destination: MacAddress) -> [u8; 14] {
        let mut frame = [0_u8; 14];
        frame[..6].copy_from_slice(destination.as_bytes());
        frame[6..12].copy_from_slice(source.as_bytes());
        frame[12..].copy_from_slice(&0x0800_u16.to_be_bytes());
        frame
    }

    fn peers() -> BTreeSet<NodeId> {
        [NodeId::from_bytes([2; 16]), NodeId::from_bytes([3; 16])]
            .into_iter()
            .collect()
    }

    #[test]
    fn unknown_then_learned_unicast_uses_complete_peer_snapshot() {
        let primary = mac(1);
        let remote = mac(2);
        let peer = NodeId::from_bytes([2; 16]);
        let mut switch = L2Switch::new(policy(), primary, Duration::ZERO).expect("switch");
        assert_eq!(
            switch
                .forward_tap_frame(&frame(primary, remote), &peers(), Duration::ZERO)
                .expect("unknown unicast"),
            TapForwarding::Flood {
                class: FloodClass::UnknownUnicast,
                peers: peers().into_iter().collect(),
            }
        );
        assert_eq!(
            switch
                .accept_peer_frame(peer, &frame(remote, primary), Duration::from_secs(1))
                .expect("learn remote"),
            PeerIngress::DeliverToTap
        );
        assert_eq!(
            switch
                .forward_tap_frame(&frame(primary, remote), &peers(), Duration::from_secs(1))
                .expect("known unicast"),
            TapForwarding::Unicast(peer)
        );
    }

    #[test]
    fn flood_classes_have_independent_buckets_and_refill() {
        let primary = mac(1);
        let mut switch = L2Switch::new(policy(), primary, Duration::ZERO).expect("switch");
        let broadcast = frame(primary, MacAddress::BROADCAST);
        let multicast = frame(primary, MacAddress::from_bytes([1, 0, 0x5e, 0, 0, 1]));
        for _accepted in 0..2 {
            assert!(matches!(
                switch
                    .forward_tap_frame(&broadcast, &peers(), Duration::ZERO)
                    .expect("broadcast"),
                TapForwarding::Flood {
                    class: FloodClass::Broadcast,
                    ..
                }
            ));
        }
        assert_eq!(
            switch
                .forward_tap_frame(&broadcast, &peers(), Duration::ZERO)
                .expect("rate limited"),
            TapForwarding::RateLimited {
                class: FloodClass::Broadcast
            }
        );
        assert!(matches!(
            switch
                .forward_tap_frame(&multicast, &peers(), Duration::ZERO)
                .expect("independent multicast bucket"),
            TapForwarding::Flood {
                class: FloodClass::Multicast,
                ..
            }
        ));
        assert!(matches!(
            switch
                .forward_tap_frame(&broadcast, &peers(), Duration::from_millis(500))
                .expect("refilled broadcast"),
            TapForwarding::Flood { .. }
        ));
    }

    #[test]
    fn remote_conflict_quarantines_then_relearns_and_local_mac_wins() {
        let primary = mac(1);
        let claimed = mac(9);
        let first = NodeId::from_bytes([4; 16]);
        let second = NodeId::from_bytes([5; 16]);
        let mut switch = L2Switch::new(policy(), primary, Duration::ZERO).expect("switch");
        switch
            .accept_peer_frame(first, &frame(claimed, primary), Duration::ZERO)
            .expect("first claim");
        switch
            .accept_peer_frame(second, &frame(claimed, primary), Duration::from_secs(1))
            .expect("conflicting claim");
        assert!(switch.remote_peer(claimed).is_none());
        assert!(switch.is_contested(claimed));
        switch
            .accept_peer_frame(first, &frame(claimed, primary), Duration::from_secs(30))
            .expect("contest still active before deadline");
        assert!(switch.remote_peer(claimed).is_none());
        switch
            .accept_peer_frame(first, &frame(claimed, primary), Duration::from_secs(31))
            .expect("relearn after contest");
        assert_eq!(switch.remote_peer(claimed), Some(first));
        assert_eq!(
            switch
                .accept_peer_frame(first, &frame(primary, claimed), Duration::from_secs(33))
                .expect("local conflict"),
            PeerIngress::DropLocalMacConflict
        );
    }

    #[test]
    fn aging_peer_removal_split_horizon_and_invalid_sources_are_enforced() {
        let primary = mac(1);
        let remote = mac(2);
        let peer = NodeId::from_bytes([6; 16]);
        let mut switch = L2Switch::new(policy(), primary, Duration::ZERO).expect("switch");
        assert_eq!(
            switch
                .accept_peer_frame(peer, &frame(remote, MacAddress::BROADCAST), Duration::ZERO)
                .expect("peer broadcast remains local"),
            PeerIngress::DeliverToTap
        );
        switch.remove_peer(peer);
        assert!(switch.remote_peer(remote).is_none());
        switch
            .accept_peer_frame(peer, &frame(remote, primary), Duration::ZERO)
            .expect("relearn");
        switch.expire(Duration::from_secs(30));
        assert!(switch.remote_peer(remote).is_none());
        assert!(switch
            .forward_tap_frame(
                &frame(MacAddress::BROADCAST, primary),
                &peers(),
                Duration::ZERO
            )
            .is_err());
    }

    #[test]
    fn oldest_dynamic_entries_are_evicted_at_local_and_per_peer_bounds() {
        let primary = mac(1);
        let peer = NodeId::from_bytes([7; 16]);
        let mut switch = L2Switch::new(policy(), primary, Duration::ZERO).expect("switch");
        for index in 0..33_u16 {
            assert_eq!(
                switch
                    .forward_tap_frame(
                        &frame(indexed_mac(index), primary),
                        &peers(),
                        Duration::from_millis(u64::from(index)),
                    )
                    .expect("learn local source"),
                TapForwarding::Local
            );
        }
        assert!(matches!(
            switch
                .forward_tap_frame(
                    &frame(primary, indexed_mac(0)),
                    &peers(),
                    Duration::from_secs(1),
                )
                .expect("oldest local destination is unknown"),
            TapForwarding::Flood {
                class: FloodClass::UnknownUnicast,
                ..
            }
        ));

        for index in 100..357_u16 {
            switch
                .accept_peer_frame(
                    peer,
                    &frame(indexed_mac(index), primary),
                    Duration::from_millis(u64::from(index)),
                )
                .expect("learn bounded remote source");
        }
        assert!(switch.remote_peer(indexed_mac(100)).is_none());
        assert_eq!(switch.remote_peer(indexed_mac(356)), Some(peer));
    }
}
