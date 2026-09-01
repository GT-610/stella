//! Canonical grants, policy, and peer-list encoding from one authority view.

use std::fmt;

use stella_common::NetworkId;
use stella_crypto::{derive_controller_id, IdentitySigningKey};
use stella_proto::{
    encode_connectivity_list_from_encoded_records, encode_peer_list, CodecError,
    ConnectivityListView, PeerListView, PeerRecordRef, ProtocolVersion, MEMBERSHIP_GRANT_LENGTH,
    NETWORK_POLICY_LENGTH,
};
use thiserror::Error;
use zeroize::Zeroizing;

use crate::{
    authorization::{issue_membership_grant, AuthorizationError},
    store::NetworkSessionView,
};

/// Fully encoded network state derived from one coherent authority view.
pub struct EncodedNetworkState {
    network_id: NetworkId,
    controller_epoch: u64,
    snapshot_revision: u64,
    local_grant: [u8; MEMBERSHIP_GRANT_LENGTH],
    policy: [u8; NETWORK_POLICY_LENGTH],
    peer_list: Vec<u8>,
    connectivity_list: Option<Zeroizing<Vec<u8>>>,
}

impl EncodedNetworkState {
    /// Returns the virtual network represented by this state.
    #[must_use]
    pub const fn network_id(&self) -> NetworkId {
        self.network_id
    }

    /// Returns the coherent non-zero controller epoch.
    #[must_use]
    pub const fn controller_epoch(&self) -> u64 {
        self.controller_epoch
    }

    /// Returns the coherent non-zero peer snapshot revision.
    #[must_use]
    pub const fn snapshot_revision(&self) -> u64 {
        self.snapshot_revision
    }

    /// Borrows the local node's canonical signed membership grant.
    #[must_use]
    pub const fn local_grant(&self) -> &[u8; MEMBERSHIP_GRANT_LENGTH] {
        &self.local_grant
    }

    /// Borrows the exact canonical network-policy bytes.
    #[must_use]
    pub const fn policy(&self) -> &[u8; NETWORK_POLICY_LENGTH] {
        &self.policy
    }

    /// Borrows the complete node-ID-sorted peer-list encoding.
    #[must_use]
    pub fn peer_list(&self) -> &[u8] {
        &self.peer_list
    }

    /// Borrows the complete node-ID-sorted version 0.2 connectivity list.
    ///
    /// Version 0.1 state has no connectivity list.
    #[must_use]
    pub fn connectivity_list(&self) -> Option<&[u8]> {
        self.connectivity_list
            .as_ref()
            .map(|encoded| encoded.as_slice())
    }
}

impl fmt::Debug for EncodedNetworkState {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("EncodedNetworkState")
            .field("network_id", &self.network_id)
            .field("controller_epoch", &self.controller_epoch)
            .field("snapshot_revision", &self.snapshot_revision)
            .field("peer_list_length", &self.peer_list.len())
            .field(
                "connectivity_list_length",
                &self.connectivity_list.as_ref().map(|encoded| encoded.len()),
            )
            .finish_non_exhaustive()
    }
}

/// Signs and encodes one coherent authority view for control-plane delivery.
///
/// The local grant, every peer grant, policy bytes, epoch, revision, and peer
/// endpoint set all originate from `view`. The peer list excludes the local
/// node because the store view already enforces that invariant.
///
/// # Errors
///
/// Returns [`NetworkStateError`] for authorization, canonical encoding,
/// checked-length, or bounded allocation failure.
pub fn encode_network_state(
    controller_identity: &IdentitySigningKey,
    view: &NetworkSessionView,
    now: u64,
    version: ProtocolVersion,
) -> Result<EncodedNetworkState, NetworkStateError> {
    let network = view.network();
    let local_grant = issue_membership_grant(
        controller_identity,
        view.local_node(),
        network,
        view.local_membership(),
        now,
    )?;
    let mut policy = [0_u8; NETWORK_POLICY_LENGTH];
    network.policy().encode(&mut policy)?;

    let mut peer_grants = Vec::new();
    peer_grants
        .try_reserve_exact(view.peers().len())
        .map_err(|_| NetworkStateError::AllocationFailed {
            requested: view.peers().len(),
        })?;
    for peer in view.peers() {
        peer_grants.push(issue_membership_grant(
            controller_identity,
            peer.node(),
            network,
            peer.membership(),
            now,
        )?);
    }

    let mut records = Vec::new();
    records.try_reserve_exact(view.peers().len()).map_err(|_| {
        NetworkStateError::AllocationFailed {
            requested: view.peers().len(),
        }
    })?;
    let mut peer_list_length = 4_usize;
    for (peer, grant) in view.peers().iter().zip(&peer_grants) {
        let record = PeerRecordRef::new(
            peer.node().node_id(),
            *peer.node().public_key().as_bytes(),
            grant,
            peer.endpoint_lease().endpoints(),
        )?;
        peer_list_length = peer_list_length
            .checked_add(record.encoded_len()?)
            .ok_or(NetworkStateError::LengthOverflow)?;
        records.push(record);
    }

    let mut peer_list = Vec::new();
    peer_list.try_reserve_exact(peer_list_length).map_err(|_| {
        NetworkStateError::AllocationFailed {
            requested: peer_list_length,
        }
    })?;
    peer_list.resize(peer_list_length, 0);
    let encoded_length = encode_peer_list(&records, &mut peer_list)?;
    peer_list.truncate(encoded_length);
    PeerListView::decode(&peer_list)?.validate_context(
        network.policy().max_flood_peers,
        view.local_node().node_id(),
        network.network_id(),
        derive_controller_id(controller_identity.public_key()),
        network.controller_epoch(),
    )?;

    let connectivity_list = match version {
        ProtocolVersion::V0_1 => None,
        ProtocolVersion::V0_2 => Some(encode_connectivity_list(view)?),
        unsupported => {
            return Err(NetworkStateError::UnsupportedProtocolVersion {
                major: unsupported.major,
                minor: unsupported.minor,
            });
        }
    };

    Ok(EncodedNetworkState {
        network_id: network.network_id(),
        controller_epoch: network.controller_epoch(),
        snapshot_revision: network.snapshot_revision(),
        local_grant,
        policy,
        peer_list,
        connectivity_list,
    })
}

fn encode_connectivity_list(
    view: &NetworkSessionView,
) -> Result<Zeroizing<Vec<u8>>, NetworkStateError> {
    let record_count = view
        .peers()
        .iter()
        .filter(|peer| peer.connectivity().is_some())
        .count();
    let mut records = Vec::new();
    records
        .try_reserve_exact(record_count)
        .map_err(|_| NetworkStateError::AllocationFailed {
            requested: record_count,
        })?;
    let mut encoded_length = 4_usize;
    for peer in view.peers() {
        let Some(connectivity) = peer.connectivity() else {
            continue;
        };
        let encoded_record = connectivity.encoded_record();
        encoded_length = encoded_length
            .checked_add(encoded_record.len())
            .ok_or(NetworkStateError::LengthOverflow)?;
        records.push(encoded_record);
    }

    let mut encoded = Zeroizing::new(Vec::new());
    encoded
        .try_reserve_exact(encoded_length)
        .map_err(|_| NetworkStateError::AllocationFailed {
            requested: encoded_length,
        })?;
    encoded.resize(encoded_length, 0);
    let actual_length = encode_connectivity_list_from_encoded_records(&records, &mut encoded)?;
    encoded.truncate(actual_length);
    ConnectivityListView::decode(&encoded)?;
    Ok(encoded)
}

/// Failure while signing or encoding one coherent network state view.
#[derive(Debug, Error)]
pub enum NetworkStateError {
    /// Persisted records could not produce a valid signed grant.
    #[error(transparent)]
    Authorization(#[from] AuthorizationError),
    /// Canonical policy, grant, peer-record, or peer-list encoding failed.
    #[error(transparent)]
    Codec(#[from] CodecError),
    /// A bounded output allocation could not be reserved.
    #[error("could not allocate {requested} bytes or entries for network state")]
    AllocationFailed {
        /// Requested byte or entry count.
        requested: usize,
    },
    /// Checked peer or connectivity-list length arithmetic overflowed.
    #[error("network-state list length arithmetic overflowed")]
    LengthOverflow,
    /// The caller requested an operational version this encoder does not know.
    #[error("network-state encoding does not support protocol version {major}.{minor}")]
    UnsupportedProtocolVersion {
        /// Unsupported major version.
        major: u8,
        /// Unsupported minor version.
        minor: u8,
    },
}

#[cfg(all(test, windows))]
mod tests {
    use std::{
        net::Ipv4Addr,
        path::PathBuf,
        sync::atomic::{AtomicU64, Ordering},
    };

    use stella_common::NetworkId;
    use stella_crypto::{derive_controller_id, IdentitySeed, IdentitySigningKey};
    use stella_proto::{
        encode_connectivity_generation, ConfidentialityPolicy, ConnectivityCarrier,
        ConnectivityGenerationRef, ConnectivityListView, Endpoint, IceCandidate, IceCandidateClass,
        MembershipGrantView, NetworkPolicy, PeerListView, ProtocolVersion, NETWORK_POLICY_LENGTH,
    };

    use super::encode_network_state;
    use crate::store::{AuthorityStore, NetworkRecord, NodeRecord};

    static TEMP_SEQUENCE: AtomicU64 = AtomicU64::new(1);

    fn signing_key(seed: u8) -> IdentitySigningKey {
        IdentitySigningKey::from_seed(&IdentitySeed::from_bytes([seed; 32]))
    }

    fn test_store() -> (PathBuf, AuthorityStore, IdentitySigningKey, NetworkId) {
        let sequence = TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        let directory = std::env::temp_dir().join(format!(
            "stella-network-state-{}-{sequence}",
            std::process::id()
        ));
        std::fs::create_dir(&directory).expect("create test directory");
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
            .create_network(&NetworkRecord::new(policy, "Encoded LAN", 100).expect("valid network"))
            .expect("create network");
        (directory, store, controller, network_id)
    }

    fn connectivity_generation(created_at: u64) -> Vec<u8> {
        let candidates = [IceCandidate {
            class: IceCandidateClass::Host,
            carrier: ConnectivityCarrier::DirectUdp,
            priority: u32::MAX - 1,
            foundation: 1,
            max_datagram_size: 1_200,
            address: "192.0.2.94:4242".parse().expect("candidate address"),
            related_address: None,
            relay_id: None,
        }];
        let generation = ConnectivityGenerationRef::new(
            95,
            96,
            created_at,
            created_at + 600,
            b"Abcd1234",
            b"Abcdefghijklmnopqrstuv",
            &candidates,
        )
        .expect("valid generation");
        let mut encoded = vec![0; generation.encoded_len().expect("generation length")];
        encode_connectivity_generation(generation, &mut encoded).expect("encode generation");
        encoded
    }

    #[test]
    fn coherent_view_encodes_local_and_online_peer_grants() {
        let (directory, store, controller, network_id) = test_store();
        let local =
            NodeRecord::new(signing_key(93).public_key(), "Local", 100).expect("valid local node");
        let peer =
            NodeRecord::new(signing_key(94).public_key(), "Peer", 100).expect("valid peer node");
        store.create_node(&local).expect("create local node");
        store.create_node(&peer).expect("create peer node");
        store
            .add_member(local.node_id(), network_id, 110)
            .expect("add local member");
        store
            .add_member(peer.node_id(), network_id, 110)
            .expect("add peer member");
        let endpoint = Endpoint::UdpIpv4 {
            priority: 0,
            port: 4_242,
            max_datagram_size: 1_200,
            address: Ipv4Addr::new(192, 0, 2, 94),
        };
        store
            .publish_endpoints(peer.node_id(), network_id, &[endpoint], 120)
            .expect("publish peer endpoint");
        let generation = connectivity_generation(120);
        store
            .publish_connectivity(peer.node_id(), network_id, Some(&generation), 120)
            .expect("publish peer connectivity");
        let view = store
            .network_session_view(local.node_id(), network_id)
            .expect("read coherent view");

        let encoded = encode_network_state(&controller, &view, 200, ProtocolVersion::V0_1)
            .expect("encode version 0.1 state");
        let encoded_v0_2 = encode_network_state(&controller, &view, 200, ProtocolVersion::V0_2)
            .expect("encode version 0.2 state");
        assert_eq!(encoded.network_id(), network_id);
        assert_eq!(
            encoded.controller_epoch(),
            view.network().controller_epoch()
        );
        assert_eq!(
            encoded.snapshot_revision(),
            view.network().snapshot_revision()
        );
        let local_grant = MembershipGrantView::decode(encoded.local_grant())
            .expect("decode local grant")
            .grant();
        assert_eq!(local_grant.node_id, local.node_id());
        assert_eq!(local_grant.not_before, 200);
        assert_eq!(local_grant.not_after, 1_100);
        let policy = NetworkPolicy::decode(encoded.policy()).expect("decode policy");
        let mut policy_bytes = [0_u8; NETWORK_POLICY_LENGTH];
        policy.encode(&mut policy_bytes).expect("re-encode policy");
        assert_eq!(&policy_bytes, encoded.policy());
        assert!(encoded.connectivity_list().is_none());
        assert_eq!(encoded_v0_2.peer_list(), encoded.peer_list());
        assert_eq!(
            encoded_v0_2.snapshot_revision(),
            encoded.snapshot_revision()
        );
        let connectivity = ConnectivityListView::decode(
            encoded_v0_2
                .connectivity_list()
                .expect("version 0.2 connectivity list"),
        )
        .expect("decode connectivity list");
        assert_eq!(connectivity.len(), 1);
        let connectivity_record = connectivity.records().next().expect("connectivity record");
        assert_eq!(connectivity_record.node_id(), peer.node_id());
        assert_eq!(connectivity_record.generation().generation_id(), 95);
        let peers = PeerListView::decode(encoded.peer_list()).expect("decode peer list");
        assert_eq!(peers.len(), 1);
        let encoded_peer = peers.peers().next().expect("peer exists");
        assert_eq!(encoded_peer.node_id(), peer.node_id());
        assert_eq!(encoded_peer.endpoints().collect::<Vec<_>>(), vec![endpoint]);
        peers
            .validate_context(
                policy.max_flood_peers,
                local.node_id(),
                network_id,
                derive_controller_id(controller.public_key()),
                encoded.controller_epoch(),
            )
            .expect("peer list matches enclosing state");
        drop(store);
        std::fs::remove_dir_all(directory).expect("remove test directory");
    }
}
