//! Repeatable 32-node and bounded 100-node controller snapshot validation.

use std::{
    path::PathBuf,
    sync::atomic::{AtomicU64, Ordering},
    time::{Duration, Instant},
};

use stella_common::NetworkId;
use stella_crypto::{derive_controller_id, IdentitySeed, IdentitySigningKey};
use stella_proto::{ConfidentialityPolicy, NetworkPolicy, PeerListView, ProtocolVersion};
use stella_server::{
    network_state::encode_network_state,
    store::{AuthorityStore, NetworkRecord, NodeRecord, StoreError},
};

const MAX_SNAPSHOT_BYTES: usize = 1024 * 1024;
const MAX_AGGREGATE_BYTES: usize = 64 * 1024 * 1024;
const TEST_TIME: u64 = 1_800_000_000;

static TEMP_SEQUENCE: AtomicU64 = AtomicU64::new(1);

#[test]
fn regular_room_builds_complete_32_node_views() {
    run_scale_profile(32);
}

#[test]
fn bounded_stress_builds_complete_100_node_views_and_rejects_101st_member() {
    run_scale_profile(100);
}

#[allow(clippy::too_many_lines)]
fn run_scale_profile(node_count: usize) {
    let started = Instant::now();
    let directory = temp_directory(node_count);
    std::fs::create_dir(&directory).expect("create scale test directory");
    let controller = signing_key(0);
    let controller_id = derive_controller_id(controller.public_key());
    let store = AuthorityStore::initialize(&directory.join("authority.redb"), controller_id)
        .expect("initialize authority store");
    let network_id = NetworkId::from_bytes(
        [u8::try_from(node_count).expect("profile fits one byte"); NetworkId::LENGTH],
    );
    let max_flood_peers = u16::try_from(node_count).expect("profile fits policy field");
    let policy = NetworkPolicy {
        confidentiality: ConfidentialityPolicy::Encrypt,
        max_frame_size: 1_514,
        max_flood_peers,
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
        .create_network(
            &NetworkRecord::new(policy, "Scale validation LAN", TEST_TIME)
                .expect("valid scale network"),
        )
        .expect("create scale network");

    let mut node_ids = Vec::with_capacity(node_count);
    for index in 0..node_count {
        let signing = signing_key(index.saturating_add(1));
        let record = NodeRecord::new(
            signing.public_key(),
            &format!("scale-node-{index:03}"),
            TEST_TIME,
        )
        .expect("valid scale node");
        let node_id = record.node_id();
        store.create_node(&record).expect("create scale node");
        store
            .add_member(node_id, network_id, TEST_TIME)
            .expect("activate scale membership");
        store
            .publish_endpoints(node_id, network_id, &[], TEST_TIME)
            .expect("publish online lease");
        node_ids.push(node_id);
    }

    let overflow_signing = signing_key(node_count.saturating_add(1));
    let overflow = NodeRecord::new(
        overflow_signing.public_key(),
        "scale-overflow-node",
        TEST_TIME,
    )
    .expect("valid overflow node");
    store
        .create_node(&overflow)
        .expect("create known overflow node");
    assert!(matches!(
        store.add_member(overflow.node_id(), network_id, TEST_TIME),
        Err(StoreError::NetworkFull { network_id: full }) if full == network_id
    ));
    let setup_elapsed = started.elapsed();

    let verify_started = Instant::now();
    store.verify().expect("verify populated authority store");
    assert_eq!(
        store
            .list_memberships(network_id)
            .expect("list scale memberships")
            .len(),
        node_count
    );
    let verify_elapsed = verify_started.elapsed();

    let mut aggregate_bytes = 0_usize;
    let mut maximum_snapshot_bytes = 0_usize;
    let mut validated_relationships = 0_usize;
    let mut view_elapsed = Duration::ZERO;
    let mut encode_elapsed = Duration::ZERO;
    for node_id in &node_ids {
        let view_started = Instant::now();
        let view = store
            .network_session_view(*node_id, network_id)
            .expect("read coherent scale view");
        view_elapsed = view_elapsed.saturating_add(view_started.elapsed());
        assert_eq!(view.peers().len(), node_count.saturating_sub(1));
        assert!(view
            .peers()
            .iter()
            .all(|peer| peer.node().node_id() != *node_id));
        assert!(view
            .peers()
            .windows(2)
            .all(|pair| pair[0].node().node_id() < pair[1].node().node_id()));

        let encode_started = Instant::now();
        let encoded = encode_network_state(&controller, &view, TEST_TIME, ProtocolVersion::V0_2)
            .expect("encode complete scale snapshot");
        encode_elapsed = encode_elapsed.saturating_add(encode_started.elapsed());
        assert_eq!(encoded.network_id(), network_id);
        let peers = PeerListView::decode(encoded.peer_list()).expect("decode scale peer list");
        assert_eq!(peers.len(), node_count.saturating_sub(1));
        let connectivity_length = encoded
            .connectivity_list()
            .expect("version 0.2 connectivity list")
            .len();
        let snapshot_bytes = encoded
            .peer_list()
            .len()
            .checked_add(connectivity_length)
            .expect("snapshot byte count");
        assert!(snapshot_bytes <= MAX_SNAPSHOT_BYTES);
        aggregate_bytes = aggregate_bytes
            .checked_add(snapshot_bytes)
            .expect("aggregate byte count");
        assert!(aggregate_bytes <= MAX_AGGREGATE_BYTES);
        maximum_snapshot_bytes = maximum_snapshot_bytes.max(snapshot_bytes);
        validated_relationships = validated_relationships
            .checked_add(peers.len().saturating_add(1))
            .expect("relationship count");
    }
    assert_eq!(
        validated_relationships,
        node_count.checked_mul(node_count).expect("profile square")
    );

    eprintln!(
        "membership scale: nodes={node_count} receiver_views={node_count} relationships={validated_relationships} max_snapshot_bytes={maximum_snapshot_bytes} aggregate_bytes={aggregate_bytes} setup_ms={} verify_ms={} view_ms={} encode_ms={} total_ms={}",
        setup_elapsed.as_millis(),
        verify_elapsed.as_millis(),
        view_elapsed.as_millis(),
        encode_elapsed.as_millis(),
        started.elapsed().as_millis()
    );

    drop(store);
    std::fs::remove_dir_all(&directory).expect("remove scale test directory");
}

fn signing_key(index: usize) -> IdentitySigningKey {
    let mut seed = [0x5a_u8; 32];
    seed[..8].copy_from_slice(
        &u64::try_from(index)
            .expect("test key index fits u64")
            .to_be_bytes(),
    );
    IdentitySigningKey::from_seed(&IdentitySeed::from_bytes(seed))
}

fn temp_directory(node_count: usize) -> PathBuf {
    let sequence = TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed);
    std::env::temp_dir().join(format!(
        "stella-membership-scale-{}-{node_count}-{sequence}",
        std::process::id()
    ))
}
