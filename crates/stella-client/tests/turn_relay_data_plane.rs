//! Relay-only encrypted L2 data-plane coverage over the real TURN UDP runtime.

#![cfg(windows)]

use std::{
    net::{IpAddr, Ipv4Addr, SocketAddr},
    path::PathBuf,
    sync::atomic::{AtomicU64, Ordering},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use stella_client::{
    NetworkDataPlane, NetworkState, RoutedDatagram, SnapshotInput, TurnCredentials, TurnUdpClient,
    TurnUdpClientConfig,
};
use stella_common::{MacAddress, NetworkId, RelayId};
use stella_crypto::{derive_controller_id, derive_node_id, IdentitySeed, IdentitySigningKey};
use stella_proto::{
    encode_connectivity_generation, ConfidentialityPolicy, ConnectivityCarrier,
    ConnectivityGenerationRef, IceCandidate, IceCandidateClass, NetworkPolicy, ProtocolVersion,
};
use stella_server::{
    network_state::encode_network_state,
    relay_credentials::RelayCredentialAuthority,
    store::{AuthorityStore, NetworkRecord, NodeRecord},
    turn_relay::{TurnUdpRelay, TurnUdpRelayConfig},
};
use stella_transport::Endpoint as TransportEndpoint;
use tokio::{sync::oneshot, time::timeout};

const CONTROL_TIME: u64 = 130;
const RELAY_PUBLIC_IP: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 200);
const RELATED_PUBLIC_IP: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 201);
static TEMP_SEQUENCE: AtomicU64 = AtomicU64::new(1);

fn temp_directory() -> PathBuf {
    let sequence = TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed);
    std::env::temp_dir().join(format!(
        "stella-turn-data-plane-{}-{sequence}",
        std::process::id()
    ))
}

fn signing_key(marker: u8) -> IdentitySigningKey {
    IdentitySigningKey::from_seed(&IdentitySeed::from_bytes([marker; 32]))
}

fn unix_time() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("test clock after Unix epoch")
        .as_secs()
}

fn network_policy(network_id: NetworkId) -> NetworkPolicy {
    NetworkPolicy {
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
    }
}

fn connectivity_bytes(client: &TurnUdpClient) -> Vec<u8> {
    let candidate = IceCandidate {
        class: IceCandidateClass::Relay,
        carrier: ConnectivityCarrier::TurnUdp,
        priority: 1_000_000,
        foundation: 1,
        max_datagram_size: 1_200,
        address: client.relayed_address(),
        related_address: Some(SocketAddr::new(
            IpAddr::V4(RELATED_PUBLIC_IP),
            client.mapped_address().port(),
        )),
        relay_id: Some(client.relay_id()),
    };
    let candidates = [candidate];
    let generation = ConnectivityGenerationRef::new(
        u64::from(client.relayed_address().port()),
        u64::from(client.relayed_address().port()) + 1,
        CONTROL_TIME,
        CONTROL_TIME + 470,
        b"RelayUfr",
        b"RelayPassword1234567890",
        &candidates,
    )
    .expect("relay generation");
    let mut encoded = vec![0_u8; generation.encoded_len().expect("generation length")];
    encode_connectivity_generation(generation, &mut encoded).expect("encode generation");
    encoded
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
    let encoded = encode_network_state(controller, &view, CONTROL_TIME, ProtocolVersion::V0_2)
        .expect("encode network state");
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
        connectivity_list_bytes: encoded.connectivity_list(),
        now: CONTROL_TIME,
    })
    .expect("validate network state")
}

fn advertised_endpoint(client: &TurnUdpClient) -> TransportEndpoint {
    TransportEndpoint::TurnUdp {
        relay_id: client.relay_id(),
        address: client.relayed_address(),
    }
}

fn loopback_endpoint(client: &TurnUdpClient) -> TransportEndpoint {
    TransportEndpoint::TurnUdp {
        relay_id: client.relay_id(),
        address: SocketAddr::new(
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            client.relayed_address().port(),
        ),
    }
}

async fn relay_flight(
    sender_plane: &NetworkDataPlane,
    sender: &TurnUdpClient,
    receiver_plane: &mut NetworkDataPlane,
    receiver: &TurnUdpClient,
    receiver_key: &IdentitySigningKey,
    datagrams: Vec<RoutedDatagram>,
    now: Duration,
) -> (Vec<RoutedDatagram>, Option<Vec<u8>>) {
    let expected_target = advertised_endpoint(receiver);
    let actual_target = loopback_endpoint(receiver);
    let expected_source = advertised_endpoint(sender);
    let actual_source = loopback_endpoint(sender);
    let mut responses = Vec::new();
    let mut tap_frame = None;
    for datagram in datagrams {
        assert_eq!(
            sender_plane
                .transport_endpoint(datagram.path_id())
                .expect("resolve relay path"),
            &expected_target
        );
        sender
            .send_to(&actual_target, datagram.bytes())
            .await
            .expect("send through TURN relay");
        let mut received_bytes = vec![0_u8; 1_200];
        let metadata = timeout(
            Duration::from_secs(2),
            receiver.receive(&mut received_bytes),
        )
        .await
        .expect("relay receive timeout")
        .expect("receive TURN datagram");
        assert_eq!(metadata.source, actual_source);
        let output = receiver_plane
            .accept_datagram(
                &expected_source,
                &received_bytes[..metadata.length],
                receiver_key,
                CONTROL_TIME,
                now,
            )
            .expect("accept relayed Stella datagram");
        let (next, delivered) = output.into_parts();
        responses.extend(next);
        if delivered.is_some() {
            assert!(tap_frame.is_none());
            tap_frame = delivered;
        }
    }
    (responses, tap_frame)
}

fn ethernet_frame(source: MacAddress, destination: MacAddress, marker: u8) -> Vec<u8> {
    let mut frame = vec![marker; 128];
    frame[..6].copy_from_slice(destination.as_bytes());
    frame[6..12].copy_from_slice(source.as_bytes());
    frame[12..14].copy_from_slice(&0x0800_u16.to_be_bytes());
    frame
}

#[tokio::test]
#[allow(
    clippy::too_many_lines,
    reason = "the complete relay-only handshake and encrypted L2 exchange is one scenario"
)]
async fn relay_only_candidates_establish_and_carry_encrypted_l2_frames() {
    let directory = temp_directory();
    std::fs::create_dir(&directory).expect("create test directory");
    let controller = signing_key(0x61);
    let alice_key = signing_key(0x62);
    let bob_key = signing_key(0x63);
    let alice_id = derive_node_id(alice_key.public_key());
    let bob_id = derive_node_id(bob_key.public_key());
    let network_id = NetworkId::from_bytes([0x64; 16]);
    let relay_id = RelayId::from_bytes([0x65; 16]);
    let store = AuthorityStore::initialize(
        &directory.join("controller.redb"),
        derive_controller_id(controller.public_key()),
    )
    .expect("initialize store");
    store
        .create_network(
            &NetworkRecord::new(network_policy(network_id), "Relay-only LAN", 100)
                .expect("network record"),
        )
        .expect("create network");
    for (key, name) in [(&alice_key, "Alice"), (&bob_key, "Bob")] {
        let record = NodeRecord::new(key.public_key(), name, 100).expect("node record");
        store.create_node(&record).expect("create node");
        store
            .add_member(record.node_id(), network_id, 110)
            .expect("add member");
    }

    let authority =
        RelayCredentialAuthority::new([0x66; 32], 300).expect("relay credential authority");
    let credential_time = unix_time();
    let alice_credential = authority
        .issue(relay_id, alice_id, credential_time)
        .expect("issue Alice relay credential");
    let bob_credential = authority
        .issue(relay_id, bob_id, credential_time)
        .expect("issue Bob relay credential");
    let relay = TurnUdpRelay::bind(
        TurnUdpRelayConfig::new(
            relay_id,
            SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            IpAddr::V4(RELAY_PUBLIC_IP),
        ),
        authority,
    )
    .await
    .expect("bind TURN relay");
    let relay_address = relay.local_address().expect("TURN listener address");
    let (shutdown_sender, shutdown_receiver) = oneshot::channel();
    let relay_task = tokio::spawn(relay.run(async move {
        let _result = shutdown_receiver.await;
    }));
    let turn_config = TurnUdpClientConfig::new(
        relay_id,
        relay_address,
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
    );
    let alice_turn = TurnUdpClient::allocate(
        turn_config,
        TurnCredentials::new(
            alice_credential.username().to_vec(),
            alice_credential.secret().to_vec(),
            alice_credential.expires_at(),
        )
        .expect("Alice TURN credentials"),
    )
    .await
    .expect("allocate Alice relay path");
    let bob_turn = TurnUdpClient::allocate(
        turn_config,
        TurnCredentials::new(
            bob_credential.username().to_vec(),
            bob_credential.secret().to_vec(),
            bob_credential.expires_at(),
        )
        .expect("Bob TURN credentials"),
    )
    .await
    .expect("allocate Bob relay path");
    store
        .publish_connectivity(
            alice_id,
            network_id,
            Some(&connectivity_bytes(&alice_turn)),
            CONTROL_TIME,
        )
        .expect("publish Alice relay candidate");
    store
        .publish_connectivity(
            bob_id,
            network_id,
            Some(&connectivity_bytes(&bob_turn)),
            CONTROL_TIME,
        )
        .expect("publish Bob relay candidate");

    let alice_mac = MacAddress::from_bytes([0x02, 0, 0, 0, 2, 1]);
    let bob_mac = MacAddress::from_bytes([0x02, 0, 0, 0, 2, 2]);
    let mut alice = NetworkDataPlane::new(
        state(&store, &controller, &alice_key, network_id),
        alice_mac,
        "127.0.0.1:47001".parse().expect("Alice direct address"),
        1_200,
        &alice_key,
        Duration::ZERO,
    )
    .expect("Alice data plane");
    let mut bob = NetworkDataPlane::new(
        state(&store, &controller, &bob_key, network_id),
        bob_mac,
        "127.0.0.1:47002".parse().expect("Bob direct address"),
        1_200,
        &bob_key,
        Duration::ZERO,
    )
    .expect("Bob data plane");
    alice
        .set_turn_udp_available(true)
        .expect("enable Alice relay path");
    bob.set_turn_udp_available(true)
        .expect("enable Bob relay path");
    assert_eq!(
        alice.relay_endpoints(),
        vec![advertised_endpoint(&bob_turn)]
    );
    assert_eq!(
        bob.relay_endpoints(),
        vec![advertised_endpoint(&alice_turn)]
    );
    alice_turn
        .prepare_peer(&loopback_endpoint(&bob_turn))
        .await
        .expect("prepare Bob relay path");
    bob_turn
        .prepare_peer(&loopback_endpoint(&alice_turn))
        .await
        .expect("prepare Alice relay path");

    let mut pending = alice
        .start_handshakes(&alice_key, CONTROL_TIME, Duration::ZERO)
        .expect("start Alice handshake")
        .into_parts()
        .0;
    let mut from_alice = true;
    if pending.is_empty() {
        pending = bob
            .start_handshakes(&bob_key, CONTROL_TIME, Duration::ZERO)
            .expect("start Bob handshake")
            .into_parts()
            .0;
        from_alice = false;
    }
    for flight in 0..8 {
        if pending.is_empty() {
            break;
        }
        let (next, delivered) = if from_alice {
            relay_flight(
                &alice,
                &alice_turn,
                &mut bob,
                &bob_turn,
                &bob_key,
                pending,
                Duration::from_millis(flight),
            )
            .await
        } else {
            relay_flight(
                &bob,
                &bob_turn,
                &mut alice,
                &alice_turn,
                &alice_key,
                pending,
                Duration::from_millis(flight),
            )
            .await
        };
        assert!(delivered.is_none());
        pending = next;
        from_alice = !from_alice;
    }
    assert!(pending.is_empty(), "handshake did not converge");
    assert_eq!(alice.established_peers().len(), 1);
    assert!(alice.established_peers().contains(&bob_id));
    assert_eq!(bob.established_peers().len(), 1);
    assert!(bob.established_peers().contains(&alice_id));

    let broadcast = ethernet_frame(alice_mac, MacAddress::BROADCAST, 0xa1);
    let outbound = alice
        .accept_tap_frame(&broadcast, Duration::from_secs(1))
        .expect("route broadcast")
        .into_parts()
        .0;
    let (responses, delivered) = relay_flight(
        &alice,
        &alice_turn,
        &mut bob,
        &bob_turn,
        &bob_key,
        outbound,
        Duration::from_secs(1),
    )
    .await;
    assert!(responses.is_empty());
    assert_eq!(delivered.as_deref(), Some(broadcast.as_slice()));

    let unicast = ethernet_frame(bob_mac, alice_mac, 0xb2);
    let outbound = bob
        .accept_tap_frame(&unicast, Duration::from_secs(2))
        .expect("route learned unicast")
        .into_parts()
        .0;
    let (responses, delivered) = relay_flight(
        &bob,
        &bob_turn,
        &mut alice,
        &alice_turn,
        &alice_key,
        outbound,
        Duration::from_secs(2),
    )
    .await;
    assert!(responses.is_empty());
    assert_eq!(delivered.as_deref(), Some(unicast.as_slice()));

    alice_turn.shutdown().await.expect("shutdown Alice TURN");
    bob_turn.shutdown().await.expect("shutdown Bob TURN");
    let _result = shutdown_sender.send(());
    timeout(Duration::from_secs(2), relay_task)
        .await
        .expect("relay shutdown timeout")
        .expect("relay task join")
        .expect("relay run");
    drop(store);
    std::fs::remove_dir_all(directory).expect("remove test directory");
}
