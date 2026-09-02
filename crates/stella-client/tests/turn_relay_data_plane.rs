//! Relay-first encrypted L2 coverage with ICE-driven direct-path upgrade.

#![cfg(windows)]

use std::{
    collections::VecDeque,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    path::PathBuf,
    sync::atomic::{AtomicU64, Ordering},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use stella_client::{
    IceAgent, IceNomination, IcePeerConfig, NetworkDataError, NetworkDataPlane, NetworkState,
    RoutedDatagram, SnapshotInput, TurnCredentials, TurnUdpClient, TurnUdpClientConfig,
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

fn direct_candidate(address: SocketAddr, foundation: u32) -> IceCandidate {
    IceCandidate {
        class: IceCandidateClass::Host,
        carrier: ConnectivityCarrier::DirectUdp,
        priority: 2_130_706_431,
        foundation,
        max_datagram_size: 1_200,
        address,
        related_address: None,
        relay_id: None,
    }
}

fn converge_ice(
    alice_id: stella_common::NodeId,
    bob_id: stella_common::NodeId,
    alice_candidate: IceCandidate,
    bob_candidate: IceCandidate,
) -> (IceNomination, IceNomination) {
    let mut alice = IceAgent::new(
        alice_id,
        10,
        b"AliceUfr",
        b"AlicePassword123456789",
        &[alice_candidate],
    )
    .expect("Alice ICE agent");
    let mut bob = IceAgent::new(
        bob_id,
        20,
        b"BobUfrag",
        b"BobPassword12345678901",
        &[bob_candidate],
    )
    .expect("Bob ICE agent");
    alice
        .upsert_peer(IcePeerConfig {
            node_id: bob_id,
            generation_id: 2,
            tie_breaker: 20,
            username_fragment: b"BobUfrag",
            password: b"BobPassword12345678901",
            candidates: &[bob_candidate],
        })
        .expect("configure Bob ICE generation");
    bob.upsert_peer(IcePeerConfig {
        node_id: alice_id,
        generation_id: 1,
        tie_breaker: 10,
        username_fragment: b"AliceUfr",
        password: b"AlicePassword123456789",
        candidates: &[alice_candidate],
    })
    .expect("configure Alice ICE generation");

    let mut queue = VecDeque::new();
    for transmission in alice
        .poll(Duration::ZERO)
        .expect("poll Alice ICE")
        .into_parts()
        .0
    {
        queue.push_back((true, transmission));
    }
    for transmission in bob
        .poll(Duration::ZERO)
        .expect("poll Bob ICE")
        .into_parts()
        .0
    {
        queue.push_back((false, transmission));
    }
    let mut alice_nomination = None;
    let mut bob_nomination = None;
    for step in 0..32 {
        let Some((from_alice, transmission)) = queue.pop_front() else {
            break;
        };
        let now = Duration::from_millis(step);
        let output = if from_alice {
            bob.accept(alice_candidate.address, transmission.bytes(), now)
                .expect("Bob accepts ICE datagram")
                .expect("Bob ICE component")
        } else {
            alice
                .accept(bob_candidate.address, transmission.bytes(), now)
                .expect("Alice accepts ICE datagram")
                .expect("Alice ICE component")
        };
        let (responses, nominations) = output.into_parts();
        for nomination in nominations {
            if from_alice {
                bob_nomination = Some(nomination);
            } else {
                alice_nomination = Some(nomination);
            }
        }
        for response in responses {
            queue.push_back((!from_alice, response));
        }
        for transmission in alice.poll(now).expect("repoll Alice ICE").into_parts().0 {
            queue.push_back((true, transmission));
        }
        for transmission in bob.poll(now).expect("repoll Bob ICE").into_parts().0 {
            queue.push_back((false, transmission));
        }
        if alice_nomination.is_some() && bob_nomination.is_some() {
            break;
        }
    }
    (
        alice_nomination.expect("Alice direct nomination"),
        bob_nomination.expect("Bob direct nomination"),
    )
}

fn direct_flight(
    sender_plane: &NetworkDataPlane,
    sender_address: SocketAddr,
    receiver_plane: &mut NetworkDataPlane,
    receiver_address: SocketAddr,
    receiver_key: &IdentitySigningKey,
    datagrams: Vec<RoutedDatagram>,
    now: Duration,
) -> (Vec<RoutedDatagram>, Option<Vec<u8>>) {
    let expected_target = TransportEndpoint::Udp(receiver_address);
    let expected_source = TransportEndpoint::Udp(sender_address);
    let mut responses = Vec::new();
    let mut tap_frame = None;
    for datagram in datagrams {
        assert_eq!(
            sender_plane
                .transport_endpoint(datagram.path_id())
                .expect("resolve direct path"),
            &expected_target
        );
        let output = receiver_plane
            .accept_datagram(
                &expected_source,
                datagram.bytes(),
                receiver_key,
                CONTROL_TIME,
                now,
            )
            .expect("accept direct Stella datagram");
        let (next, delivered) = output.into_parts();
        responses.extend(next);
        if delivered.is_some() {
            assert!(tap_frame.is_none());
            tap_frame = delivered;
        }
    }
    (responses, tap_frame)
}

#[tokio::test]
#[allow(
    clippy::too_many_lines,
    reason = "the complete relay-first handshake, ICE upgrade, and grace window are one scenario"
)]
async fn relay_first_session_upgrades_to_direct_and_retires_old_path() {
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
    let alice_direct_address: SocketAddr =
        "192.0.2.61:47001".parse().expect("Alice direct address");
    let bob_direct_address: SocketAddr = "192.0.2.62:47002".parse().expect("Bob direct address");
    let mut alice = NetworkDataPlane::new(
        state(&store, &controller, &alice_key, network_id),
        alice_mac,
        alice_direct_address,
        1_200,
        &alice_key,
        Duration::ZERO,
    )
    .expect("Alice data plane");
    let mut bob = NetworkDataPlane::new(
        state(&store, &controller, &bob_key, network_id),
        bob_mac,
        bob_direct_address,
        1_200,
        &bob_key,
        Duration::ZERO,
    )
    .expect("Bob data plane");
    alice
        .set_relay_carrier_available(ConnectivityCarrier::TurnUdp, true)
        .expect("enable Alice relay path");
    bob.set_relay_carrier_available(ConnectivityCarrier::TurnUdp, true)
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

    let delayed_old_first = ethernet_frame(alice_mac, MacAddress::BROADCAST, 0xc3);
    let delayed_old_first_datagrams = alice
        .accept_tap_frame(&delayed_old_first, Duration::from_secs(3))
        .expect("protect first delayed relay frame")
        .into_parts()
        .0;
    let delayed_old_second = ethernet_frame(alice_mac, MacAddress::BROADCAST, 0xd4);
    let mut delayed_old_second_datagrams = alice
        .accept_tap_frame(&delayed_old_second, Duration::from_secs(4))
        .expect("protect second delayed relay frame")
        .into_parts()
        .0;

    let alice_direct_candidate = direct_candidate(alice_direct_address, 11);
    let bob_direct_candidate = direct_candidate(bob_direct_address, 12);
    let (alice_nomination, bob_nomination) = converge_ice(
        alice_id,
        bob_id,
        alice_direct_candidate,
        bob_direct_candidate,
    );
    assert_eq!(alice_nomination.peer_node_id, bob_id);
    assert_eq!(alice_nomination.address, bob_direct_address);
    assert_eq!(bob_nomination.peer_node_id, alice_id);
    assert_eq!(bob_nomination.address, alice_direct_address);
    alice
        .nominate_direct_path(alice_nomination.peer_node_id, alice_nomination.address)
        .expect("install Alice direct path");
    bob.nominate_direct_path(bob_nomination.peer_node_id, bob_nomination.address)
        .expect("install Bob direct path");

    let upgrade_start = Duration::from_secs(10);
    let mut pending = alice
        .start_handshakes(&alice_key, CONTROL_TIME, upgrade_start)
        .expect("start Alice direct handshake")
        .into_parts()
        .0;
    let mut from_alice = true;
    if pending.is_empty() {
        pending = bob
            .start_handshakes(&bob_key, CONTROL_TIME, upgrade_start)
            .expect("start Bob direct handshake")
            .into_parts()
            .0;
        from_alice = false;
    }
    for flight in 0..8 {
        if pending.is_empty() {
            break;
        }
        let now = upgrade_start.saturating_add(Duration::from_millis(flight));
        let (next, delivered) = if from_alice {
            direct_flight(
                &alice,
                alice_direct_address,
                &mut bob,
                bob_direct_address,
                &bob_key,
                pending,
                now,
            )
        } else {
            direct_flight(
                &bob,
                bob_direct_address,
                &mut alice,
                alice_direct_address,
                &alice_key,
                pending,
                now,
            )
        };
        assert!(delivered.is_none());
        pending = next;
        from_alice = !from_alice;
    }
    assert!(pending.is_empty(), "direct handshake did not converge");

    let direct_broadcast = ethernet_frame(alice_mac, MacAddress::BROADCAST, 0xe5);
    let outbound = alice
        .accept_tap_frame(&direct_broadcast, Duration::from_secs(11))
        .expect("route direct broadcast")
        .into_parts()
        .0;
    let (responses, delivered) = direct_flight(
        &alice,
        alice_direct_address,
        &mut bob,
        bob_direct_address,
        &bob_key,
        outbound,
        Duration::from_secs(11),
    );
    assert!(responses.is_empty());
    assert_eq!(delivered.as_deref(), Some(direct_broadcast.as_slice()));

    let (responses, delivered) = relay_flight(
        &alice,
        &alice_turn,
        &mut bob,
        &bob_turn,
        &bob_key,
        delayed_old_first_datagrams,
        Duration::from_secs(12),
    )
    .await;
    assert!(responses.is_empty());
    assert_eq!(delivered.as_deref(), Some(delayed_old_first.as_slice()));

    let maintenance = bob
        .maintain(&bob_key, CONTROL_TIME + 41, Duration::from_secs(41))
        .expect("expire Bob retired relay session");
    assert!(maintenance.tap_frame().is_none());
    assert_eq!(delayed_old_second_datagrams.len(), 1);
    let delayed_old_second_datagram = delayed_old_second_datagrams.remove(0);
    assert_eq!(
        alice
            .transport_endpoint(delayed_old_second_datagram.path_id())
            .expect("resolve retired relay path"),
        &advertised_endpoint(&bob_turn)
    );
    alice_turn
        .send_to(
            &loopback_endpoint(&bob_turn),
            delayed_old_second_datagram.bytes(),
        )
        .await
        .expect("send expired relay-session datagram");
    let mut received_bytes = vec![0_u8; 1_200];
    let metadata = timeout(
        Duration::from_secs(2),
        bob_turn.receive(&mut received_bytes),
    )
    .await
    .expect("expired relay receive timeout")
    .expect("receive expired relay-session datagram");
    let error = bob
        .accept_datagram(
            &advertised_endpoint(&alice_turn),
            &received_bytes[..metadata.length],
            &bob_key,
            CONTROL_TIME + 41,
            Duration::from_secs(41),
        )
        .expect_err("expired relay session must be rejected");
    assert!(matches!(
        error,
        NetworkDataError::NoPeerSession { peer_node_id } if peer_node_id == alice_id
    ));

    assert!(alice.withdraw_direct_path(bob_id, bob_direct_address));
    assert!(bob.withdraw_direct_path(alice_id, alice_direct_address));
    let recovery_start = Duration::from_secs(42);
    let mut pending = alice
        .start_handshakes(&alice_key, CONTROL_TIME, recovery_start)
        .expect("start Alice relay recovery handshake")
        .into_parts()
        .0;
    let mut from_alice = true;
    if pending.is_empty() {
        pending = bob
            .start_handshakes(&bob_key, CONTROL_TIME, recovery_start)
            .expect("start Bob relay recovery handshake")
            .into_parts()
            .0;
        from_alice = false;
    }
    for flight in 0..8 {
        if pending.is_empty() {
            break;
        }
        let now = recovery_start.saturating_add(Duration::from_millis(flight));
        let (next, delivered) = if from_alice {
            relay_flight(
                &alice,
                &alice_turn,
                &mut bob,
                &bob_turn,
                &bob_key,
                pending,
                now,
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
                now,
            )
            .await
        };
        assert!(delivered.is_none());
        pending = next;
        from_alice = !from_alice;
    }
    assert!(
        pending.is_empty(),
        "relay recovery handshake did not converge"
    );

    let recovered_broadcast = ethernet_frame(alice_mac, MacAddress::BROADCAST, 0xf6);
    let outbound = alice
        .accept_tap_frame(&recovered_broadcast, Duration::from_secs(43))
        .expect("route recovered relay broadcast")
        .into_parts()
        .0;
    let (responses, delivered) = relay_flight(
        &alice,
        &alice_turn,
        &mut bob,
        &bob_turn,
        &bob_key,
        outbound,
        Duration::from_secs(43),
    )
    .await;
    assert!(responses.is_empty());
    assert_eq!(delivered.as_deref(), Some(recovered_broadcast.as_slice()));

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
