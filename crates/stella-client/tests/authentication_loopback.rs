//! Windows loopback coverage for client TLS pinning and Stella authentication.

#![cfg(windows)]

use std::{
    net::{Ipv4Addr, SocketAddr},
    path::PathBuf,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
    },
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use stella_client::{
    authenticate_controller, ActiveControl, BearerCredential, ClientError, ControllerTrust,
    Enrollment, SpkiPin,
};
use stella_common::NetworkId;
use stella_crypto::{derive_node_id, IdentitySigningKey};
use stella_proto::{
    ConfidentialityPolicy, ConnectivityCarrier, ConnectivityGenerationRef, Endpoint, IceCandidate,
    IceCandidateClass, NetworkPolicy, ProtocolVersion,
};
use stella_server::{
    active::serve_control_session,
    bootstrap::{initialize_controller, BootstrapOptions},
    config::ServerConfig,
    runtime::{run_controller, SessionError, SessionHandler},
    store::{AuthorityStore, NetworkRecord},
};
use tokio::{
    sync::oneshot,
    time::{sleep, Instant},
};

static TEMP_SEQUENCE: AtomicU64 = AtomicU64::new(1);

fn temp_directory() -> PathBuf {
    let sequence = TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed);
    std::env::temp_dir().join(format!(
        "stella-client-authentication-{}-{sequence}",
        std::process::id()
    ))
}

fn reserve_loopback_address() -> SocketAddr {
    let listener = std::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .expect("reserve loopback controller address");
    listener.local_addr().expect("read reserved address")
}

fn now() -> u64 {
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

#[tokio::test(flavor = "current_thread")]
#[allow(
    clippy::too_many_lines,
    reason = "the ordered end-to-end authentication and join transcript is clearer as one scenario"
)]
async fn pinned_client_enrolls_and_reauthenticates_existing_node() {
    let directory = temp_directory();
    let config_path = directory.join("server.toml");
    let address = reserve_loopback_address();
    let initialized = initialize_controller(
        &config_path,
        &BootstrapOptions {
            listen: address,
            ..BootstrapOptions::default()
        },
    )
    .expect("initialize controller deployment");
    let config = ServerConfig::load(&config_path).expect("load controller configuration");
    let store = AuthorityStore::open(&config.database_path, initialized.controller_id)
        .expect("open authority before server starts");
    let issued_at = now();
    let enrollment_token = store
        .issue_enrollment_token(issued_at, issued_at + 3_600)
        .expect("issue enrollment token");
    let credential = BearerCredential::from_bytes(*enrollment_token.expose_secret());
    let peer_enrollment_token = store
        .issue_enrollment_token(issued_at, issued_at + 3_600)
        .expect("issue peer enrollment token");
    let peer_credential = BearerCredential::from_bytes(*peer_enrollment_token.expose_secret());
    let network_id = NetworkId::from_bytes([0x44; 16]);
    store
        .create_network(
            &NetworkRecord::new(
                network_policy(network_id),
                "Windows loopback LAN",
                issued_at,
            )
            .expect("valid network"),
        )
        .expect("create loopback network");
    let join_token = store
        .issue_join_token(network_id, issued_at, issued_at + 3_600)
        .expect("issue join token");
    let join_credential = BearerCredential::from_bytes(*join_token.expose_secret());
    let peer_join_token = store
        .issue_join_token(network_id, issued_at, issued_at + 3_600)
        .expect("issue peer join token");
    let peer_join_credential = BearerCredential::from_bytes(*peer_join_token.expose_secret());
    drop(store);

    let handler: SessionHandler = Arc::new(|session| {
        Box::pin(async move {
            serve_control_session(session)
                .await
                .map_err(|error| Box::new(error) as SessionError)
        })
    });
    let (shutdown_sender, shutdown_receiver) = oneshot::channel();
    let server_path = config_path.clone();
    let server = tokio::spawn(async move {
        run_controller(
            &server_path,
            async move {
                let _shutdown = shutdown_receiver.await;
            },
            handler,
        )
        .await
    });

    let trust = ControllerTrust::new(
        address,
        String::from("localhost"),
        initialized.controller_id,
        vec![SpkiPin::from_digest(initialized.tls_spki_sha256)],
    )
    .expect("valid controller trust");
    let node_key = IdentitySigningKey::generate().expect("generate node identity");
    let node_id = derive_node_id(node_key.public_key());

    let wrong_trust = ControllerTrust::new(
        address,
        String::from("localhost"),
        initialized.controller_id,
        vec![SpkiPin::from_digest([0xff; 32])],
    )
    .expect("syntactically valid wrong pin");
    assert!(matches!(
        authentication_error_after_listener_ready(&wrong_trust, &node_key).await,
        ClientError::Tls(_)
    ));

    let first_connection = authenticate_after_listener_ready(
        &trust,
        &node_key,
        Enrollment::new(&credential, "Windows loopback client"),
    )
    .await;
    assert_eq!(first_connection.controller_id(), initialized.controller_id);
    assert_eq!(first_connection.node_id(), node_id);
    assert_eq!(first_connection.protocol_version(), ProtocolVersion::V0_2);
    assert!(first_connection.server_time() >= issued_at);
    let mut first = ActiveControl::new(first_connection);
    let first_epoch = first
        .join_network(network_id, Some(&join_credential))
        .await
        .expect("join network and activate initial snapshot")
        .controller_epoch();
    assert!(first
        .network(network_id)
        .expect("active first network")
        .peers()
        .is_empty());
    let initial_revision = first
        .network(network_id)
        .expect("active first network")
        .snapshot_revision();
    assert!(first
        .receive_update_until(Instant::now() + Duration::from_millis(10))
        .await
        .expect("idle update wait remains valid")
        .is_none());
    let endpoint = Endpoint::UdpIpv4 {
        priority: 0,
        port: 45_123,
        max_datagram_size: 1_200,
        address: Ipv4Addr::LOCALHOST,
    };
    let endpoint_revision = first
        .publish_endpoints(network_id, &[endpoint])
        .await
        .expect("publish endpoint and reconcile snapshot")
        .snapshot_revision();
    assert!(endpoint_revision >= initial_revision);
    let candidates = [IceCandidate {
        class: IceCandidateClass::Host,
        carrier: ConnectivityCarrier::DirectUdp,
        priority: u32::MAX - 1,
        foundation: 1,
        max_datagram_size: 1_200,
        address: "192.0.2.10:45123".parse().expect("candidate address"),
        related_address: None,
        relay_id: None,
    }];
    let generation = ConnectivityGenerationRef::new(
        1,
        2,
        issued_at,
        issued_at + 600,
        b"Abcd1234",
        b"Abcdefghijklmnopqrstuv",
        &candidates,
    )
    .expect("valid connectivity generation");
    let connectivity_revision = first
        .publish_connectivity(network_id, Some(generation))
        .await
        .expect("publish connectivity and reconcile snapshot")
        .snapshot_revision();
    assert!(connectivity_revision > endpoint_revision);
    let withdrawn_revision = first
        .publish_connectivity(network_id, None)
        .await
        .expect("withdraw connectivity and reconcile snapshot")
        .snapshot_revision();
    assert!(withdrawn_revision > connectivity_revision);

    let peer_key = IdentitySigningKey::generate().expect("generate peer identity");
    let peer_connection = authenticate_controller(
        &trust,
        &peer_key,
        Some(Enrollment::new(&peer_credential, "Windows loopback peer")),
    )
    .await
    .expect("enroll peer while first node is active");
    let mut peer = ActiveControl::new(peer_connection);
    peer.join_network(network_id, Some(&peer_join_credential))
        .await
        .expect("peer joins loopback network");
    peer.publish_endpoints(
        network_id,
        &[Endpoint::UdpIpv4 {
            priority: 0,
            port: 45_124,
            max_datagram_size: 1_200,
            address: Ipv4Addr::LOCALHOST,
        }],
    )
    .await
    .expect("peer publishes endpoint");
    let peer_candidates = [IceCandidate {
        class: IceCandidateClass::Host,
        carrier: ConnectivityCarrier::DirectUdp,
        priority: u32::MAX - 2,
        foundation: 2,
        max_datagram_size: 1_200,
        address: "192.0.2.11:45124".parse().expect("peer candidate address"),
        related_address: None,
        relay_id: None,
    }];
    let peer_generation = ConnectivityGenerationRef::new(
        3,
        4,
        issued_at,
        issued_at + 600,
        b"Efgh5678",
        b"Zyxwvutsrqponmlkjihgfe",
        &peer_candidates,
    )
    .expect("valid peer connectivity generation");
    peer.publish_connectivity(network_id, Some(peer_generation))
        .await
        .expect("peer publishes connectivity");

    let heartbeat = first.heartbeat().await.expect("heartbeat is acknowledged");
    assert_eq!(heartbeat.counter(), 1);
    assert!(heartbeat.server_time() >= issued_at);
    assert_eq!(heartbeat.updated_networks(), &[network_id]);
    assert_eq!(
        first
            .network(network_id)
            .expect("heartbeat restored active network")
            .peers()
            .len(),
        1
    );
    let peer_id = derive_node_id(peer_key.public_key());
    let peer_connectivity = first
        .network(network_id)
        .expect("heartbeat restored active network")
        .peers()
        .get(&peer_id)
        .expect("peer exists")
        .connectivity()
        .expect("peer connectivity exists");
    assert_eq!(peer_connectivity.generation_id(), 3);
    assert_eq!(peer_connectivity.password(), b"Zyxwvutsrqponmlkjihgfe");
    let reconciled_epoch = first
        .network(network_id)
        .expect("heartbeat restored active network")
        .controller_epoch();
    assert!(reconciled_epoch > first_epoch);
    drop(peer);
    drop(first);

    let second_connection = authenticate_controller(&trust, &node_key, None)
        .await
        .expect("known node authenticates without enrollment material");
    assert_eq!(second_connection.node_id(), node_id);
    let mut second = ActiveControl::new(second_connection);
    let repeated_state = second
        .join_network(network_id, None)
        .await
        .expect("existing membership rejoins without a token");
    assert_eq!(repeated_state.controller_epoch(), reconciled_epoch);
    assert!(matches!(
        second
            .join_network(NetworkId::from_bytes([0x45; 16]), None)
            .await,
        Err(ClientError::NetworkRequestRejected {
            operation: "join",
            status: 200,
            ..
        })
    ));
    let leave_epoch = second
        .leave_network(network_id)
        .await
        .expect("authoritatively leave network");
    assert!(leave_epoch > reconciled_epoch);
    assert!(second.network(network_id).is_none());
    assert_eq!(
        second
            .leave_network(network_id)
            .await
            .expect("repeat leave is idempotent"),
        leave_epoch
    );
    drop(second);

    let third_connection = authenticate_controller(&trust, &node_key, None)
        .await
        .expect("left node remains enrolled");
    let mut third = ActiveControl::new(third_connection);
    assert!(matches!(
        third.join_network(network_id, None).await,
        Err(ClientError::NetworkRequestRejected {
            operation: "join",
            status: 111,
            ..
        })
    ));
    drop(third);

    shutdown_sender.send(()).expect("request server shutdown");
    server
        .await
        .expect("join server task")
        .expect("server shuts down cleanly");
    std::fs::remove_dir_all(&directory).expect("remove test deployment");
}

async fn authentication_error_after_listener_ready(
    trust: &ControllerTrust,
    identity: &IdentitySigningKey,
) -> ClientError {
    for _attempt in 0..100 {
        match authenticate_controller(trust, identity, None).await {
            Ok(_) => panic!("authentication unexpectedly accepted the wrong pin"),
            Err(ClientError::Connect { .. }) => sleep(Duration::from_millis(10)).await,
            Err(error) => return error,
        }
    }
    authenticate_controller(trust, identity, None)
        .await
        .expect_err("wrong pin is rejected after the listener starts")
}

async fn authenticate_after_listener_ready(
    trust: &ControllerTrust,
    identity: &IdentitySigningKey,
    enrollment: Enrollment<'_>,
) -> stella_client::AuthenticatedControl {
    for _attempt in 0..100 {
        match authenticate_controller(trust, identity, Some(enrollment)).await {
            Ok(session) => return session,
            Err(ClientError::Connect { .. }) => sleep(Duration::from_millis(10)).await,
            Err(error) => panic!("unexpected authentication failure: {error}"),
        }
    }
    authenticate_controller(trust, identity, Some(enrollment))
        .await
        .expect("controller listener becomes ready")
}
