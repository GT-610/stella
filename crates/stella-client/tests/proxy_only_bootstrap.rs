//! Proxy-only controller bootstrap through controller-issued WSS relay data.
//!
//! Windows-only. This target intentionally compiles to an empty test binary
//! on other platforms; run it on Windows.

#![cfg(windows)]

mod common;

use std::{
    fmt::Write as _,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    sync::Arc,
    time::Duration,
};

use stella_client::{
    authenticate_controller, BearerCredential, ControllerTrust, Enrollment, RelayServiceState,
    SpkiPin, TurnCredentials, TurnWebSocketClient, TurnWebSocketClientConfig,
};
use stella_common::RelayId;
use stella_crypto::IdentitySigningKey;
use stella_proto::RelayCarrierMask;
use stella_server::{
    active::serve_control_session,
    bootstrap::{initialize_controller, BootstrapOptions},
    config::ServerConfig,
    relay_credentials::{create_relay_credential_key, load_relay_credential_authority},
    runtime::{run_controller, SessionError, SessionHandler},
    store::AuthorityStore,
    tls::load_tls_server_config,
    turn_relay::{TurnTcpRelayConfig, TurnWebSocketRelay},
};
use tokio::{
    io::{copy_bidirectional, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    sync::oneshot,
    time::timeout,
};

#[tokio::test(flavor = "current_thread")]
#[allow(
    clippy::too_many_lines,
    reason = "controller bootstrap, credential issuance, two CONNECT tunnels, and WSS relay data form one scenario"
)]
async fn controller_issued_credentials_drive_proxied_websocket_relay_data() {
    let directory = common::temp_directory("stella-proxy-only-bootstrap");
    let config_path = directory.join("server.toml");
    let controller_address = common::reserve_loopback_address();
    let relay_address = common::reserve_loopback_address();
    let relay_id = RelayId::from_bytes([0x51; 16]);
    let initialized = initialize_controller(
        &config_path,
        &BootstrapOptions {
            listen: controller_address,
            ..BootstrapOptions::default()
        },
    )
    .expect("initialize proxy-only controller deployment");
    let relay_key_path = directory.join("secrets/relay-credential.key");
    create_relay_credential_key(&relay_key_path).expect("create protected relay credential key");
    let relay_pin = SpkiPin::from_digest(initialized.tls_spki_sha256);
    let mut configuration =
        std::fs::read_to_string(&config_path).expect("read initialized controller configuration");
    write!(
        configuration,
        "\n[connectivity]\nrevision = 1\ncredential_key = \"secrets/relay-credential.key\"\ncredential_lifetime_seconds = 300\nstun_servers = [\"192.0.2.20:3478\"]\n\n[[connectivity.relays]]\nid = \"{relay_id}\"\npriority = 0\nhostname = \"localhost\"\ntls_server_name = \"localhost\"\nregion = \"proxy-only\"\nsecure_websocket = {}\naddresses = [\"127.0.0.1\"]\nspki_pins = [\"{relay_pin}\"]\n",
        relay_address.port()
    )
    .expect("append proxy-only connectivity config");
    std::fs::write(&config_path, configuration).expect("write proxy-only connectivity config");
    let config = ServerConfig::load(&config_path).expect("load proxy-only controller config");
    let relay_settings = config
        .turn_websocket_relay_settings(relay_id)
        .expect("resolve WebSocket relay settings");

    let store = AuthorityStore::open(&config.database_path, initialized.controller_id)
        .expect("open authority before proxy-only controller starts");
    let issued_at = common::unix_time();
    let enrollment_a = store
        .issue_enrollment_token(issued_at, issued_at + 3_600)
        .expect("issue A enrollment token");
    let enrollment_b = store
        .issue_enrollment_token(issued_at, issued_at + 3_600)
        .expect("issue B enrollment token");
    let credential_a = BearerCredential::from_bytes(*enrollment_a.expose_secret());
    let credential_b = BearerCredential::from_bytes(*enrollment_b.expose_secret());
    drop(store);

    let relay_authority = load_relay_credential_authority(
        &relay_settings.credential_key_path,
        relay_settings.credential_lifetime_seconds,
    )
    .expect("load shared relay credential authority");
    let relay_tls =
        load_tls_server_config(&config.tls_certificate_path, &config.tls_private_key_path)
            .expect("load relay TLS from controller identity");
    let mut relay_config = TurnTcpRelayConfig::new(
        relay_id,
        relay_address,
        IpAddr::V4(Ipv4Addr::LOCALHOST),
        IpAddr::V4(Ipv4Addr::LOCALHOST),
    );
    relay_config.max_datagram_size = relay_settings.max_datagram_size;
    relay_config.allocation_lifetime_seconds = relay_settings.allocation_lifetime_seconds;
    relay_config.idle_timeout_seconds = relay_settings.idle_timeout_seconds;
    let relay = TurnWebSocketRelay::bind(
        relay_config,
        relay_authority,
        relay_tls,
        Duration::from_secs(2),
    )
    .await
    .expect("bind proxy-only WebSocket relay");
    assert_eq!(
        relay.local_address().expect("WebSocket relay address"),
        relay_address
    );
    let (relay_shutdown_sender, relay_shutdown_receiver) = oneshot::channel();
    let relay_task = tokio::spawn(relay.run(async move {
        let _shutdown = relay_shutdown_receiver.await;
    }));

    let handler: SessionHandler = Arc::new(|session| {
        Box::pin(async move {
            serve_control_session(session)
                .await
                .map_err(|error| Box::new(error) as SessionError)
        })
    });
    let (controller_shutdown_sender, controller_shutdown_receiver) = oneshot::channel();
    let server_path = config_path.clone();
    let controller_task = tokio::spawn(async move {
        run_controller(
            &server_path,
            async move {
                let _shutdown = controller_shutdown_receiver.await;
            },
            handler,
        )
        .await
    });
    common::wait_for_tcp_listener(controller_address).await;

    let proxy_listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("bind shared explicit proxy");
    let proxy_address = proxy_listener.local_addr().expect("shared proxy address");
    let controller_request = common::canonical_connect_request(controller_address.port());
    let relay_request = common::canonical_connect_request(relay_address.port());
    let proxy_task = tokio::spawn(async move {
        let mut controller_tunnels = 0_u8;
        let mut relay_tunnels = 0_u8;
        let mut tunnels = Vec::new();
        for _connection in 0..4 {
            let (mut downstream, _client) = proxy_listener
                .accept()
                .await
                .expect("accept proxy-only connection");
            let request = common::read_connect_request(&mut downstream).await;
            let upstream_address = if request == controller_request {
                controller_tunnels = controller_tunnels.saturating_add(1);
                controller_address
            } else if request == relay_request {
                relay_tunnels = relay_tunnels.saturating_add(1);
                relay_address
            } else {
                panic!(
                    "unexpected CONNECT request: {}",
                    String::from_utf8_lossy(&request)
                );
            };
            tunnels.push(tokio::spawn(async move {
                let mut upstream = TcpStream::connect(upstream_address)
                    .await
                    .expect("connect proxy to selected upstream");
                downstream
                    .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                    .await
                    .expect("accept proxy-only CONNECT");
                copy_bidirectional(&mut downstream, &mut upstream)
                    .await
                    .expect("forward proxy-only TLS tunnel");
            }));
        }
        assert_eq!(controller_tunnels, 2);
        assert_eq!(relay_tunnels, 2);
        for tunnel in tunnels {
            tunnel.await.expect("proxy-only tunnel task");
        }
    });

    let trust = ControllerTrust::new(
        controller_address,
        String::from("localhost"),
        initialized.controller_id,
        vec![relay_pin],
    )
    .expect("valid proxy-only controller trust")
    .with_https_proxy(Some(proxy_address));
    let node_a = IdentitySigningKey::generate().expect("generate A identity");
    let node_b = IdentitySigningKey::generate().expect("generate B identity");
    let control_a = authenticate_controller(
        &trust,
        &node_a,
        Some(Enrollment::new(&credential_a, "Proxy-only A")),
    )
    .await
    .expect("authenticate A through shared proxy");
    let connectivity_a = control_a
        .connectivity_config()
        .expect("A receives connectivity config")
        .clone();
    drop(control_a);
    let control_b = authenticate_controller(
        &trust,
        &node_b,
        Some(Enrollment::new(&credential_b, "Proxy-only B")),
    )
    .await
    .expect("authenticate B through shared proxy");
    let connectivity_b = control_b
        .connectivity_config()
        .expect("B receives connectivity config")
        .clone();
    drop(control_b);

    let service_a = only_websocket_service(&connectivity_a);
    let service_b = only_websocket_service(&connectivity_b);
    assert_eq!(service_a.relay_id(), relay_id);
    assert_eq!(service_b.relay_id(), relay_id);
    assert_ne!(
        service_a.credential_username(),
        service_b.credential_username()
    );
    assert_ne!(service_a.credential_secret(), service_b.credential_secret());
    let client_a = allocate_from_controller(service_a, proxy_address)
        .await
        .expect("allocate A from controller-issued relay credentials");
    let client_b = allocate_from_controller(service_b, proxy_address)
        .await
        .expect("allocate B from controller-issued relay credentials");
    let endpoint_a = client_a.local_endpoint();
    let endpoint_b = client_b.local_endpoint();
    client_a
        .prepare_peer(&endpoint_b)
        .await
        .expect("prepare B from A");
    client_b
        .prepare_peer(&endpoint_a)
        .await
        .expect("prepare A from B");

    let mut received = [0_u8; 64];
    client_a
        .send_to(&endpoint_b, b"controller to WSS relay")
        .await
        .expect("send controller-authorized A datagram");
    let metadata = timeout(Duration::from_secs(2), client_b.receive(&mut received))
        .await
        .expect("B relay receive timeout")
        .expect("B relay receive");
    assert_eq!(metadata.source, endpoint_a);
    assert_eq!(&received[..metadata.length], b"controller to WSS relay");

    client_b
        .send_to(&endpoint_a, b"WSS relay back to controller client")
        .await
        .expect("send controller-authorized B datagram");
    let metadata = timeout(Duration::from_secs(2), client_a.receive(&mut received))
        .await
        .expect("A relay receive timeout")
        .expect("A relay receive");
    assert_eq!(metadata.source, endpoint_b);
    assert_eq!(
        &received[..metadata.length],
        b"WSS relay back to controller client"
    );

    client_b.shutdown().await.expect("shutdown B relay client");
    client_a.shutdown().await.expect("shutdown A relay client");
    proxy_task.await.expect("shared proxy task");
    let _shutdown = controller_shutdown_sender.send(());
    controller_task
        .await
        .expect("join controller task")
        .expect("controller shuts down cleanly");
    let _shutdown = relay_shutdown_sender.send(());
    timeout(Duration::from_secs(2), relay_task)
        .await
        .expect("relay shutdown timeout")
        .expect("join relay task")
        .expect("relay shuts down cleanly");
    std::fs::remove_dir_all(directory).expect("remove proxy-only deployment");
}

fn only_websocket_service(
    connectivity: &stella_client::ConnectivityConfigState,
) -> &RelayServiceState {
    assert_eq!(connectivity.relay_services().len(), 1);
    let service = &connectivity.relay_services()[0];
    assert_eq!(service.carriers(), RelayCarrierMask::SECURE_WEBSOCKET);
    assert_eq!(service.hostname(), "localhost");
    assert_eq!(service.tls_server_name(), "localhost");
    service
}

async fn allocate_from_controller(
    service: &RelayServiceState,
    proxy_address: SocketAddr,
) -> Result<TurnWebSocketClient, stella_client::TurnUdpError> {
    let relay_address = service.addresses()[0].address;
    let mut config = TurnWebSocketClientConfig::new(
        service.relay_id(),
        SocketAddr::new(relay_address, service.ports().secure_websocket),
        SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0),
        service.tls_server_name().to_owned(),
        service.trust(),
        service.spki_pins().to_vec(),
    );
    config.proxy_address = Some(proxy_address);
    config.server_hostname = service.hostname().to_owned();
    config.max_datagram_size = usize::try_from(service.max_datagram_size())
        .expect("relay datagram size fits this platform");
    config.allocation_lifetime_seconds = service.allocation_lifetime_seconds();
    config.idle_timeout_seconds = service.idle_timeout_seconds();
    TurnWebSocketClient::allocate(
        config,
        TurnCredentials::new(
            service.credential_username().to_vec(),
            service.credential_secret().to_vec(),
            service.credential_expires_at(),
        )?,
    )
    .await
}
