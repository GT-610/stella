//! Windows loopback coverage for the authenticated controller request loop.

#![cfg(windows)]

use std::{
    fs::File,
    io::BufReader,
    net::{Ipv4Addr, SocketAddr},
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
    },
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use stella_common::{ControllerId, NetworkId};
use stella_control::{
    sign_node_proof, InboundSequence, MessageBuilder, NodeProofContext, OutboundSequence,
    RecordReader, RecordWriter, CONTROL_EXPORTER_LABEL, CONTROL_EXPORTER_LENGTH,
    CONTROL_NONCE_LENGTH,
};
use stella_crypto::{derive_node_id, IdentitySigningKey};
use stella_proto::{
    encode_endpoint_set, encode_network_revision_list, ConfidentialityPolicy, ControlFieldType,
    ControlMessageType, Endpoint, MembershipGrantView, NetworkPolicy, NetworkRevision,
    NetworkRevisionListView, PeerListView, VersionEntry, VersionListView,
};
use stella_server::{
    active::serve_control_session,
    bootstrap::{initialize_controller, BootstrapOptions},
    config::ServerConfig,
    runtime::{run_controller, SessionError, SessionHandler},
    store::{AuthorityStore, BearerToken, NetworkRecord},
};
use tokio::{net::TcpStream, sync::oneshot, time::sleep};
use tokio_rustls::{
    client::TlsStream as ClientTlsStream,
    rustls::{self, pki_types::ServerName, version::TLS13, ClientConfig, RootCertStore},
    TlsConnector,
};

static TEMP_SEQUENCE: AtomicU64 = AtomicU64::new(1);

struct ActiveClient {
    stream: ClientTlsStream<TcpStream>,
    inbound: InboundSequence,
    outbound: OutboundSequence,
}

impl ActiveClient {
    async fn send(&mut self, builder: MessageBuilder) -> u64 {
        let message = self.outbound.build(builder).expect("build client message");
        let message_id = message.header().expect("read client header").message_id;
        let mut writer = RecordWriter::new(&mut self.stream);
        writer
            .write_message(&message)
            .await
            .expect("write client message");
        writer.flush().await.expect("flush client message");
        message_id
    }

    async fn read(&mut self, expected: ControlMessageType) -> stella_control::OwnedControlMessage {
        let message = RecordReader::new(&mut self.stream)
            .read_message()
            .await
            .expect("read server message")
            .expect("server message is present");
        let header = message.header().expect("read server header");
        self.inbound
            .accept(header.message_id)
            .expect("server message sequence");
        assert_eq!(header.message_type, expected);
        message
    }
}

fn temp_directory() -> PathBuf {
    let sequence = TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed);
    std::env::temp_dir().join(format!(
        "stella-active-loopback-{}-{sequence}",
        std::process::id()
    ))
}

fn reserve_loopback_address() -> SocketAddr {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("reserve loopback address");
    listener.local_addr().expect("read reserved address")
}

fn client_connector(certificate_path: &Path) -> TlsConnector {
    let file = File::open(certificate_path).expect("open test certificate");
    let mut reader = BufReader::new(file);
    let certificates = rustls_pemfile::certs(&mut reader)
        .collect::<Result<Vec<_>, _>>()
        .expect("decode test certificate");
    let mut roots = RootCertStore::empty();
    for certificate in certificates {
        roots.add(certificate).expect("trust test certificate");
    }
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let client = ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&TLS13])
        .expect("configure TLS 1.3 client")
        .with_root_certificates(roots)
        .with_no_client_auth();
    TlsConnector::from(Arc::new(client))
}

async fn connect_with_retry(address: SocketAddr) -> TcpStream {
    for _ in 0..100 {
        match TcpStream::connect(address).await {
            Ok(stream) => return stream,
            Err(_) => sleep(Duration::from_millis(10)).await,
        }
    }
    TcpStream::connect(address)
        .await
        .expect("controller listener becomes ready")
}

fn field_value(message: &stella_control::OwnedControlMessage, wanted: ControlFieldType) -> &[u8] {
    message
        .view()
        .expect("validated server message")
        .fields()
        .find_map(|field| (field.field_type() == Some(wanted)).then(|| field.value()))
        .expect("required server field")
}

fn status_code(message: &stella_control::OwnedControlMessage) -> u16 {
    u16::from_be_bytes(
        field_value(message, ControlFieldType::StatusCode)
            .try_into()
            .expect("status width"),
    )
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

#[allow(clippy::too_many_lines)]
async fn authenticate_client(
    connector: &TlsConnector,
    address: SocketAddr,
    expected_controller_id: ControllerId,
    node_key: &IdentitySigningKey,
    enrollment_token: &BearerToken,
) -> ActiveClient {
    let tcp = connect_with_retry(address).await;
    let server_name = ServerName::try_from("localhost")
        .expect("valid test server name")
        .to_owned();
    let mut stream = connector
        .connect(server_name, tcp)
        .await
        .expect("complete TLS 1.3 handshake");
    let mut inbound = InboundSequence::new();
    let mut outbound = OutboundSequence::new();

    let server_hello = RecordReader::new(&mut stream)
        .read_message()
        .await
        .expect("read server hello")
        .expect("server hello is present");
    let hello_header = server_hello.header().expect("server hello header");
    inbound
        .accept(hello_header.message_id)
        .expect("server hello sequence");
    assert_eq!(hello_header.message_type, ControlMessageType::ServerHello);
    let versions = VersionListView::decode(field_value(
        &server_hello,
        ControlFieldType::SupportedVersions,
    ))
    .expect("decode supported versions");
    assert_eq!(
        versions.entries().collect::<Vec<_>>(),
        vec![VersionEntry::V0_1_SUITE_1]
    );
    let server_nonce: [u8; CONTROL_NONCE_LENGTH] =
        field_value(&server_hello, ControlFieldType::ServerNonce)
            .try_into()
            .expect("server nonce width");
    let controller_id = ControllerId::from_bytes(
        field_value(&server_hello, ControlFieldType::ControllerId)
            .try_into()
            .expect("controller ID width"),
    );
    assert_eq!(controller_id, expected_controller_id);

    let mut client_nonce = [0_u8; CONTROL_NONCE_LENGTH];
    getrandom::fill(&mut client_nonce).expect("generate client nonce");
    if client_nonce.iter().all(|byte| *byte == 0) {
        client_nonce[0] = 1;
    }
    let node_id = derive_node_id(node_key.public_key());
    let mut selected = [0_u8; 4];
    VersionEntry::V0_1_SUITE_1
        .encode(&mut selected)
        .expect("encode selected version");
    let mut client_hello = MessageBuilder::new(ControlMessageType::ClientHello)
        .with_correlation(hello_header.message_id);
    client_hello
        .push_field(ControlFieldType::SelectedVersion, &selected)
        .expect("selected version field");
    client_hello
        .push_field(ControlFieldType::ClientNonce, &client_nonce)
        .expect("client nonce field");
    client_hello
        .push_field(ControlFieldType::NodeId, node_id.as_bytes())
        .expect("node ID field");
    client_hello
        .push_field(
            ControlFieldType::NodePublicKey,
            node_key.public_key().as_bytes(),
        )
        .expect("node key field");
    let client_hello_message = outbound
        .build(client_hello)
        .expect("build client hello message");
    let client_hello_id = client_hello_message
        .header()
        .expect("client hello header")
        .message_id;
    let mut writer = RecordWriter::new(&mut stream);
    writer
        .write_message(&client_hello_message)
        .await
        .expect("write client hello");
    writer.flush().await.expect("flush client hello");

    let exporter = stream
        .get_ref()
        .1
        .export_keying_material(
            [0_u8; CONTROL_EXPORTER_LENGTH],
            CONTROL_EXPORTER_LABEL,
            None,
        )
        .expect("derive client TLS exporter");
    let server_proof = RecordReader::new(&mut stream)
        .read_message()
        .await
        .expect("read server proof")
        .expect("server proof is present");
    let proof_header = server_proof.header().expect("server proof header");
    inbound
        .accept(proof_header.message_id)
        .expect("server proof sequence");
    assert_eq!(proof_header.message_type, ControlMessageType::ServerProof);
    assert_eq!(proof_header.correlation_id, client_hello_id);

    let node_signature = sign_node_proof(
        node_key,
        NodeProofContext::new(
            &exporter,
            &server_nonce,
            &client_nonce,
            VersionEntry::V0_1_SUITE_1,
            controller_id,
            node_id,
        ),
    );
    let mut node_auth =
        MessageBuilder::new(ControlMessageType::NodeAuth).with_correlation(proof_header.message_id);
    node_auth
        .push_field(ControlFieldType::NodeSignature, &node_signature)
        .expect("node signature field");
    node_auth
        .push_field(
            ControlFieldType::EnrollmentToken,
            enrollment_token.expose_secret(),
        )
        .expect("enrollment token field");
    node_auth
        .push_field(ControlFieldType::DisplayName, b"active loopback node")
        .expect("display name field");
    let node_auth_message = outbound.build(node_auth).expect("build node auth message");
    let node_auth_id = node_auth_message
        .header()
        .expect("node auth header")
        .message_id;
    let mut writer = RecordWriter::new(&mut stream);
    writer
        .write_message(&node_auth_message)
        .await
        .expect("write node auth");
    writer.flush().await.expect("flush node auth");

    let auth_result = RecordReader::new(&mut stream)
        .read_message()
        .await
        .expect("read auth result")
        .expect("auth result is present");
    let auth_header = auth_result.header().expect("auth result header");
    inbound
        .accept(auth_header.message_id)
        .expect("auth result sequence");
    assert_eq!(auth_header.message_type, ControlMessageType::AuthResult);
    assert_eq!(auth_header.correlation_id, node_auth_id);
    assert_eq!(status_code(&auth_result), 0);

    ActiveClient {
        stream,
        inbound,
        outbound,
    }
}

fn join_request(network_id: NetworkId, token: &BearerToken) -> MessageBuilder {
    let mut builder = MessageBuilder::new(ControlMessageType::JoinRequest);
    builder
        .push_field(ControlFieldType::NetworkId, network_id.as_bytes())
        .expect("network ID field");
    builder
        .push_field(ControlFieldType::JoinToken, token.expose_secret())
        .expect("join token field");
    builder
}

fn leave_request(network_id: NetworkId) -> MessageBuilder {
    let mut builder = MessageBuilder::new(ControlMessageType::LeaveRequest);
    builder
        .push_field(ControlFieldType::NetworkId, network_id.as_bytes())
        .expect("network ID field");
    builder
}

fn endpoint_update(network_id: NetworkId, endpoints: &[Endpoint]) -> MessageBuilder {
    let mut encoded = [0_u8; 228];
    let length = encode_endpoint_set(endpoints, &mut encoded).expect("encode endpoint set");
    let mut builder = MessageBuilder::new(ControlMessageType::EndpointUpdate);
    builder
        .push_field(ControlFieldType::NetworkId, network_id.as_bytes())
        .expect("network ID field");
    builder
        .push_field(ControlFieldType::EndpointSet, &encoded[..length])
        .expect("endpoint set field");
    builder
}

fn snapshot_request(network_id: NetworkId, revision: u64) -> MessageBuilder {
    let mut builder = MessageBuilder::new(ControlMessageType::SnapshotRequest);
    builder
        .push_field(ControlFieldType::NetworkId, network_id.as_bytes())
        .expect("network ID field");
    builder
        .push_field(ControlFieldType::SnapshotRevision, &revision.to_be_bytes())
        .expect("snapshot revision field");
    builder
}

fn heartbeat(counter: u64, revisions: &[NetworkRevision]) -> MessageBuilder {
    let mut encoded = [0_u8; 4 + 32 * 256];
    let length =
        encode_network_revision_list(revisions, &mut encoded).expect("encode network revisions");
    let mut builder = MessageBuilder::new(ControlMessageType::Heartbeat);
    builder
        .push_field(ControlFieldType::HeartbeatCounter, &counter.to_be_bytes())
        .expect("heartbeat counter field");
    builder
        .push_field(ControlFieldType::NetworkRevisions, &encoded[..length])
        .expect("network revisions field");
    builder
}

#[allow(clippy::too_many_lines)]
#[tokio::test(flavor = "current_thread")]
async fn authenticated_loopback_joins_snapshots_and_leaves_idempotently() {
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
    let config = ServerConfig::load(&config_path).expect("load test configuration");
    let store = AuthorityStore::open(&config.database_path, initialized.controller_id)
        .expect("open authority before server");
    let issued_at = now();
    let enrollment_token = store
        .issue_enrollment_token(issued_at, issued_at + 3_600)
        .expect("issue enrollment token");
    let network_id = NetworkId::from_bytes([0x42; 16]);
    store
        .create_network(
            &NetworkRecord::new(network_policy(network_id), "Loopback LAN", issued_at)
                .expect("valid network"),
        )
        .expect("create network");
    let join_token = store
        .issue_join_token(network_id, issued_at, issued_at + 3_600)
        .expect("issue join token");
    drop(store);

    let connector = client_connector(&config.tls_certificate_path);
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

    let node_key = IdentitySigningKey::generate().expect("generate node identity");
    let node_id = derive_node_id(node_key.public_key());
    let mut client = authenticate_client(
        &connector,
        address,
        initialized.controller_id,
        &node_key,
        &enrollment_token,
    )
    .await;

    let join_id = client.send(join_request(network_id, &join_token)).await;
    let join_result = client.read(ControlMessageType::JoinResult).await;
    assert_eq!(
        join_result.header().expect("join header").correlation_id,
        join_id
    );
    assert_eq!(status_code(&join_result), 0);
    MembershipGrantView::decode(field_value(&join_result, ControlFieldType::MembershipGrant))
        .expect("decode join grant");
    NetworkPolicy::decode(field_value(&join_result, ControlFieldType::NetworkPolicy))
        .expect("decode join policy");
    let first_snapshot = client.read(ControlMessageType::PeerSnapshot).await;
    assert_eq!(
        first_snapshot
            .header()
            .expect("snapshot header")
            .correlation_id,
        0
    );
    assert!(
        PeerListView::decode(field_value(&first_snapshot, ControlFieldType::PeerList,))
            .expect("decode peer list")
            .is_empty()
    );

    let repeated_join_id = client.send(join_request(network_id, &join_token)).await;
    let repeated_join = client.read(ControlMessageType::JoinResult).await;
    assert_eq!(
        repeated_join
            .header()
            .expect("repeated join header")
            .correlation_id,
        repeated_join_id
    );
    assert_eq!(status_code(&repeated_join), 0);
    let _repeated_snapshot = client.read(ControlMessageType::PeerSnapshot).await;

    let endpoint = Endpoint::UdpIpv4 {
        priority: 10,
        port: 42_424,
        max_datagram_size: 1_200,
        address: Ipv4Addr::new(192, 0, 2, 42),
    };
    let endpoint_id = client.send(endpoint_update(network_id, &[endpoint])).await;
    let endpoint_result = client.read(ControlMessageType::EndpointResult).await;
    assert_eq!(
        endpoint_result
            .header()
            .expect("endpoint result header")
            .correlation_id,
        endpoint_id
    );
    assert_eq!(status_code(&endpoint_result), 0);
    let endpoint_revision = u64::from_be_bytes(
        field_value(&endpoint_result, ControlFieldType::SnapshotRevision)
            .try_into()
            .expect("endpoint revision width"),
    );

    let snapshot_id = client
        .send(snapshot_request(network_id, endpoint_revision))
        .await;
    let requested_snapshot = client.read(ControlMessageType::PeerSnapshot).await;
    assert_eq!(
        requested_snapshot
            .header()
            .expect("requested snapshot header")
            .correlation_id,
        snapshot_id
    );
    assert_eq!(
        u64::from_be_bytes(
            field_value(&requested_snapshot, ControlFieldType::SnapshotRevision)
                .try_into()
                .expect("requested snapshot revision width")
        ),
        endpoint_revision
    );

    let stale_revision = NetworkRevision {
        network_id,
        controller_epoch: u64::from_be_bytes(
            field_value(&requested_snapshot, ControlFieldType::ControllerEpoch)
                .try_into()
                .expect("requested snapshot epoch width"),
        ),
        snapshot_revision: endpoint_revision.saturating_sub(1).max(1),
    };
    let heartbeat_id = client.send(heartbeat(1, &[stale_revision])).await;
    let heartbeat_ack = client.read(ControlMessageType::HeartbeatAck).await;
    assert_eq!(
        heartbeat_ack
            .header()
            .expect("heartbeat ACK header")
            .correlation_id,
        heartbeat_id
    );
    assert_eq!(
        u64::from_be_bytes(
            field_value(&heartbeat_ack, ControlFieldType::HeartbeatCounter)
                .try_into()
                .expect("heartbeat counter width")
        ),
        1
    );
    let authoritative_revision = NetworkRevisionListView::decode(field_value(
        &heartbeat_ack,
        ControlFieldType::NetworkRevisions,
    ))
    .expect("decode ACK revisions")
    .revisions()
    .next()
    .expect("joined network revision");
    assert_eq!(authoritative_revision.network_id, network_id);
    assert_eq!(authoritative_revision.snapshot_revision, endpoint_revision);
    let reconciled_snapshot = client.read(ControlMessageType::PeerSnapshot).await;
    assert_eq!(
        reconciled_snapshot
            .header()
            .expect("reconciled snapshot header")
            .correlation_id,
        0
    );

    let current_heartbeat_id = client.send(heartbeat(2, &[authoritative_revision])).await;
    let current_heartbeat_ack = client.read(ControlMessageType::HeartbeatAck).await;
    assert_eq!(
        current_heartbeat_ack
            .header()
            .expect("current heartbeat ACK header")
            .correlation_id,
        current_heartbeat_id
    );

    let leave_id = client.send(leave_request(network_id)).await;
    let leave_result = client.read(ControlMessageType::LeaveResult).await;
    assert_eq!(
        leave_result.header().expect("leave header").correlation_id,
        leave_id
    );
    assert_eq!(status_code(&leave_result), 0);
    let first_leave_epoch = u64::from_be_bytes(
        field_value(&leave_result, ControlFieldType::ControllerEpoch)
            .try_into()
            .expect("leave epoch width"),
    );

    let repeated_leave_id = client.send(leave_request(network_id)).await;
    let repeated_leave = client.read(ControlMessageType::LeaveResult).await;
    assert_eq!(
        repeated_leave
            .header()
            .expect("repeated leave header")
            .correlation_id,
        repeated_leave_id
    );
    assert_eq!(status_code(&repeated_leave), 0);
    assert_eq!(
        u64::from_be_bytes(
            field_value(&repeated_leave, ControlFieldType::ControllerEpoch)
                .try_into()
                .expect("repeated leave epoch width")
        ),
        first_leave_epoch
    );

    drop(client);
    shutdown_sender.send(()).expect("request server shutdown");
    server
        .await
        .expect("server task joins")
        .expect("server shuts down cleanly");
    let store = AuthorityStore::open(&config.database_path, initialized.controller_id)
        .expect("reopen authority after server");
    assert_eq!(
        store
            .get_membership(node_id, network_id)
            .expect("read final membership"),
        None
    );
    drop(store);
    std::fs::remove_dir_all(&directory).expect("remove test directory");
}
