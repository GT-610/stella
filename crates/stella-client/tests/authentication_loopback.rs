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
    authenticate_controller, BearerCredential, ClientError, ControllerTrust, Enrollment, SpkiPin,
};
use stella_crypto::{derive_node_id, IdentitySigningKey};
use stella_server::{
    active::serve_control_session,
    bootstrap::{initialize_controller, BootstrapOptions},
    config::ServerConfig,
    runtime::{run_controller, SessionError, SessionHandler},
    store::AuthorityStore,
};
use tokio::{sync::oneshot, time::sleep};

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

#[tokio::test(flavor = "current_thread")]
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

    let first = authenticate_after_listener_ready(
        &trust,
        &node_key,
        Enrollment::new(&credential, "Windows loopback client"),
    )
    .await;
    assert_eq!(first.controller_id(), initialized.controller_id);
    assert_eq!(first.node_id(), node_id);
    assert!(first.server_time() >= issued_at);
    drop(first);

    let second = authenticate_controller(&trust, &node_key, None)
        .await
        .expect("known node authenticates without enrollment material");
    assert_eq!(second.node_id(), node_id);
    drop(second);

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
