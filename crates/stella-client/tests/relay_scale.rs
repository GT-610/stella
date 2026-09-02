//! Repeatable 32-node and bounded 100-node live TURN allocation validation.

use std::{
    collections::BTreeSet,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use stella_client::{TurnCredentials, TurnUdpClient, TurnUdpClientConfig, TurnUdpError};
use stella_common::{NodeId, RelayId};
use stella_proto::StunMethod;
use stella_server::{
    relay_credentials::RelayCredentialAuthority,
    turn_relay::{TurnUdpRelay, TurnUdpRelayConfig},
};
use tokio::{sync::oneshot, task::JoinSet, time::timeout};

#[tokio::test]
async fn regular_room_maintains_32_live_turn_allocations() {
    run_relay_scale_profile(32).await;
}

#[tokio::test]
async fn bounded_room_maintains_100_allocations_and_rejects_101st() {
    run_relay_scale_profile(100).await;
}

#[allow(clippy::too_many_lines)]
async fn run_relay_scale_profile(node_count: usize) {
    let started = Instant::now();
    let relay_id = relay_id(node_count);
    let authority =
        RelayCredentialAuthority::new([0x5d; 32], 300).expect("create relay credential authority");
    let now = unix_time();
    let mut credentials = Vec::with_capacity(node_count);
    for index in 0..node_count {
        let credential = authority
            .issue(relay_id, node_id(index), now)
            .expect("issue scale credential");
        credentials.push(
            TurnCredentials::new(
                credential.username().to_vec(),
                credential.secret().to_vec(),
                credential.expires_at(),
            )
            .expect("own scale credential"),
        );
    }
    let overflow = authority
        .issue(relay_id, node_id(node_count), now)
        .expect("issue overflow credential");
    let overflow = TurnCredentials::new(
        overflow.username().to_vec(),
        overflow.secret().to_vec(),
        overflow.expires_at(),
    )
    .expect("own overflow credential");

    let mut relay_config = TurnUdpRelayConfig::new(
        relay_id,
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
        IpAddr::V4(Ipv4Addr::LOCALHOST),
        IpAddr::V4(Ipv4Addr::LOCALHOST),
    );
    relay_config.max_allocations = node_count;
    relay_config.max_allocations_per_node = 1;
    relay_config.allocation_lifetime_seconds = 60;
    relay_config.idle_timeout_seconds = 30;
    let relay = TurnUdpRelay::bind(relay_config, authority)
        .await
        .expect("bind scale relay");
    let relay_address = relay.local_address().expect("scale relay address");
    let (shutdown_sender, shutdown_receiver) = oneshot::channel();
    let relay_task = tokio::spawn(relay.run(async move {
        let _result = shutdown_receiver.await;
    }));

    let client_config = TurnUdpClientConfig::new(
        relay_id,
        relay_address,
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
    );
    let mut pending = JoinSet::new();
    for credential in credentials {
        pending.spawn(TurnUdpClient::allocate(client_config, credential));
    }
    let mut clients = Vec::with_capacity(node_count);
    while let Some(result) = pending.join_next().await {
        clients.push(
            result
                .expect("allocation task")
                .expect("create live TURN allocation"),
        );
    }
    assert_eq!(clients.len(), node_count);
    let relayed_addresses = clients
        .iter()
        .map(TurnUdpClient::relayed_address)
        .collect::<BTreeSet<_>>();
    assert_eq!(relayed_addresses.len(), node_count);

    assert!(matches!(
        TurnUdpClient::allocate(client_config, overflow).await,
        Err(TurnUdpError::Rejected {
            method: StunMethod::Allocate,
            code: 486,
        })
    ));

    let mut shutdowns = JoinSet::new();
    for client in clients {
        shutdowns.spawn(async move { client.shutdown().await });
    }
    while let Some(result) = shutdowns.join_next().await {
        result
            .expect("shutdown task")
            .expect("delete live TURN allocation");
    }
    let _result = shutdown_sender.send(());
    timeout(Duration::from_secs(5), relay_task)
        .await
        .expect("relay shutdown deadline")
        .expect("relay task join")
        .expect("relay runtime");

    eprintln!(
        "relay scale: allocations={node_count} unique_relayed_addresses={} overflow_status=486 elapsed_ms={}",
        relayed_addresses.len(),
        started.elapsed().as_millis()
    );
}

fn relay_id(node_count: usize) -> RelayId {
    let mut bytes = [0x4d; 16];
    bytes[..8].copy_from_slice(
        &u64::try_from(node_count)
            .expect("profile size fits u64")
            .to_be_bytes(),
    );
    RelayId::from_bytes(bytes)
}

fn node_id(index: usize) -> NodeId {
    let mut bytes = [0x6e; 16];
    bytes[..8].copy_from_slice(
        &u64::try_from(index)
            .expect("node index fits u64")
            .to_be_bytes(),
    );
    NodeId::from_bytes(bytes)
}

fn unix_time() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("test clock")
        .as_secs()
}
