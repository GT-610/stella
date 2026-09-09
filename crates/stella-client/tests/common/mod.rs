//! Shared helpers for the Windows-only client integration tests.
//!
//! Windows-only in practice: this module is included via `mod common;` from
//! `cfg(windows)` test targets, so it is not compiled on other platforms.

// Each integration test binary is a separate crate that uses a different
// subset of these helpers; unused-in-one-binary warnings would otherwise fire.
#![allow(
    dead_code,
    reason = "shared by Windows-only test binaries with different subsets"
)]

use std::{
    net::{Ipv4Addr, SocketAddr},
    path::PathBuf,
    sync::atomic::{AtomicU64, Ordering},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use tokio::{io::AsyncReadExt, net::TcpStream, time::sleep};

use stella_common::NetworkId;
use stella_crypto::{IdentitySeed, IdentitySigningKey};
use stella_proto::{ConfidentialityPolicy, NetworkPolicy};

static TEMP_SEQUENCE: AtomicU64 = AtomicU64::new(1);

/// Creates a unique temporary directory path with the given filename prefix.
#[must_use]
pub fn temp_directory(prefix: &str) -> PathBuf {
    let sequence = TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed);
    std::env::temp_dir().join(format!("{prefix}-{}-{sequence}", std::process::id()))
}

/// Reserves a loopback address by binding port zero and releasing it.
pub fn reserve_loopback_address() -> SocketAddr {
    let listener =
        std::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).expect("reserve loopback address");
    listener.local_addr().expect("read reserved address")
}

/// Current Unix time in seconds for test credential issuance.
#[must_use]
pub fn unix_time() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("test clock after Unix epoch")
        .as_secs()
}

/// Waits until a TCP listener accepts connections (controller startup).
pub async fn wait_for_tcp_listener(address: SocketAddr) {
    for _attempt in 0..100 {
        match TcpStream::connect(address).await {
            Ok(stream) => {
                drop(stream);
                return;
            }
            Err(_) => sleep(Duration::from_millis(10)).await,
        }
    }
    TcpStream::connect(address)
        .await
        .expect("controller listener becomes ready");
}

/// Reads one HTTP CONNECT request up to the terminating blank line.
pub async fn read_connect_request(stream: &mut TcpStream) -> Vec<u8> {
    let mut request = Vec::new();
    loop {
        let mut byte = [0_u8; 1];
        stream
            .read_exact(&mut byte)
            .await
            .expect("read CONNECT request");
        request.push(byte[0]);
        assert!(request.len() <= 1_024);
        if request.ends_with(b"\r\n\r\n") {
            return request;
        }
    }
}

/// Builds the canonical CONNECT request for the given loopback port.
///
/// Only used by the proxy bootstrap tests; other test binaries that share
/// this module do not need it.
#[must_use]
pub fn canonical_connect_request(port: u16) -> Vec<u8> {
    format!("CONNECT localhost:{port} HTTP/1.1\r\nHost: localhost:{port}\r\n\r\n").into_bytes()
}

/// Checks whether `haystack` contains `needle` as a contiguous subslice.
///
/// Only used by the authentication tests to assert that secrets never appear
/// in plaintext CONNECT requests; other test binaries do not need it.
#[must_use]
pub fn contains_subslice(haystack: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty()
        && haystack
            .windows(needle.len())
            .any(|window| window == needle)
}

/// Derives a deterministic test identity from a single marker byte.
#[must_use]
pub fn signing_key(marker: u8) -> IdentitySigningKey {
    IdentitySigningKey::from_seed(&IdentitySeed::from_bytes([marker; 32]))
}

/// Canonical test network policy shared by the loopback scenarios.
#[must_use]
pub fn network_policy(network_id: NetworkId) -> NetworkPolicy {
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
