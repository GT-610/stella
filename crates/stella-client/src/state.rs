//! Validated in-memory controller state for one virtual network.

use std::collections::BTreeMap;

use stella_common::{ControllerId, NetworkId, NodeId};
use stella_crypto::{
    sha256_segments, validate_controller_id, validate_node_id, CryptoError, IdentityPublicKey,
};
use stella_proto::{
    CodecError, Endpoint, MembershipGrant, MembershipGrantView, NetworkPolicy, PeerListView,
    PeerRecordView, MEMBERSHIP_GRANT_LENGTH, MEMBERSHIP_GRANT_SIGNATURE_DOMAIN,
};
use thiserror::Error;

/// Fully validated authorization and reachability metadata for one peer.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PeerState {
    node_id: NodeId,
    public_key: IdentityPublicKey,
    grant: MembershipGrant,
    grant_bytes: [u8; MEMBERSHIP_GRANT_LENGTH],
    endpoints: Vec<Endpoint>,
}

impl PeerState {
    /// Returns the peer node ID.
    #[must_use]
    pub const fn node_id(&self) -> NodeId {
        self.node_id
    }

    /// Returns the validated peer Ed25519 public key.
    #[must_use]
    pub const fn public_key(&self) -> IdentityPublicKey {
        self.public_key
    }

    /// Returns the parsed controller-signed membership grant.
    #[must_use]
    pub const fn grant(&self) -> MembershipGrant {
        self.grant
    }

    /// Returns the exact encoded controller-signed membership grant.
    #[must_use]
    pub const fn grant_bytes(&self) -> &[u8; MEMBERSHIP_GRANT_LENGTH] {
        &self.grant_bytes
    }

    /// Returns the canonical advertised endpoint sequence.
    #[must_use]
    pub fn endpoints(&self) -> &[Endpoint] {
        &self.endpoints
    }
}

/// Atomic authoritative view for one joined virtual network.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NetworkState {
    network_id: NetworkId,
    controller_epoch: u64,
    snapshot_revision: u64,
    policy: NetworkPolicy,
    local_grant: MembershipGrant,
    local_grant_bytes: [u8; MEMBERSHIP_GRANT_LENGTH],
    peers: BTreeMap<NodeId, PeerState>,
}

impl NetworkState {
    /// Returns the virtual network ID.
    #[must_use]
    pub const fn network_id(&self) -> NetworkId {
        self.network_id
    }

    /// Returns the authoritative controller epoch.
    #[must_use]
    pub const fn controller_epoch(&self) -> u64 {
        self.controller_epoch
    }

    /// Returns the accepted complete peer-snapshot revision.
    #[must_use]
    pub const fn snapshot_revision(&self) -> u64 {
        self.snapshot_revision
    }

    /// Returns the canonical network policy.
    #[must_use]
    pub const fn policy(&self) -> NetworkPolicy {
        self.policy
    }

    /// Returns the parsed local membership grant.
    #[must_use]
    pub const fn local_grant(&self) -> MembershipGrant {
        self.local_grant
    }

    /// Returns the exact encoded local membership grant.
    #[must_use]
    pub const fn local_grant_bytes(&self) -> &[u8; MEMBERSHIP_GRANT_LENGTH] {
        &self.local_grant_bytes
    }

    /// Returns all authorized online peers in stable node-ID order.
    #[must_use]
    pub const fn peers(&self) -> &BTreeMap<NodeId, PeerState> {
        &self.peers
    }

    /// Replaces the local grant after validating one `GRANT_REFRESH` view.
    ///
    /// The refresh must describe the current epoch and accepted snapshot
    /// revision. A revision change requires a complete peer snapshot instead.
    ///
    /// # Errors
    ///
    /// Returns [`StateError`] without modifying the prior grant when epoch,
    /// revision, policy, identity, time, digest, or signature validation fails.
    pub fn refresh_local_grant(&mut self, input: &GrantRefreshInput<'_>) -> Result<(), StateError> {
        validate_controller_id(input.controller_id, input.controller_public_key)?;
        ensure_equal(
            self.controller_epoch == input.controller_epoch,
            "grant refresh",
            "controller epoch",
        )?;
        ensure_equal(
            self.snapshot_revision == input.snapshot_revision,
            "grant refresh",
            "snapshot revision",
        )?;
        let policy = NetworkPolicy::decode(input.policy_bytes)?;
        ensure_equal(policy == self.policy, "grant refresh", "network policy")?;
        let grant_bytes = fixed_grant(input.grant_bytes)?;
        let grant = validate_grant(
            &grant_bytes,
            GrantContext {
                controller_id: input.controller_id,
                controller_public_key: input.controller_public_key,
                network_id: self.network_id,
                controller_epoch: input.controller_epoch,
                node_id: input.local_node_id,
                node_public_key: input.local_public_key,
                policy,
                policy_bytes: input.policy_bytes,
                now: input.now,
            },
        )?;
        self.local_grant = grant;
        self.local_grant_bytes = grant_bytes;
        Ok(())
    }

    /// Validates a complete snapshot into temporary owned state.
    ///
    /// # Errors
    ///
    /// Returns [`StateError`] when any enclosing field, policy, grant, peer,
    /// endpoint, identity, signature, epoch, or validity check fails.
    pub fn from_snapshot(input: &SnapshotInput<'_>) -> Result<Self, StateError> {
        validate_controller_id(input.controller_id, input.controller_public_key)?;
        ensure_equal(
            input.snapshot_revision != 0,
            "peer snapshot",
            "snapshot revision",
        )?;
        let policy = NetworkPolicy::decode(input.policy_bytes)?;
        ensure_equal(
            policy.network_id == input.network_id,
            "peer snapshot",
            "policy network ID",
        )?;
        let local_grant_bytes = fixed_grant(input.local_grant_bytes)?;
        let local_grant = validate_grant(
            &local_grant_bytes,
            GrantContext {
                controller_id: input.controller_id,
                controller_public_key: input.controller_public_key,
                network_id: input.network_id,
                controller_epoch: input.controller_epoch,
                node_id: input.local_node_id,
                node_public_key: input.local_public_key,
                policy,
                policy_bytes: input.policy_bytes,
                now: input.now,
            },
        )?;
        let peer_list = PeerListView::decode(input.peer_list_bytes)?;
        peer_list.validate_context(
            policy.max_flood_peers,
            input.local_node_id,
            input.network_id,
            input.controller_id,
            input.controller_epoch,
        )?;
        let mut peers = BTreeMap::new();
        for peer in peer_list.peers() {
            let owned = validate_peer(
                &peer,
                NetworkValidationContext {
                    controller_id: input.controller_id,
                    controller_public_key: input.controller_public_key,
                    network_id: input.network_id,
                    controller_epoch: input.controller_epoch,
                    policy,
                    policy_bytes: input.policy_bytes,
                    now: input.now,
                },
            )?;
            peers.insert(owned.node_id, owned);
        }
        Ok(Self {
            network_id: input.network_id,
            controller_epoch: input.controller_epoch,
            snapshot_revision: input.snapshot_revision,
            policy,
            local_grant,
            local_grant_bytes,
            peers,
        })
    }
}

/// Borrowed fields from one complete authenticated `PEER_SNAPSHOT` message.
#[derive(Clone, Copy, Debug)]
pub struct SnapshotInput<'a> {
    /// Authenticated Stella controller ID.
    pub controller_id: ControllerId,
    /// Public key whose ID equals `controller_id`.
    pub controller_public_key: IdentityPublicKey,
    /// Locally authenticated node ID.
    pub local_node_id: NodeId,
    /// Public key whose ID equals `local_node_id`.
    pub local_public_key: IdentityPublicKey,
    /// Network named by the enclosing snapshot.
    pub network_id: NetworkId,
    /// Non-zero authoritative controller epoch.
    pub controller_epoch: u64,
    /// Non-zero complete snapshot revision.
    pub snapshot_revision: u64,
    /// Exact encoded local membership grant.
    pub local_grant_bytes: &'a [u8],
    /// Exact canonical network-policy bytes.
    pub policy_bytes: &'a [u8],
    /// Exact complete peer-list bytes.
    pub peer_list_bytes: &'a [u8],
    /// Unix time used for every grant validity check.
    pub now: u64,
}

/// Borrowed fields from one authenticated `GRANT_REFRESH` message.
#[derive(Clone, Copy, Debug)]
pub struct GrantRefreshInput<'a> {
    /// Authenticated Stella controller ID.
    pub controller_id: ControllerId,
    /// Public key whose ID equals `controller_id`.
    pub controller_public_key: IdentityPublicKey,
    /// Locally authenticated node ID.
    pub local_node_id: NodeId,
    /// Public key whose ID equals `local_node_id`.
    pub local_public_key: IdentityPublicKey,
    /// Epoch named by the refresh.
    pub controller_epoch: u64,
    /// Snapshot revision named by the refresh.
    pub snapshot_revision: u64,
    /// Exact encoded replacement local membership grant.
    pub grant_bytes: &'a [u8],
    /// Exact canonical network-policy bytes.
    pub policy_bytes: &'a [u8],
    /// Unix time used for grant validity checking.
    pub now: u64,
}

#[derive(Clone, Copy)]
struct GrantContext<'a> {
    controller_id: ControllerId,
    controller_public_key: IdentityPublicKey,
    network_id: NetworkId,
    controller_epoch: u64,
    node_id: NodeId,
    node_public_key: IdentityPublicKey,
    policy: NetworkPolicy,
    policy_bytes: &'a [u8],
    now: u64,
}

#[derive(Clone, Copy)]
struct NetworkValidationContext<'a> {
    controller_id: ControllerId,
    controller_public_key: IdentityPublicKey,
    network_id: NetworkId,
    controller_epoch: u64,
    policy: NetworkPolicy,
    policy_bytes: &'a [u8],
    now: u64,
}

fn validate_peer(
    peer: &PeerRecordView<'_>,
    context: NetworkValidationContext<'_>,
) -> Result<PeerState, StateError> {
    let public_key = IdentityPublicKey::from_bytes(peer.node_public_key())?;
    validate_node_id(peer.node_id(), public_key)?;
    let grant_view = peer.membership_grant();
    let grant_bytes = fixed_grant_bytes(&grant_view);
    let grant = validate_grant(
        &grant_bytes,
        GrantContext {
            controller_id: context.controller_id,
            controller_public_key: context.controller_public_key,
            network_id: context.network_id,
            controller_epoch: context.controller_epoch,
            node_id: peer.node_id(),
            node_public_key: public_key,
            policy: context.policy,
            policy_bytes: context.policy_bytes,
            now: context.now,
        },
    )?;
    Ok(PeerState {
        node_id: peer.node_id(),
        public_key,
        grant,
        grant_bytes,
        endpoints: peer.endpoints().collect(),
    })
}

fn validate_grant(
    grant_bytes: &[u8; MEMBERSHIP_GRANT_LENGTH],
    context: GrantContext<'_>,
) -> Result<MembershipGrant, StateError> {
    let view = MembershipGrantView::decode(grant_bytes)?;
    let grant = view.grant();
    context.controller_public_key.verify_segments(
        MEMBERSHIP_GRANT_SIGNATURE_DOMAIN,
        &[view.signed_body()],
        view.signature(),
    )?;
    validate_node_id(
        grant.node_id,
        IdentityPublicKey::from_bytes(grant.node_public_key)?,
    )?;
    ensure_equal(
        grant.controller_id == context.controller_id,
        "membership grant",
        "controller ID",
    )?;
    ensure_equal(
        grant.network_id == context.network_id,
        "membership grant",
        "network ID",
    )?;
    ensure_equal(
        grant.controller_epoch == context.controller_epoch,
        "membership grant",
        "controller epoch",
    )?;
    ensure_equal(
        grant.node_id == context.node_id,
        "membership grant",
        "node ID",
    )?;
    ensure_equal(
        grant.node_public_key == context.node_public_key.to_bytes(),
        "membership grant",
        "node public key",
    )?;
    let digest = sha256_segments(&[context.policy_bytes]);
    grant.validate_policy(context.policy, &digest)?;
    if context.now < grant.not_before || context.now >= grant.not_after {
        return Err(StateError::GrantInactive {
            node_id: grant.node_id,
            now: context.now,
            not_before: grant.not_before,
            not_after: grant.not_after,
        });
    }
    Ok(grant)
}

fn fixed_grant(value: &[u8]) -> Result<[u8; MEMBERSHIP_GRANT_LENGTH], StateError> {
    value.try_into().map_err(|_| StateError::GrantLength {
        actual: value.len(),
    })
}

fn fixed_grant_bytes(grant: &MembershipGrantView<'_>) -> [u8; MEMBERSHIP_GRANT_LENGTH] {
    let mut bytes = [0_u8; MEMBERSHIP_GRANT_LENGTH];
    bytes[..grant.signed_body().len()].copy_from_slice(grant.signed_body());
    bytes[grant.signed_body().len()..].copy_from_slice(grant.signature());
    bytes
}

fn ensure_equal(
    matches: bool,
    context: &'static str,
    field: &'static str,
) -> Result<(), StateError> {
    if !matches {
        return Err(StateError::InconsistentField { context, field });
    }
    Ok(())
}

/// Failure while validating or updating controller-distributed network state.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum StateError {
    /// A policy, grant, peer record, peer list, or endpoint failed wire checks.
    #[error(transparent)]
    Codec(#[from] CodecError),
    /// A node identity or controller signature failed cryptographic checks.
    #[error(transparent)]
    Crypto(#[from] CryptoError),
    /// A raw grant did not have the protocol's fixed width.
    #[error("membership grant must contain {expected} bytes, got {actual}", expected = MEMBERSHIP_GRANT_LENGTH)]
    GrantLength {
        /// Supplied encoded grant length.
        actual: usize,
    },
    /// Authenticated enclosing state and a nested object disagree.
    #[error("{context} has inconsistent {field}")]
    InconsistentField {
        /// Object relationship being checked.
        context: &'static str,
        /// First mismatched field.
        field: &'static str,
    },
    /// A correctly signed grant is not valid at the evaluation time.
    #[error(
        "membership grant for {node_id} is inactive at {now}; valid interval is [{not_before}, {not_after})"
    )]
    GrantInactive {
        /// Node authorized by the grant.
        node_id: NodeId,
        /// Evaluation Unix time.
        now: u64,
        /// Inclusive grant start.
        not_before: u64,
        /// Exclusive grant end.
        not_after: u64,
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
    use stella_crypto::{derive_controller_id, derive_node_id, IdentitySeed, IdentitySigningKey};
    use stella_proto::{ConfidentialityPolicy, Endpoint, NetworkPolicy};
    use stella_server::{
        network_state::encode_network_state,
        store::{AuthorityStore, NetworkRecord, NodeRecord},
    };

    use super::{NetworkState, SnapshotInput, StateError};

    static TEMP_SEQUENCE: AtomicU64 = AtomicU64::new(1);

    fn signing_key(seed: u8) -> IdentitySigningKey {
        IdentitySigningKey::from_seed(&IdentitySeed::from_bytes([seed; 32]))
    }

    fn fixture() -> (
        PathBuf,
        AuthorityStore,
        IdentitySigningKey,
        IdentitySigningKey,
        NetworkId,
    ) {
        let sequence = TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        let directory = std::env::temp_dir().join(format!(
            "stella-client-state-{}-{sequence}",
            std::process::id()
        ));
        std::fs::create_dir(&directory).expect("create test directory");
        let controller = signing_key(71);
        let store = AuthorityStore::initialize(
            &directory.join("controller.redb"),
            derive_controller_id(controller.public_key()),
        )
        .expect("initialize authority store");
        let network_id = NetworkId::from_bytes([72; 16]);
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
            .create_network(&NetworkRecord::new(policy, "Client state", 100).expect("network"))
            .expect("create network");
        let local = signing_key(73);
        let local_record = NodeRecord::new(local.public_key(), "Local", 100).expect("local node");
        let peer = signing_key(74);
        let peer_record = NodeRecord::new(peer.public_key(), "Peer", 100).expect("peer node");
        store.create_node(&local_record).expect("create local node");
        store.create_node(&peer_record).expect("create peer node");
        store
            .add_member(local_record.node_id(), network_id, 110)
            .expect("add local member");
        store
            .add_member(peer_record.node_id(), network_id, 110)
            .expect("add peer member");
        store
            .publish_endpoints(
                peer_record.node_id(),
                network_id,
                &[Endpoint::UdpIpv4 {
                    priority: 0,
                    port: 45_001,
                    max_datagram_size: 1_200,
                    address: Ipv4Addr::LOCALHOST,
                }],
                120,
            )
            .expect("publish peer endpoint");
        (directory, store, controller, local, network_id)
    }

    #[test]
    fn complete_snapshot_validates_before_becoming_owned_state() {
        let (directory, store, controller, local, network_id) = fixture();
        let view = store
            .network_session_view(derive_node_id(local.public_key()), network_id)
            .expect("read network view");
        let encoded = encode_network_state(&controller, &view, 200).expect("encode state");
        let state = NetworkState::from_snapshot(&SnapshotInput {
            controller_id: derive_controller_id(controller.public_key()),
            controller_public_key: controller.public_key(),
            local_node_id: derive_node_id(local.public_key()),
            local_public_key: local.public_key(),
            network_id,
            controller_epoch: encoded.controller_epoch(),
            snapshot_revision: encoded.snapshot_revision(),
            local_grant_bytes: encoded.local_grant(),
            policy_bytes: encoded.policy(),
            peer_list_bytes: encoded.peer_list(),
            now: 200,
        })
        .expect("snapshot validates");

        assert_eq!(state.network_id(), network_id);
        assert_eq!(state.controller_epoch(), encoded.controller_epoch());
        assert_eq!(state.snapshot_revision(), encoded.snapshot_revision());
        assert_eq!(state.peers().len(), 1);
        assert_eq!(
            state.local_grant().node_id,
            derive_node_id(local.public_key())
        );
        drop(store);
        std::fs::remove_dir_all(directory).expect("remove test directory");
    }

    #[test]
    fn snapshot_rejects_bad_signature_and_expired_grant() {
        let (directory, store, controller, local, network_id) = fixture();
        let view = store
            .network_session_view(derive_node_id(local.public_key()), network_id)
            .expect("read network view");
        let encoded = encode_network_state(&controller, &view, 200).expect("encode state");
        let mut bad_grant = *encoded.local_grant();
        let last = bad_grant.len() - 1;
        bad_grant[last] ^= 1;
        let bad_input = SnapshotInput {
            controller_id: derive_controller_id(controller.public_key()),
            controller_public_key: controller.public_key(),
            local_node_id: derive_node_id(local.public_key()),
            local_public_key: local.public_key(),
            network_id,
            controller_epoch: encoded.controller_epoch(),
            snapshot_revision: encoded.snapshot_revision(),
            local_grant_bytes: &bad_grant,
            policy_bytes: encoded.policy(),
            peer_list_bytes: encoded.peer_list(),
            now: 200,
        };
        assert!(matches!(
            NetworkState::from_snapshot(&bad_input),
            Err(StateError::Crypto(_))
        ));
        let expired_input = SnapshotInput {
            local_grant_bytes: encoded.local_grant(),
            now: 1_100,
            ..bad_input
        };
        assert!(matches!(
            NetworkState::from_snapshot(&expired_input),
            Err(StateError::GrantInactive { .. })
        ));
        drop(store);
        std::fs::remove_dir_all(directory).expect("remove test directory");
    }
}
