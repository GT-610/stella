//! Controller-signed membership authorization objects.

use stella_crypto::{derive_controller_id, sha256_segments, CryptoError, IdentitySigningKey};
use stella_proto::{
    encode_membership_grant, CodecError, MembershipGrant, MEMBERSHIP_GRANT_LENGTH,
    MEMBERSHIP_GRANT_SIGNATURE_DOMAIN, MEMBERSHIP_GRANT_SIGNED_BODY_LENGTH, NETWORK_POLICY_LENGTH,
};
use thiserror::Error;

use crate::store::{MembershipRecord, MembershipStatus, NetworkRecord, NodeRecord};

/// Issues one canonical controller-signed membership grant.
///
/// The persisted node, network, and membership records must describe the same
/// enabled active authorization. The grant lifetime is the network policy's
/// bounded session lifetime, and its policy digest covers the exact canonical
/// 64-byte policy encoding.
///
/// # Errors
///
/// Returns [`AuthorizationError`] when records are inconsistent, the node or
/// membership is disabled, validity arithmetic overflows, protocol encoding
/// rejects a field, or Ed25519 signing fails.
pub fn issue_membership_grant(
    controller_signing_key: &IdentitySigningKey,
    node: &NodeRecord,
    network: &NetworkRecord,
    membership: &MembershipRecord,
    now: u64,
) -> Result<[u8; MEMBERSHIP_GRANT_LENGTH], AuthorizationError> {
    validate_records(node, network, membership)?;
    let policy = network.policy();
    let not_after = now
        .checked_add(u64::from(policy.session_lifetime_seconds))
        .ok_or(AuthorizationError::ValidityOverflow)?;
    let mut encoded_policy = [0_u8; NETWORK_POLICY_LENGTH];
    policy.encode(&mut encoded_policy)?;
    let grant = MembershipGrant {
        confidentiality: policy.confidentiality,
        permissions: membership.permissions(),
        network_id: network.network_id(),
        node_id: node.node_id(),
        node_public_key: *node.public_key().as_bytes(),
        controller_id: derive_controller_id(controller_signing_key.public_key()),
        controller_epoch: network.controller_epoch(),
        not_before: now,
        not_after,
        max_frame_size: policy.max_frame_size,
        max_flood_peers: policy.max_flood_peers,
        flood_rate: policy.flood_rate,
        flood_burst: policy.flood_burst,
        policy_digest: sha256_segments(&[&encoded_policy]),
        grant_serial: membership.grant_serial(),
    };
    let mut signed_body = [0_u8; MEMBERSHIP_GRANT_SIGNED_BODY_LENGTH];
    grant.encode_signed_body(&mut signed_body)?;
    let signature =
        controller_signing_key.sign_segments(MEMBERSHIP_GRANT_SIGNATURE_DOMAIN, &[&signed_body])?;
    let mut encoded = [0_u8; MEMBERSHIP_GRANT_LENGTH];
    encode_membership_grant(grant, &signature, &mut encoded)?;
    Ok(encoded)
}

fn validate_records(
    node: &NodeRecord,
    network: &NetworkRecord,
    membership: &MembershipRecord,
) -> Result<(), AuthorizationError> {
    if !node.enabled() {
        return Err(AuthorizationError::NodeDisabled);
    }
    if membership.status() != MembershipStatus::Active {
        return Err(AuthorizationError::MembershipSuspended);
    }
    if membership.node_id() != node.node_id() {
        return Err(AuthorizationError::RecordMismatch { field: "node ID" });
    }
    if membership.network_id() != network.network_id() {
        return Err(AuthorizationError::RecordMismatch {
            field: "network ID",
        });
    }
    Ok(())
}

/// Membership grant issuance failure.
#[derive(Debug, Error)]
pub enum AuthorizationError {
    /// The node is administratively disabled.
    #[error("node is administratively disabled")]
    NodeDisabled,
    /// The membership exists but is suspended.
    #[error("network membership is suspended")]
    MembershipSuspended,
    /// Persisted records do not describe the same authorization.
    #[error("authority records disagree on {field}")]
    RecordMismatch {
        /// First inconsistent field.
        field: &'static str,
    },
    /// Grant expiration arithmetic overflowed.
    #[error("membership grant validity overflows Unix time")]
    ValidityOverflow,
    /// Canonical grant or policy encoding failed.
    #[error(transparent)]
    Codec(#[from] CodecError),
    /// Signature assembly or verification failed.
    #[error(transparent)]
    Crypto(#[from] CryptoError),
}

#[cfg(test)]
mod tests {
    use std::{
        path::PathBuf,
        sync::atomic::{AtomicU64, Ordering},
    };

    use stella_common::NetworkId;
    use stella_crypto::{derive_controller_id, IdentitySeed, IdentitySigningKey};
    use stella_proto::{
        ConfidentialityPolicy, MembershipGrantView, NetworkPolicy,
        MEMBERSHIP_GRANT_SIGNATURE_DOMAIN, NETWORK_POLICY_LENGTH,
    };

    use super::{issue_membership_grant, AuthorizationError};
    use crate::store::{AuthorityStore, MembershipStatus, NetworkRecord, NodeRecord};

    static TEMP_SEQUENCE: AtomicU64 = AtomicU64::new(1);

    fn temp_database() -> (PathBuf, PathBuf) {
        let sequence = TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        let directory = std::env::temp_dir().join(format!(
            "stella-authorization-{}-{sequence}",
            std::process::id()
        ));
        std::fs::create_dir(&directory).expect("create test directory");
        let database = directory.join("controller.redb");
        (directory, database)
    }

    fn policy(network_id: NetworkId) -> NetworkPolicy {
        NetworkPolicy {
            confidentiality: ConfidentialityPolicy::Encrypt,
            max_frame_size: 1_514,
            max_flood_peers: 32,
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

    #[test]
    fn grant_binds_current_records_policy_and_controller_signature() {
        let controller = IdentitySigningKey::from_seed(&IdentitySeed::from_bytes([71; 32]));
        let node_key = IdentitySigningKey::from_seed(&IdentitySeed::from_bytes([72; 32]));
        let controller_id = derive_controller_id(controller.public_key());
        let (directory, database) = temp_database();
        let store = AuthorityStore::initialize(&database, controller_id).expect("create store");
        let node = NodeRecord::new(node_key.public_key(), "authorization node", 10)
            .expect("create node record");
        let node_id = node.node_id();
        store.create_node(&node).expect("persist node");
        let network_id = NetworkId::from_bytes([73; 16]);
        let network = NetworkRecord::new(policy(network_id), "authorization LAN", 11)
            .expect("create network record");
        store.create_network(&network).expect("persist network");
        store
            .add_member(node_id, network_id, 12)
            .expect("add membership");
        let network = store
            .get_network(network_id)
            .expect("read network")
            .expect("network exists");
        let membership = store
            .get_membership(node_id, network_id)
            .expect("read membership")
            .expect("membership exists");

        let encoded = issue_membership_grant(&controller, &node, &network, &membership, 100)
            .expect("issue grant");
        let view = MembershipGrantView::decode(&encoded).expect("decode issued grant");
        let grant = view.grant();
        assert_eq!(grant.not_before, 100);
        assert_eq!(grant.not_after, 1_000);
        assert_eq!(grant.controller_epoch, network.controller_epoch());
        assert_eq!(grant.grant_serial, membership.grant_serial());
        let mut policy_bytes = [0_u8; NETWORK_POLICY_LENGTH];
        network
            .policy()
            .encode(&mut policy_bytes)
            .expect("encode policy");
        grant
            .validate_policy(
                network.policy(),
                &stella_crypto::sha256_segments(&[&policy_bytes]),
            )
            .expect("grant matches policy");
        controller
            .public_key()
            .verify_segments(
                MEMBERSHIP_GRANT_SIGNATURE_DOMAIN,
                &[view.signed_body()],
                view.signature(),
            )
            .expect("verify controller signature");

        drop(store);
        std::fs::remove_dir_all(directory).expect("remove test directory");
    }

    #[test]
    fn disabled_suspended_mismatched_and_overflowing_grants_fail_closed() {
        let controller = IdentitySigningKey::from_seed(&IdentitySeed::from_bytes([81; 32]));
        let first_key = IdentitySigningKey::from_seed(&IdentitySeed::from_bytes([82; 32]));
        let second_key = IdentitySigningKey::from_seed(&IdentitySeed::from_bytes([83; 32]));
        let controller_id = derive_controller_id(controller.public_key());
        let (directory, database) = temp_database();
        let store = AuthorityStore::initialize(&database, controller_id).expect("create store");
        let first = NodeRecord::new(first_key.public_key(), "first node", 1).expect("first node");
        let second =
            NodeRecord::new(second_key.public_key(), "second node", 1).expect("second node");
        store.create_node(&first).expect("persist first node");
        store.create_node(&second).expect("persist second node");
        let network_id = NetworkId::from_bytes([84; 16]);
        store
            .create_network(
                &NetworkRecord::new(policy(network_id), "failure LAN", 1).expect("network"),
            )
            .expect("persist network");
        store
            .add_member(first.node_id(), network_id, 2)
            .expect("first membership");
        let network = store
            .get_network(network_id)
            .expect("read network")
            .expect("network exists");
        let membership = store
            .get_membership(first.node_id(), network_id)
            .expect("read membership")
            .expect("membership exists");
        assert!(matches!(
            issue_membership_grant(&controller, &second, &network, &membership, 3),
            Err(AuthorizationError::RecordMismatch { field: "node ID" })
        ));
        assert!(matches!(
            issue_membership_grant(&controller, &first, &network, &membership, u64::MAX),
            Err(AuthorizationError::ValidityOverflow)
        ));

        store
            .set_membership_status(first.node_id(), network_id, MembershipStatus::Suspended)
            .expect("suspend membership");
        let suspended = store
            .get_membership(first.node_id(), network_id)
            .expect("read suspended membership")
            .expect("membership exists");
        let current_network = store
            .get_network(network_id)
            .expect("read current network")
            .expect("network exists");
        assert!(matches!(
            issue_membership_grant(&controller, &first, &current_network, &suspended, 4),
            Err(AuthorizationError::MembershipSuspended)
        ));

        store
            .set_node_enabled(first.node_id(), false)
            .expect("disable node");
        let disabled = store
            .get_node(first.node_id())
            .expect("read disabled node")
            .expect("node exists");
        assert!(matches!(
            issue_membership_grant(&controller, &disabled, &current_network, &membership, 4),
            Err(AuthorizationError::NodeDisabled)
        ));
        drop(store);
        std::fs::remove_dir_all(directory).expect("remove test directory");
    }
}
