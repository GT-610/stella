//! Transactional redb controller authority store.

use std::{
    fs::OpenOptions,
    path::{Path, PathBuf},
    str,
};

use redb::{Database, ReadableTable, TableDefinition};
use stella_common::{ControllerId, GrantSerial, NetworkId, NodeId};
use stella_crypto::{derive_node_id, sha256_segments, CryptoError, IdentityPublicKey};
use stella_proto::{CodecError, MembershipPermissions, NetworkPolicy, NETWORK_POLICY_LENGTH};
use thiserror::Error;
use zeroize::{Zeroize, ZeroizeOnDrop};

const STORE_SCHEMA_VERSION: u32 = 1;
const RECORD_VERSION: u8 = 1;
const MAX_DISPLAY_NAME_BYTES: usize = 64;
const NODE_RECORD_FIXED_LENGTH: usize = 48;
const NETWORK_RECORD_FIXED_LENGTH: usize = 96;
const NODE_RECORD_MAGIC: [u8; 4] = *b"SNOD";
const NETWORK_RECORD_MAGIC: [u8; 4] = *b"SNET";
const MEMBERSHIP_RECORD_MAGIC: [u8; 4] = *b"SMEM";
const ENROLLMENT_TOKEN_RECORD_MAGIC: [u8; 4] = *b"SENT";
const JOIN_TOKEN_RECORD_MAGIC: [u8; 4] = *b"SJTK";
const NODE_ENABLED_FLAG: u8 = 0x01;
const MEMBERSHIP_RECORD_LENGTH: usize = 64;
const TOKEN_RECORD_LENGTH: usize = 24;
const JOIN_TOKEN_RECORD_LENGTH: usize = 40;
const TOKEN_LENGTH: usize = 32;
const TOKEN_GENERATION_ATTEMPTS: usize = 4;

/// Domain prefix used before hashing enrollment bearer tokens for storage.
pub const ENROLLMENT_TOKEN_DOMAIN: &[u8] = b"stella enrollment token v1";

/// Domain prefix used before hashing network join bearer tokens for storage.
pub const JOIN_TOKEN_DOMAIN: &[u8] = b"stella join token v1";

const SCHEMA_VERSION_KEY: &str = "schema_version";
const CONTROLLER_ID_KEY: &str = "controller_id";

const METADATA: TableDefinition<&str, &[u8]> = TableDefinition::new("metadata");
const NODES: TableDefinition<&[u8], &[u8]> = TableDefinition::new("nodes");
const NETWORKS: TableDefinition<&[u8], &[u8]> = TableDefinition::new("networks");
const MEMBERSHIPS: TableDefinition<&[u8], &[u8]> = TableDefinition::new("memberships");
const ENDPOINTS: TableDefinition<&[u8], &[u8]> = TableDefinition::new("endpoints");
const ENROLLMENT_TOKENS: TableDefinition<&[u8], &[u8]> = TableDefinition::new("enrollment_tokens");
const JOIN_TOKENS: TableDefinition<&[u8], &[u8]> = TableDefinition::new("join_tokens");

/// Open transactional controller authority state.
pub struct AuthorityStore {
    database: Database,
    controller_id: ControllerId,
    path: PathBuf,
}

impl AuthorityStore {
    /// Creates a new redb file and initializes every version 1 authority table.
    ///
    /// The target is opened with create-new semantics and is never silently
    /// replaced or reused.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError`] when the path already exists, the file cannot be
    /// created, redb initialization fails, or metadata cannot be committed.
    pub fn initialize(path: &Path, controller_id: ControllerId) -> Result<Self, StoreError> {
        if controller_id.is_zero() {
            return Err(StoreError::InvalidControllerId);
        }
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .open(path)
            .map_err(|source| StoreError::Create {
                path: path.to_path_buf(),
                source,
            })?;
        let database = redb::Builder::new().create_file(file)?;
        let write = database.begin_write()?;
        {
            let mut metadata = write.open_table(METADATA)?;
            let schema_version = STORE_SCHEMA_VERSION.to_be_bytes();
            metadata.insert(SCHEMA_VERSION_KEY, schema_version.as_slice())?;
            metadata.insert(CONTROLLER_ID_KEY, controller_id.as_bytes().as_slice())?;
        }
        create_empty_tables(&write)?;
        write.commit()?;
        Ok(Self {
            database,
            controller_id,
            path: path.to_path_buf(),
        })
    }

    /// Opens existing authority state and verifies schema and controller binding.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError`] for redb failure, missing or malformed metadata,
    /// an unsupported schema, a controller identity mismatch, or corrupt
    /// versioned records.
    pub fn open(path: &Path, expected_controller_id: ControllerId) -> Result<Self, StoreError> {
        if expected_controller_id.is_zero() {
            return Err(StoreError::InvalidControllerId);
        }
        let database = Database::open(path)?;
        let controller_id = read_metadata(&database)?;
        if controller_id != expected_controller_id {
            return Err(StoreError::ControllerMismatch {
                expected: expected_controller_id,
                actual: controller_id,
            });
        }
        let store = Self {
            database,
            controller_id,
            path: path.to_path_buf(),
        };
        store.verify()?;
        Ok(store)
    }

    /// Returns the controller identity permanently bound to this database.
    #[must_use]
    pub const fn controller_id(&self) -> ControllerId {
        self.controller_id
    }

    /// Returns the database path used to open this store.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Verifies metadata, table definitions, record decoding, and key identity.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError`] when any table is missing or incompatible, any
    /// record is malformed, or a record's derived identifier differs from its
    /// table key.
    pub fn verify(&self) -> Result<(), StoreError> {
        let controller_id = read_metadata(&self.database)?;
        if controller_id != self.controller_id {
            return Err(StoreError::ControllerMismatch {
                expected: self.controller_id,
                actual: controller_id,
            });
        }
        let read = self.database.begin_read()?;
        {
            let nodes = read.open_table(NODES)?;
            for entry in nodes.iter()? {
                let (key, value) = entry?;
                let node_id =
                    decode_identifier::<{ NodeId::LENGTH }>(key.value(), "nodes", "node key")?;
                let record = NodeRecord::decode(value.value())?;
                if record.node_id().as_bytes() != &node_id {
                    return Err(StoreError::RecordKeyMismatch { table: "nodes" });
                }
            }
        }
        {
            let networks = read.open_table(NETWORKS)?;
            for entry in networks.iter()? {
                let (key, value) = entry?;
                let network_id = decode_identifier::<{ NetworkId::LENGTH }>(
                    key.value(),
                    "networks",
                    "network key",
                )?;
                let record = NetworkRecord::decode(value.value())?;
                if record.network_id().as_bytes() != &network_id {
                    return Err(StoreError::RecordKeyMismatch { table: "networks" });
                }
            }
        }
        {
            let memberships = read.open_table(MEMBERSHIPS)?;
            let nodes = read.open_table(NODES)?;
            let networks = read.open_table(NETWORKS)?;
            for entry in memberships.iter()? {
                let (key, value) = entry?;
                let key = decode_identifier::<32>(key.value(), "memberships", "membership key")?;
                let record = MembershipRecord::decode(value.value())?;
                validate_membership_key(&record, &key)?;
                if nodes.get(record.node_id.as_bytes().as_slice())?.is_none() {
                    return Err(StoreError::NodeNotFound {
                        node_id: record.node_id,
                    });
                }
                if networks
                    .get(record.network_id.as_bytes().as_slice())?
                    .is_none()
                {
                    return Err(StoreError::NetworkNotFound {
                        network_id: record.network_id,
                    });
                }
            }
        }
        read.open_table(ENDPOINTS)?;
        {
            let tokens = read.open_table(ENROLLMENT_TOKENS)?;
            for entry in tokens.iter()? {
                let (key, value) = entry?;
                decode_identifier::<32>(key.value(), "enrollment_tokens", "token digest")?;
                TokenRecord::decode(
                    value.value(),
                    ENROLLMENT_TOKEN_RECORD_MAGIC,
                    "enrollment_tokens",
                )?;
            }
        }
        {
            let tokens = read.open_table(JOIN_TOKENS)?;
            let networks = read.open_table(NETWORKS)?;
            for entry in tokens.iter()? {
                let (key, value) = entry?;
                decode_identifier::<32>(key.value(), "join_tokens", "token digest")?;
                let record = JoinTokenRecord::decode(value.value())?;
                if networks
                    .get(record.network_id.as_bytes().as_slice())?
                    .is_none()
                {
                    return Err(StoreError::NetworkNotFound {
                        network_id: record.network_id,
                    });
                }
            }
        }
        Ok(())
    }

    /// Inserts one administratively known node identity.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::NodeAlreadyExists`] when the derived node ID is
    /// present, or a persistence/encoding error otherwise.
    pub fn create_node(&self, record: &NodeRecord) -> Result<(), StoreError> {
        let node_id = record.node_id();
        let encoded = record.encode()?;
        let write = self.database.begin_write()?;
        {
            let mut nodes = write.open_table(NODES)?;
            if nodes.get(node_id.as_bytes().as_slice())?.is_some() {
                return Err(StoreError::NodeAlreadyExists { node_id });
            }
            nodes.insert(node_id.as_bytes().as_slice(), encoded.as_slice())?;
        }
        write.commit()?;
        Ok(())
    }

    /// Returns one node record by stable identity.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError`] for persistence or record-decoding failure.
    pub fn get_node(&self, node_id: NodeId) -> Result<Option<NodeRecord>, StoreError> {
        let read = self.database.begin_read()?;
        let nodes = read.open_table(NODES)?;
        let Some(value) = nodes.get(node_id.as_bytes().as_slice())? else {
            return Ok(None);
        };
        let record = NodeRecord::decode(value.value())?;
        if record.node_id() != node_id {
            return Err(StoreError::RecordKeyMismatch { table: "nodes" });
        }
        Ok(Some(record))
    }

    /// Lists all nodes in stable node-ID order.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError`] for persistence, key, or record-decoding failure.
    pub fn list_nodes(&self) -> Result<Vec<NodeRecord>, StoreError> {
        let read = self.database.begin_read()?;
        let nodes = read.open_table(NODES)?;
        let mut records = Vec::new();
        for entry in nodes.iter()? {
            let (key, value) = entry?;
            let key = decode_identifier::<{ NodeId::LENGTH }>(key.value(), "nodes", "node key")?;
            let record = NodeRecord::decode(value.value())?;
            if record.node_id().as_bytes() != &key {
                return Err(StoreError::RecordKeyMismatch { table: "nodes" });
            }
            records.push(record);
        }
        Ok(records)
    }

    /// Changes a node's administrative enabled state and invalidates grants.
    ///
    /// Returns `true` when a stored value changed and `false` for an idempotent
    /// request. A change rotates every membership grant serial and advances
    /// each affected network's controller epoch and snapshot revision in the
    /// same transaction.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::NodeNotFound`] for an unknown node or a
    /// persistence/decoding error otherwise.
    pub fn set_node_enabled(&self, node_id: NodeId, enabled: bool) -> Result<bool, StoreError> {
        let write = self.database.begin_write()?;
        let mut node = load_node_for_write(&write, node_id)?;
        if node.enabled == enabled {
            return Ok(false);
        }

        let mut memberships_to_update = Vec::new();
        {
            let memberships = write.open_table(MEMBERSHIPS)?;
            for entry in memberships.iter()? {
                let (key, value) = entry?;
                let key = decode_identifier::<32>(key.value(), "memberships", "membership key")?;
                let record = MembershipRecord::decode(value.value())?;
                validate_membership_key(&record, &key)?;
                if record.node_id == node_id {
                    memberships_to_update.push((key, record));
                }
            }
        }

        let mut authority_updates = Vec::with_capacity(memberships_to_update.len());
        for (key, mut membership) in memberships_to_update {
            membership.grant_serial = generate_grant_serial()?;
            let mut network = load_network_for_write(&write, membership.network_id)?;
            network.advance_authority()?;
            authority_updates.push((
                key,
                membership.encode()?,
                membership.network_id,
                network.encode()?,
            ));
        }

        node.enabled = enabled;
        let encoded_node = node.encode()?;
        {
            let mut nodes = write.open_table(NODES)?;
            nodes.insert(node_id.as_bytes().as_slice(), encoded_node.as_slice())?;
        }
        {
            let mut memberships = write.open_table(MEMBERSHIPS)?;
            for (key, encoded_membership, _, _) in &authority_updates {
                memberships.insert(key.as_slice(), encoded_membership.as_slice())?;
            }
        }
        {
            let mut networks = write.open_table(NETWORKS)?;
            for (_, _, network_id, encoded_network) in &authority_updates {
                networks.insert(network_id.as_bytes().as_slice(), encoded_network.as_slice())?;
            }
        }
        write.commit()?;
        Ok(true)
    }

    /// Inserts one virtual network and its canonical policy.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::NetworkAlreadyExists`] for a duplicate ID or a
    /// persistence/encoding error otherwise.
    pub fn create_network(&self, record: &NetworkRecord) -> Result<(), StoreError> {
        let network_id = record.network_id();
        let encoded = record.encode()?;
        let write = self.database.begin_write()?;
        {
            let mut networks = write.open_table(NETWORKS)?;
            if networks.get(network_id.as_bytes().as_slice())?.is_some() {
                return Err(StoreError::NetworkAlreadyExists { network_id });
            }
            networks.insert(network_id.as_bytes().as_slice(), encoded.as_slice())?;
        }
        write.commit()?;
        Ok(())
    }

    /// Returns one network record by stable ID.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError`] for persistence or record-decoding failure.
    pub fn get_network(&self, network_id: NetworkId) -> Result<Option<NetworkRecord>, StoreError> {
        let read = self.database.begin_read()?;
        let networks = read.open_table(NETWORKS)?;
        let Some(value) = networks.get(network_id.as_bytes().as_slice())? else {
            return Ok(None);
        };
        let record = NetworkRecord::decode(value.value())?;
        if record.network_id() != network_id {
            return Err(StoreError::RecordKeyMismatch { table: "networks" });
        }
        Ok(Some(record))
    }

    /// Lists all networks in stable network-ID order.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError`] for persistence, key, or record-decoding failure.
    pub fn list_networks(&self) -> Result<Vec<NetworkRecord>, StoreError> {
        let read = self.database.begin_read()?;
        let networks = read.open_table(NETWORKS)?;
        let mut records = Vec::new();
        for entry in networks.iter()? {
            let (key, value) = entry?;
            let key =
                decode_identifier::<{ NetworkId::LENGTH }>(key.value(), "networks", "network key")?;
            let record = NetworkRecord::decode(value.value())?;
            if record.network_id().as_bytes() != &key {
                return Err(StoreError::RecordKeyMismatch { table: "networks" });
            }
            records.push(record);
        }
        Ok(records)
    }

    /// Creates and stores one single-use enrollment token digest.
    ///
    /// Raw token bytes are returned once and are never persisted.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError`] for an invalid lifetime, unavailable randomness,
    /// repeated digest collision, or persistence failure.
    pub fn issue_enrollment_token(
        &self,
        created_at: u64,
        expires_at: u64,
    ) -> Result<BearerToken, StoreError> {
        let record = TokenRecord::new(created_at, expires_at)?;
        let encoded = record.encode(ENROLLMENT_TOKEN_RECORD_MAGIC);
        for _ in 0..TOKEN_GENERATION_ATTEMPTS {
            let token = BearerToken::generate()?;
            let digest = enrollment_token_digest(&token);
            let write = self.database.begin_write()?;
            let inserted = {
                let mut tokens = write.open_table(ENROLLMENT_TOKENS)?;
                if tokens.get(digest.as_slice())?.is_some() {
                    false
                } else {
                    tokens.insert(digest.as_slice(), encoded.as_slice())?;
                    true
                }
            };
            if inserted {
                write.commit()?;
                return Ok(token);
            }
        }
        Err(StoreError::TokenGenerationCollision)
    }

    /// Atomically consumes an enrollment token and registers its node identity.
    ///
    /// A validation, duplicate-node, expiry, or persistence failure leaves the
    /// token unconsumed.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError`] when the node record is invalid, the token is
    /// missing or expired, the node exists, or the transaction cannot commit.
    pub fn enroll_node(
        &self,
        token: &BearerToken,
        public_key: IdentityPublicKey,
        display_name: &str,
        now: u64,
    ) -> Result<NodeRecord, StoreError> {
        let record = NodeRecord::new(public_key, display_name, now)?;
        let node_id = record.node_id();
        let encoded_node = record.encode()?;
        let digest = enrollment_token_digest(token);
        let write = self.database.begin_write()?;
        let token_record = {
            let tokens = write.open_table(ENROLLMENT_TOKENS)?;
            let Some(value) = tokens.get(digest.as_slice())? else {
                return Err(StoreError::EnrollmentTokenInvalid);
            };
            TokenRecord::decode(
                value.value(),
                ENROLLMENT_TOKEN_RECORD_MAGIC,
                "enrollment_tokens",
            )?
        };
        if token_record.is_expired(now) {
            return Err(StoreError::EnrollmentTokenInvalid);
        }
        {
            let mut nodes = write.open_table(NODES)?;
            if nodes.get(node_id.as_bytes().as_slice())?.is_some() {
                return Err(StoreError::NodeAlreadyExists { node_id });
            }
            nodes.insert(node_id.as_bytes().as_slice(), encoded_node.as_slice())?;
        }
        {
            let mut tokens = write.open_table(ENROLLMENT_TOKENS)?;
            if tokens.remove(digest.as_slice())?.is_none() {
                return Err(StoreError::EnrollmentTokenInvalid);
            }
        }
        write.commit()?;
        Ok(record)
    }

    /// Creates and stores one single-use join token scoped to a network.
    ///
    /// Raw token bytes are returned once and are never persisted.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError`] for an unknown network, invalid lifetime,
    /// unavailable randomness, repeated collision, or persistence failure.
    pub fn issue_join_token(
        &self,
        network_id: NetworkId,
        created_at: u64,
        expires_at: u64,
    ) -> Result<BearerToken, StoreError> {
        let record = JoinTokenRecord {
            token: TokenRecord::new(created_at, expires_at)?,
            network_id,
        };
        let encoded = record.encode();
        for _ in 0..TOKEN_GENERATION_ATTEMPTS {
            let token = BearerToken::generate()?;
            let digest = join_token_digest(&token);
            let write = self.database.begin_write()?;
            {
                let networks = write.open_table(NETWORKS)?;
                if networks.get(network_id.as_bytes().as_slice())?.is_none() {
                    return Err(StoreError::NetworkNotFound { network_id });
                }
            }
            let inserted = {
                let mut tokens = write.open_table(JOIN_TOKENS)?;
                if tokens.get(digest.as_slice())?.is_some() {
                    false
                } else {
                    tokens.insert(digest.as_slice(), encoded.as_slice())?;
                    true
                }
            };
            if inserted {
                write.commit()?;
                return Ok(token);
            }
        }
        Err(StoreError::TokenGenerationCollision)
    }

    /// Atomically consumes a network-scoped token and activates membership.
    ///
    /// Repeating an already-active join is idempotent and does not consume the
    /// supplied token or advance authority counters.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError`] for an unknown or disabled node, unknown/full
    /// network, suspended membership, invalid token, exhausted counter, or
    /// transaction failure.
    pub fn join_with_token(
        &self,
        token: &BearerToken,
        node_id: NodeId,
        network_id: NetworkId,
        now: u64,
    ) -> Result<AuthorityRevision, StoreError> {
        let digest = join_token_digest(token);
        self.add_membership_transaction(node_id, network_id, now, Some(digest))
    }

    /// Administratively activates membership without a bearer token.
    ///
    /// Repeating an already-active assignment is idempotent.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError`] for an unknown or disabled node, unknown/full
    /// network, suspended membership, exhausted counter, or transaction failure.
    pub fn add_member(
        &self,
        node_id: NodeId,
        network_id: NetworkId,
        now: u64,
    ) -> Result<AuthorityRevision, StoreError> {
        self.add_membership_transaction(node_id, network_id, now, None)
    }

    /// Removes membership and endpoint state in one authority transaction.
    ///
    /// Repeating an absent leave is idempotent and returns current counters.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError`] for an unknown network, corrupt state, exhausted
    /// counter, or transaction failure.
    pub fn leave_network(
        &self,
        node_id: NodeId,
        network_id: NetworkId,
    ) -> Result<AuthorityRevision, StoreError> {
        let key = membership_key(network_id, node_id);
        let write = self.database.begin_write()?;
        let mut network = load_network_for_write(&write, network_id)?;
        let present = {
            let memberships = write.open_table(MEMBERSHIPS)?;
            let present = memberships.get(key.as_slice())?.is_some();
            present
        };
        if !present {
            return Ok(network.revision());
        }
        let revision = network.advance_authority()?;
        let encoded_network = network.encode()?;
        {
            let mut memberships = write.open_table(MEMBERSHIPS)?;
            memberships.remove(key.as_slice())?;
        }
        {
            let mut endpoints = write.open_table(ENDPOINTS)?;
            endpoints.remove(key.as_slice())?;
        }
        {
            let mut networks = write.open_table(NETWORKS)?;
            networks.insert(network_id.as_bytes().as_slice(), encoded_network.as_slice())?;
        }
        write.commit()?;
        Ok(revision)
    }

    /// Suspends or resumes an existing membership and rotates its grant serial.
    ///
    /// Repeating the current status is idempotent.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError`] for an unknown network or membership, unavailable
    /// randomness, exhausted counter, corrupt state, or transaction failure.
    pub fn set_membership_status(
        &self,
        node_id: NodeId,
        network_id: NetworkId,
        status: MembershipStatus,
    ) -> Result<AuthorityRevision, StoreError> {
        let key = membership_key(network_id, node_id);
        let write = self.database.begin_write()?;
        let mut network = load_network_for_write(&write, network_id)?;
        let mut membership = {
            let memberships = write.open_table(MEMBERSHIPS)?;
            let Some(value) = memberships.get(key.as_slice())? else {
                return Err(StoreError::MembershipNotFound {
                    network_id,
                    node_id,
                });
            };
            MembershipRecord::decode(value.value())?
        };
        validate_membership_key(&membership, &key)?;
        if membership.status == status {
            return Ok(network.revision());
        }
        membership.status = status;
        membership.grant_serial = generate_grant_serial()?;
        let revision = network.advance_authority()?;
        let encoded_membership = membership.encode()?;
        let encoded_network = network.encode()?;
        {
            let mut memberships = write.open_table(MEMBERSHIPS)?;
            memberships.insert(key.as_slice(), encoded_membership.as_slice())?;
        }
        {
            let mut networks = write.open_table(NETWORKS)?;
            networks.insert(network_id.as_bytes().as_slice(), encoded_network.as_slice())?;
        }
        write.commit()?;
        Ok(revision)
    }

    /// Returns one network membership.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError`] for persistence, key, or record-decoding failure.
    pub fn get_membership(
        &self,
        node_id: NodeId,
        network_id: NetworkId,
    ) -> Result<Option<MembershipRecord>, StoreError> {
        let key = membership_key(network_id, node_id);
        let read = self.database.begin_read()?;
        let memberships = read.open_table(MEMBERSHIPS)?;
        let Some(value) = memberships.get(key.as_slice())? else {
            return Ok(None);
        };
        let record = MembershipRecord::decode(value.value())?;
        validate_membership_key(&record, &key)?;
        Ok(Some(record))
    }

    /// Lists every membership in one network in node-ID order.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError`] for persistence, key, or record-decoding failure.
    pub fn list_memberships(
        &self,
        network_id: NetworkId,
    ) -> Result<Vec<MembershipRecord>, StoreError> {
        let read = self.database.begin_read()?;
        let memberships = read.open_table(MEMBERSHIPS)?;
        let mut records = Vec::new();
        for entry in memberships.iter()? {
            let (key, value) = entry?;
            let key = decode_identifier::<32>(key.value(), "memberships", "membership key")?;
            let record = MembershipRecord::decode(value.value())?;
            validate_membership_key(&record, &key)?;
            if record.network_id == network_id {
                records.push(record);
            }
        }
        Ok(records)
    }

    fn add_membership_transaction(
        &self,
        node_id: NodeId,
        network_id: NetworkId,
        now: u64,
        token_digest: Option<[u8; 32]>,
    ) -> Result<AuthorityRevision, StoreError> {
        let key = membership_key(network_id, node_id);
        let write = self.database.begin_write()?;
        let mut network = load_network_for_write(&write, network_id)?;
        {
            let memberships = write.open_table(MEMBERSHIPS)?;
            if let Some(value) = memberships.get(key.as_slice())? {
                let record = MembershipRecord::decode(value.value())?;
                validate_membership_key(&record, &key)?;
                return match record.status {
                    MembershipStatus::Active => Ok(network.revision()),
                    MembershipStatus::Suspended => Err(StoreError::MembershipSuspended {
                        network_id,
                        node_id,
                    }),
                };
            };
        }
        let node = load_node_for_write(&write, node_id)?;
        if !node.enabled {
            return Err(StoreError::NodeDisabled { node_id });
        }
        enforce_network_capacity(&write, &network)?;
        if let Some(digest) = token_digest {
            let token_record = {
                let tokens = write.open_table(JOIN_TOKENS)?;
                let Some(value) = tokens.get(digest.as_slice())? else {
                    return Err(StoreError::JoinTokenInvalid);
                };
                JoinTokenRecord::decode(value.value())?
            };
            if token_record.token.is_expired(now) || token_record.network_id != network_id {
                return Err(StoreError::JoinTokenInvalid);
            }
        }
        let membership = MembershipRecord::new(network_id, node_id, now, generate_grant_serial()?);
        let revision = network.advance_authority()?;
        let encoded_membership = membership.encode()?;
        let encoded_network = network.encode()?;
        {
            let mut memberships = write.open_table(MEMBERSHIPS)?;
            memberships.insert(key.as_slice(), encoded_membership.as_slice())?;
        }
        {
            let mut networks = write.open_table(NETWORKS)?;
            networks.insert(network_id.as_bytes().as_slice(), encoded_network.as_slice())?;
        }
        if let Some(digest) = token_digest {
            let mut tokens = write.open_table(JOIN_TOKENS)?;
            if tokens.remove(digest.as_slice())?.is_none() {
                return Err(StoreError::JoinTokenInvalid);
            }
        }
        write.commit()?;
        Ok(revision)
    }
}

impl std::fmt::Debug for AuthorityStore {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("AuthorityStore")
            .field("controller_id", &self.controller_id)
            .field("path", &self.path)
            .finish_non_exhaustive()
    }
}

/// Persisted node identity and administrative state.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NodeRecord {
    public_key: IdentityPublicKey,
    enabled: bool,
    display_name: String,
    created_at: u64,
}

impl NodeRecord {
    /// Creates a validated enabled node record.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError`] when the display name is empty, oversized, or
    /// contains a control character.
    pub fn new(
        public_key: IdentityPublicKey,
        display_name: &str,
        created_at: u64,
    ) -> Result<Self, StoreError> {
        validate_display_name(display_name)?;
        Ok(Self {
            public_key,
            enabled: true,
            display_name: display_name.to_owned(),
            created_at,
        })
    }

    /// Returns the stable node ID derived from the public key.
    #[must_use]
    pub fn node_id(&self) -> NodeId {
        derive_node_id(self.public_key)
    }

    /// Returns the node's validated Ed25519 public key.
    #[must_use]
    pub const fn public_key(&self) -> IdentityPublicKey {
        self.public_key
    }

    /// Returns whether application authentication is administratively allowed.
    #[must_use]
    pub const fn enabled(&self) -> bool {
        self.enabled
    }

    /// Returns the bounded human-readable node name.
    #[must_use]
    pub fn display_name(&self) -> &str {
        &self.display_name
    }

    /// Returns the creation time as Unix seconds.
    #[must_use]
    pub const fn created_at(&self) -> u64 {
        self.created_at
    }

    fn encode(&self) -> Result<Vec<u8>, StoreError> {
        validate_display_name(&self.display_name)?;
        let length = NODE_RECORD_FIXED_LENGTH
            .checked_add(self.display_name.len())
            .ok_or(StoreError::LengthOverflow)?;
        let name_length =
            u16::try_from(self.display_name.len()).map_err(|_| StoreError::LengthOverflow)?;
        let mut bytes = allocate_record(length)?;
        bytes[0..4].copy_from_slice(&NODE_RECORD_MAGIC);
        bytes[4] = RECORD_VERSION;
        bytes[5] = if self.enabled { NODE_ENABLED_FLAG } else { 0 };
        bytes[6..8].copy_from_slice(&name_length.to_be_bytes());
        bytes[8..16].copy_from_slice(&self.created_at.to_be_bytes());
        bytes[16..48].copy_from_slice(self.public_key.as_bytes());
        bytes[NODE_RECORD_FIXED_LENGTH..].copy_from_slice(self.display_name.as_bytes());
        Ok(bytes)
    }

    fn decode(bytes: &[u8]) -> Result<Self, StoreError> {
        if bytes.len() < NODE_RECORD_FIXED_LENGTH {
            return Err(malformed("nodes", "record is truncated"));
        }
        if bytes.get(0..4) != Some(NODE_RECORD_MAGIC.as_slice()) {
            return Err(malformed("nodes", "record magic is invalid"));
        }
        if bytes[4] != RECORD_VERSION {
            return Err(malformed("nodes", "record version is unsupported"));
        }
        let flags = bytes[5];
        if flags & !NODE_ENABLED_FLAG != 0 {
            return Err(malformed("nodes", "record flags are invalid"));
        }
        let name_length = usize::from(u16::from_be_bytes([bytes[6], bytes[7]]));
        let expected = NODE_RECORD_FIXED_LENGTH
            .checked_add(name_length)
            .ok_or(StoreError::LengthOverflow)?;
        if bytes.len() != expected {
            return Err(malformed("nodes", "record length is inconsistent"));
        }
        let created_at = u64::from_be_bytes(copy_array(bytes, 8, "nodes", "creation time")?);
        let public_key =
            IdentityPublicKey::from_bytes(copy_array(bytes, 16, "nodes", "public key")?)?;
        let display_name = decode_display_name(&bytes[NODE_RECORD_FIXED_LENGTH..])?;
        Ok(Self {
            public_key,
            enabled: flags & NODE_ENABLED_FLAG != 0,
            display_name,
            created_at,
        })
    }
}

/// Persisted virtual-network authority counters and canonical policy.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NetworkRecord {
    controller_epoch: u64,
    snapshot_revision: u64,
    created_at: u64,
    policy: NetworkPolicy,
    display_name: String,
}

impl NetworkRecord {
    /// Creates a new network at epoch and snapshot revision 1.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError`] when the network ID or policy is invalid, or the
    /// display name violates its text bound.
    pub fn new(
        policy: NetworkPolicy,
        display_name: &str,
        created_at: u64,
    ) -> Result<Self, StoreError> {
        if policy.network_id.is_zero() {
            return Err(StoreError::InvalidNetworkId);
        }
        let mut encoded = [0_u8; NETWORK_POLICY_LENGTH];
        policy.encode(&mut encoded)?;
        validate_display_name(display_name)?;
        Ok(Self {
            controller_epoch: 1,
            snapshot_revision: 1,
            created_at,
            policy,
            display_name: display_name.to_owned(),
        })
    }

    /// Returns the stable virtual-network identifier.
    #[must_use]
    pub const fn network_id(&self) -> NetworkId {
        self.policy.network_id
    }

    /// Returns the non-zero authorization epoch.
    #[must_use]
    pub const fn controller_epoch(&self) -> u64 {
        self.controller_epoch
    }

    /// Returns the non-zero peer snapshot revision.
    #[must_use]
    pub const fn snapshot_revision(&self) -> u64 {
        self.snapshot_revision
    }

    /// Returns the creation time as Unix seconds.
    #[must_use]
    pub const fn created_at(&self) -> u64 {
        self.created_at
    }

    /// Returns the exact canonical policy stored for this network.
    #[must_use]
    pub const fn policy(&self) -> NetworkPolicy {
        self.policy
    }

    /// Returns the bounded human-readable network name.
    #[must_use]
    pub fn display_name(&self) -> &str {
        &self.display_name
    }

    fn advance_authority(&mut self) -> Result<AuthorityRevision, StoreError> {
        self.controller_epoch =
            self.controller_epoch
                .checked_add(1)
                .ok_or(StoreError::CounterExhausted {
                    network_id: self.network_id(),
                })?;
        self.snapshot_revision =
            self.snapshot_revision
                .checked_add(1)
                .ok_or(StoreError::CounterExhausted {
                    network_id: self.network_id(),
                })?;
        Ok(self.revision())
    }

    const fn revision(&self) -> AuthorityRevision {
        AuthorityRevision {
            network_id: self.policy.network_id,
            controller_epoch: self.controller_epoch,
            snapshot_revision: self.snapshot_revision,
        }
    }

    fn encode(&self) -> Result<Vec<u8>, StoreError> {
        if self.controller_epoch == 0 || self.snapshot_revision == 0 {
            return Err(malformed("networks", "authority counter is zero"));
        }
        validate_display_name(&self.display_name)?;
        let length = NETWORK_RECORD_FIXED_LENGTH
            .checked_add(self.display_name.len())
            .ok_or(StoreError::LengthOverflow)?;
        let name_length =
            u16::try_from(self.display_name.len()).map_err(|_| StoreError::LengthOverflow)?;
        let mut policy = [0_u8; NETWORK_POLICY_LENGTH];
        self.policy.encode(&mut policy)?;
        let mut bytes = allocate_record(length)?;
        bytes[0..4].copy_from_slice(&NETWORK_RECORD_MAGIC);
        bytes[4] = RECORD_VERSION;
        bytes[5] = 0;
        bytes[6..8].copy_from_slice(&name_length.to_be_bytes());
        bytes[8..16].copy_from_slice(&self.controller_epoch.to_be_bytes());
        bytes[16..24].copy_from_slice(&self.snapshot_revision.to_be_bytes());
        bytes[24..32].copy_from_slice(&self.created_at.to_be_bytes());
        bytes[32..96].copy_from_slice(&policy);
        bytes[NETWORK_RECORD_FIXED_LENGTH..].copy_from_slice(self.display_name.as_bytes());
        Ok(bytes)
    }

    fn decode(bytes: &[u8]) -> Result<Self, StoreError> {
        if bytes.len() < NETWORK_RECORD_FIXED_LENGTH {
            return Err(malformed("networks", "record is truncated"));
        }
        if bytes.get(0..4) != Some(NETWORK_RECORD_MAGIC.as_slice()) {
            return Err(malformed("networks", "record magic is invalid"));
        }
        if bytes[4] != RECORD_VERSION {
            return Err(malformed("networks", "record version is unsupported"));
        }
        if bytes[5] != 0 {
            return Err(malformed("networks", "record flags are invalid"));
        }
        let name_length = usize::from(u16::from_be_bytes([bytes[6], bytes[7]]));
        let expected = NETWORK_RECORD_FIXED_LENGTH
            .checked_add(name_length)
            .ok_or(StoreError::LengthOverflow)?;
        if bytes.len() != expected {
            return Err(malformed("networks", "record length is inconsistent"));
        }
        let controller_epoch =
            u64::from_be_bytes(copy_array(bytes, 8, "networks", "controller epoch")?);
        let snapshot_revision =
            u64::from_be_bytes(copy_array(bytes, 16, "networks", "snapshot revision")?);
        if controller_epoch == 0 || snapshot_revision == 0 {
            return Err(malformed("networks", "authority counter is zero"));
        }
        let created_at = u64::from_be_bytes(copy_array(bytes, 24, "networks", "creation time")?);
        let policy = NetworkPolicy::decode(
            bytes
                .get(32..96)
                .ok_or_else(|| malformed("networks", "policy is truncated"))?,
        )?;
        let display_name = decode_display_name(&bytes[NETWORK_RECORD_FIXED_LENGTH..])?;
        Ok(Self {
            controller_epoch,
            snapshot_revision,
            created_at,
            policy,
            display_name,
        })
    }
}

/// One raw 32-byte enrollment or join bearer credential.
///
/// The value is non-cloneable, redacts diagnostics, and zeroizes on drop.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct BearerToken([u8; TOKEN_LENGTH]);

impl BearerToken {
    /// Validates and owns raw token bytes received from a trusted input boundary.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::InvalidBearerToken`] for an all-zero token.
    pub fn from_bytes(bytes: [u8; TOKEN_LENGTH]) -> Result<Self, StoreError> {
        if bytes.iter().all(|byte| *byte == 0) {
            return Err(StoreError::InvalidBearerToken);
        }
        Ok(Self(bytes))
    }

    /// Generates a fresh token from operating-system cryptographic randomness.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::RandomnessUnavailable`] when the operating system
    /// random source fails.
    pub fn generate() -> Result<Self, StoreError> {
        let mut bytes = [0_u8; TOKEN_LENGTH];
        loop {
            getrandom::fill(&mut bytes).map_err(|_| StoreError::RandomnessUnavailable)?;
            if bytes.iter().any(|byte| *byte != 0) {
                return Ok(Self(bytes));
            }
        }
    }

    /// Intentionally exposes the raw token at a control-message or CLI boundary.
    #[must_use]
    pub const fn expose_secret(&self) -> &[u8; TOKEN_LENGTH] {
        &self.0
    }

    pub(crate) const fn duplicate(&self) -> Self {
        Self(self.0)
    }
}

impl std::fmt::Debug for BearerToken {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("BearerToken([REDACTED])")
    }
}

/// Administrative membership state persisted by the controller.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum MembershipStatus {
    /// Node is authorized according to its current grant and epoch.
    Active = 1,
    /// Membership exists but must not receive a usable grant.
    Suspended = 2,
}

impl TryFrom<u8> for MembershipStatus {
    type Error = StoreError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Self::Active),
            2 => Ok(Self::Suspended),
            _ => Err(malformed("memberships", "membership status is invalid")),
        }
    }
}

/// Persisted node authorization within one virtual network.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MembershipRecord {
    status: MembershipStatus,
    permissions: MembershipPermissions,
    joined_at: u64,
    network_id: NetworkId,
    node_id: NodeId,
    grant_serial: GrantSerial,
}

impl MembershipRecord {
    fn new(
        network_id: NetworkId,
        node_id: NodeId,
        joined_at: u64,
        grant_serial: GrantSerial,
    ) -> Self {
        Self {
            status: MembershipStatus::Active,
            permissions: MembershipPermissions::ALL,
            joined_at,
            network_id,
            node_id,
            grant_serial,
        }
    }

    /// Returns whether this authorization is active or suspended.
    #[must_use]
    pub const fn status(&self) -> MembershipStatus {
        self.status
    }

    /// Returns the allowed data-plane operations.
    #[must_use]
    pub const fn permissions(&self) -> MembershipPermissions {
        self.permissions
    }

    /// Returns the membership creation time as Unix seconds.
    #[must_use]
    pub const fn joined_at(&self) -> u64 {
        self.joined_at
    }

    /// Returns the authorized virtual network.
    #[must_use]
    pub const fn network_id(&self) -> NetworkId {
        self.network_id
    }

    /// Returns the authorized node identity.
    #[must_use]
    pub const fn node_id(&self) -> NodeId {
        self.node_id
    }

    /// Returns the current non-zero grant serial.
    #[must_use]
    pub const fn grant_serial(&self) -> GrantSerial {
        self.grant_serial
    }

    fn encode(&self) -> Result<[u8; MEMBERSHIP_RECORD_LENGTH], StoreError> {
        if self.network_id.is_zero() || self.node_id.is_zero() || self.grant_serial.is_zero() {
            return Err(malformed(
                "memberships",
                "membership identity or grant serial is zero",
            ));
        }
        let mut bytes = [0_u8; MEMBERSHIP_RECORD_LENGTH];
        bytes[0..4].copy_from_slice(&MEMBERSHIP_RECORD_MAGIC);
        bytes[4] = RECORD_VERSION;
        bytes[5] = self.status as u8;
        bytes[6..8].copy_from_slice(&self.permissions.bits().to_be_bytes());
        bytes[8..16].copy_from_slice(&self.joined_at.to_be_bytes());
        bytes[16..32].copy_from_slice(self.network_id.as_bytes());
        bytes[32..48].copy_from_slice(self.node_id.as_bytes());
        bytes[48..64].copy_from_slice(self.grant_serial.as_bytes());
        Ok(bytes)
    }

    fn decode(bytes: &[u8]) -> Result<Self, StoreError> {
        if bytes.len() != MEMBERSHIP_RECORD_LENGTH {
            return Err(malformed("memberships", "record length is invalid"));
        }
        if bytes.get(0..4) != Some(MEMBERSHIP_RECORD_MAGIC.as_slice()) {
            return Err(malformed("memberships", "record magic is invalid"));
        }
        if bytes[4] != RECORD_VERSION {
            return Err(malformed("memberships", "record version is unsupported"));
        }
        let status = MembershipStatus::try_from(bytes[5])?;
        let permissions =
            MembershipPermissions::from_bits(u16::from_be_bytes([bytes[6], bytes[7]]))?;
        if permissions == MembershipPermissions::NONE {
            return Err(malformed("memberships", "permissions are empty"));
        }
        let joined_at = u64::from_be_bytes(copy_array(
            bytes,
            8,
            "memberships",
            "join time is truncated",
        )?);
        let network_id = NetworkId::from_bytes(copy_array(
            bytes,
            16,
            "memberships",
            "network ID is truncated",
        )?);
        let node_id = NodeId::from_bytes(copy_array(
            bytes,
            32,
            "memberships",
            "node ID is truncated",
        )?);
        let grant_serial = GrantSerial::from_bytes(copy_array(
            bytes,
            48,
            "memberships",
            "grant serial is truncated",
        )?);
        if network_id.is_zero() || node_id.is_zero() || grant_serial.is_zero() {
            return Err(malformed(
                "memberships",
                "membership identity or grant serial is zero",
            ));
        }
        Ok(Self {
            status,
            permissions,
            joined_at,
            network_id,
            node_id,
            grant_serial,
        })
    }
}

/// Network counters committed by one authority mutation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AuthorityRevision {
    /// Mutated network.
    pub network_id: NetworkId,
    /// Current non-zero authorization epoch.
    pub controller_epoch: u64,
    /// Current non-zero peer snapshot revision.
    pub snapshot_revision: u64,
}

#[derive(Clone, Copy)]
struct TokenRecord {
    created_at: u64,
    expires_at: u64,
}

impl TokenRecord {
    fn new(created_at: u64, expires_at: u64) -> Result<Self, StoreError> {
        if expires_at <= created_at {
            return Err(StoreError::InvalidTokenLifetime);
        }
        Ok(Self {
            created_at,
            expires_at,
        })
    }

    fn encode(self, magic: [u8; 4]) -> [u8; TOKEN_RECORD_LENGTH] {
        let mut bytes = [0_u8; TOKEN_RECORD_LENGTH];
        bytes[0..4].copy_from_slice(&magic);
        bytes[4] = RECORD_VERSION;
        bytes[8..16].copy_from_slice(&self.created_at.to_be_bytes());
        bytes[16..24].copy_from_slice(&self.expires_at.to_be_bytes());
        bytes
    }

    fn decode(bytes: &[u8], magic: [u8; 4], table: &'static str) -> Result<Self, StoreError> {
        if bytes.len() != TOKEN_RECORD_LENGTH {
            return Err(malformed(table, "token record length is invalid"));
        }
        if bytes.get(0..4) != Some(magic.as_slice()) || bytes[4] != RECORD_VERSION {
            return Err(malformed(table, "token record header is invalid"));
        }
        if bytes[5..8].iter().any(|byte| *byte != 0) {
            return Err(malformed(table, "token reserved bytes are non-zero"));
        }
        let record = Self {
            created_at: u64::from_be_bytes(copy_array(
                bytes,
                8,
                table,
                "token creation time is truncated",
            )?),
            expires_at: u64::from_be_bytes(copy_array(
                bytes,
                16,
                table,
                "token expiry is truncated",
            )?),
        };
        if record.expires_at <= record.created_at {
            return Err(malformed(table, "token lifetime is invalid"));
        }
        Ok(record)
    }

    const fn is_expired(self, now: u64) -> bool {
        now >= self.expires_at
    }
}

#[derive(Clone, Copy)]
struct JoinTokenRecord {
    token: TokenRecord,
    network_id: NetworkId,
}

impl JoinTokenRecord {
    fn encode(self) -> [u8; JOIN_TOKEN_RECORD_LENGTH] {
        let token = self.token.encode(JOIN_TOKEN_RECORD_MAGIC);
        let mut bytes = [0_u8; JOIN_TOKEN_RECORD_LENGTH];
        bytes[..TOKEN_RECORD_LENGTH].copy_from_slice(&token);
        bytes[24..40].copy_from_slice(self.network_id.as_bytes());
        bytes
    }

    fn decode(bytes: &[u8]) -> Result<Self, StoreError> {
        if bytes.len() != JOIN_TOKEN_RECORD_LENGTH {
            return Err(malformed(
                "join_tokens",
                "join token record length is invalid",
            ));
        }
        let token = TokenRecord::decode(
            &bytes[..TOKEN_RECORD_LENGTH],
            JOIN_TOKEN_RECORD_MAGIC,
            "join_tokens",
        )?;
        let network_id = NetworkId::from_bytes(copy_array(
            bytes,
            24,
            "join_tokens",
            "join token network ID is truncated",
        )?);
        if network_id.is_zero() {
            return Err(malformed("join_tokens", "join token network ID is zero"));
        }
        Ok(Self { token, network_id })
    }
}

/// Authority database initialization, validation, or transaction failure.
#[derive(Debug, Error)]
pub enum StoreError {
    /// The new database file could not be created exclusively.
    #[error("could not create authority database {path}: {source}")]
    Create {
        /// Requested database path.
        path: PathBuf,
        /// Underlying filesystem error.
        source: std::io::Error,
    },
    /// A boxed redb database, transaction, table, storage, or commit failure.
    #[error("authority database operation failed: {0}")]
    Redb(#[source] Box<redb::Error>),
    /// A canonical network policy failed validation.
    #[error("invalid stored network policy: {0}")]
    Codec(#[from] CodecError),
    /// An Ed25519 public key failed validation.
    #[error("invalid stored identity key: {0}")]
    Crypto(#[from] CryptoError),
    /// The configured or stored controller ID is all zero.
    #[error("controller ID must be non-zero")]
    InvalidControllerId,
    /// A network record uses the all-zero network ID.
    #[error("network ID must be non-zero")]
    InvalidNetworkId,
    /// Required schema metadata is absent or malformed.
    #[error("authority metadata field {field} is missing or malformed")]
    InvalidMetadata {
        /// Stable metadata field name.
        field: &'static str,
    },
    /// The database schema is not supported by this binary.
    #[error("unsupported authority schema version {actual}; supported version is {supported}")]
    UnsupportedSchema {
        /// Version stored in the database.
        actual: u32,
        /// Version implemented by this binary.
        supported: u32,
    },
    /// The database belongs to another controller identity.
    #[error("authority database controller mismatch: expected {expected}, found {actual}")]
    ControllerMismatch {
        /// Identity loaded by the process.
        expected: ControllerId,
        /// Identity stored in database metadata.
        actual: ControllerId,
    },
    /// A persisted internal record is structurally invalid.
    #[error("malformed authority record in {table}: {reason}")]
    MalformedRecord {
        /// Stable table name.
        table: &'static str,
        /// Redacted invariant description.
        reason: &'static str,
    },
    /// A record's derived identity differs from its database key.
    #[error("authority record key does not match its value in {table}")]
    RecordKeyMismatch {
        /// Stable table name.
        table: &'static str,
    },
    /// A node with the same derived ID already exists.
    #[error("node {node_id} already exists")]
    NodeAlreadyExists {
        /// Duplicate node ID.
        node_id: NodeId,
    },
    /// A requested node does not exist.
    #[error("node {node_id} does not exist")]
    NodeNotFound {
        /// Missing node ID.
        node_id: NodeId,
    },
    /// A network with the same ID already exists.
    #[error("network {network_id} already exists")]
    NetworkAlreadyExists {
        /// Duplicate network ID.
        network_id: NetworkId,
    },
    /// A requested virtual network does not exist.
    #[error("network {network_id} does not exist")]
    NetworkNotFound {
        /// Missing network ID.
        network_id: NetworkId,
    },
    /// A node is present but administratively disabled.
    #[error("node {node_id} is disabled")]
    NodeDisabled {
        /// Disabled node ID.
        node_id: NodeId,
    },
    /// A bearer token is the forbidden all-zero value.
    #[error("bearer token must be non-zero")]
    InvalidBearerToken,
    /// A token expiry is not later than its creation time.
    #[error("bearer token expiry must be later than creation time")]
    InvalidTokenLifetime,
    /// The enrollment token digest is absent or expired.
    #[error("enrollment token is invalid or expired")]
    EnrollmentTokenInvalid,
    /// The join token digest is absent, expired, or scoped to another network.
    #[error("join token is invalid, expired, or scoped to another network")]
    JoinTokenInvalid,
    /// Repeated random generation collided with existing token digests.
    #[error("unable to generate a unique bearer token")]
    TokenGenerationCollision,
    /// The operating system could not supply cryptographic randomness.
    #[error("operating-system cryptographic randomness is unavailable")]
    RandomnessUnavailable,
    /// Membership exists but is suspended.
    #[error("membership for node {node_id} in network {network_id} is suspended")]
    MembershipSuspended {
        /// Suspended network ID.
        network_id: NetworkId,
        /// Suspended node ID.
        node_id: NodeId,
    },
    /// A requested membership does not exist.
    #[error("membership for node {node_id} in network {network_id} does not exist")]
    MembershipNotFound {
        /// Missing network ID.
        network_id: NetworkId,
        /// Missing node ID.
        node_id: NodeId,
    },
    /// Network membership reached the signed flood-peer policy limit.
    #[error("network {network_id} has reached its member limit")]
    NetworkFull {
        /// Full network ID.
        network_id: NetworkId,
    },
    /// A monotonic epoch or revision reached `u64::MAX`.
    #[error("authority counter for network {network_id} is exhausted")]
    CounterExhausted {
        /// Network whose counter cannot advance.
        network_id: NetworkId,
    },
    /// A bounded display name is invalid.
    #[error("display name must contain 1 through 64 UTF-8 bytes without control characters")]
    InvalidDisplayName,
    /// Checked record-length arithmetic overflowed.
    #[error("authority record length overflow")]
    LengthOverflow,
    /// Bounded record storage could not be reserved.
    #[error("unable to allocate bounded authority record storage")]
    AllocationFailed,
}

macro_rules! convert_redb_error {
    ($error:ty) => {
        impl From<$error> for StoreError {
            fn from(error: $error) -> Self {
                Self::Redb(Box::new(error.into()))
            }
        }
    };
}

convert_redb_error!(redb::DatabaseError);
convert_redb_error!(redb::TransactionError);
convert_redb_error!(redb::TableError);
convert_redb_error!(redb::StorageError);
convert_redb_error!(redb::CommitError);

fn enrollment_token_digest(token: &BearerToken) -> [u8; 32] {
    sha256_segments(&[ENROLLMENT_TOKEN_DOMAIN, token.expose_secret()])
}

fn join_token_digest(token: &BearerToken) -> [u8; 32] {
    sha256_segments(&[JOIN_TOKEN_DOMAIN, token.expose_secret()])
}

fn membership_key(network_id: NetworkId, node_id: NodeId) -> [u8; 32] {
    let mut key = [0_u8; 32];
    key[..NetworkId::LENGTH].copy_from_slice(network_id.as_bytes());
    key[NetworkId::LENGTH..].copy_from_slice(node_id.as_bytes());
    key
}

fn validate_membership_key(record: &MembershipRecord, key: &[u8; 32]) -> Result<(), StoreError> {
    if membership_key(record.network_id, record.node_id) != *key {
        return Err(StoreError::RecordKeyMismatch {
            table: "memberships",
        });
    }
    Ok(())
}

fn generate_grant_serial() -> Result<GrantSerial, StoreError> {
    let mut bytes = [0_u8; GrantSerial::LENGTH];
    loop {
        getrandom::fill(&mut bytes).map_err(|_| StoreError::RandomnessUnavailable)?;
        let serial = GrantSerial::from_bytes(bytes);
        if !serial.is_zero() {
            return Ok(serial);
        }
    }
}

fn load_network_for_write(
    write: &redb::WriteTransaction,
    network_id: NetworkId,
) -> Result<NetworkRecord, StoreError> {
    let networks = write.open_table(NETWORKS)?;
    let Some(value) = networks.get(network_id.as_bytes().as_slice())? else {
        return Err(StoreError::NetworkNotFound { network_id });
    };
    let record = NetworkRecord::decode(value.value())?;
    if record.network_id() != network_id {
        return Err(StoreError::RecordKeyMismatch { table: "networks" });
    }
    Ok(record)
}

fn load_node_for_write(
    write: &redb::WriteTransaction,
    node_id: NodeId,
) -> Result<NodeRecord, StoreError> {
    let nodes = write.open_table(NODES)?;
    let Some(value) = nodes.get(node_id.as_bytes().as_slice())? else {
        return Err(StoreError::NodeNotFound { node_id });
    };
    let record = NodeRecord::decode(value.value())?;
    if record.node_id() != node_id {
        return Err(StoreError::RecordKeyMismatch { table: "nodes" });
    }
    Ok(record)
}

fn enforce_network_capacity(
    write: &redb::WriteTransaction,
    network: &NetworkRecord,
) -> Result<(), StoreError> {
    let memberships = write.open_table(MEMBERSHIPS)?;
    let mut count = 0_usize;
    for entry in memberships.iter()? {
        let (key, value) = entry?;
        let key = decode_identifier::<32>(key.value(), "memberships", "membership key")?;
        let record = MembershipRecord::decode(value.value())?;
        validate_membership_key(&record, &key)?;
        if record.network_id == network.network_id() {
            count = count.checked_add(1).ok_or(StoreError::LengthOverflow)?;
        }
    }
    if count >= usize::from(network.policy.max_flood_peers) {
        return Err(StoreError::NetworkFull {
            network_id: network.network_id(),
        });
    }
    Ok(())
}

fn create_empty_tables(write: &redb::WriteTransaction) -> Result<(), StoreError> {
    write.open_table(NODES)?;
    write.open_table(NETWORKS)?;
    write.open_table(MEMBERSHIPS)?;
    write.open_table(ENDPOINTS)?;
    write.open_table(ENROLLMENT_TOKENS)?;
    write.open_table(JOIN_TOKENS)?;
    Ok(())
}

fn read_metadata(database: &Database) -> Result<ControllerId, StoreError> {
    let read = database.begin_read()?;
    let metadata = read.open_table(METADATA)?;
    let schema = metadata
        .get(SCHEMA_VERSION_KEY)?
        .ok_or(StoreError::InvalidMetadata {
            field: SCHEMA_VERSION_KEY,
        })?;
    let schema =
        u32::from_be_bytes(
            schema
                .value()
                .try_into()
                .map_err(|_| StoreError::InvalidMetadata {
                    field: SCHEMA_VERSION_KEY,
                })?,
        );
    if schema != STORE_SCHEMA_VERSION {
        return Err(StoreError::UnsupportedSchema {
            actual: schema,
            supported: STORE_SCHEMA_VERSION,
        });
    }
    let controller = metadata
        .get(CONTROLLER_ID_KEY)?
        .ok_or(StoreError::InvalidMetadata {
            field: CONTROLLER_ID_KEY,
        })?;
    let controller = ControllerId::from_bytes(controller.value().try_into().map_err(|_| {
        StoreError::InvalidMetadata {
            field: CONTROLLER_ID_KEY,
        }
    })?);
    if controller.is_zero() {
        return Err(StoreError::InvalidControllerId);
    }
    Ok(controller)
}

fn validate_display_name(display_name: &str) -> Result<(), StoreError> {
    if display_name.is_empty()
        || display_name.len() > MAX_DISPLAY_NAME_BYTES
        || display_name.chars().any(char::is_control)
    {
        return Err(StoreError::InvalidDisplayName);
    }
    Ok(())
}

fn decode_display_name(bytes: &[u8]) -> Result<String, StoreError> {
    let display_name = str::from_utf8(bytes).map_err(|_| StoreError::InvalidDisplayName)?;
    validate_display_name(display_name)?;
    let mut owned = String::new();
    owned
        .try_reserve_exact(display_name.len())
        .map_err(|_| StoreError::AllocationFailed)?;
    owned.push_str(display_name);
    Ok(owned)
}

fn allocate_record(length: usize) -> Result<Vec<u8>, StoreError> {
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(length)
        .map_err(|_| StoreError::AllocationFailed)?;
    bytes.resize(length, 0);
    Ok(bytes)
}

fn copy_array<const N: usize>(
    bytes: &[u8],
    offset: usize,
    table: &'static str,
    reason: &'static str,
) -> Result<[u8; N], StoreError> {
    let end = offset.checked_add(N).ok_or(StoreError::LengthOverflow)?;
    bytes
        .get(offset..end)
        .ok_or_else(|| malformed(table, reason))?
        .try_into()
        .map_err(|_| malformed(table, reason))
}

fn decode_identifier<const N: usize>(
    bytes: &[u8],
    table: &'static str,
    reason: &'static str,
) -> Result<[u8; N], StoreError> {
    bytes.try_into().map_err(|_| malformed(table, reason))
}

const fn malformed(table: &'static str, reason: &'static str) -> StoreError {
    StoreError::MalformedRecord { table, reason }
}

#[cfg(test)]
mod tests {
    use std::{
        path::PathBuf,
        sync::atomic::{AtomicU64, Ordering},
    };

    use stella_common::{ControllerId, GrantSerial, NetworkId, NodeId};
    use stella_crypto::{IdentitySeed, IdentitySigningKey};
    use stella_proto::{ConfidentialityPolicy, NetworkPolicy};

    use super::{
        AuthorityStore, BearerToken, MembershipStatus, NetworkRecord, NodeRecord, StoreError,
    };

    static TEMP_SEQUENCE: AtomicU64 = AtomicU64::new(1);

    fn temp_directory() -> PathBuf {
        let sequence = TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        std::env::temp_dir().join(format!(
            "stella-authority-store-{}-{sequence}",
            std::process::id()
        ))
    }

    fn signing_key(seed: u8) -> IdentitySigningKey {
        IdentitySigningKey::from_seed(&IdentitySeed::from_bytes([seed; 32]))
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

    fn membership_serial(
        store: &AuthorityStore,
        node_id: NodeId,
        network_id: NetworkId,
    ) -> GrantSerial {
        store
            .get_membership(node_id, network_id)
            .expect("membership lookup")
            .expect("membership exists")
            .grant_serial()
    }

    #[test]
    fn initialization_binds_controller_and_creates_all_tables() {
        let directory = temp_directory();
        std::fs::create_dir(&directory).expect("create test directory");
        let path = directory.join("controller.redb");
        let controller_id = ControllerId::from_bytes([1; 16]);
        let store = AuthorityStore::initialize(&path, controller_id).expect("initialize store");
        assert_eq!(store.controller_id(), controller_id);
        assert_eq!(store.path(), path);
        store.verify().expect("empty initialized store is valid");
        drop(store);

        let reopened = AuthorityStore::open(&path, controller_id).expect("reopen valid store");
        reopened.verify().expect("reopened store is valid");
        drop(reopened);
        assert!(matches!(
            AuthorityStore::open(&path, ControllerId::from_bytes([2; 16])),
            Err(StoreError::ControllerMismatch { .. })
        ));
        assert!(matches!(
            AuthorityStore::initialize(&path, controller_id),
            Err(StoreError::Create { .. })
        ));
        std::fs::remove_dir_all(&directory).expect("remove test directory");
    }

    #[test]
    fn node_records_round_trip_and_enable_changes_are_idempotent() {
        let directory = temp_directory();
        std::fs::create_dir(&directory).expect("create test directory");
        let path = directory.join("controller.redb");
        let store = AuthorityStore::initialize(&path, ControllerId::from_bytes([3; 16]))
            .expect("initialize store");
        let record =
            NodeRecord::new(signing_key(4).public_key(), "Windows node", 100).expect("valid node");
        let node_id = record.node_id();
        store.create_node(&record).expect("insert node");
        assert!(matches!(
            store.create_node(&record),
            Err(StoreError::NodeAlreadyExists { .. })
        ));
        assert_eq!(
            store.get_node(node_id).expect("read node"),
            Some(record.clone())
        );
        assert_eq!(store.list_nodes().expect("list nodes"), vec![record]);
        assert!(store
            .set_node_enabled(node_id, false)
            .expect("disable node"));
        assert!(!store
            .set_node_enabled(node_id, false)
            .expect("repeat disable"));
        assert!(!store
            .get_node(node_id)
            .expect("read disabled node")
            .expect("node exists")
            .enabled());
        drop(store);
        std::fs::remove_dir_all(&directory).expect("remove test directory");
    }

    #[test]
    fn network_records_round_trip_with_authority_counters() {
        let directory = temp_directory();
        std::fs::create_dir(&directory).expect("create test directory");
        let path = directory.join("controller.redb");
        let store = AuthorityStore::initialize(&path, ControllerId::from_bytes([5; 16]))
            .expect("initialize store");
        let network_id = NetworkId::from_bytes([6; 16]);
        let record =
            NetworkRecord::new(policy(network_id), "LAN games", 200).expect("valid network record");
        store.create_network(&record).expect("insert network");
        assert!(matches!(
            store.create_network(&record),
            Err(StoreError::NetworkAlreadyExists { .. })
        ));
        assert_eq!(
            store.get_network(network_id).expect("read network"),
            Some(record.clone())
        );
        assert_eq!(store.list_networks().expect("list networks"), vec![record]);
        store.verify().expect("populated store is valid");
        drop(store);
        std::fs::remove_dir_all(&directory).expect("remove test directory");
    }

    #[test]
    fn enrollment_token_is_consumed_with_node_registration() {
        let directory = temp_directory();
        std::fs::create_dir(&directory).expect("create test directory");
        let path = directory.join("controller.redb");
        let store = AuthorityStore::initialize(&path, ControllerId::from_bytes([7; 16]))
            .expect("initialize store");
        let token = store
            .issue_enrollment_token(100, 200)
            .expect("issue enrollment token");
        assert_eq!(format!("{token:?}"), "BearerToken([REDACTED])");
        let key = signing_key(8).public_key();
        let record = store
            .enroll_node(&token, key, "Enrolled node", 150)
            .expect("consume token and enroll node");
        assert_eq!(
            store.get_node(record.node_id()).expect("get node"),
            Some(record)
        );
        assert!(matches!(
            store.enroll_node(&token, signing_key(9).public_key(), "Replay", 151),
            Err(StoreError::EnrollmentTokenInvalid)
        ));

        let expired = store
            .issue_enrollment_token(200, 300)
            .expect("issue expiring token");
        assert!(matches!(
            store.enroll_node(&expired, signing_key(10).public_key(), "Late", 300),
            Err(StoreError::EnrollmentTokenInvalid)
        ));
        store.verify().expect("enrollment state remains valid");
        drop(store);
        std::fs::remove_dir_all(&directory).expect("remove test directory");
    }

    #[test]
    fn join_token_membership_and_leave_commit_authority_atomically() {
        let directory = temp_directory();
        std::fs::create_dir(&directory).expect("create test directory");
        let path = directory.join("controller.redb");
        let store = AuthorityStore::initialize(&path, ControllerId::from_bytes([11; 16]))
            .expect("initialize store");
        let node =
            NodeRecord::new(signing_key(12).public_key(), "Joining node", 100).expect("valid node");
        let node_id = node.node_id();
        store.create_node(&node).expect("create node");
        let network_id = NetworkId::from_bytes([13; 16]);
        store
            .create_network(
                &NetworkRecord::new(policy(network_id), "Joined LAN", 100).expect("valid network"),
            )
            .expect("create network");
        let token = store
            .issue_join_token(network_id, 100, 200)
            .expect("issue join token");

        store
            .set_node_enabled(node_id, false)
            .expect("disable node");
        assert!(matches!(
            store.join_with_token(&token, node_id, network_id, 150),
            Err(StoreError::NodeDisabled { .. })
        ));
        store.set_node_enabled(node_id, true).expect("enable node");
        let joined = store
            .join_with_token(&token, node_id, network_id, 150)
            .expect("same token remains usable after failed transaction");
        assert_eq!(joined.controller_epoch, 2);
        assert_eq!(joined.snapshot_revision, 2);
        assert_eq!(
            store
                .get_membership(node_id, network_id)
                .expect("get membership")
                .expect("membership exists")
                .status(),
            MembershipStatus::Active
        );
        assert_eq!(
            store
                .join_with_token(&token, node_id, network_id, 151)
                .expect("repeat join is idempotent"),
            joined
        );

        let second_node =
            NodeRecord::new(signing_key(14).public_key(), "Second node", 100).expect("valid node");
        let second_node_id = second_node.node_id();
        store.create_node(&second_node).expect("create second node");
        assert!(matches!(
            store.join_with_token(&token, second_node_id, network_id, 152),
            Err(StoreError::JoinTokenInvalid)
        ));

        let left = store
            .leave_network(node_id, network_id)
            .expect("leave membership");
        assert_eq!(left.controller_epoch, 3);
        assert_eq!(left.snapshot_revision, 3);
        assert_eq!(
            store
                .leave_network(node_id, network_id)
                .expect("repeat leave is idempotent"),
            left
        );
        assert!(store
            .get_membership(node_id, network_id)
            .expect("membership lookup")
            .is_none());
        store.verify().expect("join and leave state is valid");
        drop(store);
        std::fs::remove_dir_all(&directory).expect("remove test directory");
    }

    #[test]
    fn administrative_membership_status_rotates_authority_once() {
        let directory = temp_directory();
        std::fs::create_dir(&directory).expect("create test directory");
        let path = directory.join("controller.redb");
        let store = AuthorityStore::initialize(&path, ControllerId::from_bytes([15; 16]))
            .expect("initialize store");
        let node =
            NodeRecord::new(signing_key(16).public_key(), "Managed node", 100).expect("valid node");
        let node_id = node.node_id();
        store.create_node(&node).expect("create node");
        let network_id = NetworkId::from_bytes([17; 16]);
        store
            .create_network(
                &NetworkRecord::new(policy(network_id), "Managed LAN", 100).expect("valid network"),
            )
            .expect("create network");
        let joined = store
            .add_member(node_id, network_id, 110)
            .expect("administrative add");
        assert_eq!(joined.controller_epoch, 2);
        let active_serial = store
            .get_membership(node_id, network_id)
            .expect("membership lookup")
            .expect("membership exists")
            .grant_serial();
        let suspended = store
            .set_membership_status(node_id, network_id, MembershipStatus::Suspended)
            .expect("suspend membership");
        assert_eq!(suspended.controller_epoch, 3);
        let suspended_record = store
            .get_membership(node_id, network_id)
            .expect("membership lookup")
            .expect("membership exists");
        assert_eq!(suspended_record.status(), MembershipStatus::Suspended);
        assert_ne!(suspended_record.grant_serial(), active_serial);
        assert_eq!(
            store
                .set_membership_status(node_id, network_id, MembershipStatus::Suspended)
                .expect("repeat suspension"),
            suspended
        );
        assert!(matches!(
            store.add_member(node_id, network_id, 120),
            Err(StoreError::MembershipSuspended { .. })
        ));
        let resumed = store
            .set_membership_status(node_id, network_id, MembershipStatus::Active)
            .expect("resume membership");
        assert_eq!(resumed.controller_epoch, 4);
        assert_eq!(
            store
                .list_memberships(network_id)
                .expect("list memberships")
                .len(),
            1
        );
        drop(store);
        std::fs::remove_dir_all(&directory).expect("remove test directory");
    }

    #[test]
    fn node_enable_changes_invalidate_every_membership_atomically() {
        let directory = temp_directory();
        std::fs::create_dir(&directory).expect("create test directory");
        let path = directory.join("controller.redb");
        let store = AuthorityStore::initialize(&path, ControllerId::from_bytes([18; 16]))
            .expect("initialize store");
        let node =
            NodeRecord::new(signing_key(19).public_key(), "Revoked node", 100).expect("valid node");
        let node_id = node.node_id();
        store.create_node(&node).expect("create node");
        let first_network_id = NetworkId::from_bytes([20; 16]);
        let second_network_id = NetworkId::from_bytes([21; 16]);
        for (network_id, name) in [
            (first_network_id, "First LAN"),
            (second_network_id, "Second LAN"),
        ] {
            store
                .create_network(
                    &NetworkRecord::new(policy(network_id), name, 100).expect("valid network"),
                )
                .expect("create network");
            store
                .add_member(node_id, network_id, 110)
                .expect("add member");
        }
        let original_serials = [first_network_id, second_network_id]
            .map(|network_id| membership_serial(&store, node_id, network_id));

        assert!(store
            .set_node_enabled(node_id, false)
            .expect("disable node"));
        for (index, network_id) in [first_network_id, second_network_id]
            .into_iter()
            .enumerate()
        {
            let network = store
                .get_network(network_id)
                .expect("network lookup")
                .expect("network exists");
            assert_eq!(network.controller_epoch(), 3);
            assert_eq!(network.snapshot_revision(), 3);
            let disabled_serial = membership_serial(&store, node_id, network_id);
            assert_ne!(disabled_serial, original_serials[index]);
        }

        let disabled_serials = [first_network_id, second_network_id]
            .map(|network_id| membership_serial(&store, node_id, network_id));
        assert!(!store
            .set_node_enabled(node_id, false)
            .expect("repeat disable"));
        for (index, network_id) in [first_network_id, second_network_id]
            .into_iter()
            .enumerate()
        {
            let network = store
                .get_network(network_id)
                .expect("network lookup")
                .expect("network exists");
            assert_eq!(network.controller_epoch(), 3);
            assert_eq!(network.snapshot_revision(), 3);
            assert_eq!(
                membership_serial(&store, node_id, network_id),
                disabled_serials[index]
            );
        }

        assert!(store.set_node_enabled(node_id, true).expect("enable node"));
        for (index, network_id) in [first_network_id, second_network_id]
            .into_iter()
            .enumerate()
        {
            let network = store
                .get_network(network_id)
                .expect("network lookup")
                .expect("network exists");
            assert_eq!(network.controller_epoch(), 4);
            assert_eq!(network.snapshot_revision(), 4);
            assert_ne!(
                membership_serial(&store, node_id, network_id),
                disabled_serials[index]
            );
        }
        store.verify().expect("node revocation state is valid");
        drop(store);
        std::fs::remove_dir_all(&directory).expect("remove test directory");
    }

    #[test]
    fn all_zero_bearer_token_is_rejected() {
        assert!(matches!(
            BearerToken::from_bytes([0; 32]),
            Err(StoreError::InvalidBearerToken)
        ));
    }
}
