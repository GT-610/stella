//! Transactional redb controller authority store.

use std::{
    fs::OpenOptions,
    path::{Path, PathBuf},
    str,
};

use redb::{Database, ReadableTable, TableDefinition};
use stella_common::{ControllerId, NetworkId, NodeId};
use stella_crypto::{derive_node_id, CryptoError, IdentityPublicKey};
use stella_proto::{CodecError, NetworkPolicy, NETWORK_POLICY_LENGTH};
use thiserror::Error;

const STORE_SCHEMA_VERSION: u32 = 1;
const RECORD_VERSION: u8 = 1;
const MAX_DISPLAY_NAME_BYTES: usize = 64;
const NODE_RECORD_FIXED_LENGTH: usize = 48;
const NETWORK_RECORD_FIXED_LENGTH: usize = 96;
const NODE_RECORD_MAGIC: [u8; 4] = *b"SNOD";
const NETWORK_RECORD_MAGIC: [u8; 4] = *b"SNET";
const NODE_ENABLED_FLAG: u8 = 0x01;

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
        read.open_table(MEMBERSHIPS)?;
        read.open_table(ENDPOINTS)?;
        read.open_table(ENROLLMENT_TOKENS)?;
        read.open_table(JOIN_TOKENS)?;
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

    /// Changes a node's administrative enabled state.
    ///
    /// Returns `true` when a stored value changed and `false` for an idempotent
    /// request.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::NodeNotFound`] for an unknown node or a
    /// persistence/decoding error otherwise.
    pub fn set_node_enabled(&self, node_id: NodeId, enabled: bool) -> Result<bool, StoreError> {
        let write = self.database.begin_write()?;
        let changed;
        {
            let mut nodes = write.open_table(NODES)?;
            let mut record = {
                let Some(value) = nodes.get(node_id.as_bytes().as_slice())? else {
                    return Err(StoreError::NodeNotFound { node_id });
                };
                NodeRecord::decode(value.value())?
            };
            if record.node_id() != node_id {
                return Err(StoreError::RecordKeyMismatch { table: "nodes" });
            }
            changed = record.enabled != enabled;
            if changed {
                record.enabled = enabled;
                let encoded = record.encode()?;
                nodes.insert(node_id.as_bytes().as_slice(), encoded.as_slice())?;
            }
        }
        if changed {
            write.commit()?;
        }
        Ok(changed)
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

    use stella_common::{ControllerId, NetworkId};
    use stella_crypto::{IdentitySeed, IdentitySigningKey};
    use stella_proto::{ConfidentialityPolicy, NetworkPolicy};

    use super::{AuthorityStore, NetworkRecord, NodeRecord, StoreError};

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
}
