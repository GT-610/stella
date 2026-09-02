//! Bounded ICE connectivity checks and regular direct-path nomination.

use std::{
    collections::{BTreeMap, BTreeSet, HashMap},
    net::{IpAddr, Ipv4Addr, SocketAddr},
    time::Duration,
};

use hmac::{Hmac, KeyInit, Mac};
use sha2::Sha256;
use stella_common::NodeId;
use stella_proto::{
    decode_stun_xor_address, encode_stun_message, encode_stun_xor_address, ConnectivityCarrier,
    IceCandidate, StunAttributeRef, StunAttributeType, StunClass, StunMessageRef, StunMessageType,
    StunMessageView, StunMethod, StunTransactionId,
};
use thiserror::Error;
use zeroize::Zeroizing;

type HmacSha256 = Hmac<Sha256>;

const INITIAL_RETRANSMIT_TIMEOUT: Duration = Duration::from_millis(250);
const MAX_RETRANSMIT_TIMEOUT: Duration = Duration::from_secs(1);
const CHECK_TIMEOUT: Duration = Duration::from_secs(5);
const MAX_ACTIVE_TRANSACTIONS: usize = 256;
const MAX_REMOTE_CANDIDATES: usize = 32;

/// Failure while validating or advancing bounded ICE checks.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum IceError {
    /// A local or remote short-term credential is invalid.
    #[error("invalid ICE short-term credentials")]
    InvalidCredentials,
    /// Operating-system randomness was unavailable.
    #[error("operating-system randomness is unavailable for ICE transaction ID")]
    RandomnessUnavailable,
    /// A monotonic transaction deadline overflowed.
    #[error("ICE transaction deadline overflowed")]
    DeadlineOverflow,
    /// The active ICE transaction bound was reached.
    #[error("ICE active transaction capacity is exhausted")]
    TransactionCapacity,
    /// A STUN request or response failed short-term integrity validation.
    #[error("ICE STUN MESSAGE-INTEGRITY-SHA256 validation failed")]
    Integrity,
    /// A required ICE attribute is missing, duplicated, or inconsistent.
    #[error("invalid ICE STUN attribute: {field}")]
    InvalidAttribute {
        /// Stable non-secret attribute description.
        field: &'static str,
    },
    /// Both endpoints claimed an inconsistent ICE role.
    #[error("ICE role conflict with peer {peer_node_id}")]
    RoleConflict {
        /// Peer whose advertised tie breaker conflicts with the request.
        peer_node_id: NodeId,
    },
    /// Generic STUN framing or address decoding failed.
    #[error(transparent)]
    Codec(#[from] stella_proto::CodecError),
}

/// Borrowed controller-authorized ICE generation for one peer.
#[derive(Clone, Copy)]
pub struct IcePeerConfig<'a> {
    /// Authorized peer identity.
    pub node_id: NodeId,
    /// Complete remote generation identifier.
    pub generation_id: u64,
    /// Remote ICE role tie breaker.
    pub tie_breaker: u64,
    /// Remote username fragment.
    pub username_fragment: &'a [u8],
    /// Remote short-term password.
    pub password: &'a [u8],
    /// Remote generation candidates in descending priority order.
    pub candidates: &'a [IceCandidate],
}

impl std::fmt::Debug for IcePeerConfig<'_> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("IcePeerConfig")
            .field("node_id", &self.node_id)
            .field("generation_id", &self.generation_id)
            .field("tie_breaker", &self.tie_breaker)
            .field("username_fragment_length", &self.username_fragment.len())
            .field("password_length", &self.password.len())
            .field("candidate_count", &self.candidates.len())
            .finish()
    }
}

/// One complete direct STUN datagram selected for transmission.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IceTransmission {
    peer_node_id: NodeId,
    target: SocketAddr,
    bytes: Vec<u8>,
}

impl IceTransmission {
    /// Returns the authorized peer associated with this check.
    #[must_use]
    pub const fn peer_node_id(&self) -> NodeId {
        self.peer_node_id
    }

    /// Returns the exact remote direct candidate or peer-reflexive address.
    #[must_use]
    pub const fn target(&self) -> SocketAddr {
        self.target
    }

    /// Borrows the complete encoded STUN datagram.
    #[must_use]
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }
}

/// One direct path nominated by a completed regular ICE check.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct IceNomination {
    /// Authorized peer reached by the path.
    pub peer_node_id: NodeId,
    /// Exact source and destination tuple selected locally.
    pub address: SocketAddr,
}

/// Output produced by an inbound check or maintenance poll.
#[derive(Debug, Default)]
pub struct IceOutput {
    transmissions: Vec<IceTransmission>,
    nominations: Vec<IceNomination>,
}

impl IceOutput {
    /// Borrows complete STUN datagrams ready to send.
    #[must_use]
    pub fn transmissions(&self) -> &[IceTransmission] {
        &self.transmissions
    }

    /// Borrows newly nominated direct paths.
    #[must_use]
    pub fn nominations(&self) -> &[IceNomination] {
        &self.nominations
    }

    /// Consumes output into transmissions and nominations.
    #[must_use]
    pub fn into_parts(self) -> (Vec<IceTransmission>, Vec<IceNomination>) {
        (self.transmissions, self.nominations)
    }
}

/// One network-scoped ICE component sharing the Stella direct UDP socket.
pub struct IceAgent {
    local_node_id: NodeId,
    tie_breaker: u64,
    username_fragment: Zeroizing<Vec<u8>>,
    password: Zeroizing<Vec<u8>>,
    local_candidate: Option<IceCandidate>,
    peers: BTreeMap<NodeId, Peer>,
    transactions: HashMap<StunTransactionId, Transaction>,
}

impl IceAgent {
    /// Creates an ICE component from one local connectivity generation.
    ///
    /// Relay candidates are ignored because ICE checks in this agent validate
    /// only direct UDP paths. An empty direct-candidate set creates a dormant
    /// agent that can still be replaced when gathering completes.
    ///
    /// # Errors
    ///
    /// Returns [`IceError`] for invalid credentials or malformed direct candidates.
    pub fn new(
        local_node_id: NodeId,
        tie_breaker: u64,
        username_fragment: &[u8],
        password: &[u8],
        candidates: &[IceCandidate],
    ) -> Result<Self, IceError> {
        validate_credentials(username_fragment, password)?;
        if tie_breaker == 0 {
            return Err(IceError::InvalidAttribute {
                field: "local ICE tie breaker",
            });
        }
        let local_candidate = candidates
            .iter()
            .copied()
            .find(|candidate| candidate.carrier == ConnectivityCarrier::DirectUdp)
            .map(|candidate| {
                candidate.validate()?;
                Ok::<_, IceError>(candidate)
            })
            .transpose()?;
        Ok(Self {
            local_node_id,
            tie_breaker,
            username_fragment: Zeroizing::new(username_fragment.to_vec()),
            password: Zeroizing::new(password.to_vec()),
            local_candidate,
            peers: BTreeMap::new(),
            transactions: HashMap::new(),
        })
    }

    /// Adds or atomically replaces one authorized remote generation.
    ///
    /// # Errors
    ///
    /// Returns [`IceError`] for invalid credentials or direct candidates.
    pub fn upsert_peer(&mut self, config: IcePeerConfig<'_>) -> Result<(), IceError> {
        validate_credentials(config.username_fragment, config.password)?;
        if config.tie_breaker == 0 {
            return Err(IceError::InvalidAttribute {
                field: "remote ICE tie breaker",
            });
        }
        let family = self
            .local_candidate
            .map(|candidate| candidate.address.is_ipv4());
        let mut candidates = config
            .candidates
            .iter()
            .copied()
            .filter(|candidate| {
                candidate.carrier == ConnectivityCarrier::DirectUdp
                    && family.is_some_and(|ipv4| candidate.address.is_ipv4() == ipv4)
            })
            .take(MAX_REMOTE_CANDIDATES)
            .collect::<Vec<_>>();
        for candidate in &candidates {
            candidate.validate()?;
        }
        candidates.sort_by_key(|candidate| std::cmp::Reverse(candidate.priority));
        let replacement = Peer {
            generation_id: config.generation_id,
            tie_breaker: config.tie_breaker,
            username_fragment: Zeroizing::new(config.username_fragment.to_vec()),
            password: Zeroizing::new(config.password.to_vec()),
            candidates: candidates
                .into_iter()
                .map(|candidate| candidate.address)
                .collect(),
            next_candidate: 0,
            active_transaction: None,
            succeeded: None,
            nominated: None,
        };
        if self.peers.get(&config.node_id).is_some_and(|current| {
            current.generation_id == replacement.generation_id
                && current.tie_breaker == replacement.tie_breaker
                && current.username_fragment == replacement.username_fragment
                && current.password == replacement.password
                && current.candidates == replacement.candidates
        }) {
            return Ok(());
        }
        self.remove_peer_transactions(config.node_id);
        self.peers.insert(config.node_id, replacement);
        Ok(())
    }

    /// Removes peer state and checks not named in the authoritative set.
    pub fn retain_peers(&mut self, authorized: &BTreeSet<NodeId>) {
        let removed = self
            .peers
            .keys()
            .filter(|peer| !authorized.contains(peer))
            .copied()
            .collect::<Vec<_>>();
        for peer in removed {
            self.peers.remove(&peer);
            self.remove_peer_transactions(peer);
        }
    }

    /// Emits due checks, advances retransmission timers, and tries later pairs.
    ///
    /// # Errors
    ///
    /// Returns [`IceError`] for randomness, capacity, encoding, or deadline failure.
    pub fn poll(&mut self, now: Duration) -> Result<IceOutput, IceError> {
        self.expire_transactions(now);
        let to_start = self
            .peers
            .iter()
            .filter(|(_, peer)| {
                peer.nominated.is_none()
                    && peer.active_transaction.is_none()
                    && peer.next_candidate < peer.candidates.len()
            })
            .map(|(peer_node_id, peer)| (*peer_node_id, peer.candidates[peer.next_candidate]))
            .collect::<Vec<_>>();
        for (peer_node_id, target) in to_start {
            if let Some(peer) = self.peers.get_mut(&peer_node_id) {
                peer.next_candidate += 1;
            }
            self.create_transaction(peer_node_id, target, false, now)?;
        }
        let mut transmissions = Vec::new();
        let mut due = self
            .transactions
            .iter()
            .filter_map(|(transaction_id, transaction)| {
                (now >= transaction.next_send && now < transaction.deadline)
                    .then_some(*transaction_id)
            })
            .collect::<Vec<_>>();
        due.sort_by_key(|transaction_id| *transaction_id.as_bytes());
        for transaction_id in due {
            if let Some(transaction) = self.transactions.get_mut(&transaction_id) {
                transmissions.push(transaction.transmission());
                transaction.next_send = now.saturating_add(transaction.retransmit);
                transaction.retransmit = transaction
                    .retransmit
                    .saturating_mul(2)
                    .min(MAX_RETRANSMIT_TIMEOUT);
            }
        }
        Ok(IceOutput {
            transmissions,
            nominations: Vec::new(),
        })
    }

    /// Processes one UDP datagram when it is a STUN Binding record.
    ///
    /// `Ok(None)` means the datagram is not STUN and should continue to the
    /// Stella packet decoder. Invalid matching ICE records fail closed.
    ///
    /// # Errors
    ///
    /// Returns [`IceError`] for malformed records, attributes, credentials,
    /// integrity, roles, randomness, capacity, or deadline failure.
    pub fn accept(
        &mut self,
        source: SocketAddr,
        datagram: &[u8],
        now: Duration,
    ) -> Result<Option<IceOutput>, IceError> {
        if !looks_like_stun(datagram) {
            return Ok(None);
        }
        let message = StunMessageView::decode(datagram)?;
        if message.message_type().method != StunMethod::Binding {
            return Ok(Some(IceOutput::default()));
        }
        match message.message_type().class {
            StunClass::Request => self.accept_request(source, &message, now).map(Some),
            StunClass::SuccessResponse => self.accept_response(source, &message, now).map(Some),
            StunClass::ErrorResponse | StunClass::Indication => Ok(Some(IceOutput::default())),
        }
    }

    fn accept_request(
        &mut self,
        source: SocketAddr,
        message: &StunMessageView<'_>,
        now: Duration,
    ) -> Result<IceOutput, IceError> {
        let username = required_attribute(message, StunAttributeType::USERNAME, "USERNAME")?;
        let peer_node_id = self.peer_for_username(username)?;
        let peer = self
            .peers
            .get(&peer_node_id)
            .ok_or(IceError::InvalidAttribute { field: "USERNAME" })?;
        verify_integrity(message, &self.password)?;
        let priority = required_u32(message, StunAttributeType::PRIORITY, "PRIORITY")?;
        if priority == 0 {
            return Err(IceError::InvalidAttribute { field: "PRIORITY" });
        }
        let local_controlling = self.local_controlling(peer_node_id, peer.tie_breaker);
        let peer_controlling = role_attribute(message, peer.tie_breaker)?;
        if peer_controlling == local_controlling {
            return Err(IceError::RoleConflict { peer_node_id });
        }
        let use_candidate =
            optional_empty_attribute(message, StunAttributeType::USE_CANDIDATE, "USE-CANDIDATE")?;
        if use_candidate && !peer_controlling {
            return Err(IceError::InvalidAttribute {
                field: "USE-CANDIDATE role",
            });
        }
        validate_source(source)?;
        let mut mapped = [0_u8; 20];
        let mapped_length = encode_stun_xor_address(source, message.transaction_id(), &mut mapped)?;
        let response = encode_signed_binding(
            StunClass::SuccessResponse,
            message.transaction_id(),
            &[OwnedAttribute::new(
                StunAttributeType::XOR_MAPPED_ADDRESS,
                mapped[..mapped_length].to_vec(),
            )],
            &self.password,
        )?;
        let mut output = IceOutput {
            transmissions: vec![IceTransmission {
                peer_node_id,
                target: source,
                bytes: response,
            }],
            nominations: Vec::new(),
        };
        if use_candidate {
            if let Some(peer) = self.peers.get_mut(&peer_node_id) {
                peer.nominated = Some(source);
            }
            output.nominations.push(IceNomination {
                peer_node_id,
                address: source,
            });
        }
        let triggered = self
            .peers
            .get(&peer_node_id)
            .is_some_and(|peer| peer.nominated.is_none() && peer.active_transaction.is_none());
        if triggered {
            self.learn_peer_reflexive(peer_node_id, source, priority);
            let transaction_id = self.create_transaction(peer_node_id, source, false, now)?;
            if let Some(transaction) = self.transactions.get_mut(&transaction_id) {
                output.transmissions.push(transaction.transmission());
                transaction.next_send = now.saturating_add(transaction.retransmit);
            }
        }
        Ok(output)
    }

    fn accept_response(
        &mut self,
        source: SocketAddr,
        message: &StunMessageView<'_>,
        now: Duration,
    ) -> Result<IceOutput, IceError> {
        let Some(transaction) = self.transactions.remove(&message.transaction_id()) else {
            return Ok(IceOutput::default());
        };
        if transaction.target != source {
            self.transactions
                .insert(message.transaction_id(), transaction);
            return Err(IceError::InvalidAttribute {
                field: "response source",
            });
        }
        let peer_tie_breaker = {
            let peer = self
                .peers
                .get(&transaction.peer_node_id)
                .ok_or(IceError::InvalidAttribute { field: "peer" })?;
            verify_integrity(message, &peer.password)?;
            peer.tie_breaker
        };
        let mapped = required_attribute(
            message,
            StunAttributeType::XOR_MAPPED_ADDRESS,
            "XOR-MAPPED-ADDRESS",
        )?;
        let _local_mapping = decode_stun_xor_address(mapped, message.transaction_id())?;
        if let Some(peer) = self.peers.get_mut(&transaction.peer_node_id) {
            peer.active_transaction = None;
            peer.succeeded = Some(source);
        }
        let mut output = IceOutput::default();
        if transaction.nomination {
            if let Some(peer) = self.peers.get_mut(&transaction.peer_node_id) {
                peer.nominated = Some(source);
            }
            output.nominations.push(IceNomination {
                peer_node_id: transaction.peer_node_id,
                address: source,
            });
        } else if self.local_controlling(transaction.peer_node_id, peer_tie_breaker) {
            let transaction_id =
                self.create_transaction(transaction.peer_node_id, source, true, now)?;
            if let Some(transaction) = self.transactions.get_mut(&transaction_id) {
                output.transmissions.push(transaction.transmission());
                transaction.next_send = now.saturating_add(transaction.retransmit);
            }
        }
        Ok(output)
    }

    fn peer_for_username(&self, username: &[u8]) -> Result<NodeId, IceError> {
        let Some(separator) = username.iter().position(|byte| *byte == b':') else {
            return Err(IceError::InvalidAttribute { field: "USERNAME" });
        };
        let (local, peer_with_separator) = username.split_at(separator);
        let peer = &peer_with_separator[1..];
        if local != self.username_fragment.as_slice() || peer.is_empty() {
            return Err(IceError::InvalidAttribute { field: "USERNAME" });
        }
        self.peers
            .iter()
            .find_map(|(node_id, state)| {
                (state.username_fragment.as_slice() == peer).then_some(*node_id)
            })
            .ok_or(IceError::InvalidAttribute { field: "USERNAME" })
    }

    fn local_controlling(&self, peer_node_id: NodeId, peer_tie_breaker: u64) -> bool {
        self.tie_breaker > peer_tie_breaker
            || (self.tie_breaker == peer_tie_breaker && self.local_node_id > peer_node_id)
    }

    fn create_transaction(
        &mut self,
        peer_node_id: NodeId,
        target: SocketAddr,
        nomination: bool,
        now: Duration,
    ) -> Result<StunTransactionId, IceError> {
        if self.transactions.len() >= MAX_ACTIVE_TRANSACTIONS {
            return Err(IceError::TransactionCapacity);
        }
        let peer = self
            .peers
            .get(&peer_node_id)
            .ok_or(IceError::InvalidAttribute { field: "peer" })?;
        let local_candidate = self.local_candidate.ok_or(IceError::InvalidAttribute {
            field: "local direct candidate",
        })?;
        let transaction_id = random_transaction_id()?;
        let username = [
            peer.username_fragment.as_slice(),
            b":",
            self.username_fragment.as_slice(),
        ]
        .concat();
        let priority = local_candidate.priority.to_be_bytes();
        let role = self.tie_breaker.to_be_bytes();
        let role_type = if self.local_controlling(peer_node_id, peer.tie_breaker) {
            StunAttributeType::ICE_CONTROLLING
        } else {
            StunAttributeType::ICE_CONTROLLED
        };
        let mut attributes = vec![
            OwnedAttribute::new(StunAttributeType::USERNAME, username),
            OwnedAttribute::new(StunAttributeType::PRIORITY, priority.to_vec()),
            OwnedAttribute::new(role_type, role.to_vec()),
        ];
        if nomination {
            attributes.push(OwnedAttribute::new(
                StunAttributeType::USE_CANDIDATE,
                Vec::new(),
            ));
        }
        let request = encode_signed_binding(
            StunClass::Request,
            transaction_id,
            &attributes,
            &peer.password,
        )?;
        let deadline = now
            .checked_add(CHECK_TIMEOUT)
            .ok_or(IceError::DeadlineOverflow)?;
        self.transactions.insert(
            transaction_id,
            Transaction {
                peer_node_id,
                target,
                nomination,
                request,
                next_send: now,
                retransmit: INITIAL_RETRANSMIT_TIMEOUT,
                deadline,
            },
        );
        if let Some(peer) = self.peers.get_mut(&peer_node_id) {
            peer.active_transaction = Some(transaction_id);
        }
        Ok(transaction_id)
    }

    fn expire_transactions(&mut self, now: Duration) {
        let expired = self
            .transactions
            .iter()
            .filter_map(|(transaction_id, transaction)| {
                (now >= transaction.deadline).then_some((*transaction_id, transaction.peer_node_id))
            })
            .collect::<Vec<_>>();
        for (transaction_id, peer_node_id) in expired {
            self.transactions.remove(&transaction_id);
            if let Some(peer) = self.peers.get_mut(&peer_node_id) {
                if peer.active_transaction == Some(transaction_id) {
                    peer.active_transaction = None;
                }
            }
        }
    }

    fn remove_peer_transactions(&mut self, peer_node_id: NodeId) {
        self.transactions
            .retain(|_, transaction| transaction.peer_node_id != peer_node_id);
    }

    fn learn_peer_reflexive(&mut self, peer_node_id: NodeId, source: SocketAddr, _priority: u32) {
        let Some(peer) = self.peers.get_mut(&peer_node_id) else {
            return;
        };
        if peer.candidates.contains(&source) || peer.candidates.len() >= MAX_REMOTE_CANDIDATES {
            return;
        }
        peer.candidates.insert(0, source);
        peer.next_candidate = peer.next_candidate.saturating_add(1);
    }
}

impl std::fmt::Debug for IceAgent {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("IceAgent")
            .field("local_node_id", &self.local_node_id)
            .field("tie_breaker", &self.tie_breaker)
            .field("username_fragment_length", &self.username_fragment.len())
            .field("password_length", &self.password.len())
            .field("has_direct_candidate", &self.local_candidate.is_some())
            .field("peer_count", &self.peers.len())
            .field("transaction_count", &self.transactions.len())
            .finish()
    }
}

struct Peer {
    generation_id: u64,
    tie_breaker: u64,
    username_fragment: Zeroizing<Vec<u8>>,
    password: Zeroizing<Vec<u8>>,
    candidates: Vec<SocketAddr>,
    next_candidate: usize,
    active_transaction: Option<StunTransactionId>,
    succeeded: Option<SocketAddr>,
    nominated: Option<SocketAddr>,
}

struct Transaction {
    peer_node_id: NodeId,
    target: SocketAddr,
    nomination: bool,
    request: Vec<u8>,
    next_send: Duration,
    retransmit: Duration,
    deadline: Duration,
}

impl Transaction {
    fn transmission(&self) -> IceTransmission {
        IceTransmission {
            peer_node_id: self.peer_node_id,
            target: self.target,
            bytes: self.request.clone(),
        }
    }
}

struct OwnedAttribute {
    attribute_type: StunAttributeType,
    value: Vec<u8>,
}

impl OwnedAttribute {
    fn new(attribute_type: StunAttributeType, value: Vec<u8>) -> Self {
        Self {
            attribute_type,
            value,
        }
    }
}

fn encode_signed_binding(
    class: StunClass,
    transaction_id: StunTransactionId,
    attributes: &[OwnedAttribute],
    password: &[u8],
) -> Result<Vec<u8>, IceError> {
    let zero_integrity = [0_u8; 32];
    let mut references = attributes
        .iter()
        .map(|attribute| StunAttributeRef {
            attribute_type: attribute.attribute_type,
            value: &attribute.value,
        })
        .collect::<Vec<_>>();
    references.push(StunAttributeRef {
        attribute_type: StunAttributeType::MESSAGE_INTEGRITY_SHA256,
        value: &zero_integrity,
    });
    let message = StunMessageRef {
        message_type: StunMessageType::new(StunMethod::Binding, class),
        transaction_id,
        attributes: &references,
    };
    let mut encoded = vec![0_u8; message.encoded_len()?];
    let length = encode_stun_message(message, &mut encoded)?;
    encoded.truncate(length);
    sign_integrity(&mut encoded, password)?;
    Ok(encoded)
}

fn sign_integrity(encoded: &mut [u8], password: &[u8]) -> Result<(), IceError> {
    let (offset, tag) = {
        let message = StunMessageView::decode(encoded)?;
        let integrity = message.message_integrity_sha256()?;
        let mut mac =
            <HmacSha256 as KeyInit>::new_from_slice(password).map_err(|_| IceError::Integrity)?;
        mac.update(integrity.message_type_bytes());
        mac.update(&integrity.adjusted_body_length().to_be_bytes());
        mac.update(integrity.bytes_after_length());
        (integrity.value_offset(), mac.finalize().into_bytes())
    };
    let destination = encoded
        .get_mut(offset..offset.saturating_add(tag.len()))
        .ok_or(IceError::Integrity)?;
    destination.copy_from_slice(&tag);
    Ok(())
}

fn verify_integrity(message: &StunMessageView<'_>, password: &[u8]) -> Result<(), IceError> {
    let integrity = message
        .message_integrity_sha256()
        .map_err(|_| IceError::Integrity)?;
    let mut mac =
        <HmacSha256 as KeyInit>::new_from_slice(password).map_err(|_| IceError::Integrity)?;
    mac.update(integrity.message_type_bytes());
    mac.update(&integrity.adjusted_body_length().to_be_bytes());
    mac.update(integrity.bytes_after_length());
    mac.verify_slice(integrity.value())
        .map_err(|_| IceError::Integrity)
}

fn role_attribute(message: &StunMessageView<'_>, expected: u64) -> Result<bool, IceError> {
    let controlling = unique_attribute(message, StunAttributeType::ICE_CONTROLLING)?;
    let controlled = unique_attribute(message, StunAttributeType::ICE_CONTROLLED)?;
    let (value, peer_controlling) = match (controlling, controlled) {
        (Some(value), None) => (value, true),
        (None, Some(value)) => (value, false),
        _ => {
            return Err(IceError::InvalidAttribute { field: "ICE role" });
        }
    };
    let tie_breaker =
        u64::from_be_bytes(
            <[u8; 8]>::try_from(value).map_err(|_| IceError::InvalidAttribute {
                field: "ICE role tie breaker",
            })?,
        );
    if tie_breaker != expected {
        return Err(IceError::InvalidAttribute {
            field: "ICE role tie breaker",
        });
    }
    Ok(peer_controlling)
}

fn required_u32(
    message: &StunMessageView<'_>,
    attribute_type: StunAttributeType,
    field: &'static str,
) -> Result<u32, IceError> {
    let value = required_attribute(message, attribute_type, field)?;
    Ok(u32::from_be_bytes(
        <[u8; 4]>::try_from(value).map_err(|_| IceError::InvalidAttribute { field })?,
    ))
}

fn required_attribute<'a>(
    message: &'a StunMessageView<'a>,
    attribute_type: StunAttributeType,
    field: &'static str,
) -> Result<&'a [u8], IceError> {
    unique_attribute(message, attribute_type)?.ok_or(IceError::InvalidAttribute { field })
}

fn optional_empty_attribute(
    message: &StunMessageView<'_>,
    attribute_type: StunAttributeType,
    field: &'static str,
) -> Result<bool, IceError> {
    match unique_attribute(message, attribute_type)? {
        Some([]) => Ok(true),
        Some(_) => Err(IceError::InvalidAttribute { field }),
        None => Ok(false),
    }
}

fn unique_attribute<'a>(
    message: &'a StunMessageView<'a>,
    attribute_type: StunAttributeType,
) -> Result<Option<&'a [u8]>, IceError> {
    let mut found = None;
    for attribute in message.attributes() {
        let attribute = attribute?;
        if attribute.attribute_type() == attribute_type {
            if found.is_some() {
                return Err(IceError::InvalidAttribute {
                    field: "duplicate attribute",
                });
            }
            found = Some(attribute.value());
        }
    }
    Ok(found)
}

fn validate_credentials(username_fragment: &[u8], password: &[u8]) -> Result<(), IceError> {
    let valid = |bytes: &[u8]| {
        !bytes.is_empty()
            && bytes
                .iter()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'+' | b'/'))
    };
    if valid(username_fragment) && valid(password) {
        Ok(())
    } else {
        Err(IceError::InvalidCredentials)
    }
}

fn validate_source(source: SocketAddr) -> Result<(), IceError> {
    let invalid = source.port() == 0
        || source.ip().is_unspecified()
        || source.ip().is_multicast()
        || matches!(source.ip(), IpAddr::V4(address) if address == Ipv4Addr::BROADCAST);
    if invalid {
        Err(IceError::InvalidAttribute {
            field: "peer-reflexive source",
        })
    } else {
        Ok(())
    }
}

fn looks_like_stun(datagram: &[u8]) -> bool {
    datagram.len() >= 20
        && datagram[0] & 0xc0 == 0
        && datagram.get(4..8) == Some(stella_proto::STUN_MAGIC_COOKIE.to_be_bytes().as_slice())
}

fn random_transaction_id() -> Result<StunTransactionId, IceError> {
    let mut bytes = [0_u8; 12];
    getrandom::fill(&mut bytes).map_err(|_| IceError::RandomnessUnavailable)?;
    Ok(StunTransactionId::from_bytes(bytes))
}

#[cfg(test)]
mod tests {
    use std::{collections::VecDeque, time::Duration};

    use stella_common::NodeId;
    use stella_proto::{ConnectivityCarrier, IceCandidate, IceCandidateClass};

    use super::{IceAgent, IcePeerConfig};

    fn candidate(address: &str, priority: u32) -> IceCandidate {
        IceCandidate {
            class: IceCandidateClass::Host,
            carrier: ConnectivityCarrier::DirectUdp,
            priority,
            foundation: priority,
            max_datagram_size: 1_200,
            address: address.parse().expect("candidate address"),
            related_address: None,
            relay_id: None,
        }
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn regular_nomination_converges_and_integrity_rejects_mutation() {
        let alice_id = NodeId::from_bytes([0x11; 16]);
        let bob_id = NodeId::from_bytes([0x22; 16]);
        let alice_candidate = candidate("192.0.2.10:40000", 2_130_706_431);
        let bob_candidate = candidate("192.0.2.20:40001", 2_130_706_431);
        let mut alice = IceAgent::new(
            alice_id,
            10,
            b"AliceUfr",
            b"AlicePassword123456789",
            &[alice_candidate],
        )
        .expect("Alice agent");
        let mut bob = IceAgent::new(
            bob_id,
            20,
            b"BobUfrag",
            b"BobPassword12345678901",
            &[bob_candidate],
        )
        .expect("Bob agent");
        alice
            .upsert_peer(IcePeerConfig {
                node_id: bob_id,
                generation_id: 2,
                tie_breaker: 20,
                username_fragment: b"BobUfrag",
                password: b"BobPassword12345678901",
                candidates: &[bob_candidate],
            })
            .expect("configure Bob");
        bob.upsert_peer(IcePeerConfig {
            node_id: alice_id,
            generation_id: 1,
            tie_breaker: 10,
            username_fragment: b"AliceUfr",
            password: b"AlicePassword123456789",
            candidates: &[alice_candidate],
        })
        .expect("configure Alice");

        let first = alice
            .poll(Duration::ZERO)
            .expect("initial Alice check")
            .into_parts()
            .0
            .remove(0);
        let mut mutated = first.bytes().to_vec();
        let last = mutated.len() - 1;
        mutated[last] ^= 1;
        assert!(bob
            .accept(alice_candidate.address, &mutated, Duration::ZERO)
            .is_err());

        let mut queue = VecDeque::new();
        queue.push_back((true, first));
        for transmission in bob
            .poll(Duration::ZERO)
            .expect("initial Bob check")
            .into_parts()
            .0
        {
            queue.push_back((false, transmission));
        }
        let mut alice_nomination = None;
        let mut bob_nomination = None;
        for step in 0..32 {
            let Some((from_alice, transmission)) = queue.pop_front() else {
                break;
            };
            let now = Duration::from_millis(step);
            let output = if from_alice {
                bob.accept(alice_candidate.address, transmission.bytes(), now)
                    .expect("Bob accepts check")
                    .expect("ICE datagram")
            } else {
                alice
                    .accept(bob_candidate.address, transmission.bytes(), now)
                    .expect("Alice accepts check")
                    .expect("ICE datagram")
            };
            let (responses, nominations) = output.into_parts();
            for nomination in nominations {
                if from_alice {
                    bob_nomination = Some(nomination);
                } else {
                    alice_nomination = Some(nomination);
                }
            }
            for response in responses {
                queue.push_back((!from_alice, response));
            }
            for transmission in alice.poll(now).expect("poll Alice").into_parts().0 {
                queue.push_back((true, transmission));
            }
            for transmission in bob.poll(now).expect("poll Bob").into_parts().0 {
                queue.push_back((false, transmission));
            }
            if alice_nomination.is_some() && bob_nomination.is_some() {
                break;
            }
        }
        assert_eq!(
            alice_nomination.expect("Alice nomination").address,
            bob_candidate.address
        );
        assert_eq!(
            bob_nomination.expect("Bob nomination").address,
            alice_candidate.address
        );
        let diagnostic = format!("{alice:?}");
        assert!(!diagnostic.contains("AliceUfr"));
        assert!(!diagnostic.contains("AlicePassword"));
    }
}
