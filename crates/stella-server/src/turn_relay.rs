//! Bounded authenticated TURN-over-UDP relay runtime.

use std::{
    collections::{HashMap, VecDeque},
    fmt,
    future::Future,
    net::{IpAddr, SocketAddr},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use stella_common::{NodeId, RelayId};
use stella_proto::{
    encode_stun_error_code, encode_stun_message, encode_stun_xor_address, CodecError,
    StunAttributeRef, StunAttributeType, StunClass, StunMessageRef, StunMessageType,
    StunMessageView, StunMethod, StunTransactionId,
};
use thiserror::Error;
use tokio::{net::UdpSocket, time::MissedTickBehavior};

use crate::{
    relay_credentials::{RelayCredentialAuthority, TurnNonceStatus},
    turn_auth::{AuthenticatedTurnRequest, TurnAuthenticationError, TurnAuthenticator},
};

const SOFTWARE: &[u8] = b"stella-server/0.1";
const REQUESTED_TRANSPORT_UDP: [u8; 4] = [17, 0, 0, 0];
const RESPONSE_CACHE_LIFETIME: Duration = Duration::from_secs(40);
const RESPONSE_CACHE_CAPACITY: usize = 4_096;
const RECEIVE_BUFFER_LENGTH: usize = u16::MAX as usize;

/// Runtime limits and addresses for one TURN UDP listener.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TurnUdpRelayConfig {
    /// Stable relay identity used by controller-issued credentials.
    pub relay_id: RelayId,
    /// Client-facing TURN UDP listener address.
    pub listen_address: SocketAddr,
    /// Local IP used when binding per-client allocation sockets.
    pub allocation_bind_address: IpAddr,
    /// Address returned to clients in XOR-RELAYED-ADDRESS.
    pub advertised_address: IpAddr,
    /// Largest relayed Stella datagram accepted by this deployment.
    pub max_datagram_size: usize,
    /// Maximum granted allocation lifetime.
    pub allocation_lifetime_seconds: u32,
    /// Allocation inactivity deadline.
    pub idle_timeout_seconds: u32,
    /// Global active allocation limit.
    pub max_allocations: usize,
    /// Active allocation limit for one authenticated node.
    pub max_allocations_per_node: usize,
}

impl TurnUdpRelayConfig {
    /// Creates conservative defaults around one listener and advertised IP.
    #[must_use]
    pub const fn new(
        relay_id: RelayId,
        listen_address: SocketAddr,
        allocation_bind_address: IpAddr,
        advertised_address: IpAddr,
    ) -> Self {
        Self {
            relay_id,
            listen_address,
            allocation_bind_address,
            advertised_address,
            max_datagram_size: 1_200,
            allocation_lifetime_seconds: 600,
            idle_timeout_seconds: 120,
            max_allocations: 1_024,
            max_allocations_per_node: 4,
        }
    }

    fn validate(self) -> Result<(), TurnRelayError> {
        if self.relay_id.is_zero() {
            return Err(invalid_config("relay ID must be non-zero"));
        }
        let family = self.listen_address.is_ipv4();
        if self.allocation_bind_address.is_ipv4() != family
            || self.advertised_address.is_ipv4() != family
        {
            return Err(invalid_config(
                "listener, allocation bind, and advertised addresses must use one family",
            ));
        }
        if self.advertised_address.is_unspecified()
            || self.advertised_address.is_multicast()
            || self.max_datagram_size < 1_200
            || self.max_datagram_size > 65_507
        {
            return Err(invalid_config(
                "advertised address or maximum datagram size is invalid",
            ));
        }
        if !(60..=3_600).contains(&self.allocation_lifetime_seconds) {
            return Err(invalid_config(
                "allocation lifetime must be between 60 and 3600 seconds",
            ));
        }
        if !(30..=3_600).contains(&self.idle_timeout_seconds) {
            return Err(invalid_config(
                "idle timeout must be between 30 and 3600 seconds",
            ));
        }
        if self.max_allocations == 0
            || self.max_allocations > 65_535
            || self.max_allocations_per_node == 0
            || self.max_allocations_per_node > self.max_allocations
        {
            return Err(invalid_config("allocation count limits are invalid"));
        }
        Ok(())
    }
}

/// One bound TURN UDP relay ready to serve requests.
pub struct TurnUdpRelay {
    config: TurnUdpRelayConfig,
    authenticator: TurnAuthenticator,
    control: UdpSocket,
    allocations: HashMap<SocketAddr, Allocation>,
    response_cache: HashMap<ResponseCacheKey, CachedResponse>,
    response_cache_order: VecDeque<ResponseCacheKey>,
}

impl TurnUdpRelay {
    /// Validates configuration and binds the client-facing UDP socket.
    ///
    /// # Errors
    ///
    /// Returns [`TurnRelayError`] for invalid limits, credential scope, or an
    /// operating-system bind failure.
    pub async fn bind(
        config: TurnUdpRelayConfig,
        credentials: RelayCredentialAuthority,
    ) -> Result<Self, TurnRelayError> {
        config.validate()?;
        let authenticator = TurnAuthenticator::new(credentials, config.relay_id)?;
        let control = UdpSocket::bind(config.listen_address)
            .await
            .map_err(|source| TurnRelayError::BindControl {
                address: config.listen_address,
                source,
            })?;
        Ok(Self {
            config,
            authenticator,
            control,
            allocations: HashMap::new(),
            response_cache: HashMap::new(),
            response_cache_order: VecDeque::new(),
        })
    }

    /// Returns the actual listener address, including an assigned port.
    ///
    /// # Errors
    ///
    /// Returns [`TurnRelayError`] if the operating system cannot report the
    /// bound socket address.
    pub fn local_address(&self) -> Result<SocketAddr, TurnRelayError> {
        self.control
            .local_addr()
            .map_err(|source| TurnRelayError::LocalAddress { source })
    }

    /// Serves TURN UDP until `shutdown` resolves.
    ///
    /// Malformed or one-way records are dropped locally; listener I/O failure
    /// terminates the runtime so the service manager can restart it.
    ///
    /// # Errors
    ///
    /// Returns [`TurnRelayError`] for clock or listener I/O failures and for
    /// internal response encoding failures.
    pub async fn run<F>(mut self, shutdown: F) -> Result<(), TurnRelayError>
    where
        F: Future<Output = ()> + Send,
    {
        let mut shutdown = std::pin::pin!(shutdown);
        let mut cleanup = tokio::time::interval(Duration::from_secs(1));
        cleanup.set_missed_tick_behavior(MissedTickBehavior::Delay);
        let mut receive_buffer = vec![0_u8; RECEIVE_BUFFER_LENGTH];
        loop {
            tokio::select! {
                () = &mut shutdown => return Ok(()),
                _ = cleanup.tick() => self.remove_expired(Instant::now()),
                received = self.control.recv_from(&mut receive_buffer) => {
                    let (length, client) = received.map_err(|source| TurnRelayError::ReceiveControl {
                        source,
                    })?;
                    let now_unix = unix_time()?;
                    let now = Instant::now();
                    if let Some(response) = self
                        .handle_client_record(&receive_buffer[..length], client, now_unix, now)
                        .await?
                    {
                        self.control
                            .send_to(&response, client)
                            .await
                            .map_err(|source| TurnRelayError::SendControl { client, source })?;
                    }
                }
            }
        }
    }

    async fn handle_client_record(
        &mut self,
        input: &[u8],
        client: SocketAddr,
        now_unix: u64,
        now: Instant,
    ) -> Result<Option<Vec<u8>>, TurnRelayError> {
        if input.len() < 2 || input[0] & 0xc0 != 0 {
            return Ok(None);
        }
        let Ok(message) = StunMessageView::decode(input) else {
            return Ok(None);
        };
        if message.message_type().class != StunClass::Request {
            return Ok(None);
        }
        let cache_key = ResponseCacheKey {
            client,
            transaction_id: message.transaction_id(),
        };
        if let Some(cached) = self.response_cache.get(&cache_key) {
            if cached.expires_at > now {
                return Ok(Some(cached.bytes.clone()));
            }
        }

        let response = match message.message_type().method {
            StunMethod::Binding => Self::handle_binding(&message, client)?,
            StunMethod::Allocate => {
                self.handle_allocate(&message, client, now_unix, now)
                    .await?
            }
            StunMethod::Refresh => self.handle_refresh(&message, client, now_unix, now)?,
            _ => Self::error_response(&message, 400, "Bad Request", None, None)?,
        };
        self.cache_response(cache_key, response.clone(), now)?;
        Ok(Some(response))
    }

    fn handle_binding(
        message: &StunMessageView<'_>,
        client: SocketAddr,
    ) -> Result<Vec<u8>, TurnRelayError> {
        let unknown = unknown_required_attributes(message)?;
        if !unknown.is_empty() {
            return Self::error_response(message, 420, "Unknown Attribute", None, Some(&unknown));
        }
        let mapped = xor_address_value(client, message.transaction_id())?;
        encode_response(
            message.message_type().method,
            StunClass::SuccessResponse,
            message.transaction_id(),
            vec![
                OwnedAttribute::new(StunAttributeType::XOR_MAPPED_ADDRESS, mapped),
                OwnedAttribute::new(StunAttributeType::SOFTWARE, SOFTWARE.to_vec()),
            ],
            None,
        )
    }

    async fn handle_allocate(
        &mut self,
        message: &StunMessageView<'_>,
        client: SocketAddr,
        now_unix: u64,
        now: Instant,
    ) -> Result<Vec<u8>, TurnRelayError> {
        let authenticated = match self.authenticate(message, now_unix)? {
            AuthenticationDecision::Authenticated(value) => value,
            AuthenticationDecision::Response(response) => return Ok(response),
        };
        let unknown = unknown_required_attributes(message)?;
        if !unknown.is_empty() {
            return Self::error_response(
                message,
                420,
                "Unknown Attribute",
                Some(&authenticated),
                Some(&unknown),
            );
        }
        let requested_transport = match Self::validated_method_value(
            unique_attribute(message, StunAttributeType::REQUESTED_TRANSPORT),
            message,
            &authenticated,
        )? {
            Ok(value) => value,
            Err(response) => return Ok(response),
        };
        let Some(requested_transport) = requested_transport else {
            return Self::error_response(message, 400, "Bad Request", Some(&authenticated), None);
        };
        if requested_transport != REQUESTED_TRANSPORT_UDP {
            return Self::error_response(
                message,
                442,
                "Unsupported Transport Protocol",
                Some(&authenticated),
                None,
            );
        }
        let lifetime = match Self::validated_method_value(
            requested_lifetime(message, self.config.allocation_lifetime_seconds, false),
            message,
            &authenticated,
        )? {
            Ok(value) => value,
            Err(response) => return Ok(response),
        };
        if self.allocations.contains_key(&client) {
            return Self::error_response(
                message,
                437,
                "Allocation Mismatch",
                Some(&authenticated),
                None,
            );
        }
        let node_id = authenticated.node_id();
        if self.allocations.len() >= self.config.max_allocations
            || self
                .allocations
                .values()
                .filter(|allocation| allocation.node_id == node_id)
                .count()
                >= self.config.max_allocations_per_node
        {
            return Self::error_response(
                message,
                486,
                "Allocation Quota Reached",
                Some(&authenticated),
                None,
            );
        }
        let (allocation, response) = self
            .create_allocation(message, client, node_id, lifetime, now, &authenticated)
            .await?;
        self.allocations.insert(client, allocation);
        Ok(response)
    }

    async fn create_allocation(
        &self,
        message: &StunMessageView<'_>,
        client: SocketAddr,
        node_id: NodeId,
        lifetime: u32,
        now: Instant,
        authenticated: &AuthenticatedTurnRequest,
    ) -> Result<(Allocation, Vec<u8>), TurnRelayError> {
        let socket = UdpSocket::bind(SocketAddr::new(self.config.allocation_bind_address, 0))
            .await
            .map_err(|source| TurnRelayError::BindAllocation {
                address: self.config.allocation_bind_address,
                source,
            })?;
        let local = socket
            .local_addr()
            .map_err(|source| TurnRelayError::AllocationLocalAddress { source })?;
        let relayed_address = SocketAddr::new(self.config.advertised_address, local.port());
        let allocation = Allocation {
            node_id,
            _socket: socket,
            relayed_address,
            expires_at: checked_deadline(now, lifetime, "allocation lifetime")?,
            idle_deadline: checked_deadline(
                now,
                self.config.idle_timeout_seconds,
                "allocation idle timeout",
            )?,
        };
        let response = encode_response(
            message.message_type().method,
            StunClass::SuccessResponse,
            message.transaction_id(),
            vec![
                OwnedAttribute::new(
                    StunAttributeType::XOR_RELAYED_ADDRESS,
                    xor_address_value(relayed_address, message.transaction_id())?,
                ),
                OwnedAttribute::new(
                    StunAttributeType::XOR_MAPPED_ADDRESS,
                    xor_address_value(client, message.transaction_id())?,
                ),
                OwnedAttribute::new(StunAttributeType::LIFETIME, lifetime.to_be_bytes().to_vec()),
                OwnedAttribute::new(StunAttributeType::SOFTWARE, SOFTWARE.to_vec()),
            ],
            Some(authenticated),
        )?;
        Ok((allocation, response))
    }

    fn handle_refresh(
        &mut self,
        message: &StunMessageView<'_>,
        client: SocketAddr,
        now_unix: u64,
        now: Instant,
    ) -> Result<Vec<u8>, TurnRelayError> {
        let authenticated = match self.authenticate(message, now_unix)? {
            AuthenticationDecision::Authenticated(value) => value,
            AuthenticationDecision::Response(response) => return Ok(response),
        };
        let unknown = unknown_required_attributes(message)?;
        if !unknown.is_empty() {
            return Self::error_response(
                message,
                420,
                "Unknown Attribute",
                Some(&authenticated),
                Some(&unknown),
            );
        }
        let lifetime = match Self::validated_method_value(
            requested_lifetime(message, self.config.allocation_lifetime_seconds, true),
            message,
            &authenticated,
        )? {
            Ok(value) => value,
            Err(response) => return Ok(response),
        };
        let Some(allocation) = self.allocations.get_mut(&client) else {
            return Self::error_response(
                message,
                437,
                "Allocation Mismatch",
                Some(&authenticated),
                None,
            );
        };
        if allocation.node_id != authenticated.node_id() {
            return Self::error_response(
                message,
                441,
                "Wrong Credentials",
                Some(&authenticated),
                None,
            );
        }
        if lifetime == 0 {
            self.allocations.remove(&client);
        } else {
            allocation.expires_at = checked_deadline(now, lifetime, "allocation lifetime")?;
            allocation.idle_deadline = checked_deadline(
                now,
                self.config.idle_timeout_seconds,
                "allocation idle timeout",
            )?;
        }
        encode_response(
            message.message_type().method,
            StunClass::SuccessResponse,
            message.transaction_id(),
            vec![
                OwnedAttribute::new(StunAttributeType::LIFETIME, lifetime.to_be_bytes().to_vec()),
                OwnedAttribute::new(StunAttributeType::SOFTWARE, SOFTWARE.to_vec()),
            ],
            Some(&authenticated),
        )
    }

    fn authenticate(
        &self,
        message: &StunMessageView<'_>,
        now_unix: u64,
    ) -> Result<AuthenticationDecision, TurnRelayError> {
        match self
            .authenticator
            .authenticate_including_stale(message, now_unix)
        {
            Ok((authenticated, TurnNonceStatus::Valid)) => {
                Ok(AuthenticationDecision::Authenticated(authenticated))
            }
            Ok((authenticated, TurnNonceStatus::Expired)) => {
                let challenge = self.authenticator.issue_challenge(now_unix)?;
                Ok(AuthenticationDecision::Response(Self::challenge_response(
                    message,
                    438,
                    "Stale Nonce",
                    &challenge,
                    Some(&authenticated),
                )?))
            }
            Ok((_authenticated, TurnNonceStatus::Invalid)) => {
                Err(TurnRelayError::InvalidAuthenticationState)
            }
            Err(TurnAuthenticationError::Malformed { .. }) => Ok(AuthenticationDecision::Response(
                Self::error_response(message, 400, "Bad Request", None, None)?,
            )),
            Err(TurnAuthenticationError::Unauthorized | TurnAuthenticationError::StaleNonce) => {
                let challenge = self.authenticator.issue_challenge(now_unix)?;
                Ok(AuthenticationDecision::Response(Self::challenge_response(
                    message,
                    401,
                    "Unauthorized",
                    &challenge,
                    None,
                )?))
            }
        }
    }

    fn validated_method_value<T>(
        result: Result<T, TurnRelayError>,
        message: &StunMessageView<'_>,
        authenticated: &AuthenticatedTurnRequest,
    ) -> Result<Result<T, Vec<u8>>, TurnRelayError> {
        match result {
            Ok(value) => Ok(Ok(value)),
            Err(TurnRelayError::MalformedRequest { .. }) => Ok(Err(Self::error_response(
                message,
                400,
                "Bad Request",
                Some(authenticated),
                None,
            )?)),
            Err(error) => Err(error),
        }
    }

    fn challenge_response(
        message: &StunMessageView<'_>,
        code: u16,
        reason: &str,
        challenge: &crate::turn_auth::TurnChallenge,
        authenticated: Option<&AuthenticatedTurnRequest>,
    ) -> Result<Vec<u8>, TurnRelayError> {
        let mut algorithm = [0_u8; 4];
        challenge.password_algorithm().encode(&mut algorithm)?;
        let mut error = vec![0_u8; 4 + reason.len()];
        let length = encode_stun_error_code(code, reason, &mut error)?;
        error.truncate(length);
        encode_response(
            message.message_type().method,
            StunClass::ErrorResponse,
            message.transaction_id(),
            vec![
                OwnedAttribute::new(StunAttributeType::ERROR_CODE, error),
                OwnedAttribute::new(StunAttributeType::REALM, challenge.realm().to_vec()),
                OwnedAttribute::new(StunAttributeType::NONCE, challenge.nonce().to_vec()),
                OwnedAttribute::new(StunAttributeType::PASSWORD_ALGORITHM, algorithm.to_vec()),
                OwnedAttribute::new(StunAttributeType::SOFTWARE, SOFTWARE.to_vec()),
            ],
            authenticated,
        )
    }

    fn error_response(
        message: &StunMessageView<'_>,
        code: u16,
        reason: &str,
        authenticated: Option<&AuthenticatedTurnRequest>,
        unknown_attributes: Option<&[u16]>,
    ) -> Result<Vec<u8>, TurnRelayError> {
        let mut error = vec![0_u8; 4 + reason.len()];
        let length = encode_stun_error_code(code, reason, &mut error)?;
        error.truncate(length);
        let mut attributes = vec![OwnedAttribute::new(StunAttributeType::ERROR_CODE, error)];
        if let Some(unknown) = unknown_attributes {
            let mut value = Vec::with_capacity(unknown.len().saturating_mul(2));
            for attribute_type in unknown {
                value.extend_from_slice(&attribute_type.to_be_bytes());
            }
            attributes.push(OwnedAttribute::new(
                StunAttributeType::UNKNOWN_ATTRIBUTES,
                value,
            ));
        }
        attributes.push(OwnedAttribute::new(
            StunAttributeType::SOFTWARE,
            SOFTWARE.to_vec(),
        ));
        encode_response(
            message.message_type().method,
            StunClass::ErrorResponse,
            message.transaction_id(),
            attributes,
            authenticated,
        )
    }

    fn cache_response(
        &mut self,
        key: ResponseCacheKey,
        bytes: Vec<u8>,
        now: Instant,
    ) -> Result<(), TurnRelayError> {
        let expires_at =
            now.checked_add(RESPONSE_CACHE_LIFETIME)
                .ok_or(TurnRelayError::DeadlineOverflow {
                    field: "response cache lifetime",
                })?;
        self.response_cache
            .insert(key, CachedResponse { bytes, expires_at });
        self.response_cache_order.push_back(key);
        while self.response_cache.len() > RESPONSE_CACHE_CAPACITY {
            let Some(oldest) = self.response_cache_order.pop_front() else {
                break;
            };
            self.response_cache.remove(&oldest);
        }
        Ok(())
    }

    fn remove_expired(&mut self, now: Instant) {
        self.allocations.retain(|_client, allocation| {
            allocation.expires_at > now && allocation.idle_deadline > now
        });
        self.response_cache
            .retain(|_key, response| response.expires_at > now);
        while self
            .response_cache_order
            .front()
            .is_some_and(|key| !self.response_cache.contains_key(key))
        {
            self.response_cache_order.pop_front();
        }
    }
}

impl fmt::Debug for TurnUdpRelay {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("TurnUdpRelay")
            .field("config", &self.config)
            .field("authenticator", &self.authenticator)
            .field("allocation_count", &self.allocations.len())
            .field("response_cache_count", &self.response_cache.len())
            .finish_non_exhaustive()
    }
}

struct Allocation {
    node_id: NodeId,
    _socket: UdpSocket,
    relayed_address: SocketAddr,
    expires_at: Instant,
    idle_deadline: Instant,
}

impl fmt::Debug for Allocation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Allocation")
            .field("node_id", &self.node_id)
            .field("relayed_address", &self.relayed_address)
            .field("expires_at", &self.expires_at)
            .field("idle_deadline", &self.idle_deadline)
            .finish_non_exhaustive()
    }
}

enum AuthenticationDecision {
    Authenticated(AuthenticatedTurnRequest),
    Response(Vec<u8>),
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
struct ResponseCacheKey {
    client: SocketAddr,
    transaction_id: StunTransactionId,
}

struct CachedResponse {
    bytes: Vec<u8>,
    expires_at: Instant,
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

fn encode_response(
    method: StunMethod,
    class: StunClass,
    transaction_id: StunTransactionId,
    mut attributes: Vec<OwnedAttribute>,
    authenticated: Option<&AuthenticatedTurnRequest>,
) -> Result<Vec<u8>, TurnRelayError> {
    let zero_integrity = [0_u8; 32];
    if authenticated.is_some() {
        attributes.push(OwnedAttribute::new(
            StunAttributeType::MESSAGE_INTEGRITY_SHA256,
            zero_integrity.to_vec(),
        ));
    }
    let references = attributes
        .iter()
        .map(|attribute| StunAttributeRef {
            attribute_type: attribute.attribute_type,
            value: &attribute.value,
        })
        .collect::<Vec<_>>();
    let message = StunMessageRef {
        message_type: StunMessageType::new(method, class),
        transaction_id,
        attributes: &references,
    };
    let mut encoded = vec![0_u8; message.encoded_len()?];
    let length = encode_stun_message(message, &mut encoded)?;
    encoded.truncate(length);
    if let Some(authenticated) = authenticated {
        authenticated
            .sign_encoded_message(&mut encoded)
            .map_err(|_error| TurnRelayError::ResponseIntegrity)?;
    }
    Ok(encoded)
}

fn xor_address_value(
    address: SocketAddr,
    transaction_id: StunTransactionId,
) -> Result<Vec<u8>, TurnRelayError> {
    let mut value = vec![0_u8; if address.is_ipv4() { 8 } else { 20 }];
    let length = encode_stun_xor_address(address, transaction_id, &mut value)?;
    value.truncate(length);
    Ok(value)
}

fn unique_attribute<'a>(
    message: &StunMessageView<'a>,
    requested: StunAttributeType,
) -> Result<Option<&'a [u8]>, TurnRelayError> {
    let mut found = None;
    for attribute in message.attributes() {
        let attribute = attribute?;
        if attribute.attribute_type() == requested && found.replace(attribute.value()).is_some() {
            return Err(TurnRelayError::MalformedRequest {
                detail: "duplicate method attribute",
            });
        }
    }
    Ok(found)
}

fn requested_lifetime(
    message: &StunMessageView<'_>,
    maximum: u32,
    zero_allowed: bool,
) -> Result<u32, TurnRelayError> {
    let Some(value) = unique_attribute(message, StunAttributeType::LIFETIME)? else {
        return Ok(maximum);
    };
    let bytes = <[u8; 4]>::try_from(value).map_err(|_| TurnRelayError::MalformedRequest {
        detail: "LIFETIME must contain four bytes",
    })?;
    let requested = u32::from_be_bytes(bytes);
    if requested == 0 && !zero_allowed {
        return Err(TurnRelayError::MalformedRequest {
            detail: "Allocate lifetime must be non-zero",
        });
    }
    Ok(requested.min(maximum))
}

fn unknown_required_attributes(message: &StunMessageView<'_>) -> Result<Vec<u16>, TurnRelayError> {
    let mut unknown = Vec::new();
    for attribute in message.attributes() {
        let attribute = attribute?;
        let attribute_type = attribute.attribute_type();
        if attribute_type.comprehension_required()
            && !is_known_attribute(attribute_type)
            && !unknown.contains(&attribute_type.as_u16())
        {
            unknown.push(attribute_type.as_u16());
        }
    }
    unknown.sort_unstable();
    Ok(unknown)
}

fn is_known_attribute(attribute_type: StunAttributeType) -> bool {
    attribute_type == StunAttributeType::MAPPED_ADDRESS
        || attribute_type == StunAttributeType::USERNAME
        || attribute_type == StunAttributeType::MESSAGE_INTEGRITY
        || attribute_type == StunAttributeType::ERROR_CODE
        || attribute_type == StunAttributeType::UNKNOWN_ATTRIBUTES
        || attribute_type == StunAttributeType::CHANNEL_NUMBER
        || attribute_type == StunAttributeType::LIFETIME
        || attribute_type == StunAttributeType::XOR_PEER_ADDRESS
        || attribute_type == StunAttributeType::DATA
        || attribute_type == StunAttributeType::REALM
        || attribute_type == StunAttributeType::NONCE
        || attribute_type == StunAttributeType::XOR_RELAYED_ADDRESS
        || attribute_type == StunAttributeType::REQUESTED_TRANSPORT
        || attribute_type == StunAttributeType::DONT_FRAGMENT
        || attribute_type == StunAttributeType::MESSAGE_INTEGRITY_SHA256
        || attribute_type == StunAttributeType::PASSWORD_ALGORITHM
        || attribute_type == StunAttributeType::USERHASH
        || attribute_type == StunAttributeType::XOR_MAPPED_ADDRESS
        || attribute_type == StunAttributeType::SOFTWARE
        || attribute_type == StunAttributeType::ALTERNATE_SERVER
        || attribute_type == StunAttributeType::FINGERPRINT
}

fn checked_deadline(
    now: Instant,
    seconds: u32,
    field: &'static str,
) -> Result<Instant, TurnRelayError> {
    now.checked_add(Duration::from_secs(u64::from(seconds)))
        .ok_or(TurnRelayError::DeadlineOverflow { field })
}

fn unix_time() -> Result<u64, TurnRelayError> {
    Ok(SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| TurnRelayError::ClockBeforeUnixEpoch)?
        .as_secs())
}

fn invalid_config(reason: &'static str) -> TurnRelayError {
    TurnRelayError::InvalidConfig { reason }
}

/// TURN UDP relay startup or runtime failure.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum TurnRelayError {
    /// A runtime address or resource limit is invalid.
    #[error("invalid TURN relay configuration: {reason}")]
    InvalidConfig {
        /// Stable configuration rule description.
        reason: &'static str,
    },
    /// Client-facing control socket bind failed.
    #[error("unable to bind TURN UDP listener {address}")]
    BindControl {
        /// Requested listener address.
        address: SocketAddr,
        /// Underlying socket failure.
        #[source]
        source: std::io::Error,
    },
    /// Bound listener address could not be queried.
    #[error("unable to query TURN UDP listener address")]
    LocalAddress {
        /// Underlying socket failure.
        #[source]
        source: std::io::Error,
    },
    /// A per-client relay allocation socket could not be bound.
    #[error("unable to bind TURN allocation socket on {address}")]
    BindAllocation {
        /// Requested local allocation IP.
        address: IpAddr,
        /// Underlying socket failure.
        #[source]
        source: std::io::Error,
    },
    /// Bound allocation address could not be queried.
    #[error("unable to query TURN allocation socket address")]
    AllocationLocalAddress {
        /// Underlying socket failure.
        #[source]
        source: std::io::Error,
    },
    /// Client-facing receive failed.
    #[error("TURN UDP listener receive failed")]
    ReceiveControl {
        /// Underlying socket failure.
        #[source]
        source: std::io::Error,
    },
    /// Sending a response to a TURN client failed.
    #[error("unable to send TURN response to {client}")]
    SendControl {
        /// Client transport address.
        client: SocketAddr,
        /// Underlying socket failure.
        #[source]
        source: std::io::Error,
    },
    /// System wall clock precedes the Unix epoch.
    #[error("system clock is before the Unix epoch")]
    ClockBeforeUnixEpoch,
    /// A monotonic deadline could not be represented.
    #[error("TURN {field} deadline overflowed")]
    DeadlineOverflow {
        /// Deadline being calculated.
        field: &'static str,
    },
    /// A method-specific request attribute is malformed.
    #[error("malformed TURN request: {detail}")]
    MalformedRequest {
        /// Stable non-sensitive rule description.
        detail: &'static str,
    },
    /// Authentication returned an impossible nonce state.
    #[error("TURN authentication returned an invalid internal nonce state")]
    InvalidAuthenticationState,
    /// Relay credential or nonce creation failed.
    #[error(transparent)]
    Credential(#[from] crate::relay_credentials::RelayCredentialError),
    /// TURN wire encoding failed.
    #[error(transparent)]
    Codec(#[from] CodecError),
    /// Authenticated response signing failed.
    #[error("unable to sign TURN response integrity")]
    ResponseIntegrity,
}

#[cfg(test)]
mod tests {
    use std::{
        net::{IpAddr, Ipv4Addr, SocketAddr},
        time::Duration,
    };

    use hmac::{Hmac, KeyInit, Mac};
    use sha2::{Digest, Sha256};
    use stella_common::{NodeId, RelayId};
    use stella_proto::{
        decode_stun_xor_address, encode_stun_message, StunAttributeRef, StunAttributeType,
        StunClass, StunErrorCodeView, StunMessageRef, StunMessageType, StunMessageView, StunMethod,
        StunPasswordAlgorithm, StunTransactionId,
    };
    use tokio::{net::UdpSocket, sync::oneshot, time::timeout};
    use zeroize::Zeroizing;

    use super::{TurnUdpRelay, TurnUdpRelayConfig};
    use crate::relay_credentials::RelayCredentialAuthority;

    type HmacSha256 = Hmac<Sha256>;

    #[tokio::test]
    #[allow(clippy::too_many_lines)]
    async fn binding_allocate_retransmit_refresh_and_delete_round_trip() {
        let relay_id = RelayId::from_bytes([0x61; 16]);
        let node_id = NodeId::from_bytes([0x62; 16]);
        let authority =
            RelayCredentialAuthority::new([0x63; 32], 300).expect("credential authority");
        let credential = authority
            .issue(relay_id, node_id, unix_time_for_test())
            .expect("issue credential");
        let config = TurnUdpRelayConfig::new(
            relay_id,
            SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            IpAddr::V4(Ipv4Addr::LOCALHOST),
        );
        let relay = TurnUdpRelay::bind(config, authority)
            .await
            .expect("bind TURN relay");
        let relay_address = relay.local_address().expect("relay address");
        let (shutdown_tx, shutdown_rx) = oneshot::channel();
        let task = tokio::spawn(relay.run(async move {
            let _result = shutdown_rx.await;
        }));
        let client = UdpSocket::bind(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0))
            .await
            .expect("bind client");

        let binding_tx = StunTransactionId::from_bytes([1; 12]);
        send_message(&client, relay_address, StunMethod::Binding, binding_tx, &[]).await;
        let binding = receive_message(&client).await;
        assert_eq!(binding.message_type().class, StunClass::SuccessResponse);
        let mapped = required_attribute(&binding, StunAttributeType::XOR_MAPPED_ADDRESS);
        assert_eq!(
            decode_stun_xor_address(mapped, binding_tx).expect("decode mapped address"),
            client.local_addr().expect("client local address")
        );

        let allocate_challenge_tx = StunTransactionId::from_bytes([2; 12]);
        let requested_transport = [17, 0, 0, 0];
        send_message(
            &client,
            relay_address,
            StunMethod::Allocate,
            allocate_challenge_tx,
            &[StunAttributeRef {
                attribute_type: StunAttributeType::REQUESTED_TRANSPORT,
                value: &requested_transport,
            }],
        )
        .await;
        let challenge = receive_owned_message(&client).await;
        let challenge_view = StunMessageView::decode(&challenge).expect("decode challenge");
        assert_error(&challenge_view, 401);
        let realm = required_attribute(&challenge_view, StunAttributeType::REALM).to_vec();
        let nonce = required_attribute(&challenge_view, StunAttributeType::NONCE).to_vec();

        let allocate_tx = StunTransactionId::from_bytes([4; 12]);
        let authenticated_allocate = signed_request(
            StunMethod::Allocate,
            allocate_tx,
            credential.username(),
            &realm,
            &nonce,
            credential.secret(),
            &[StunAttributeRef {
                attribute_type: StunAttributeType::REQUESTED_TRANSPORT,
                value: &requested_transport,
            }],
        );
        client
            .send_to(&authenticated_allocate, relay_address)
            .await
            .expect("send authenticated Allocate");
        let allocated_bytes = receive_owned_message(&client).await;
        let allocated =
            StunMessageView::decode(&allocated_bytes).expect("decode Allocate response");
        assert_eq!(allocated.message_type().class, StunClass::SuccessResponse);
        let relayed = decode_stun_xor_address(
            required_attribute(&allocated, StunAttributeType::XOR_RELAYED_ADDRESS),
            allocate_tx,
        )
        .expect("decode relayed address");
        assert_eq!(relayed.ip(), IpAddr::V4(Ipv4Addr::LOCALHOST));
        assert_ne!(relayed.port(), 0);

        client
            .send_to(&authenticated_allocate, relay_address)
            .await
            .expect("retransmit Allocate");
        assert_eq!(receive_owned_message(&client).await, allocated_bytes);

        let refresh_tx = StunTransactionId::from_bytes([3; 12]);
        let zero_lifetime = 0_u32.to_be_bytes();
        let refresh = signed_request(
            StunMethod::Refresh,
            refresh_tx,
            credential.username(),
            &realm,
            &nonce,
            credential.secret(),
            &[StunAttributeRef {
                attribute_type: StunAttributeType::LIFETIME,
                value: &zero_lifetime,
            }],
        );
        client
            .send_to(&refresh, relay_address)
            .await
            .expect("send delete Refresh");
        let deleted = receive_message(&client).await;
        assert_eq!(deleted.message_type().class, StunClass::SuccessResponse);
        assert_eq!(
            required_attribute(&deleted, StunAttributeType::LIFETIME),
            zero_lifetime
        );

        let _result = shutdown_tx.send(());
        timeout(Duration::from_secs(2), task)
            .await
            .expect("relay shutdown deadline")
            .expect("relay task join")
            .expect("relay runtime");
    }

    fn signed_request(
        method: StunMethod,
        transaction_id: StunTransactionId,
        username: &[u8],
        realm: &[u8],
        nonce: &[u8],
        password: &[u8],
        method_attributes: &[StunAttributeRef<'_>],
    ) -> Vec<u8> {
        let mut algorithm = [0_u8; 4];
        StunPasswordAlgorithm::Sha256
            .encode(&mut algorithm)
            .expect("encode password algorithm");
        let zero_integrity = [0_u8; 32];
        let mut attributes = vec![
            StunAttributeRef {
                attribute_type: StunAttributeType::USERNAME,
                value: username,
            },
            StunAttributeRef {
                attribute_type: StunAttributeType::REALM,
                value: realm,
            },
            StunAttributeRef {
                attribute_type: StunAttributeType::NONCE,
                value: nonce,
            },
            StunAttributeRef {
                attribute_type: StunAttributeType::PASSWORD_ALGORITHM,
                value: &algorithm,
            },
        ];
        attributes.extend_from_slice(method_attributes);
        attributes.push(StunAttributeRef {
            attribute_type: StunAttributeType::MESSAGE_INTEGRITY_SHA256,
            value: &zero_integrity,
        });
        let mut encoded = encode_message(method, transaction_id, &attributes);
        let message = StunMessageView::decode(&encoded).expect("decode unsigned request");
        let integrity = message
            .message_integrity_sha256()
            .expect("integrity boundary");
        let key = long_term_key(username, realm, password);
        let mut mac =
            <HmacSha256 as KeyInit>::new_from_slice(key.as_ref()).expect("fixed HMAC key");
        mac.update(integrity.message_type_bytes());
        mac.update(&integrity.adjusted_body_length().to_be_bytes());
        mac.update(integrity.bytes_after_length());
        let tag = mac.finalize().into_bytes();
        let offset = integrity.value_offset();
        encoded[offset..offset + tag.len()].copy_from_slice(&tag);
        encoded
    }

    async fn send_message(
        client: &UdpSocket,
        relay: SocketAddr,
        method: StunMethod,
        transaction_id: StunTransactionId,
        attributes: &[StunAttributeRef<'_>],
    ) {
        client
            .send_to(&encode_message(method, transaction_id, attributes), relay)
            .await
            .expect("send STUN request");
    }

    fn encode_message(
        method: StunMethod,
        transaction_id: StunTransactionId,
        attributes: &[StunAttributeRef<'_>],
    ) -> Vec<u8> {
        let message = StunMessageRef {
            message_type: StunMessageType::new(method, StunClass::Request),
            transaction_id,
            attributes,
        };
        let mut encoded = vec![0_u8; message.encoded_len().expect("message length")];
        encode_stun_message(message, &mut encoded).expect("encode STUN message");
        encoded
    }

    async fn receive_owned_message(socket: &UdpSocket) -> Vec<u8> {
        let mut buffer = vec![0_u8; u16::MAX as usize];
        let length = timeout(Duration::from_secs(2), socket.recv(&mut buffer))
            .await
            .expect("receive timeout")
            .expect("receive response");
        buffer.truncate(length);
        buffer
    }

    async fn receive_message(socket: &UdpSocket) -> StunMessageView<'static> {
        let bytes = receive_owned_message(socket).await.into_boxed_slice();
        let leaked = Box::leak(bytes);
        StunMessageView::decode(leaked).expect("decode STUN response")
    }

    fn required_attribute<'a>(
        message: &StunMessageView<'a>,
        attribute_type: StunAttributeType,
    ) -> &'a [u8] {
        message
            .attributes()
            .map(|attribute| attribute.expect("valid attribute"))
            .find(|attribute| attribute.attribute_type() == attribute_type)
            .expect("required attribute")
            .value()
    }

    fn assert_error(message: &StunMessageView<'_>, expected: u16) {
        assert_eq!(message.message_type().class, StunClass::ErrorResponse);
        assert_eq!(
            StunErrorCodeView::decode(required_attribute(message, StunAttributeType::ERROR_CODE))
                .expect("decode error")
                .code(),
            expected
        );
    }

    fn long_term_key(username: &[u8], realm: &[u8], password: &[u8]) -> Zeroizing<[u8; 32]> {
        let mut digest = Sha256::new();
        digest.update(username);
        digest.update(b":");
        digest.update(realm);
        digest.update(b":");
        digest.update(password);
        Zeroizing::new(digest.finalize().into())
    }

    fn unix_time_for_test() -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("test clock")
            .as_secs()
    }
}
