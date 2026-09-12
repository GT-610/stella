//! Same-socket STUN discovery and bounded host ICE candidate gathering.

use std::{
    collections::BTreeSet,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    time::Duration,
};

use stella_proto::{
    decode_stun_xor_address, encode_stun_message, ConnectivityCarrier, IceCandidate,
    IceCandidateClass, StunAttributeType, StunClass, StunMessageRef, StunMessageType,
    StunMessageView, StunMethod, StunServer, StunTransactionId,
};
use stella_transport::{DatagramTransport, Endpoint, TransportError, UdpTransport};
use thiserror::Error;
use tokio::time::{timeout_at, Instant};

const INITIAL_RETRANSMIT_TIMEOUT: Duration = Duration::from_millis(250);
const MAX_RETRANSMIT_TIMEOUT: Duration = Duration::from_secs(1);
const TRANSACTION_TIMEOUT: Duration = Duration::from_secs(3);
const POST_SUCCESS_GRACE: Duration = Duration::from_millis(250);
const RECEIVE_BUFFER_SIZE: usize = 1_200;
const MAX_DEFERRED_DATAGRAMS: usize = 32;
const MAX_HOST_CANDIDATES: usize = 16;
const MAX_STUN_SERVERS: usize = 8;
const HOST_TYPE_PREFERENCE: u32 = 126;
const SERVER_REFLEXIVE_TYPE_PREFERENCE: u32 = 100;
const STUN_FINGERPRINT_XOR: u32 = 0x5354_554e;

/// Failure while gathering direct UDP connectivity candidates.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum StunDiscoveryError {
    /// Interface enumeration failed.
    #[error("network interface enumeration failed")]
    InterfaceEnumeration(#[source] std::io::Error),
    /// Operating-system randomness was unavailable.
    #[error("operating-system randomness is unavailable for STUN transaction ID")]
    RandomnessUnavailable,
    /// A monotonic STUN transaction deadline overflowed.
    #[error("STUN transaction deadline overflowed")]
    DeadlineOverflow,
    /// UDP transport I/O or bounds validation failed.
    #[error(transparent)]
    Transport(#[from] TransportError),
    /// A matching STUN response was malformed.
    #[error(transparent)]
    Codec(#[from] stella_proto::CodecError),
    /// A supplied STUN fingerprint did not authenticate the received record.
    #[error("STUN FINGERPRINT validation failed")]
    InvalidFingerprint,
}

/// One unrelated UDP datagram retained while STUN owned the receive loop.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct DeferredUdpDatagram {
    pub(crate) source: Endpoint,
    pub(crate) bytes: Vec<u8>,
}

/// Successful same-socket server-reflexive discovery and deferred traffic.
#[derive(Debug)]
pub(crate) struct StunDiscovery {
    pub(crate) mappings: Vec<StunMapping>,
    pub(crate) deferred: Vec<DeferredUdpDatagram>,
    pub(crate) dropped_datagrams: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct StunMapping {
    pub(crate) mapped_address: SocketAddr,
    pub(crate) base_address: SocketAddr,
}

/// Enumerates bounded host candidates for the socket family and port.
pub(crate) fn gather_host_candidates(
    local_socket: SocketAddr,
    excluded_interfaces: &BTreeSet<String>,
    max_datagram_size: u32,
) -> Result<Vec<IceCandidate>, StunDiscoveryError> {
    let mut addresses = if local_socket.ip().is_unspecified() {
        if_addrs::get_if_addrs()
            .map_err(StunDiscoveryError::InterfaceEnumeration)?
            .into_iter()
            .filter(|interface| {
                !excluded_interfaces
                    .iter()
                    .any(|excluded| interface.name.eq_ignore_ascii_case(excluded))
            })
            .map(|interface| interface.ip())
            .filter(|address| address.is_ipv4() == local_socket.is_ipv4())
            .filter(|address| usable_host_address(*address))
            .collect::<Vec<_>>()
    } else if usable_host_address(local_socket.ip()) {
        vec![local_socket.ip()]
    } else {
        Vec::new()
    };
    addresses.sort_by_key(host_address_sort_key);
    addresses.dedup();
    addresses.truncate(MAX_HOST_CANDIDATES);
    Ok(addresses
        .into_iter()
        .enumerate()
        .map(|(index, address)| IceCandidate {
            class: IceCandidateClass::Host,
            carrier: ConnectivityCarrier::DirectUdp,
            priority: candidate_priority(
                HOST_TYPE_PREFERENCE,
                u16::MAX.saturating_sub(u16::try_from(index).unwrap_or(u16::MAX)),
            ),
            foundation: candidate_foundation(IceCandidateClass::Host, address),
            max_datagram_size,
            address: SocketAddr::new(address, local_socket.port()),
            related_address: None,
            relay_id: None,
        })
        .collect())
}

/// Performs Binding discovery against bounded configured services in parallel.
pub(crate) async fn discover_server_reflexive(
    transport: &UdpTransport,
    servers: &[StunServer],
) -> Result<StunDiscovery, StunDiscoveryError> {
    let mut deferred = Vec::new();
    let mut dropped_datagrams = 0;
    let started_at = Instant::now();
    let deadline = started_at
        .checked_add(TRANSACTION_TIMEOUT)
        .ok_or(StunDiscoveryError::DeadlineOverflow)?;
    let mut seen_servers = BTreeSet::new();
    let mut transactions = servers
        .iter()
        .copied()
        .filter(|server| server.address.is_ipv4() == transport.local_address().is_ipv4())
        .filter(|server| seen_servers.insert(server.address))
        .take(MAX_STUN_SERVERS)
        .map(|server| BindingTransaction::new(server.address, started_at, deadline))
        .collect::<Result<Vec<_>, _>>()?;
    let mut mappings = Vec::new();
    let mut receive_buffer = vec![0_u8; RECEIVE_BUFFER_SIZE];
    while !transactions.is_empty() {
        let now = Instant::now();
        transactions.retain(|transaction| now < transaction.deadline);
        if transactions.is_empty() {
            break;
        }
        for transaction in &mut transactions {
            if now >= transaction.next_send {
                transport
                    .send_to(&Endpoint::Udp(transaction.server), &transaction.request)
                    .await?;
                transaction.next_send = now
                    .checked_add(transaction.retransmit)
                    .ok_or(StunDiscoveryError::DeadlineOverflow)?;
                transaction.retransmit = transaction
                    .retransmit
                    .saturating_mul(2)
                    .min(MAX_RETRANSMIT_TIMEOUT);
            }
        }
        let wake_at = transactions
            .iter()
            .map(|transaction| transaction.next_send.min(transaction.deadline))
            .min()
            .ok_or(StunDiscoveryError::DeadlineOverflow)?;
        let received = match timeout_at(wake_at, transport.receive(&mut receive_buffer)).await {
            Ok(result) => result?,
            Err(_elapsed) => continue,
        };
        let bytes = receive_buffer[..received.length].to_vec();
        let Some(source) = received.source.as_udp() else {
            defer_datagram(
                &mut deferred,
                received.source,
                bytes,
                &mut dropped_datagrams,
            );
            continue;
        };
        if !transactions
            .iter()
            .any(|transaction| transaction.server == source)
        {
            defer_datagram(
                &mut deferred,
                received.source,
                bytes,
                &mut dropped_datagrams,
            );
            continue;
        }
        let Ok(message) = StunMessageView::decode(&bytes) else {
            continue;
        };
        let Some(index) = transactions.iter().position(|transaction| {
            transaction.server == source && transaction.transaction_id == message.transaction_id()
        }) else {
            continue;
        };
        if message.message_type().method != StunMethod::Binding {
            continue;
        }
        if message.message_type().class != StunClass::SuccessResponse {
            transactions.swap_remove(index);
            continue;
        }
        if validate_optional_fingerprint(&message).is_err() {
            transactions.swap_remove(index);
            continue;
        }
        let mapped = match unique_attribute(&message, StunAttributeType::XOR_MAPPED_ADDRESS) {
            Ok(Some(mapped)) => mapped,
            Ok(None) | Err(_) => {
                transactions.swap_remove(index);
                continue;
            }
        };
        let mapped_address =
            match decode_stun_xor_address(mapped, transactions[index].transaction_id) {
                Ok(address) => address,
                Err(_) => {
                    transactions.swap_remove(index);
                    continue;
                }
            };
        if mapped_address.is_ipv4() != transport.local_address().is_ipv4() {
            transactions.swap_remove(index);
            continue;
        }
        if let Some(base_address) =
            routed_base_address(transport.local_address(), transactions[index].server)
        {
            let mapping = StunMapping {
                mapped_address,
                base_address,
            };
            let first_success = mappings.is_empty();
            if !mappings.contains(&mapping) {
                mappings.push(mapping);
            }
            if first_success {
                let completion_deadline = Instant::now()
                    .checked_add(POST_SUCCESS_GRACE)
                    .ok_or(StunDiscoveryError::DeadlineOverflow)?;
                for transaction in &mut transactions {
                    transaction.deadline = transaction.deadline.min(completion_deadline);
                }
            }
        }
        transactions.swap_remove(index);
    }
    Ok(StunDiscovery {
        mappings,
        deferred,
        dropped_datagrams,
    })
}

/// Builds validated server-reflexive candidates from discovery output.
pub(crate) fn server_reflexive_candidates(
    discovery: &StunDiscovery,
    max_datagram_size: u32,
) -> Vec<IceCandidate> {
    discovery
        .mappings
        .iter()
        .enumerate()
        .filter_map(|(index, mapping)| {
            let candidate = IceCandidate {
                class: IceCandidateClass::ServerReflexive,
                carrier: ConnectivityCarrier::DirectUdp,
                priority: candidate_priority(
                    SERVER_REFLEXIVE_TYPE_PREFERENCE,
                    u16::MAX.saturating_sub(u16::try_from(index).unwrap_or(u16::MAX)),
                ),
                foundation: candidate_foundation(
                    IceCandidateClass::ServerReflexive,
                    mapping.mapped_address.ip(),
                ),
                max_datagram_size,
                address: mapping.mapped_address,
                related_address: Some(mapping.base_address),
                relay_id: None,
            };
            candidate.validate().is_ok().then_some(candidate)
        })
        .collect()
}

struct BindingTransaction {
    server: SocketAddr,
    transaction_id: StunTransactionId,
    request: Vec<u8>,
    next_send: Instant,
    retransmit: Duration,
    deadline: Instant,
}

impl BindingTransaction {
    fn new(
        server: SocketAddr,
        started_at: Instant,
        deadline: Instant,
    ) -> Result<Self, StunDiscoveryError> {
        let transaction_id = random_transaction_id()?;
        let request = StunMessageRef {
            message_type: StunMessageType::new(StunMethod::Binding, StunClass::Request),
            transaction_id,
            attributes: &[],
        };
        let mut encoded = vec![0_u8; request.encoded_len()?];
        let length = encode_stun_message(request, &mut encoded)?;
        encoded.truncate(length);
        Ok(Self {
            server,
            transaction_id,
            request: encoded,
            next_send: started_at,
            retransmit: INITIAL_RETRANSMIT_TIMEOUT,
            deadline,
        })
    }
}

fn defer_datagram(
    deferred: &mut Vec<DeferredUdpDatagram>,
    source: Endpoint,
    bytes: Vec<u8>,
    dropped_datagrams: &mut usize,
) {
    if deferred.len() < MAX_DEFERRED_DATAGRAMS {
        deferred.push(DeferredUdpDatagram { source, bytes });
    } else {
        *dropped_datagrams = dropped_datagrams.saturating_add(1);
    }
}

fn unique_attribute<'a>(
    message: &'a StunMessageView<'a>,
    attribute_type: StunAttributeType,
) -> Result<Option<&'a [u8]>, stella_proto::CodecError> {
    let mut found = None;
    for attribute in message.attributes() {
        let attribute = attribute?;
        if attribute.attribute_type() == attribute_type {
            if found.is_some() {
                return Err(stella_proto::CodecError::DuplicateStunAttribute {
                    attribute_type: attribute_type.as_u16(),
                });
            }
            found = Some(attribute.value());
        }
    }
    Ok(found)
}

fn validate_optional_fingerprint(message: &StunMessageView<'_>) -> Result<(), StunDiscoveryError> {
    let mut fingerprint = None;
    for attribute in message.attributes() {
        let attribute = attribute?;
        if attribute.attribute_type() != StunAttributeType::FINGERPRINT {
            continue;
        }
        if fingerprint.is_some() || attribute.value().len() != 4 {
            return Err(StunDiscoveryError::InvalidFingerprint);
        }
        fingerprint = Some((
            attribute.encoded_offset(),
            attribute.encoded_len(),
            attribute.value(),
        ));
    }
    let Some((offset, encoded_len, value)) = fingerprint else {
        return Ok(());
    };
    if offset.saturating_add(encoded_len) != message.encoded().len() {
        return Err(StunDiscoveryError::InvalidFingerprint);
    }
    let expected = crc32(&message.encoded()[..offset]) ^ STUN_FINGERPRINT_XOR;
    let actual = u32::from_be_bytes(
        <[u8; 4]>::try_from(value).map_err(|_| StunDiscoveryError::InvalidFingerprint)?,
    );
    if actual == expected {
        Ok(())
    } else {
        Err(StunDiscoveryError::InvalidFingerprint)
    }
}

fn crc32(bytes: &[u8]) -> u32 {
    let mut crc = u32::MAX;
    for byte in bytes {
        crc ^= u32::from(*byte);
        for _ in 0..8 {
            let polynomial = 0xedb8_8320 & 0_u32.wrapping_sub(crc & 1);
            crc = (crc >> 1) ^ polynomial;
        }
    }
    !crc
}

fn random_transaction_id() -> Result<StunTransactionId, StunDiscoveryError> {
    let mut bytes = [0_u8; 12];
    getrandom::fill(&mut bytes).map_err(|_| StunDiscoveryError::RandomnessUnavailable)?;
    Ok(StunTransactionId::from_bytes(bytes))
}

fn routed_base_address(local_socket: SocketAddr, server: SocketAddr) -> Option<SocketAddr> {
    if !local_socket.ip().is_unspecified() {
        return Some(local_socket);
    }
    let bind = if server.is_ipv4() {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0)
    } else {
        SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0)
    };
    let socket = std::net::UdpSocket::bind(bind).ok()?;
    socket.connect(server).ok()?;
    let routed = socket.local_addr().ok()?;
    usable_host_address(routed.ip()).then(|| SocketAddr::new(routed.ip(), local_socket.port()))
}

fn usable_host_address(address: IpAddr) -> bool {
    match address {
        IpAddr::V4(address) => {
            !address.is_unspecified()
                && !address.is_loopback()
                && !address.is_multicast()
                && !address.is_link_local()
                && address != Ipv4Addr::BROADCAST
        }
        IpAddr::V6(address) => {
            !address.is_unspecified()
                && !address.is_loopback()
                && !address.is_multicast()
                && !address.is_unicast_link_local()
                && address.to_ipv4_mapped().is_none()
        }
    }
}

fn host_address_sort_key(address: &IpAddr) -> (u8, [u8; 16]) {
    match address {
        IpAddr::V6(address) if !address.is_unique_local() => (0, address.octets()),
        IpAddr::V4(address) => {
            let mut bytes = [0_u8; 16];
            bytes[..4].copy_from_slice(&address.octets());
            (1, bytes)
        }
        IpAddr::V6(address) => (2, address.octets()),
    }
}

const fn candidate_priority(type_preference: u32, local_preference: u16) -> u32 {
    (type_preference << 24) | ((local_preference as u32) << 8) | 255
}

fn candidate_foundation(class: IceCandidateClass, address: IpAddr) -> u32 {
    let mut value = u32::from(class.as_u8());
    match address {
        IpAddr::V4(address) => value ^= u32::from_be_bytes(address.octets()),
        IpAddr::V6(address) => {
            for chunk in address.octets().chunks_exact(4) {
                value ^= u32::from_be_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);
            }
        }
    }
    value.max(1)
}

#[cfg(test)]
mod tests {
    use std::{collections::BTreeSet, net::IpAddr, time::Duration};

    use stella_common::RelayId;
    use stella_proto::{
        encode_stun_message, IceCandidateClass, StunAttributeRef, StunAttributeType, StunClass,
        StunMessageRef, StunMessageType, StunMessageView, StunMethod, StunServer,
        StunTransactionId,
    };
    use stella_server::{
        relay_credentials::RelayCredentialAuthority,
        turn_relay::{TurnUdpRelay, TurnUdpRelayConfig},
    };
    use stella_transport::{DatagramTransport, Endpoint, UdpConfig, UdpTransport};
    use tokio::{sync::oneshot, time::timeout};

    use super::{
        crc32, defer_datagram, discover_server_reflexive, gather_host_candidates,
        server_reflexive_candidates, validate_optional_fingerprint, MAX_DEFERRED_DATAGRAMS,
        STUN_FINGERPRINT_XOR,
    };

    #[test]
    fn optional_fingerprint_is_verified_when_present() {
        assert_eq!(crc32(b"123456789"), 0xcbf4_3926);
        let placeholder = [0_u8; 4];
        let attributes = [StunAttributeRef {
            attribute_type: StunAttributeType::FINGERPRINT,
            value: &placeholder,
        }];
        let message = StunMessageRef {
            message_type: StunMessageType::new(StunMethod::Binding, StunClass::SuccessResponse),
            transaction_id: StunTransactionId::from_bytes([0x45; 12]),
            attributes: &attributes,
        };
        let mut encoded = vec![0_u8; message.encoded_len().expect("message length")];
        let length = encode_stun_message(message, &mut encoded).expect("encode fingerprint");
        encoded.truncate(length);
        let attribute_offset = encoded.len() - 8;
        let value_offset = encoded.len() - 4;
        let fingerprint = crc32(&encoded[..attribute_offset]) ^ STUN_FINGERPRINT_XOR;
        encoded[value_offset..].copy_from_slice(&fingerprint.to_be_bytes());

        let view = StunMessageView::decode(&encoded).expect("decode fingerprint");
        validate_optional_fingerprint(&view).expect("valid fingerprint");
        let last = encoded.len() - 1;
        encoded[last] ^= 1;
        let view = StunMessageView::decode(&encoded).expect("decode mutated fingerprint");
        assert!(validate_optional_fingerprint(&view).is_err());
    }

    #[test]
    fn specified_host_candidate_is_valid_and_tap_exclusions_are_case_insensitive() {
        let candidates = gather_host_candidates(
            "192.0.2.50:47000".parse().expect("local socket"),
            &BTreeSet::from(["Stella TAP".to_owned()]),
            1_200,
        )
        .expect("gather candidates");
        assert_eq!(candidates.len(), 1);
        assert_eq!(candidates[0].class, IceCandidateClass::Host);
        assert_eq!(
            candidates[0].address,
            "192.0.2.50:47000".parse().expect("candidate address")
        );
        candidates[0].validate().expect("valid host candidate");
    }

    #[test]
    fn deferred_datagram_queue_counts_overflow() {
        let source = Endpoint::Udp("127.0.0.1:47001".parse().expect("source address"));
        let mut deferred = Vec::new();
        let mut dropped_datagrams = 0;
        for index in 0..MAX_DEFERRED_DATAGRAMS + 3 {
            defer_datagram(
                &mut deferred,
                source.clone(),
                vec![u8::try_from(index).expect("test index fits u8")],
                &mut dropped_datagrams,
            );
        }

        assert_eq!(deferred.len(), MAX_DEFERRED_DATAGRAMS);
        assert_eq!(deferred[0].bytes, [0]);
        assert_eq!(
            deferred[MAX_DEFERRED_DATAGRAMS - 1].bytes,
            [u8::try_from(MAX_DEFERRED_DATAGRAMS - 1).expect("capacity fits u8")]
        );
        assert_eq!(dropped_datagrams, 3);
    }

    #[tokio::test]
    async fn binding_discovers_mapping_on_the_data_socket() {
        let relay_id = RelayId::from_bytes([0x31; 16]);
        let authority =
            RelayCredentialAuthority::new([0x32; 32], 300).expect("credential authority");
        let relay = TurnUdpRelay::bind(
            TurnUdpRelayConfig::new(
                relay_id,
                "127.0.0.1:0".parse().expect("relay bind"),
                IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
                IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
            ),
            authority,
        )
        .await
        .expect("bind relay");
        let relay_address = relay.local_address().expect("relay address");
        let (shutdown_sender, shutdown_receiver) = oneshot::channel();
        let relay_task = tokio::spawn(relay.run(async move {
            let _result = shutdown_receiver.await;
        }));
        let transport = UdpTransport::bind(UdpConfig::new(
            "127.0.0.1:0".parse().expect("transport bind"),
        ))
        .await
        .expect("bind data transport");
        let blackhole = tokio::net::UdpSocket::bind("127.0.0.1:0")
            .await
            .expect("bind blackhole STUN server");
        let discovery = timeout(
            Duration::from_secs(1),
            discover_server_reflexive(
                &transport,
                &[
                    StunServer {
                        priority: 0,
                        address: blackhole.local_addr().expect("blackhole address"),
                    },
                    StunServer {
                        priority: 1,
                        address: relay_address,
                    },
                ],
            ),
        )
        .await
        .expect("parallel STUN discovery timeout")
        .expect("STUN discovery");
        assert_eq!(discovery.mappings.len(), 1);
        assert_eq!(
            discovery.mappings[0].mapped_address,
            transport.local_address()
        );
        assert_eq!(
            discovery.mappings[0].base_address,
            transport.local_address()
        );
        assert!(discovery.deferred.is_empty());
        assert_eq!(discovery.dropped_datagrams, 0);
        assert!(server_reflexive_candidates(&discovery, 1_200).is_empty());

        transport.shutdown().await.expect("shutdown transport");
        let _result = shutdown_sender.send(());
        timeout(Duration::from_secs(2), relay_task)
            .await
            .expect("relay shutdown timeout")
            .expect("relay task join")
            .expect("relay run");
    }
}
