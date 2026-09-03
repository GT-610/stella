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
const RECEIVE_BUFFER_SIZE: usize = 1_200;
const MAX_DEFERRED_DATAGRAMS: usize = 32;
const MAX_HOST_CANDIDATES: usize = 16;
const HOST_TYPE_PREFERENCE: u32 = 126;
const SERVER_REFLEXIVE_TYPE_PREFERENCE: u32 = 100;

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
    pub(crate) mapped_address: Option<SocketAddr>,
    pub(crate) base_address: Option<SocketAddr>,
    pub(crate) deferred: Vec<DeferredUdpDatagram>,
    pub(crate) dropped_datagrams: usize,
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

/// Performs Binding discovery against configured services in preference order.
pub(crate) async fn discover_server_reflexive(
    transport: &UdpTransport,
    servers: &[StunServer],
) -> Result<StunDiscovery, StunDiscoveryError> {
    let mut deferred = Vec::new();
    let mut dropped_datagrams = 0;
    for server in servers
        .iter()
        .copied()
        .filter(|server| server.address.is_ipv4() == transport.local_address().is_ipv4())
    {
        if let Some(mapped_address) = binding_transaction(
            transport,
            server.address,
            &mut deferred,
            &mut dropped_datagrams,
        )
        .await?
        {
            return Ok(StunDiscovery {
                mapped_address: Some(mapped_address),
                base_address: routed_base_address(transport.local_address(), server.address),
                deferred,
                dropped_datagrams,
            });
        }
    }
    Ok(StunDiscovery {
        mapped_address: None,
        base_address: None,
        deferred,
        dropped_datagrams,
    })
}

/// Builds one validated server-reflexive candidate from discovery output.
pub(crate) fn server_reflexive_candidate(
    discovery: &StunDiscovery,
    max_datagram_size: u32,
) -> Option<IceCandidate> {
    let mapped = discovery.mapped_address?;
    let base = discovery.base_address?;
    let candidate = IceCandidate {
        class: IceCandidateClass::ServerReflexive,
        carrier: ConnectivityCarrier::DirectUdp,
        priority: candidate_priority(SERVER_REFLEXIVE_TYPE_PREFERENCE, u16::MAX),
        foundation: candidate_foundation(IceCandidateClass::ServerReflexive, mapped.ip()),
        max_datagram_size,
        address: mapped,
        related_address: Some(base),
        relay_id: None,
    };
    candidate.validate().is_ok().then_some(candidate)
}

async fn binding_transaction(
    transport: &UdpTransport,
    server: SocketAddr,
    deferred: &mut Vec<DeferredUdpDatagram>,
    dropped_datagrams: &mut usize,
) -> Result<Option<SocketAddr>, StunDiscoveryError> {
    let transaction_id = random_transaction_id()?;
    let request = StunMessageRef {
        message_type: StunMessageType::new(StunMethod::Binding, StunClass::Request),
        transaction_id,
        attributes: &[],
    };
    let mut encoded = vec![0_u8; request.encoded_len()?];
    let length = encode_stun_message(request, &mut encoded)?;
    encoded.truncate(length);
    let endpoint = Endpoint::Udp(server);
    let deadline = Instant::now()
        .checked_add(TRANSACTION_TIMEOUT)
        .ok_or(StunDiscoveryError::DeadlineOverflow)?;
    let mut retransmit = INITIAL_RETRANSMIT_TIMEOUT;
    let mut receive_buffer = vec![0_u8; RECEIVE_BUFFER_SIZE];
    loop {
        transport.send_to(&endpoint, &encoded).await?;
        let attempt_deadline = deadline.min(
            Instant::now()
                .checked_add(retransmit)
                .ok_or(StunDiscoveryError::DeadlineOverflow)?,
        );
        loop {
            let received =
                match timeout_at(attempt_deadline, transport.receive(&mut receive_buffer)).await {
                    Ok(result) => result?,
                    Err(_elapsed) => break,
                };
            let bytes = receive_buffer[..received.length].to_vec();
            if received.source != endpoint {
                defer_datagram(deferred, received.source, bytes, dropped_datagrams);
                continue;
            }
            let Ok(message) = StunMessageView::decode(&bytes) else {
                continue;
            };
            if message.transaction_id() != transaction_id
                || message.message_type().method != StunMethod::Binding
            {
                continue;
            }
            if message.message_type().class != StunClass::SuccessResponse {
                return Ok(None);
            }
            let mapped = unique_attribute(&message, StunAttributeType::XOR_MAPPED_ADDRESS)?.ok_or(
                stella_proto::CodecError::MissingStunAttribute {
                    attribute_type: StunAttributeType::XOR_MAPPED_ADDRESS.as_u16(),
                },
            )?;
            return decode_stun_xor_address(mapped, transaction_id)
                .map(Some)
                .map_err(Into::into);
        }
        if Instant::now() >= deadline {
            return Ok(None);
        }
        retransmit = retransmit.saturating_mul(2).min(MAX_RETRANSMIT_TIMEOUT);
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
    use stella_proto::{IceCandidateClass, StunServer};
    use stella_server::{
        relay_credentials::RelayCredentialAuthority,
        turn_relay::{TurnUdpRelay, TurnUdpRelayConfig},
    };
    use stella_transport::{DatagramTransport, Endpoint, UdpConfig, UdpTransport};
    use tokio::{sync::oneshot, time::timeout};

    use super::{
        defer_datagram, discover_server_reflexive, gather_host_candidates,
        server_reflexive_candidate, MAX_DEFERRED_DATAGRAMS,
    };

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
        let discovery = discover_server_reflexive(
            &transport,
            &[StunServer {
                priority: 0,
                address: relay_address,
            }],
        )
        .await
        .expect("STUN discovery");
        assert_eq!(discovery.mapped_address, Some(transport.local_address()));
        assert_eq!(discovery.base_address, Some(transport.local_address()));
        assert!(discovery.deferred.is_empty());
        assert_eq!(discovery.dropped_datagrams, 0);
        assert!(server_reflexive_candidate(&discovery, 1_200).is_none());

        transport.shutdown().await.expect("shutdown transport");
        let _result = shutdown_sender.send(());
        timeout(Duration::from_secs(2), relay_task)
            .await
            .expect("relay shutdown timeout")
            .expect("relay task join")
            .expect("relay run");
    }
}
