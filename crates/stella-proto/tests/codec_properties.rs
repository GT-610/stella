//! Property tests for strict Stella codec bounds and round-trip symmetry.

use proptest::prelude::*;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use stella_common::{NetworkId, NodeId};
use stella_proto::{
    decode_control_record_length, decode_turn_stream_record_length, encode_endpoint_set,
    encode_session_confirm, encode_session_reject, encode_stun_server_list, CommonHeader,
    ConnectivityGenerationView, ConnectivityListView, ConnectivityRecordView, ControlFieldIter,
    ControlHeader, ControlMessageView, DataHeader, DataPacketView, Endpoint, EndpointSetView,
    HandshakeHeader, IceCandidate, KeepaliveHeader, KeepalivePacketView, MembershipGrantView,
    NetworkPolicy, NetworkRevisionListView, PacketType, PeerListView, PeerRecordView,
    ProtocolVersion, RelayServiceListView, RelayServiceView, SessionConfirmRef, SessionConfirmRole,
    SessionConfirmView, SessionInitView, SessionRejectReason, SessionRejectRef, SessionRejectView,
    SessionResponseView, StunMessageView, StunServer, StunServerListView, TurnChannelDataView,
    VersionListView, HANDSHAKE_FIXED_HEADER_LENGTH, MAX_ENDPOINT_DATAGRAM_SIZE,
    MIN_ENDPOINT_DATAGRAM_SIZE, SESSION_CONFIRM_PAYLOAD_LENGTH, SESSION_CONFIRM_RESPONDER_FLAG,
    SESSION_REJECT_PAYLOAD_LENGTH, STUN_SERVER_RECORD_LENGTH,
};

#[derive(Clone, Copy)]
struct HeaderFields {
    network_id: [u8; 16],
    sender_node_id: [u8; 16],
    receiver_node_id: [u8; 16],
    controller_epoch: u64,
    handshake_id: u64,
    timestamp: u64,
    session_id: u64,
}

fn handshake_header(
    packet_type: PacketType,
    flags: u8,
    payload_length: usize,
    fields: HeaderFields,
) -> HandshakeHeader {
    HandshakeHeader {
        common: CommonHeader {
            version: ProtocolVersion::CURRENT,
            packet_type,
            flags,
            header_length: u16::try_from(HANDSHAKE_FIXED_HEADER_LENGTH)
                .expect("fixed handshake header fits u16"),
            payload_length: u32::try_from(payload_length).expect("handshake payload fits u32"),
            network_id: NetworkId::from_bytes(fields.network_id),
        },
        sender_node_id: NodeId::from_bytes(fields.sender_node_id),
        receiver_node_id: NodeId::from_bytes(fields.receiver_node_id),
        controller_epoch: fields.controller_epoch,
        handshake_id: fields.handshake_id,
        timestamp: fields.timestamp,
        session_id: fields.session_id,
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(512))]

    #[test]
    fn arbitrary_codec_input_never_panics(input in prop::collection::vec(any::<u8>(), 0..4_097)) {
        let _common_header = CommonHeader::decode(&input);
        let _data_header = DataHeader::decode(&input);
        let _data_packet = DataPacketView::decode(&input);
        let _keepalive_header = KeepaliveHeader::decode(&input);
        let _keepalive_packet = KeepalivePacketView::decode(&input);
        let _handshake_header = HandshakeHeader::decode(&input);
        let _session_init = SessionInitView::decode(&input);
        let _session_response = SessionResponseView::decode(&input);
        let _session_confirm = SessionConfirmView::decode(&input);
        let _session_reject = SessionRejectView::decode(&input);
        let _control_header = ControlHeader::decode(&input);
        let _control_message = ControlMessageView::decode(&input);
        let _control_fields = ControlFieldIter::decode(&input);
        let _record_length = decode_control_record_length(&input);
        let _membership_grant = MembershipGrantView::decode(&input);
        let _network_policy = NetworkPolicy::decode(&input);
        let _version_list = VersionListView::decode(&input);
        let _endpoint_set = EndpointSetView::decode(&input);
        let _network_revisions = NetworkRevisionListView::decode(&input);
        let _peer_record = PeerRecordView::decode(&input);
        let _peer_list = PeerListView::decode(&input);
        let _candidate = IceCandidate::decode(&input);
        let _connectivity_generation = ConnectivityGenerationView::decode(&input);
        let _connectivity_record = ConnectivityRecordView::decode(&input);
        let _connectivity_list = ConnectivityListView::decode(&input);
        let _stun_servers = StunServerListView::decode(&input);
        let _relay_service = RelayServiceView::decode(&input);
        let _relay_services = RelayServiceListView::decode(&input);
        let _stun_message = StunMessageView::decode(&input);
        let _turn_channel_datagram = TurnChannelDataView::decode_datagram(&input);
        let _turn_channel_stream = TurnChannelDataView::decode_stream(&input);
        let _turn_stream_length = decode_turn_stream_record_length(&input);
        if let Ok(fields) = ControlFieldIter::decode(&input) { for field in fields { let _ = field; } }
        if let Ok(view) = ControlMessageView::decode(&input) { for field in view.fields() { let _ = field; } }
        if let Ok(view) = StunMessageView::decode(&input) { for attribute in view.attributes() { let _ = attribute; } }
        if let Ok(view) = PeerListView::decode(&input) { for peer in view.peers() { let _ = peer; } }
        if let Ok(view) = EndpointSetView::decode(&input) { for endpoint in view.endpoints() { let _ = endpoint; } }
        if let Ok(view) = ConnectivityGenerationView::decode(&input) { for candidate in view.candidates() { let _ = candidate; } }
        if let Ok(view) = ConnectivityListView::decode(&input) { for record in view.records() { let _ = record; } }
        if let Ok(view) = RelayServiceListView::decode(&input) { for service in view.services() { let _ = service; } }
        if let Ok(view) = StunServerListView::decode(&input) { for server in view.servers() { let _ = server; } }
    }

    #[test]
    fn session_confirm_encode_decode_is_symmetric(
        network_id in any::<[u8; 16]>(),
        sender_node_id in any::<[u8; 16]>(),
        receiver_node_id in any::<[u8; 16]>(),
        controller_epoch in 1_u64..=u64::MAX,
        handshake_id in 1_u64..=u64::MAX,
        timestamp in any::<u64>(),
        session_id in 1_u64..=u64::MAX,
        response_hash in any::<[u8; 32]>(),
        tag in any::<[u8; 16]>(),
        responder in any::<bool>(),
    ) {
        let role = if responder {
            SessionConfirmRole::Responder
        } else {
            SessionConfirmRole::Initiator
        };
        let flags = if responder {
            SESSION_CONFIRM_RESPONDER_FLAG
        } else {
            0
        };
        let header = handshake_header(
            PacketType::SessionConfirm,
            flags,
            SESSION_CONFIRM_PAYLOAD_LENGTH,
            HeaderFields {
                network_id,
                sender_node_id,
                receiver_node_id,
                controller_epoch,
                handshake_id,
                timestamp,
                session_id,
            },
        );
        let payload = SessionConfirmRef {
            response_hash: &response_hash,
            role,
            confirmation_tag: &tag,
        };
        let mut encoded = [0_u8; HANDSHAKE_FIXED_HEADER_LENGTH + SESSION_CONFIRM_PAYLOAD_LENGTH];

        let length = encode_session_confirm(header, &[], payload, &mut encoded)
            .expect("generated confirmation is valid");
        prop_assert_eq!(length, encoded.len());
        let decoded = SessionConfirmView::decode(&encoded)
            .expect("encoded confirmation must decode");
        prop_assert_eq!(decoded.header(), header);
        prop_assert_eq!(decoded.response_hash(), &response_hash);
        prop_assert_eq!(decoded.role(), role);
        prop_assert_eq!(decoded.confirmation_tag(), &tag);
        prop_assert_eq!(decoded.datagram(), encoded);
        // Valid seeds exercise deep checks that arbitrary magic bytes rarely reach.
        for length in 0..encoded.len() {
            prop_assert!(SessionConfirmView::decode(&encoded[..length]).is_err());
        }
        for offset in [2, 3, 7, 8, 9, 10, 11, 129, 130, 131, 132, 133, 134, 135] {
            let mut invalid = encoded;
            invalid[offset] ^= 0x80;
            prop_assert!(SessionConfirmView::decode(&invalid).is_err());
        }
    }

    #[test]
    fn session_reject_encode_decode_is_symmetric(
        network_id in any::<[u8; 16]>(),
        sender_node_id in any::<[u8; 16]>(),
        receiver_node_id in any::<[u8; 16]>(),
        controller_epoch in 1_u64..=u64::MAX,
        handshake_id in 1_u64..=u64::MAX,
        timestamp in any::<u64>(),
        session_id in 1_u64..=u64::MAX,
        raw_reason in 1_u16..=u16::MAX,
        retry_after_ms in prop_oneof![Just(0_u32), 100_u32..=60_000],
        init_hash in any::<[u8; 32]>(),
        signature in any::<[u8; 64]>(),
    ) {
        let reason = SessionRejectReason::try_from(raw_reason)
            .expect("non-zero rejection reason is representable");
        let header = handshake_header(
            PacketType::SessionReject,
            0,
            SESSION_REJECT_PAYLOAD_LENGTH,
            HeaderFields {
                network_id,
                sender_node_id,
                receiver_node_id,
                controller_epoch,
                handshake_id,
                timestamp,
                session_id,
            },
        );
        let payload = SessionRejectRef {
            reason,
            retry_after_ms,
            init_hash: &init_hash,
            signature: &signature,
        };
        let mut encoded = [0_u8; HANDSHAKE_FIXED_HEADER_LENGTH + SESSION_REJECT_PAYLOAD_LENGTH];

        let length = encode_session_reject(header, &[], payload, &mut encoded)
            .expect("generated rejection is valid");
        prop_assert_eq!(length, encoded.len());
        let decoded = SessionRejectView::decode(&encoded)
            .expect("encoded rejection must decode");
        prop_assert_eq!(decoded.header(), header);
        prop_assert_eq!(decoded.reason().as_u16(), raw_reason);
        prop_assert_eq!(decoded.retry_after_ms(), retry_after_ms);
        prop_assert_eq!(decoded.init_hash(), &init_hash);
        prop_assert_eq!(decoded.signature(), &signature);
        prop_assert_eq!(decoded.datagram(), encoded);
    }

    #[test]
    fn network_policy_encode_decode_is_symmetric(
        encrypted in any::<bool>(),
        max_frame_size in any::<u16>(),
        max_flood_peers in any::<u16>(),
        flood_rate in any::<u32>(),
        flood_burst in any::<u32>(),
        mac_age_seconds in any::<u32>(),
        heartbeat_seconds in any::<u16>(),
        peer_lease_seconds in any::<u16>(),
        session_lifetime_seconds in any::<u32>(),
        reassembly_timeout_ms in any::<u32>(),
        network_id in any::<[u8; 16]>(),
        policy_revision in any::<u64>(),
    ) {
        let policy = clamped_policy(
            encrypted,
            max_frame_size,
            max_flood_peers,
            flood_rate,
            flood_burst,
            mac_age_seconds,
            heartbeat_seconds,
            peer_lease_seconds,
            session_lifetime_seconds,
            reassembly_timeout_ms,
            network_id,
            policy_revision,
        );
        let mut encoded = [0_u8; 64];
        policy.encode(&mut encoded).expect("clamped policy encodes");
        let decoded =
            NetworkPolicy::decode(&encoded).expect("encoded policy must decode");
        prop_assert_eq!(decoded, policy);
        for length in 0..encoded.len() {
            prop_assert!(NetworkPolicy::decode(&encoded[..length]).is_err());
        }
    }

    #[test]
    fn endpoint_set_encode_decode_is_symmetric(
        endpoints in prop::collection::vec(
            (
                any::<bool>(),
                any::<u8>(),
                any::<u8>(),
                any::<u32>(),
                any::<[u8; 16]>(),
            ),
            0..=8
        ),
    ) {
        let mut endpoints: Vec<Endpoint> = endpoints
            .into_iter()
            .enumerate()
            .map(|(index, (v6, _priority, port, datagram_size, address))| {
                generated_endpoint(
                    v6,
                    u8::try_from(index).unwrap_or(0),
                    port,
                    datagram_size,
                    address,
                )
            })
            .collect();
        endpoints.sort_by_key(|endpoint| (endpoint.priority(), endpoint.kind(), endpoint.port()));
        endpoints
            .dedup_by_key(|endpoint| (endpoint.priority(), endpoint.kind(), endpoint.port()));
        let mut encoded = [0_u8; 4 + 8 * 28];
        let length =
            encode_endpoint_set(&endpoints, &mut encoded).expect("sorted endpoints encode");
        let decoded = EndpointSetView::decode(&encoded[..length])
            .expect("encoded endpoint set must decode");
        prop_assert_eq!(decoded.endpoints().count(), endpoints.len());
        for (decoded_endpoint, endpoint) in decoded.endpoints().zip(endpoints.iter().copied()) {
            prop_assert_eq!(decoded_endpoint, endpoint);
        }
        for prefix in 0..length {
            prop_assert!(EndpointSetView::decode(&encoded[..prefix]).is_err());
        }
    }

    #[test]
    fn stun_server_list_encode_decode_is_symmetric(
        servers in prop::collection::vec(
            (any::<bool>(), any::<u8>(), any::<u8>(), any::<[u8; 16]>()),
            1..=8
        ),
    ) {
        let mut servers: Vec<StunServer> = servers
            .into_iter()
            .enumerate()
            .map(|(index, (v6, _priority, port, address))| {
                let port = u16::from(port).max(1);
                let address = if v6 {
                    let candidate = Ipv6Addr::from(address);
                    if candidate.is_multicast()
                        || candidate.is_unicast_link_local()
                        || candidate.is_loopback()
                        || candidate.is_unspecified()
                        || candidate.to_ipv4_mapped().is_some()
                    {
                        SocketAddr::new(
                            std::net::IpAddr::V6(Ipv6Addr::from([
                                0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1,
                            ])),
                            port,
                        )
                    } else {
                        SocketAddr::new(std::net::IpAddr::V6(candidate), port)
                    }
                } else {
                    // STUN addresses additionally reject loopback, so every
                    // generated IPv4 address maps into the TEST-NET-1 block.
                    let mut last = address[3] & 0x7f;
                    if last == 0 {
                        last = 1;
                    }
                    SocketAddr::new(
                        std::net::IpAddr::V4(Ipv4Addr::new(192, 0, 2, last)),
                        port,
                    )
                };
                StunServer {
                    priority: u8::try_from(index).unwrap_or(0),
                    address,
                }
            })
            .collect();
        let mut encoded = [0_u8; 4 + 8 * STUN_SERVER_RECORD_LENGTH];
        let length =
            encode_stun_server_list(&servers, &mut encoded).expect("sorted servers encode");
        let decoded = StunServerListView::decode(&encoded[..length])
            .expect("encoded STUN server list must decode");
        prop_assert_eq!(decoded.servers().count(), servers.len());
        for (decoded_server, server) in decoded.servers().zip(servers.iter().copied()) {
            prop_assert_eq!(decoded_server, server);
        }
        for prefix in 0..length {
            prop_assert!(StunServerListView::decode(&encoded[..prefix]).is_err());
        }
    }
}

/// Random valid policy values clamped into their protocol ranges.
#[allow(clippy::too_many_arguments)]
fn clamped_policy(
    encrypted: bool,
    max_frame_size: u16,
    max_flood_peers: u16,
    flood_rate: u32,
    flood_burst: u32,
    mac_age_seconds: u32,
    heartbeat_seconds: u16,
    peer_lease_seconds: u16,
    session_lifetime_seconds: u32,
    reassembly_timeout_ms: u32,
    network_id: [u8; 16],
    policy_revision: u64,
) -> NetworkPolicy {
    let heartbeat_seconds = heartbeat_seconds.clamp(5, 300);
    let minimum_lease = heartbeat_seconds.saturating_mul(3).clamp(5, 900);
    let flood_rate = flood_rate.clamp(1, 1_000_000);
    NetworkPolicy {
        confidentiality: if encrypted {
            stella_proto::ConfidentialityPolicy::Encrypt
        } else {
            stella_proto::ConfidentialityPolicy::AuthenticateOnly
        },
        max_frame_size: max_frame_size.clamp(1_514, 9_216),
        max_flood_peers: max_flood_peers.clamp(2, 256),
        flood_rate,
        flood_burst: flood_burst.clamp(flood_rate, 2_000_000),
        mac_age_seconds: mac_age_seconds.clamp(30, 3_600),
        heartbeat_seconds,
        peer_lease_seconds: peer_lease_seconds.clamp(minimum_lease, 900),
        session_lifetime_seconds: session_lifetime_seconds.clamp(60, 3_600),
        reassembly_timeout_ms: reassembly_timeout_ms.clamp(500, 10_000),
        network_id: NetworkId::from_bytes(if network_id.iter().all(|byte| *byte == 0) {
            [1; 16]
        } else {
            network_id
        }),
        policy_revision: policy_revision.max(1),
    }
}

/// Builds one valid endpoint from arbitrary generator bytes.
fn generated_endpoint(
    v6: bool,
    priority: u8,
    port: u8,
    datagram_size: u32,
    address: [u8; 16],
) -> Endpoint {
    let datagram_size = datagram_size.clamp(MIN_ENDPOINT_DATAGRAM_SIZE, MAX_ENDPOINT_DATAGRAM_SIZE);
    if v6 {
        let candidate = Ipv6Addr::from(address);
        let address = if candidate.is_multicast()
            || candidate.is_unspecified()
            || candidate.to_ipv4_mapped().is_some()
        {
            Ipv6Addr::from([0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1])
        } else {
            candidate
        };
        Endpoint::UdpIpv6 {
            priority,
            port: u16::from(port).max(1),
            max_datagram_size: datagram_size,
            address,
        }
    } else {
        let mut octets = [address[0], address[1], address[2], address[3]];
        // Keep the first octet in the IPv4 unicast range and clear the
        // unspecified and broadcast forms.
        octets[0] &= 0x7f;
        if octets == [0, 0, 0, 0] {
            octets = [1, 0, 0, 0];
        }
        if octets == [255, 255, 255, 255] {
            octets = [255, 255, 255, 254];
        }
        Endpoint::UdpIpv4 {
            priority,
            port: u16::from(port).max(1),
            max_datagram_size: datagram_size,
            address: Ipv4Addr::from(octets),
        }
    }
}
