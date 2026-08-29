//! Property tests for strict Stella codec bounds and round-trip symmetry.

use proptest::prelude::*;
use stella_common::{NetworkId, NodeId};
use stella_proto::{
    decode_control_record_length, encode_session_confirm, encode_session_reject, CommonHeader,
    ControlFieldIter, ControlHeader, ControlMessageView, DataHeader, DataPacketView,
    EndpointSetView, HandshakeHeader, KeepaliveHeader, KeepalivePacketView, MembershipGrantView,
    NetworkPolicy, NetworkRevisionListView, PacketType, PeerListView, PeerRecordView,
    ProtocolVersion, SessionConfirmRef, SessionConfirmRole, SessionConfirmView, SessionInitView,
    SessionRejectReason, SessionRejectRef, SessionRejectView, SessionResponseView, VersionListView,
    HANDSHAKE_FIXED_HEADER_LENGTH, SESSION_CONFIRM_PAYLOAD_LENGTH, SESSION_CONFIRM_RESPONDER_FLAG,
    SESSION_REJECT_PAYLOAD_LENGTH,
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
    fn arbitrary_codec_input_never_panics(input in prop::collection::vec(any::<u8>(), 0..2_049)) {
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
}
