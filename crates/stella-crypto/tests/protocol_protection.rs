//! End-to-end protocol-codec and peer-session protection tests.

use stella_common::{MacAddress, NetworkId, NodeId};
use stella_crypto::{
    derive_session_secrets, session_transcript_hash, CryptoError, EphemeralPublicKey,
    EphemeralSecret, ReplayWindow, SessionProtectors, SessionRole, AUTHENTICATION_TAG_LENGTH,
};
use stella_proto::{
    encode_data_packet, encode_keepalive_packet, encode_session_confirm, CommonHeader, DataHeader,
    DataPacketView, ExtensionRef, HandshakeHeader, KeepaliveHeader, KeepalivePacketView,
    PacketType, ProtocolVersion, SessionConfirmRef, SessionConfirmRole, SessionConfirmView,
    DATA_ENCRYPTED_FLAG, DATA_FIXED_HEADER_LENGTH, HANDSHAKE_FIXED_HEADER_LENGTH,
    KEEPALIVE_FIXED_HEADER_LENGTH, SESSION_CONFIRM_PAYLOAD_LENGTH, SESSION_CONFIRM_RESPONDER_FLAG,
};

const NETWORK_ID: NetworkId = NetworkId::from_bytes([0x10; 16]);
const INITIATOR_ID: NodeId = NodeId::from_bytes([0x20; 16]);
const RESPONDER_ID: NodeId = NodeId::from_bytes([0x30; 16]);
const ALICE_SECRET: [u8; 32] = [
    0x77, 0x07, 0x6d, 0x0a, 0x73, 0x18, 0xa5, 0x7d, 0x3c, 0x16, 0xc1, 0x72, 0x51, 0xb2, 0x66, 0x45,
    0xdf, 0x4c, 0x2f, 0x87, 0xeb, 0xc0, 0x99, 0x2a, 0xb1, 0x77, 0xfb, 0xa5, 0x1d, 0xb9, 0x2c, 0x2a,
];
const ALICE_PUBLIC: [u8; 32] = [
    0x85, 0x20, 0xf0, 0x09, 0x89, 0x30, 0xa7, 0x54, 0x74, 0x8b, 0x7d, 0xdc, 0xb4, 0x3e, 0xf7, 0x5a,
    0x0d, 0xbf, 0x3a, 0x0d, 0x26, 0x38, 0x1a, 0xf4, 0xeb, 0xa4, 0xa9, 0x8e, 0xaa, 0x9b, 0x4e, 0x6a,
];
const BOB_SECRET: [u8; 32] = [
    0x5d, 0xab, 0x08, 0x7e, 0x62, 0x4a, 0x8a, 0x4b, 0x79, 0xe1, 0x7f, 0x8b, 0x83, 0x80, 0x0e, 0xe6,
    0x6f, 0x3b, 0xb1, 0x29, 0x26, 0x18, 0xb6, 0xfd, 0x1c, 0x2f, 0x8b, 0x27, 0xff, 0x88, 0xe0, 0xeb,
];
const BOB_PUBLIC: [u8; 32] = [
    0xde, 0x9e, 0xdb, 0x7d, 0x7b, 0x7d, 0xc1, 0xb4, 0xd3, 0x5b, 0x61, 0xc2, 0xec, 0xe4, 0x35, 0x37,
    0x3f, 0x83, 0x43, 0xc8, 0x5b, 0x78, 0x67, 0x4d, 0xad, 0xfc, 0x7e, 0x14, 0x6f, 0x88, 0x2b, 0x4f,
];
const FRAME: [u8; 14] = [
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x02, 0x21, 0x22, 0x23, 0x24, 0x25, 0x08, 0x00,
];

#[test]
fn protocol_datagrams_use_exact_crypto_ranges_and_shared_replay_state() {
    let transcript_hash =
        session_transcript_hash(b"encoded SESSION_INIT", b"encoded SESSION_RESPONSE");
    let (initiator, responder) = session_protectors(&transcript_hash);
    let mut replay = ReplayWindow::new();

    protect_encrypted_data(&initiator, &responder, &mut replay);
    protect_authenticate_only_data(&initiator, &responder, &mut replay);
    protect_keepalive(&initiator, &responder, &mut replay);
    protect_confirmations(&initiator, &responder, &transcript_hash);
}

fn session_protectors(transcript_hash: &[u8; 32]) -> (SessionProtectors, SessionProtectors) {
    let initiator_shared = EphemeralSecret::from_bytes(ALICE_SECRET)
        .agree(EphemeralPublicKey::from_bytes(BOB_PUBLIC))
        .expect("contributory fixed agreement");
    let responder_shared = EphemeralSecret::from_bytes(BOB_SECRET)
        .agree(EphemeralPublicKey::from_bytes(ALICE_PUBLIC))
        .expect("contributory fixed agreement");
    let initiator =
        derive_session_secrets(initiator_shared, transcript_hash, SessionRole::Initiator)
            .expect("fixed-size HKDF outputs")
            .into_protectors();
    let responder =
        derive_session_secrets(responder_shared, transcript_hash, SessionRole::Responder)
            .expect("fixed-size HKDF outputs")
            .into_protectors();
    (initiator, responder)
}

fn protect_encrypted_data(
    initiator: &SessionProtectors,
    responder: &SessionProtectors,
    replay: &mut ReplayWindow,
) {
    let extension = ExtensionRef::new(1, &[0xaa]).expect("valid non-critical extension");
    let header = data_header(1, 11, DATA_ENCRYPTED_FLAG, 112);
    let encoded_length =
        usize::from(header.common.header_length) + FRAME.len() + AUTHENTICATION_TAG_LENGTH;
    let mut draft = vec![0_u8; encoded_length];
    encode_data_packet(header, &[extension], &FRAME, &[0; 16], &mut draft)
        .expect("valid encrypted DATA draft");
    let draft_view = DataPacketView::decode(&draft).expect("valid encrypted DATA draft view");

    let mut ciphertext = [0_u8; FRAME.len()];
    let tag = initiator
        .send()
        .seal_encrypted(
            header.sequence_number,
            draft_view.authenticated_header(),
            &FRAME,
            &mut ciphertext,
        )
        .expect("bounded encrypted DATA packet");
    let mut encoded = vec![0_u8; encoded_length];
    encode_data_packet(header, &[extension], &ciphertext, &tag, &mut encoded)
        .expect("valid protected encrypted DATA packet");

    let packet = DataPacketView::decode(&encoded).expect("valid protected DATA view");
    assert_eq!(
        packet.authenticated_header(),
        draft_view.authenticated_header()
    );
    assert_eq!(replay.precheck(packet.header().sequence_number), Ok(()));
    let mut plaintext = [0x5a; FRAME.len()];
    assert_eq!(
        responder.receive().open_encrypted(
            packet.header().sequence_number,
            packet.authenticated_header(),
            packet.fragment(),
            packet.tag(),
            &mut plaintext,
        ),
        Ok(FRAME.len())
    );
    assert_eq!(plaintext, FRAME);
    assert_eq!(
        packet.header().validate_authenticated_frame(&plaintext),
        Ok(())
    );
    assert_eq!(replay.commit(packet.header().sequence_number), Ok(()));
}

fn protect_authenticate_only_data(
    initiator: &SessionProtectors,
    responder: &SessionProtectors,
    replay: &mut ReplayWindow,
) {
    let header = data_header(
        2,
        12,
        0,
        u16::try_from(DATA_FIXED_HEADER_LENGTH).expect("DATA header length fits u16"),
    );
    let encoded_length = DATA_FIXED_HEADER_LENGTH + FRAME.len() + AUTHENTICATION_TAG_LENGTH;
    let mut draft = vec![0_u8; encoded_length];
    encode_data_packet(header, &[], &FRAME, &[0; 16], &mut draft)
        .expect("valid authenticate-only DATA draft");
    let draft_view = DataPacketView::decode(&draft).expect("valid authenticate-only DATA view");
    let tag = initiator
        .send()
        .authenticate_only(
            header.sequence_number,
            draft_view.authenticated_header(),
            draft_view.fragment(),
        )
        .expect("bounded authenticate-only DATA packet");
    let mut encoded = vec![0_u8; encoded_length];
    encode_data_packet(header, &[], &FRAME, &tag, &mut encoded)
        .expect("valid protected authenticate-only DATA packet");

    let packet = DataPacketView::decode(&encoded).expect("valid authenticate-only DATA view");
    assert_eq!(replay.precheck(packet.header().sequence_number), Ok(()));
    assert_eq!(
        responder.receive().verify_authenticate_only(
            packet.header().sequence_number,
            packet.authenticated_header(),
            packet.fragment(),
            packet.tag(),
        ),
        Ok(())
    );
    assert_eq!(packet.fragment(), FRAME);
    assert_eq!(replay.commit(packet.header().sequence_number), Ok(()));
}

fn protect_keepalive(
    initiator: &SessionProtectors,
    responder: &SessionProtectors,
    replay: &mut ReplayWindow,
) {
    let header = KeepaliveHeader {
        common: common_header(
            PacketType::Keepalive,
            0,
            u16::try_from(KEEPALIVE_FIXED_HEADER_LENGTH).expect("KEEPALIVE header length fits u16"),
            0,
        ),
        sender_node_id: INITIATOR_ID,
        session_id: 7,
        sequence_number: 3,
        controller_epoch: 9,
        probe_id: 3,
        echo_probe_id: 2,
    };
    let encoded_length = KEEPALIVE_FIXED_HEADER_LENGTH + AUTHENTICATION_TAG_LENGTH;
    let mut draft = vec![0_u8; encoded_length];
    encode_keepalive_packet(header, &[], &[0; 16], &mut draft).expect("valid KEEPALIVE draft");
    let draft_view = KeepalivePacketView::decode(&draft).expect("valid KEEPALIVE draft view");
    let tag = initiator
        .send()
        .authenticate_header(header.sequence_number, draft_view.authenticated_header())
        .expect("bounded KEEPALIVE header");
    let mut encoded = vec![0_u8; encoded_length];
    encode_keepalive_packet(header, &[], &tag, &mut encoded).expect("valid protected KEEPALIVE");

    let packet = KeepalivePacketView::decode(&encoded).expect("valid protected KEEPALIVE view");
    assert_eq!(replay.precheck(packet.header().sequence_number), Ok(()));
    assert_eq!(
        responder.receive().verify_header(
            packet.header().sequence_number,
            packet.authenticated_header(),
            packet.tag(),
        ),
        Ok(())
    );
    assert_eq!(replay.commit(packet.header().sequence_number), Ok(()));
    assert_eq!(
        replay.precheck(2),
        Err(CryptoError::DuplicateSequenceNumber { sequence_number: 2 })
    );
}

fn protect_confirmations(
    initiator: &SessionProtectors,
    responder: &SessionProtectors,
    transcript_hash: &[u8; 32],
) {
    let response_hash = [0x71; 32];
    let initiator_header =
        confirmation_header(INITIATOR_ID, RESPONDER_ID, SessionConfirmRole::Initiator);
    let initiator_tag = confirmation_tag(
        initiator.local_confirmation(),
        transcript_hash,
        initiator_header,
        &response_hash,
        SessionConfirmRole::Initiator,
    );
    let initiator_datagram = encode_confirmation(
        initiator_header,
        &response_hash,
        SessionConfirmRole::Initiator,
        &initiator_tag,
    );
    let initiator_view =
        SessionConfirmView::decode(&initiator_datagram).expect("valid initiator confirmation");
    assert_eq!(
        responder.remote_confirmation().verify_tag(
            transcript_hash,
            initiator_view.authenticated_header(),
            initiator_view.authenticated_payload(),
            initiator_view.confirmation_tag(),
        ),
        Ok(())
    );

    let responder_header =
        confirmation_header(RESPONDER_ID, INITIATOR_ID, SessionConfirmRole::Responder);
    let responder_tag = confirmation_tag(
        responder.local_confirmation(),
        transcript_hash,
        responder_header,
        &response_hash,
        SessionConfirmRole::Responder,
    );
    let responder_datagram = encode_confirmation(
        responder_header,
        &response_hash,
        SessionConfirmRole::Responder,
        &responder_tag,
    );
    let responder_view =
        SessionConfirmView::decode(&responder_datagram).expect("valid responder confirmation");
    assert_eq!(
        initiator.remote_confirmation().verify_tag(
            transcript_hash,
            responder_view.authenticated_header(),
            responder_view.authenticated_payload(),
            responder_view.confirmation_tag(),
        ),
        Ok(())
    );
}

fn confirmation_tag(
    authenticator: &stella_crypto::ConfirmationAuthenticator,
    transcript_hash: &[u8; 32],
    header: HandshakeHeader,
    response_hash: &[u8; 32],
    role: SessionConfirmRole,
) -> [u8; 16] {
    let draft = encode_confirmation(header, response_hash, role, &[0; 16]);
    let view = SessionConfirmView::decode(&draft).expect("valid confirmation draft");
    authenticator
        .create_tag(
            transcript_hash,
            view.authenticated_header(),
            view.authenticated_payload(),
        )
        .expect("bounded confirmation associated data")
}

fn encode_confirmation(
    header: HandshakeHeader,
    response_hash: &[u8; 32],
    role: SessionConfirmRole,
    tag: &[u8; 16],
) -> Vec<u8> {
    let mut encoded = vec![0_u8; HANDSHAKE_FIXED_HEADER_LENGTH + SESSION_CONFIRM_PAYLOAD_LENGTH];
    encode_session_confirm(
        header,
        &[],
        SessionConfirmRef {
            response_hash,
            role,
            confirmation_tag: tag,
        },
        &mut encoded,
    )
    .expect("valid SESSION_CONFIRM");
    encoded
}

fn data_header(sequence_number: u64, frame_id: u64, flags: u8, header_length: u16) -> DataHeader {
    DataHeader {
        common: common_header(
            PacketType::Data,
            flags,
            header_length,
            u32::try_from(FRAME.len()).expect("test frame length fits u32"),
        ),
        sender_node_id: INITIATOR_ID,
        session_id: 7,
        sequence_number,
        controller_epoch: 9,
        frame_id,
        frame_length: u16::try_from(FRAME.len()).expect("test frame length fits u16"),
        fragment_offset: 0,
        fragment_length: u16::try_from(FRAME.len()).expect("test fragment length fits u16"),
        source_mac: MacAddress::from_bytes([0x02, 0x21, 0x22, 0x23, 0x24, 0x25]),
        destination_mac: MacAddress::from_bytes([0x10, 0x11, 0x12, 0x13, 0x14, 0x15]),
        outer_ether_type: 0x0800,
    }
}

fn confirmation_header(
    sender_node_id: NodeId,
    receiver_node_id: NodeId,
    role: SessionConfirmRole,
) -> HandshakeHeader {
    let flags = match role {
        SessionConfirmRole::Initiator => 0,
        SessionConfirmRole::Responder => SESSION_CONFIRM_RESPONDER_FLAG,
    };
    HandshakeHeader {
        common: common_header(
            PacketType::SessionConfirm,
            flags,
            u16::try_from(HANDSHAKE_FIXED_HEADER_LENGTH).expect("handshake header length fits u16"),
            u32::try_from(SESSION_CONFIRM_PAYLOAD_LENGTH)
                .expect("confirmation payload length fits u32"),
        ),
        sender_node_id,
        receiver_node_id,
        controller_epoch: 9,
        handshake_id: 5,
        timestamp: 1_800_000_000,
        session_id: 7,
    }
}

const fn common_header(
    packet_type: PacketType,
    flags: u8,
    header_length: u16,
    payload_length: u32,
) -> CommonHeader {
    CommonHeader {
        version: ProtocolVersion::CURRENT,
        packet_type,
        flags,
        header_length,
        payload_length,
        network_id: NETWORK_ID,
    }
}
