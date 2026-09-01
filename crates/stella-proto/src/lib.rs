//! Pure parsing and serialization support for the Stella wire protocol.

#![forbid(unsafe_code)]

mod common;
mod connectivity;
mod control;
mod cursor;
mod data;
mod error;
mod extension;
mod grant;
mod handshake;
mod keepalive;
mod nested;
mod peer;
mod policy;
mod relay;
mod turn;

pub use common::{
    CommonHeader, PacketType, ProtocolVersion, COMMON_HEADER_LENGTH, MAGIC, MAX_HEADER_LENGTH,
    PROTOCOL_MAJOR, PROTOCOL_MINOR,
};
pub use connectivity::{
    encode_connectivity_generation, encode_connectivity_list,
    encode_connectivity_list_from_encoded_records, encode_connectivity_record,
    encode_stun_server_list, ConnectivityCarrier, ConnectivityGenerationRef,
    ConnectivityGenerationView, ConnectivityListView, ConnectivityRecordIter,
    ConnectivityRecordRef, ConnectivityRecordView, IceCandidate, IceCandidateClass,
    IceCandidateIter, StunServer, StunServerIter, StunServerListView,
    CONNECTIVITY_GENERATION_FORMAT_VERSION, CONNECTIVITY_GENERATION_HEADER_LENGTH,
    CONNECTIVITY_GENERATION_MAGIC, CONNECTIVITY_RECORD_FIXED_LENGTH, ICE_CANDIDATE_RECORD_LENGTH,
    MAX_CONNECTIVITY_GENERATION_LIFETIME_SECONDS, MAX_CONNECTIVITY_RECORDS, MAX_ICE_CANDIDATES,
    MAX_ICE_PASSWORD_LENGTH, MAX_ICE_USERNAME_FRAGMENT_LENGTH, MAX_STUN_SERVERS,
    MIN_ICE_PASSWORD_LENGTH, MIN_ICE_USERNAME_FRAGMENT_LENGTH, STUN_SERVER_RECORD_LENGTH,
};
pub use control::{
    control_fields_encoded_len, decode_control_record_length, encode_control_fields,
    encode_control_message, encode_control_record_length, ControlFieldIter, ControlFieldRef,
    ControlFieldType, ControlHeader, ControlMessageType, ControlMessageView, CONTROL_HEADER_LENGTH,
    CONTROL_MAGIC, CONTROL_RECORD_PREFIX_LENGTH, MAX_CONTROL_RECORD_LENGTH,
};
pub use data::{
    encode_data_packet, DataHeader, DataPacketView, AUTHENTICATION_TAG_LENGTH, DATA_ENCRYPTED_FLAG,
    DATA_FIXED_HEADER_LENGTH, MAX_ETHERNET_FRAME_LENGTH, MIN_ETHERNET_FRAME_LENGTH,
};
pub use error::CodecError;
pub use extension::{encode_extensions, extensions_encoded_len, ExtensionIter, ExtensionRef};
pub use grant::{
    encode_membership_grant, MembershipGrant, MembershipGrantView, MembershipPermissions,
    ED25519_SIGNATURE_LENGTH, MAX_MEMBERSHIP_GRANT_LIFETIME_SECONDS,
    MEMBERSHIP_GRANT_FORMAT_VERSION, MEMBERSHIP_GRANT_LENGTH, MEMBERSHIP_GRANT_MAGIC,
    MEMBERSHIP_GRANT_SIGNATURE_DOMAIN, MEMBERSHIP_GRANT_SIGNED_BODY_LENGTH,
};
pub use handshake::{
    encode_session_confirm, encode_session_init, encode_session_reject, encode_session_response,
    HandshakeHeader, SessionConfirmRef, SessionConfirmRole, SessionConfirmView, SessionInitRef,
    SessionInitView, SessionRejectReason, SessionRejectRef, SessionRejectView, SessionResponseRef,
    SessionResponseView, HANDSHAKE_FIXED_HEADER_LENGTH, HANDSHAKE_NONCE_LENGTH,
    SESSION_CONFIRM_AUTHENTICATED_PAYLOAD_LENGTH, SESSION_CONFIRM_AUTHENTICATION_DOMAIN,
    SESSION_CONFIRM_PAYLOAD_LENGTH, SESSION_CONFIRM_RESPONDER_FLAG, SESSION_INIT_PAYLOAD_LENGTH,
    SESSION_INIT_SIGNATURE_DOMAIN, SESSION_INIT_SIGNED_PAYLOAD_LENGTH,
    SESSION_REJECT_PAYLOAD_LENGTH, SESSION_REJECT_SIGNATURE_DOMAIN,
    SESSION_REJECT_SIGNED_PAYLOAD_LENGTH, SESSION_RESPONSE_PAYLOAD_LENGTH,
    SESSION_RESPONSE_SIGNATURE_DOMAIN, SESSION_RESPONSE_SIGNED_PAYLOAD_LENGTH,
    SHA256_DIGEST_LENGTH, X25519_PUBLIC_KEY_LENGTH,
};
pub use keepalive::{
    encode_keepalive_packet, KeepaliveHeader, KeepalivePacketView, KEEPALIVE_FIXED_HEADER_LENGTH,
};
pub use nested::{
    encode_endpoint_set, encode_network_revision_list, encode_version_list, Endpoint, EndpointIter,
    EndpointSetView, NetworkRevision, NetworkRevisionIter, NetworkRevisionListView, VersionEntry,
    VersionIter, VersionListView, MAX_ENDPOINTS, MAX_ENDPOINT_DATAGRAM_SIZE, MAX_NETWORK_REVISIONS,
    MAX_SUPPORTED_VERSIONS, MIN_ENDPOINT_DATAGRAM_SIZE,
};
pub use peer::{
    encode_peer_list, encode_peer_record, PeerListIter, PeerListView, PeerRecordRef,
    PeerRecordView, MAX_PEER_LIST_ENTRIES, MAX_PEER_RECORD_LENGTH, PEER_RECORD_FIXED_LENGTH,
};
pub use policy::{
    ConfidentialityPolicy, NetworkPolicy, NETWORK_POLICY_FORMAT_VERSION, NETWORK_POLICY_LENGTH,
    NETWORK_POLICY_MAGIC,
};
pub use relay::{
    encode_relay_service, encode_relay_service_list, RelayAddress, RelayAddressIter,
    RelayCarrierMask, RelayPorts, RelayServiceIter, RelayServiceListView, RelayServiceRef,
    RelayServiceView, RelaySpkiPinIter, RelayTrustRequirements, MAX_RELAY_ADDRESSES,
    MAX_RELAY_CREDENTIAL_LIFETIME_SECONDS, MAX_RELAY_DNS_NAME_LENGTH, MAX_RELAY_REGION_LENGTH,
    MAX_RELAY_SECRET_LENGTH, MAX_RELAY_SERVICES, MAX_RELAY_SPKI_PINS, MAX_RELAY_USERNAME_LENGTH,
    MIN_RELAY_SECRET_LENGTH, RELAY_ADDRESS_RECORD_LENGTH, RELAY_SERVICE_HEADER_LENGTH,
};
pub use turn::{
    decode_stun_xor_address, decode_turn_stream_record_length, encode_stun_error_code,
    encode_stun_message, encode_stun_xor_address, encode_turn_channel_data,
    encode_turn_channel_data_stream, stun_attributes_encoded_len, StunAttributeIter,
    StunAttributeRef, StunAttributeType, StunAttributeView, StunClass, StunErrorCodeView,
    StunMessageIntegritySha256, StunMessageRef, StunMessageType, StunMessageView, StunMethod,
    StunPasswordAlgorithm, StunTransactionId, TurnChannelDataView, TurnChannelNumber,
    MAX_STUN_ERROR_REASON_LENGTH, MAX_STUN_MESSAGE_LENGTH, MAX_TURN_CHANNEL_NUMBER,
    MIN_TURN_CHANNEL_NUMBER, STUN_HEADER_LENGTH, STUN_MAGIC_COOKIE,
    STUN_MESSAGE_INTEGRITY_SHA256_LENGTH, STUN_XOR_IPV4_ADDRESS_LENGTH,
    STUN_XOR_IPV6_ADDRESS_LENGTH, TURN_CHANNEL_DATA_HEADER_LENGTH,
};
