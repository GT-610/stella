//! Pure parsing and serialization support for the Stella wire protocol.

#![forbid(unsafe_code)]

mod common;
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

pub use common::{
    CommonHeader, PacketType, ProtocolVersion, COMMON_HEADER_LENGTH, MAGIC, MAX_HEADER_LENGTH,
    PROTOCOL_MAJOR, PROTOCOL_MINOR,
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
    encode_session_init, encode_session_response, HandshakeHeader, SessionInitRef, SessionInitView,
    SessionResponseRef, SessionResponseView, HANDSHAKE_FIXED_HEADER_LENGTH, HANDSHAKE_NONCE_LENGTH,
    SESSION_INIT_PAYLOAD_LENGTH, SESSION_INIT_SIGNATURE_DOMAIN, SESSION_INIT_SIGNED_PAYLOAD_LENGTH,
    SESSION_RESPONSE_PAYLOAD_LENGTH, SESSION_RESPONSE_SIGNATURE_DOMAIN,
    SESSION_RESPONSE_SIGNED_PAYLOAD_LENGTH, SHA256_DIGEST_LENGTH, X25519_PUBLIC_KEY_LENGTH,
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
