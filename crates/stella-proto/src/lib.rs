//! Pure parsing and serialization support for the Stella wire protocol.

#![forbid(unsafe_code)]

mod common;
mod cursor;
mod data;
mod error;
mod extension;
mod grant;
mod keepalive;
mod policy;

pub use common::{
    CommonHeader, PacketType, ProtocolVersion, COMMON_HEADER_LENGTH, MAGIC, MAX_HEADER_LENGTH,
    PROTOCOL_MAJOR, PROTOCOL_MINOR,
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
pub use keepalive::{
    encode_keepalive_packet, KeepaliveHeader, KeepalivePacketView, KEEPALIVE_FIXED_HEADER_LENGTH,
};
pub use policy::{
    ConfidentialityPolicy, NetworkPolicy, NETWORK_POLICY_FORMAT_VERSION, NETWORK_POLICY_LENGTH,
    NETWORK_POLICY_MAGIC,
};
