//! Pure parsing and serialization support for the Stella wire protocol.

#![forbid(unsafe_code)]

mod common;
mod cursor;
mod data;
mod error;
mod extension;
mod keepalive;

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
pub use keepalive::{
    encode_keepalive_packet, KeepaliveHeader, KeepalivePacketView, KEEPALIVE_FIXED_HEADER_LENGTH,
};
