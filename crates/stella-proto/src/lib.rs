//! Pure parsing and serialization support for the Stella wire protocol.

#![forbid(unsafe_code)]

mod common;
mod cursor;
mod error;
mod extension;

pub use common::{
    CommonHeader, PacketType, ProtocolVersion, COMMON_HEADER_LENGTH, MAGIC, MAX_HEADER_LENGTH,
    PROTOCOL_MAJOR, PROTOCOL_MINOR,
};
pub use error::CodecError;
pub use extension::{encode_extensions, extensions_encoded_len, ExtensionIter, ExtensionRef};
