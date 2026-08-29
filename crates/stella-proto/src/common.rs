//! Common Stella data-plane datagram header.

use stella_common::NetworkId;

use crate::{cursor::ReadCursor, cursor::WriteCursor, CodecError};

/// Four-byte magic at the beginning of every data-plane datagram.
pub const MAGIC: [u8; 4] = *b"STLA";

/// Encoded length of the common data-plane header.
pub const COMMON_HEADER_LENGTH: usize = 32;

/// Largest header accepted by protocol version 0.1.
pub const MAX_HEADER_LENGTH: usize = 1_024;

/// First protocol major version implemented by this workspace.
pub const PROTOCOL_MAJOR: u8 = 0;

/// First protocol minor version implemented by this workspace.
pub const PROTOCOL_MINOR: u8 = 1;

/// Protocol version advertised during negotiation.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct ProtocolVersion {
    /// Incompatible format generation.
    pub major: u8,
    /// Backward-compatible feature generation within one major version.
    pub minor: u8,
}

impl ProtocolVersion {
    /// Version implemented by this crate.
    pub const CURRENT: Self = Self {
        major: PROTOCOL_MAJOR,
        minor: PROTOCOL_MINOR,
    };
}

/// Registered version 0.1 data-plane packet type.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum PacketType {
    /// Protected Ethernet frame fragment.
    Data = 0x01,
    /// Authenticated liveness probe.
    Keepalive = 0x02,
    /// Peer session initiator message.
    SessionInit = 0x10,
    /// Peer session responder message.
    SessionResponse = 0x11,
    /// Peer session key confirmation.
    SessionConfirm = 0x12,
    /// Peer session rejection.
    SessionReject = 0x13,
}

impl PacketType {
    /// Returns the canonical packet type byte.
    #[must_use]
    pub const fn as_u8(self) -> u8 {
        self as u8
    }
}

impl TryFrom<u8> for PacketType {
    type Error = CodecError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0x01 => Ok(Self::Data),
            0x02 => Ok(Self::Keepalive),
            0x10 => Ok(Self::SessionInit),
            0x11 => Ok(Self::SessionResponse),
            0x12 => Ok(Self::SessionConfirm),
            0x13 => Ok(Self::SessionReject),
            _ => Err(CodecError::UnsupportedPacketType { value }),
        }
    }
}

/// Parsed 32-byte common data-plane header.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CommonHeader {
    /// Protocol version encoded by the datagram.
    pub version: ProtocolVersion,
    /// Type-specific packet layout.
    pub packet_type: PacketType,
    /// Type-specific flag bits.
    pub flags: u8,
    /// Entire header length including extensions.
    pub header_length: u16,
    /// Bytes after the header and before a type-specific trailer.
    pub payload_length: u32,
    /// Target virtual network.
    pub network_id: NetworkId,
}

impl CommonHeader {
    /// Decodes and validates a common header from the start of `input`.
    ///
    /// # Errors
    ///
    /// Returns [`CodecError`] when the input is truncated or contains an
    /// invalid magic, version, type, reserved field, or header length.
    pub fn decode(input: &[u8]) -> Result<Self, CodecError> {
        let mut cursor = ReadCursor::new(input, 0);
        let magic = cursor.read_array::<4>("magic")?;
        if magic != MAGIC {
            return Err(CodecError::InvalidMagic);
        }

        let version = ProtocolVersion {
            major: cursor.read_u8("version major")?,
            minor: cursor.read_u8("version minor")?,
        };
        if version != ProtocolVersion::CURRENT {
            return Err(CodecError::UnsupportedVersion {
                major: version.major,
                minor: version.minor,
            });
        }

        let packet_type = PacketType::try_from(cursor.read_u8("packet type")?)?;
        let flags = cursor.read_u8("flags")?;
        let header_length = cursor.read_u16("header length")?;
        let reserved_offset = cursor.position();
        let reserved = cursor.read_u16("common reserved")?;
        if reserved != 0 {
            return Err(CodecError::NonZeroReserved {
                field: "common reserved",
                offset: reserved_offset,
            });
        }
        let payload_length = cursor.read_u32("payload length")?;
        let network_id = NetworkId::from_bytes(cursor.read_array("network ID")?);

        let header = Self {
            version,
            packet_type,
            flags,
            header_length,
            payload_length,
            network_id,
        };
        header.validate()?;
        Ok(header)
    }

    /// Encodes the common header into exactly the first 32 bytes of `output`.
    ///
    /// # Errors
    ///
    /// Returns [`CodecError`] when the header is invalid or `output` is
    /// shorter than [`COMMON_HEADER_LENGTH`].
    pub fn encode(self, output: &mut [u8]) -> Result<(), CodecError> {
        self.validate()?;
        let mut cursor = WriteCursor::new(output, 0);
        cursor.write_bytes(&MAGIC, "magic")?;
        cursor.write_u8(self.version.major, "version major")?;
        cursor.write_u8(self.version.minor, "version minor")?;
        cursor.write_u8(self.packet_type.as_u8(), "packet type")?;
        cursor.write_u8(self.flags, "flags")?;
        cursor.write_u16(self.header_length, "header length")?;
        cursor.write_u16(0, "common reserved")?;
        cursor.write_u32(self.payload_length, "payload length")?;
        cursor.write_bytes(self.network_id.as_bytes(), "network ID")?;
        Ok(())
    }

    /// Validates version-independent common header invariants.
    ///
    /// # Errors
    ///
    /// Returns [`CodecError`] for an unsupported version or a header length
    /// outside the aligned version 0.1 bounds.
    pub fn validate(self) -> Result<(), CodecError> {
        if self.version != ProtocolVersion::CURRENT {
            return Err(CodecError::UnsupportedVersion {
                major: self.version.major,
                minor: self.version.minor,
            });
        }
        let header_length = usize::from(self.header_length);
        if header_length < COMMON_HEADER_LENGTH {
            return Err(CodecError::HeaderTooShort {
                actual: header_length,
                minimum: COMMON_HEADER_LENGTH,
            });
        }
        if header_length > MAX_HEADER_LENGTH {
            return Err(CodecError::HeaderTooLong {
                actual: header_length,
                maximum: MAX_HEADER_LENGTH,
            });
        }
        if header_length % 4 != 0 {
            return Err(CodecError::UnalignedHeaderLength {
                actual: header_length,
            });
        }
        Ok(())
    }

    /// Rejects flag bits outside `allowed` for this packet type.
    ///
    /// # Errors
    ///
    /// Returns [`CodecError::ReservedFlags`] when any disallowed bit is set.
    pub fn validate_flags(self, allowed: u8) -> Result<(), CodecError> {
        if self.flags & !allowed != 0 {
            return Err(CodecError::ReservedFlags {
                packet_type: self.packet_type.as_u8(),
                flags: self.flags,
                allowed,
            });
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use stella_common::NetworkId;

    use super::{
        CommonHeader, PacketType, ProtocolVersion, COMMON_HEADER_LENGTH, MAX_HEADER_LENGTH,
    };
    use crate::CodecError;

    fn header() -> CommonHeader {
        CommonHeader {
            version: ProtocolVersion::CURRENT,
            packet_type: PacketType::Data,
            flags: 1,
            header_length: 104,
            payload_length: 14,
            network_id: NetworkId::from_bytes([
                0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
            ]),
        }
    }

    #[test]
    fn common_header_matches_canonical_bytes() {
        let expected = [
            0x53, 0x54, 0x4c, 0x41, 0, 1, 1, 1, 0, 104, 0, 0, 0, 0, 0, 14, 0, 1, 2, 3, 4, 5, 6, 7,
            8, 9, 10, 11, 12, 13, 14, 15,
        ];
        let mut encoded = [0; COMMON_HEADER_LENGTH];

        assert_eq!(header().encode(&mut encoded), Ok(()));
        assert_eq!(encoded, expected);
        assert_eq!(CommonHeader::decode(&encoded), Ok(header()));
    }

    #[test]
    fn common_header_rejects_malformed_fields() {
        let mut encoded = [0; COMMON_HEADER_LENGTH];
        header().encode(&mut encoded).expect("valid common header");

        encoded[0] ^= 1;
        assert_eq!(
            CommonHeader::decode(&encoded),
            Err(CodecError::InvalidMagic)
        );
        encoded[0] ^= 1;

        encoded[5] = 2;
        assert_eq!(
            CommonHeader::decode(&encoded),
            Err(CodecError::UnsupportedVersion { major: 0, minor: 2 })
        );
        encoded[5] = 1;

        encoded[6] = 3;
        assert_eq!(
            CommonHeader::decode(&encoded),
            Err(CodecError::UnsupportedPacketType { value: 3 })
        );
        encoded[6] = 1;

        encoded[10] = 1;
        assert_eq!(
            CommonHeader::decode(&encoded),
            Err(CodecError::NonZeroReserved {
                field: "common reserved",
                offset: 10,
            })
        );
    }

    #[test]
    fn common_header_validates_length_alignment_flags_and_output() {
        let mut candidate = header();
        candidate.header_length =
            u16::try_from(COMMON_HEADER_LENGTH - 4).expect("common header length fits u16");
        assert_eq!(
            candidate.validate(),
            Err(CodecError::HeaderTooShort {
                actual: COMMON_HEADER_LENGTH - 4,
                minimum: COMMON_HEADER_LENGTH,
            })
        );

        candidate.header_length =
            u16::try_from(MAX_HEADER_LENGTH + 4).expect("maximum header length fits u16");
        assert_eq!(
            candidate.validate(),
            Err(CodecError::HeaderTooLong {
                actual: MAX_HEADER_LENGTH + 4,
                maximum: MAX_HEADER_LENGTH,
            })
        );

        candidate.header_length = 34;
        assert_eq!(
            candidate.validate(),
            Err(CodecError::UnalignedHeaderLength { actual: 34 })
        );

        assert_eq!(
            header().validate_flags(0),
            Err(CodecError::ReservedFlags {
                packet_type: 1,
                flags: 1,
                allowed: 0,
            })
        );

        let mut short = [0; COMMON_HEADER_LENGTH - 1];
        assert_eq!(
            header().encode(&mut short),
            Err(CodecError::OutputTooSmall {
                field: "network ID",
                offset: 16,
                needed: 16,
                remaining: 15,
            })
        );
    }

    #[test]
    fn current_version_matches_constants() {
        assert_eq!(ProtocolVersion::CURRENT.major, super::PROTOCOL_MAJOR);
        assert_eq!(ProtocolVersion::CURRENT.minor, super::PROTOCOL_MINOR);
    }
}
