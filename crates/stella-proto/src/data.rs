//! Protected Ethernet data packet codec.

use std::fmt;

use stella_common::{MacAddress, NodeId};

use crate::{
    common::{validate_record_length, COMMON_HEADER_LENGTH},
    cursor::{ReadCursor, WriteCursor},
    extension::{
        encode_extension_block_at, extensions_encoded_len, validate_extension_block, ExtensionIter,
        ExtensionRef,
    },
    CodecError, CommonHeader, PacketType,
};

/// Encoded length of the fixed `DATA` header.
pub const DATA_FIXED_HEADER_LENGTH: usize = 104;

/// Length of every ChaCha20-Poly1305 authentication tag.
pub const AUTHENTICATION_TAG_LENGTH: usize = 16;

/// `DATA` flag selecting encrypted rather than authenticate-only protection.
pub const DATA_ENCRYPTED_FLAG: u8 = 0x01;

/// Smallest complete Ethernet frame carried by Stella.
pub const MIN_ETHERNET_FRAME_LENGTH: u16 = 14;

/// Protocol hard limit for a complete Ethernet frame.
pub const MAX_ETHERNET_FRAME_LENGTH: u16 = 9_216;

/// Parsed 104-byte fixed `DATA` header.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct DataHeader {
    /// Common datagram fields.
    pub common: CommonHeader,
    /// Authenticated sending node.
    pub sender_node_id: NodeId,
    /// Non-zero peer session identifier.
    pub session_id: u64,
    /// Non-zero directional protected-packet sequence number.
    pub sequence_number: u64,
    /// Controller-issued epoch authorizing the peer session.
    pub controller_epoch: u64,
    /// Non-zero identifier shared by every fragment of one frame.
    pub frame_id: u64,
    /// Complete Ethernet frame length before fragmentation.
    pub frame_length: u16,
    /// Byte offset of this fragment in the complete frame.
    pub fragment_offset: u16,
    /// Number of protected fragment bytes in this packet.
    pub fragment_length: u16,
    /// Source address copied from the complete Ethernet frame.
    pub source_mac: MacAddress,
    /// Destination address copied from the complete Ethernet frame.
    pub destination_mac: MacAddress,
    /// Verbatim Ethernet bytes 12 and 13.
    pub outer_ether_type: u16,
}

impl fmt::Debug for DataHeader {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DataHeader")
            .field("common", &self.common)
            .field("sender_node_id", &self.sender_node_id)
            .field("session_id", &self.session_id)
            .field("sequence_number", &self.sequence_number)
            .field("controller_epoch", &self.controller_epoch)
            .field("frame_id", &self.frame_id)
            .field("frame_length", &self.frame_length)
            .field("fragment_offset", &self.fragment_offset)
            .field("fragment_length", &self.fragment_length)
            .field("ethernet_metadata", &"unauthenticated")
            .finish_non_exhaustive()
    }
}

impl DataHeader {
    /// Decodes and structurally validates a fixed `DATA` header.
    ///
    /// This does not authenticate the packet or validate MAC metadata against
    /// a reassembled Ethernet frame.
    ///
    /// # Errors
    ///
    /// Returns [`CodecError`] when the input is truncated or any fixed-header
    /// version, type, flag, length, reserved field, identifier, or fragment
    /// range is invalid.
    pub fn decode(input: &[u8]) -> Result<Self, CodecError> {
        let common = CommonHeader::decode(input)?;
        let type_specific = input
            .get(COMMON_HEADER_LENGTH..)
            .ok_or(CodecError::Truncated {
                field: "DATA fixed header",
                offset: input.len(),
                needed: DATA_FIXED_HEADER_LENGTH.saturating_sub(input.len()),
                remaining: 0,
            })?;
        let mut cursor = ReadCursor::new(type_specific, COMMON_HEADER_LENGTH);
        let sender_node_id = NodeId::from_bytes(cursor.read_array("sender node ID")?);
        let session_id = cursor.read_u64("session ID")?;
        let sequence_number = cursor.read_u64("sequence number")?;
        let controller_epoch = cursor.read_u64("controller epoch")?;
        let frame_id = cursor.read_u64("frame ID")?;
        let frame_length = cursor.read_u16("frame length")?;
        let fragment_offset = cursor.read_u16("fragment offset")?;
        let fragment_length = cursor.read_u16("fragment length")?;
        let reserved_1_offset = COMMON_HEADER_LENGTH.saturating_add(cursor.position());
        let reserved_1 = cursor.read_u16("DATA reserved 1")?;
        if reserved_1 != 0 {
            return Err(CodecError::NonZeroReserved {
                field: "DATA reserved 1",
                offset: reserved_1_offset,
            });
        }
        let source_mac = MacAddress::from_bytes(cursor.read_array("source MAC")?);
        let destination_mac = MacAddress::from_bytes(cursor.read_array("destination MAC")?);
        let outer_ether_type = cursor.read_u16("outer EtherType")?;
        let reserved_2_offset = COMMON_HEADER_LENGTH.saturating_add(cursor.position());
        let reserved_2 = cursor.read_u16("DATA reserved 2")?;
        if reserved_2 != 0 {
            return Err(CodecError::NonZeroReserved {
                field: "DATA reserved 2",
                offset: reserved_2_offset,
            });
        }

        let header = Self {
            common,
            sender_node_id,
            session_id,
            sequence_number,
            controller_epoch,
            frame_id,
            frame_length,
            fragment_offset,
            fragment_length,
            source_mac,
            destination_mac,
            outer_ether_type,
        };
        header.validate()?;
        Ok(header)
    }

    /// Encodes this fixed header into the first 104 bytes of `output`.
    ///
    /// Reserved fields are written as zero.
    ///
    /// # Errors
    ///
    /// Returns [`CodecError`] when the header is invalid or `output` is too
    /// small.
    pub fn encode(self, output: &mut [u8]) -> Result<(), CodecError> {
        self.validate()?;
        let output_length = output.len();
        let fixed_output =
            output
                .get_mut(..DATA_FIXED_HEADER_LENGTH)
                .ok_or(CodecError::OutputTooSmall {
                    field: "DATA fixed header",
                    offset: 0,
                    needed: DATA_FIXED_HEADER_LENGTH,
                    remaining: output_length,
                })?;
        self.common.encode(fixed_output)?;
        let type_specific =
            fixed_output
                .get_mut(COMMON_HEADER_LENGTH..)
                .ok_or(CodecError::OutputTooSmall {
                    field: "DATA type-specific header",
                    offset: COMMON_HEADER_LENGTH,
                    needed: DATA_FIXED_HEADER_LENGTH - COMMON_HEADER_LENGTH,
                    remaining: 0,
                })?;
        let mut cursor = WriteCursor::new(type_specific, COMMON_HEADER_LENGTH);
        cursor.write_bytes(self.sender_node_id.as_bytes(), "sender node ID")?;
        cursor.write_u64(self.session_id, "session ID")?;
        cursor.write_u64(self.sequence_number, "sequence number")?;
        cursor.write_u64(self.controller_epoch, "controller epoch")?;
        cursor.write_u64(self.frame_id, "frame ID")?;
        cursor.write_u16(self.frame_length, "frame length")?;
        cursor.write_u16(self.fragment_offset, "fragment offset")?;
        cursor.write_u16(self.fragment_length, "fragment length")?;
        cursor.write_u16(0, "DATA reserved 1")?;
        cursor.write_bytes(self.source_mac.as_bytes(), "source MAC")?;
        cursor.write_bytes(self.destination_mac.as_bytes(), "destination MAC")?;
        cursor.write_u16(self.outer_ether_type, "outer EtherType")?;
        cursor.write_u16(0, "DATA reserved 2")?;
        Ok(())
    }

    /// Validates all version 0.1 structural `DATA` invariants.
    ///
    /// # Errors
    ///
    /// Returns [`CodecError`] for an invalid common header, packet type,
    /// reserved flag, fixed-header length, payload length, zero identifier,
    /// frame length, or fragment range.
    pub fn validate(self) -> Result<(), CodecError> {
        self.common.validate()?;
        if self.common.packet_type != PacketType::Data {
            return Err(CodecError::UnexpectedPacketType {
                expected: PacketType::Data.as_u8(),
                actual: self.common.packet_type.as_u8(),
            });
        }
        self.common.validate_flags(DATA_ENCRYPTED_FLAG)?;
        let header_length = usize::from(self.common.header_length);
        if header_length < DATA_FIXED_HEADER_LENGTH {
            return Err(CodecError::HeaderTooShort {
                actual: header_length,
                minimum: DATA_FIXED_HEADER_LENGTH,
            });
        }
        let payload_length = usize::try_from(self.common.payload_length).map_err(|_| {
            CodecError::IntegerOverflow {
                field: "DATA payload length",
            }
        })?;
        if payload_length != usize::from(self.fragment_length) {
            return Err(CodecError::LengthMismatch {
                field: "DATA payload",
                expected: usize::from(self.fragment_length),
                actual: payload_length,
            });
        }
        validate_nonzero(self.session_id, "session ID")?;
        validate_nonzero(self.sequence_number, "sequence number")?;
        validate_nonzero(self.frame_id, "frame ID")?;
        if !(MIN_ETHERNET_FRAME_LENGTH..=MAX_ETHERNET_FRAME_LENGTH).contains(&self.frame_length) {
            return Err(CodecError::InvalidFrameLength {
                actual: self.frame_length,
                minimum: MIN_ETHERNET_FRAME_LENGTH,
                maximum: MAX_ETHERNET_FRAME_LENGTH,
            });
        }
        if self.fragment_length == 0 {
            return Err(CodecError::InvalidFragmentLength);
        }
        let fragment_end = u32::from(self.fragment_offset)
            .checked_add(u32::from(self.fragment_length))
            .ok_or(CodecError::IntegerOverflow {
                field: "fragment range",
            })?;
        if self.fragment_offset >= self.frame_length || fragment_end > u32::from(self.frame_length)
        {
            return Err(CodecError::FragmentOutOfRange {
                offset: self.fragment_offset,
                end: fragment_end,
                frame_length: self.frame_length,
            });
        }
        Ok(())
    }

    /// Returns whether fragment bytes are encrypted on the wire.
    #[must_use]
    pub const fn is_encrypted(self) -> bool {
        self.common.flags & DATA_ENCRYPTED_FLAG != 0
    }

    /// Validates authenticated metadata against a complete Ethernet frame.
    ///
    /// Callers must invoke this only after every fragment has been
    /// authenticated and the full frame has been reassembled.
    ///
    /// # Errors
    ///
    /// Returns [`CodecError`] when the frame length differs, the source MAC is
    /// zero or a group address, or the destination, source, or outer `EtherType`
    /// differs from this authenticated header.
    pub fn validate_authenticated_frame(self, frame: &[u8]) -> Result<(), CodecError> {
        let expected_length = usize::from(self.frame_length);
        if frame.len() != expected_length {
            return Err(CodecError::LengthMismatch {
                field: "complete Ethernet frame",
                expected: expected_length,
                actual: frame.len(),
            });
        }
        if self.source_mac.is_zero() || self.source_mac.is_group() {
            return Err(CodecError::InvalidSourceMac);
        }

        let destination = frame
            .get(..MacAddress::LENGTH)
            .ok_or(CodecError::Truncated {
                field: "Ethernet destination MAC",
                offset: 0,
                needed: MacAddress::LENGTH,
                remaining: frame.len(),
            })?;
        if destination != self.destination_mac.as_bytes() {
            return Err(CodecError::EthernetMetadataMismatch {
                field: "destination MAC",
            });
        }

        let source_start = MacAddress::LENGTH;
        let source_end = source_start + MacAddress::LENGTH;
        let source = frame
            .get(source_start..source_end)
            .ok_or(CodecError::Truncated {
                field: "Ethernet source MAC",
                offset: source_start,
                needed: MacAddress::LENGTH,
                remaining: frame.len().saturating_sub(source_start),
            })?;
        if source != self.source_mac.as_bytes() {
            return Err(CodecError::EthernetMetadataMismatch {
                field: "source MAC",
            });
        }

        let ether_type = frame.get(12..14).ok_or(CodecError::Truncated {
            field: "Ethernet outer EtherType",
            offset: 12,
            needed: 2,
            remaining: frame.len().saturating_sub(12),
        })?;
        if ether_type != self.outer_ether_type.to_be_bytes() {
            return Err(CodecError::EthernetMetadataMismatch {
                field: "outer EtherType",
            });
        }
        Ok(())
    }
}

/// Borrowed, structurally validated `DATA` datagram.
#[derive(Clone)]
pub struct DataPacketView<'a> {
    header: DataHeader,
    authenticated_header: &'a [u8],
    extension_bytes: &'a [u8],
    fragment: &'a [u8],
    tag: &'a [u8; AUTHENTICATION_TAG_LENGTH],
}

impl<'a> DataPacketView<'a> {
    /// Decodes one complete `DATA` datagram without allocating.
    ///
    /// Authentication and Ethernet metadata validation remain the caller's
    /// responsibility.
    ///
    /// # Errors
    ///
    /// Returns [`CodecError`] for any malformed fixed header, extension,
    /// length, fragment range, missing tag, or trailing byte.
    pub fn decode(input: &'a [u8]) -> Result<Self, CodecError> {
        let header = DataHeader::decode(input)?;
        let header_length = usize::from(header.common.header_length);
        let fragment_length = usize::from(header.fragment_length);
        let expected_length = header_length
            .checked_add(fragment_length)
            .and_then(|length| length.checked_add(AUTHENTICATION_TAG_LENGTH))
            .ok_or(CodecError::IntegerOverflow {
                field: "DATA datagram length",
            })?;
        validate_record_length(input.len(), expected_length, "DATA datagram")?;

        let authenticated_header = input.get(..header_length).ok_or(CodecError::Truncated {
            field: "DATA authenticated header",
            offset: 0,
            needed: header_length,
            remaining: input.len(),
        })?;
        let extension_bytes =
            input
                .get(DATA_FIXED_HEADER_LENGTH..header_length)
                .ok_or(CodecError::Truncated {
                    field: "DATA extension block",
                    offset: DATA_FIXED_HEADER_LENGTH,
                    needed: header_length.saturating_sub(DATA_FIXED_HEADER_LENGTH),
                    remaining: input.len().saturating_sub(DATA_FIXED_HEADER_LENGTH),
                })?;
        validate_extension_block(extension_bytes, DATA_FIXED_HEADER_LENGTH)?;

        let fragment_end =
            header_length
                .checked_add(fragment_length)
                .ok_or(CodecError::IntegerOverflow {
                    field: "DATA fragment end",
                })?;
        let fragment = input
            .get(header_length..fragment_end)
            .ok_or(CodecError::Truncated {
                field: "DATA fragment",
                offset: header_length,
                needed: fragment_length,
                remaining: input.len().saturating_sub(header_length),
            })?;
        let tag_bytes = input
            .get(fragment_end..expected_length)
            .ok_or(CodecError::Truncated {
                field: "DATA authentication tag",
                offset: fragment_end,
                needed: AUTHENTICATION_TAG_LENGTH,
                remaining: input.len().saturating_sub(fragment_end),
            })?;
        let tag = <&[u8; AUTHENTICATION_TAG_LENGTH]>::try_from(tag_bytes).map_err(|_| {
            CodecError::LengthMismatch {
                field: "DATA authentication tag",
                expected: AUTHENTICATION_TAG_LENGTH,
                actual: tag_bytes.len(),
            }
        })?;

        Ok(Self {
            header,
            authenticated_header,
            extension_bytes,
            fragment,
            tag,
        })
    }

    /// Returns the parsed fixed header.
    #[must_use]
    pub const fn header(&self) -> DataHeader {
        self.header
    }

    /// Borrows the exact associated-data header bytes, including extensions.
    #[must_use]
    pub const fn authenticated_header(&self) -> &'a [u8] {
        self.authenticated_header
    }

    /// Iterates over the validated header extensions.
    #[must_use]
    pub const fn extensions(&self) -> ExtensionIter<'a> {
        ExtensionIter::new(self.extension_bytes)
    }

    /// Borrows the protected fragment bytes.
    #[must_use]
    pub const fn fragment(&self) -> &'a [u8] {
        self.fragment
    }

    /// Borrows the authentication tag.
    #[must_use]
    pub const fn tag(&self) -> &'a [u8; AUTHENTICATION_TAG_LENGTH] {
        self.tag
    }

    /// Returns the exact datagram length.
    #[must_use]
    pub const fn encoded_len(&self) -> usize {
        self.authenticated_header.len() + self.fragment.len() + AUTHENTICATION_TAG_LENGTH
    }
}

/// Encodes one complete `DATA` datagram into caller-provided storage.
///
/// The returned value is the exact number of bytes written. Extra output
/// capacity is left unchanged.
///
/// # Errors
///
/// Returns [`CodecError`] when the header, extensions, declared lengths, or
/// fragment are inconsistent, arithmetic overflows, or `output` is too small.
pub fn encode_data_packet(
    header: DataHeader,
    extensions: &[ExtensionRef<'_>],
    fragment: &[u8],
    tag: &[u8; AUTHENTICATION_TAG_LENGTH],
    output: &mut [u8],
) -> Result<usize, CodecError> {
    header.validate()?;
    if fragment.len() != usize::from(header.fragment_length) {
        return Err(CodecError::LengthMismatch {
            field: "DATA fragment",
            expected: usize::from(header.fragment_length),
            actual: fragment.len(),
        });
    }
    let extension_length = extensions_encoded_len(extensions)?;
    let expected_header_length = DATA_FIXED_HEADER_LENGTH
        .checked_add(extension_length)
        .ok_or(CodecError::IntegerOverflow {
            field: "DATA header length",
        })?;
    let declared_header_length = usize::from(header.common.header_length);
    if declared_header_length != expected_header_length {
        return Err(CodecError::LengthMismatch {
            field: "DATA header",
            expected: expected_header_length,
            actual: declared_header_length,
        });
    }
    let encoded_length = expected_header_length
        .checked_add(fragment.len())
        .and_then(|length| length.checked_add(AUTHENTICATION_TAG_LENGTH))
        .ok_or(CodecError::IntegerOverflow {
            field: "DATA datagram length",
        })?;
    if output.len() < encoded_length {
        return Err(CodecError::OutputTooSmall {
            field: "DATA datagram",
            offset: 0,
            needed: encoded_length,
            remaining: output.len(),
        });
    }

    let output_length = output.len();
    let packet = output
        .get_mut(..encoded_length)
        .ok_or(CodecError::OutputTooSmall {
            field: "DATA datagram",
            offset: 0,
            needed: encoded_length,
            remaining: output_length,
        })?;
    let packet_length = packet.len();
    let fixed_header =
        packet
            .get_mut(..DATA_FIXED_HEADER_LENGTH)
            .ok_or(CodecError::OutputTooSmall {
                field: "DATA fixed header",
                offset: 0,
                needed: DATA_FIXED_HEADER_LENGTH,
                remaining: packet_length,
            })?;
    header.encode(fixed_header)?;

    let extension_output = packet
        .get_mut(DATA_FIXED_HEADER_LENGTH..expected_header_length)
        .ok_or(CodecError::OutputTooSmall {
            field: "DATA extension block",
            offset: DATA_FIXED_HEADER_LENGTH,
            needed: extension_length,
            remaining: packet_length.saturating_sub(DATA_FIXED_HEADER_LENGTH),
        })?;
    encode_extension_block_at(extensions, extension_output, DATA_FIXED_HEADER_LENGTH)?;

    let fragment_end =
        expected_header_length
            .checked_add(fragment.len())
            .ok_or(CodecError::IntegerOverflow {
                field: "DATA fragment end",
            })?;
    let fragment_output =
        packet
            .get_mut(expected_header_length..fragment_end)
            .ok_or(CodecError::OutputTooSmall {
                field: "DATA fragment",
                offset: expected_header_length,
                needed: fragment.len(),
                remaining: packet_length.saturating_sub(expected_header_length),
            })?;
    fragment_output.copy_from_slice(fragment);
    let tag_output =
        packet
            .get_mut(fragment_end..encoded_length)
            .ok_or(CodecError::OutputTooSmall {
                field: "DATA authentication tag",
                offset: fragment_end,
                needed: AUTHENTICATION_TAG_LENGTH,
                remaining: packet_length.saturating_sub(fragment_end),
            })?;
    tag_output.copy_from_slice(tag);
    Ok(encoded_length)
}

fn validate_nonzero(value: u64, field: &'static str) -> Result<(), CodecError> {
    if value == 0 {
        return Err(CodecError::ZeroField { field });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use stella_common::{MacAddress, NetworkId, NodeId};

    use super::{
        encode_data_packet, DataHeader, DataPacketView, AUTHENTICATION_TAG_LENGTH,
        DATA_ENCRYPTED_FLAG, DATA_FIXED_HEADER_LENGTH, MAX_ETHERNET_FRAME_LENGTH,
        MIN_ETHERNET_FRAME_LENGTH,
    };
    use crate::{CodecError, CommonHeader, ExtensionRef, PacketType, ProtocolVersion};

    const FRAME: [u8; 14] = [0x02, 0, 0, 0, 0, 1, 0x02, 0, 0, 0, 0, 2, 0x08, 0x00];
    const FIXED_HEADER: [u8; DATA_FIXED_HEADER_LENGTH] = [
        0x53, 0x54, 0x4c, 0x41, 0, 1, 1, 0, 0, 104, 0, 0, 0, 0, 0, 14, 0, 1, 2, 3, 4, 5, 6, 7, 8,
        9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31,
        0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0, 3, 0, 0, 0, 0, 0, 0,
        0, 4, 0, 14, 0, 0, 0, 14, 0, 0, 0x02, 0, 0, 0, 0, 2, 0x02, 0, 0, 0, 0, 1, 0x08, 0, 0, 0,
    ];

    fn header() -> DataHeader {
        DataHeader {
            common: CommonHeader {
                version: ProtocolVersion::CURRENT,
                packet_type: PacketType::Data,
                flags: 0,
                header_length: u16::try_from(DATA_FIXED_HEADER_LENGTH)
                    .expect("fixed header length fits u16"),
                payload_length: u32::try_from(FRAME.len()).expect("frame length fits u32"),
                network_id: NetworkId::from_bytes([
                    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
                ]),
            },
            sender_node_id: NodeId::from_bytes([
                16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31,
            ]),
            session_id: 1,
            sequence_number: 2,
            controller_epoch: 3,
            frame_id: 4,
            frame_length: 14,
            fragment_offset: 0,
            fragment_length: 14,
            source_mac: MacAddress::from_bytes([0x02, 0, 0, 0, 0, 2]),
            destination_mac: MacAddress::from_bytes([0x02, 0, 0, 0, 0, 1]),
            outer_ether_type: 0x0800,
        }
    }

    #[test]
    fn data_packet_matches_canonical_header_and_round_trips() {
        let tag = [0xa5; AUTHENTICATION_TAG_LENGTH];
        let mut encoded =
            [0xcc; DATA_FIXED_HEADER_LENGTH + FRAME.len() + AUTHENTICATION_TAG_LENGTH];

        assert_eq!(
            encode_data_packet(header(), &[], &FRAME, &tag, &mut encoded),
            Ok(encoded.len())
        );
        assert_eq!(encoded[..DATA_FIXED_HEADER_LENGTH], FIXED_HEADER);

        let decoded = DataPacketView::decode(&encoded).expect("valid DATA packet");
        assert_eq!(decoded.header(), header());
        assert_eq!(decoded.authenticated_header(), FIXED_HEADER);
        assert_eq!(decoded.extensions().next(), None);
        assert_eq!(decoded.fragment(), FRAME);
        assert_eq!(decoded.tag(), &tag);
        assert_eq!(decoded.encoded_len(), encoded.len());
        assert!(!decoded.header().is_encrypted());
        assert_eq!(
            decoded.header().validate_authenticated_frame(&FRAME),
            Ok(())
        );
    }

    #[test]
    fn data_packet_encodes_and_decodes_extensions() {
        let extension = ExtensionRef::new(1, &[0xaa]).expect("valid extension");
        let mut candidate = header();
        candidate.common.flags = DATA_ENCRYPTED_FLAG;
        candidate.common.header_length = 112;
        let tag = [0x5a; AUTHENTICATION_TAG_LENGTH];
        let mut encoded = [0; 112 + FRAME.len() + AUTHENTICATION_TAG_LENGTH];

        assert_eq!(
            encode_data_packet(candidate, &[extension], &FRAME, &tag, &mut encoded),
            Ok(encoded.len())
        );
        let decoded = DataPacketView::decode(&encoded).expect("valid extended DATA packet");
        assert!(decoded.header().is_encrypted());
        assert_eq!(decoded.extensions().collect::<Vec<_>>(), vec![extension]);
        assert_eq!(
            &decoded.authenticated_header()[104..],
            &[0, 1, 0, 1, 0xaa, 0, 0, 0]
        );
    }

    #[test]
    fn data_header_rejects_type_flags_reserved_and_zero_fields() {
        let mut candidate = header();
        candidate.common.packet_type = PacketType::Keepalive;
        assert_eq!(
            candidate.validate(),
            Err(CodecError::UnexpectedPacketType {
                expected: 1,
                actual: 2,
            })
        );

        candidate = header();
        candidate.common.flags = 2;
        assert_eq!(
            candidate.validate(),
            Err(CodecError::ReservedFlags {
                packet_type: 1,
                flags: 2,
                allowed: 1,
            })
        );

        candidate = header();
        candidate.session_id = 0;
        assert_eq!(
            candidate.validate(),
            Err(CodecError::ZeroField {
                field: "session ID",
            })
        );

        candidate = header();
        candidate.sequence_number = 0;
        assert_eq!(
            candidate.validate(),
            Err(CodecError::ZeroField {
                field: "sequence number",
            })
        );

        candidate = header();
        candidate.frame_id = 0;
        assert_eq!(
            candidate.validate(),
            Err(CodecError::ZeroField { field: "frame ID" })
        );

        let mut bytes = FIXED_HEADER;
        bytes[86] = 1;
        assert_eq!(
            DataHeader::decode(&bytes),
            Err(CodecError::NonZeroReserved {
                field: "DATA reserved 1",
                offset: 86,
            })
        );
        bytes = FIXED_HEADER;
        bytes[103] = 1;
        assert_eq!(
            DataHeader::decode(&bytes),
            Err(CodecError::NonZeroReserved {
                field: "DATA reserved 2",
                offset: 102,
            })
        );
    }

    #[test]
    fn data_header_validates_frame_and_fragment_boundaries() {
        let mut candidate = header();
        candidate.frame_length = MIN_ETHERNET_FRAME_LENGTH - 1;
        assert_eq!(
            candidate.validate(),
            Err(CodecError::InvalidFrameLength {
                actual: MIN_ETHERNET_FRAME_LENGTH - 1,
                minimum: MIN_ETHERNET_FRAME_LENGTH,
                maximum: MAX_ETHERNET_FRAME_LENGTH,
            })
        );

        candidate = header();
        candidate.frame_length = MAX_ETHERNET_FRAME_LENGTH;
        candidate.fragment_length = 1;
        candidate.common.payload_length = 1;
        candidate.fragment_offset = MAX_ETHERNET_FRAME_LENGTH - 1;
        assert_eq!(candidate.validate(), Ok(()));

        candidate.fragment_offset = MAX_ETHERNET_FRAME_LENGTH;
        assert_eq!(
            candidate.validate(),
            Err(CodecError::FragmentOutOfRange {
                offset: MAX_ETHERNET_FRAME_LENGTH,
                end: u32::from(MAX_ETHERNET_FRAME_LENGTH) + 1,
                frame_length: MAX_ETHERNET_FRAME_LENGTH,
            })
        );

        candidate = header();
        candidate.fragment_length = 0;
        candidate.common.payload_length = 0;
        assert_eq!(candidate.validate(), Err(CodecError::InvalidFragmentLength));
    }

    #[test]
    fn data_packet_rejects_length_mismatches_truncation_and_trailing_bytes() {
        let tag = [0; AUTHENTICATION_TAG_LENGTH];
        let mut encoded = [0; DATA_FIXED_HEADER_LENGTH + FRAME.len() + AUTHENTICATION_TAG_LENGTH];
        encode_data_packet(header(), &[], &FRAME, &tag, &mut encoded).expect("valid DATA packet");

        assert!(matches!(
            DataPacketView::decode(&encoded[..encoded.len() - 1]),
            Err(CodecError::Truncated {
                field: "DATA datagram",
                offset,
                needed: 1,
                remaining: 0,
            }) if offset == encoded.len() - 1
        ));

        let mut with_trailer = encoded.to_vec();
        with_trailer.push(0);
        assert!(matches!(
            DataPacketView::decode(&with_trailer),
            Err(CodecError::TrailingBytes { expected, actual })
                if expected == encoded.len() && actual == encoded.len() + 1
        ));

        assert_eq!(
            encode_data_packet(header(), &[], &FRAME[..13], &tag, &mut encoded),
            Err(CodecError::LengthMismatch {
                field: "DATA fragment",
                expected: 14,
                actual: 13,
            })
        );
        let short_length = encoded.len() - 1;
        assert_eq!(
            encode_data_packet(header(), &[], &FRAME, &tag, &mut encoded[..short_length]),
            Err(CodecError::OutputTooSmall {
                field: "DATA datagram",
                offset: 0,
                needed: encoded.len(),
                remaining: short_length,
            })
        );
    }

    #[test]
    fn authenticated_frame_validation_rejects_bad_metadata() {
        let debug = format!("{:?}", header());
        assert!(debug.contains("ethernet_metadata: \"unauthenticated\""));
        assert!(!debug.contains("02:00:00:00:00:01"));

        let mut candidate = header();
        candidate.source_mac = MacAddress::BROADCAST;
        assert_eq!(
            candidate.validate_authenticated_frame(&FRAME),
            Err(CodecError::InvalidSourceMac)
        );

        candidate = header();
        candidate.destination_mac = MacAddress::from_bytes([0x02, 0, 0, 0, 0, 9]);
        assert_eq!(
            candidate.validate_authenticated_frame(&FRAME),
            Err(CodecError::EthernetMetadataMismatch {
                field: "destination MAC",
            })
        );

        assert_eq!(
            header().validate_authenticated_frame(&FRAME[..13]),
            Err(CodecError::LengthMismatch {
                field: "complete Ethernet frame",
                expected: 14,
                actual: 13,
            })
        );
    }
}
