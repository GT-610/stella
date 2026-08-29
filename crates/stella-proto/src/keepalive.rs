//! Authenticated keepalive packet codec.

use stella_common::NodeId;

use crate::{
    common::{validate_record_length, COMMON_HEADER_LENGTH},
    cursor::{ReadCursor, WriteCursor},
    extension::{
        encode_extension_block_at, extensions_encoded_len, validate_extension_block, ExtensionIter,
        ExtensionRef,
    },
    CodecError, CommonHeader, PacketType, AUTHENTICATION_TAG_LENGTH,
};

/// Encoded length of the fixed `KEEPALIVE` header.
pub const KEEPALIVE_FIXED_HEADER_LENGTH: usize = 88;

/// Parsed 88-byte fixed `KEEPALIVE` header.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct KeepaliveHeader {
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
    /// Probe identifier equal to `sequence_number`.
    pub probe_id: u64,
    /// Zero or a previously authenticated peer probe identifier.
    pub echo_probe_id: u64,
}

impl KeepaliveHeader {
    /// Decodes and structurally validates a fixed `KEEPALIVE` header.
    ///
    /// This does not authenticate the packet or resolve session state.
    ///
    /// # Errors
    ///
    /// Returns [`CodecError`] when the input is truncated or any version,
    /// type, flag, header length, payload length, session identifier, sequence
    /// number, or probe identifier is invalid.
    pub fn decode(input: &[u8]) -> Result<Self, CodecError> {
        let common = CommonHeader::decode(input)?;
        let type_specific = input
            .get(COMMON_HEADER_LENGTH..)
            .ok_or(CodecError::Truncated {
                field: "KEEPALIVE fixed header",
                offset: input.len(),
                needed: KEEPALIVE_FIXED_HEADER_LENGTH.saturating_sub(input.len()),
                remaining: 0,
            })?;
        let mut cursor = ReadCursor::new(type_specific, COMMON_HEADER_LENGTH);
        let header = Self {
            common,
            sender_node_id: NodeId::from_bytes(cursor.read_array("sender node ID")?),
            session_id: cursor.read_u64("session ID")?,
            sequence_number: cursor.read_u64("sequence number")?,
            controller_epoch: cursor.read_u64("controller epoch")?,
            probe_id: cursor.read_u64("probe ID")?,
            echo_probe_id: cursor.read_u64("echo probe ID")?,
        };
        header.validate()?;
        Ok(header)
    }

    /// Encodes this fixed header into the first 88 bytes of `output`.
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
                .get_mut(..KEEPALIVE_FIXED_HEADER_LENGTH)
                .ok_or(CodecError::OutputTooSmall {
                    field: "KEEPALIVE fixed header",
                    offset: 0,
                    needed: KEEPALIVE_FIXED_HEADER_LENGTH,
                    remaining: output_length,
                })?;
        self.common.encode(fixed_output)?;
        let type_specific =
            fixed_output
                .get_mut(COMMON_HEADER_LENGTH..)
                .ok_or(CodecError::OutputTooSmall {
                    field: "KEEPALIVE type-specific header",
                    offset: COMMON_HEADER_LENGTH,
                    needed: KEEPALIVE_FIXED_HEADER_LENGTH - COMMON_HEADER_LENGTH,
                    remaining: 0,
                })?;
        let mut cursor = WriteCursor::new(type_specific, COMMON_HEADER_LENGTH);
        cursor.write_bytes(self.sender_node_id.as_bytes(), "sender node ID")?;
        cursor.write_u64(self.session_id, "session ID")?;
        cursor.write_u64(self.sequence_number, "sequence number")?;
        cursor.write_u64(self.controller_epoch, "controller epoch")?;
        cursor.write_u64(self.probe_id, "probe ID")?;
        cursor.write_u64(self.echo_probe_id, "echo probe ID")?;
        Ok(())
    }

    /// Validates all version 0.1 structural `KEEPALIVE` invariants.
    ///
    /// # Errors
    ///
    /// Returns [`CodecError`] for an invalid common header, packet type,
    /// flags, fixed-header length, non-empty payload, zero session or sequence
    /// number, or a probe ID different from the sequence number.
    pub fn validate(self) -> Result<(), CodecError> {
        self.common.validate()?;
        if self.common.packet_type != PacketType::Keepalive {
            return Err(CodecError::UnexpectedPacketType {
                expected: PacketType::Keepalive.as_u8(),
                actual: self.common.packet_type.as_u8(),
            });
        }
        self.common.validate_flags(0)?;
        let header_length = usize::from(self.common.header_length);
        if header_length < KEEPALIVE_FIXED_HEADER_LENGTH {
            return Err(CodecError::HeaderTooShort {
                actual: header_length,
                minimum: KEEPALIVE_FIXED_HEADER_LENGTH,
            });
        }
        if self.common.payload_length != 0 {
            let actual = usize::try_from(self.common.payload_length).map_err(|_| {
                CodecError::IntegerOverflow {
                    field: "KEEPALIVE payload length",
                }
            })?;
            return Err(CodecError::LengthMismatch {
                field: "KEEPALIVE payload",
                expected: 0,
                actual,
            });
        }
        validate_nonzero(self.session_id, "session ID")?;
        validate_nonzero(self.sequence_number, "sequence number")?;
        if self.probe_id != self.sequence_number {
            return Err(CodecError::ProbeIdMismatch {
                sequence_number: self.sequence_number,
                probe_id: self.probe_id,
            });
        }
        Ok(())
    }
}

/// Borrowed, structurally validated `KEEPALIVE` datagram.
#[derive(Clone)]
pub struct KeepalivePacketView<'a> {
    header: KeepaliveHeader,
    authenticated_header: &'a [u8],
    extension_bytes: &'a [u8],
    tag: &'a [u8; AUTHENTICATION_TAG_LENGTH],
}

impl<'a> KeepalivePacketView<'a> {
    /// Decodes one complete `KEEPALIVE` datagram without allocating.
    ///
    /// Authentication and replay-state updates remain the caller's
    /// responsibility.
    ///
    /// # Errors
    ///
    /// Returns [`CodecError`] for any malformed fixed header, extension,
    /// length, missing tag, non-empty payload, or trailing byte.
    pub fn decode(input: &'a [u8]) -> Result<Self, CodecError> {
        let header = KeepaliveHeader::decode(input)?;
        let header_length = usize::from(header.common.header_length);
        let expected_length = header_length.checked_add(AUTHENTICATION_TAG_LENGTH).ok_or(
            CodecError::IntegerOverflow {
                field: "KEEPALIVE datagram length",
            },
        )?;
        validate_record_length(input.len(), expected_length, "KEEPALIVE datagram")?;

        let authenticated_header = input.get(..header_length).ok_or(CodecError::Truncated {
            field: "KEEPALIVE authenticated header",
            offset: 0,
            needed: header_length,
            remaining: input.len(),
        })?;
        let extension_bytes = input
            .get(KEEPALIVE_FIXED_HEADER_LENGTH..header_length)
            .ok_or(CodecError::Truncated {
                field: "KEEPALIVE extension block",
                offset: KEEPALIVE_FIXED_HEADER_LENGTH,
                needed: header_length.saturating_sub(KEEPALIVE_FIXED_HEADER_LENGTH),
                remaining: input.len().saturating_sub(KEEPALIVE_FIXED_HEADER_LENGTH),
            })?;
        validate_extension_block(extension_bytes, KEEPALIVE_FIXED_HEADER_LENGTH)?;

        let tag_bytes = input
            .get(header_length..expected_length)
            .ok_or(CodecError::Truncated {
                field: "KEEPALIVE authentication tag",
                offset: header_length,
                needed: AUTHENTICATION_TAG_LENGTH,
                remaining: input.len().saturating_sub(header_length),
            })?;
        let tag = <&[u8; AUTHENTICATION_TAG_LENGTH]>::try_from(tag_bytes).map_err(|_| {
            CodecError::LengthMismatch {
                field: "KEEPALIVE authentication tag",
                expected: AUTHENTICATION_TAG_LENGTH,
                actual: tag_bytes.len(),
            }
        })?;

        Ok(Self {
            header,
            authenticated_header,
            extension_bytes,
            tag,
        })
    }

    /// Returns the parsed fixed header.
    #[must_use]
    pub const fn header(&self) -> KeepaliveHeader {
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

    /// Borrows the authentication tag.
    #[must_use]
    pub const fn tag(&self) -> &'a [u8; AUTHENTICATION_TAG_LENGTH] {
        self.tag
    }

    /// Returns the exact datagram length.
    #[must_use]
    pub const fn encoded_len(&self) -> usize {
        self.authenticated_header.len() + AUTHENTICATION_TAG_LENGTH
    }
}

/// Encodes one complete `KEEPALIVE` datagram into caller-provided storage.
///
/// The returned value is the exact number of bytes written. Extra output
/// capacity is left unchanged.
///
/// # Errors
///
/// Returns [`CodecError`] when the header, extensions, or declared length is
/// invalid, arithmetic overflows, or `output` is too small.
pub fn encode_keepalive_packet(
    header: KeepaliveHeader,
    extensions: &[ExtensionRef<'_>],
    tag: &[u8; AUTHENTICATION_TAG_LENGTH],
    output: &mut [u8],
) -> Result<usize, CodecError> {
    header.validate()?;
    let extension_length = extensions_encoded_len(extensions)?;
    let expected_header_length = KEEPALIVE_FIXED_HEADER_LENGTH
        .checked_add(extension_length)
        .ok_or(CodecError::IntegerOverflow {
            field: "KEEPALIVE header length",
        })?;
    let declared_header_length = usize::from(header.common.header_length);
    if declared_header_length != expected_header_length {
        return Err(CodecError::LengthMismatch {
            field: "KEEPALIVE header",
            expected: expected_header_length,
            actual: declared_header_length,
        });
    }
    let encoded_length = expected_header_length
        .checked_add(AUTHENTICATION_TAG_LENGTH)
        .ok_or(CodecError::IntegerOverflow {
            field: "KEEPALIVE datagram length",
        })?;
    if output.len() < encoded_length {
        return Err(CodecError::OutputTooSmall {
            field: "KEEPALIVE datagram",
            offset: 0,
            needed: encoded_length,
            remaining: output.len(),
        });
    }

    let output_length = output.len();
    let packet = output
        .get_mut(..encoded_length)
        .ok_or(CodecError::OutputTooSmall {
            field: "KEEPALIVE datagram",
            offset: 0,
            needed: encoded_length,
            remaining: output_length,
        })?;
    let packet_length = packet.len();
    let fixed_header =
        packet
            .get_mut(..KEEPALIVE_FIXED_HEADER_LENGTH)
            .ok_or(CodecError::OutputTooSmall {
                field: "KEEPALIVE fixed header",
                offset: 0,
                needed: KEEPALIVE_FIXED_HEADER_LENGTH,
                remaining: packet_length,
            })?;
    header.encode(fixed_header)?;

    let extension_output = packet
        .get_mut(KEEPALIVE_FIXED_HEADER_LENGTH..expected_header_length)
        .ok_or(CodecError::OutputTooSmall {
            field: "KEEPALIVE extension block",
            offset: KEEPALIVE_FIXED_HEADER_LENGTH,
            needed: extension_length,
            remaining: packet_length.saturating_sub(KEEPALIVE_FIXED_HEADER_LENGTH),
        })?;
    encode_extension_block_at(extensions, extension_output, KEEPALIVE_FIXED_HEADER_LENGTH)?;

    let tag_output = packet
        .get_mut(expected_header_length..encoded_length)
        .ok_or(CodecError::OutputTooSmall {
            field: "KEEPALIVE authentication tag",
            offset: expected_header_length,
            needed: AUTHENTICATION_TAG_LENGTH,
            remaining: packet_length.saturating_sub(expected_header_length),
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
    use stella_common::{NetworkId, NodeId};

    use super::{
        encode_keepalive_packet, KeepaliveHeader, KeepalivePacketView,
        KEEPALIVE_FIXED_HEADER_LENGTH,
    };
    use crate::{
        CodecError, CommonHeader, ExtensionRef, PacketType, ProtocolVersion,
        AUTHENTICATION_TAG_LENGTH,
    };

    const FIXED_HEADER: [u8; KEEPALIVE_FIXED_HEADER_LENGTH] = [
        0x53, 0x54, 0x4c, 0x41, 0, 1, 2, 0, 0, 88, 0, 0, 0, 0, 0, 0, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9,
        10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 0,
        0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0, 3, 0, 0, 0, 0, 0, 0, 0,
        2, 0, 0, 0, 0, 0, 0, 0, 4,
    ];

    fn header() -> KeepaliveHeader {
        KeepaliveHeader {
            common: CommonHeader {
                version: ProtocolVersion::CURRENT,
                packet_type: PacketType::Keepalive,
                flags: 0,
                header_length: u16::try_from(KEEPALIVE_FIXED_HEADER_LENGTH)
                    .expect("fixed header length fits u16"),
                payload_length: 0,
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
            probe_id: 2,
            echo_probe_id: 4,
        }
    }

    #[test]
    fn keepalive_matches_canonical_bytes_and_round_trips() {
        let tag = [0xa5; AUTHENTICATION_TAG_LENGTH];
        let mut encoded = [0xcc; KEEPALIVE_FIXED_HEADER_LENGTH + AUTHENTICATION_TAG_LENGTH];

        assert_eq!(
            encode_keepalive_packet(header(), &[], &tag, &mut encoded),
            Ok(encoded.len())
        );
        assert_eq!(encoded[..KEEPALIVE_FIXED_HEADER_LENGTH], FIXED_HEADER);

        let decoded = KeepalivePacketView::decode(&encoded).expect("valid KEEPALIVE packet");
        assert_eq!(decoded.header(), header());
        assert_eq!(decoded.authenticated_header(), FIXED_HEADER);
        assert_eq!(decoded.extensions().next(), None);
        assert_eq!(decoded.tag(), &tag);
        assert_eq!(decoded.encoded_len(), encoded.len());
    }

    #[test]
    fn keepalive_encodes_and_decodes_extensions() {
        let extension = ExtensionRef::new(7, &[1, 2]).expect("valid extension");
        let mut candidate = header();
        candidate.common.header_length = 96;
        let tag = [0x5a; AUTHENTICATION_TAG_LENGTH];
        let mut encoded = [0; 96 + AUTHENTICATION_TAG_LENGTH];

        assert_eq!(
            encode_keepalive_packet(candidate, &[extension], &tag, &mut encoded),
            Ok(encoded.len())
        );
        let decoded =
            KeepalivePacketView::decode(&encoded).expect("valid extended KEEPALIVE packet");
        assert_eq!(decoded.extensions().collect::<Vec<_>>(), vec![extension]);
        assert_eq!(
            &decoded.authenticated_header()[88..],
            &[0, 7, 0, 2, 1, 2, 0, 0]
        );
    }

    #[test]
    fn keepalive_rejects_type_flags_payload_zero_and_probe_mismatch() {
        let mut candidate = header();
        candidate.common.packet_type = PacketType::Data;
        assert_eq!(
            candidate.validate(),
            Err(CodecError::UnexpectedPacketType {
                expected: 2,
                actual: 1,
            })
        );

        candidate = header();
        candidate.common.flags = 1;
        assert_eq!(
            candidate.validate(),
            Err(CodecError::ReservedFlags {
                packet_type: 2,
                flags: 1,
                allowed: 0,
            })
        );

        candidate = header();
        candidate.common.payload_length = 1;
        assert_eq!(
            candidate.validate(),
            Err(CodecError::LengthMismatch {
                field: "KEEPALIVE payload",
                expected: 0,
                actual: 1,
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
        candidate.probe_id = 0;
        assert_eq!(
            candidate.validate(),
            Err(CodecError::ZeroField {
                field: "sequence number",
            })
        );

        candidate = header();
        candidate.probe_id = 3;
        assert_eq!(
            candidate.validate(),
            Err(CodecError::ProbeIdMismatch {
                sequence_number: 2,
                probe_id: 3,
            })
        );
    }

    #[test]
    fn keepalive_rejects_truncation_trailing_and_small_output() {
        let tag = [0; AUTHENTICATION_TAG_LENGTH];
        let mut encoded = [0; KEEPALIVE_FIXED_HEADER_LENGTH + AUTHENTICATION_TAG_LENGTH];
        encode_keepalive_packet(header(), &[], &tag, &mut encoded).expect("valid KEEPALIVE packet");

        assert!(matches!(
            KeepalivePacketView::decode(&encoded[..encoded.len() - 1]),
            Err(CodecError::Truncated {
                field: "KEEPALIVE datagram",
                offset,
                needed: 1,
                remaining: 0,
            }) if offset == encoded.len() - 1
        ));

        let mut with_trailer = encoded.to_vec();
        with_trailer.push(0);
        assert!(matches!(
            KeepalivePacketView::decode(&with_trailer),
            Err(CodecError::TrailingBytes { expected, actual })
                if expected == encoded.len() && actual == encoded.len() + 1
        ));

        let short_length = encoded.len() - 1;
        assert_eq!(
            encode_keepalive_packet(header(), &[], &tag, &mut encoded[..short_length]),
            Err(CodecError::OutputTooSmall {
                field: "KEEPALIVE datagram",
                offset: 0,
                needed: encoded.len(),
                remaining: short_length,
            })
        );
    }
}
