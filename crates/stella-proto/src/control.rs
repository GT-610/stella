//! TLS control-message framing, headers, and body fields.

use std::fmt;

use stella_common::{NetworkId, NodeId};

use crate::{
    common::{validate_record_length, MAX_HEADER_LENGTH},
    cursor::{ReadCursor, WriteCursor},
    extension::{
        encode_extension_block_at, extensions_encoded_len, validate_extension_block, ExtensionIter,
        ExtensionRef,
    },
    CodecError, ConnectivityGenerationView, ConnectivityListView, ConnectivityRecordView,
    EndpointSetView, MembershipGrantView, NetworkPolicy, NetworkRevisionListView, PeerListView,
    PeerRecordView, ProtocolVersion, RelayServiceListView, StunServerListView, VersionEntry,
    VersionListView,
};

/// Magic at the beginning of every control message.
pub const CONTROL_MAGIC: [u8; 4] = *b"STLC";

/// Exact length of the fixed control-message header.
pub const CONTROL_HEADER_LENGTH: usize = 32;

/// Length of the outer control-record prefix.
pub const CONTROL_RECORD_PREFIX_LENGTH: usize = 4;

/// Largest control message permitted on one TLS connection.
pub const MAX_CONTROL_RECORD_LENGTH: usize = 1_048_576;

const CONTROL_FIELD_PREFIX_LENGTH: usize = 4;
const CRITICAL_CONTROL_FIELD_BIT: u16 = 0x8000;

/// Registered control message type through version 0.2.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u16)]
pub enum ControlMessageType {
    /// Controller negotiation greeting.
    ServerHello = 0x0001,
    /// Client version and identity selection.
    ClientHello = 0x0002,
    /// Controller TLS-exporter proof.
    ServerProof = 0x0003,
    /// Node TLS-exporter proof and optional enrollment.
    NodeAuth = 0x0004,
    /// Authentication result.
    AuthResult = 0x0005,
    /// Request to join a virtual network.
    JoinRequest = 0x0010,
    /// Network join result.
    JoinResult = 0x0011,
    /// Request to leave a virtual network.
    LeaveRequest = 0x0012,
    /// Network leave result.
    LeaveResult = 0x0013,
    /// Publication of numeric data-plane endpoints.
    EndpointUpdate = 0x0020,
    /// Endpoint publication result.
    EndpointResult = 0x0021,
    /// Complete version 0.2 connectivity-generation publication or withdrawal.
    ConnectivityUpdate = 0x0022,
    /// Version 0.2 connectivity publication result.
    ConnectivityResult = 0x0023,
    /// Full authoritative peer snapshot.
    PeerSnapshot = 0x0030,
    /// One peer-state delta.
    PeerDelta = 0x0031,
    /// Request for a replacement peer snapshot.
    SnapshotRequest = 0x0032,
    /// Client control heartbeat.
    Heartbeat = 0x0040,
    /// Controller heartbeat acknowledgement.
    HeartbeatAck = 0x0041,
    /// Refreshed local membership authorization.
    GrantRefresh = 0x0050,
    /// Version 0.2 deployment STUN and relay configuration.
    ConnectivityConfig = 0x0060,
    /// Graceful controller shutdown notice.
    ServerShutdown = 0x00fe,
    /// Fatal or request-scoped protocol error.
    Error = 0x00ff,
}

impl ControlMessageType {
    /// Returns the canonical two-byte type value.
    #[must_use]
    pub const fn as_u16(self) -> u16 {
        self as u16
    }

    const fn minimum_version(self) -> ProtocolVersion {
        match self {
            Self::ConnectivityUpdate | Self::ConnectivityResult | Self::ConnectivityConfig => {
                ProtocolVersion::V0_2
            }
            _ => ProtocolVersion::V0_1,
        }
    }
}

impl TryFrom<u16> for ControlMessageType {
    type Error = CodecError;

    fn try_from(value: u16) -> Result<Self, CodecError> {
        match value {
            0x0001 => Ok(Self::ServerHello),
            0x0002 => Ok(Self::ClientHello),
            0x0003 => Ok(Self::ServerProof),
            0x0004 => Ok(Self::NodeAuth),
            0x0005 => Ok(Self::AuthResult),
            0x0010 => Ok(Self::JoinRequest),
            0x0011 => Ok(Self::JoinResult),
            0x0012 => Ok(Self::LeaveRequest),
            0x0013 => Ok(Self::LeaveResult),
            0x0020 => Ok(Self::EndpointUpdate),
            0x0021 => Ok(Self::EndpointResult),
            0x0022 => Ok(Self::ConnectivityUpdate),
            0x0023 => Ok(Self::ConnectivityResult),
            0x0030 => Ok(Self::PeerSnapshot),
            0x0031 => Ok(Self::PeerDelta),
            0x0032 => Ok(Self::SnapshotRequest),
            0x0040 => Ok(Self::Heartbeat),
            0x0041 => Ok(Self::HeartbeatAck),
            0x0050 => Ok(Self::GrantRefresh),
            0x0060 => Ok(Self::ConnectivityConfig),
            0x00fe => Ok(Self::ServerShutdown),
            0x00ff => Ok(Self::Error),
            _ => Err(CodecError::UnsupportedControlMessageType { value }),
        }
    }
}

/// Parsed 32-byte control-message header.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ControlHeader {
    /// Negotiated protocol version, or zero for `SERVER_HELLO`.
    pub version: ProtocolVersion,
    /// Message body schema.
    pub message_type: ControlMessageType,
    /// Type-specific flags; zero in version 0.1.
    pub flags: u16,
    /// Fixed header plus aligned header extensions.
    pub header_length: u16,
    /// Aligned body-field bytes.
    pub body_length: u32,
    /// Non-zero sender-local monotonic message identifier.
    pub message_id: u64,
    /// Triggering request ID for a response, otherwise zero.
    pub correlation_id: u64,
}

impl ControlHeader {
    /// Decodes and validates a fixed control-message header.
    ///
    /// # Errors
    ///
    /// Returns [`CodecError`] when the input is truncated or the magic,
    /// version, type, flags, header length, or message ID is invalid.
    pub fn decode(input: &[u8]) -> Result<Self, CodecError> {
        let mut cursor = ReadCursor::new(input, 0);
        if cursor.read_array::<4>("control magic")? != CONTROL_MAGIC {
            return Err(CodecError::InvalidObjectMagic {
                object: "control message",
            });
        }
        let version = ProtocolVersion {
            major: cursor.read_u8("version major")?,
            minor: cursor.read_u8("version minor")?,
        };
        let header = Self {
            version,
            message_type: ControlMessageType::try_from(cursor.read_u16("control message type")?)?,
            flags: cursor.read_u16("control flags")?,
            header_length: cursor.read_u16("control header length")?,
            body_length: cursor.read_u32("control body length")?,
            message_id: cursor.read_u64("control message ID")?,
            correlation_id: cursor.read_u64("control correlation ID")?,
        };
        header.validate()?;
        Ok(header)
    }

    /// Encodes this header into exactly the first 32 bytes of `output`.
    ///
    /// # Errors
    ///
    /// Returns [`CodecError`] when the header is invalid or `output` is too
    /// small.
    pub fn encode(self, output: &mut [u8]) -> Result<(), CodecError> {
        self.validate()?;
        let mut cursor = WriteCursor::new(output, 0);
        cursor.write_bytes(&CONTROL_MAGIC, "control magic")?;
        cursor.write_u8(self.version.major, "version major")?;
        cursor.write_u8(self.version.minor, "version minor")?;
        cursor.write_u16(self.message_type.as_u16(), "control message type")?;
        cursor.write_u16(self.flags, "control flags")?;
        cursor.write_u16(self.header_length, "control header length")?;
        cursor.write_u32(self.body_length, "control body length")?;
        cursor.write_u64(self.message_id, "control message ID")?;
        cursor.write_u64(self.correlation_id, "control correlation ID")?;
        Ok(())
    }

    /// Validates all stateless control-header invariants through version 0.2.
    ///
    /// Message sequence continuity, direction, outstanding correlations, and
    /// connection state remain higher-layer responsibilities.
    ///
    /// # Errors
    ///
    /// Returns [`CodecError`] for an invalid negotiation/operational version,
    /// a message unavailable in that version, non-zero flags, an unaligned or
    /// bounded header length, or message ID zero. `SERVER_HELLO` additionally
    /// requires ID 1 and correlation zero.
    pub fn validate(self) -> Result<(), CodecError> {
        let negotiation = self.message_type == ControlMessageType::ServerHello;
        let version_supported = if negotiation {
            self.version.major == 0 && self.version.minor == 0
        } else {
            matches!(self.version, ProtocolVersion::V0_1 | ProtocolVersion::V0_2)
        };
        if !version_supported {
            return Err(CodecError::UnsupportedVersion {
                major: self.version.major,
                minor: self.version.minor,
            });
        }
        if !negotiation && self.version < self.message_type.minimum_version() {
            return Err(CodecError::UnsupportedControlMessageType {
                value: self.message_type.as_u16(),
            });
        }
        if self.flags != 0 {
            return Err(CodecError::ReservedControlFlags {
                flags: self.flags,
                allowed: 0,
            });
        }
        let header_length = usize::from(self.header_length);
        if header_length < CONTROL_HEADER_LENGTH {
            return Err(CodecError::HeaderTooShort {
                actual: header_length,
                minimum: CONTROL_HEADER_LENGTH,
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
        if self.message_id == 0 {
            return Err(CodecError::ZeroField {
                field: "control message ID",
            });
        }
        if self.message_type == ControlMessageType::ServerHello {
            if self.message_id != 1 {
                return Err(CodecError::ValueOutOfRange {
                    field: "SERVER_HELLO message ID",
                    actual: self.message_id,
                    minimum: 1,
                    maximum: 1,
                });
            }
            if self.correlation_id != 0 {
                return Err(CodecError::ValueOutOfRange {
                    field: "SERVER_HELLO correlation ID",
                    actual: self.correlation_id,
                    minimum: 0,
                    maximum: 0,
                });
            }
        }
        Ok(())
    }
}

/// Registered control body field type through version 0.2.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
#[repr(u16)]
pub enum ControlFieldType {
    /// Ordered supported version and suite entries.
    SupportedVersions = 0x8001,
    /// One selected version and suite entry.
    SelectedVersion = 0x8002,
    /// Fresh controller nonce.
    ServerNonce = 0x8003,
    /// Fresh node nonce.
    ClientNonce = 0x8004,
    /// Controller identity.
    ControllerId = 0x8005,
    /// Controller Ed25519 public key.
    ControllerPublicKey = 0x8006,
    /// Controller Ed25519 proof signature.
    ControllerSignature = 0x8007,
    /// Node identity.
    NodeId = 0x8008,
    /// Node Ed25519 public key.
    NodePublicKey = 0x8009,
    /// Node Ed25519 proof signature.
    NodeSignature = 0x800a,
    /// Raw enrollment credential bytes.
    EnrollmentToken = 0x800b,
    /// Human-readable node display name.
    DisplayName = 0x800c,
    /// Two-byte result or error status.
    StatusCode = 0x800d,
    /// Bounded human-readable status text.
    StatusMessage = 0x800e,
    /// Non-zero controller epoch.
    ControllerEpoch = 0x800f,
    /// Non-zero virtual network identifier.
    NetworkId = 0x8010,
    /// Raw network join credential bytes.
    JoinToken = 0x8011,
    /// Signed 240-byte membership grant.
    MembershipGrant = 0x8012,
    /// Canonical 64-byte network policy.
    NetworkPolicy = 0x8013,
    /// Non-zero peer snapshot revision.
    SnapshotRevision = 0x8014,
    /// Nested peer list.
    PeerList = 0x8015,
    /// One nested peer record.
    PeerRecord = 0x8016,
    /// One peer delta operation.
    DeltaOperation = 0x8017,
    /// Nested numeric endpoint set.
    EndpointSet = 0x8018,
    /// Non-zero heartbeat counter.
    HeartbeatCounter = 0x8019,
    /// Nested per-network revision list.
    NetworkRevisions = 0x801a,
    /// Controller Unix time in seconds.
    ServerTime = 0x801b,
    /// Retry delay in milliseconds.
    RetryAfterMs = 0x801c,
    /// Graceful shutdown Unix deadline.
    ShutdownDeadline = 0x801d,
    /// Monotonic deployment connectivity-configuration revision.
    ConnectivityConfigRevision = 0x801e,
    /// Complete version 0.2 local connectivity generation.
    ConnectivityGeneration = 0x801f,
    /// Version 0.2 peer connectivity list.
    ConnectivityList = 0x8020,
    /// One version 0.2 peer connectivity record.
    ConnectivityRecord = 0x8021,
    /// Version 0.2 STUN server list.
    StunServerList = 0x8022,
    /// Version 0.2 relay service and credential list.
    RelayServiceList = 0x8023,
}

impl ControlFieldType {
    /// Returns the canonical critical field type.
    #[must_use]
    pub const fn as_u16(self) -> u16 {
        self as u16
    }

    const fn minimum_version(self) -> ProtocolVersion {
        match self {
            Self::ConnectivityConfigRevision
            | Self::ConnectivityGeneration
            | Self::ConnectivityList
            | Self::ConnectivityRecord
            | Self::StunServerList
            | Self::RelayServiceList => ProtocolVersion::V0_2,
            _ => ProtocolVersion::V0_1,
        }
    }
}

impl TryFrom<u16> for ControlFieldType {
    type Error = CodecError;

    fn try_from(value: u16) -> Result<Self, Self::Error> {
        match value {
            0x8001 => Ok(Self::SupportedVersions),
            0x8002 => Ok(Self::SelectedVersion),
            0x8003 => Ok(Self::ServerNonce),
            0x8004 => Ok(Self::ClientNonce),
            0x8005 => Ok(Self::ControllerId),
            0x8006 => Ok(Self::ControllerPublicKey),
            0x8007 => Ok(Self::ControllerSignature),
            0x8008 => Ok(Self::NodeId),
            0x8009 => Ok(Self::NodePublicKey),
            0x800a => Ok(Self::NodeSignature),
            0x800b => Ok(Self::EnrollmentToken),
            0x800c => Ok(Self::DisplayName),
            0x800d => Ok(Self::StatusCode),
            0x800e => Ok(Self::StatusMessage),
            0x800f => Ok(Self::ControllerEpoch),
            0x8010 => Ok(Self::NetworkId),
            0x8011 => Ok(Self::JoinToken),
            0x8012 => Ok(Self::MembershipGrant),
            0x8013 => Ok(Self::NetworkPolicy),
            0x8014 => Ok(Self::SnapshotRevision),
            0x8015 => Ok(Self::PeerList),
            0x8016 => Ok(Self::PeerRecord),
            0x8017 => Ok(Self::DeltaOperation),
            0x8018 => Ok(Self::EndpointSet),
            0x8019 => Ok(Self::HeartbeatCounter),
            0x801a => Ok(Self::NetworkRevisions),
            0x801b => Ok(Self::ServerTime),
            0x801c => Ok(Self::RetryAfterMs),
            0x801d => Ok(Self::ShutdownDeadline),
            0x801e => Ok(Self::ConnectivityConfigRevision),
            0x801f => Ok(Self::ConnectivityGeneration),
            0x8020 => Ok(Self::ConnectivityList),
            0x8021 => Ok(Self::ConnectivityRecord),
            0x8022 => Ok(Self::StunServerList),
            0x8023 => Ok(Self::RelayServiceList),
            _ => Err(CodecError::UnknownCriticalControlField {
                field_type: value,
                offset: 0,
            }),
        }
    }
}

/// Borrowed control body field value.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct ControlFieldRef<'a> {
    raw_type: u16,
    value: &'a [u8],
}

impl<'a> ControlFieldRef<'a> {
    /// Creates and validates one registered control body field.
    ///
    /// # Errors
    ///
    /// Returns [`CodecError`] when the field value has an invalid width,
    /// enum, text encoding, non-zero requirement, or embedded signed object.
    pub fn new(field_type: ControlFieldType, value: &'a [u8]) -> Result<Self, CodecError> {
        validate_control_field_value(field_type, value)?;
        Ok(Self {
            raw_type: field_type.as_u16(),
            value,
        })
    }

    /// Returns the raw 16-bit type, including its critical bit.
    #[must_use]
    pub const fn raw_type(self) -> u16 {
        self.raw_type
    }

    /// Returns the registered type, or `None` for an unknown non-critical field.
    #[must_use]
    pub fn field_type(self) -> Option<ControlFieldType> {
        ControlFieldType::try_from(self.raw_type).ok()
    }

    /// Returns whether the critical bit is set.
    #[must_use]
    pub const fn is_critical(self) -> bool {
        self.raw_type & CRITICAL_CONTROL_FIELD_BIT != 0
    }

    /// Borrows the field value without its prefix or padding.
    #[must_use]
    pub const fn value(self) -> &'a [u8] {
        self.value
    }

    /// Returns the encoded prefix, value, and padding length.
    ///
    /// # Errors
    ///
    /// Returns [`CodecError::IntegerOverflow`] when the aligned size cannot be
    /// represented by the platform.
    pub fn encoded_len(self) -> Result<usize, CodecError> {
        padded_control_field_length(self.value.len())
    }
}

impl fmt::Debug for ControlFieldRef<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ControlFieldRef")
            .field("raw_type", &format_args!("0x{:04x}", self.raw_type))
            .field("value_length", &self.value.len())
            .finish_non_exhaustive()
    }
}

/// Iterator over a validated control body field block.
#[derive(Clone)]
pub struct ControlFieldIter<'a> {
    bytes: &'a [u8],
    position: usize,
}

impl<'a> ControlFieldIter<'a> {
    const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, position: 0 }
    }

    /// Validates a complete field block and returns its iterator.
    ///
    /// Error offsets are relative to the beginning of `bytes`.
    ///
    /// # Errors
    ///
    /// Returns [`CodecError`] for a malformed type, order, length, padding, or
    /// registered field value.
    pub fn decode(bytes: &'a [u8]) -> Result<Self, CodecError> {
        validate_control_field_block(bytes, 0)?;
        Ok(Self::new(bytes))
    }
}

impl<'a> Iterator for ControlFieldIter<'a> {
    type Item = ControlFieldRef<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        let prefix_end = self.position.checked_add(CONTROL_FIELD_PREFIX_LENGTH)?;
        let prefix = self.bytes.get(self.position..prefix_end)?;
        let raw_type = u16::from_be_bytes([prefix[0], prefix[1]]);
        let value_length = usize::from(u16::from_be_bytes([prefix[2], prefix[3]]));
        let value_end = prefix_end.checked_add(value_length)?;
        let value = self.bytes.get(prefix_end..value_end)?;
        let encoded_length = padded_control_field_length(value_length).ok()?;
        self.position = self.position.checked_add(encoded_length)?;
        Some(ControlFieldRef { raw_type, value })
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        let remaining = self.bytes.len().saturating_sub(self.position);
        (0, Some(remaining / CONTROL_FIELD_PREFIX_LENGTH))
    }
}

impl std::iter::FusedIterator for ControlFieldIter<'_> {}

/// Returns the exact encoded length of ordered control body fields.
///
/// # Errors
///
/// Returns [`CodecError`] for duplicate/out-of-order fields or size overflow.
pub fn control_fields_encoded_len(fields: &[ControlFieldRef<'_>]) -> Result<usize, CodecError> {
    validate_control_field_order(fields, 0)?;
    fields.iter().try_fold(0_usize, |total, field| {
        total
            .checked_add(field.encoded_len()?)
            .ok_or(CodecError::IntegerOverflow {
                field: "control body",
            })
    })
}

/// Encodes ordered control body fields and zeroes every padding byte.
///
/// The returned value is the number of bytes written.
///
/// # Errors
///
/// Returns [`CodecError`] for an invalid field, order, length, arithmetic
/// overflow, or insufficient output capacity.
pub fn encode_control_fields(
    fields: &[ControlFieldRef<'_>],
    output: &mut [u8],
) -> Result<usize, CodecError> {
    encode_control_fields_at(fields, output, 0)
}

/// Borrowed, structurally validated control message without its outer prefix.
#[derive(Clone)]
pub struct ControlMessageView<'a> {
    header: ControlHeader,
    extension_bytes: &'a [u8],
    body: &'a [u8],
}

impl<'a> ControlMessageView<'a> {
    /// Decodes one complete control message after the outer length prefix.
    ///
    /// # Errors
    ///
    /// Returns [`CodecError`] when the record bound, header, extension block,
    /// body length, field block, or trailing bytes are invalid.
    pub fn decode(record: &'a [u8]) -> Result<Self, CodecError> {
        validate_control_record_bound(record.len())?;
        let header = ControlHeader::decode(record)?;
        let header_length = usize::from(header.header_length);
        let body_length =
            usize::try_from(header.body_length).map_err(|_| CodecError::IntegerOverflow {
                field: "control body length",
            })?;
        let expected_length =
            header_length
                .checked_add(body_length)
                .ok_or(CodecError::IntegerOverflow {
                    field: "control record length",
                })?;
        validate_record_length(record.len(), expected_length, "control message")?;
        let extension_bytes =
            record
                .get(CONTROL_HEADER_LENGTH..header_length)
                .ok_or(CodecError::Truncated {
                    field: "control header extensions",
                    offset: CONTROL_HEADER_LENGTH,
                    needed: header_length.saturating_sub(CONTROL_HEADER_LENGTH),
                    remaining: record.len().saturating_sub(CONTROL_HEADER_LENGTH),
                })?;
        validate_extension_block(extension_bytes, CONTROL_HEADER_LENGTH)?;
        let body = record
            .get(header_length..expected_length)
            .ok_or(CodecError::Truncated {
                field: "control body",
                offset: header_length,
                needed: body_length,
                remaining: record.len().saturating_sub(header_length),
            })?;
        validate_control_field_block(body, header_length)?;
        validate_control_message_fields(
            header.version,
            header.message_type,
            ControlFieldIter::new(body),
        )?;
        Ok(Self {
            header,
            extension_bytes,
            body,
        })
    }

    /// Returns the parsed fixed header.
    #[must_use]
    pub const fn header(&self) -> ControlHeader {
        self.header
    }

    /// Iterates over validated header extensions.
    #[must_use]
    pub const fn extensions(&self) -> ExtensionIter<'a> {
        ExtensionIter::new(self.extension_bytes)
    }

    /// Borrows the exact aligned body bytes.
    #[must_use]
    pub const fn body(&self) -> &'a [u8] {
        self.body
    }

    /// Iterates over validated body fields.
    #[must_use]
    pub const fn fields(&self) -> ControlFieldIter<'a> {
        ControlFieldIter::new(self.body)
    }

    /// Returns the exact message length without the outer prefix.
    #[must_use]
    pub fn encoded_len(&self) -> usize {
        usize::from(self.header.header_length) + self.body.len()
    }
}

/// Decodes and bounds-checks a four-byte outer control-record prefix.
///
/// # Errors
///
/// Returns [`CodecError`] when `prefix` is not exactly four bytes or the
/// declared message length is outside 32 through 1,048,576 bytes.
pub fn decode_control_record_length(prefix: &[u8]) -> Result<usize, CodecError> {
    validate_record_length(
        prefix.len(),
        CONTROL_RECORD_PREFIX_LENGTH,
        "control record prefix",
    )?;
    let bytes = <[u8; CONTROL_RECORD_PREFIX_LENGTH]>::try_from(prefix).map_err(|_| {
        CodecError::LengthMismatch {
            field: "control record prefix",
            expected: CONTROL_RECORD_PREFIX_LENGTH,
            actual: prefix.len(),
        }
    })?;
    let length =
        usize::try_from(u32::from_be_bytes(bytes)).map_err(|_| CodecError::IntegerOverflow {
            field: "control record length",
        })?;
    validate_control_record_bound(length)?;
    Ok(length)
}

/// Encodes a bounded message length into a four-byte outer prefix.
///
/// # Errors
///
/// Returns [`CodecError`] when `record_length` is outside protocol bounds,
/// cannot fit `u32`, or `output` is too small.
pub fn encode_control_record_length(
    record_length: usize,
    output: &mut [u8],
) -> Result<(), CodecError> {
    validate_control_record_bound(record_length)?;
    let wire_length = u32::try_from(record_length).map_err(|_| CodecError::IntegerOverflow {
        field: "control record length",
    })?;
    let mut cursor = WriteCursor::new(output, 0);
    cursor.write_u32(wire_length, "control record length")
}

/// Encodes one complete control message without its outer length prefix.
///
/// The returned value is the exact number of message bytes written.
///
/// # Errors
///
/// Returns [`CodecError`] when the header, extensions, fields, or declared
/// lengths are inconsistent, arithmetic overflows, or `output` is too small.
pub fn encode_control_message(
    header: ControlHeader,
    header_extensions: &[ExtensionRef<'_>],
    fields: &[ControlFieldRef<'_>],
    output: &mut [u8],
) -> Result<usize, CodecError> {
    header.validate()?;
    validate_control_message_fields(header.version, header.message_type, fields.iter().copied())?;
    let extension_length = extensions_encoded_len(header_extensions)?;
    let expected_header_length =
        CONTROL_HEADER_LENGTH
            .checked_add(extension_length)
            .ok_or(CodecError::IntegerOverflow {
                field: "control header length",
            })?;
    if usize::from(header.header_length) != expected_header_length {
        return Err(CodecError::LengthMismatch {
            field: "control header",
            expected: expected_header_length,
            actual: usize::from(header.header_length),
        });
    }
    let expected_body_length = control_fields_encoded_len(fields)?;
    let declared_body_length =
        usize::try_from(header.body_length).map_err(|_| CodecError::IntegerOverflow {
            field: "control body length",
        })?;
    if declared_body_length != expected_body_length {
        return Err(CodecError::LengthMismatch {
            field: "control body",
            expected: expected_body_length,
            actual: declared_body_length,
        });
    }
    let encoded_length = expected_header_length
        .checked_add(expected_body_length)
        .ok_or(CodecError::IntegerOverflow {
            field: "control message length",
        })?;
    validate_control_record_bound(encoded_length)?;
    if output.len() < encoded_length {
        return Err(CodecError::OutputTooSmall {
            field: "control message",
            offset: 0,
            needed: encoded_length,
            remaining: output.len(),
        });
    }

    let output_length = output.len();
    let message = output
        .get_mut(..encoded_length)
        .ok_or(CodecError::OutputTooSmall {
            field: "control message",
            offset: 0,
            needed: encoded_length,
            remaining: output_length,
        })?;
    let message_length = message.len();
    let fixed_header =
        message
            .get_mut(..CONTROL_HEADER_LENGTH)
            .ok_or(CodecError::OutputTooSmall {
                field: "control fixed header",
                offset: 0,
                needed: CONTROL_HEADER_LENGTH,
                remaining: message_length,
            })?;
    header.encode(fixed_header)?;
    let extension_output = message
        .get_mut(CONTROL_HEADER_LENGTH..expected_header_length)
        .ok_or(CodecError::OutputTooSmall {
            field: "control header extensions",
            offset: CONTROL_HEADER_LENGTH,
            needed: extension_length,
            remaining: message_length.saturating_sub(CONTROL_HEADER_LENGTH),
        })?;
    encode_extension_block_at(header_extensions, extension_output, CONTROL_HEADER_LENGTH)?;
    let body_output = message
        .get_mut(expected_header_length..encoded_length)
        .ok_or(CodecError::OutputTooSmall {
            field: "control body",
            offset: expected_header_length,
            needed: expected_body_length,
            remaining: message_length.saturating_sub(expected_header_length),
        })?;
    encode_control_fields_at(fields, body_output, expected_header_length)?;
    Ok(encoded_length)
}

fn validate_control_record_bound(length: usize) -> Result<(), CodecError> {
    if !(CONTROL_HEADER_LENGTH..=MAX_CONTROL_RECORD_LENGTH).contains(&length) {
        return Err(CodecError::ValueOutOfRange {
            field: "control record length",
            actual: u64::try_from(length).unwrap_or(u64::MAX),
            minimum: u64::try_from(CONTROL_HEADER_LENGTH).unwrap_or(u64::MAX),
            maximum: u64::try_from(MAX_CONTROL_RECORD_LENGTH).unwrap_or(u64::MAX),
        });
    }
    Ok(())
}

fn validate_control_field_block(bytes: &[u8], base_offset: usize) -> Result<(), CodecError> {
    let mut cursor = ReadCursor::new(bytes, base_offset);
    let mut previous = None;
    while cursor.position() < bytes.len() {
        let field_offset = base_offset.saturating_add(cursor.position());
        let raw_type = cursor.read_u16("control field type")?;
        if raw_type == 0 {
            return Err(CodecError::InvalidControlFieldType {
                offset: field_offset,
            });
        }
        if let Some(previous_type) = previous {
            if raw_type <= previous_type {
                return Err(CodecError::ControlFieldsOutOfOrder {
                    previous: previous_type,
                    current: raw_type,
                    offset: field_offset,
                });
            }
        }
        previous = Some(raw_type);
        let value_length = usize::from(cursor.read_u16("control field length")?);
        let value = cursor.read_slice(value_length, "control field value")?;
        let encoded_length = padded_control_field_length(value_length)?;
        let padding_length = encoded_length
            .checked_sub(CONTROL_FIELD_PREFIX_LENGTH + value_length)
            .ok_or(CodecError::IntegerOverflow {
                field: "control field padding",
            })?;
        let padding_offset = base_offset.saturating_add(cursor.position());
        let padding = cursor.read_slice(padding_length, "control field padding")?;
        if padding.iter().any(|byte| *byte != 0) {
            return Err(CodecError::NonZeroReserved {
                field: "control field padding",
                offset: padding_offset,
            });
        }
        if raw_type & CRITICAL_CONTROL_FIELD_BIT != 0 {
            let field_type = ControlFieldType::try_from(raw_type).map_err(|_| {
                CodecError::UnknownCriticalControlField {
                    field_type: raw_type,
                    offset: field_offset,
                }
            })?;
            validate_control_field_value(field_type, value)?;
        }
    }
    Ok(())
}

fn validate_control_field_order(
    fields: &[ControlFieldRef<'_>],
    base_offset: usize,
) -> Result<(), CodecError> {
    let mut previous = None;
    let mut offset = base_offset;
    for field in fields {
        if let Some(previous_type) = previous {
            if field.raw_type <= previous_type {
                return Err(CodecError::ControlFieldsOutOfOrder {
                    previous: previous_type,
                    current: field.raw_type,
                    offset,
                });
            }
        }
        previous = Some(field.raw_type);
        offset = offset
            .checked_add(field.encoded_len()?)
            .ok_or(CodecError::IntegerOverflow {
                field: "control field offset",
            })?;
    }
    Ok(())
}

fn encode_control_fields_at(
    fields: &[ControlFieldRef<'_>],
    output: &mut [u8],
    base_offset: usize,
) -> Result<usize, CodecError> {
    validate_control_field_order(fields, base_offset)?;
    let required = control_fields_encoded_len(fields)?;
    if output.len() < required {
        return Err(CodecError::OutputTooSmall {
            field: "control body fields",
            offset: base_offset,
            needed: required,
            remaining: output.len(),
        });
    }
    let mut cursor = WriteCursor::new(output, base_offset);
    for field in fields {
        if let Some(field_type) = field.field_type() {
            validate_control_field_value(field_type, field.value)?;
        }
        let value_length =
            u16::try_from(field.value.len()).map_err(|_| CodecError::LengthMismatch {
                field: "control field value",
                expected: usize::from(u16::MAX),
                actual: field.value.len(),
            })?;
        cursor.write_u16(field.raw_type, "control field type")?;
        cursor.write_u16(value_length, "control field length")?;
        cursor.write_bytes(field.value, "control field value")?;
        let padding_length = field
            .encoded_len()?
            .checked_sub(CONTROL_FIELD_PREFIX_LENGTH + field.value.len())
            .ok_or(CodecError::IntegerOverflow {
                field: "control field padding",
            })?;
        cursor.write_bytes(&[0_u8; 3][..padding_length], "control field padding")?;
    }
    Ok(cursor.position())
}

fn padded_control_field_length(value_length: usize) -> Result<usize, CodecError> {
    let unpadded = CONTROL_FIELD_PREFIX_LENGTH
        .checked_add(value_length)
        .ok_or(CodecError::IntegerOverflow {
            field: "control field length",
        })?;
    unpadded
        .checked_add(3)
        .map(|length| length & !3)
        .ok_or(CodecError::IntegerOverflow {
            field: "control field alignment",
        })
}

fn validate_control_field_value(
    field_type: ControlFieldType,
    value: &[u8],
) -> Result<(), CodecError> {
    match field_type {
        ControlFieldType::PeerList => {
            let _peers = PeerListView::decode(value)?;
            Ok(())
        }
        ControlFieldType::PeerRecord => {
            let _peer = PeerRecordView::decode(value)?;
            Ok(())
        }
        ControlFieldType::SupportedVersions => {
            let _versions = VersionListView::decode(value)?;
            Ok(())
        }
        ControlFieldType::SelectedVersion => {
            let _version = VersionEntry::decode(value)?;
            Ok(())
        }
        ControlFieldType::ServerNonce | ControlFieldType::ClientNonce => {
            validate_exact_width(value, 32, "control nonce")
        }
        ControlFieldType::ControllerId | ControlFieldType::NodeId => {
            validate_exact_width(value, 16, "control identity")
        }
        ControlFieldType::ControllerPublicKey | ControlFieldType::NodePublicKey => {
            validate_exact_width(value, 32, "control public key")
        }
        ControlFieldType::ControllerSignature | ControlFieldType::NodeSignature => {
            validate_exact_width(value, 64, "control signature")
        }
        ControlFieldType::EnrollmentToken | ControlFieldType::JoinToken => {
            validate_exact_width(value, 32, "control token")
        }
        ControlFieldType::DisplayName => validate_text(value, 1, 64, "display name"),
        ControlFieldType::StatusCode => validate_exact_width(value, 2, "status code"),
        ControlFieldType::StatusMessage => validate_text(value, 0, 256, "status message"),
        ControlFieldType::ControllerEpoch => validate_nonzero_u64(value, "controller epoch"),
        ControlFieldType::NetworkId => {
            validate_exact_width(value, 16, "network ID")?;
            let bytes = <[u8; 16]>::try_from(value).map_err(|_| CodecError::LengthMismatch {
                field: "network ID",
                expected: 16,
                actual: value.len(),
            })?;
            if NetworkId::from_bytes(bytes).is_zero() {
                return Err(CodecError::ZeroField {
                    field: "network ID",
                });
            }
            Ok(())
        }
        ControlFieldType::MembershipGrant => {
            let _view = MembershipGrantView::decode(value)?;
            Ok(())
        }
        ControlFieldType::NetworkPolicy => {
            let _policy = NetworkPolicy::decode(value)?;
            Ok(())
        }
        ControlFieldType::SnapshotRevision => validate_nonzero_u64(value, "snapshot revision"),
        ControlFieldType::DeltaOperation => {
            validate_exact_width(value, 1, "delta operation")?;
            if !(1..=4).contains(&value[0]) {
                return Err(CodecError::InvalidEnumValue {
                    field: "delta operation",
                    value: u64::from(value[0]),
                });
            }
            Ok(())
        }
        ControlFieldType::EndpointSet => {
            let _endpoints = EndpointSetView::decode(value)?;
            Ok(())
        }
        ControlFieldType::HeartbeatCounter => validate_nonzero_u64(value, "heartbeat counter"),
        ControlFieldType::NetworkRevisions => {
            let _revisions = NetworkRevisionListView::decode(value)?;
            Ok(())
        }
        ControlFieldType::ServerTime | ControlFieldType::ShutdownDeadline => {
            validate_exact_width(value, 8, "Unix time")
        }
        ControlFieldType::RetryAfterMs => validate_retry_after(value),
        ControlFieldType::ConnectivityConfigRevision
        | ControlFieldType::ConnectivityGeneration
        | ControlFieldType::ConnectivityList
        | ControlFieldType::ConnectivityRecord
        | ControlFieldType::StunServerList
        | ControlFieldType::RelayServiceList => {
            validate_connectivity_control_field_value(field_type, value)
        }
    }
}

fn validate_retry_after(value: &[u8]) -> Result<(), CodecError> {
    validate_exact_width(value, 4, "retry after milliseconds")?;
    let bytes = <[u8; 4]>::try_from(value).map_err(|_| CodecError::LengthMismatch {
        field: "retry after milliseconds",
        expected: 4,
        actual: value.len(),
    })?;
    let retry = u32::from_be_bytes(bytes);
    if retry != 0 && !(100..=60_000).contains(&retry) {
        return Err(CodecError::ValueOutOfRange {
            field: "retry after milliseconds",
            actual: u64::from(retry),
            minimum: 100,
            maximum: 60_000,
        });
    }
    Ok(())
}

fn validate_connectivity_control_field_value(
    field_type: ControlFieldType,
    value: &[u8],
) -> Result<(), CodecError> {
    match field_type {
        ControlFieldType::ConnectivityConfigRevision => {
            validate_nonzero_u64(value, "connectivity configuration revision")
        }
        ControlFieldType::ConnectivityGeneration => {
            ConnectivityGenerationView::decode(value).map(|_| ())
        }
        ControlFieldType::ConnectivityList => ConnectivityListView::decode(value).map(|_| ()),
        ControlFieldType::ConnectivityRecord => ConnectivityRecordView::decode(value).map(|_| ()),
        ControlFieldType::StunServerList => StunServerListView::decode(value).map(|_| ()),
        ControlFieldType::RelayServiceList => RelayServiceListView::decode(value).map(|_| ()),
        _ => Err(CodecError::InvalidEnumValue {
            field: "connectivity control field",
            value: u64::from(field_type.as_u16()),
        }),
    }
}

fn validate_control_message_fields<'a>(
    version: ProtocolVersion,
    message_type: ControlMessageType,
    fields: impl IntoIterator<Item = ControlFieldRef<'a>>,
) -> Result<(), CodecError> {
    let schema_version = if message_type == ControlMessageType::ServerHello {
        ProtocolVersion::V0_1
    } else {
        version
    };
    let mut present = 0_u64;
    let mut delta_operation = None;
    let mut delta_node_id = None;
    let mut connectivity_node_id = None;
    for field in fields {
        let Some(field_type) = field.field_type() else {
            continue;
        };
        if !field_allowed(schema_version, message_type, field_type) {
            return Err(CodecError::UnexpectedControlField {
                message_type: message_type.as_u16(),
                field_type: field_type.as_u16(),
            });
        }
        present |= field_bit(field_type);
        if field_type == ControlFieldType::DeltaOperation {
            delta_operation = field.value.first().copied();
        } else if field_type == ControlFieldType::NodeId {
            delta_node_id = Some(decode_control_node_id(field.value)?);
        } else if field_type == ControlFieldType::ConnectivityRecord {
            connectivity_node_id = Some(ConnectivityRecordView::decode(field.value)?.node_id());
        }
    }

    for field_type in ALL_CONTROL_FIELDS {
        if field_required(schema_version, message_type, field_type)
            && present & field_bit(field_type) == 0
        {
            return Err(CodecError::MissingControlField {
                message_type: message_type.as_u16(),
                field_type: field_type.as_u16(),
            });
        }
    }

    if message_type == ControlMessageType::PeerDelta {
        validate_peer_delta_fields(
            schema_version,
            present,
            delta_operation,
            delta_node_id,
            connectivity_node_id,
        )?;
    }
    Ok(())
}

fn validate_peer_delta_fields(
    version: ProtocolVersion,
    present: u64,
    operation: Option<u8>,
    node_id: Option<NodeId>,
    connectivity_node_id: Option<NodeId>,
) -> Result<(), CodecError> {
    let has_node = present & field_bit(ControlFieldType::NodeId) != 0;
    let has_peer = present & field_bit(ControlFieldType::PeerRecord) != 0;
    let has_connectivity = present & field_bit(ControlFieldType::ConnectivityRecord) != 0;
    let valid_shape = match operation {
        Some(1) => !has_node && has_peer && !has_connectivity,
        Some(2 | 4) => has_node && !has_peer && !has_connectivity,
        Some(3) => !has_peer && has_connectivity,
        _ => true,
    };
    if !valid_shape {
        let detail = match operation {
            Some(1) => "add/replace requires PEER_RECORD and forbids NODE_ID",
            Some(2) => "remove requires NODE_ID and forbids PEER_RECORD",
            Some(3) => "connectivity replacement requires CONNECTIVITY_RECORD and optional NODE_ID",
            Some(4) => "connectivity withdrawal requires NODE_ID only",
            _ => "unknown peer delta operation",
        };
        return Err(CodecError::InvalidControlFieldCombination {
            message_type: ControlMessageType::PeerDelta.as_u16(),
            detail,
        });
    }
    if version == ProtocolVersion::V0_1 && matches!(operation, Some(3 | 4)) {
        return Err(CodecError::InvalidControlFieldCombination {
            message_type: ControlMessageType::PeerDelta.as_u16(),
            detail: "version 0.1 permits only peer delta operations 1 and 2",
        });
    }
    if operation == Some(3) && node_id.is_some() && node_id != connectivity_node_id {
        return Err(CodecError::InconsistentField {
            context: "peer connectivity delta",
            field: "node ID",
        });
    }
    Ok(())
}

fn decode_control_node_id(value: &[u8]) -> Result<NodeId, CodecError> {
    let bytes = <[u8; 16]>::try_from(value).map_err(|_| CodecError::LengthMismatch {
        field: "node ID",
        expected: 16,
        actual: value.len(),
    })?;
    Ok(NodeId::from_bytes(bytes))
}

const ALL_CONTROL_FIELDS: [ControlFieldType; 35] = [
    ControlFieldType::SupportedVersions,
    ControlFieldType::SelectedVersion,
    ControlFieldType::ServerNonce,
    ControlFieldType::ClientNonce,
    ControlFieldType::ControllerId,
    ControlFieldType::ControllerPublicKey,
    ControlFieldType::ControllerSignature,
    ControlFieldType::NodeId,
    ControlFieldType::NodePublicKey,
    ControlFieldType::NodeSignature,
    ControlFieldType::EnrollmentToken,
    ControlFieldType::DisplayName,
    ControlFieldType::StatusCode,
    ControlFieldType::StatusMessage,
    ControlFieldType::ControllerEpoch,
    ControlFieldType::NetworkId,
    ControlFieldType::JoinToken,
    ControlFieldType::MembershipGrant,
    ControlFieldType::NetworkPolicy,
    ControlFieldType::SnapshotRevision,
    ControlFieldType::PeerList,
    ControlFieldType::PeerRecord,
    ControlFieldType::DeltaOperation,
    ControlFieldType::EndpointSet,
    ControlFieldType::HeartbeatCounter,
    ControlFieldType::NetworkRevisions,
    ControlFieldType::ServerTime,
    ControlFieldType::RetryAfterMs,
    ControlFieldType::ShutdownDeadline,
    ControlFieldType::ConnectivityConfigRevision,
    ControlFieldType::ConnectivityGeneration,
    ControlFieldType::ConnectivityList,
    ControlFieldType::ConnectivityRecord,
    ControlFieldType::StunServerList,
    ControlFieldType::RelayServiceList,
];

const fn field_bit(field_type: ControlFieldType) -> u64 {
    let index = field_type.as_u16() - ControlFieldType::SupportedVersions.as_u16();
    1_u64 << index
}

fn field_allowed(
    version: ProtocolVersion,
    message_type: ControlMessageType,
    field_type: ControlFieldType,
) -> bool {
    if version < field_type.minimum_version() {
        return false;
    }
    field_required(version, message_type, field_type)
        || matches!(
            (message_type, field_type),
            (
                ControlMessageType::NodeAuth,
                ControlFieldType::EnrollmentToken | ControlFieldType::DisplayName
            ) | (
                ControlMessageType::AuthResult
                    | ControlMessageType::JoinResult
                    | ControlMessageType::LeaveResult
                    | ControlMessageType::EndpointResult
                    | ControlMessageType::ConnectivityResult
                    | ControlMessageType::Error,
                ControlFieldType::StatusMessage
            ) | (ControlMessageType::JoinRequest, ControlFieldType::JoinToken)
                | (
                    ControlMessageType::JoinResult,
                    ControlFieldType::MembershipGrant
                        | ControlFieldType::NetworkPolicy
                        | ControlFieldType::SnapshotRevision
                )
                | (
                    ControlMessageType::PeerDelta,
                    ControlFieldType::NodeId
                        | ControlFieldType::PeerRecord
                        | ControlFieldType::ConnectivityRecord
                )
                | (
                    ControlMessageType::ConnectivityUpdate,
                    ControlFieldType::ConnectivityGeneration
                )
                | (
                    ControlMessageType::AuthResult,
                    ControlFieldType::ConnectivityConfigRevision
                )
                | (ControlMessageType::Error, ControlFieldType::RetryAfterMs)
        )
}

fn field_required(
    version: ProtocolVersion,
    message_type: ControlMessageType,
    field_type: ControlFieldType,
) -> bool {
    matches!(
        (message_type, field_type),
        (
            ControlMessageType::ServerHello,
            ControlFieldType::SupportedVersions
                | ControlFieldType::ServerNonce
                | ControlFieldType::ControllerId
                | ControlFieldType::ControllerPublicKey
                | ControlFieldType::ServerTime
        ) | (
            ControlMessageType::ClientHello,
            ControlFieldType::SelectedVersion
                | ControlFieldType::ClientNonce
                | ControlFieldType::NodeId
                | ControlFieldType::NodePublicKey
        ) | (
            ControlMessageType::ServerProof,
            ControlFieldType::ControllerSignature
        ) | (
            ControlMessageType::NodeAuth,
            ControlFieldType::NodeSignature
        ) | (
            ControlMessageType::AuthResult
                | ControlMessageType::JoinResult
                | ControlMessageType::LeaveResult
                | ControlMessageType::EndpointResult
                | ControlMessageType::ConnectivityResult
                | ControlMessageType::Error,
            ControlFieldType::StatusCode
        ) | (
            ControlMessageType::AuthResult | ControlMessageType::HeartbeatAck,
            ControlFieldType::ServerTime
        ) | (
            ControlMessageType::JoinRequest
                | ControlMessageType::JoinResult
                | ControlMessageType::LeaveRequest
                | ControlMessageType::LeaveResult
                | ControlMessageType::EndpointUpdate
                | ControlMessageType::EndpointResult
                | ControlMessageType::ConnectivityUpdate
                | ControlMessageType::ConnectivityResult
                | ControlMessageType::PeerSnapshot
                | ControlMessageType::PeerDelta
                | ControlMessageType::SnapshotRequest
                | ControlMessageType::GrantRefresh,
            ControlFieldType::NetworkId
        ) | (
            ControlMessageType::JoinResult
                | ControlMessageType::LeaveResult
                | ControlMessageType::EndpointResult
                | ControlMessageType::ConnectivityResult
                | ControlMessageType::PeerSnapshot
                | ControlMessageType::PeerDelta
                | ControlMessageType::GrantRefresh,
            ControlFieldType::ControllerEpoch
        ) | (
            ControlMessageType::EndpointUpdate,
            ControlFieldType::EndpointSet
        ) | (
            ControlMessageType::EndpointResult
                | ControlMessageType::ConnectivityResult
                | ControlMessageType::PeerSnapshot
                | ControlMessageType::PeerDelta
                | ControlMessageType::SnapshotRequest
                | ControlMessageType::GrantRefresh,
            ControlFieldType::SnapshotRevision
        ) | (
            ControlMessageType::PeerSnapshot | ControlMessageType::GrantRefresh,
            ControlFieldType::MembershipGrant | ControlFieldType::NetworkPolicy
        ) | (ControlMessageType::PeerSnapshot, ControlFieldType::PeerList)
            | (
                ControlMessageType::PeerDelta,
                ControlFieldType::DeltaOperation
            )
            | (
                ControlMessageType::Heartbeat | ControlMessageType::HeartbeatAck,
                ControlFieldType::HeartbeatCounter | ControlFieldType::NetworkRevisions
            )
            | (
                ControlMessageType::ServerShutdown,
                ControlFieldType::StatusMessage | ControlFieldType::ShutdownDeadline
            )
            | (
                ControlMessageType::ConnectivityConfig,
                ControlFieldType::ConnectivityConfigRevision
                    | ControlFieldType::StunServerList
                    | ControlFieldType::RelayServiceList
            )
    ) || (version == ProtocolVersion::V0_2
        && message_type == ControlMessageType::PeerSnapshot
        && field_type == ControlFieldType::ConnectivityList)
}

fn validate_exact_width(
    value: &[u8],
    expected: usize,
    field: &'static str,
) -> Result<(), CodecError> {
    if value.len() != expected {
        return Err(CodecError::LengthMismatch {
            field,
            expected,
            actual: value.len(),
        });
    }
    Ok(())
}

fn validate_nonzero_u64(value: &[u8], field: &'static str) -> Result<(), CodecError> {
    validate_exact_width(value, 8, field)?;
    let bytes = <[u8; 8]>::try_from(value).map_err(|_| CodecError::LengthMismatch {
        field,
        expected: 8,
        actual: value.len(),
    })?;
    if u64::from_be_bytes(bytes) == 0 {
        return Err(CodecError::ZeroField { field });
    }
    Ok(())
}

fn validate_text(
    value: &[u8],
    minimum: usize,
    maximum: usize,
    field: &'static str,
) -> Result<(), CodecError> {
    if !(minimum..=maximum).contains(&value.len()) {
        return Err(CodecError::ValueOutOfRange {
            field,
            actual: u64::try_from(value.len()).unwrap_or(u64::MAX),
            minimum: u64::try_from(minimum).unwrap_or(u64::MAX),
            maximum: u64::try_from(maximum).unwrap_or(u64::MAX),
        });
    }
    let text = std::str::from_utf8(value).map_err(|error| CodecError::InvalidUtf8 {
        field,
        offset: error.valid_up_to(),
    })?;
    for (offset, character) in text.char_indices() {
        let codepoint = u32::from(character);
        if codepoint <= 0x1f || (0x7f..=0x9f).contains(&codepoint) {
            return Err(CodecError::InvalidTextCharacter { field, offset });
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::net::SocketAddr;

    use stella_common::{NodeId, RelayId};

    use super::{
        control_fields_encoded_len, decode_control_record_length, encode_control_fields,
        encode_control_message, encode_control_record_length, field_required, ControlFieldIter,
        ControlFieldRef, ControlFieldType, ControlHeader, ControlMessageType, ControlMessageView,
        CONTROL_HEADER_LENGTH,
    };
    use crate::{
        encode_connectivity_record, encode_relay_service_list, encode_stun_server_list, CodecError,
        ConnectivityCarrier, ConnectivityGenerationRef, ConnectivityRecordRef, ExtensionRef,
        IceCandidate, IceCandidateClass, ProtocolVersion, RelayAddress, RelayCarrierMask,
        RelayPorts, RelayServiceRef, RelayTrustRequirements, StunServer,
    };

    const NETWORK_ID: [u8; 16] = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15];
    const JOIN_TOKEN: [u8; 32] = [0x44; 32];
    const NODE_ID: [u8; 16] = [0x55; 16];
    const CONTROLLER_EPOCH: [u8; 8] = 9_u64.to_be_bytes();
    const SNAPSHOT_REVISION: [u8; 8] = 12_u64.to_be_bytes();

    fn join_header() -> ControlHeader {
        ControlHeader {
            version: ProtocolVersion::CURRENT,
            message_type: ControlMessageType::JoinRequest,
            flags: 0,
            header_length: u16::try_from(CONTROL_HEADER_LENGTH)
                .expect("control header length fits u16"),
            body_length: 56,
            message_id: 7,
            correlation_id: 0,
        }
    }

    fn join_fields() -> [ControlFieldRef<'static>; 2] {
        [
            ControlFieldRef::new(ControlFieldType::NetworkId, &NETWORK_ID)
                .expect("valid network ID"),
            ControlFieldRef::new(ControlFieldType::JoinToken, &JOIN_TOKEN)
                .expect("valid join token"),
        ]
    }

    fn peer_delta_header(body_length: usize) -> ControlHeader {
        ControlHeader {
            version: ProtocolVersion::CURRENT,
            message_type: ControlMessageType::PeerDelta,
            flags: 0,
            header_length: u16::try_from(CONTROL_HEADER_LENGTH)
                .expect("control header length fits u16"),
            body_length: u32::try_from(body_length).expect("test body length fits u32"),
            message_id: 8,
            correlation_id: 0,
        }
    }

    fn peer_delta_fields(operation: &'static [u8]) -> [ControlFieldRef<'static>; 5] {
        [
            ControlFieldRef::new(ControlFieldType::NodeId, &NODE_ID).expect("valid node ID"),
            ControlFieldRef::new(ControlFieldType::ControllerEpoch, &CONTROLLER_EPOCH)
                .expect("valid controller epoch"),
            ControlFieldRef::new(ControlFieldType::NetworkId, &NETWORK_ID)
                .expect("valid network ID"),
            ControlFieldRef::new(ControlFieldType::SnapshotRevision, &SNAPSHOT_REVISION)
                .expect("valid snapshot revision"),
            ControlFieldRef::new(ControlFieldType::DeltaOperation, operation)
                .expect("valid delta operation"),
        ]
    }

    fn connectivity_record_bytes(node_id: [u8; 16]) -> Vec<u8> {
        let candidates = [IceCandidate {
            class: IceCandidateClass::Host,
            carrier: ConnectivityCarrier::DirectUdp,
            priority: 100,
            foundation: 1,
            max_datagram_size: 1_200,
            address: SocketAddr::from(([192, 0, 2, 10], 50_000)),
            related_address: None,
            relay_id: None,
        }];
        let generation = ConnectivityGenerationRef::new(
            1,
            2,
            1_000,
            1_600,
            b"Abcd1234",
            b"Abcdefghijklmnopqrstuv",
            &candidates,
        )
        .expect("valid connectivity generation");
        let record = ConnectivityRecordRef::new(NodeId::from_bytes(node_id), generation)
            .expect("valid connectivity record");
        let mut encoded = vec![0; record.encoded_len().expect("connectivity record length")];
        encode_connectivity_record(record, &mut encoded).expect("encode connectivity record");
        encoded
    }

    fn connectivity_config_values() -> (Vec<u8>, Vec<u8>) {
        let stun_servers = [StunServer {
            priority: 0,
            address: SocketAddr::from(([192, 0, 2, 20], 3_478)),
        }];
        let mut stun_bytes = vec![0; 28];
        encode_stun_server_list(&stun_servers, &mut stun_bytes).expect("encode STUN list");

        let addresses = [RelayAddress {
            priority: 0,
            address: "192.0.2.30".parse().expect("relay address"),
        }];
        let service = RelayServiceRef {
            relay_id: RelayId::from_bytes([1; 16]),
            carriers: RelayCarrierMask::TURN_UDP,
            priority: 0,
            max_datagram_size: 1_200,
            allocation_lifetime_seconds: 600,
            idle_timeout_seconds: 120,
            credential_issued_at: 1_000,
            credential_expires_at: 1_600,
            hostname: "",
            tls_server_name: "",
            credential_username: b"node 1",
            credential_secret: b"0123456789abcdef",
            region: "test",
            trust: RelayTrustRequirements::NONE,
            ports: RelayPorts {
                turn_udp: 3_478,
                turn_tcp: 0,
                turn_tls: 0,
                secure_websocket: 0,
            },
            addresses: &addresses,
            spki_pins: &[],
        };
        let mut relay_bytes = vec![0; 4 + service.encoded_len().expect("relay service length")];
        encode_relay_service_list(&[service], &mut relay_bytes).expect("encode relay list");
        (stun_bytes, relay_bytes)
    }

    #[test]
    fn control_message_matches_canonical_header_and_round_trips() {
        let mut encoded = [0; 88];
        assert_eq!(
            encode_control_message(join_header(), &[], &join_fields(), &mut encoded),
            Ok(encoded.len())
        );
        assert_eq!(
            &encoded[..CONTROL_HEADER_LENGTH],
            &[
                0x53, 0x54, 0x4c, 0x43, 0, 1, 0, 0x10, 0, 0, 0, 32, 0, 0, 0, 56, 0, 0, 0, 0, 0, 0,
                0, 7, 0, 0, 0, 0, 0, 0, 0, 0,
            ]
        );
        assert_eq!(&encoded[32..36], &[0x80, 0x10, 0, 16]);
        assert_eq!(&encoded[36..52], &NETWORK_ID);
        assert_eq!(&encoded[52..56], &[0x80, 0x11, 0, 32]);
        assert_eq!(&encoded[56..], &JOIN_TOKEN);

        let decoded = ControlMessageView::decode(&encoded).expect("valid control message");
        assert_eq!(decoded.header(), join_header());
        assert_eq!(decoded.extensions().next(), None);
        assert_eq!(decoded.body(), &encoded[32..]);
        assert_eq!(decoded.fields().collect::<Vec<_>>(), join_fields());
        assert_eq!(decoded.encoded_len(), encoded.len());
    }

    #[test]
    fn control_record_prefix_round_trips_and_enforces_bounds() {
        let mut prefix = [0; 4];
        assert_eq!(encode_control_record_length(88, &mut prefix), Ok(()));
        assert_eq!(prefix, [0, 0, 0, 88]);
        assert_eq!(decode_control_record_length(&prefix), Ok(88));
        assert_eq!(
            decode_control_record_length(&[0, 0, 0, 31]),
            Err(CodecError::ValueOutOfRange {
                field: "control record length",
                actual: 31,
                minimum: 32,
                maximum: 1_048_576,
            })
        );
    }

    #[test]
    fn control_header_validates_negotiation_version_flags_and_ids() {
        let server_hello = ControlHeader {
            version: ProtocolVersion { major: 0, minor: 0 },
            message_type: ControlMessageType::ServerHello,
            flags: 0,
            header_length: 32,
            body_length: 0,
            message_id: 1,
            correlation_id: 0,
        };
        assert_eq!(server_hello.validate(), Ok(()));

        let mut invalid = server_hello;
        invalid.version = ProtocolVersion::CURRENT;
        assert_eq!(
            invalid.validate(),
            Err(CodecError::UnsupportedVersion { major: 0, minor: 1 })
        );

        invalid = join_header();
        invalid.flags = 1;
        assert_eq!(
            invalid.validate(),
            Err(CodecError::ReservedControlFlags {
                flags: 1,
                allowed: 0,
            })
        );

        invalid = join_header();
        invalid.message_id = 0;
        assert_eq!(
            invalid.validate(),
            Err(CodecError::ZeroField {
                field: "control message ID",
            })
        );
    }

    #[test]
    fn control_fields_reject_order_unknown_critical_and_padding() {
        let fields = join_fields();
        assert_eq!(control_fields_encoded_len(&fields), Ok(56));
        assert_eq!(
            control_fields_encoded_len(&[fields[1], fields[0]]),
            Err(CodecError::ControlFieldsOutOfOrder {
                previous: 0x8011,
                current: 0x8010,
                offset: 36,
            })
        );

        assert_eq!(
            ControlFieldIter::decode(&[0x80, 0x24, 0, 0]).map(|_| ()),
            Err(CodecError::UnknownCriticalControlField {
                field_type: 0x8024,
                offset: 0,
            })
        );
        assert_eq!(
            ControlFieldIter::decode(&[0, 1, 0, 1, 0xaa, 1, 0, 0]).map(|_| ()),
            Err(CodecError::NonZeroReserved {
                field: "control field padding",
                offset: 5,
            })
        );
    }

    #[test]
    fn control_field_values_validate_text_lengths_and_sensitive_debug() {
        assert!(ControlFieldRef::new(ControlFieldType::DisplayName, "节点".as_bytes()).is_ok());
        assert_eq!(
            ControlFieldRef::new(ControlFieldType::DisplayName, b"bad\nname"),
            Err(CodecError::InvalidTextCharacter {
                field: "display name",
                offset: 3,
            })
        );
        assert_eq!(
            ControlFieldRef::new(ControlFieldType::StatusMessage, &[0xff]),
            Err(CodecError::InvalidUtf8 {
                field: "status message",
                offset: 0,
            })
        );
        let token =
            ControlFieldRef::new(ControlFieldType::JoinToken, &JOIN_TOKEN).expect("valid token");
        let debug = format!("{token:?}");
        assert!(debug.contains("value_length: 32"));
        assert!(!debug.contains("44, 44"));
    }

    #[test]
    fn control_message_supports_header_extensions_and_rejects_bad_lengths() {
        let extension = ExtensionRef::new(1, &[0xaa]).expect("valid extension");
        let mut header = join_header();
        header.header_length = 40;
        let mut encoded = [0; 96];
        assert_eq!(
            encode_control_message(header, &[extension], &join_fields(), &mut encoded),
            Ok(encoded.len())
        );
        let decoded = ControlMessageView::decode(&encoded).expect("valid extended message");
        assert_eq!(decoded.extensions().collect::<Vec<_>>(), vec![extension]);

        header.body_length = 52;
        assert_eq!(
            encode_control_message(header, &[extension], &join_fields(), &mut encoded),
            Err(CodecError::LengthMismatch {
                field: "control body",
                expected: 56,
                actual: 52,
            })
        );

        let mut short = [0; 87];
        assert_eq!(
            encode_control_message(join_header(), &[], &join_fields(), &mut short),
            Err(CodecError::OutputTooSmall {
                field: "control message",
                offset: 0,
                needed: 88,
                remaining: 87,
            })
        );

        let mut body = [0; 56];
        assert_eq!(encode_control_fields(&join_fields(), &mut body), Ok(56));
    }

    #[test]
    fn control_message_schema_requires_join_network_id() {
        let fields = [
            ControlFieldRef::new(ControlFieldType::JoinToken, &JOIN_TOKEN)
                .expect("valid join token"),
        ];
        let mut header = join_header();
        header.body_length =
            u32::try_from(control_fields_encoded_len(&fields).expect("valid field lengths"))
                .expect("test body length fits u32");
        let mut encoded = [0; 80];

        assert_eq!(
            encode_control_message(header, &[], &fields, &mut encoded),
            Err(CodecError::MissingControlField {
                message_type: ControlMessageType::JoinRequest.as_u16(),
                field_type: ControlFieldType::NetworkId.as_u16(),
            })
        );
    }

    #[test]
    fn control_message_schema_rejects_unexpected_join_status() {
        let status = 0_u16.to_be_bytes();
        let fields = [
            ControlFieldRef::new(ControlFieldType::StatusCode, &status).expect("valid status code"),
            ControlFieldRef::new(ControlFieldType::NetworkId, &NETWORK_ID)
                .expect("valid network ID"),
        ];
        let mut header = join_header();
        header.body_length =
            u32::try_from(control_fields_encoded_len(&fields).expect("valid field lengths"))
                .expect("test body length fits u32");
        let mut encoded = [0; 80];

        assert_eq!(
            encode_control_message(header, &[], &fields, &mut encoded),
            Err(CodecError::UnexpectedControlField {
                message_type: ControlMessageType::JoinRequest.as_u16(),
                field_type: ControlFieldType::StatusCode.as_u16(),
            })
        );
    }

    #[test]
    fn peer_delta_remove_schema_round_trips() {
        let fields = peer_delta_fields(&[2]);
        let body_length = control_fields_encoded_len(&fields).expect("valid field lengths");
        let header = peer_delta_header(body_length);
        let mut encoded = [0; 104];

        assert_eq!(
            encode_control_message(header, &[], &fields, &mut encoded),
            Ok(encoded.len())
        );
        let decoded = ControlMessageView::decode(&encoded).expect("valid peer removal");
        assert_eq!(decoded.header(), header);
        assert_eq!(decoded.fields().collect::<Vec<_>>(), fields);
    }

    #[test]
    fn peer_delta_schema_rejects_wrong_add_and_remove_payloads() {
        let add_fields = peer_delta_fields(&[1]);
        let add_body_length = control_fields_encoded_len(&add_fields).expect("valid field lengths");
        let mut encoded = [0; 104];
        assert_eq!(
            encode_control_message(
                peer_delta_header(add_body_length),
                &[],
                &add_fields,
                &mut encoded,
            ),
            Err(CodecError::InvalidControlFieldCombination {
                message_type: ControlMessageType::PeerDelta.as_u16(),
                detail: "add/replace requires PEER_RECORD and forbids NODE_ID",
            })
        );

        let remove_all_fields = peer_delta_fields(&[2]);
        let remove_fields = &remove_all_fields[1..];
        let remove_body_length =
            control_fields_encoded_len(remove_fields).expect("valid field lengths");
        assert_eq!(
            encode_control_message(
                peer_delta_header(remove_body_length),
                &[],
                remove_fields,
                &mut encoded,
            ),
            Err(CodecError::InvalidControlFieldCombination {
                message_type: ControlMessageType::PeerDelta.as_u16(),
                detail: "remove requires NODE_ID and forbids PEER_RECORD",
            })
        );
    }

    #[test]
    fn control_header_gates_version_0_2_message_types() {
        for message_type in [
            ControlMessageType::ConnectivityUpdate,
            ControlMessageType::ConnectivityResult,
            ControlMessageType::ConnectivityConfig,
        ] {
            let mut header = ControlHeader {
                version: ProtocolVersion::V0_2,
                message_type,
                flags: 0,
                header_length: 32,
                body_length: 0,
                message_id: 1,
                correlation_id: 0,
            };
            assert_eq!(header.validate(), Ok(()));
            header.version = ProtocolVersion::V0_1;
            assert_eq!(
                header.validate(),
                Err(CodecError::UnsupportedControlMessageType {
                    value: message_type.as_u16(),
                })
            );
        }

        let mut future = join_header();
        future.version = ProtocolVersion { major: 0, minor: 3 };
        assert_eq!(
            future.validate(),
            Err(CodecError::UnsupportedVersion { major: 0, minor: 3 })
        );
        assert!(!field_required(
            ProtocolVersion::V0_1,
            ControlMessageType::PeerSnapshot,
            ControlFieldType::ConnectivityList,
        ));
        assert!(field_required(
            ProtocolVersion::V0_2,
            ControlMessageType::PeerSnapshot,
            ControlFieldType::ConnectivityList,
        ));
    }

    #[test]
    fn connectivity_update_withdrawal_round_trips_only_in_version_0_2() {
        let fields = [
            ControlFieldRef::new(ControlFieldType::NetworkId, &NETWORK_ID)
                .expect("valid network ID"),
        ];
        let body_length = control_fields_encoded_len(&fields).expect("field length");
        let mut header = ControlHeader {
            version: ProtocolVersion::V0_2,
            message_type: ControlMessageType::ConnectivityUpdate,
            flags: 0,
            header_length: 32,
            body_length: u32::try_from(body_length).expect("body length fits u32"),
            message_id: 9,
            correlation_id: 0,
        };
        let mut encoded = vec![0; CONTROL_HEADER_LENGTH + body_length];
        assert_eq!(
            encode_control_message(header, &[], &fields, &mut encoded),
            Ok(encoded.len())
        );
        let decoded = ControlMessageView::decode(&encoded).expect("decode connectivity withdrawal");
        assert_eq!(decoded.header(), header);

        header.version = ProtocolVersion::V0_1;
        assert!(matches!(
            encode_control_message(header, &[], &fields, &mut encoded),
            Err(CodecError::UnsupportedControlMessageType { value: 0x0022 })
        ));
    }

    #[test]
    fn connectivity_delta_operations_are_versioned_and_bind_node_identity() {
        let withdraw_fields = peer_delta_fields(&[4]);
        let withdraw_length =
            control_fields_encoded_len(&withdraw_fields).expect("withdraw field lengths");
        let mut withdraw_header = peer_delta_header(withdraw_length);
        withdraw_header.version = ProtocolVersion::V0_2;
        let mut withdraw_bytes = vec![0; CONTROL_HEADER_LENGTH + withdraw_length];
        assert_eq!(
            encode_control_message(withdraw_header, &[], &withdraw_fields, &mut withdraw_bytes,),
            Ok(withdraw_bytes.len())
        );

        let version_0_1_header = peer_delta_header(withdraw_length);
        assert!(matches!(
            encode_control_message(
                version_0_1_header,
                &[],
                &withdraw_fields,
                &mut withdraw_bytes,
            ),
            Err(CodecError::InvalidControlFieldCombination {
                detail: "version 0.1 permits only peer delta operations 1 and 2",
                ..
            })
        ));

        let record = connectivity_record_bytes(NODE_ID);
        let operation = [3];
        let fields = [
            ControlFieldRef::new(ControlFieldType::NodeId, &NODE_ID).expect("valid node ID"),
            ControlFieldRef::new(ControlFieldType::ControllerEpoch, &CONTROLLER_EPOCH)
                .expect("valid controller epoch"),
            ControlFieldRef::new(ControlFieldType::NetworkId, &NETWORK_ID)
                .expect("valid network ID"),
            ControlFieldRef::new(ControlFieldType::SnapshotRevision, &SNAPSHOT_REVISION)
                .expect("valid snapshot revision"),
            ControlFieldRef::new(ControlFieldType::DeltaOperation, &operation)
                .expect("valid connectivity operation"),
            ControlFieldRef::new(ControlFieldType::ConnectivityRecord, &record)
                .expect("valid connectivity record"),
        ];
        let body_length = control_fields_encoded_len(&fields).expect("replacement field lengths");
        let mut header = peer_delta_header(body_length);
        header.version = ProtocolVersion::V0_2;
        let mut encoded = vec![0; CONTROL_HEADER_LENGTH + body_length];
        assert_eq!(
            encode_control_message(header, &[], &fields, &mut encoded),
            Ok(encoded.len())
        );

        let different_node = [0x56; 16];
        let mut mismatched = fields;
        mismatched[0] = ControlFieldRef::new(ControlFieldType::NodeId, &different_node)
            .expect("valid different node ID");
        assert!(matches!(
            encode_control_message(header, &[], &mismatched, &mut encoded),
            Err(CodecError::InconsistentField {
                context: "peer connectivity delta",
                field: "node ID",
            })
        ));
    }

    #[test]
    fn connectivity_config_validates_nested_stun_and_relay_records() {
        let revision = 7_u64.to_be_bytes();
        let (stun_servers, relay_services) = connectivity_config_values();
        let fields = [
            ControlFieldRef::new(ControlFieldType::ConnectivityConfigRevision, &revision)
                .expect("valid connectivity configuration revision"),
            ControlFieldRef::new(ControlFieldType::StunServerList, &stun_servers)
                .expect("valid STUN server list"),
            ControlFieldRef::new(ControlFieldType::RelayServiceList, &relay_services)
                .expect("valid relay service list"),
        ];
        let body_length = control_fields_encoded_len(&fields).expect("configuration field lengths");
        let header = ControlHeader {
            version: ProtocolVersion::V0_2,
            message_type: ControlMessageType::ConnectivityConfig,
            flags: 0,
            header_length: 32,
            body_length: u32::try_from(body_length).expect("body length fits u32"),
            message_id: 10,
            correlation_id: 0,
        };
        let mut encoded = vec![0; CONTROL_HEADER_LENGTH + body_length];
        assert_eq!(
            encode_control_message(header, &[], &fields, &mut encoded),
            Ok(encoded.len())
        );
        let decoded = ControlMessageView::decode(&encoded).expect("decode connectivity config");
        assert_eq!(decoded.header(), header);
        assert_eq!(decoded.fields().count(), 3);
    }
}
