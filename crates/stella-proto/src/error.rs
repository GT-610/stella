//! Typed protocol codec failures.

use thiserror::Error;

/// Error returned when a Stella wire value cannot be decoded or encoded.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
#[non_exhaustive]
pub enum CodecError {
    /// An input record ended before a field could be read.
    #[error("truncated {field} at byte offset {offset}: need {needed} bytes, have {remaining}")]
    Truncated {
        /// Name of the field being decoded.
        field: &'static str,
        /// Absolute byte offset at which the read began.
        offset: usize,
        /// Number of bytes required for the field.
        needed: usize,
        /// Number of bytes remaining in the input.
        remaining: usize,
    },
    /// A caller-provided output slice is too small.
    #[error(
        "output too small for {field} at byte offset {offset}: need {needed} bytes, have {remaining}"
    )]
    OutputTooSmall {
        /// Name of the field being encoded.
        field: &'static str,
        /// Absolute byte offset at which the write began.
        offset: usize,
        /// Number of bytes required for the field.
        needed: usize,
        /// Number of bytes remaining in the output.
        remaining: usize,
    },
    /// A record contains bytes after its declared end.
    #[error("unexpected trailing bytes: expected {expected} bytes, got {actual}")]
    TrailingBytes {
        /// Exact length declared by the record.
        expected: usize,
        /// Supplied input length.
        actual: usize,
    },
    /// The four-byte Stella magic is invalid.
    #[error("invalid Stella magic")]
    InvalidMagic,
    /// The protocol version is not implemented by this codec.
    #[error("unsupported protocol version {major}.{minor}")]
    UnsupportedVersion {
        /// Wire major version.
        major: u8,
        /// Wire minor version.
        minor: u8,
    },
    /// The packet type is reserved or unsupported.
    #[error("unsupported packet type 0x{value:02x}")]
    UnsupportedPacketType {
        /// Packet type byte from the wire.
        value: u8,
    },
    /// Type-specific flags contain a reserved bit.
    #[error(
        "packet type 0x{packet_type:02x} has reserved flags 0x{flags:02x}; allowed mask is 0x{allowed:02x}"
    )]
    ReservedFlags {
        /// Packet type byte.
        packet_type: u8,
        /// Flags supplied by the record.
        flags: u8,
        /// Allowed flag mask.
        allowed: u8,
    },
    /// A type-specific decoder received a different registered packet type.
    #[error("unexpected packet type 0x{actual:02x}; expected 0x{expected:02x}")]
    UnexpectedPacketType {
        /// Required packet type byte.
        expected: u8,
        /// Actual registered packet type byte.
        actual: u8,
    },
    /// A header is shorter than the relevant fixed header.
    #[error("header length {actual} is smaller than minimum {minimum}")]
    HeaderTooShort {
        /// Declared header length.
        actual: usize,
        /// Required fixed-header length.
        minimum: usize,
    },
    /// A header exceeds the protocol limit.
    #[error("header length {actual} exceeds maximum {maximum}")]
    HeaderTooLong {
        /// Declared header length.
        actual: usize,
        /// Protocol maximum.
        maximum: usize,
    },
    /// A header length is not aligned to four bytes.
    #[error("header length {actual} is not four-byte aligned")]
    UnalignedHeaderLength {
        /// Declared header length.
        actual: usize,
    },
    /// A length field disagrees with the enclosing record.
    #[error("invalid {field} length: expected {expected}, got {actual}")]
    LengthMismatch {
        /// Name of the inconsistent field.
        field: &'static str,
        /// Required length.
        expected: usize,
        /// Supplied length.
        actual: usize,
    },
    /// Checked size or range arithmetic overflowed.
    #[error("integer overflow while calculating {field}")]
    IntegerOverflow {
        /// Name of the size or range being calculated.
        field: &'static str,
    },
    /// A reserved field or alignment byte is non-zero.
    #[error("non-zero reserved field {field} at byte offset {offset}")]
    NonZeroReserved {
        /// Name of the reserved field.
        field: &'static str,
        /// Absolute byte offset of the non-zero value.
        offset: usize,
    },
    /// A field that must be non-zero is zero.
    #[error("{field} must be non-zero")]
    ZeroField {
        /// Name of the zero-valued field.
        field: &'static str,
    },
    /// A complete Ethernet frame length is outside protocol bounds.
    #[error("frame length {actual} is outside {minimum}..={maximum}")]
    InvalidFrameLength {
        /// Supplied complete frame length.
        actual: u16,
        /// Protocol minimum.
        minimum: u16,
        /// Protocol maximum.
        maximum: u16,
    },
    /// A fragment has zero length.
    #[error("fragment length must be non-zero")]
    InvalidFragmentLength,
    /// A fragment range is outside its declared complete frame.
    #[error("fragment range {offset}..{end} is outside frame length {frame_length}")]
    FragmentOutOfRange {
        /// Fragment byte offset.
        offset: u16,
        /// Exclusive fragment end.
        end: u32,
        /// Complete frame length.
        frame_length: u16,
    },
    /// A keepalive probe does not use its packet sequence number.
    #[error("keepalive probe ID {probe_id} does not equal sequence number {sequence_number}")]
    ProbeIdMismatch {
        /// Directional protected-packet sequence number.
        sequence_number: u64,
        /// Supplied keepalive probe identifier.
        probe_id: u64,
    },
    /// Authenticated Ethernet metadata has an invalid source address.
    #[error("authenticated Ethernet source MAC is zero or a group address")]
    InvalidSourceMac,
    /// Authenticated header metadata disagrees with the complete frame.
    #[error("authenticated Ethernet {field} does not match the complete frame")]
    EthernetMetadataMismatch {
        /// Name of the inconsistent Ethernet field.
        field: &'static str,
    },
    /// Extension type zero is forbidden.
    #[error("invalid extension type zero at byte offset {offset}")]
    InvalidExtensionType {
        /// Absolute offset of the extension prefix.
        offset: usize,
    },
    /// Version 0.1 does not define the supplied critical extension.
    #[error("unknown critical extension 0x{extension_type:04x} at byte offset {offset}")]
    UnknownCriticalExtension {
        /// Critical extension type.
        extension_type: u16,
        /// Absolute offset of the extension prefix.
        offset: usize,
    },
}
