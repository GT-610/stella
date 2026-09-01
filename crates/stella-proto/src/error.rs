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
    /// A signed or canonical object's format magic is invalid.
    #[error("invalid {object} magic")]
    InvalidObjectMagic {
        /// Name of the object format.
        object: &'static str,
    },
    /// The protocol version is not implemented by this codec.
    #[error("unsupported protocol version {major}.{minor}")]
    UnsupportedVersion {
        /// Wire major version.
        major: u8,
        /// Wire minor version.
        minor: u8,
    },
    /// A signed or canonical object's format version is unsupported.
    #[error("unsupported {object} format version {version}")]
    UnsupportedObjectVersion {
        /// Name of the object format.
        object: &'static str,
        /// Supplied format version.
        version: u8,
    },
    /// A numeric enum value is not registered.
    #[error("invalid {field} value {value}")]
    InvalidEnumValue {
        /// Name of the enum field.
        field: &'static str,
        /// Supplied wire value.
        value: u64,
    },
    /// A numeric value is outside its protocol bounds.
    #[error("{field} value {actual} is outside {minimum}..={maximum}")]
    ValueOutOfRange {
        /// Name of the bounded field.
        field: &'static str,
        /// Supplied value.
        actual: u64,
        /// Inclusive minimum.
        minimum: u64,
        /// Inclusive maximum.
        maximum: u64,
    },
    /// A bit mask contains undefined reserved bits.
    #[error("{field} bits 0x{bits:x} exceed allowed mask 0x{allowed:x}")]
    ReservedBits {
        /// Name of the bit-mask field.
        field: &'static str,
        /// Supplied bits.
        bits: u64,
        /// Allowed bit mask.
        allowed: u64,
    },
    /// A signed object's validity interval is empty or reversed.
    #[error("invalid validity interval: not_before {not_before}, not_after {not_after}")]
    InvalidTimeRange {
        /// Inclusive validity start.
        not_before: u64,
        /// Exclusive validity end.
        not_after: u64,
    },
    /// A signed object's lifetime exceeds its protocol maximum.
    #[error("validity lifetime {actual} seconds exceeds maximum {maximum}")]
    LifetimeTooLong {
        /// Supplied validity lifetime in seconds.
        actual: u64,
        /// Maximum validity lifetime in seconds.
        maximum: u64,
    },
    /// Two authenticated or canonical objects disagree on a required field.
    #[error("inconsistent {field} between {context}")]
    InconsistentField {
        /// Objects being compared.
        context: &'static str,
        /// Name of the inconsistent field.
        field: &'static str,
    },
    /// A nested list repeats an entry that must be unique.
    #[error("duplicate entry {index} in {context}")]
    DuplicateNestedEntry {
        /// Name of the nested list.
        context: &'static str,
        /// Zero-based index of the duplicate.
        index: usize,
    },
    /// A nested list is not in its required canonical order.
    #[error("entry {index} in {context} is not strictly ordered")]
    NestedRecordsOutOfOrder {
        /// Name of the nested list.
        context: &'static str,
        /// Zero-based index of the first non-increasing entry.
        index: usize,
    },
    /// A numeric endpoint kind is not registered.
    #[error("unsupported endpoint kind {kind}")]
    UnsupportedEndpointKind {
        /// Endpoint kind byte.
        kind: u8,
    },
    /// A numeric endpoint address is unusable for unicast transport.
    #[error("invalid {family} endpoint address")]
    InvalidEndpointAddress {
        /// Address family name.
        family: &'static str,
    },
    /// The packet type is reserved or unsupported.
    #[error("unsupported packet type 0x{value:02x}")]
    UnsupportedPacketType {
        /// Packet type byte from the wire.
        value: u8,
    },
    /// The control message type is reserved or unsupported.
    #[error("unsupported control message type 0x{value:04x}")]
    UnsupportedControlMessageType {
        /// Control message type from the wire.
        value: u16,
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
    /// Control flags contain a reserved bit.
    #[error("control flags 0x{flags:04x} exceed allowed mask 0x{allowed:04x}")]
    ReservedControlFlags {
        /// Flags supplied by the control header.
        flags: u16,
        /// Allowed flag mask.
        allowed: u16,
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
    /// Control field type zero is forbidden.
    #[error("invalid control field type zero at byte offset {offset}")]
    InvalidControlFieldType {
        /// Absolute offset of the field prefix.
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
    /// A critical control field is not registered in this version.
    #[error("unknown critical control field 0x{field_type:04x} at byte offset {offset}")]
    UnknownCriticalControlField {
        /// Critical field type.
        field_type: u16,
        /// Absolute offset of the field prefix.
        offset: usize,
    },
    /// Control body fields are duplicated or not in increasing order.
    #[error(
        "control field 0x{current:04x} at byte offset {offset} does not follow 0x{previous:04x}"
    )]
    ControlFieldsOutOfOrder {
        /// Previous field type.
        previous: u16,
        /// Current duplicate or lower field type.
        current: u16,
        /// Absolute offset of the current field prefix.
        offset: usize,
    },
    /// A required field is absent from a control message.
    #[error("control message 0x{message_type:04x} is missing required field 0x{field_type:04x}")]
    MissingControlField {
        /// Control message type.
        message_type: u16,
        /// Missing registered field type.
        field_type: u16,
    },
    /// A registered field is not permitted in a control message.
    #[error("control field 0x{field_type:04x} is not allowed in message 0x{message_type:04x}")]
    UnexpectedControlField {
        /// Control message type.
        message_type: u16,
        /// Unexpected registered field type.
        field_type: u16,
    },
    /// Individually valid fields form an invalid message-specific combination.
    #[error("invalid field combination in control message 0x{message_type:04x}: {detail}")]
    InvalidControlFieldCombination {
        /// Control message type.
        message_type: u16,
        /// Stable redacted description of the violated rule.
        detail: &'static str,
    },
    /// A text field is not valid UTF-8.
    #[error("{field} is not valid UTF-8 at byte offset {offset}")]
    InvalidUtf8 {
        /// Name of the text field.
        field: &'static str,
        /// Offset within the field value.
        offset: usize,
    },
    /// A text field contains a forbidden C0 or C1 control character.
    #[error("{field} contains a control character at byte offset {offset}")]
    InvalidTextCharacter {
        /// Name of the text field.
        field: &'static str,
        /// Offset within the field value.
        offset: usize,
    },
    /// A required STUN attribute is absent.
    #[error("STUN message is missing required attribute 0x{attribute_type:04x}")]
    MissingStunAttribute {
        /// Missing attribute type.
        attribute_type: u16,
    },
    /// A STUN attribute that must be unique occurs more than once.
    #[error("duplicate STUN attribute 0x{attribute_type:04x}")]
    DuplicateStunAttribute {
        /// Duplicated attribute type.
        attribute_type: u16,
    },
    /// A registered STUN attribute has an invalid value length.
    #[error(
        "invalid STUN attribute 0x{attribute_type:04x} length: expected {expected}, got {actual}"
    )]
    InvalidStunAttributeLength {
        /// Attribute type whose value length is invalid.
        attribute_type: u16,
        /// Required exact value length.
        expected: usize,
        /// Supplied value length.
        actual: usize,
    },
    /// A STUN attribute appears after an integrity attribute that must cover it.
    #[error("STUN attribute 0x{attribute_type:04x} is invalid after message integrity")]
    InvalidStunAttributeOrder {
        /// Attribute type found in the invalid position.
        attribute_type: u16,
    },
}
