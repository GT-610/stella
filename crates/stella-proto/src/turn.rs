//! STUN/TURN message and `ChannelData` record framing used by Stella relays.

use std::{
    fmt,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
};

use crate::{
    cursor::{ReadCursor, WriteCursor},
    CodecError,
};

/// RFC 8489 magic cookie present in every STUN message.
pub const STUN_MAGIC_COOKIE: u32 = 0x2112_a442;

/// Exact fixed STUN message header length.
pub const STUN_HEADER_LENGTH: usize = 20;

/// Exact TURN `ChannelData` header length.
pub const TURN_CHANNEL_DATA_HEADER_LENGTH: usize = 4;

/// Largest aligned STUN message representable by its 16-bit body length.
pub const MAX_STUN_MESSAGE_LENGTH: usize = STUN_HEADER_LENGTH + (u16::MAX as usize & !3);

/// Minimum TURN channel number allocated by a client.
pub const MIN_TURN_CHANNEL_NUMBER: u16 = 0x4000;

/// Maximum TURN channel number allocated by a client.
pub const MAX_TURN_CHANNEL_NUMBER: u16 = 0x7fff;

/// Exact value length of `MESSAGE-INTEGRITY-SHA256`.
pub const STUN_MESSAGE_INTEGRITY_SHA256_LENGTH: usize = 32;

/// Exact value length of an IPv4 XOR address attribute.
pub const STUN_XOR_IPV4_ADDRESS_LENGTH: usize = 8;

/// Exact value length of an IPv6 XOR address attribute.
pub const STUN_XOR_IPV6_ADDRESS_LENGTH: usize = 20;

/// Largest error reason phrase accepted by the Stella TURN profile.
pub const MAX_STUN_ERROR_REASON_LENGTH: usize = 127;

const STUN_ATTRIBUTE_HEADER_LENGTH: usize = 4;
const STUN_IPV4_FAMILY: u8 = 0x01;
const STUN_IPV6_FAMILY: u8 = 0x02;

/// STUN message class encoded across the two class bits.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum StunClass {
    /// Client request expecting a success or error response.
    Request = 0,
    /// One-way indication without a transaction response.
    Indication = 1,
    /// Successful response to a request.
    SuccessResponse = 2,
    /// Error response to a request.
    ErrorResponse = 3,
}

impl TryFrom<u8> for StunClass {
    type Error = CodecError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::Request),
            1 => Ok(Self::Indication),
            2 => Ok(Self::SuccessResponse),
            3 => Ok(Self::ErrorResponse),
            _ => Err(CodecError::InvalidEnumValue {
                field: "STUN message class",
                value: u64::from(value),
            }),
        }
    }
}

/// STUN or TURN method required by the Stella relay profile.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u16)]
pub enum StunMethod {
    /// STUN Binding discovery or consent check.
    Binding = 0x001,
    /// TURN allocation creation.
    Allocate = 0x003,
    /// TURN allocation refresh or deletion.
    Refresh = 0x004,
    /// TURN relayed datagram send indication.
    Send = 0x006,
    /// TURN relayed datagram receive indication.
    Data = 0x007,
    /// TURN peer permission creation.
    CreatePermission = 0x008,
    /// TURN channel binding creation or refresh.
    ChannelBind = 0x009,
}

impl TryFrom<u16> for StunMethod {
    type Error = CodecError;

    fn try_from(value: u16) -> Result<Self, Self::Error> {
        match value {
            0x001 => Ok(Self::Binding),
            0x003 => Ok(Self::Allocate),
            0x004 => Ok(Self::Refresh),
            0x006 => Ok(Self::Send),
            0x007 => Ok(Self::Data),
            0x008 => Ok(Self::CreatePermission),
            0x009 => Ok(Self::ChannelBind),
            _ => Err(CodecError::InvalidEnumValue {
                field: "STUN method",
                value: u64::from(value),
            }),
        }
    }
}

/// Decoded STUN method and class pair.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StunMessageType {
    /// Registered method.
    pub method: StunMethod,
    /// Transaction class.
    pub class: StunClass,
}

impl StunMessageType {
    /// Creates one method/class pair.
    #[must_use]
    pub const fn new(method: StunMethod, class: StunClass) -> Self {
        Self { method, class }
    }

    /// Returns the RFC 8489 scattered-bit wire value.
    #[must_use]
    pub const fn as_u16(self) -> u16 {
        let method = self.method as u16;
        let class = self.class as u16;
        (method & 0x000f)
            | ((method & 0x0070) << 1)
            | ((method & 0x0f80) << 2)
            | ((class & 0x0001) << 4)
            | ((class & 0x0002) << 7)
    }
}

impl TryFrom<u16> for StunMessageType {
    type Error = CodecError;

    fn try_from(value: u16) -> Result<Self, Self::Error> {
        if value & 0xc000 != 0 {
            return Err(CodecError::ReservedBits {
                field: "STUN message type",
                bits: u64::from(value),
                allowed: 0x3fff,
            });
        }
        let method = (value & 0x000f) | ((value & 0x00e0) >> 1) | ((value & 0x3e00) >> 2);
        let class = u8::try_from(((value >> 4) & 1) | ((value >> 7) & 2)).map_err(|_| {
            CodecError::InvalidEnumValue {
                field: "STUN message class",
                value: u64::from(value),
            }
        })?;
        Ok(Self {
            method: StunMethod::try_from(method)?,
            class: StunClass::try_from(class)?,
        })
    }
}

/// Opaque 96-bit STUN transaction identifier.
#[derive(Clone, Copy, Eq, Hash, PartialEq)]
pub struct StunTransactionId([u8; 12]);

impl StunTransactionId {
    /// Creates an identifier from its exact wire bytes.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; 12]) -> Self {
        Self(bytes)
    }

    /// Borrows the exact wire bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 12] {
        &self.0
    }
}

impl fmt::Debug for StunTransactionId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("StunTransactionId")
            .finish_non_exhaustive()
    }
}

/// Password derivation algorithm accepted by the Stella TURN profile.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u16)]
pub enum StunPasswordAlgorithm {
    /// SHA-256 long-term credential key derivation from RFC 8489.
    Sha256 = 0x0002,
}

impl StunPasswordAlgorithm {
    /// Returns the registered two-byte algorithm number.
    #[must_use]
    pub const fn as_u16(self) -> u16 {
        self as u16
    }

    /// Encodes the algorithm and its empty parameter block.
    ///
    /// # Errors
    ///
    /// Returns [`CodecError`] when `output` is shorter than four bytes.
    pub fn encode(self, output: &mut [u8]) -> Result<usize, CodecError> {
        let mut cursor = WriteCursor::new(output, 0);
        cursor.write_u16(self.as_u16(), "STUN password algorithm")?;
        cursor.write_u16(0, "STUN password algorithm parameter length")?;
        Ok(cursor.position())
    }

    /// Decodes the exact Stella SHA-256 password-algorithm value.
    ///
    /// # Errors
    ///
    /// Returns [`CodecError`] for an unsupported algorithm, non-empty
    /// parameters, truncation, or trailing bytes.
    pub fn decode(input: &[u8]) -> Result<Self, CodecError> {
        let mut cursor = ReadCursor::new(input, 0);
        let algorithm = cursor.read_u16("STUN password algorithm")?;
        if algorithm != Self::Sha256.as_u16() {
            return Err(CodecError::InvalidEnumValue {
                field: "STUN password algorithm",
                value: u64::from(algorithm),
            });
        }
        let parameter_length =
            usize::from(cursor.read_u16("STUN password algorithm parameter length")?);
        if parameter_length != 0 {
            return Err(CodecError::LengthMismatch {
                field: "STUN password algorithm parameters",
                expected: 0,
                actual: parameter_length,
            });
        }
        if input.len() != cursor.position() {
            return Err(CodecError::TrailingBytes {
                expected: cursor.position(),
                actual: input.len(),
            });
        }
        Ok(Self::Sha256)
    }
}

/// Encodes one STUN XOR address attribute value.
///
/// The output contains only the attribute value, not its four-byte attribute
/// header. Stella accepts non-zero unicast IPv4 and IPv6 socket addresses.
///
/// # Errors
///
/// Returns [`CodecError`] for a zero port, unusable address, or an output
/// buffer shorter than 8 bytes for IPv4 or 20 bytes for IPv6.
pub fn encode_stun_xor_address(
    address: SocketAddr,
    transaction_id: StunTransactionId,
    output: &mut [u8],
) -> Result<usize, CodecError> {
    validate_stun_socket_address(address)?;
    let mut cursor = WriteCursor::new(output, 0);
    cursor.write_u8(0, "STUN address reserved")?;
    match address.ip() {
        IpAddr::V4(ip) => {
            cursor.write_u8(STUN_IPV4_FAMILY, "STUN address family")?;
            cursor.write_u16(
                address.port() ^ ((STUN_MAGIC_COOKIE >> 16) as u16),
                "STUN XOR port",
            )?;
            let address_bytes = ip.octets();
            let mask = STUN_MAGIC_COOKIE.to_be_bytes();
            let xored: [u8; 4] = std::array::from_fn(|index| address_bytes[index] ^ mask[index]);
            cursor.write_bytes(&xored, "STUN XOR IPv4 address")?;
        }
        IpAddr::V6(ip) => {
            cursor.write_u8(STUN_IPV6_FAMILY, "STUN address family")?;
            cursor.write_u16(
                address.port() ^ ((STUN_MAGIC_COOKIE >> 16) as u16),
                "STUN XOR port",
            )?;
            let address_bytes = ip.octets();
            let cookie = STUN_MAGIC_COOKIE.to_be_bytes();
            let xored: [u8; 16] = std::array::from_fn(|index| {
                let mask = if index < cookie.len() {
                    cookie[index]
                } else {
                    transaction_id.as_bytes()[index - cookie.len()]
                };
                address_bytes[index] ^ mask
            });
            cursor.write_bytes(&xored, "STUN XOR IPv6 address")?;
        }
    }
    Ok(cursor.position())
}

/// Decodes one exact STUN XOR address attribute value.
///
/// # Errors
///
/// Returns [`CodecError`] for malformed length, reserved bytes, unsupported
/// family, a zero port, or a non-unicast address.
pub fn decode_stun_xor_address(
    input: &[u8],
    transaction_id: StunTransactionId,
) -> Result<SocketAddr, CodecError> {
    let mut cursor = ReadCursor::new(input, 0);
    if cursor.read_u8("STUN address reserved")? != 0 {
        return Err(CodecError::NonZeroReserved {
            field: "STUN address reserved",
            offset: 0,
        });
    }
    let family = cursor.read_u8("STUN address family")?;
    let port = cursor.read_u16("STUN XOR port")? ^ ((STUN_MAGIC_COOKIE >> 16) as u16);
    if port == 0 {
        return Err(CodecError::ZeroField {
            field: "STUN address port",
        });
    }
    let ip = match family {
        STUN_IPV4_FAMILY => {
            if input.len() != STUN_XOR_IPV4_ADDRESS_LENGTH {
                return Err(CodecError::LengthMismatch {
                    field: "STUN XOR IPv4 address",
                    expected: STUN_XOR_IPV4_ADDRESS_LENGTH,
                    actual: input.len(),
                });
            }
            let xored = cursor.read_array::<4>("STUN XOR IPv4 address")?;
            let mask = STUN_MAGIC_COOKIE.to_be_bytes();
            IpAddr::V4(Ipv4Addr::from(std::array::from_fn(|index| {
                xored[index] ^ mask[index]
            })))
        }
        STUN_IPV6_FAMILY => {
            if input.len() != STUN_XOR_IPV6_ADDRESS_LENGTH {
                return Err(CodecError::LengthMismatch {
                    field: "STUN XOR IPv6 address",
                    expected: STUN_XOR_IPV6_ADDRESS_LENGTH,
                    actual: input.len(),
                });
            }
            let xored = cursor.read_array::<16>("STUN XOR IPv6 address")?;
            let cookie = STUN_MAGIC_COOKIE.to_be_bytes();
            IpAddr::V6(Ipv6Addr::from(std::array::from_fn(|index| {
                let mask = if index < cookie.len() {
                    cookie[index]
                } else {
                    transaction_id.as_bytes()[index - cookie.len()]
                };
                xored[index] ^ mask
            })))
        }
        _ => {
            return Err(CodecError::InvalidEnumValue {
                field: "STUN address family",
                value: u64::from(family),
            });
        }
    };
    let address = SocketAddr::new(ip, port);
    validate_stun_socket_address(address)?;
    Ok(address)
}

fn validate_stun_socket_address(address: SocketAddr) -> Result<(), CodecError> {
    if address.port() == 0 {
        return Err(CodecError::ZeroField {
            field: "STUN address port",
        });
    }
    let ip = address.ip();
    let invalid = ip.is_unspecified()
        || ip.is_multicast()
        || matches!(ip, IpAddr::V4(value) if value == Ipv4Addr::BROADCAST);
    if invalid {
        return Err(CodecError::InvalidEndpointAddress {
            family: if ip.is_ipv4() { "IPv4" } else { "IPv6" },
        });
    }
    Ok(())
}

/// Borrowed validated STUN `ERROR-CODE` attribute value.
#[derive(Clone, Copy)]
pub struct StunErrorCodeView<'a> {
    code: u16,
    reason: &'a str,
}

impl<'a> StunErrorCodeView<'a> {
    /// Decodes one exact `ERROR-CODE` attribute value.
    ///
    /// # Errors
    ///
    /// Returns [`CodecError`] for truncation, reserved bits, a status outside
    /// 300 through 699, invalid UTF-8, control characters, or an oversized
    /// reason phrase.
    pub fn decode(input: &'a [u8]) -> Result<Self, CodecError> {
        let mut cursor = ReadCursor::new(input, 0);
        let reserved = cursor.read_u16("STUN error code reserved")?;
        if reserved != 0 {
            return Err(CodecError::NonZeroReserved {
                field: "STUN error code reserved",
                offset: 0,
            });
        }
        let class = cursor.read_u8("STUN error class")?;
        if class & 0xf8 != 0 {
            return Err(CodecError::ReservedBits {
                field: "STUN error class",
                bits: u64::from(class),
                allowed: 0x07,
            });
        }
        let number = cursor.read_u8("STUN error number")?;
        if number > 99 {
            return Err(CodecError::ValueOutOfRange {
                field: "STUN error number",
                actual: u64::from(number),
                minimum: 0,
                maximum: 99,
            });
        }
        let code = u16::from(class) * 100 + u16::from(number);
        validate_stun_error_code(code)?;
        let reason_bytes =
            cursor.read_slice(input.len() - cursor.position(), "STUN error reason")?;
        let reason =
            std::str::from_utf8(reason_bytes).map_err(|error| CodecError::InvalidUtf8 {
                field: "STUN error reason",
                offset: error.valid_up_to(),
            })?;
        validate_stun_error_reason(reason)?;
        Ok(Self { code, reason })
    }

    /// Returns the represented three-digit status code.
    #[must_use]
    pub const fn code(&self) -> u16 {
        self.code
    }

    /// Borrows the validated reason phrase.
    #[must_use]
    pub const fn reason(&self) -> &'a str {
        self.reason
    }
}

impl fmt::Debug for StunErrorCodeView<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("StunErrorCodeView")
            .field("code", &self.code)
            .field("reason_length", &self.reason.len())
            .finish()
    }
}

/// Encodes one STUN `ERROR-CODE` attribute value.
///
/// # Errors
///
/// Returns [`CodecError`] when the code is outside 300 through 699, the reason
/// is longer than 127 bytes or contains a control character, or `output` is too
/// small.
pub fn encode_stun_error_code(
    code: u16,
    reason: &str,
    output: &mut [u8],
) -> Result<usize, CodecError> {
    validate_stun_error_code(code)?;
    validate_stun_error_reason(reason)?;
    let class = u8::try_from(code / 100).map_err(|_| CodecError::ValueOutOfRange {
        field: "STUN error class",
        actual: u64::from(code / 100),
        minimum: 3,
        maximum: 6,
    })?;
    let number = u8::try_from(code % 100).map_err(|_| CodecError::ValueOutOfRange {
        field: "STUN error number",
        actual: u64::from(code % 100),
        minimum: 0,
        maximum: 99,
    })?;
    let mut cursor = WriteCursor::new(output, 0);
    cursor.write_u16(0, "STUN error code reserved")?;
    cursor.write_u8(class, "STUN error class")?;
    cursor.write_u8(number, "STUN error number")?;
    cursor.write_bytes(reason.as_bytes(), "STUN error reason")?;
    Ok(cursor.position())
}

fn validate_stun_error_code(code: u16) -> Result<(), CodecError> {
    if !(300..=699).contains(&code) {
        return Err(CodecError::ValueOutOfRange {
            field: "STUN error code",
            actual: u64::from(code),
            minimum: 300,
            maximum: 699,
        });
    }
    Ok(())
}

fn validate_stun_error_reason(reason: &str) -> Result<(), CodecError> {
    if reason.len() > MAX_STUN_ERROR_REASON_LENGTH {
        return Err(CodecError::ValueOutOfRange {
            field: "STUN error reason length",
            actual: reason.len() as u64,
            minimum: 0,
            maximum: MAX_STUN_ERROR_REASON_LENGTH as u64,
        });
    }
    if let Some((offset, _character)) = reason
        .char_indices()
        .find(|(_offset, character)| character.is_control())
    {
        return Err(CodecError::InvalidTextCharacter {
            field: "STUN error reason",
            offset,
        });
    }
    Ok(())
}

/// STUN/TURN attribute type, including unrecognized extension values.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct StunAttributeType(u16);

impl StunAttributeType {
    /// MAPPED-ADDRESS.
    pub const MAPPED_ADDRESS: Self = Self(0x0001);
    /// USERNAME.
    pub const USERNAME: Self = Self(0x0006);
    /// MESSAGE-INTEGRITY using HMAC-SHA-1.
    pub const MESSAGE_INTEGRITY: Self = Self(0x0008);
    /// ERROR-CODE.
    pub const ERROR_CODE: Self = Self(0x0009);
    /// UNKNOWN-ATTRIBUTES.
    pub const UNKNOWN_ATTRIBUTES: Self = Self(0x000a);
    /// CHANNEL-NUMBER.
    pub const CHANNEL_NUMBER: Self = Self(0x000c);
    /// LIFETIME.
    pub const LIFETIME: Self = Self(0x000d);
    /// XOR-PEER-ADDRESS.
    pub const XOR_PEER_ADDRESS: Self = Self(0x0012);
    /// DATA.
    pub const DATA: Self = Self(0x0013);
    /// REALM.
    pub const REALM: Self = Self(0x0014);
    /// NONCE.
    pub const NONCE: Self = Self(0x0015);
    /// XOR-RELAYED-ADDRESS.
    pub const XOR_RELAYED_ADDRESS: Self = Self(0x0016);
    /// REQUESTED-TRANSPORT.
    pub const REQUESTED_TRANSPORT: Self = Self(0x0019);
    /// DONT-FRAGMENT.
    pub const DONT_FRAGMENT: Self = Self(0x001a);
    /// MESSAGE-INTEGRITY-SHA256.
    pub const MESSAGE_INTEGRITY_SHA256: Self = Self(0x001c);
    /// PASSWORD-ALGORITHM.
    pub const PASSWORD_ALGORITHM: Self = Self(0x001d);
    /// USERHASH.
    pub const USERHASH: Self = Self(0x001e);
    /// XOR-MAPPED-ADDRESS.
    pub const XOR_MAPPED_ADDRESS: Self = Self(0x0020);
    /// SOFTWARE.
    pub const SOFTWARE: Self = Self(0x8022);
    /// ALTERNATE-SERVER.
    pub const ALTERNATE_SERVER: Self = Self(0x8023);
    /// FINGERPRINT.
    pub const FINGERPRINT: Self = Self(0x8028);

    /// Creates a non-zero extension attribute type.
    #[must_use]
    pub const fn new(value: u16) -> Option<Self> {
        if value == 0 {
            None
        } else {
            Some(Self(value))
        }
    }

    /// Returns the two-byte wire value.
    #[must_use]
    pub const fn as_u16(self) -> u16 {
        self.0
    }

    /// Returns whether an unknown receiver must reject this attribute.
    #[must_use]
    pub const fn comprehension_required(self) -> bool {
        self.0 < 0x8000
    }
}

/// Borrowed STUN attribute supplied for encoding.
#[derive(Clone, Copy)]
pub struct StunAttributeRef<'a> {
    /// Attribute type.
    pub attribute_type: StunAttributeType,
    /// Exact unpadded value bytes.
    pub value: &'a [u8],
}

impl StunAttributeRef<'_> {
    /// Returns the four-byte-aligned encoded length.
    ///
    /// # Errors
    ///
    /// Returns [`CodecError`] when the value exceeds the 16-bit attribute
    /// length or alignment arithmetic overflows.
    pub fn encoded_len(&self) -> Result<usize, CodecError> {
        let _length = u16::try_from(self.value.len()).map_err(|_| CodecError::ValueOutOfRange {
            field: "STUN attribute length",
            actual: self.value.len() as u64,
            minimum: 0,
            maximum: u64::from(u16::MAX),
        })?;
        align_to_four(
            STUN_ATTRIBUTE_HEADER_LENGTH
                .checked_add(self.value.len())
                .ok_or(CodecError::IntegerOverflow {
                    field: "STUN attribute encoded length",
                })?,
        )
    }
}

impl fmt::Debug for StunAttributeRef<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("StunAttributeRef")
            .field("attribute_type", &self.attribute_type)
            .field("value_length", &self.value.len())
            .finish()
    }
}

/// Borrowed complete STUN message supplied for encoding.
#[derive(Clone, Copy, Debug)]
pub struct StunMessageRef<'a> {
    /// Method and class.
    pub message_type: StunMessageType,
    /// Transaction identifier.
    pub transaction_id: StunTransactionId,
    /// Ordered attributes.
    pub attributes: &'a [StunAttributeRef<'a>],
}

impl StunMessageRef<'_> {
    /// Returns the exact encoded message length.
    ///
    /// # Errors
    ///
    /// Returns [`CodecError`] for oversized attributes, arithmetic overflow,
    /// or a body that cannot fit the STUN 16-bit length.
    pub fn encoded_len(&self) -> Result<usize, CodecError> {
        let body_length = stun_attributes_encoded_len(self.attributes)?;
        let _body_length = u16::try_from(body_length).map_err(|_| CodecError::ValueOutOfRange {
            field: "STUN message body length",
            actual: body_length as u64,
            minimum: 0,
            maximum: u64::from(u16::MAX),
        })?;
        STUN_HEADER_LENGTH
            .checked_add(body_length)
            .ok_or(CodecError::IntegerOverflow {
                field: "STUN message encoded length",
            })
    }
}

/// Returns the aligned encoded length of an ordered attribute sequence.
///
/// # Errors
///
/// Returns [`CodecError`] for oversized values or checked arithmetic overflow.
pub fn stun_attributes_encoded_len(
    attributes: &[StunAttributeRef<'_>],
) -> Result<usize, CodecError> {
    attributes.iter().try_fold(0_usize, |length, attribute| {
        length
            .checked_add(attribute.encoded_len()?)
            .ok_or(CodecError::IntegerOverflow {
                field: "STUN attributes encoded length",
            })
    })
}

/// Encodes one complete STUN/TURN message and zeroes all attribute padding.
///
/// # Errors
///
/// Returns [`CodecError`] for invalid lengths, arithmetic overflow, or a
/// caller-provided output slice that is too small.
pub fn encode_stun_message(
    message: StunMessageRef<'_>,
    output: &mut [u8],
) -> Result<usize, CodecError> {
    let encoded_length = message.encoded_len()?;
    let body_length = encoded_length - STUN_HEADER_LENGTH;
    let body_length = u16::try_from(body_length).map_err(|_| CodecError::ValueOutOfRange {
        field: "STUN message body length",
        actual: body_length as u64,
        minimum: 0,
        maximum: u64::from(u16::MAX),
    })?;
    let mut cursor = WriteCursor::new(output, 0);
    cursor.write_u16(message.message_type.as_u16(), "STUN message type")?;
    cursor.write_u16(body_length, "STUN message body length")?;
    cursor.write_u32(STUN_MAGIC_COOKIE, "STUN magic cookie")?;
    cursor.write_bytes(message.transaction_id.as_bytes(), "STUN transaction ID")?;
    for attribute in message.attributes {
        let value_length =
            u16::try_from(attribute.value.len()).map_err(|_| CodecError::ValueOutOfRange {
                field: "STUN attribute length",
                actual: attribute.value.len() as u64,
                minimum: 0,
                maximum: u64::from(u16::MAX),
            })?;
        cursor.write_u16(attribute.attribute_type.as_u16(), "STUN attribute type")?;
        cursor.write_u16(value_length, "STUN attribute length")?;
        cursor.write_bytes(attribute.value, "STUN attribute value")?;
        let padded = align_to_four(cursor.position())?;
        while cursor.position() < padded {
            cursor.write_u8(0, "STUN attribute padding")?;
        }
    }
    Ok(cursor.position())
}

/// Borrowed validated STUN attribute.
#[derive(Clone, Copy)]
pub struct StunAttributeView<'a> {
    attribute_type: StunAttributeType,
    value: &'a [u8],
    encoded_offset: usize,
    encoded_length: usize,
}

impl<'a> StunAttributeView<'a> {
    /// Returns the attribute type.
    #[must_use]
    pub const fn attribute_type(&self) -> StunAttributeType {
        self.attribute_type
    }

    /// Borrows the exact unpadded value bytes.
    #[must_use]
    pub const fn value(&self) -> &'a [u8] {
        self.value
    }

    /// Returns the absolute offset of the attribute header in its message.
    #[must_use]
    pub const fn encoded_offset(&self) -> usize {
        self.encoded_offset
    }

    /// Returns the absolute offset of the unpadded value in its message.
    #[must_use]
    pub const fn value_offset(&self) -> usize {
        self.encoded_offset + STUN_ATTRIBUTE_HEADER_LENGTH
    }

    /// Returns the aligned encoded attribute length including its header.
    #[must_use]
    pub const fn encoded_len(&self) -> usize {
        self.encoded_length
    }
}

impl fmt::Debug for StunAttributeView<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("StunAttributeView")
            .field("attribute_type", &self.attribute_type)
            .field("value_length", &self.value.len())
            .field("encoded_offset", &self.encoded_offset)
            .field("encoded_length", &self.encoded_length)
            .finish()
    }
}

/// Iterator over bounded STUN attribute records.
pub struct StunAttributeIter<'a> {
    body: &'a [u8],
    position: usize,
}

impl<'a> Iterator for StunAttributeIter<'a> {
    type Item = Result<StunAttributeView<'a>, CodecError>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.position == self.body.len() {
            return None;
        }
        if self.position > self.body.len() {
            return Some(Err(CodecError::TrailingBytes {
                expected: self.body.len(),
                actual: self.position,
            }));
        }
        let base = STUN_HEADER_LENGTH.saturating_add(self.position);
        let remaining = &self.body[self.position..];
        let mut cursor = ReadCursor::new(remaining, base);
        let raw_attribute_type = match cursor.read_u16("STUN attribute type") {
            Ok(value) => value,
            Err(error) => {
                self.position = self.body.len();
                return Some(Err(error));
            }
        };
        let Some(attribute_type) = StunAttributeType::new(raw_attribute_type) else {
            self.position = self.body.len();
            return Some(Err(CodecError::InvalidEnumValue {
                field: "STUN attribute type",
                value: 0,
            }));
        };
        let value_length = match cursor.read_u16("STUN attribute length") {
            Ok(value) => usize::from(value),
            Err(error) => {
                self.position = self.body.len();
                return Some(Err(error));
            }
        };
        let value = match cursor.read_slice(value_length, "STUN attribute value") {
            Ok(value) => value,
            Err(error) => {
                self.position = self.body.len();
                return Some(Err(error));
            }
        };
        let consumed = match align_to_four(cursor.position()) {
            Ok(value) => value,
            Err(error) => {
                self.position = self.body.len();
                return Some(Err(error));
            }
        };
        let Some(next) = self.position.checked_add(consumed) else {
            self.position = self.body.len();
            return Some(Err(CodecError::IntegerOverflow {
                field: "STUN attribute iterator position",
            }));
        };
        if next > self.body.len() {
            self.position = self.body.len();
            return Some(Err(CodecError::Truncated {
                field: "STUN attribute padding",
                offset: base.saturating_add(cursor.position()),
                needed: consumed.saturating_sub(cursor.position()),
                remaining: remaining.len().saturating_sub(cursor.position()),
            }));
        }
        self.position = next;
        Some(Ok(StunAttributeView {
            attribute_type,
            value,
            encoded_offset: base,
            encoded_length: consumed,
        }))
    }
}

/// Validated `MESSAGE-INTEGRITY-SHA256` calculation ranges.
#[derive(Clone, Copy)]
pub struct StunMessageIntegritySha256<'a> {
    encoded: &'a [u8],
    integrity_offset: usize,
    value_offset: usize,
    adjusted_body_length: u16,
    value: &'a [u8; STUN_MESSAGE_INTEGRITY_SHA256_LENGTH],
}

impl<'a> StunMessageIntegritySha256<'a> {
    /// Borrows the original two-byte message type before the length field.
    #[must_use]
    pub fn message_type_bytes(&self) -> &'a [u8] {
        &self.encoded[..2]
    }

    /// Returns the temporary body length used by the integrity calculation.
    #[must_use]
    pub const fn adjusted_body_length(&self) -> u16 {
        self.adjusted_body_length
    }

    /// Borrows bytes after the header length through the attribute before
    /// `MESSAGE-INTEGRITY-SHA256`.
    #[must_use]
    pub fn bytes_after_length(&self) -> &'a [u8] {
        &self.encoded[4..self.integrity_offset]
    }

    /// Borrows the received complete 32-byte HMAC value.
    #[must_use]
    pub const fn value(&self) -> &'a [u8; STUN_MESSAGE_INTEGRITY_SHA256_LENGTH] {
        self.value
    }

    /// Returns the absolute offset at which the HMAC value begins.
    #[must_use]
    pub const fn value_offset(&self) -> usize {
        self.value_offset
    }
}

impl fmt::Debug for StunMessageIntegritySha256<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("StunMessageIntegritySha256")
            .field("integrity_offset", &self.integrity_offset)
            .field("value_offset", &self.value_offset)
            .field("adjusted_body_length", &self.adjusted_body_length)
            .finish_non_exhaustive()
    }
}

/// Borrowed validated complete STUN/TURN message.
#[derive(Clone, Copy)]
pub struct StunMessageView<'a> {
    encoded: &'a [u8],
    message_type: StunMessageType,
    transaction_id: StunTransactionId,
    body: &'a [u8],
}

impl<'a> StunMessageView<'a> {
    /// Decodes one exact complete message and validates every attribute range.
    ///
    /// Attribute padding is ignored on input as required by STUN and is zeroed
    /// by [`encode_stun_message`].
    ///
    /// # Errors
    ///
    /// Returns [`CodecError`] for truncation, invalid type, cookie, alignment,
    /// declared length, attribute ranges, zero attribute types, or trailing
    /// bytes.
    pub fn decode(input: &'a [u8]) -> Result<Self, CodecError> {
        let mut cursor = ReadCursor::new(input, 0);
        let message_type = StunMessageType::try_from(cursor.read_u16("STUN message type")?)?;
        let body_length = usize::from(cursor.read_u16("STUN message body length")?);
        if body_length % 4 != 0 {
            return Err(CodecError::UnalignedHeaderLength {
                actual: body_length,
            });
        }
        if cursor.read_u32("STUN magic cookie")? != STUN_MAGIC_COOKIE {
            return Err(CodecError::InvalidObjectMagic {
                object: "STUN message",
            });
        }
        let transaction_id =
            StunTransactionId::from_bytes(cursor.read_array::<12>("STUN transaction ID")?);
        let expected =
            STUN_HEADER_LENGTH
                .checked_add(body_length)
                .ok_or(CodecError::IntegerOverflow {
                    field: "STUN message length",
                })?;
        if input.len() != expected {
            return Err(CodecError::TrailingBytes {
                expected,
                actual: input.len(),
            });
        }
        let body = cursor.read_slice(body_length, "STUN message body")?;
        let view = Self {
            encoded: input,
            message_type,
            transaction_id,
            body,
        };
        for attribute in view.attributes() {
            let _attribute = attribute?;
        }
        Ok(view)
    }

    /// Returns the method and class.
    #[must_use]
    pub const fn message_type(&self) -> StunMessageType {
        self.message_type
    }

    /// Returns the transaction identifier.
    #[must_use]
    pub const fn transaction_id(&self) -> StunTransactionId {
        self.transaction_id
    }

    /// Borrows the exact complete encoded message.
    #[must_use]
    pub const fn encoded(&self) -> &'a [u8] {
        self.encoded
    }

    /// Iterates over validated attributes in wire order.
    #[must_use]
    pub const fn attributes(&self) -> StunAttributeIter<'a> {
        StunAttributeIter {
            body: self.body,
            position: 0,
        }
    }

    /// Locates and validates the SHA-256 message-integrity boundary.
    ///
    /// The returned ranges let a cryptographic caller feed the message type,
    /// the adjusted two-byte body length, and `bytes_after_length()` to
    /// HMAC-SHA-256 without copying or mutating the received message.
    ///
    /// # Errors
    ///
    /// Returns [`CodecError`] when the integrity attribute is missing,
    /// duplicated, not exactly 32 bytes, or followed by anything except one
    /// exact four-byte `FINGERPRINT` attribute.
    pub fn message_integrity_sha256(&self) -> Result<StunMessageIntegritySha256<'a>, CodecError> {
        let mut integrity = None;
        let mut fingerprint_seen = false;
        for attribute in self.attributes() {
            let attribute = attribute?;
            let attribute_type = attribute.attribute_type();
            if attribute_type == StunAttributeType::MESSAGE_INTEGRITY_SHA256 {
                if integrity.is_some() {
                    return Err(CodecError::DuplicateStunAttribute {
                        attribute_type: attribute_type.as_u16(),
                    });
                }
                if fingerprint_seen {
                    return Err(CodecError::InvalidStunAttributeOrder {
                        attribute_type: attribute_type.as_u16(),
                    });
                }
                if attribute.value().len() != STUN_MESSAGE_INTEGRITY_SHA256_LENGTH {
                    return Err(CodecError::InvalidStunAttributeLength {
                        attribute_type: attribute_type.as_u16(),
                        expected: STUN_MESSAGE_INTEGRITY_SHA256_LENGTH,
                        actual: attribute.value().len(),
                    });
                }
                integrity = Some(attribute);
                continue;
            }
            if attribute_type == StunAttributeType::FINGERPRINT {
                if fingerprint_seen {
                    return Err(CodecError::DuplicateStunAttribute {
                        attribute_type: attribute_type.as_u16(),
                    });
                }
                if integrity.is_none() {
                    return Err(CodecError::InvalidStunAttributeOrder {
                        attribute_type: attribute_type.as_u16(),
                    });
                }
                if attribute.value().len() != 4 {
                    return Err(CodecError::InvalidStunAttributeLength {
                        attribute_type: attribute_type.as_u16(),
                        expected: 4,
                        actual: attribute.value().len(),
                    });
                }
                fingerprint_seen = true;
                continue;
            }
            if integrity.is_some() {
                return Err(CodecError::InvalidStunAttributeOrder {
                    attribute_type: attribute_type.as_u16(),
                });
            }
        }
        let attribute = integrity.ok_or(CodecError::MissingStunAttribute {
            attribute_type: StunAttributeType::MESSAGE_INTEGRITY_SHA256.as_u16(),
        })?;
        let integrity_end = attribute
            .encoded_offset()
            .checked_add(attribute.encoded_len())
            .ok_or(CodecError::IntegerOverflow {
                field: "STUN message integrity boundary",
            })?;
        let adjusted_body_length =
            integrity_end
                .checked_sub(STUN_HEADER_LENGTH)
                .ok_or(CodecError::IntegerOverflow {
                    field: "STUN message integrity body length",
                })?;
        let adjusted_body_length =
            u16::try_from(adjusted_body_length).map_err(|_| CodecError::ValueOutOfRange {
                field: "STUN message integrity body length",
                actual: adjusted_body_length as u64,
                minimum: 0,
                maximum: u64::from(u16::MAX),
            })?;
        let value = <&[u8; STUN_MESSAGE_INTEGRITY_SHA256_LENGTH]>::try_from(attribute.value())
            .map_err(|_| CodecError::InvalidStunAttributeLength {
                attribute_type: attribute.attribute_type().as_u16(),
                expected: STUN_MESSAGE_INTEGRITY_SHA256_LENGTH,
                actual: attribute.value().len(),
            })?;
        Ok(StunMessageIntegritySha256 {
            encoded: self.encoded,
            integrity_offset: attribute.encoded_offset(),
            value_offset: attribute.value_offset(),
            adjusted_body_length,
            value,
        })
    }
}

impl fmt::Debug for StunMessageView<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("StunMessageView")
            .field("message_type", &self.message_type)
            .field("transaction_id", &self.transaction_id)
            .field("body_length", &self.body.len())
            .finish_non_exhaustive()
    }
}

/// Validated TURN channel number in the dynamic allocation range.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct TurnChannelNumber(u16);

impl TurnChannelNumber {
    /// Creates a channel number in `0x4000..=0x7fff`.
    #[must_use]
    pub const fn new(value: u16) -> Option<Self> {
        if value >= MIN_TURN_CHANNEL_NUMBER && value <= MAX_TURN_CHANNEL_NUMBER {
            Some(Self(value))
        } else {
            None
        }
    }

    /// Returns the two-byte wire value.
    #[must_use]
    pub const fn get(self) -> u16 {
        self.0
    }
}

/// Encodes one TURN `ChannelData` datagram without stream padding.
///
/// # Errors
///
/// Returns [`CodecError`] when data exceeds 65,535 bytes, length arithmetic
/// overflows, or the output is too small.
pub fn encode_turn_channel_data(
    channel: TurnChannelNumber,
    data: &[u8],
    output: &mut [u8],
) -> Result<usize, CodecError> {
    encode_turn_channel_data_inner(channel, data, output, false)
}

/// Encodes one TURN `ChannelData` stream record with zero alignment padding.
///
/// # Errors
///
/// Returns the same errors as [`encode_turn_channel_data`].
pub fn encode_turn_channel_data_stream(
    channel: TurnChannelNumber,
    data: &[u8],
    output: &mut [u8],
) -> Result<usize, CodecError> {
    encode_turn_channel_data_inner(channel, data, output, true)
}

fn encode_turn_channel_data_inner(
    channel: TurnChannelNumber,
    data: &[u8],
    output: &mut [u8],
    stream_padding: bool,
) -> Result<usize, CodecError> {
    let data_length = u16::try_from(data.len()).map_err(|_| CodecError::ValueOutOfRange {
        field: "TURN ChannelData length",
        actual: data.len() as u64,
        minimum: 0,
        maximum: u64::from(u16::MAX),
    })?;
    let unpadded = TURN_CHANNEL_DATA_HEADER_LENGTH
        .checked_add(data.len())
        .ok_or(CodecError::IntegerOverflow {
            field: "TURN ChannelData record length",
        })?;
    let encoded_length = if stream_padding {
        align_to_four(unpadded)?
    } else {
        unpadded
    };
    let mut cursor = WriteCursor::new(output, 0);
    cursor.write_u16(channel.get(), "TURN channel number")?;
    cursor.write_u16(data_length, "TURN ChannelData length")?;
    cursor.write_bytes(data, "TURN ChannelData payload")?;
    while cursor.position() < encoded_length {
        cursor.write_u8(0, "TURN ChannelData stream padding")?;
    }
    Ok(cursor.position())
}

/// Borrowed validated TURN `ChannelData` record.
#[derive(Clone, Copy)]
pub struct TurnChannelDataView<'a> {
    channel: TurnChannelNumber,
    data: &'a [u8],
}

impl<'a> TurnChannelDataView<'a> {
    /// Decodes one exact UDP `ChannelData` datagram without alignment padding.
    ///
    /// # Errors
    ///
    /// Returns [`CodecError`] for truncation, an out-of-range channel number,
    /// or trailing bytes.
    pub fn decode_datagram(input: &'a [u8]) -> Result<Self, CodecError> {
        Self::decode(input, false)
    }

    /// Decodes one exact stream `ChannelData` record including alignment padding.
    ///
    /// Stream padding bytes are ignored as specified by TURN.
    ///
    /// # Errors
    ///
    /// Returns [`CodecError`] for truncation, an out-of-range channel number,
    /// or inconsistent padded length.
    pub fn decode_stream(input: &'a [u8]) -> Result<Self, CodecError> {
        Self::decode(input, true)
    }

    fn decode(input: &'a [u8], stream_padding: bool) -> Result<Self, CodecError> {
        let mut cursor = ReadCursor::new(input, 0);
        let raw_channel = cursor.read_u16("TURN channel number")?;
        let channel = TurnChannelNumber::new(raw_channel).ok_or(CodecError::ValueOutOfRange {
            field: "TURN channel number",
            actual: u64::from(raw_channel),
            minimum: u64::from(MIN_TURN_CHANNEL_NUMBER),
            maximum: u64::from(MAX_TURN_CHANNEL_NUMBER),
        })?;
        let data_length = usize::from(cursor.read_u16("TURN ChannelData length")?);
        let data = cursor.read_slice(data_length, "TURN ChannelData payload")?;
        let unpadded = TURN_CHANNEL_DATA_HEADER_LENGTH
            .checked_add(data_length)
            .ok_or(CodecError::IntegerOverflow {
                field: "TURN ChannelData record length",
            })?;
        let expected = if stream_padding {
            align_to_four(unpadded)?
        } else {
            unpadded
        };
        if input.len() != expected {
            return Err(CodecError::TrailingBytes {
                expected,
                actual: input.len(),
            });
        }
        Ok(Self { channel, data })
    }

    /// Returns the bound channel number.
    #[must_use]
    pub const fn channel(&self) -> TurnChannelNumber {
        self.channel
    }

    /// Borrows the exact relayed datagram bytes.
    #[must_use]
    pub const fn data(&self) -> &'a [u8] {
        self.data
    }
}

impl fmt::Debug for TurnChannelDataView<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("TurnChannelDataView")
            .field("channel", &self.channel)
            .field("data_length", &self.data.len())
            .finish()
    }
}

/// Returns the exact next record length for a TURN TCP/TLS byte stream.
///
/// `prefix` must contain the first four bytes. STUN records include their
/// 20-byte header and already-aligned body. `ChannelData` records include
/// four-byte stream padding.
///
/// # Errors
///
/// Returns [`CodecError`] for a short prefix, unsupported leading bits,
/// invalid STUN method/class, unaligned STUN body, invalid channel number, or
/// checked length overflow.
pub fn decode_turn_stream_record_length(prefix: &[u8]) -> Result<usize, CodecError> {
    let mut cursor = ReadCursor::new(prefix, 0);
    let leading = cursor.read_u16("TURN stream record type")?;
    let length = usize::from(cursor.read_u16("TURN stream record length")?);
    match leading >> 14 {
        0 => {
            let _message_type = StunMessageType::try_from(leading)?;
            if length % 4 != 0 {
                return Err(CodecError::UnalignedHeaderLength { actual: length });
            }
            STUN_HEADER_LENGTH
                .checked_add(length)
                .ok_or(CodecError::IntegerOverflow {
                    field: "TURN STUN stream record length",
                })
        }
        1 => {
            let _channel = TurnChannelNumber::new(leading).ok_or(CodecError::ValueOutOfRange {
                field: "TURN channel number",
                actual: u64::from(leading),
                minimum: u64::from(MIN_TURN_CHANNEL_NUMBER),
                maximum: u64::from(MAX_TURN_CHANNEL_NUMBER),
            })?;
            align_to_four(TURN_CHANNEL_DATA_HEADER_LENGTH.checked_add(length).ok_or(
                CodecError::IntegerOverflow {
                    field: "TURN ChannelData stream record length",
                },
            )?)
        }
        _ => Err(CodecError::ReservedBits {
            field: "TURN stream record type",
            bits: u64::from(leading),
            allowed: 0x7fff,
        }),
    }
}

fn align_to_four(length: usize) -> Result<usize, CodecError> {
    length
        .checked_add(3)
        .map(|value| value & !3)
        .ok_or(CodecError::IntegerOverflow {
            field: "four-byte alignment",
        })
}

#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};

    use super::{
        decode_stun_xor_address, decode_turn_stream_record_length, encode_stun_error_code,
        encode_stun_message, encode_stun_xor_address, encode_turn_channel_data,
        encode_turn_channel_data_stream, StunAttributeRef, StunAttributeType, StunClass,
        StunErrorCodeView, StunMessageRef, StunMessageType, StunMessageView, StunMethod,
        StunPasswordAlgorithm, StunTransactionId, TurnChannelDataView, TurnChannelNumber,
        STUN_MAGIC_COOKIE,
    };
    use crate::CodecError;

    const TRANSACTION_ID: StunTransactionId =
        StunTransactionId::from_bytes([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12]);

    #[test]
    fn registered_turn_message_types_match_rfc_values() {
        assert_eq!(
            StunMessageType::new(StunMethod::Allocate, StunClass::Request).as_u16(),
            0x0003
        );
        assert_eq!(
            StunMessageType::new(StunMethod::Allocate, StunClass::SuccessResponse).as_u16(),
            0x0103
        );
        assert_eq!(
            StunMessageType::new(StunMethod::Allocate, StunClass::ErrorResponse).as_u16(),
            0x0113
        );
        assert_eq!(
            StunMessageType::new(StunMethod::Send, StunClass::Indication).as_u16(),
            0x0016
        );
        assert_eq!(
            StunMessageType::new(StunMethod::Data, StunClass::Indication).as_u16(),
            0x0017
        );
        for raw in [0x0001, 0x0003, 0x0103, 0x0113, 0x0016, 0x0017, 0x0008] {
            assert_eq!(
                StunMessageType::try_from(raw)
                    .expect("registered type")
                    .as_u16(),
                raw
            );
        }
    }

    #[test]
    fn allocate_request_matches_canonical_bytes_and_round_trips() {
        let transport = [17, 0, 0, 0];
        let lifetime = 600_u32.to_be_bytes();
        let attributes = [
            StunAttributeRef {
                attribute_type: StunAttributeType::REQUESTED_TRANSPORT,
                value: &transport,
            },
            StunAttributeRef {
                attribute_type: StunAttributeType::LIFETIME,
                value: &lifetime,
            },
        ];
        let message = StunMessageRef {
            message_type: StunMessageType::new(StunMethod::Allocate, StunClass::Request),
            transaction_id: TRANSACTION_ID,
            attributes: &attributes,
        };
        let mut encoded = [0_u8; 36];
        assert_eq!(
            encode_stun_message(message, &mut encoded).expect("encode allocate request"),
            encoded.len()
        );
        assert_eq!(
            encoded,
            [
                0x00, 0x03, 0x00, 0x10, 0x21, 0x12, 0xa4, 0x42, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11,
                12, 0x00, 0x19, 0x00, 0x04, 17, 0, 0, 0, 0x00, 0x0d, 0x00, 0x04, 0x00, 0x00, 0x02,
                0x58,
            ]
        );
        let decoded = StunMessageView::decode(&encoded).expect("decode allocate request");
        assert_eq!(decoded.message_type(), message.message_type);
        assert_eq!(decoded.transaction_id(), TRANSACTION_ID);
        let decoded_attributes = decoded
            .attributes()
            .collect::<Result<Vec<_>, _>>()
            .expect("decode attributes");
        assert_eq!(decoded_attributes.len(), 2);
        assert_eq!(
            decoded_attributes[0].attribute_type(),
            StunAttributeType::REQUESTED_TRANSPORT
        );
        assert_eq!(decoded_attributes[0].value(), &transport);
        assert_eq!(decoded_attributes[1].value(), &lifetime);
    }

    #[test]
    fn attribute_padding_is_zeroed_but_ignored_when_decoding() {
        let attributes = [StunAttributeRef {
            attribute_type: StunAttributeType::USERNAME,
            value: b"abc",
        }];
        let message = StunMessageRef {
            message_type: StunMessageType::new(StunMethod::Allocate, StunClass::Request),
            transaction_id: TRANSACTION_ID,
            attributes: &attributes,
        };
        let mut encoded = [0x5a; 28];
        encode_stun_message(message, &mut encoded).expect("encode padded attribute");
        assert_eq!(encoded[27], 0);
        encoded[27] = 0x5a;
        let decoded = StunMessageView::decode(&encoded).expect("padding is ignored");
        let attribute = decoded
            .attributes()
            .next()
            .expect("one attribute")
            .expect("valid attribute");
        assert_eq!(attribute.value(), b"abc");
        let diagnostic = format!("{decoded:?} {attribute:?}");
        assert!(!diagnostic.contains("abc"));
    }

    #[test]
    fn xor_addresses_match_ipv4_wire_example_and_round_trip_ipv6() {
        let ipv4 = SocketAddr::new(Ipv4Addr::new(192, 0, 2, 1).into(), 32_853);
        let mut encoded_ipv4 = [0_u8; 8];
        assert_eq!(
            encode_stun_xor_address(ipv4, TRANSACTION_ID, &mut encoded_ipv4)
                .expect("encode IPv4 XOR address"),
            encoded_ipv4.len()
        );
        assert_eq!(
            encoded_ipv4,
            [0x00, 0x01, 0xa1, 0x47, 0xe1, 0x12, 0xa6, 0x43]
        );
        assert_eq!(
            decode_stun_xor_address(&encoded_ipv4, TRANSACTION_ID)
                .expect("decode IPv4 XOR address"),
            ipv4
        );

        let ipv6 = SocketAddr::new(
            "2001:db8:1234:5678:90ab:cdef:1234:5678"
                .parse::<Ipv6Addr>()
                .expect("IPv6 address")
                .into(),
            44_300,
        );
        let mut encoded_ipv6 = [0_u8; 20];
        encode_stun_xor_address(ipv6, TRANSACTION_ID, &mut encoded_ipv6)
            .expect("encode IPv6 XOR address");
        assert_eq!(
            decode_stun_xor_address(&encoded_ipv6, TRANSACTION_ID)
                .expect("decode IPv6 XOR address"),
            ipv6
        );
    }

    #[test]
    fn xor_addresses_reject_reserved_family_length_and_non_unicast_values() {
        let mut address = [0_u8; 8];
        address[1] = 1;
        address[2..4].copy_from_slice(&(9_u16 ^ 0x2112).to_be_bytes());
        address[4..8].copy_from_slice(&STUN_MAGIC_COOKIE.to_be_bytes());
        assert!(matches!(
            decode_stun_xor_address(&address, TRANSACTION_ID),
            Err(CodecError::InvalidEndpointAddress { family: "IPv4" })
        ));
        address[0] = 1;
        assert!(matches!(
            decode_stun_xor_address(&address, TRANSACTION_ID),
            Err(CodecError::NonZeroReserved { .. })
        ));
        address[0] = 0;
        address[1] = 3;
        assert!(matches!(
            decode_stun_xor_address(&address, TRANSACTION_ID),
            Err(CodecError::InvalidEnumValue {
                field: "STUN address family",
                ..
            })
        ));
        address[1] = 1;
        assert!(matches!(
            decode_stun_xor_address(&address[..7], TRANSACTION_ID),
            Err(CodecError::LengthMismatch { .. })
        ));
    }

    #[test]
    fn error_code_and_password_algorithm_values_are_strict() {
        let mut error = [0_u8; 16];
        let length =
            encode_stun_error_code(401, "Unauthorized", &mut error).expect("encode error code");
        assert_eq!(&error[..length], b"\0\0\x04\x01Unauthorized");
        let decoded = StunErrorCodeView::decode(&error[..length]).expect("decode error code");
        assert_eq!(decoded.code(), 401);
        assert_eq!(decoded.reason(), "Unauthorized");
        assert!(encode_stun_error_code(299, "invalid", &mut error).is_err());
        assert!(encode_stun_error_code(400, "bad\nrequest", &mut error).is_err());

        let mut algorithm = [0_u8; 4];
        assert_eq!(
            StunPasswordAlgorithm::Sha256
                .encode(&mut algorithm)
                .expect("encode password algorithm"),
            4
        );
        assert_eq!(algorithm, [0, 2, 0, 0]);
        assert_eq!(
            StunPasswordAlgorithm::decode(&algorithm).expect("decode password algorithm"),
            StunPasswordAlgorithm::Sha256
        );
        assert!(StunPasswordAlgorithm::decode(&[0, 1, 0, 0]).is_err());
        assert!(StunPasswordAlgorithm::decode(&[0, 2, 0, 1]).is_err());
    }

    #[test]
    fn sha256_integrity_ranges_adjust_header_and_exclude_integrity_value() {
        let zero_integrity = [0_u8; 32];
        let fingerprint = [0_u8; 4];
        let attributes = [
            StunAttributeRef {
                attribute_type: StunAttributeType::USERNAME,
                value: b"abc",
            },
            StunAttributeRef {
                attribute_type: StunAttributeType::MESSAGE_INTEGRITY_SHA256,
                value: &zero_integrity,
            },
            StunAttributeRef {
                attribute_type: StunAttributeType::FINGERPRINT,
                value: &fingerprint,
            },
        ];
        let message = StunMessageRef {
            message_type: StunMessageType::new(StunMethod::Allocate, StunClass::Request),
            transaction_id: TRANSACTION_ID,
            attributes: &attributes,
        };
        let mut encoded = vec![0_u8; message.encoded_len().expect("encoded length")];
        encode_stun_message(message, &mut encoded).expect("encode authenticated request");
        let view = StunMessageView::decode(&encoded).expect("decode authenticated request");
        let integrity = view
            .message_integrity_sha256()
            .expect("locate integrity range");
        assert_eq!(integrity.adjusted_body_length(), 44);
        assert_eq!(integrity.value(), &zero_integrity);
        assert_eq!(integrity.value_offset(), 32);

        let mut hmac_input = Vec::new();
        hmac_input.extend_from_slice(integrity.message_type_bytes());
        hmac_input.extend_from_slice(&integrity.adjusted_body_length().to_be_bytes());
        hmac_input.extend_from_slice(integrity.bytes_after_length());
        let mut expected = encoded[..28].to_vec();
        expected[2..4].copy_from_slice(&44_u16.to_be_bytes());
        assert_eq!(hmac_input, expected);
    }

    #[test]
    fn sha256_integrity_rejects_missing_duplicate_and_trailing_attributes() {
        let integrity = [0_u8; 32];
        let duplicate = [
            StunAttributeRef {
                attribute_type: StunAttributeType::MESSAGE_INTEGRITY_SHA256,
                value: &integrity,
            },
            StunAttributeRef {
                attribute_type: StunAttributeType::MESSAGE_INTEGRITY_SHA256,
                value: &integrity,
            },
        ];
        let trailing_lifetime = 300_u32.to_be_bytes();
        let trailing = [
            duplicate[0],
            StunAttributeRef {
                attribute_type: StunAttributeType::LIFETIME,
                value: &trailing_lifetime,
            },
        ];
        for (attributes, expected_duplicate) in
            [(duplicate.as_slice(), true), (trailing.as_slice(), false)]
        {
            let message = StunMessageRef {
                message_type: StunMessageType::new(StunMethod::Allocate, StunClass::Request),
                transaction_id: TRANSACTION_ID,
                attributes,
            };
            let mut encoded = vec![0_u8; message.encoded_len().expect("encoded length")];
            encode_stun_message(message, &mut encoded).expect("encode integrity case");
            let result = StunMessageView::decode(&encoded)
                .expect("decode integrity case")
                .message_integrity_sha256();
            assert_eq!(
                matches!(result, Err(CodecError::DuplicateStunAttribute { .. })),
                expected_duplicate
            );
            assert_eq!(
                matches!(result, Err(CodecError::InvalidStunAttributeOrder { .. })),
                !expected_duplicate
            );
        }
        let empty = StunMessageRef {
            message_type: StunMessageType::new(StunMethod::Allocate, StunClass::Request),
            transaction_id: TRANSACTION_ID,
            attributes: &[],
        };
        let mut encoded = [0_u8; 20];
        encode_stun_message(empty, &mut encoded).expect("encode empty request");
        assert!(matches!(
            StunMessageView::decode(&encoded)
                .expect("decode empty request")
                .message_integrity_sha256(),
            Err(CodecError::MissingStunAttribute { .. })
        ));
    }

    #[test]
    fn malformed_stun_lengths_types_and_cookie_are_rejected() {
        let mut header = [0_u8; 20];
        header[..2].copy_from_slice(&0x0003_u16.to_be_bytes());
        header[4..8].copy_from_slice(&STUN_MAGIC_COOKIE.to_be_bytes());
        assert!(StunMessageView::decode(&header).is_ok());

        let mut bad_cookie = header;
        bad_cookie[4] ^= 1;
        assert!(matches!(
            StunMessageView::decode(&bad_cookie),
            Err(CodecError::InvalidObjectMagic {
                object: "STUN message"
            })
        ));
        let mut unaligned = header;
        unaligned[2..4].copy_from_slice(&1_u16.to_be_bytes());
        assert!(matches!(
            StunMessageView::decode(&unaligned),
            Err(CodecError::UnalignedHeaderLength { actual: 1 })
        ));
        let mut unknown_method = header;
        unknown_method[..2].copy_from_slice(&0x0002_u16.to_be_bytes());
        assert!(matches!(
            StunMessageView::decode(&unknown_method),
            Err(CodecError::InvalidEnumValue {
                field: "STUN method",
                ..
            })
        ));
        let mut trailing = header.to_vec();
        trailing.push(0);
        assert!(matches!(
            StunMessageView::decode(&trailing),
            Err(CodecError::TrailingBytes {
                expected: 20,
                actual: 21
            })
        ));

        let mut truncated_attribute = header.to_vec();
        truncated_attribute[2..4].copy_from_slice(&4_u16.to_be_bytes());
        truncated_attribute.extend_from_slice(&[0x00, 0x06, 0x00, 0x04]);
        assert!(matches!(
            StunMessageView::decode(&truncated_attribute),
            Err(CodecError::Truncated {
                field: "STUN attribute value",
                ..
            })
        ));
    }

    #[test]
    fn channel_data_preserves_datagram_and_stream_boundaries() {
        let channel = TurnChannelNumber::new(0x4001).expect("valid channel");
        let mut datagram = [0_u8; 7];
        assert_eq!(
            encode_turn_channel_data(channel, b"abc", &mut datagram)
                .expect("encode datagram ChannelData"),
            7
        );
        let decoded =
            TurnChannelDataView::decode_datagram(&datagram).expect("decode datagram ChannelData");
        assert_eq!(decoded.channel(), channel);
        assert_eq!(decoded.data(), b"abc");

        let mut stream = [0x5a; 8];
        assert_eq!(
            encode_turn_channel_data_stream(channel, b"abc", &mut stream)
                .expect("encode stream ChannelData"),
            8
        );
        assert_eq!(stream[7], 0);
        assert_eq!(
            decode_turn_stream_record_length(&stream[..4]).expect("channel record length"),
            8
        );
        assert_eq!(
            TurnChannelDataView::decode_stream(&stream)
                .expect("decode stream ChannelData")
                .data(),
            b"abc"
        );
        assert!(TurnChannelDataView::decode_datagram(&stream).is_err());
    }

    #[test]
    fn stream_framing_distinguishes_stun_channel_and_reserved_prefixes() {
        assert_eq!(
            decode_turn_stream_record_length(&[0x00, 0x03, 0x00, 0x10])
                .expect("STUN record length"),
            36
        );
        assert_eq!(
            decode_turn_stream_record_length(&[0x40, 0x00, 0x00, 0x05])
                .expect("ChannelData record length"),
            12
        );
        assert!(matches!(
            decode_turn_stream_record_length(&[0x80, 0x00, 0, 0]),
            Err(CodecError::ReservedBits { .. })
        ));
        assert!(matches!(
            decode_turn_stream_record_length(&[0x00, 0x03, 0x00]),
            Err(CodecError::Truncated { .. })
        ));
    }
}
