//! Peer-session handshake datagram codec.

use stella_common::{GrantSerial, NodeId};

use crate::{
    common::{validate_record_length, COMMON_HEADER_LENGTH},
    cursor::{ReadCursor, WriteCursor},
    extension::{
        encode_extension_block_at, extensions_encoded_len, validate_extension_block, ExtensionIter,
        ExtensionRef,
    },
    CodecError, CommonHeader, MembershipGrantView, PacketType, ED25519_SIGNATURE_LENGTH,
    MAX_ENDPOINT_DATAGRAM_SIZE, MEMBERSHIP_GRANT_LENGTH, MIN_ENDPOINT_DATAGRAM_SIZE,
};

/// Encoded length of the fixed header shared by every handshake datagram.
pub const HANDSHAKE_FIXED_HEADER_LENGTH: usize = 96;

/// Exact `SESSION_INIT` payload length.
pub const SESSION_INIT_PAYLOAD_LENGTH: usize = 392;

/// Bytes at the start of a `SESSION_INIT` payload covered by its signature.
pub const SESSION_INIT_SIGNED_PAYLOAD_LENGTH: usize = 328;

/// Exact `SESSION_RESPONSE` payload length.
pub const SESSION_RESPONSE_PAYLOAD_LENGTH: usize = 408;

/// Bytes at the start of a `SESSION_RESPONSE` payload covered by its signature.
pub const SESSION_RESPONSE_SIGNED_PAYLOAD_LENGTH: usize = 344;

/// Exact `SESSION_CONFIRM` payload length.
pub const SESSION_CONFIRM_PAYLOAD_LENGTH: usize = 56;

/// Bytes at the start of a `SESSION_CONFIRM` payload used as associated data.
pub const SESSION_CONFIRM_AUTHENTICATED_PAYLOAD_LENGTH: usize = 40;

/// Header flag identifying a responder confirmation.
pub const SESSION_CONFIRM_RESPONDER_FLAG: u8 = 0x01;

/// Exact `SESSION_REJECT` payload length.
pub const SESSION_REJECT_PAYLOAD_LENGTH: usize = 104;

/// Bytes at the start of a `SESSION_REJECT` payload covered by its signature.
pub const SESSION_REJECT_SIGNED_PAYLOAD_LENGTH: usize = 40;

/// Length of an ephemeral X25519 public key.
pub const X25519_PUBLIC_KEY_LENGTH: usize = 32;

/// Length of a peer-handshake random nonce.
pub const HANDSHAKE_NONCE_LENGTH: usize = 32;

/// Length of a SHA-256 digest carried by a handshake message.
pub const SHA256_DIGEST_LENGTH: usize = 32;

/// Domain prefix for an initiator's Ed25519 signature.
pub const SESSION_INIT_SIGNATURE_DOMAIN: &[u8] = b"stella session init v1";

/// Domain prefix for a responder's Ed25519 signature.
pub const SESSION_RESPONSE_SIGNATURE_DOMAIN: &[u8] = b"stella session response v1";

/// Domain prefix for a role's key-confirmation associated data.
pub const SESSION_CONFIRM_AUTHENTICATION_DOMAIN: &[u8] = b"stella session confirm v1";

/// Domain prefix for a responder's authenticated rejection signature.
pub const SESSION_REJECT_SIGNATURE_DOMAIN: &[u8] = b"stella session reject v1";

/// Parsed 96-byte fixed peer-handshake header.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HandshakeHeader {
    /// Common datagram fields.
    pub common: CommonHeader,
    /// Claimed sending node.
    pub sender_node_id: NodeId,
    /// Intended receiving node.
    pub receiver_node_id: NodeId,
    /// Non-zero controller epoch authorizing the exchange.
    pub controller_epoch: u64,
    /// Non-zero random exchange identifier.
    pub handshake_id: u64,
    /// Sender wall-clock time as Unix seconds.
    pub timestamp: u64,
    /// Non-zero proposed peer-session identifier.
    pub session_id: u64,
}

impl HandshakeHeader {
    /// Decodes and structurally validates a fixed handshake header.
    ///
    /// This does not check wall-clock freshness, replay caches, grant expiry,
    /// or any cryptographic value.
    ///
    /// # Errors
    ///
    /// Returns [`CodecError`] when the input is truncated or the version,
    /// packet type, flags, lengths, epoch, handshake ID, or session ID is
    /// invalid.
    pub fn decode(input: &[u8]) -> Result<Self, CodecError> {
        let common = CommonHeader::decode(input)?;
        let type_specific = input
            .get(COMMON_HEADER_LENGTH..)
            .ok_or(CodecError::Truncated {
                field: "handshake fixed header",
                offset: input.len(),
                needed: HANDSHAKE_FIXED_HEADER_LENGTH.saturating_sub(input.len()),
                remaining: 0,
            })?;
        let mut cursor = ReadCursor::new(type_specific, COMMON_HEADER_LENGTH);
        let header = Self {
            common,
            sender_node_id: NodeId::from_bytes(cursor.read_array("sender node ID")?),
            receiver_node_id: NodeId::from_bytes(cursor.read_array("receiver node ID")?),
            controller_epoch: cursor.read_u64("controller epoch")?,
            handshake_id: cursor.read_u64("handshake ID")?,
            timestamp: cursor.read_u64("handshake timestamp")?,
            session_id: cursor.read_u64("session ID")?,
        };
        header.validate()?;
        Ok(header)
    }

    /// Encodes this fixed header into the first 96 bytes of `output`.
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
                .get_mut(..HANDSHAKE_FIXED_HEADER_LENGTH)
                .ok_or(CodecError::OutputTooSmall {
                    field: "handshake fixed header",
                    offset: 0,
                    needed: HANDSHAKE_FIXED_HEADER_LENGTH,
                    remaining: output_length,
                })?;
        self.common.encode(fixed_output)?;
        let type_specific =
            fixed_output
                .get_mut(COMMON_HEADER_LENGTH..)
                .ok_or(CodecError::OutputTooSmall {
                    field: "handshake type-specific header",
                    offset: COMMON_HEADER_LENGTH,
                    needed: HANDSHAKE_FIXED_HEADER_LENGTH - COMMON_HEADER_LENGTH,
                    remaining: 0,
                })?;
        let mut cursor = WriteCursor::new(type_specific, COMMON_HEADER_LENGTH);
        cursor.write_bytes(self.sender_node_id.as_bytes(), "sender node ID")?;
        cursor.write_bytes(self.receiver_node_id.as_bytes(), "receiver node ID")?;
        cursor.write_u64(self.controller_epoch, "controller epoch")?;
        cursor.write_u64(self.handshake_id, "handshake ID")?;
        cursor.write_u64(self.timestamp, "handshake timestamp")?;
        cursor.write_u64(self.session_id, "session ID")?;
        Ok(())
    }

    /// Validates all stateless version 0.1 handshake-header invariants.
    ///
    /// # Errors
    ///
    /// Returns [`CodecError`] for a non-handshake packet type, invalid common
    /// header, reserved flag, short fixed header, wrong type-specific payload
    /// length, or zero epoch, handshake ID, or session ID.
    pub fn validate(self) -> Result<(), CodecError> {
        self.common.validate()?;
        let (payload_length, allowed_flags) = handshake_layout(self.common.packet_type)?;
        self.common.validate_flags(allowed_flags)?;
        let header_length = usize::from(self.common.header_length);
        if header_length < HANDSHAKE_FIXED_HEADER_LENGTH {
            return Err(CodecError::HeaderTooShort {
                actual: header_length,
                minimum: HANDSHAKE_FIXED_HEADER_LENGTH,
            });
        }
        let actual_payload = usize::try_from(self.common.payload_length).map_err(|_| {
            CodecError::IntegerOverflow {
                field: "handshake payload length",
            }
        })?;
        if actual_payload != payload_length {
            return Err(CodecError::LengthMismatch {
                field: "handshake payload",
                expected: payload_length,
                actual: actual_payload,
            });
        }
        validate_nonzero(self.controller_epoch, "controller epoch")?;
        validate_nonzero(self.handshake_id, "handshake ID")?;
        validate_nonzero(self.session_id, "session ID")
    }

    fn validate_type(self, expected: PacketType) -> Result<(), CodecError> {
        self.validate()?;
        if self.common.packet_type != expected {
            return Err(CodecError::UnexpectedPacketType {
                expected: expected.as_u8(),
                actual: self.common.packet_type.as_u8(),
            });
        }
        Ok(())
    }
}

/// Borrowed fields used to encode a `SESSION_INIT` payload.
#[derive(Clone, Copy)]
pub struct SessionInitRef<'a> {
    /// Complete controller-signed membership grant for the initiator.
    pub initiator_grant: &'a [u8; MEMBERSHIP_GRANT_LENGTH],
    /// Serial of the receiver grant the initiator expects.
    pub receiver_grant_serial: GrantSerial,
    /// Initiator ephemeral X25519 public key.
    pub initiator_ephemeral: &'a [u8; X25519_PUBLIC_KEY_LENGTH],
    /// Fresh initiator nonce.
    pub initiator_nonce: &'a [u8; HANDSHAKE_NONCE_LENGTH],
    /// Largest datagram the initiator can receive.
    pub max_datagram_size: u32,
    /// Initiator Ed25519 signature over the normative input ranges.
    pub signature: &'a [u8; ED25519_SIGNATURE_LENGTH],
}

/// Borrowed, structurally validated `SESSION_INIT` datagram.
#[derive(Clone)]
pub struct SessionInitView<'a> {
    header: HandshakeHeader,
    datagram: &'a [u8],
    signed_header: &'a [u8],
    extension_bytes: &'a [u8],
    signed_payload: &'a [u8],
    initiator_grant: MembershipGrantView<'a>,
    receiver_grant_serial: GrantSerial,
    initiator_ephemeral: &'a [u8; X25519_PUBLIC_KEY_LENGTH],
    initiator_nonce: &'a [u8; HANDSHAKE_NONCE_LENGTH],
    max_datagram_size: u32,
    signature: &'a [u8; ED25519_SIGNATURE_LENGTH],
}

impl<'a> SessionInitView<'a> {
    /// Decodes one exact `SESSION_INIT` datagram without allocating.
    ///
    /// # Errors
    ///
    /// Returns [`CodecError`] for a malformed header, extension, embedded
    /// grant, field, reserved byte, nonce, datagram limit, signature range,
    /// truncation, or trailing byte.
    pub fn decode(input: &'a [u8]) -> Result<Self, CodecError> {
        let parts = decode_handshake_parts(input, PacketType::SessionInit)?;
        let mut cursor = ReadCursor::new(parts.payload, parts.signed_header.len());
        let grant_bytes = cursor.read_slice(MEMBERSHIP_GRANT_LENGTH, "initiator grant")?;
        let initiator_grant = MembershipGrantView::decode(grant_bytes)?;
        validate_grant_header(&initiator_grant, parts.header)?;
        let receiver_grant_serial =
            GrantSerial::from_bytes(cursor.read_array("receiver grant serial")?);
        validate_nonzero_identifier(receiver_grant_serial.is_zero(), "receiver grant serial")?;
        let initiator_ephemeral = array_ref(
            cursor.read_slice(X25519_PUBLIC_KEY_LENGTH, "initiator ephemeral key")?,
            "initiator ephemeral key",
            parts.signed_header.len() + cursor.position() - X25519_PUBLIC_KEY_LENGTH,
        )?;
        let initiator_nonce = array_ref(
            cursor.read_slice(HANDSHAKE_NONCE_LENGTH, "initiator nonce")?,
            "initiator nonce",
            parts.signed_header.len() + cursor.position() - HANDSHAKE_NONCE_LENGTH,
        )?;
        validate_nonzero_bytes(initiator_nonce, "initiator nonce")?;
        let max_datagram_size = cursor.read_u32("maximum datagram size")?;
        validate_datagram_size(max_datagram_size)?;
        let reserved_offset = parts.signed_header.len() + cursor.position();
        if cursor.read_u32("SESSION_INIT reserved")? != 0 {
            return Err(CodecError::NonZeroReserved {
                field: "SESSION_INIT reserved",
                offset: reserved_offset,
            });
        }
        let signature = array_ref(
            cursor.read_slice(ED25519_SIGNATURE_LENGTH, "SESSION_INIT signature")?,
            "SESSION_INIT signature",
            parts.signed_header.len() + cursor.position() - ED25519_SIGNATURE_LENGTH,
        )?;
        let signed_payload = parts
            .payload
            .get(..SESSION_INIT_SIGNED_PAYLOAD_LENGTH)
            .ok_or(CodecError::Truncated {
                field: "SESSION_INIT signed payload",
                offset: parts.signed_header.len(),
                needed: SESSION_INIT_SIGNED_PAYLOAD_LENGTH,
                remaining: parts.payload.len(),
            })?;

        Ok(Self {
            header: parts.header,
            datagram: parts.datagram,
            signed_header: parts.signed_header,
            extension_bytes: parts.extension_bytes,
            signed_payload,
            initiator_grant,
            receiver_grant_serial,
            initiator_ephemeral,
            initiator_nonce,
            max_datagram_size,
            signature,
        })
    }

    /// Returns the parsed shared handshake header.
    #[must_use]
    pub const fn header(&self) -> HandshakeHeader {
        self.header
    }

    /// Borrows the exact complete datagram used by transcript hashing.
    #[must_use]
    pub const fn datagram(&self) -> &'a [u8] {
        self.datagram
    }

    /// Borrows the complete fixed and extended header covered by the signature.
    #[must_use]
    pub const fn signed_header(&self) -> &'a [u8] {
        self.signed_header
    }

    /// Iterates over the validated header extensions.
    #[must_use]
    pub const fn extensions(&self) -> ExtensionIter<'a> {
        ExtensionIter::new(self.extension_bytes)
    }

    /// Borrows the payload prefix covered by the initiator signature.
    #[must_use]
    pub const fn signed_payload(&self) -> &'a [u8] {
        self.signed_payload
    }

    /// Returns the decoded initiator membership grant.
    #[must_use]
    pub fn initiator_grant(&self) -> MembershipGrantView<'a> {
        self.initiator_grant.clone()
    }

    /// Returns the expected receiver membership-grant serial.
    #[must_use]
    pub const fn receiver_grant_serial(&self) -> GrantSerial {
        self.receiver_grant_serial
    }

    /// Borrows the initiator ephemeral X25519 public key.
    #[must_use]
    pub const fn initiator_ephemeral(&self) -> &'a [u8; X25519_PUBLIC_KEY_LENGTH] {
        self.initiator_ephemeral
    }

    /// Borrows the initiator nonce.
    #[must_use]
    pub const fn initiator_nonce(&self) -> &'a [u8; HANDSHAKE_NONCE_LENGTH] {
        self.initiator_nonce
    }

    /// Returns the initiator receive datagram limit.
    #[must_use]
    pub const fn max_datagram_size(&self) -> u32 {
        self.max_datagram_size
    }

    /// Borrows the initiator Ed25519 signature.
    #[must_use]
    pub const fn signature(&self) -> &'a [u8; ED25519_SIGNATURE_LENGTH] {
        self.signature
    }

    /// Returns the exact datagram length.
    #[must_use]
    pub const fn encoded_len(&self) -> usize {
        self.datagram.len()
    }
}

/// Encodes one complete `SESSION_INIT` datagram into caller-provided storage.
///
/// The signature is copied as supplied; cryptographic signature generation is
/// the caller's responsibility.
///
/// # Errors
///
/// Returns [`CodecError`] when the header, extensions, grant, fields, declared
/// lengths, or output capacity is invalid.
pub fn encode_session_init(
    header: HandshakeHeader,
    extensions: &[ExtensionRef<'_>],
    payload: SessionInitRef<'_>,
    output: &mut [u8],
) -> Result<usize, CodecError> {
    header.validate_type(PacketType::SessionInit)?;
    let grant = MembershipGrantView::decode(payload.initiator_grant)?;
    validate_grant_header(&grant, header)?;
    validate_nonzero_identifier(
        payload.receiver_grant_serial.is_zero(),
        "receiver grant serial",
    )?;
    validate_nonzero_bytes(payload.initiator_nonce, "initiator nonce")?;
    validate_datagram_size(payload.max_datagram_size)?;

    let mut encoded_payload = [0_u8; SESSION_INIT_PAYLOAD_LENGTH];
    let mut cursor = WriteCursor::new(&mut encoded_payload, 0);
    cursor.write_bytes(payload.initiator_grant, "initiator grant")?;
    cursor.write_bytes(
        payload.receiver_grant_serial.as_bytes(),
        "receiver grant serial",
    )?;
    cursor.write_bytes(payload.initiator_ephemeral, "initiator ephemeral key")?;
    cursor.write_bytes(payload.initiator_nonce, "initiator nonce")?;
    cursor.write_u32(payload.max_datagram_size, "maximum datagram size")?;
    cursor.write_u32(0, "SESSION_INIT reserved")?;
    cursor.write_bytes(payload.signature, "SESSION_INIT signature")?;
    encode_handshake_datagram(header, extensions, &encoded_payload, output)
}

/// Borrowed fields used to encode a `SESSION_RESPONSE` payload.
#[derive(Clone, Copy)]
pub struct SessionResponseRef<'a> {
    /// Complete controller-signed membership grant for the responder.
    pub responder_grant: &'a [u8; MEMBERSHIP_GRANT_LENGTH],
    /// SHA-256 digest of the exact initiation datagram.
    pub init_hash: &'a [u8; SHA256_DIGEST_LENGTH],
    /// Responder ephemeral X25519 public key.
    pub responder_ephemeral: &'a [u8; X25519_PUBLIC_KEY_LENGTH],
    /// Fresh responder nonce.
    pub responder_nonce: &'a [u8; HANDSHAKE_NONCE_LENGTH],
    /// Largest datagram the responder can receive.
    pub max_datagram_size: u32,
    /// Responder Ed25519 signature over the normative input ranges.
    pub signature: &'a [u8; ED25519_SIGNATURE_LENGTH],
}

/// Borrowed, structurally validated `SESSION_RESPONSE` datagram.
#[derive(Clone)]
pub struct SessionResponseView<'a> {
    header: HandshakeHeader,
    datagram: &'a [u8],
    signed_header: &'a [u8],
    extension_bytes: &'a [u8],
    signed_payload: &'a [u8],
    responder_grant: MembershipGrantView<'a>,
    init_hash: &'a [u8; SHA256_DIGEST_LENGTH],
    responder_ephemeral: &'a [u8; X25519_PUBLIC_KEY_LENGTH],
    responder_nonce: &'a [u8; HANDSHAKE_NONCE_LENGTH],
    max_datagram_size: u32,
    signature: &'a [u8; ED25519_SIGNATURE_LENGTH],
}

impl<'a> SessionResponseView<'a> {
    /// Decodes one exact `SESSION_RESPONSE` datagram without allocating.
    ///
    /// # Errors
    ///
    /// Returns [`CodecError`] for a malformed header, extension, embedded
    /// grant, field, reserved byte, nonce, datagram limit, signature range,
    /// truncation, or trailing byte.
    pub fn decode(input: &'a [u8]) -> Result<Self, CodecError> {
        let parts = decode_handshake_parts(input, PacketType::SessionResponse)?;
        let mut cursor = ReadCursor::new(parts.payload, parts.signed_header.len());
        let grant_bytes = cursor.read_slice(MEMBERSHIP_GRANT_LENGTH, "responder grant")?;
        let responder_grant = MembershipGrantView::decode(grant_bytes)?;
        validate_grant_header(&responder_grant, parts.header)?;
        let init_hash = array_ref(
            cursor.read_slice(SHA256_DIGEST_LENGTH, "init hash")?,
            "init hash",
            parts.signed_header.len() + cursor.position() - SHA256_DIGEST_LENGTH,
        )?;
        let responder_ephemeral = array_ref(
            cursor.read_slice(X25519_PUBLIC_KEY_LENGTH, "responder ephemeral key")?,
            "responder ephemeral key",
            parts.signed_header.len() + cursor.position() - X25519_PUBLIC_KEY_LENGTH,
        )?;
        let responder_nonce = array_ref(
            cursor.read_slice(HANDSHAKE_NONCE_LENGTH, "responder nonce")?,
            "responder nonce",
            parts.signed_header.len() + cursor.position() - HANDSHAKE_NONCE_LENGTH,
        )?;
        validate_nonzero_bytes(responder_nonce, "responder nonce")?;
        let max_datagram_size = cursor.read_u32("maximum datagram size")?;
        validate_datagram_size(max_datagram_size)?;
        let reserved_offset = parts.signed_header.len() + cursor.position();
        if cursor.read_u32("SESSION_RESPONSE reserved")? != 0 {
            return Err(CodecError::NonZeroReserved {
                field: "SESSION_RESPONSE reserved",
                offset: reserved_offset,
            });
        }
        let signature = array_ref(
            cursor.read_slice(ED25519_SIGNATURE_LENGTH, "SESSION_RESPONSE signature")?,
            "SESSION_RESPONSE signature",
            parts.signed_header.len() + cursor.position() - ED25519_SIGNATURE_LENGTH,
        )?;
        let signed_payload = parts
            .payload
            .get(..SESSION_RESPONSE_SIGNED_PAYLOAD_LENGTH)
            .ok_or(CodecError::Truncated {
                field: "SESSION_RESPONSE signed payload",
                offset: parts.signed_header.len(),
                needed: SESSION_RESPONSE_SIGNED_PAYLOAD_LENGTH,
                remaining: parts.payload.len(),
            })?;

        Ok(Self {
            header: parts.header,
            datagram: parts.datagram,
            signed_header: parts.signed_header,
            extension_bytes: parts.extension_bytes,
            signed_payload,
            responder_grant,
            init_hash,
            responder_ephemeral,
            responder_nonce,
            max_datagram_size,
            signature,
        })
    }

    /// Returns the parsed shared handshake header.
    #[must_use]
    pub const fn header(&self) -> HandshakeHeader {
        self.header
    }

    /// Borrows the exact complete datagram used by transcript hashing.
    #[must_use]
    pub const fn datagram(&self) -> &'a [u8] {
        self.datagram
    }

    /// Borrows the complete fixed and extended header covered by the signature.
    #[must_use]
    pub const fn signed_header(&self) -> &'a [u8] {
        self.signed_header
    }

    /// Iterates over the validated header extensions.
    #[must_use]
    pub const fn extensions(&self) -> ExtensionIter<'a> {
        ExtensionIter::new(self.extension_bytes)
    }

    /// Borrows the payload prefix covered by the responder signature.
    #[must_use]
    pub const fn signed_payload(&self) -> &'a [u8] {
        self.signed_payload
    }

    /// Returns the decoded responder membership grant.
    #[must_use]
    pub fn responder_grant(&self) -> MembershipGrantView<'a> {
        self.responder_grant.clone()
    }

    /// Borrows the SHA-256 digest of the exact initiation datagram.
    #[must_use]
    pub const fn init_hash(&self) -> &'a [u8; SHA256_DIGEST_LENGTH] {
        self.init_hash
    }

    /// Borrows the responder ephemeral X25519 public key.
    #[must_use]
    pub const fn responder_ephemeral(&self) -> &'a [u8; X25519_PUBLIC_KEY_LENGTH] {
        self.responder_ephemeral
    }

    /// Borrows the responder nonce.
    #[must_use]
    pub const fn responder_nonce(&self) -> &'a [u8; HANDSHAKE_NONCE_LENGTH] {
        self.responder_nonce
    }

    /// Returns the responder receive datagram limit.
    #[must_use]
    pub const fn max_datagram_size(&self) -> u32 {
        self.max_datagram_size
    }

    /// Borrows the responder Ed25519 signature.
    #[must_use]
    pub const fn signature(&self) -> &'a [u8; ED25519_SIGNATURE_LENGTH] {
        self.signature
    }

    /// Returns the exact datagram length.
    #[must_use]
    pub const fn encoded_len(&self) -> usize {
        self.datagram.len()
    }
}

/// Encodes one complete `SESSION_RESPONSE` datagram into caller-provided storage.
///
/// The signature is copied as supplied; cryptographic signature generation is
/// the caller's responsibility.
///
/// # Errors
///
/// Returns [`CodecError`] when the header, extensions, grant, fields, declared
/// lengths, or output capacity is invalid.
pub fn encode_session_response(
    header: HandshakeHeader,
    extensions: &[ExtensionRef<'_>],
    payload: SessionResponseRef<'_>,
    output: &mut [u8],
) -> Result<usize, CodecError> {
    header.validate_type(PacketType::SessionResponse)?;
    let grant = MembershipGrantView::decode(payload.responder_grant)?;
    validate_grant_header(&grant, header)?;
    validate_nonzero_bytes(payload.responder_nonce, "responder nonce")?;
    validate_datagram_size(payload.max_datagram_size)?;

    let mut encoded_payload = [0_u8; SESSION_RESPONSE_PAYLOAD_LENGTH];
    let mut cursor = WriteCursor::new(&mut encoded_payload, 0);
    cursor.write_bytes(payload.responder_grant, "responder grant")?;
    cursor.write_bytes(payload.init_hash, "init hash")?;
    cursor.write_bytes(payload.responder_ephemeral, "responder ephemeral key")?;
    cursor.write_bytes(payload.responder_nonce, "responder nonce")?;
    cursor.write_u32(payload.max_datagram_size, "maximum datagram size")?;
    cursor.write_u32(0, "SESSION_RESPONSE reserved")?;
    cursor.write_bytes(payload.signature, "SESSION_RESPONSE signature")?;
    encode_handshake_datagram(header, extensions, &encoded_payload, output)
}

/// Role proved by a `SESSION_CONFIRM` message.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum SessionConfirmRole {
    /// Confirmation sent by the handshake initiator.
    Initiator = 1,
    /// Confirmation sent by the handshake responder.
    Responder = 2,
}

impl SessionConfirmRole {
    /// Returns the canonical role byte.
    #[must_use]
    pub const fn as_u8(self) -> u8 {
        self as u8
    }

    const fn required_flag(self) -> u8 {
        match self {
            Self::Initiator => 0,
            Self::Responder => SESSION_CONFIRM_RESPONDER_FLAG,
        }
    }
}

impl TryFrom<u8> for SessionConfirmRole {
    type Error = CodecError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Self::Initiator),
            2 => Ok(Self::Responder),
            _ => Err(CodecError::InvalidEnumValue {
                field: "SESSION_CONFIRM role",
                value: u64::from(value),
            }),
        }
    }
}

/// Borrowed fields used to encode a `SESSION_CONFIRM` payload.
#[derive(Clone, Copy)]
pub struct SessionConfirmRef<'a> {
    /// SHA-256 digest of the exact response datagram.
    pub response_hash: &'a [u8; SHA256_DIGEST_LENGTH],
    /// Side sending this confirmation.
    pub role: SessionConfirmRole,
    /// ChaCha20-Poly1305 tag over empty plaintext and the normative associated data.
    pub confirmation_tag: &'a [u8; crate::AUTHENTICATION_TAG_LENGTH],
}

/// Borrowed, structurally validated `SESSION_CONFIRM` datagram.
#[derive(Clone)]
pub struct SessionConfirmView<'a> {
    header: HandshakeHeader,
    datagram: &'a [u8],
    authenticated_header: &'a [u8],
    extension_bytes: &'a [u8],
    authenticated_payload: &'a [u8],
    response_hash: &'a [u8; SHA256_DIGEST_LENGTH],
    role: SessionConfirmRole,
    confirmation_tag: &'a [u8; crate::AUTHENTICATION_TAG_LENGTH],
}

impl<'a> SessionConfirmView<'a> {
    /// Decodes one exact `SESSION_CONFIRM` datagram without allocating.
    ///
    /// This only validates the encoded role and its header-flag pairing. Tag
    /// verification and transcript selection remain the caller's responsibility.
    ///
    /// # Errors
    ///
    /// Returns [`CodecError`] for a malformed header, extension, response hash,
    /// role, reserved byte, role/flag pairing, tag, truncation, or trailing byte.
    pub fn decode(input: &'a [u8]) -> Result<Self, CodecError> {
        let parts = decode_handshake_parts(input, PacketType::SessionConfirm)?;
        let mut cursor = ReadCursor::new(parts.payload, parts.signed_header.len());
        let response_hash = array_ref(
            cursor.read_slice(SHA256_DIGEST_LENGTH, "response hash")?,
            "response hash",
            parts.signed_header.len() + cursor.position() - SHA256_DIGEST_LENGTH,
        )?;
        let role = SessionConfirmRole::try_from(cursor.read_u8("SESSION_CONFIRM role")?)?;
        validate_confirm_role_flag(role, parts.header.common.flags)?;
        let reserved_offset = parts.signed_header.len() + cursor.position();
        let reserved = cursor.read_slice(7, "SESSION_CONFIRM reserved")?;
        if reserved.iter().any(|byte| *byte != 0) {
            return Err(CodecError::NonZeroReserved {
                field: "SESSION_CONFIRM reserved",
                offset: reserved_offset,
            });
        }
        let confirmation_tag = array_ref(
            cursor.read_slice(crate::AUTHENTICATION_TAG_LENGTH, "confirmation tag")?,
            "confirmation tag",
            parts.signed_header.len() + cursor.position() - crate::AUTHENTICATION_TAG_LENGTH,
        )?;
        let authenticated_payload = parts
            .payload
            .get(..SESSION_CONFIRM_AUTHENTICATED_PAYLOAD_LENGTH)
            .ok_or(CodecError::Truncated {
                field: "SESSION_CONFIRM authenticated payload",
                offset: parts.signed_header.len(),
                needed: SESSION_CONFIRM_AUTHENTICATED_PAYLOAD_LENGTH,
                remaining: parts.payload.len(),
            })?;

        Ok(Self {
            header: parts.header,
            datagram: parts.datagram,
            authenticated_header: parts.signed_header,
            extension_bytes: parts.extension_bytes,
            authenticated_payload,
            response_hash,
            role,
            confirmation_tag,
        })
    }

    /// Returns the parsed shared handshake header.
    #[must_use]
    pub const fn header(&self) -> HandshakeHeader {
        self.header
    }

    /// Borrows the exact complete confirmation datagram.
    #[must_use]
    pub const fn datagram(&self) -> &'a [u8] {
        self.datagram
    }

    /// Borrows the complete fixed and extended header used as associated data.
    #[must_use]
    pub const fn authenticated_header(&self) -> &'a [u8] {
        self.authenticated_header
    }

    /// Iterates over the validated header extensions.
    #[must_use]
    pub const fn extensions(&self) -> ExtensionIter<'a> {
        ExtensionIter::new(self.extension_bytes)
    }

    /// Borrows the payload prefix used as confirmation associated data.
    #[must_use]
    pub const fn authenticated_payload(&self) -> &'a [u8] {
        self.authenticated_payload
    }

    /// Borrows the SHA-256 digest of the exact response datagram.
    #[must_use]
    pub const fn response_hash(&self) -> &'a [u8; SHA256_DIGEST_LENGTH] {
        self.response_hash
    }

    /// Returns the role proved by this confirmation.
    #[must_use]
    pub const fn role(&self) -> SessionConfirmRole {
        self.role
    }

    /// Borrows the ChaCha20-Poly1305 confirmation tag.
    #[must_use]
    pub const fn confirmation_tag(&self) -> &'a [u8; crate::AUTHENTICATION_TAG_LENGTH] {
        self.confirmation_tag
    }

    /// Returns the exact datagram length.
    #[must_use]
    pub const fn encoded_len(&self) -> usize {
        self.datagram.len()
    }
}

/// Encodes one complete `SESSION_CONFIRM` datagram into caller-provided storage.
///
/// The tag is copied as supplied; cryptographic tag generation is the caller's
/// responsibility.
///
/// # Errors
///
/// Returns [`CodecError`] when the header, extensions, role/flag pairing,
/// declared lengths, or output capacity is invalid.
pub fn encode_session_confirm(
    header: HandshakeHeader,
    extensions: &[ExtensionRef<'_>],
    payload: SessionConfirmRef<'_>,
    output: &mut [u8],
) -> Result<usize, CodecError> {
    header.validate_type(PacketType::SessionConfirm)?;
    validate_confirm_role_flag(payload.role, header.common.flags)?;
    let mut encoded_payload = [0_u8; SESSION_CONFIRM_PAYLOAD_LENGTH];
    let mut cursor = WriteCursor::new(&mut encoded_payload, 0);
    cursor.write_bytes(payload.response_hash, "response hash")?;
    cursor.write_u8(payload.role.as_u8(), "SESSION_CONFIRM role")?;
    cursor.write_bytes(&[0; 7], "SESSION_CONFIRM reserved")?;
    cursor.write_bytes(payload.confirmation_tag, "confirmation tag")?;
    encode_handshake_datagram(header, extensions, &encoded_payload, output)
}

/// Authenticated reason carried by a `SESSION_REJECT` message.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SessionRejectReason {
    /// The initiation references a stale controller epoch.
    StaleEpoch,
    /// A required membership grant has expired.
    GrantExpired,
    /// The peer grants or network policy do not agree.
    PolicyMismatch,
    /// The proposed session or handshake collides with existing state.
    SessionCollision,
    /// The responder cannot currently accept another handshake.
    TemporarilyBusy,
    /// The negotiated path cannot carry the minimum protected frame fragment.
    PathMtuTooSmall,
    /// Future non-zero rejection reason unknown to version 0.1.
    Unknown(u16),
}

impl SessionRejectReason {
    /// Returns the canonical or preserved reason value.
    #[must_use]
    pub const fn as_u16(self) -> u16 {
        match self {
            Self::StaleEpoch => 1,
            Self::GrantExpired => 2,
            Self::PolicyMismatch => 3,
            Self::SessionCollision => 4,
            Self::TemporarilyBusy => 5,
            Self::PathMtuTooSmall => 6,
            Self::Unknown(value) => value,
        }
    }
}

impl TryFrom<u16> for SessionRejectReason {
    type Error = CodecError;

    fn try_from(value: u16) -> Result<Self, Self::Error> {
        match value {
            0 => Err(CodecError::InvalidEnumValue {
                field: "SESSION_REJECT reason",
                value: 0,
            }),
            1 => Ok(Self::StaleEpoch),
            2 => Ok(Self::GrantExpired),
            3 => Ok(Self::PolicyMismatch),
            4 => Ok(Self::SessionCollision),
            5 => Ok(Self::TemporarilyBusy),
            6 => Ok(Self::PathMtuTooSmall),
            unknown => Ok(Self::Unknown(unknown)),
        }
    }
}

/// Borrowed fields used to encode a `SESSION_REJECT` payload.
#[derive(Clone, Copy)]
pub struct SessionRejectRef<'a> {
    /// Authenticated diagnostic reason.
    pub reason: SessionRejectReason,
    /// Zero, or the bounded delay before a new attempt.
    pub retry_after_ms: u32,
    /// SHA-256 digest of the rejected initiation datagram.
    pub init_hash: &'a [u8; SHA256_DIGEST_LENGTH],
    /// Responder Ed25519 signature over the normative input ranges.
    pub signature: &'a [u8; ED25519_SIGNATURE_LENGTH],
}

/// Borrowed, structurally validated `SESSION_REJECT` datagram.
#[derive(Clone)]
pub struct SessionRejectView<'a> {
    header: HandshakeHeader,
    datagram: &'a [u8],
    signed_header: &'a [u8],
    extension_bytes: &'a [u8],
    signed_payload: &'a [u8],
    reason: SessionRejectReason,
    retry_after_ms: u32,
    init_hash: &'a [u8; SHA256_DIGEST_LENGTH],
    signature: &'a [u8; ED25519_SIGNATURE_LENGTH],
}

impl<'a> SessionRejectView<'a> {
    /// Decodes one exact `SESSION_REJECT` datagram without allocating.
    ///
    /// # Errors
    ///
    /// Returns [`CodecError`] for a malformed header, extension, zero reason,
    /// reserved byte, retry delay, digest, signature range, truncation, or
    /// trailing byte.
    pub fn decode(input: &'a [u8]) -> Result<Self, CodecError> {
        let parts = decode_handshake_parts(input, PacketType::SessionReject)?;
        let mut cursor = ReadCursor::new(parts.payload, parts.signed_header.len());
        let reason = SessionRejectReason::try_from(cursor.read_u16("SESSION_REJECT reason")?)?;
        let reserved_offset = parts.signed_header.len() + cursor.position();
        if cursor.read_u16("SESSION_REJECT reserved")? != 0 {
            return Err(CodecError::NonZeroReserved {
                field: "SESSION_REJECT reserved",
                offset: reserved_offset,
            });
        }
        let retry_after_ms = cursor.read_u32("retry after milliseconds")?;
        validate_retry_after(retry_after_ms)?;
        let init_hash = array_ref(
            cursor.read_slice(SHA256_DIGEST_LENGTH, "init hash")?,
            "init hash",
            parts.signed_header.len() + cursor.position() - SHA256_DIGEST_LENGTH,
        )?;
        let signature = array_ref(
            cursor.read_slice(ED25519_SIGNATURE_LENGTH, "SESSION_REJECT signature")?,
            "SESSION_REJECT signature",
            parts.signed_header.len() + cursor.position() - ED25519_SIGNATURE_LENGTH,
        )?;
        let signed_payload = parts
            .payload
            .get(..SESSION_REJECT_SIGNED_PAYLOAD_LENGTH)
            .ok_or(CodecError::Truncated {
                field: "SESSION_REJECT signed payload",
                offset: parts.signed_header.len(),
                needed: SESSION_REJECT_SIGNED_PAYLOAD_LENGTH,
                remaining: parts.payload.len(),
            })?;

        Ok(Self {
            header: parts.header,
            datagram: parts.datagram,
            signed_header: parts.signed_header,
            extension_bytes: parts.extension_bytes,
            signed_payload,
            reason,
            retry_after_ms,
            init_hash,
            signature,
        })
    }

    /// Returns the parsed shared handshake header.
    #[must_use]
    pub const fn header(&self) -> HandshakeHeader {
        self.header
    }

    /// Borrows the exact complete rejection datagram.
    #[must_use]
    pub const fn datagram(&self) -> &'a [u8] {
        self.datagram
    }

    /// Borrows the complete fixed and extended header covered by the signature.
    #[must_use]
    pub const fn signed_header(&self) -> &'a [u8] {
        self.signed_header
    }

    /// Iterates over the validated header extensions.
    #[must_use]
    pub const fn extensions(&self) -> ExtensionIter<'a> {
        ExtensionIter::new(self.extension_bytes)
    }

    /// Borrows the payload prefix covered by the responder signature.
    #[must_use]
    pub const fn signed_payload(&self) -> &'a [u8] {
        self.signed_payload
    }

    /// Returns the registered or preserved future rejection reason.
    #[must_use]
    pub const fn reason(&self) -> SessionRejectReason {
        self.reason
    }

    /// Returns the recommended retry delay in milliseconds.
    #[must_use]
    pub const fn retry_after_ms(&self) -> u32 {
        self.retry_after_ms
    }

    /// Borrows the SHA-256 digest of the rejected initiation datagram.
    #[must_use]
    pub const fn init_hash(&self) -> &'a [u8; SHA256_DIGEST_LENGTH] {
        self.init_hash
    }

    /// Borrows the responder Ed25519 signature.
    #[must_use]
    pub const fn signature(&self) -> &'a [u8; ED25519_SIGNATURE_LENGTH] {
        self.signature
    }

    /// Returns the exact datagram length.
    #[must_use]
    pub const fn encoded_len(&self) -> usize {
        self.datagram.len()
    }
}

/// Encodes one complete `SESSION_REJECT` datagram into caller-provided storage.
///
/// The signature is copied as supplied; cryptographic signature generation is
/// the caller's responsibility.
///
/// # Errors
///
/// Returns [`CodecError`] when the header, extensions, reason, retry delay,
/// declared lengths, or output capacity is invalid.
pub fn encode_session_reject(
    header: HandshakeHeader,
    extensions: &[ExtensionRef<'_>],
    payload: SessionRejectRef<'_>,
    output: &mut [u8],
) -> Result<usize, CodecError> {
    header.validate_type(PacketType::SessionReject)?;
    let _reason = SessionRejectReason::try_from(payload.reason.as_u16())?;
    validate_retry_after(payload.retry_after_ms)?;
    let mut encoded_payload = [0_u8; SESSION_REJECT_PAYLOAD_LENGTH];
    let mut cursor = WriteCursor::new(&mut encoded_payload, 0);
    cursor.write_u16(payload.reason.as_u16(), "SESSION_REJECT reason")?;
    cursor.write_u16(0, "SESSION_REJECT reserved")?;
    cursor.write_u32(payload.retry_after_ms, "retry after milliseconds")?;
    cursor.write_bytes(payload.init_hash, "init hash")?;
    cursor.write_bytes(payload.signature, "SESSION_REJECT signature")?;
    encode_handshake_datagram(header, extensions, &encoded_payload, output)
}

struct HandshakeParts<'a> {
    header: HandshakeHeader,
    datagram: &'a [u8],
    signed_header: &'a [u8],
    extension_bytes: &'a [u8],
    payload: &'a [u8],
}

fn decode_handshake_parts(
    input: &[u8],
    expected_type: PacketType,
) -> Result<HandshakeParts<'_>, CodecError> {
    let header = HandshakeHeader::decode(input)?;
    header.validate_type(expected_type)?;
    let header_length = usize::from(header.common.header_length);
    let payload_length =
        usize::try_from(header.common.payload_length).map_err(|_| CodecError::IntegerOverflow {
            field: "handshake payload length",
        })?;
    let expected_length =
        header_length
            .checked_add(payload_length)
            .ok_or(CodecError::IntegerOverflow {
                field: "handshake datagram length",
            })?;
    validate_record_length(input.len(), expected_length, "handshake datagram")?;
    let signed_header = input.get(..header_length).ok_or(CodecError::Truncated {
        field: "handshake signed header",
        offset: 0,
        needed: header_length,
        remaining: input.len(),
    })?;
    let extension_bytes = input
        .get(HANDSHAKE_FIXED_HEADER_LENGTH..header_length)
        .ok_or(CodecError::Truncated {
            field: "handshake extension block",
            offset: HANDSHAKE_FIXED_HEADER_LENGTH,
            needed: header_length.saturating_sub(HANDSHAKE_FIXED_HEADER_LENGTH),
            remaining: input.len().saturating_sub(HANDSHAKE_FIXED_HEADER_LENGTH),
        })?;
    validate_extension_block(extension_bytes, HANDSHAKE_FIXED_HEADER_LENGTH)?;
    let payload = input
        .get(header_length..expected_length)
        .ok_or(CodecError::Truncated {
            field: "handshake payload",
            offset: header_length,
            needed: payload_length,
            remaining: input.len().saturating_sub(header_length),
        })?;
    Ok(HandshakeParts {
        header,
        datagram: input,
        signed_header,
        extension_bytes,
        payload,
    })
}

fn encode_handshake_datagram(
    header: HandshakeHeader,
    extensions: &[ExtensionRef<'_>],
    payload: &[u8],
    output: &mut [u8],
) -> Result<usize, CodecError> {
    header.validate()?;
    let extension_length = extensions_encoded_len(extensions)?;
    let expected_header_length = HANDSHAKE_FIXED_HEADER_LENGTH
        .checked_add(extension_length)
        .ok_or(CodecError::IntegerOverflow {
            field: "handshake header length",
        })?;
    let declared_header_length = usize::from(header.common.header_length);
    if declared_header_length != expected_header_length {
        return Err(CodecError::LengthMismatch {
            field: "handshake header",
            expected: expected_header_length,
            actual: declared_header_length,
        });
    }
    let declared_payload_length =
        usize::try_from(header.common.payload_length).map_err(|_| CodecError::IntegerOverflow {
            field: "handshake payload length",
        })?;
    if declared_payload_length != payload.len() {
        return Err(CodecError::LengthMismatch {
            field: "handshake payload",
            expected: payload.len(),
            actual: declared_payload_length,
        });
    }
    let encoded_length =
        expected_header_length
            .checked_add(payload.len())
            .ok_or(CodecError::IntegerOverflow {
                field: "handshake datagram length",
            })?;
    if output.len() < encoded_length {
        return Err(CodecError::OutputTooSmall {
            field: "handshake datagram",
            offset: 0,
            needed: encoded_length,
            remaining: output.len(),
        });
    }

    let output_length = output.len();
    let datagram = output
        .get_mut(..encoded_length)
        .ok_or(CodecError::OutputTooSmall {
            field: "handshake datagram",
            offset: 0,
            needed: encoded_length,
            remaining: output_length,
        })?;
    let datagram_length = datagram.len();
    let fixed_header =
        datagram
            .get_mut(..HANDSHAKE_FIXED_HEADER_LENGTH)
            .ok_or(CodecError::OutputTooSmall {
                field: "handshake fixed header",
                offset: 0,
                needed: HANDSHAKE_FIXED_HEADER_LENGTH,
                remaining: datagram_length,
            })?;
    header.encode(fixed_header)?;
    let extension_output = datagram
        .get_mut(HANDSHAKE_FIXED_HEADER_LENGTH..expected_header_length)
        .ok_or(CodecError::OutputTooSmall {
            field: "handshake extension block",
            offset: HANDSHAKE_FIXED_HEADER_LENGTH,
            needed: extension_length,
            remaining: datagram_length.saturating_sub(HANDSHAKE_FIXED_HEADER_LENGTH),
        })?;
    encode_extension_block_at(extensions, extension_output, HANDSHAKE_FIXED_HEADER_LENGTH)?;
    let payload_output = datagram
        .get_mut(expected_header_length..encoded_length)
        .ok_or(CodecError::OutputTooSmall {
            field: "handshake payload",
            offset: expected_header_length,
            needed: payload.len(),
            remaining: datagram_length.saturating_sub(expected_header_length),
        })?;
    payload_output.copy_from_slice(payload);
    Ok(encoded_length)
}

fn handshake_layout(packet_type: PacketType) -> Result<(usize, u8), CodecError> {
    match packet_type {
        PacketType::SessionInit => Ok((SESSION_INIT_PAYLOAD_LENGTH, 0)),
        PacketType::SessionResponse => Ok((SESSION_RESPONSE_PAYLOAD_LENGTH, 0)),
        PacketType::SessionConfirm => Ok((
            SESSION_CONFIRM_PAYLOAD_LENGTH,
            SESSION_CONFIRM_RESPONDER_FLAG,
        )),
        PacketType::SessionReject => Ok((SESSION_REJECT_PAYLOAD_LENGTH, 0)),
        PacketType::Data | PacketType::Keepalive => Err(CodecError::InvalidEnumValue {
            field: "handshake packet type",
            value: u64::from(packet_type.as_u8()),
        }),
    }
}

fn validate_grant_header(
    grant: &MembershipGrantView<'_>,
    header: HandshakeHeader,
) -> Result<(), CodecError> {
    let fields = grant.grant();
    validate_consistency(fields.node_id == header.sender_node_id, "node ID")?;
    validate_consistency(fields.network_id == header.common.network_id, "network ID")?;
    validate_consistency(
        fields.controller_epoch == header.controller_epoch,
        "controller epoch",
    )
}

fn validate_consistency(matches: bool, field: &'static str) -> Result<(), CodecError> {
    if !matches {
        return Err(CodecError::InconsistentField {
            context: "membership grant and handshake header",
            field,
        });
    }
    Ok(())
}

fn validate_datagram_size(value: u32) -> Result<(), CodecError> {
    if !(MIN_ENDPOINT_DATAGRAM_SIZE..=MAX_ENDPOINT_DATAGRAM_SIZE).contains(&value) {
        return Err(CodecError::ValueOutOfRange {
            field: "maximum datagram size",
            actual: u64::from(value),
            minimum: u64::from(MIN_ENDPOINT_DATAGRAM_SIZE),
            maximum: u64::from(MAX_ENDPOINT_DATAGRAM_SIZE),
        });
    }
    Ok(())
}

fn validate_confirm_role_flag(role: SessionConfirmRole, flags: u8) -> Result<(), CodecError> {
    if flags != role.required_flag() {
        return Err(CodecError::InconsistentField {
            context: "SESSION_CONFIRM role and header flags",
            field: "confirmation role",
        });
    }
    Ok(())
}

fn validate_retry_after(value: u32) -> Result<(), CodecError> {
    if value != 0 && !(100..=60_000).contains(&value) {
        return Err(CodecError::ValueOutOfRange {
            field: "retry after milliseconds",
            actual: u64::from(value),
            minimum: 100,
            maximum: 60_000,
        });
    }
    Ok(())
}

fn validate_nonzero(value: u64, field: &'static str) -> Result<(), CodecError> {
    if value == 0 {
        return Err(CodecError::ZeroField { field });
    }
    Ok(())
}

fn validate_nonzero_identifier(is_zero: bool, field: &'static str) -> Result<(), CodecError> {
    if is_zero {
        return Err(CodecError::ZeroField { field });
    }
    Ok(())
}

fn validate_nonzero_bytes(value: &[u8], field: &'static str) -> Result<(), CodecError> {
    if value.iter().all(|byte| *byte == 0) {
        return Err(CodecError::ZeroField { field });
    }
    Ok(())
}

fn array_ref<'a, const LENGTH: usize>(
    value: &'a [u8],
    field: &'static str,
    offset: usize,
) -> Result<&'a [u8; LENGTH], CodecError> {
    <&[u8; LENGTH]>::try_from(value).map_err(|_| CodecError::Truncated {
        field,
        offset,
        needed: LENGTH,
        remaining: value.len(),
    })
}

#[cfg(test)]
mod tests {
    use stella_common::{ControllerId, GrantSerial, NetworkId, NodeId};

    use super::{
        encode_session_confirm, encode_session_init, encode_session_reject,
        encode_session_response, HandshakeHeader, SessionConfirmRef, SessionConfirmRole,
        SessionConfirmView, SessionInitRef, SessionInitView, SessionRejectReason, SessionRejectRef,
        SessionRejectView, SessionResponseRef, SessionResponseView, HANDSHAKE_FIXED_HEADER_LENGTH,
        SESSION_CONFIRM_AUTHENTICATED_PAYLOAD_LENGTH, SESSION_CONFIRM_PAYLOAD_LENGTH,
        SESSION_CONFIRM_RESPONDER_FLAG, SESSION_INIT_PAYLOAD_LENGTH,
        SESSION_INIT_SIGNED_PAYLOAD_LENGTH, SESSION_REJECT_PAYLOAD_LENGTH,
        SESSION_REJECT_SIGNED_PAYLOAD_LENGTH, SESSION_RESPONSE_PAYLOAD_LENGTH,
        SESSION_RESPONSE_SIGNED_PAYLOAD_LENGTH,
    };
    use crate::{
        encode_membership_grant, CodecError, CommonHeader, ConfidentialityPolicy, ExtensionRef,
        MembershipGrant, MembershipPermissions, PacketType, ProtocolVersion,
        ED25519_SIGNATURE_LENGTH, MEMBERSHIP_GRANT_LENGTH,
    };

    const NETWORK_ID: NetworkId =
        NetworkId::from_bytes([0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15]);
    const INITIATOR_ID: NodeId = NodeId::from_bytes([0x11; 16]);
    const RESPONDER_ID: NodeId = NodeId::from_bytes([0x22; 16]);
    const GRANT_SIGNATURE: [u8; ED25519_SIGNATURE_LENGTH] = [0xa1; ED25519_SIGNATURE_LENGTH];
    const SESSION_SIGNATURE: [u8; ED25519_SIGNATURE_LENGTH] = [0xb2; ED25519_SIGNATURE_LENGTH];
    const EPHEMERAL: [u8; 32] = [0xc3; 32];
    const NONCE: [u8; 32] = [0xd4; 32];
    const INIT_HASH: [u8; 32] = [0xe5; 32];

    fn header(packet_type: PacketType) -> HandshakeHeader {
        let (payload_length, sender, receiver) = match packet_type {
            PacketType::SessionInit => (SESSION_INIT_PAYLOAD_LENGTH, INITIATOR_ID, RESPONDER_ID),
            PacketType::SessionResponse => {
                (SESSION_RESPONSE_PAYLOAD_LENGTH, RESPONDER_ID, INITIATOR_ID)
            }
            PacketType::SessionConfirm => {
                (SESSION_CONFIRM_PAYLOAD_LENGTH, INITIATOR_ID, RESPONDER_ID)
            }
            PacketType::SessionReject => {
                (SESSION_REJECT_PAYLOAD_LENGTH, RESPONDER_ID, INITIATOR_ID)
            }
            PacketType::Data | PacketType::Keepalive => {
                panic!("test helper requires handshake packet")
            }
        };
        HandshakeHeader {
            common: CommonHeader {
                version: ProtocolVersion::CURRENT,
                packet_type,
                flags: 0,
                header_length: u16::try_from(HANDSHAKE_FIXED_HEADER_LENGTH)
                    .expect("fixed header length fits u16"),
                payload_length: u32::try_from(payload_length).expect("payload length fits u32"),
                network_id: NETWORK_ID,
            },
            sender_node_id: sender,
            receiver_node_id: receiver,
            controller_epoch: 7,
            handshake_id: 8,
            timestamp: 1_788_000_000,
            session_id: 9,
        }
    }

    fn grant(node_id: NodeId) -> MembershipGrant {
        MembershipGrant {
            confidentiality: ConfidentialityPolicy::Encrypt,
            permissions: MembershipPermissions::ALL,
            network_id: NETWORK_ID,
            node_id,
            node_public_key: [0x31; 32],
            controller_id: ControllerId::from_bytes([0x41; 16]),
            controller_epoch: 7,
            not_before: 1_788_000_000,
            not_after: 1_788_003_600,
            max_frame_size: 1_514,
            max_flood_peers: 16,
            flood_rate: 100,
            flood_burst: 200,
            policy_digest: [0x51; 32],
            grant_serial: GrantSerial::from_bytes([0x61; 16]),
        }
    }

    fn encoded_grant(node_id: NodeId) -> [u8; MEMBERSHIP_GRANT_LENGTH] {
        let mut encoded = [0; MEMBERSHIP_GRANT_LENGTH];
        encode_membership_grant(grant(node_id), &GRANT_SIGNATURE, &mut encoded)
            .expect("valid membership grant");
        encoded
    }

    #[test]
    fn handshake_header_matches_canonical_fields_and_round_trips() {
        let candidate = header(PacketType::SessionInit);
        let mut encoded = [0; HANDSHAKE_FIXED_HEADER_LENGTH];
        candidate
            .encode(&mut encoded)
            .expect("valid handshake header");

        assert_eq!(
            &encoded[..16],
            &[0x53, 0x54, 0x4c, 0x41, 0, 1, 0x10, 0, 0, 96, 0, 0, 0, 0, 1, 0x88]
        );
        assert_eq!(&encoded[16..32], NETWORK_ID.as_bytes());
        assert_eq!(&encoded[32..48], INITIATOR_ID.as_bytes());
        assert_eq!(&encoded[48..64], RESPONDER_ID.as_bytes());
        assert_eq!(&encoded[64..72], &7_u64.to_be_bytes());
        assert_eq!(&encoded[72..80], &8_u64.to_be_bytes());
        assert_eq!(&encoded[80..88], &1_788_000_000_u64.to_be_bytes());
        assert_eq!(&encoded[88..96], &9_u64.to_be_bytes());
        assert_eq!(HandshakeHeader::decode(&encoded), Ok(candidate));
    }

    #[test]
    fn session_init_matches_canonical_offsets_and_signature_ranges() {
        let initiator_grant = encoded_grant(INITIATOR_ID);
        let serial = GrantSerial::from_bytes([0x71; 16]);
        let fields = SessionInitRef {
            initiator_grant: &initiator_grant,
            receiver_grant_serial: serial,
            initiator_ephemeral: &EPHEMERAL,
            initiator_nonce: &NONCE,
            max_datagram_size: 1_400,
            signature: &SESSION_SIGNATURE,
        };
        let mut encoded = [0; HANDSHAKE_FIXED_HEADER_LENGTH + SESSION_INIT_PAYLOAD_LENGTH];

        assert_eq!(
            encode_session_init(header(PacketType::SessionInit), &[], fields, &mut encoded),
            Ok(encoded.len())
        );
        let payload = &encoded[HANDSHAKE_FIXED_HEADER_LENGTH..];
        assert_eq!(&payload[..MEMBERSHIP_GRANT_LENGTH], &initiator_grant);
        assert_eq!(&payload[240..256], serial.as_bytes());
        assert_eq!(&payload[256..288], &EPHEMERAL);
        assert_eq!(&payload[288..320], &NONCE);
        assert_eq!(&payload[320..324], &1_400_u32.to_be_bytes());
        assert_eq!(&payload[324..328], &[0; 4]);
        assert_eq!(&payload[328..], &SESSION_SIGNATURE);

        let decoded = SessionInitView::decode(&encoded).expect("valid SESSION_INIT");
        assert_eq!(decoded.header(), header(PacketType::SessionInit));
        assert_eq!(decoded.datagram(), encoded);
        assert_eq!(decoded.signed_header(), &encoded[..96]);
        assert_eq!(
            decoded.signed_payload(),
            &payload[..SESSION_INIT_SIGNED_PAYLOAD_LENGTH]
        );
        assert_eq!(decoded.receiver_grant_serial(), serial);
        assert_eq!(decoded.initiator_ephemeral(), &EPHEMERAL);
        assert_eq!(decoded.initiator_nonce(), &NONCE);
        assert_eq!(decoded.max_datagram_size(), 1_400);
        assert_eq!(decoded.signature(), &SESSION_SIGNATURE);
        assert_eq!(decoded.encoded_len(), encoded.len());
        assert_eq!(decoded.initiator_grant().grant(), grant(INITIATOR_ID));
    }

    #[test]
    fn session_response_round_trips_and_exposes_transcript_bytes() {
        let responder_grant = encoded_grant(RESPONDER_ID);
        let fields = SessionResponseRef {
            responder_grant: &responder_grant,
            init_hash: &INIT_HASH,
            responder_ephemeral: &EPHEMERAL,
            responder_nonce: &NONCE,
            max_datagram_size: 65_507,
            signature: &SESSION_SIGNATURE,
        };
        let extension = ExtensionRef::new(7, &[1, 2]).expect("valid extension");
        let mut candidate = header(PacketType::SessionResponse);
        candidate.common.header_length = 104;
        let mut encoded = [0; 104 + SESSION_RESPONSE_PAYLOAD_LENGTH];

        assert_eq!(
            encode_session_response(candidate, &[extension], fields, &mut encoded),
            Ok(encoded.len())
        );
        let decoded = SessionResponseView::decode(&encoded).expect("valid SESSION_RESPONSE");
        assert_eq!(decoded.header(), candidate);
        assert_eq!(decoded.datagram(), encoded);
        assert_eq!(decoded.signed_header(), &encoded[..104]);
        assert_eq!(decoded.extensions().collect::<Vec<_>>(), vec![extension]);
        assert_eq!(
            decoded.signed_payload(),
            &encoded[104..104 + SESSION_RESPONSE_SIGNED_PAYLOAD_LENGTH]
        );
        assert_eq!(decoded.responder_grant().grant(), grant(RESPONDER_ID));
        assert_eq!(decoded.init_hash(), &INIT_HASH);
        assert_eq!(decoded.responder_ephemeral(), &EPHEMERAL);
        assert_eq!(decoded.responder_nonce(), &NONCE);
        assert_eq!(decoded.max_datagram_size(), 65_507);
        assert_eq!(decoded.signature(), &SESSION_SIGNATURE);
    }

    #[test]
    fn signed_handshakes_reject_invalid_nonce_limit_reserved_and_grant_context() {
        let initiator_grant = encoded_grant(INITIATOR_ID);
        let serial = GrantSerial::from_bytes([0x71; 16]);
        let mut fields = SessionInitRef {
            initiator_grant: &initiator_grant,
            receiver_grant_serial: serial,
            initiator_ephemeral: &EPHEMERAL,
            initiator_nonce: &[0; 32],
            max_datagram_size: 1_400,
            signature: &SESSION_SIGNATURE,
        };
        let mut encoded = [0; HANDSHAKE_FIXED_HEADER_LENGTH + SESSION_INIT_PAYLOAD_LENGTH];
        assert_eq!(
            encode_session_init(header(PacketType::SessionInit), &[], fields, &mut encoded),
            Err(CodecError::ZeroField {
                field: "initiator nonce"
            })
        );

        fields.initiator_nonce = &NONCE;
        fields.max_datagram_size = 1_199;
        assert_eq!(
            encode_session_init(header(PacketType::SessionInit), &[], fields, &mut encoded),
            Err(CodecError::ValueOutOfRange {
                field: "maximum datagram size",
                actual: 1_199,
                minimum: 1_200,
                maximum: 65_507,
            })
        );

        let wrong_grant = encoded_grant(RESPONDER_ID);
        fields.initiator_grant = &wrong_grant;
        fields.max_datagram_size = 1_400;
        assert_eq!(
            encode_session_init(header(PacketType::SessionInit), &[], fields, &mut encoded),
            Err(CodecError::InconsistentField {
                context: "membership grant and handshake header",
                field: "node ID",
            })
        );

        fields.initiator_grant = &initiator_grant;
        encode_session_init(header(PacketType::SessionInit), &[], fields, &mut encoded)
            .expect("valid SESSION_INIT");
        encoded[HANDSHAKE_FIXED_HEADER_LENGTH + 324] = 1;
        assert_eq!(
            SessionInitView::decode(&encoded).map(|_| ()),
            Err(CodecError::NonZeroReserved {
                field: "SESSION_INIT reserved",
                offset: HANDSHAKE_FIXED_HEADER_LENGTH + 324,
            })
        );
    }

    #[test]
    fn handshake_header_rejects_non_handshake_type_flags_lengths_and_zero_ids() {
        let mut candidate = header(PacketType::SessionInit);
        candidate.common.packet_type = PacketType::Data;
        assert_eq!(
            candidate.validate(),
            Err(CodecError::InvalidEnumValue {
                field: "handshake packet type",
                value: 1,
            })
        );

        candidate = header(PacketType::SessionInit);
        candidate.common.flags = 1;
        assert_eq!(
            candidate.validate(),
            Err(CodecError::ReservedFlags {
                packet_type: 0x10,
                flags: 1,
                allowed: 0,
            })
        );

        candidate = header(PacketType::SessionInit);
        candidate.common.header_length = 92;
        assert_eq!(
            candidate.validate(),
            Err(CodecError::HeaderTooShort {
                actual: 92,
                minimum: 96,
            })
        );

        candidate = header(PacketType::SessionInit);
        candidate.common.payload_length = 391;
        assert_eq!(
            candidate.validate(),
            Err(CodecError::LengthMismatch {
                field: "handshake payload",
                expected: 392,
                actual: 391,
            })
        );

        candidate = header(PacketType::SessionInit);
        candidate.handshake_id = 0;
        assert_eq!(
            candidate.validate(),
            Err(CodecError::ZeroField {
                field: "handshake ID"
            })
        );
    }

    #[test]
    fn signed_handshakes_reject_wrong_type_truncation_trailer_and_small_output() {
        let initiator_grant = encoded_grant(INITIATOR_ID);
        let fields = SessionInitRef {
            initiator_grant: &initiator_grant,
            receiver_grant_serial: GrantSerial::from_bytes([0x71; 16]),
            initiator_ephemeral: &EPHEMERAL,
            initiator_nonce: &NONCE,
            max_datagram_size: 1_400,
            signature: &SESSION_SIGNATURE,
        };
        let mut encoded = [0; HANDSHAKE_FIXED_HEADER_LENGTH + SESSION_INIT_PAYLOAD_LENGTH];
        encode_session_init(header(PacketType::SessionInit), &[], fields, &mut encoded)
            .expect("valid SESSION_INIT");

        assert_eq!(
            SessionResponseView::decode(&encoded).map(|_| ()),
            Err(CodecError::UnexpectedPacketType {
                expected: 0x11,
                actual: 0x10,
            })
        );
        assert!(matches!(
            SessionInitView::decode(&encoded[..encoded.len() - 1]),
            Err(CodecError::Truncated {
                field: "handshake datagram",
                needed: 1,
                remaining: 0,
                ..
            })
        ));
        let mut with_trailer = encoded.to_vec();
        with_trailer.push(0);
        assert_eq!(
            SessionInitView::decode(&with_trailer).map(|_| ()),
            Err(CodecError::TrailingBytes {
                expected: encoded.len(),
                actual: encoded.len() + 1,
            })
        );
        let short_length = encoded.len() - 1;
        assert_eq!(
            encode_session_init(
                header(PacketType::SessionInit),
                &[],
                fields,
                &mut encoded[..short_length],
            ),
            Err(CodecError::OutputTooSmall {
                field: "handshake datagram",
                offset: 0,
                needed: encoded.len(),
                remaining: short_length,
            })
        );
    }

    #[test]
    fn session_confirm_round_trips_both_roles_and_exposes_authenticated_ranges() {
        let response_hash = [0x81; 32];
        let tag = [0x92; 16];
        let fields = SessionConfirmRef {
            response_hash: &response_hash,
            role: SessionConfirmRole::Initiator,
            confirmation_tag: &tag,
        };
        let mut encoded = [0; HANDSHAKE_FIXED_HEADER_LENGTH + SESSION_CONFIRM_PAYLOAD_LENGTH];
        let initiator_header = header(PacketType::SessionConfirm);

        assert_eq!(
            encode_session_confirm(initiator_header, &[], fields, &mut encoded),
            Ok(encoded.len())
        );
        assert_eq!(&encoded[96..128], &response_hash);
        assert_eq!(encoded[128], 1);
        assert_eq!(&encoded[129..136], &[0; 7]);
        assert_eq!(&encoded[136..], &tag);
        let decoded = SessionConfirmView::decode(&encoded).expect("valid initiator confirmation");
        assert_eq!(decoded.header(), initiator_header);
        assert_eq!(decoded.datagram(), encoded);
        assert_eq!(decoded.authenticated_header(), &encoded[..96]);
        assert_eq!(
            decoded.authenticated_payload(),
            &encoded[96..96 + SESSION_CONFIRM_AUTHENTICATED_PAYLOAD_LENGTH]
        );
        assert_eq!(decoded.response_hash(), &response_hash);
        assert_eq!(decoded.role(), SessionConfirmRole::Initiator);
        assert_eq!(decoded.confirmation_tag(), &tag);
        assert_eq!(decoded.encoded_len(), encoded.len());

        let mut responder_header = initiator_header;
        responder_header.common.flags = SESSION_CONFIRM_RESPONDER_FLAG;
        responder_header.sender_node_id = RESPONDER_ID;
        responder_header.receiver_node_id = INITIATOR_ID;
        let responder_fields = SessionConfirmRef {
            role: SessionConfirmRole::Responder,
            ..fields
        };
        encode_session_confirm(responder_header, &[], responder_fields, &mut encoded)
            .expect("valid responder confirmation");
        let decoded = SessionConfirmView::decode(&encoded).expect("valid responder confirmation");
        assert_eq!(decoded.role(), SessionConfirmRole::Responder);
        assert_eq!(
            decoded.header().common.flags,
            SESSION_CONFIRM_RESPONDER_FLAG
        );
    }

    #[test]
    fn session_confirm_rejects_role_flag_reserved_and_unknown_role() {
        let response_hash = [0x81; 32];
        let tag = [0x92; 16];
        let fields = SessionConfirmRef {
            response_hash: &response_hash,
            role: SessionConfirmRole::Responder,
            confirmation_tag: &tag,
        };
        let mut encoded = [0; HANDSHAKE_FIXED_HEADER_LENGTH + SESSION_CONFIRM_PAYLOAD_LENGTH];
        assert_eq!(
            encode_session_confirm(
                header(PacketType::SessionConfirm),
                &[],
                fields,
                &mut encoded
            ),
            Err(CodecError::InconsistentField {
                context: "SESSION_CONFIRM role and header flags",
                field: "confirmation role",
            })
        );

        let valid_fields = SessionConfirmRef {
            role: SessionConfirmRole::Initiator,
            ..fields
        };
        encode_session_confirm(
            header(PacketType::SessionConfirm),
            &[],
            valid_fields,
            &mut encoded,
        )
        .expect("valid confirmation");
        encoded[129] = 1;
        assert_eq!(
            SessionConfirmView::decode(&encoded).map(|_| ()),
            Err(CodecError::NonZeroReserved {
                field: "SESSION_CONFIRM reserved",
                offset: 129,
            })
        );
        encoded[129] = 0;
        encoded[128] = 3;
        assert_eq!(
            SessionConfirmView::decode(&encoded).map(|_| ()),
            Err(CodecError::InvalidEnumValue {
                field: "SESSION_CONFIRM role",
                value: 3,
            })
        );
    }

    #[test]
    fn session_reject_round_trips_known_and_future_reasons_with_signature_ranges() {
        let init_hash = [0xa3; 32];
        let signature = [0xb4; 64];
        let fields = SessionRejectRef {
            reason: SessionRejectReason::TemporarilyBusy,
            retry_after_ms: 5_000,
            init_hash: &init_hash,
            signature: &signature,
        };
        let extension = ExtensionRef::new(9, &[5]).expect("valid extension");
        let mut candidate = header(PacketType::SessionReject);
        candidate.common.header_length = 104;
        let mut encoded = [0; 104 + SESSION_REJECT_PAYLOAD_LENGTH];

        assert_eq!(
            encode_session_reject(candidate, &[extension], fields, &mut encoded),
            Ok(encoded.len())
        );
        assert_eq!(&encoded[104..106], &5_u16.to_be_bytes());
        assert_eq!(&encoded[106..108], &[0; 2]);
        assert_eq!(&encoded[108..112], &5_000_u32.to_be_bytes());
        let decoded = SessionRejectView::decode(&encoded).expect("valid SESSION_REJECT");
        assert_eq!(decoded.header(), candidate);
        assert_eq!(decoded.datagram(), encoded);
        assert_eq!(decoded.signed_header(), &encoded[..104]);
        assert_eq!(decoded.extensions().collect::<Vec<_>>(), vec![extension]);
        assert_eq!(
            decoded.signed_payload(),
            &encoded[104..104 + SESSION_REJECT_SIGNED_PAYLOAD_LENGTH]
        );
        assert_eq!(decoded.reason(), SessionRejectReason::TemporarilyBusy);
        assert_eq!(decoded.retry_after_ms(), 5_000);
        assert_eq!(decoded.init_hash(), &init_hash);
        assert_eq!(decoded.signature(), &signature);
        assert_eq!(decoded.encoded_len(), encoded.len());

        let future_fields = SessionRejectRef {
            reason: SessionRejectReason::Unknown(0x1234),
            retry_after_ms: 0,
            ..fields
        };
        encode_session_reject(candidate, &[extension], future_fields, &mut encoded)
            .expect("future non-zero reason remains decodable");
        let decoded = SessionRejectView::decode(&encoded).expect("future reason is generic");
        assert_eq!(decoded.reason(), SessionRejectReason::Unknown(0x1234));
    }

    #[test]
    fn session_reject_rejects_zero_reason_retry_bounds_and_reserved_bytes() {
        let init_hash = [0xa3; 32];
        let signature = [0xb4; 64];
        let mut fields = SessionRejectRef {
            reason: SessionRejectReason::Unknown(0),
            retry_after_ms: 0,
            init_hash: &init_hash,
            signature: &signature,
        };
        let mut encoded = [0; HANDSHAKE_FIXED_HEADER_LENGTH + SESSION_REJECT_PAYLOAD_LENGTH];
        assert_eq!(
            encode_session_reject(header(PacketType::SessionReject), &[], fields, &mut encoded),
            Err(CodecError::InvalidEnumValue {
                field: "SESSION_REJECT reason",
                value: 0,
            })
        );

        fields.reason = SessionRejectReason::StaleEpoch;
        fields.retry_after_ms = 99;
        assert_eq!(
            encode_session_reject(header(PacketType::SessionReject), &[], fields, &mut encoded),
            Err(CodecError::ValueOutOfRange {
                field: "retry after milliseconds",
                actual: 99,
                minimum: 100,
                maximum: 60_000,
            })
        );

        fields.retry_after_ms = 60_000;
        encode_session_reject(header(PacketType::SessionReject), &[], fields, &mut encoded)
            .expect("maximum retry delay is valid");
        encoded[98] = 1;
        assert_eq!(
            SessionRejectView::decode(&encoded).map(|_| ()),
            Err(CodecError::NonZeroReserved {
                field: "SESSION_REJECT reserved",
                offset: 98,
            })
        );
    }
}
