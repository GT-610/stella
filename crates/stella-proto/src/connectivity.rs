//! Version 0.2 automatic-connectivity nested record codecs.

use std::{
    cmp::Ordering,
    fmt,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
};

use stella_common::{NodeId, RelayId};

use crate::{
    common::validate_record_length,
    cursor::{ReadCursor, WriteCursor},
    CodecError, MAX_ENDPOINT_DATAGRAM_SIZE, MIN_ENDPOINT_DATAGRAM_SIZE,
};

/// Magic at the beginning of a version 0.2 connectivity generation.
pub const CONNECTIVITY_GENERATION_MAGIC: [u8; 4] = *b"SCG1";

/// Version of the connectivity-generation nested object format.
pub const CONNECTIVITY_GENERATION_FORMAT_VERSION: u8 = 1;

/// Exact length of the fixed connectivity-generation header.
pub const CONNECTIVITY_GENERATION_HEADER_LENGTH: usize = 48;

/// Exact length of one version 0.2 ICE candidate record.
pub const ICE_CANDIDATE_RECORD_LENGTH: usize = 72;

/// Maximum candidates carried by one connectivity generation.
pub const MAX_ICE_CANDIDATES: u8 = 32;

/// Minimum encoded ICE username-fragment length.
pub const MIN_ICE_USERNAME_FRAGMENT_LENGTH: usize = 8;

/// Maximum encoded ICE username-fragment length.
pub const MAX_ICE_USERNAME_FRAGMENT_LENGTH: usize = 32;

/// Minimum encoded ICE password length.
pub const MIN_ICE_PASSWORD_LENGTH: usize = 22;

/// Maximum encoded ICE password length.
pub const MAX_ICE_PASSWORD_LENGTH: usize = 64;

/// Maximum lifetime of one connectivity generation.
pub const MAX_CONNECTIVITY_GENERATION_LIFETIME_SECONDS: u64 = 600;

/// Fixed bytes before the generation in one peer connectivity record.
pub const CONNECTIVITY_RECORD_FIXED_LENGTH: usize = 20;

/// Maximum peer connectivity records in one network snapshot.
pub const MAX_CONNECTIVITY_RECORDS: u16 = 255;

/// Maximum STUN services in one automatic-connectivity configuration.
pub const MAX_STUN_SERVERS: u8 = 8;

/// Exact length of one numeric STUN service record.
pub const STUN_SERVER_RECORD_LENGTH: usize = 24;

/// ICE candidate class registered by Stella 0.2.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum IceCandidateClass {
    /// Address owned by a permitted local interface.
    Host = 1,
    /// Address discovered through STUN.
    ServerReflexive = 2,
    /// Address created through PCP, NAT-PMP, or `UPnP`.
    Mapped = 3,
    /// Address learned through a successful ICE check.
    PeerReflexive = 4,
    /// Address allocated by a TURN or Stella-compatible relay.
    Relay = 5,
}

impl IceCandidateClass {
    /// Returns the registered candidate-class byte.
    #[must_use]
    pub const fn as_u8(self) -> u8 {
        self as u8
    }
}

impl TryFrom<u8> for IceCandidateClass {
    type Error = CodecError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Self::Host),
            2 => Ok(Self::ServerReflexive),
            3 => Ok(Self::Mapped),
            4 => Ok(Self::PeerReflexive),
            5 => Ok(Self::Relay),
            _ => Err(CodecError::InvalidEnumValue {
                field: "ICE candidate class",
                value: u64::from(value),
            }),
        }
    }
}

/// Delivery carrier associated with one version 0.2 candidate.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum ConnectivityCarrier {
    /// Direct UDP socket.
    DirectUdp = 1,
    /// TURN allocation reached over UDP.
    TurnUdp = 2,
    /// TURN allocation reached over TCP.
    TurnTcp = 3,
    /// TURN allocation reached over TLS over TCP.
    TurnTls = 4,
    /// Stella TURN records carried by secure WebSocket.
    SecureWebSocket = 5,
}

impl ConnectivityCarrier {
    /// Returns the registered carrier byte.
    #[must_use]
    pub const fn as_u8(self) -> u8 {
        self as u8
    }

    /// Returns whether this carrier requires an authenticated relay service.
    #[must_use]
    pub const fn is_relay(self) -> bool {
        !matches!(self, Self::DirectUdp)
    }
}

impl TryFrom<u8> for ConnectivityCarrier {
    type Error = CodecError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Self::DirectUdp),
            2 => Ok(Self::TurnUdp),
            3 => Ok(Self::TurnTcp),
            4 => Ok(Self::TurnTls),
            5 => Ok(Self::SecureWebSocket),
            _ => Err(CodecError::InvalidEnumValue {
                field: "connectivity carrier",
                value: u64::from(value),
            }),
        }
    }
}

/// One complete version 0.2 ICE candidate.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct IceCandidate {
    /// Candidate class.
    pub class: IceCandidateClass,
    /// Direct or relay carrier.
    pub carrier: ConnectivityCarrier,
    /// RFC 8445 candidate priority.
    pub priority: u32,
    /// Non-zero implementation-local foundation value.
    pub foundation: u32,
    /// Maximum Stella datagram accepted through this candidate.
    pub max_datagram_size: u32,
    /// Candidate IP address and port.
    pub address: SocketAddr,
    /// Base or related address for non-host candidates.
    pub related_address: Option<SocketAddr>,
    /// Relay service identity for relay candidates.
    pub relay_id: Option<RelayId>,
}

impl IceCandidate {
    /// Validates candidate class, carrier, addresses, limits, and relay identity.
    ///
    /// # Errors
    ///
    /// Returns [`CodecError`] for zero priority/foundation, invalid addresses,
    /// incompatible related-address state, invalid datagram size, or an
    /// inconsistent relay carrier and relay ID.
    pub fn validate(self) -> Result<(), CodecError> {
        if self.priority == 0 {
            return Err(CodecError::ZeroField {
                field: "ICE candidate priority",
            });
        }
        if self.foundation == 0 {
            return Err(CodecError::ZeroField {
                field: "ICE candidate foundation",
            });
        }
        validate_datagram_size(
            self.max_datagram_size,
            "ICE candidate maximum datagram size",
        )?;
        validate_connectivity_address(self.address, "candidate")?;

        match (self.class, self.related_address) {
            (IceCandidateClass::Host, None) => {}
            (IceCandidateClass::Host, Some(_)) => {
                return Err(CodecError::InconsistentField {
                    context: "host ICE candidate",
                    field: "related address",
                });
            }
            (_, Some(related)) => {
                validate_connectivity_address(related, "related candidate")?;
                if self.address.is_ipv4() != related.is_ipv4() {
                    return Err(CodecError::InconsistentField {
                        context: "ICE candidate and related address",
                        field: "address family",
                    });
                }
            }
            (_, None) => {
                return Err(CodecError::InconsistentField {
                    context: "non-host ICE candidate",
                    field: "related address",
                });
            }
        }

        let relay_class = self.class == IceCandidateClass::Relay;
        if relay_class != self.carrier.is_relay() {
            return Err(CodecError::InconsistentField {
                context: "ICE candidate class and carrier",
                field: "relay state",
            });
        }
        match (relay_class, self.relay_id) {
            (true, Some(relay_id)) if !relay_id.is_zero() => {}
            (true, _) => {
                return Err(CodecError::ZeroField { field: "relay ID" });
            }
            (false, None) => {}
            (false, Some(_)) => {
                return Err(CodecError::InconsistentField {
                    context: "non-relay ICE candidate",
                    field: "relay ID",
                });
            }
        }
        Ok(())
    }

    /// Decodes exactly one 72-byte candidate record.
    ///
    /// # Errors
    ///
    /// Returns [`CodecError`] for malformed length, enum, reserved bytes,
    /// address slots, limits, or candidate semantics.
    pub fn decode(input: &[u8]) -> Result<Self, CodecError> {
        validate_record_length(
            input.len(),
            ICE_CANDIDATE_RECORD_LENGTH,
            "ICE candidate record",
        )?;
        decode_ice_candidate_at(input, 0)
    }

    /// Encodes this candidate into exactly the first 72 bytes of `output`.
    ///
    /// # Errors
    ///
    /// Returns [`CodecError`] when the candidate is invalid or `output` is too
    /// small.
    pub fn encode(self, output: &mut [u8]) -> Result<(), CodecError> {
        self.validate()?;
        let mut cursor = WriteCursor::new(output, 0);
        cursor.write_u16(
            u16::try_from(ICE_CANDIDATE_RECORD_LENGTH).map_err(|_| {
                CodecError::IntegerOverflow {
                    field: "ICE candidate record length",
                }
            })?,
            "ICE candidate record length",
        )?;
        cursor.write_u8(self.class.as_u8(), "ICE candidate class")?;
        cursor.write_u8(self.carrier.as_u8(), "connectivity carrier")?;
        cursor.write_u32(self.priority, "ICE candidate priority")?;
        cursor.write_u32(self.foundation, "ICE candidate foundation")?;
        cursor.write_u32(
            self.max_datagram_size,
            "ICE candidate maximum datagram size",
        )?;
        cursor.write_u16(self.address.port(), "ICE candidate port")?;
        cursor.write_u16(
            self.related_address.map_or(0, |address| address.port()),
            "ICE related port",
        )?;
        let (family, address_slot) = encode_ip_slot(self.address.ip());
        cursor.write_u8(family, "ICE candidate address family")?;
        cursor.write_u8(0, "ICE candidate flags")?;
        cursor.write_u16(0, "ICE candidate reserved")?;
        cursor.write_bytes(&address_slot, "ICE candidate address")?;
        let related_slot = self
            .related_address
            .map_or([0; 16], |address| encode_ip_slot(address.ip()).1);
        cursor.write_bytes(&related_slot, "ICE related address")?;
        let relay_id = self.relay_id.map_or([0; 16], RelayId::into_bytes);
        cursor.write_bytes(&relay_id, "relay ID")?;
        Ok(())
    }
}

/// Borrowed values used to encode one connectivity generation.
#[derive(Clone, Copy)]
pub struct ConnectivityGenerationRef<'a> {
    generation_id: u64,
    tie_breaker: u64,
    created_at: u64,
    expires_at: u64,
    username_fragment: &'a [u8],
    password: &'a [u8],
    candidates: &'a [IceCandidate],
}

impl<'a> ConnectivityGenerationRef<'a> {
    /// Creates and validates one complete generation value.
    ///
    /// # Errors
    ///
    /// Returns [`CodecError`] for invalid identifiers, times, credential bytes,
    /// candidate count, candidate semantics, or non-decreasing priority.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        generation_id: u64,
        tie_breaker: u64,
        created_at: u64,
        expires_at: u64,
        username_fragment: &'a [u8],
        password: &'a [u8],
        candidates: &'a [IceCandidate],
    ) -> Result<Self, CodecError> {
        validate_generation_fields(
            generation_id,
            tie_breaker,
            created_at,
            expires_at,
            username_fragment,
            password,
            candidates,
        )?;
        Ok(Self {
            generation_id,
            tie_breaker,
            created_at,
            expires_at,
            username_fragment,
            password,
            candidates,
        })
    }

    /// Returns the random generation identifier.
    #[must_use]
    pub const fn generation_id(self) -> u64 {
        self.generation_id
    }

    /// Returns the random ICE role tie breaker.
    #[must_use]
    pub const fn tie_breaker(self) -> u64 {
        self.tie_breaker
    }

    /// Returns the creation Unix time.
    #[must_use]
    pub const fn created_at(self) -> u64 {
        self.created_at
    }

    /// Returns the exclusive expiry Unix time.
    #[must_use]
    pub const fn expires_at(self) -> u64 {
        self.expires_at
    }

    /// Borrows the ICE username fragment.
    #[must_use]
    pub const fn username_fragment(self) -> &'a [u8] {
        self.username_fragment
    }

    /// Borrows the secret ICE password.
    #[must_use]
    pub const fn password(self) -> &'a [u8] {
        self.password
    }

    /// Borrows candidates in strict descending-priority order.
    #[must_use]
    pub const fn candidates(self) -> &'a [IceCandidate] {
        self.candidates
    }

    /// Returns the exact encoded generation length.
    ///
    /// # Errors
    ///
    /// Returns [`CodecError::IntegerOverflow`] if length arithmetic fails.
    pub fn encoded_len(self) -> Result<usize, CodecError> {
        generation_encoded_len(
            self.username_fragment.len(),
            self.password.len(),
            self.candidates.len(),
        )
    }
}

impl fmt::Debug for ConnectivityGenerationRef<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ConnectivityGenerationRef")
            .field("generation_id", &self.generation_id)
            .field("tie_breaker", &self.tie_breaker)
            .field("created_at", &self.created_at)
            .field("expires_at", &self.expires_at)
            .field("username_fragment_length", &self.username_fragment.len())
            .field("password_length", &self.password.len())
            .field("candidate_count", &self.candidates.len())
            .finish_non_exhaustive()
    }
}

/// Borrowed validated connectivity generation.
#[derive(Clone)]
pub struct ConnectivityGenerationView<'a> {
    generation_id: u64,
    tie_breaker: u64,
    created_at: u64,
    expires_at: u64,
    username_fragment: &'a [u8],
    password: &'a [u8],
    candidate_records: &'a [u8],
    candidate_count: u8,
    encoded_length: usize,
}

impl<'a> ConnectivityGenerationView<'a> {
    /// Decodes one complete version 0.2 connectivity generation.
    ///
    /// # Errors
    ///
    /// Returns [`CodecError`] for invalid magic, format, length, credentials,
    /// time range, padding, candidate record, or priority order.
    pub fn decode(input: &'a [u8]) -> Result<Self, CodecError> {
        let mut cursor = ReadCursor::new(input, 0);
        if cursor.read_array::<4>("connectivity generation magic")? != CONNECTIVITY_GENERATION_MAGIC
        {
            return Err(CodecError::InvalidObjectMagic {
                object: "connectivity generation",
            });
        }
        let format_version = cursor.read_u8("connectivity generation format version")?;
        if format_version != CONNECTIVITY_GENERATION_FORMAT_VERSION {
            return Err(CodecError::UnsupportedObjectVersion {
                object: "connectivity generation",
                version: format_version,
            });
        }
        let candidate_count = cursor.read_u8("ICE candidate count")?;
        validate_candidate_count(usize::from(candidate_count))?;
        let username_length = usize::from(cursor.read_u8("ICE username fragment length")?);
        let password_length = usize::from(cursor.read_u8("ICE password length")?);
        validate_credential_lengths(username_length, password_length)?;
        let encoded_length = usize::try_from(cursor.read_u32("connectivity generation length")?)
            .map_err(|_| CodecError::IntegerOverflow {
                field: "connectivity generation length",
            })?;
        validate_record_length(input.len(), encoded_length, "connectivity generation")?;
        let flags = cursor.read_u16("connectivity generation flags")?;
        if flags != 0 {
            return Err(CodecError::ReservedBits {
                field: "connectivity generation flags",
                bits: u64::from(flags),
                allowed: 0,
            });
        }
        let reserved_offset = cursor.position();
        if cursor.read_u16("connectivity generation reserved")? != 0 {
            return Err(CodecError::NonZeroReserved {
                field: "connectivity generation reserved",
                offset: reserved_offset,
            });
        }
        let generation_id = cursor.read_u64("connectivity generation ID")?;
        let tie_breaker = cursor.read_u64("ICE role tie breaker")?;
        let created_at = cursor.read_u64("connectivity generation creation time")?;
        let expires_at = cursor.read_u64("connectivity generation expiry time")?;
        validate_generation_identity_and_time(generation_id, tie_breaker, created_at, expires_at)?;

        let username_fragment = cursor.read_slice(username_length, "ICE username fragment")?;
        let password = cursor.read_slice(password_length, "ICE password")?;
        validate_ice_credential(username_fragment, "ICE username fragment")?;
        validate_ice_credential(password, "ICE password")?;
        let credential_length =
            username_length
                .checked_add(password_length)
                .ok_or(CodecError::IntegerOverflow {
                    field: "ICE credential length",
                })?;
        let padded_credential_length = align_to_four(credential_length)?;
        let padding_length = padded_credential_length
            .checked_sub(credential_length)
            .ok_or(CodecError::IntegerOverflow {
                field: "ICE credential padding",
            })?;
        let padding_offset = cursor.position();
        if cursor
            .read_slice(padding_length, "ICE credential padding")?
            .iter()
            .any(|byte| *byte != 0)
        {
            return Err(CodecError::NonZeroReserved {
                field: "ICE credential padding",
                offset: padding_offset,
            });
        }
        let candidate_length = usize::from(candidate_count)
            .checked_mul(ICE_CANDIDATE_RECORD_LENGTH)
            .ok_or(CodecError::IntegerOverflow {
                field: "ICE candidate records length",
            })?;
        let candidate_records = cursor.read_slice(candidate_length, "ICE candidate records")?;
        validate_record_length(input.len(), cursor.position(), "connectivity generation")?;
        validate_candidate_records(
            candidate_records,
            candidate_count,
            cursor.position() - candidate_length,
        )?;
        Ok(Self {
            generation_id,
            tie_breaker,
            created_at,
            expires_at,
            username_fragment,
            password,
            candidate_records,
            candidate_count,
            encoded_length,
        })
    }

    /// Returns the random generation identifier.
    #[must_use]
    pub const fn generation_id(&self) -> u64 {
        self.generation_id
    }

    /// Returns the random ICE role tie breaker.
    #[must_use]
    pub const fn tie_breaker(&self) -> u64 {
        self.tie_breaker
    }

    /// Returns the creation Unix time.
    #[must_use]
    pub const fn created_at(&self) -> u64 {
        self.created_at
    }

    /// Returns the exclusive expiry Unix time.
    #[must_use]
    pub const fn expires_at(&self) -> u64 {
        self.expires_at
    }

    /// Borrows the ICE username fragment.
    #[must_use]
    pub const fn username_fragment(&self) -> &'a [u8] {
        self.username_fragment
    }

    /// Borrows the secret ICE password.
    #[must_use]
    pub const fn password(&self) -> &'a [u8] {
        self.password
    }

    /// Iterates over validated candidates in descending priority.
    #[must_use]
    pub const fn candidates(&self) -> IceCandidateIter<'a> {
        IceCandidateIter {
            records: self.candidate_records,
            position: 0,
        }
    }

    /// Returns the exact encoded object length.
    #[must_use]
    pub const fn encoded_len(&self) -> usize {
        self.encoded_length
    }
}

impl fmt::Debug for ConnectivityGenerationView<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ConnectivityGenerationView")
            .field("generation_id", &self.generation_id)
            .field("tie_breaker", &self.tie_breaker)
            .field("created_at", &self.created_at)
            .field("expires_at", &self.expires_at)
            .field("username_fragment_length", &self.username_fragment.len())
            .field("password_length", &self.password.len())
            .field("candidate_count", &self.candidate_count)
            .finish_non_exhaustive()
    }
}

/// Iterator over validated fixed-size ICE candidate records.
#[derive(Clone)]
pub struct IceCandidateIter<'a> {
    records: &'a [u8],
    position: usize,
}

impl Iterator for IceCandidateIter<'_> {
    type Item = IceCandidate;

    fn next(&mut self) -> Option<Self::Item> {
        let end = self.position.checked_add(ICE_CANDIDATE_RECORD_LENGTH)?;
        let record = self.records.get(self.position..end)?;
        self.position = end;
        IceCandidate::decode(record).ok()
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        let remaining =
            self.records.len().saturating_sub(self.position) / ICE_CANDIDATE_RECORD_LENGTH;
        (remaining, Some(remaining))
    }
}

impl ExactSizeIterator for IceCandidateIter<'_> {}
impl std::iter::FusedIterator for IceCandidateIter<'_> {}

/// Encodes one complete connectivity generation.
///
/// # Errors
///
/// Returns [`CodecError`] when the generation is invalid, length arithmetic
/// fails, or `output` is too small.
pub fn encode_connectivity_generation(
    generation: ConnectivityGenerationRef<'_>,
    output: &mut [u8],
) -> Result<usize, CodecError> {
    let encoded_length = generation.encoded_len()?;
    if output.len() < encoded_length {
        return Err(CodecError::OutputTooSmall {
            field: "connectivity generation",
            offset: 0,
            needed: encoded_length,
            remaining: output.len(),
        });
    }
    let candidate_count =
        u8::try_from(generation.candidates.len()).map_err(|_| CodecError::ValueOutOfRange {
            field: "ICE candidate count",
            actual: u64::try_from(generation.candidates.len()).unwrap_or(u64::MAX),
            minimum: 1,
            maximum: u64::from(MAX_ICE_CANDIDATES),
        })?;
    let username_length = u8::try_from(generation.username_fragment.len()).map_err(|_| {
        CodecError::IntegerOverflow {
            field: "ICE username fragment length",
        }
    })?;
    let password_length =
        u8::try_from(generation.password.len()).map_err(|_| CodecError::IntegerOverflow {
            field: "ICE password length",
        })?;
    let mut candidate_output_position = {
        let mut cursor = WriteCursor::new(output, 0);
        cursor.write_bytes(
            &CONNECTIVITY_GENERATION_MAGIC,
            "connectivity generation magic",
        )?;
        cursor.write_u8(
            CONNECTIVITY_GENERATION_FORMAT_VERSION,
            "connectivity generation format version",
        )?;
        cursor.write_u8(candidate_count, "ICE candidate count")?;
        cursor.write_u8(username_length, "ICE username fragment length")?;
        cursor.write_u8(password_length, "ICE password length")?;
        cursor.write_u32(
            u32::try_from(encoded_length).map_err(|_| CodecError::IntegerOverflow {
                field: "connectivity generation length",
            })?,
            "connectivity generation length",
        )?;
        cursor.write_u16(0, "connectivity generation flags")?;
        cursor.write_u16(0, "connectivity generation reserved")?;
        cursor.write_u64(generation.generation_id, "connectivity generation ID")?;
        cursor.write_u64(generation.tie_breaker, "ICE role tie breaker")?;
        cursor.write_u64(
            generation.created_at,
            "connectivity generation creation time",
        )?;
        cursor.write_u64(generation.expires_at, "connectivity generation expiry time")?;
        cursor.write_bytes(generation.username_fragment, "ICE username fragment")?;
        cursor.write_bytes(generation.password, "ICE password")?;
        let credential_length = generation
            .username_fragment
            .len()
            .checked_add(generation.password.len())
            .ok_or(CodecError::IntegerOverflow {
                field: "ICE credential length",
            })?;
        let padding_length = align_to_four(credential_length)? - credential_length;
        cursor.write_bytes(&[0; 3][..padding_length], "ICE credential padding")?;
        cursor.position()
    };
    for candidate in generation.candidates {
        let end = candidate_output_position
            .checked_add(ICE_CANDIDATE_RECORD_LENGTH)
            .ok_or(CodecError::IntegerOverflow {
                field: "ICE candidate output position",
            })?;
        let remaining = output.len().saturating_sub(candidate_output_position);
        let record =
            output
                .get_mut(candidate_output_position..end)
                .ok_or(CodecError::OutputTooSmall {
                    field: "ICE candidate record",
                    offset: candidate_output_position,
                    needed: ICE_CANDIDATE_RECORD_LENGTH,
                    remaining,
                })?;
        candidate.encode(record)?;
        candidate_output_position = end;
    }
    Ok(encoded_length)
}

/// Borrowed values used to encode one peer connectivity record.
#[derive(Clone, Copy, Debug)]
pub struct ConnectivityRecordRef<'a> {
    node_id: NodeId,
    generation: ConnectivityGenerationRef<'a>,
}

impl<'a> ConnectivityRecordRef<'a> {
    /// Creates one node-keyed connectivity record.
    ///
    /// # Errors
    ///
    /// Returns [`CodecError::ZeroField`] when `node_id` is zero.
    pub fn new(
        node_id: NodeId,
        generation: ConnectivityGenerationRef<'a>,
    ) -> Result<Self, CodecError> {
        if node_id.is_zero() {
            return Err(CodecError::ZeroField { field: "node ID" });
        }
        Ok(Self {
            node_id,
            generation,
        })
    }

    /// Returns the peer node identity.
    #[must_use]
    pub const fn node_id(self) -> NodeId {
        self.node_id
    }

    /// Returns the embedded generation values.
    #[must_use]
    pub const fn generation(self) -> ConnectivityGenerationRef<'a> {
        self.generation
    }

    /// Returns the exact encoded record length.
    ///
    /// # Errors
    ///
    /// Returns [`CodecError`] for arithmetic or 16-bit length overflow.
    pub fn encoded_len(self) -> Result<usize, CodecError> {
        let length = CONNECTIVITY_RECORD_FIXED_LENGTH
            .checked_add(self.generation.encoded_len()?)
            .ok_or(CodecError::IntegerOverflow {
                field: "connectivity record length",
            })?;
        let _ = u16::try_from(length).map_err(|_| CodecError::ValueOutOfRange {
            field: "connectivity record length",
            actual: u64::try_from(length).unwrap_or(u64::MAX),
            minimum: u64::try_from(CONNECTIVITY_RECORD_FIXED_LENGTH).unwrap_or(u64::MAX),
            maximum: u64::from(u16::MAX),
        })?;
        Ok(length)
    }
}

/// Borrowed validated peer connectivity record.
#[derive(Clone)]
pub struct ConnectivityRecordView<'a> {
    node_id: NodeId,
    generation: ConnectivityGenerationView<'a>,
    encoded_length: usize,
}

impl<'a> ConnectivityRecordView<'a> {
    /// Decodes one complete connectivity record.
    ///
    /// # Errors
    ///
    /// Returns [`CodecError`] for invalid length, reserved bytes, node ID, or
    /// embedded generation.
    pub fn decode(input: &'a [u8]) -> Result<Self, CodecError> {
        let (record, consumed) = Self::decode_prefix(input, 0)?;
        validate_record_length(input.len(), consumed, "connectivity record")?;
        Ok(record)
    }

    fn decode_prefix(input: &'a [u8], base_offset: usize) -> Result<(Self, usize), CodecError> {
        let mut cursor = ReadCursor::new(input, base_offset);
        let encoded_length = usize::from(cursor.read_u16("connectivity record length")?);
        if encoded_length < CONNECTIVITY_RECORD_FIXED_LENGTH || encoded_length % 4 != 0 {
            return Err(CodecError::ValueOutOfRange {
                field: "connectivity record length",
                actual: u64::try_from(encoded_length).unwrap_or(u64::MAX),
                minimum: u64::try_from(CONNECTIVITY_RECORD_FIXED_LENGTH).unwrap_or(u64::MAX),
                maximum: u64::from(u16::MAX),
            });
        }
        if input.len() < encoded_length {
            return Err(CodecError::Truncated {
                field: "connectivity record",
                offset: base_offset,
                needed: encoded_length,
                remaining: input.len(),
            });
        }
        let reserved_offset = base_offset.saturating_add(cursor.position());
        if cursor.read_u16("connectivity record reserved")? != 0 {
            return Err(CodecError::NonZeroReserved {
                field: "connectivity record reserved",
                offset: reserved_offset,
            });
        }
        let node_id = NodeId::from_bytes(cursor.read_array("connectivity node ID")?);
        if node_id.is_zero() {
            return Err(CodecError::ZeroField { field: "node ID" });
        }
        let generation_bytes = input
            .get(CONNECTIVITY_RECORD_FIXED_LENGTH..encoded_length)
            .ok_or(CodecError::Truncated {
                field: "connectivity generation",
                offset: base_offset.saturating_add(CONNECTIVITY_RECORD_FIXED_LENGTH),
                needed: encoded_length.saturating_sub(CONNECTIVITY_RECORD_FIXED_LENGTH),
                remaining: input.len().saturating_sub(CONNECTIVITY_RECORD_FIXED_LENGTH),
            })?;
        let generation = ConnectivityGenerationView::decode(generation_bytes)?;
        Ok((
            Self {
                node_id,
                generation,
                encoded_length,
            },
            encoded_length,
        ))
    }

    /// Returns the peer node identity.
    #[must_use]
    pub const fn node_id(&self) -> NodeId {
        self.node_id
    }

    /// Returns the embedded generation.
    #[must_use]
    pub fn generation(&self) -> ConnectivityGenerationView<'a> {
        self.generation.clone()
    }

    /// Returns the exact encoded record length.
    #[must_use]
    pub const fn encoded_len(&self) -> usize {
        self.encoded_length
    }
}

impl fmt::Debug for ConnectivityRecordView<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ConnectivityRecordView")
            .field("node_id", &self.node_id)
            .field("generation", &self.generation)
            .field("encoded_length", &self.encoded_length)
            .finish()
    }
}

/// Encodes one complete peer connectivity record.
///
/// # Errors
///
/// Returns [`CodecError`] for invalid length or insufficient output capacity.
pub fn encode_connectivity_record(
    record: ConnectivityRecordRef<'_>,
    output: &mut [u8],
) -> Result<usize, CodecError> {
    let encoded_length = record.encoded_len()?;
    if output.len() < encoded_length {
        return Err(CodecError::OutputTooSmall {
            field: "connectivity record",
            offset: 0,
            needed: encoded_length,
            remaining: output.len(),
        });
    }
    {
        let mut cursor = WriteCursor::new(output, 0);
        cursor.write_u16(
            u16::try_from(encoded_length).map_err(|_| CodecError::IntegerOverflow {
                field: "connectivity record length",
            })?,
            "connectivity record length",
        )?;
        cursor.write_u16(0, "connectivity record reserved")?;
        cursor.write_bytes(record.node_id.as_bytes(), "connectivity node ID")?;
    }
    let remaining = output
        .len()
        .saturating_sub(CONNECTIVITY_RECORD_FIXED_LENGTH);
    let generation_output = output
        .get_mut(CONNECTIVITY_RECORD_FIXED_LENGTH..encoded_length)
        .ok_or(CodecError::OutputTooSmall {
            field: "connectivity generation",
            offset: CONNECTIVITY_RECORD_FIXED_LENGTH,
            needed: encoded_length.saturating_sub(CONNECTIVITY_RECORD_FIXED_LENGTH),
            remaining,
        })?;
    encode_connectivity_generation(record.generation, generation_output)?;
    Ok(encoded_length)
}

/// Borrowed validated node-ID-sorted connectivity list.
#[derive(Clone)]
pub struct ConnectivityListView<'a> {
    count: u16,
    records: &'a [u8],
}

impl<'a> ConnectivityListView<'a> {
    /// Decodes one complete connectivity list.
    ///
    /// # Errors
    ///
    /// Returns [`CodecError`] for excessive count, reserved bytes, malformed
    /// records, trailing bytes, or non-increasing node-ID order.
    pub fn decode(input: &'a [u8]) -> Result<Self, CodecError> {
        let mut cursor = ReadCursor::new(input, 0);
        let count = cursor.read_u16("connectivity record count")?;
        if count > MAX_CONNECTIVITY_RECORDS {
            return Err(CodecError::ValueOutOfRange {
                field: "connectivity record count",
                actual: u64::from(count),
                minimum: 0,
                maximum: u64::from(MAX_CONNECTIVITY_RECORDS),
            });
        }
        let reserved_offset = cursor.position();
        if cursor.read_u16("connectivity list reserved")? != 0 {
            return Err(CodecError::NonZeroReserved {
                field: "connectivity list reserved",
                offset: reserved_offset,
            });
        }
        let records = input.get(4..).ok_or(CodecError::Truncated {
            field: "connectivity records",
            offset: input.len(),
            needed: 4_usize.saturating_sub(input.len()),
            remaining: 0,
        })?;
        let mut position = 0_usize;
        let mut previous = None;
        for index in 0..usize::from(count) {
            let record_input = records.get(position..).ok_or(CodecError::Truncated {
                field: "connectivity record",
                offset: 4_usize.saturating_add(position),
                needed: 1,
                remaining: 0,
            })?;
            let (record, consumed) = ConnectivityRecordView::decode_prefix(
                record_input,
                4_usize.saturating_add(position),
            )?;
            if previous.is_some_and(|previous_id| previous_id >= record.node_id()) {
                return Err(CodecError::NestedRecordsOutOfOrder {
                    context: "connectivity list",
                    index,
                });
            }
            previous = Some(record.node_id());
            position = position
                .checked_add(consumed)
                .ok_or(CodecError::IntegerOverflow {
                    field: "connectivity list position",
                })?;
        }
        validate_record_length(records.len(), position, "connectivity records")?;
        Ok(Self { count, records })
    }

    /// Returns the number of records.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.count as usize
    }

    /// Returns whether the list is empty.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.count == 0
    }

    /// Iterates over validated connectivity records.
    #[must_use]
    pub const fn records(&self) -> ConnectivityRecordIter<'a> {
        ConnectivityRecordIter {
            records: self.records,
            position: 0,
            remaining: self.count,
        }
    }
}

/// Iterator over validated variable-size connectivity records.
#[derive(Clone)]
pub struct ConnectivityRecordIter<'a> {
    records: &'a [u8],
    position: usize,
    remaining: u16,
}

impl<'a> Iterator for ConnectivityRecordIter<'a> {
    type Item = ConnectivityRecordView<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.remaining == 0 {
            return None;
        }
        let input = self.records.get(self.position..)?;
        let (record, consumed) =
            ConnectivityRecordView::decode_prefix(input, self.position).ok()?;
        self.position = self.position.checked_add(consumed)?;
        self.remaining -= 1;
        Some(record)
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        let remaining = usize::from(self.remaining);
        (remaining, Some(remaining))
    }
}

impl ExactSizeIterator for ConnectivityRecordIter<'_> {}
impl std::iter::FusedIterator for ConnectivityRecordIter<'_> {}

/// Encodes a node-ID-sorted connectivity list.
///
/// # Errors
///
/// Returns [`CodecError`] for excessive count, invalid ordering, length
/// overflow, invalid records, or insufficient output capacity.
pub fn encode_connectivity_list(
    records: &[ConnectivityRecordRef<'_>],
    output: &mut [u8],
) -> Result<usize, CodecError> {
    let count = u16::try_from(records.len()).map_err(|_| CodecError::ValueOutOfRange {
        field: "connectivity record count",
        actual: u64::try_from(records.len()).unwrap_or(u64::MAX),
        minimum: 0,
        maximum: u64::from(MAX_CONNECTIVITY_RECORDS),
    })?;
    if count > MAX_CONNECTIVITY_RECORDS {
        return Err(CodecError::ValueOutOfRange {
            field: "connectivity record count",
            actual: u64::from(count),
            minimum: 0,
            maximum: u64::from(MAX_CONNECTIVITY_RECORDS),
        });
    }
    let mut encoded_length = 4_usize;
    let mut previous = None;
    for (index, record) in records.iter().copied().enumerate() {
        if previous.is_some_and(|previous_id| previous_id >= record.node_id) {
            return Err(CodecError::NestedRecordsOutOfOrder {
                context: "connectivity list",
                index,
            });
        }
        previous = Some(record.node_id);
        encoded_length = encoded_length.checked_add(record.encoded_len()?).ok_or(
            CodecError::IntegerOverflow {
                field: "connectivity list length",
            },
        )?;
    }
    if output.len() < encoded_length {
        return Err(CodecError::OutputTooSmall {
            field: "connectivity list",
            offset: 0,
            needed: encoded_length,
            remaining: output.len(),
        });
    }
    {
        let mut cursor = WriteCursor::new(output, 0);
        cursor.write_u16(count, "connectivity record count")?;
        cursor.write_u16(0, "connectivity list reserved")?;
    }
    let mut position = 4_usize;
    for record in records {
        let length = record.encoded_len()?;
        let end = position
            .checked_add(length)
            .ok_or(CodecError::IntegerOverflow {
                field: "connectivity record end",
            })?;
        let remaining = output.len().saturating_sub(position);
        let record_output = output
            .get_mut(position..end)
            .ok_or(CodecError::OutputTooSmall {
                field: "connectivity record",
                offset: position,
                needed: length,
                remaining,
            })?;
        encode_connectivity_record(*record, record_output)?;
        position = end;
    }
    Ok(encoded_length)
}

/// Encodes a node-ID-sorted connectivity list from canonical record bytes.
///
/// Every input record is fully decoded before any output is written. This is
/// useful when a controller persists already canonical records and must not
/// reconstruct or expose their embedded credentials merely to build a list.
///
/// # Errors
///
/// Returns [`CodecError`] for excessive count, malformed records, invalid
/// ordering, length overflow, or insufficient output capacity.
pub fn encode_connectivity_list_from_encoded_records(
    records: &[&[u8]],
    output: &mut [u8],
) -> Result<usize, CodecError> {
    let count = u16::try_from(records.len()).map_err(|_| CodecError::ValueOutOfRange {
        field: "connectivity record count",
        actual: u64::try_from(records.len()).unwrap_or(u64::MAX),
        minimum: 0,
        maximum: u64::from(MAX_CONNECTIVITY_RECORDS),
    })?;
    if count > MAX_CONNECTIVITY_RECORDS {
        return Err(CodecError::ValueOutOfRange {
            field: "connectivity record count",
            actual: u64::from(count),
            minimum: 0,
            maximum: u64::from(MAX_CONNECTIVITY_RECORDS),
        });
    }

    let mut encoded_length = 4_usize;
    let mut previous = None;
    for (index, encoded_record) in records.iter().copied().enumerate() {
        let record = ConnectivityRecordView::decode(encoded_record)?;
        if previous.is_some_and(|previous_id| previous_id >= record.node_id()) {
            return Err(CodecError::NestedRecordsOutOfOrder {
                context: "connectivity list",
                index,
            });
        }
        previous = Some(record.node_id());
        encoded_length = encoded_length.checked_add(encoded_record.len()).ok_or(
            CodecError::IntegerOverflow {
                field: "connectivity list length",
            },
        )?;
    }
    if output.len() < encoded_length {
        return Err(CodecError::OutputTooSmall {
            field: "connectivity list",
            offset: 0,
            needed: encoded_length,
            remaining: output.len(),
        });
    }
    {
        let mut cursor = WriteCursor::new(output, 0);
        cursor.write_u16(count, "connectivity record count")?;
        cursor.write_u16(0, "connectivity list reserved")?;
    }
    let mut position = 4_usize;
    for encoded_record in records {
        let end =
            position
                .checked_add(encoded_record.len())
                .ok_or(CodecError::IntegerOverflow {
                    field: "connectivity record end",
                })?;
        let remaining = output.len().saturating_sub(position);
        let record_output = output
            .get_mut(position..end)
            .ok_or(CodecError::OutputTooSmall {
                field: "connectivity record",
                offset: position,
                needed: encoded_record.len(),
                remaining,
            })?;
        record_output.copy_from_slice(encoded_record);
        position = end;
    }
    Ok(encoded_length)
}

/// One numeric STUN service used for server-reflexive candidate gathering.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StunServer {
    /// Lower values are preferred.
    pub priority: u8,
    /// Numeric UDP service address.
    pub address: SocketAddr,
}

impl StunServer {
    /// Validates the numeric unicast address and non-zero UDP port.
    ///
    /// # Errors
    ///
    /// Returns [`CodecError`] for an unusable address or zero port.
    pub fn validate(self) -> Result<(), CodecError> {
        validate_connectivity_address(self.address, "STUN server")
    }

    fn sort_cmp(self, other: Self) -> Ordering {
        let (family, address) = encode_ip_slot(self.address.ip());
        let (other_family, other_address) = encode_ip_slot(other.address.ip());
        self.priority
            .cmp(&other.priority)
            .then_with(|| family.cmp(&other_family))
            .then_with(|| address.cmp(&other_address))
            .then_with(|| self.address.port().cmp(&other.address.port()))
    }
}

/// Borrowed validated STUN server list.
#[derive(Clone)]
pub struct StunServerListView<'a> {
    count: u8,
    records: &'a [u8],
}

impl<'a> StunServerListView<'a> {
    /// Decodes one complete canonical STUN server list.
    ///
    /// # Errors
    ///
    /// Returns [`CodecError`] for count, reserved, length, address, duplicate,
    /// or order violations.
    pub fn decode(input: &'a [u8]) -> Result<Self, CodecError> {
        let mut cursor = ReadCursor::new(input, 0);
        let count = cursor.read_u8("STUN server count")?;
        if !(1..=MAX_STUN_SERVERS).contains(&count) {
            return Err(CodecError::ValueOutOfRange {
                field: "STUN server count",
                actual: u64::from(count),
                minimum: 1,
                maximum: u64::from(MAX_STUN_SERVERS),
            });
        }
        if cursor.read_array::<3>("STUN server list reserved")? != [0; 3] {
            return Err(CodecError::NonZeroReserved {
                field: "STUN server list reserved",
                offset: 1,
            });
        }
        let records_length = usize::from(count)
            .checked_mul(STUN_SERVER_RECORD_LENGTH)
            .ok_or(CodecError::IntegerOverflow {
                field: "STUN server records length",
            })?;
        let expected_length =
            4_usize
                .checked_add(records_length)
                .ok_or(CodecError::IntegerOverflow {
                    field: "STUN server list length",
                })?;
        validate_record_length(input.len(), expected_length, "STUN server list")?;
        let records = cursor.read_slice(records_length, "STUN server records")?;
        let mut previous = None;
        for index in 0..usize::from(count) {
            let server = decode_stun_server_at(records, index * STUN_SERVER_RECORD_LENGTH, 4)?;
            if previous.is_some_and(|prior: StunServer| prior.sort_cmp(server) != Ordering::Less) {
                return Err(CodecError::NestedRecordsOutOfOrder {
                    context: "STUN server list",
                    index,
                });
            }
            previous = Some(server);
        }
        Ok(Self { count, records })
    }

    /// Returns the number of configured STUN services.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.count as usize
    }

    /// Returns `false`; a valid list always has one server.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        false
    }

    /// Iterates over validated STUN servers.
    #[must_use]
    pub const fn servers(&self) -> StunServerIter<'a> {
        StunServerIter {
            records: self.records,
            position: 0,
        }
    }
}

/// Iterator over validated numeric STUN service records.
#[derive(Clone)]
pub struct StunServerIter<'a> {
    records: &'a [u8],
    position: usize,
}

impl Iterator for StunServerIter<'_> {
    type Item = StunServer;

    fn next(&mut self) -> Option<Self::Item> {
        let server = decode_stun_server_at(self.records, self.position, 0).ok()?;
        self.position = self.position.checked_add(STUN_SERVER_RECORD_LENGTH)?;
        Some(server)
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        let remaining =
            self.records.len().saturating_sub(self.position) / STUN_SERVER_RECORD_LENGTH;
        (remaining, Some(remaining))
    }
}

impl ExactSizeIterator for StunServerIter<'_> {}
impl std::iter::FusedIterator for StunServerIter<'_> {}

/// Encodes a canonical STUN server list.
///
/// # Errors
///
/// Returns [`CodecError`] for count, address, order, duplicate, arithmetic, or
/// output-capacity violations.
pub fn encode_stun_server_list(
    servers: &[StunServer],
    output: &mut [u8],
) -> Result<usize, CodecError> {
    let count = u8::try_from(servers.len()).map_err(|_| CodecError::ValueOutOfRange {
        field: "STUN server count",
        actual: u64::try_from(servers.len()).unwrap_or(u64::MAX),
        minimum: 1,
        maximum: u64::from(MAX_STUN_SERVERS),
    })?;
    if !(1..=MAX_STUN_SERVERS).contains(&count) {
        return Err(CodecError::ValueOutOfRange {
            field: "STUN server count",
            actual: u64::from(count),
            minimum: 1,
            maximum: u64::from(MAX_STUN_SERVERS),
        });
    }
    let mut previous = None;
    for (index, server) in servers.iter().copied().enumerate() {
        server.validate()?;
        if previous.is_some_and(|prior: StunServer| prior.sort_cmp(server) != Ordering::Less) {
            return Err(CodecError::NestedRecordsOutOfOrder {
                context: "STUN server list",
                index,
            });
        }
        previous = Some(server);
    }
    let records_length = servers.len().checked_mul(STUN_SERVER_RECORD_LENGTH).ok_or(
        CodecError::IntegerOverflow {
            field: "STUN server records length",
        },
    )?;
    let encoded_length =
        4_usize
            .checked_add(records_length)
            .ok_or(CodecError::IntegerOverflow {
                field: "STUN server list length",
            })?;
    if output.len() < encoded_length {
        return Err(CodecError::OutputTooSmall {
            field: "STUN server list",
            offset: 0,
            needed: encoded_length,
            remaining: output.len(),
        });
    }
    {
        let mut cursor = WriteCursor::new(output, 0);
        cursor.write_u8(count, "STUN server count")?;
        cursor.write_bytes(&[0; 3], "STUN server list reserved")?;
    }
    for (index, server) in servers.iter().copied().enumerate() {
        let start = 4 + index * STUN_SERVER_RECORD_LENGTH;
        let end = start + STUN_SERVER_RECORD_LENGTH;
        let remaining = output.len().saturating_sub(start);
        let record = output
            .get_mut(start..end)
            .ok_or(CodecError::OutputTooSmall {
                field: "STUN server record",
                offset: start,
                needed: STUN_SERVER_RECORD_LENGTH,
                remaining,
            })?;
        let (family, address) = encode_ip_slot(server.address.ip());
        let mut cursor = WriteCursor::new(record, start);
        cursor.write_u8(family, "STUN server address family")?;
        cursor.write_u8(server.priority, "STUN server priority")?;
        cursor.write_u16(server.address.port(), "STUN server port")?;
        cursor.write_bytes(&address, "STUN server address")?;
        cursor.write_u32(0, "STUN server reserved")?;
    }
    Ok(encoded_length)
}

#[allow(clippy::too_many_arguments)]
fn validate_generation_fields(
    generation_id: u64,
    tie_breaker: u64,
    created_at: u64,
    expires_at: u64,
    username_fragment: &[u8],
    password: &[u8],
    candidates: &[IceCandidate],
) -> Result<(), CodecError> {
    validate_generation_identity_and_time(generation_id, tie_breaker, created_at, expires_at)?;
    validate_credential_lengths(username_fragment.len(), password.len())?;
    validate_ice_credential(username_fragment, "ICE username fragment")?;
    validate_ice_credential(password, "ICE password")?;
    validate_candidate_count(candidates.len())?;
    let mut previous_priority = None;
    for (index, candidate) in candidates.iter().copied().enumerate() {
        candidate.validate()?;
        if previous_priority.is_some_and(|priority| priority <= candidate.priority) {
            return Err(CodecError::NestedRecordsOutOfOrder {
                context: "ICE candidate generation",
                index,
            });
        }
        previous_priority = Some(candidate.priority);
    }
    Ok(())
}

fn validate_generation_identity_and_time(
    generation_id: u64,
    tie_breaker: u64,
    created_at: u64,
    expires_at: u64,
) -> Result<(), CodecError> {
    if generation_id == 0 {
        return Err(CodecError::ZeroField {
            field: "connectivity generation ID",
        });
    }
    if tie_breaker == 0 {
        return Err(CodecError::ZeroField {
            field: "ICE role tie breaker",
        });
    }
    if created_at >= expires_at {
        return Err(CodecError::InvalidTimeRange {
            not_before: created_at,
            not_after: expires_at,
        });
    }
    let lifetime = expires_at - created_at;
    if lifetime > MAX_CONNECTIVITY_GENERATION_LIFETIME_SECONDS {
        return Err(CodecError::LifetimeTooLong {
            actual: lifetime,
            maximum: MAX_CONNECTIVITY_GENERATION_LIFETIME_SECONDS,
        });
    }
    Ok(())
}

fn validate_candidate_count(count: usize) -> Result<(), CodecError> {
    if !(1..=usize::from(MAX_ICE_CANDIDATES)).contains(&count) {
        return Err(CodecError::ValueOutOfRange {
            field: "ICE candidate count",
            actual: u64::try_from(count).unwrap_or(u64::MAX),
            minimum: 1,
            maximum: u64::from(MAX_ICE_CANDIDATES),
        });
    }
    Ok(())
}

fn validate_credential_lengths(
    username_length: usize,
    password_length: usize,
) -> Result<(), CodecError> {
    if !(MIN_ICE_USERNAME_FRAGMENT_LENGTH..=MAX_ICE_USERNAME_FRAGMENT_LENGTH)
        .contains(&username_length)
    {
        return Err(CodecError::ValueOutOfRange {
            field: "ICE username fragment length",
            actual: u64::try_from(username_length).unwrap_or(u64::MAX),
            minimum: u64::try_from(MIN_ICE_USERNAME_FRAGMENT_LENGTH).unwrap_or(u64::MAX),
            maximum: u64::try_from(MAX_ICE_USERNAME_FRAGMENT_LENGTH).unwrap_or(u64::MAX),
        });
    }
    if !(MIN_ICE_PASSWORD_LENGTH..=MAX_ICE_PASSWORD_LENGTH).contains(&password_length) {
        return Err(CodecError::ValueOutOfRange {
            field: "ICE password length",
            actual: u64::try_from(password_length).unwrap_or(u64::MAX),
            minimum: u64::try_from(MIN_ICE_PASSWORD_LENGTH).unwrap_or(u64::MAX),
            maximum: u64::try_from(MAX_ICE_PASSWORD_LENGTH).unwrap_or(u64::MAX),
        });
    }
    Ok(())
}

fn validate_ice_credential(bytes: &[u8], field: &'static str) -> Result<(), CodecError> {
    for (offset, byte) in bytes.iter().copied().enumerate() {
        if !byte.is_ascii_alphanumeric() && byte != b'+' && byte != b'/' {
            return Err(CodecError::InvalidTextCharacter { field, offset });
        }
    }
    Ok(())
}

fn generation_encoded_len(
    username_length: usize,
    password_length: usize,
    candidate_count: usize,
) -> Result<usize, CodecError> {
    let credential_length =
        username_length
            .checked_add(password_length)
            .ok_or(CodecError::IntegerOverflow {
                field: "ICE credential length",
            })?;
    let candidate_length = candidate_count
        .checked_mul(ICE_CANDIDATE_RECORD_LENGTH)
        .ok_or(CodecError::IntegerOverflow {
            field: "ICE candidate records length",
        })?;
    CONNECTIVITY_GENERATION_HEADER_LENGTH
        .checked_add(align_to_four(credential_length)?)
        .and_then(|length| length.checked_add(candidate_length))
        .ok_or(CodecError::IntegerOverflow {
            field: "connectivity generation length",
        })
}

fn align_to_four(length: usize) -> Result<usize, CodecError> {
    length
        .checked_add(3)
        .map(|value| value & !3)
        .ok_or(CodecError::IntegerOverflow {
            field: "four-byte aligned length",
        })
}

fn validate_datagram_size(value: u32, field: &'static str) -> Result<(), CodecError> {
    if !(MIN_ENDPOINT_DATAGRAM_SIZE..=MAX_ENDPOINT_DATAGRAM_SIZE).contains(&value) {
        return Err(CodecError::ValueOutOfRange {
            field,
            actual: u64::from(value),
            minimum: u64::from(MIN_ENDPOINT_DATAGRAM_SIZE),
            maximum: u64::from(MAX_ENDPOINT_DATAGRAM_SIZE),
        });
    }
    Ok(())
}

fn validate_connectivity_address(
    address: SocketAddr,
    context: &'static str,
) -> Result<(), CodecError> {
    if address.port() == 0 {
        return Err(CodecError::ZeroField {
            field: "connectivity UDP port",
        });
    }
    let invalid = match address.ip() {
        IpAddr::V4(address) => {
            address.is_unspecified()
                || address.is_loopback()
                || address.is_multicast()
                || address == Ipv4Addr::BROADCAST
        }
        IpAddr::V6(address) => {
            address.is_unspecified()
                || address.is_loopback()
                || address.is_multicast()
                || address.is_unicast_link_local()
                || address.to_ipv4_mapped().is_some()
        }
    };
    if invalid {
        return Err(CodecError::InvalidEndpointAddress { family: context });
    }
    Ok(())
}

fn encode_ip_slot(address: IpAddr) -> (u8, [u8; 16]) {
    match address {
        IpAddr::V4(address) => {
            let mut slot = [0; 16];
            slot[..4].copy_from_slice(&address.octets());
            (4, slot)
        }
        IpAddr::V6(address) => (6, address.octets()),
    }
}

fn decode_ip_slot(family: u8, slot: [u8; 16], field: &'static str) -> Result<IpAddr, CodecError> {
    match family {
        4 => {
            if slot[4..].iter().any(|byte| *byte != 0) {
                return Err(CodecError::InvalidEndpointAddress { family: field });
            }
            Ok(IpAddr::V4(Ipv4Addr::new(
                slot[0], slot[1], slot[2], slot[3],
            )))
        }
        6 => {
            let address = Ipv6Addr::from(slot);
            if address.to_ipv4_mapped().is_some() {
                return Err(CodecError::InvalidEndpointAddress { family: field });
            }
            Ok(IpAddr::V6(address))
        }
        value => Err(CodecError::InvalidEnumValue {
            field: "connectivity address family",
            value: u64::from(value),
        }),
    }
}

fn decode_ice_candidate_at(input: &[u8], base_offset: usize) -> Result<IceCandidate, CodecError> {
    let mut cursor = ReadCursor::new(input, base_offset);
    let record_length = usize::from(cursor.read_u16("ICE candidate record length")?);
    if record_length != ICE_CANDIDATE_RECORD_LENGTH {
        return Err(CodecError::LengthMismatch {
            field: "ICE candidate record length",
            expected: ICE_CANDIDATE_RECORD_LENGTH,
            actual: record_length,
        });
    }
    let class = IceCandidateClass::try_from(cursor.read_u8("ICE candidate class")?)?;
    let carrier = ConnectivityCarrier::try_from(cursor.read_u8("connectivity carrier")?)?;
    let priority = cursor.read_u32("ICE candidate priority")?;
    let foundation = cursor.read_u32("ICE candidate foundation")?;
    let max_datagram_size = cursor.read_u32("ICE candidate maximum datagram size")?;
    let port = cursor.read_u16("ICE candidate port")?;
    let related_port = cursor.read_u16("ICE related port")?;
    let family = cursor.read_u8("ICE candidate address family")?;
    let flags = cursor.read_u8("ICE candidate flags")?;
    if flags != 0 {
        return Err(CodecError::ReservedBits {
            field: "ICE candidate flags",
            bits: u64::from(flags),
            allowed: 0,
        });
    }
    let reserved_offset = base_offset.saturating_add(cursor.position());
    if cursor.read_u16("ICE candidate reserved")? != 0 {
        return Err(CodecError::NonZeroReserved {
            field: "ICE candidate reserved",
            offset: reserved_offset,
        });
    }
    let address_slot = cursor.read_array("ICE candidate address")?;
    let related_slot = cursor.read_array("ICE related address")?;
    let relay_bytes = cursor.read_array("relay ID")?;
    let address = SocketAddr::new(decode_ip_slot(family, address_slot, "candidate")?, port);
    let related_address = if related_port == 0 {
        if related_slot != [0; 16] {
            return Err(CodecError::InconsistentField {
                context: "ICE related address",
                field: "related port",
            });
        }
        None
    } else {
        Some(SocketAddr::new(
            decode_ip_slot(family, related_slot, "related candidate")?,
            related_port,
        ))
    };
    let relay_id = RelayId::from_bytes(relay_bytes);
    let candidate = IceCandidate {
        class,
        carrier,
        priority,
        foundation,
        max_datagram_size,
        address,
        related_address,
        relay_id: (!relay_id.is_zero()).then_some(relay_id),
    };
    candidate.validate()?;
    Ok(candidate)
}

fn validate_candidate_records(
    records: &[u8],
    count: u8,
    base_offset: usize,
) -> Result<(), CodecError> {
    let mut previous_priority = None;
    for index in 0..usize::from(count) {
        let start =
            index
                .checked_mul(ICE_CANDIDATE_RECORD_LENGTH)
                .ok_or(CodecError::IntegerOverflow {
                    field: "ICE candidate record offset",
                })?;
        let end =
            start
                .checked_add(ICE_CANDIDATE_RECORD_LENGTH)
                .ok_or(CodecError::IntegerOverflow {
                    field: "ICE candidate record end",
                })?;
        let record = records.get(start..end).ok_or(CodecError::Truncated {
            field: "ICE candidate record",
            offset: base_offset.saturating_add(start),
            needed: ICE_CANDIDATE_RECORD_LENGTH,
            remaining: records.len().saturating_sub(start),
        })?;
        let candidate = decode_ice_candidate_at(record, base_offset.saturating_add(start))?;
        if previous_priority.is_some_and(|priority| priority <= candidate.priority) {
            return Err(CodecError::NestedRecordsOutOfOrder {
                context: "ICE candidate generation",
                index,
            });
        }
        previous_priority = Some(candidate.priority);
    }
    Ok(())
}

fn decode_stun_server_at(
    records: &[u8],
    position: usize,
    base_offset: usize,
) -> Result<StunServer, CodecError> {
    let record = records
        .get(position..position.saturating_add(STUN_SERVER_RECORD_LENGTH))
        .ok_or(CodecError::Truncated {
            field: "STUN server record",
            offset: base_offset.saturating_add(position),
            needed: STUN_SERVER_RECORD_LENGTH,
            remaining: records.len().saturating_sub(position),
        })?;
    let mut cursor = ReadCursor::new(record, base_offset.saturating_add(position));
    let family = cursor.read_u8("STUN server address family")?;
    let priority = cursor.read_u8("STUN server priority")?;
    let port = cursor.read_u16("STUN server port")?;
    let address = cursor.read_array("STUN server address")?;
    let reserved_offset = base_offset
        .saturating_add(position)
        .saturating_add(cursor.position());
    if cursor.read_u32("STUN server reserved")? != 0 {
        return Err(CodecError::NonZeroReserved {
            field: "STUN server reserved",
            offset: reserved_offset,
        });
    }
    let server = StunServer {
        priority,
        address: SocketAddr::new(decode_ip_slot(family, address, "STUN server")?, port),
    };
    server.validate()?;
    Ok(server)
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

    use stella_common::{NodeId, RelayId};

    use super::{
        encode_connectivity_generation, encode_connectivity_list,
        encode_connectivity_list_from_encoded_records, encode_connectivity_record,
        encode_stun_server_list, ConnectivityCarrier, ConnectivityGenerationRef,
        ConnectivityGenerationView, ConnectivityListView, ConnectivityRecordRef,
        ConnectivityRecordView, IceCandidate, IceCandidateClass, StunServer, StunServerListView,
        CONNECTIVITY_GENERATION_HEADER_LENGTH, CONNECTIVITY_RECORD_FIXED_LENGTH,
        ICE_CANDIDATE_RECORD_LENGTH,
    };
    use crate::CodecError;

    const USERNAME: &[u8] = b"Abcd1234";
    const PASSWORD: &[u8] = b"Abcdefghijklmnopqrstuv";

    fn host_candidate(priority: u32) -> IceCandidate {
        IceCandidate {
            class: IceCandidateClass::Host,
            carrier: ConnectivityCarrier::DirectUdp,
            priority,
            foundation: 10,
            max_datagram_size: 1_200,
            address: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10)), 45_000),
            related_address: None,
            relay_id: None,
        }
    }

    fn relay_candidate(priority: u32) -> IceCandidate {
        IceCandidate {
            class: IceCandidateClass::Relay,
            carrier: ConnectivityCarrier::TurnTls,
            priority,
            foundation: 20,
            max_datagram_size: 1_200,
            address: SocketAddr::new(
                IpAddr::V6(Ipv6Addr::from([0x20, 1, 0xdb, 8, 0, 0, 0, 1])),
                50_000,
            ),
            related_address: Some(SocketAddr::new(
                IpAddr::V6(Ipv6Addr::from([0x20, 1, 0xdb, 8, 0, 0, 0, 2])),
                45_000,
            )),
            relay_id: Some(RelayId::from_bytes([9; 16])),
        }
    }

    fn generation(candidates: &[IceCandidate]) -> ConnectivityGenerationRef<'_> {
        ConnectivityGenerationRef::new(7, 8, 1_000, 1_600, USERNAME, PASSWORD, candidates)
            .expect("valid connectivity generation")
    }

    #[test]
    fn candidate_records_round_trip_and_enforce_relay_semantics() {
        let candidate = relay_candidate(100);
        let mut encoded = [0; ICE_CANDIDATE_RECORD_LENGTH];
        candidate
            .encode(&mut encoded)
            .expect("encode relay candidate");
        assert_eq!(IceCandidate::decode(&encoded), Ok(candidate));
        assert_eq!(&encoded[..4], &[0, 72, 5, 4]);

        let mut invalid = host_candidate(200);
        invalid.carrier = ConnectivityCarrier::TurnUdp;
        assert!(matches!(
            invalid.validate(),
            Err(CodecError::InconsistentField {
                context: "ICE candidate class and carrier",
                field: "relay state",
            })
        ));
        let mut loopback = host_candidate(200);
        loopback.address = "127.0.0.1:45000".parse().expect("loopback address");
        assert!(matches!(
            loopback.validate(),
            Err(CodecError::InvalidEndpointAddress { .. })
        ));
    }

    #[test]
    fn connectivity_generation_round_trips_and_redacts_credentials() {
        let candidates = [host_candidate(200), relay_candidate(100)];
        let generation = generation(&candidates);
        let mut encoded = vec![0; generation.encoded_len().expect("generation length")];
        assert_eq!(
            encode_connectivity_generation(generation, &mut encoded),
            Ok(encoded.len())
        );
        assert_eq!(
            encoded.len(),
            CONNECTIVITY_GENERATION_HEADER_LENGTH + 32 + 144
        );
        assert_eq!(&encoded[..4], b"SCG1");

        let decoded = ConnectivityGenerationView::decode(&encoded).expect("decode generation");
        assert_eq!(decoded.generation_id(), 7);
        assert_eq!(decoded.tie_breaker(), 8);
        assert_eq!(decoded.username_fragment(), USERNAME);
        assert_eq!(decoded.password(), PASSWORD);
        assert_eq!(decoded.candidates().collect::<Vec<_>>(), candidates);
        let diagnostic = format!("{decoded:?}");
        assert!(!diagnostic.contains("Abcd1234"));
        assert!(!diagnostic.contains("Abcdefghijklmnopqrstuv"));
    }

    #[test]
    fn connectivity_generation_rejects_order_credentials_padding_and_lifetime() {
        let candidates = [host_candidate(100), relay_candidate(200)];
        assert!(matches!(
            ConnectivityGenerationRef::new(7, 8, 1_000, 1_600, USERNAME, PASSWORD, &candidates),
            Err(CodecError::NestedRecordsOutOfOrder {
                context: "ICE candidate generation",
                index: 1,
            })
        ));
        assert!(matches!(
            ConnectivityGenerationRef::new(
                7,
                8,
                1_000,
                1_601,
                USERNAME,
                PASSWORD,
                &[host_candidate(100)]
            ),
            Err(CodecError::LifetimeTooLong { .. })
        ));
        assert!(matches!(
            ConnectivityGenerationRef::new(
                7,
                8,
                1_000,
                1_600,
                b"bad_name",
                PASSWORD,
                &[host_candidate(100)]
            ),
            Err(CodecError::InvalidTextCharacter { .. })
        ));

        let candidates = [host_candidate(100)];
        let generation = generation(&candidates);
        let mut encoded = vec![0; generation.encoded_len().expect("generation length")];
        encode_connectivity_generation(generation, &mut encoded).expect("encode generation");
        encoded[CONNECTIVITY_GENERATION_HEADER_LENGTH + USERNAME.len() + PASSWORD.len()] = 1;
        assert!(matches!(
            ConnectivityGenerationView::decode(&encoded),
            Err(CodecError::NonZeroReserved {
                field: "ICE credential padding",
                ..
            })
        ));
    }

    #[test]
    fn connectivity_records_and_lists_round_trip_in_node_order() {
        let first_candidates = [host_candidate(200)];
        let second_candidates = [host_candidate(100)];
        let first =
            ConnectivityRecordRef::new(NodeId::from_bytes([1; 16]), generation(&first_candidates))
                .expect("first record");
        let second =
            ConnectivityRecordRef::new(NodeId::from_bytes([2; 16]), generation(&second_candidates))
                .expect("second record");
        let mut record_bytes = vec![0; first.encoded_len().expect("record length")];
        assert_eq!(
            encode_connectivity_record(first, &mut record_bytes),
            Ok(record_bytes.len())
        );
        assert_eq!(
            usize::from(u16::from_be_bytes([record_bytes[0], record_bytes[1]])),
            CONNECTIVITY_RECORD_FIXED_LENGTH
                + generation(&first_candidates)
                    .encoded_len()
                    .expect("generation length")
        );
        let decoded = ConnectivityRecordView::decode(&record_bytes).expect("decode record");
        assert_eq!(decoded.node_id(), first.node_id());
        assert_eq!(decoded.generation().generation_id(), 7);
        let mut second_record_bytes = vec![0; second.encoded_len().expect("record length")];
        encode_connectivity_record(second, &mut second_record_bytes).expect("encode second record");

        let length = 4
            + first.encoded_len().expect("first length")
            + second.encoded_len().expect("second length");
        let mut list_bytes = vec![0; length];
        assert_eq!(
            encode_connectivity_list(&[first, second], &mut list_bytes),
            Ok(length)
        );
        let mut stored_list_bytes = vec![0; length];
        assert_eq!(
            encode_connectivity_list_from_encoded_records(
                &[&record_bytes, &second_record_bytes],
                &mut stored_list_bytes
            ),
            Ok(length)
        );
        assert_eq!(stored_list_bytes, list_bytes);
        let list = ConnectivityListView::decode(&list_bytes).expect("decode list");
        assert_eq!(list.len(), 2);
        assert_eq!(
            list.records()
                .map(|record| record.node_id())
                .collect::<Vec<_>>(),
            vec![first.node_id(), second.node_id()]
        );
        assert!(matches!(
            encode_connectivity_list(&[second, first], &mut list_bytes),
            Err(CodecError::NestedRecordsOutOfOrder {
                context: "connectivity list",
                index: 1,
            })
        ));
        assert!(matches!(
            encode_connectivity_list_from_encoded_records(
                &[&second_record_bytes, &record_bytes],
                &mut stored_list_bytes
            ),
            Err(CodecError::NestedRecordsOutOfOrder {
                context: "connectivity list",
                index: 1,
            })
        ));
    }

    #[test]
    fn stun_server_list_round_trips_and_requires_canonical_order() {
        let first = StunServer {
            priority: 0,
            address: "192.0.2.1:3478".parse().expect("first STUN server"),
        };
        let second = StunServer {
            priority: 1,
            address: "[2001:db8::1]:3478".parse().expect("second STUN server"),
        };
        let mut encoded = vec![0; 4 + 2 * super::STUN_SERVER_RECORD_LENGTH];
        assert_eq!(
            encode_stun_server_list(&[first, second], &mut encoded),
            Ok(encoded.len())
        );
        let decoded = StunServerListView::decode(&encoded).expect("decode STUN server list");
        assert_eq!(decoded.servers().collect::<Vec<_>>(), vec![first, second]);
        assert!(matches!(
            encode_stun_server_list(&[second, first], &mut encoded),
            Err(CodecError::NestedRecordsOutOfOrder {
                context: "STUN server list",
                index: 1,
            })
        ));
    }
}
