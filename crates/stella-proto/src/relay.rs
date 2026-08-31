//! Version 0.2 relay-service configuration codecs.

use std::{
    cmp::Ordering,
    fmt,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
};

use stella_common::RelayId;

use crate::{
    common::validate_record_length,
    cursor::{ReadCursor, WriteCursor},
    CodecError, MAX_ENDPOINT_DATAGRAM_SIZE, MIN_ENDPOINT_DATAGRAM_SIZE,
};

/// Fixed header bytes before relay-service strings and nested records.
pub const RELAY_SERVICE_HEADER_LENGTH: usize = 68;

/// Exact length of one numeric relay-address record.
pub const RELAY_ADDRESS_RECORD_LENGTH: usize = 20;

/// Maximum relay services in one controller configuration.
pub const MAX_RELAY_SERVICES: u8 = 8;

/// Maximum numeric addresses advertised by one relay service.
pub const MAX_RELAY_ADDRESSES: u8 = 8;

/// Maximum SHA-256 SPKI pins advertised by one relay service.
pub const MAX_RELAY_SPKI_PINS: u8 = 4;

/// Maximum lifetime of controller-issued relay credentials.
pub const MAX_RELAY_CREDENTIAL_LIFETIME_SECONDS: u64 = 600;

/// Maximum DNS hostname or TLS server-name byte length.
pub const MAX_RELAY_DNS_NAME_LENGTH: usize = 253;

/// Maximum relay credential username byte length.
pub const MAX_RELAY_USERNAME_LENGTH: usize = 128;

/// Minimum opaque relay credential secret byte length.
pub const MIN_RELAY_SECRET_LENGTH: usize = 16;

/// Maximum opaque relay credential secret byte length.
pub const MAX_RELAY_SECRET_LENGTH: usize = 128;

/// Maximum diagnostic region-label byte length.
pub const MAX_RELAY_REGION_LENGTH: usize = 32;

/// Registered client-to-relay carrier mask.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RelayCarrierMask(u16);

impl RelayCarrierMask {
    /// TURN carried over UDP.
    pub const TURN_UDP: Self = Self(1 << 0);
    /// TURN carried over TCP.
    pub const TURN_TCP: Self = Self(1 << 1);
    /// TURN carried over TLS over TCP.
    pub const TURN_TLS: Self = Self(1 << 2);
    /// Stella TURN records carried by secure WebSocket.
    pub const SECURE_WEBSOCKET: Self = Self(1 << 3);
    /// Every carrier defined by version 0.2.
    pub const ALL: Self =
        Self(Self::TURN_UDP.0 | Self::TURN_TCP.0 | Self::TURN_TLS.0 | Self::SECURE_WEBSOCKET.0);

    /// Creates a carrier mask after rejecting zero and undefined bits.
    ///
    /// # Errors
    ///
    /// Returns [`CodecError`] when no carrier or an undefined carrier bit is set.
    pub fn from_bits(bits: u16) -> Result<Self, CodecError> {
        if bits == 0 {
            return Err(CodecError::ZeroField {
                field: "relay carrier mask",
            });
        }
        if bits & !Self::ALL.0 != 0 {
            return Err(CodecError::ReservedBits {
                field: "relay carrier mask",
                bits: u64::from(bits),
                allowed: u64::from(Self::ALL.0),
            });
        }
        Ok(Self(bits))
    }

    /// Returns the canonical mask bits.
    #[must_use]
    pub const fn bits(self) -> u16 {
        self.0
    }

    /// Returns whether every bit in `carrier` is present.
    #[must_use]
    pub const fn contains(self, carrier: Self) -> bool {
        self.0 & carrier.0 == carrier.0
    }

    /// Returns whether TLS or secure WebSocket certificate validation is needed.
    #[must_use]
    pub const fn requires_tls(self) -> bool {
        self.contains(Self::TURN_TLS) || self.contains(Self::SECURE_WEBSOCKET)
    }
}

/// TLS trust checks required for a relay service.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RelayTrustRequirements(u8);

impl RelayTrustRequirements {
    /// No TLS trust check because no TLS carrier is offered.
    pub const NONE: Self = Self(0);
    /// Require normal Web PKI name and chain validation.
    pub const WEB_PKI: Self = Self(1 << 0);
    /// Require one configured SHA-256 SPKI pin to match.
    pub const SPKI_PIN: Self = Self(1 << 1);
    /// Every trust requirement defined by version 0.2.
    pub const ALL: Self = Self(Self::WEB_PKI.0 | Self::SPKI_PIN.0);

    /// Creates trust requirements after rejecting undefined bits.
    ///
    /// # Errors
    ///
    /// Returns [`CodecError`] when an undefined trust bit is set.
    pub fn from_bits(bits: u8) -> Result<Self, CodecError> {
        if bits & !Self::ALL.0 != 0 {
            return Err(CodecError::ReservedBits {
                field: "relay TLS trust requirements",
                bits: u64::from(bits),
                allowed: u64::from(Self::ALL.0),
            });
        }
        Ok(Self(bits))
    }

    /// Returns the canonical trust bits.
    #[must_use]
    pub const fn bits(self) -> u8 {
        self.0
    }

    /// Returns whether every bit in `requirement` is present.
    #[must_use]
    pub const fn contains(self, requirement: Self) -> bool {
        self.0 & requirement.0 == requirement.0
    }

    /// Returns whether no trust check is configured.
    #[must_use]
    pub const fn is_empty(self) -> bool {
        self.0 == 0
    }
}

/// Carrier-specific listener ports for one relay service.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RelayPorts {
    /// TURN over UDP port, or zero when unsupported.
    pub turn_udp: u16,
    /// TURN over TCP port, or zero when unsupported.
    pub turn_tcp: u16,
    /// TURN over TLS port, or zero when unsupported.
    pub turn_tls: u16,
    /// Secure WebSocket port, or zero when unsupported.
    pub secure_websocket: u16,
}

/// One numeric address of a relay service.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RelayAddress {
    /// Lower values are preferred.
    pub priority: u8,
    /// Numeric unicast address; carrier ports are stored by the service.
    pub address: IpAddr,
}

impl RelayAddress {
    /// Validates a numeric address that has an unambiguous scope.
    ///
    /// # Errors
    ///
    /// Returns [`CodecError`] for unspecified, multicast, broadcast,
    /// IPv4-mapped IPv6, or unscoped link-local IPv6 addresses.
    pub fn validate(self) -> Result<(), CodecError> {
        validate_relay_ip(self.address)
    }

    fn sort_cmp(self, other: Self) -> Ordering {
        let (family, address) = encode_ip_slot(self.address);
        let (other_family, other_address) = encode_ip_slot(other.address);
        self.priority
            .cmp(&other.priority)
            .then_with(|| family.cmp(&other_family))
            .then_with(|| address.cmp(&other_address))
    }
}

/// Borrowed values used to encode one relay service record.
#[derive(Clone, Copy)]
pub struct RelayServiceRef<'a> {
    /// Stable service identity.
    pub relay_id: RelayId,
    /// Supported client-to-relay carriers.
    pub carriers: RelayCarrierMask,
    /// Lower values are preferred across services.
    pub priority: u16,
    /// Maximum complete Stella datagram relayed by this service.
    pub max_datagram_size: u32,
    /// Advertised allocation lifetime in seconds.
    pub allocation_lifetime_seconds: u32,
    /// Allocation idle timeout in seconds.
    pub idle_timeout_seconds: u32,
    /// Controller credential issue Unix time.
    pub credential_issued_at: u64,
    /// Exclusive controller credential expiry Unix time.
    pub credential_expires_at: u64,
    /// Optional canonical lower-case DNS hostname.
    pub hostname: &'a str,
    /// Optional canonical lower-case TLS server name.
    pub tls_server_name: &'a str,
    /// Printable relay-authentication username.
    pub credential_username: &'a [u8],
    /// Opaque relay-authentication secret.
    pub credential_secret: &'a [u8],
    /// Optional printable deployment region label.
    pub region: &'a str,
    /// Required certificate trust checks.
    pub trust: RelayTrustRequirements,
    /// Carrier-specific listener ports.
    pub ports: RelayPorts,
    /// Canonically ordered numeric service addresses.
    pub addresses: &'a [RelayAddress],
    /// Canonically ordered SHA-256 SPKI pins.
    pub spki_pins: &'a [[u8; 32]],
}

impl RelayServiceRef<'_> {
    /// Validates all scalar, text, credential, carrier, address, and pin rules.
    ///
    /// # Errors
    ///
    /// Returns [`CodecError`] for an invalid service identifier, bounds,
    /// credential, carrier/port combination, trust configuration, text,
    /// address order, or pin order.
    pub fn validate(self) -> Result<(), CodecError> {
        validate_service_scalars(self)?;
        validate_relay_addresses(self.addresses)?;
        validate_spki_pins(self.spki_pins)?;
        Ok(())
    }

    /// Returns the exact encoded service-record length.
    ///
    /// # Errors
    ///
    /// Returns [`CodecError`] for invalid data or length overflow.
    pub fn encoded_len(self) -> Result<usize, CodecError> {
        self.validate()?;
        relay_service_encoded_len(self)
    }
}

impl fmt::Debug for RelayServiceRef<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RelayServiceRef")
            .field("relay_id", &self.relay_id)
            .field("carriers", &self.carriers)
            .field("priority", &self.priority)
            .field("max_datagram_size", &self.max_datagram_size)
            .field(
                "allocation_lifetime_seconds",
                &self.allocation_lifetime_seconds,
            )
            .field("idle_timeout_seconds", &self.idle_timeout_seconds)
            .field("credential_issued_at", &self.credential_issued_at)
            .field("credential_expires_at", &self.credential_expires_at)
            .field("hostname", &self.hostname)
            .field("tls_server_name", &self.tls_server_name)
            .field(
                "credential_username_length",
                &self.credential_username.len(),
            )
            .field("credential_secret_length", &self.credential_secret.len())
            .field("region", &self.region)
            .field("trust", &self.trust)
            .field("ports", &self.ports)
            .field("address_count", &self.addresses.len())
            .field("spki_pin_count", &self.spki_pins.len())
            .finish_non_exhaustive()
    }
}

/// Borrowed validated relay service record.
#[derive(Clone)]
pub struct RelayServiceView<'a> {
    relay_id: RelayId,
    carriers: RelayCarrierMask,
    priority: u16,
    max_datagram_size: u32,
    allocation_lifetime_seconds: u32,
    idle_timeout_seconds: u32,
    credential_issued_at: u64,
    credential_expires_at: u64,
    hostname: &'a str,
    tls_server_name: &'a str,
    credential_username: &'a [u8],
    credential_secret: &'a [u8],
    region: &'a str,
    trust: RelayTrustRequirements,
    ports: RelayPorts,
    address_records: &'a [u8],
    address_count: u8,
    pin_records: &'a [u8],
    pin_count: u8,
    encoded_length: usize,
}

#[derive(Clone, Copy)]
struct RelayServiceHeader {
    encoded_length: usize,
    address_count: u8,
    pin_count: u8,
    relay_id: RelayId,
    carriers: RelayCarrierMask,
    priority: u16,
    max_datagram_size: u32,
    allocation_lifetime_seconds: u32,
    idle_timeout_seconds: u32,
    credential_issued_at: u64,
    credential_expires_at: u64,
    hostname_length: usize,
    tls_name_length: usize,
    username_length: usize,
    secret_length: usize,
    region_length: usize,
    trust: RelayTrustRequirements,
    ports: RelayPorts,
}

impl<'a> RelayServiceView<'a> {
    /// Decodes one complete relay service record.
    ///
    /// # Errors
    ///
    /// Returns [`CodecError`] for invalid length, bounds, text, credentials,
    /// carrier ports, trust, addresses, pins, padding, or trailing bytes.
    pub fn decode(input: &'a [u8]) -> Result<Self, CodecError> {
        let (service, consumed) = Self::decode_prefix(input, 0)?;
        validate_record_length(input.len(), consumed, "relay service record")?;
        Ok(service)
    }

    fn decode_prefix(input: &'a [u8], base_offset: usize) -> Result<(Self, usize), CodecError> {
        let (header, mut cursor) = decode_relay_service_header(input, base_offset)?;
        let hostname_bytes = cursor.read_slice(header.hostname_length, "relay hostname")?;
        let tls_name_bytes = cursor.read_slice(header.tls_name_length, "relay TLS server name")?;
        let credential_username =
            cursor.read_slice(header.username_length, "relay credential username")?;
        let credential_secret =
            cursor.read_slice(header.secret_length, "relay credential secret")?;
        let region_bytes = cursor.read_slice(header.region_length, "relay region label")?;
        let hostname = decode_text(hostname_bytes, "relay hostname")?;
        let tls_server_name = decode_text(tls_name_bytes, "relay TLS server name")?;
        let region = decode_text(region_bytes, "relay region label")?;
        let string_length = relay_header_strings_length(header)?;
        let padding_length = align_to_four(string_length)? - string_length;
        let padding_offset = base_offset.saturating_add(cursor.position());
        if cursor
            .read_slice(padding_length, "relay service string padding")?
            .iter()
            .any(|byte| *byte != 0)
        {
            return Err(CodecError::NonZeroReserved {
                field: "relay service string padding",
                offset: padding_offset,
            });
        }
        let address_length = usize::from(header.address_count)
            .checked_mul(RELAY_ADDRESS_RECORD_LENGTH)
            .ok_or(CodecError::IntegerOverflow {
                field: "relay address records length",
            })?;
        let address_offset = cursor.position();
        let address_records = cursor.read_slice(address_length, "relay address records")?;
        validate_relay_address_records(
            address_records,
            header.address_count,
            base_offset.saturating_add(address_offset),
        )?;
        let pin_length =
            usize::from(header.pin_count)
                .checked_mul(32)
                .ok_or(CodecError::IntegerOverflow {
                    field: "relay SPKI pin records length",
                })?;
        let pin_offset = cursor.position();
        let pin_records = cursor.read_slice(pin_length, "relay SPKI pin records")?;
        validate_spki_pin_records(
            pin_records,
            header.pin_count,
            base_offset.saturating_add(pin_offset),
        )?;
        validate_record_length(
            header.encoded_length,
            cursor.position(),
            "relay service record",
        )?;

        let service = Self {
            relay_id: header.relay_id,
            carriers: header.carriers,
            priority: header.priority,
            max_datagram_size: header.max_datagram_size,
            allocation_lifetime_seconds: header.allocation_lifetime_seconds,
            idle_timeout_seconds: header.idle_timeout_seconds,
            credential_issued_at: header.credential_issued_at,
            credential_expires_at: header.credential_expires_at,
            hostname,
            tls_server_name,
            credential_username,
            credential_secret,
            region,
            trust: header.trust,
            ports: header.ports,
            address_records,
            address_count: header.address_count,
            pin_records,
            pin_count: header.pin_count,
            encoded_length: header.encoded_length,
        };
        validate_decoded_service(&service)?;
        Ok((service, header.encoded_length))
    }

    /// Returns the stable relay identity.
    #[must_use]
    pub const fn relay_id(&self) -> RelayId {
        self.relay_id
    }

    /// Returns supported carriers.
    #[must_use]
    pub const fn carriers(&self) -> RelayCarrierMask {
        self.carriers
    }

    /// Returns the service priority.
    #[must_use]
    pub const fn priority(&self) -> u16 {
        self.priority
    }

    /// Returns the maximum relayed Stella datagram.
    #[must_use]
    pub const fn max_datagram_size(&self) -> u32 {
        self.max_datagram_size
    }

    /// Returns the allocation lifetime in seconds.
    #[must_use]
    pub const fn allocation_lifetime_seconds(&self) -> u32 {
        self.allocation_lifetime_seconds
    }

    /// Returns the idle timeout in seconds.
    #[must_use]
    pub const fn idle_timeout_seconds(&self) -> u32 {
        self.idle_timeout_seconds
    }

    /// Returns the credential issue Unix time.
    #[must_use]
    pub const fn credential_issued_at(&self) -> u64 {
        self.credential_issued_at
    }

    /// Returns the exclusive credential expiry Unix time.
    #[must_use]
    pub const fn credential_expires_at(&self) -> u64 {
        self.credential_expires_at
    }

    /// Returns the optional canonical DNS hostname.
    #[must_use]
    pub const fn hostname(&self) -> &'a str {
        self.hostname
    }

    /// Returns the optional canonical TLS server name.
    #[must_use]
    pub const fn tls_server_name(&self) -> &'a str {
        self.tls_server_name
    }

    /// Borrows the relay credential username.
    #[must_use]
    pub const fn credential_username(&self) -> &'a [u8] {
        self.credential_username
    }

    /// Borrows the opaque relay credential secret.
    #[must_use]
    pub const fn credential_secret(&self) -> &'a [u8] {
        self.credential_secret
    }

    /// Returns the optional region label.
    #[must_use]
    pub const fn region(&self) -> &'a str {
        self.region
    }

    /// Returns required TLS trust checks.
    #[must_use]
    pub const fn trust(&self) -> RelayTrustRequirements {
        self.trust
    }

    /// Returns carrier listener ports.
    #[must_use]
    pub const fn ports(&self) -> RelayPorts {
        self.ports
    }

    /// Iterates over validated numeric addresses.
    #[must_use]
    pub const fn addresses(&self) -> RelayAddressIter<'a> {
        RelayAddressIter {
            records: self.address_records,
            position: 0,
        }
    }

    /// Iterates over validated SHA-256 SPKI pins.
    #[must_use]
    pub const fn spki_pins(&self) -> RelaySpkiPinIter<'a> {
        RelaySpkiPinIter {
            records: self.pin_records,
            position: 0,
        }
    }

    /// Returns the exact encoded record length.
    #[must_use]
    pub const fn encoded_len(&self) -> usize {
        self.encoded_length
    }
}

fn decode_relay_service_header(
    input: &[u8],
    base_offset: usize,
) -> Result<(RelayServiceHeader, ReadCursor<'_>), CodecError> {
    let mut length_cursor = ReadCursor::new(input, base_offset);
    let encoded_length = usize::from(length_cursor.read_u16("relay service record length")?);
    if encoded_length < RELAY_SERVICE_HEADER_LENGTH || encoded_length % 4 != 0 {
        return Err(CodecError::ValueOutOfRange {
            field: "relay service record length",
            actual: u64::try_from(encoded_length).unwrap_or(u64::MAX),
            minimum: u64::try_from(RELAY_SERVICE_HEADER_LENGTH).unwrap_or(u64::MAX),
            maximum: u64::from(u16::MAX),
        });
    }
    let record = input.get(..encoded_length).ok_or(CodecError::Truncated {
        field: "relay service record",
        offset: base_offset,
        needed: encoded_length,
        remaining: input.len(),
    })?;
    let mut cursor = ReadCursor::new(record, base_offset);
    let _ = cursor.read_u16("relay service record length")?;
    let address_count = cursor.read_u8("relay address count")?;
    validate_count(address_count, MAX_RELAY_ADDRESSES, "relay address count", 0)?;
    let pin_count = cursor.read_u8("relay SPKI pin count")?;
    validate_count(pin_count, MAX_RELAY_SPKI_PINS, "relay SPKI pin count", 0)?;
    let relay_id = RelayId::from_bytes(cursor.read_array("relay ID")?);
    let carriers = RelayCarrierMask::from_bits(cursor.read_u16("relay carrier mask")?)?;
    let priority = cursor.read_u16("relay service priority")?;
    let max_datagram_size = cursor.read_u32("relay maximum datagram size")?;
    let allocation_lifetime_seconds = cursor.read_u32("relay allocation lifetime")?;
    let idle_timeout_seconds = cursor.read_u32("relay idle timeout")?;
    let credential_issued_at = cursor.read_u64("relay credential issue time")?;
    let credential_expires_at = cursor.read_u64("relay credential expiry time")?;
    let hostname_length = usize::from(cursor.read_u8("relay hostname length")?);
    let tls_name_length = usize::from(cursor.read_u8("relay TLS name length")?);
    let username_length = usize::from(cursor.read_u8("relay username length")?);
    let secret_length = usize::from(cursor.read_u8("relay secret length")?);
    let region_length = usize::from(cursor.read_u8("relay region length")?);
    let trust = RelayTrustRequirements::from_bits(cursor.read_u8("relay TLS trust")?)?;
    let reserved_offset = base_offset.saturating_add(cursor.position());
    if cursor.read_u16("relay service reserved")? != 0 {
        return Err(CodecError::NonZeroReserved {
            field: "relay service reserved",
            offset: reserved_offset,
        });
    }
    let ports = RelayPorts {
        turn_udp: cursor.read_u16("TURN UDP port")?,
        turn_tcp: cursor.read_u16("TURN TCP port")?,
        turn_tls: cursor.read_u16("TURN TLS port")?,
        secure_websocket: cursor.read_u16("relay WebSocket port")?,
    };
    Ok((
        RelayServiceHeader {
            encoded_length,
            address_count,
            pin_count,
            relay_id,
            carriers,
            priority,
            max_datagram_size,
            allocation_lifetime_seconds,
            idle_timeout_seconds,
            credential_issued_at,
            credential_expires_at,
            hostname_length,
            tls_name_length,
            username_length,
            secret_length,
            region_length,
            trust,
            ports,
        },
        cursor,
    ))
}

fn relay_header_strings_length(header: RelayServiceHeader) -> Result<usize, CodecError> {
    header
        .hostname_length
        .checked_add(header.tls_name_length)
        .and_then(|value| value.checked_add(header.username_length))
        .and_then(|value| value.checked_add(header.secret_length))
        .and_then(|value| value.checked_add(header.region_length))
        .ok_or(CodecError::IntegerOverflow {
            field: "relay service strings length",
        })
}

impl fmt::Debug for RelayServiceView<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RelayServiceView")
            .field("relay_id", &self.relay_id)
            .field("carriers", &self.carriers)
            .field("priority", &self.priority)
            .field("max_datagram_size", &self.max_datagram_size)
            .field(
                "allocation_lifetime_seconds",
                &self.allocation_lifetime_seconds,
            )
            .field("idle_timeout_seconds", &self.idle_timeout_seconds)
            .field("credential_issued_at", &self.credential_issued_at)
            .field("credential_expires_at", &self.credential_expires_at)
            .field("hostname", &self.hostname)
            .field("tls_server_name", &self.tls_server_name)
            .field(
                "credential_username_length",
                &self.credential_username.len(),
            )
            .field("credential_secret_length", &self.credential_secret.len())
            .field("region", &self.region)
            .field("trust", &self.trust)
            .field("ports", &self.ports)
            .field("address_count", &self.address_count)
            .field("spki_pin_count", &self.pin_count)
            .field("encoded_length", &self.encoded_length)
            .finish_non_exhaustive()
    }
}

/// Iterator over validated numeric relay addresses.
#[derive(Clone)]
pub struct RelayAddressIter<'a> {
    records: &'a [u8],
    position: usize,
}

impl Iterator for RelayAddressIter<'_> {
    type Item = RelayAddress;

    fn next(&mut self) -> Option<Self::Item> {
        let address = decode_relay_address_at(self.records, self.position, 0).ok()?;
        self.position = self.position.checked_add(RELAY_ADDRESS_RECORD_LENGTH)?;
        Some(address)
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        let remaining =
            self.records.len().saturating_sub(self.position) / RELAY_ADDRESS_RECORD_LENGTH;
        (remaining, Some(remaining))
    }
}

impl ExactSizeIterator for RelayAddressIter<'_> {}
impl std::iter::FusedIterator for RelayAddressIter<'_> {}

/// Iterator over validated SHA-256 SPKI pins.
#[derive(Clone)]
pub struct RelaySpkiPinIter<'a> {
    records: &'a [u8],
    position: usize,
}

impl<'a> Iterator for RelaySpkiPinIter<'a> {
    type Item = &'a [u8; 32];

    fn next(&mut self) -> Option<Self::Item> {
        let end = self.position.checked_add(32)?;
        let bytes = self.records.get(self.position..end)?;
        self.position = end;
        bytes.try_into().ok()
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        let remaining = self.records.len().saturating_sub(self.position) / 32;
        (remaining, Some(remaining))
    }
}

impl ExactSizeIterator for RelaySpkiPinIter<'_> {}
impl std::iter::FusedIterator for RelaySpkiPinIter<'_> {}

#[derive(Clone, Copy)]
struct RelayWireLengths {
    address_count: u8,
    pin_count: u8,
    hostname: u8,
    tls_name: u8,
    username: u8,
    secret: u8,
    region: u8,
}

/// Encodes one complete relay service record.
///
/// # Errors
///
/// Returns [`CodecError`] for invalid service data, length overflow, or
/// insufficient output capacity.
pub fn encode_relay_service(
    service: RelayServiceRef<'_>,
    output: &mut [u8],
) -> Result<usize, CodecError> {
    let encoded_length = service.encoded_len()?;
    if output.len() < encoded_length {
        return Err(CodecError::OutputTooSmall {
            field: "relay service record",
            offset: 0,
            needed: encoded_length,
            remaining: output.len(),
        });
    }
    let lengths = relay_wire_lengths(service)?;
    let mut position = encode_relay_header_and_strings(service, encoded_length, lengths, output)?;
    position = encode_relay_addresses(service.addresses, output, position)?;
    encode_relay_pins(service.spki_pins, output, position)?;
    Ok(encoded_length)
}

fn relay_wire_lengths(service: RelayServiceRef<'_>) -> Result<RelayWireLengths, CodecError> {
    Ok(RelayWireLengths {
        address_count: u8::try_from(service.addresses.len()).map_err(|_| {
            CodecError::IntegerOverflow {
                field: "relay address count",
            }
        })?,
        pin_count: u8::try_from(service.spki_pins.len()).map_err(|_| {
            CodecError::IntegerOverflow {
                field: "relay SPKI pin count",
            }
        })?,
        hostname: u8::try_from(service.hostname.len()).map_err(|_| {
            CodecError::IntegerOverflow {
                field: "relay hostname length",
            }
        })?,
        tls_name: u8::try_from(service.tls_server_name.len()).map_err(|_| {
            CodecError::IntegerOverflow {
                field: "relay TLS server-name length",
            }
        })?,
        username: u8::try_from(service.credential_username.len()).map_err(|_| {
            CodecError::IntegerOverflow {
                field: "relay credential username length",
            }
        })?,
        secret: u8::try_from(service.credential_secret.len()).map_err(|_| {
            CodecError::IntegerOverflow {
                field: "relay credential secret length",
            }
        })?,
        region: u8::try_from(service.region.len()).map_err(|_| CodecError::IntegerOverflow {
            field: "relay region-label length",
        })?,
    })
}

fn encode_relay_header_and_strings(
    service: RelayServiceRef<'_>,
    encoded_length: usize,
    lengths: RelayWireLengths,
    output: &mut [u8],
) -> Result<usize, CodecError> {
    let mut cursor = WriteCursor::new(output, 0);
    cursor.write_u16(
        u16::try_from(encoded_length).map_err(|_| CodecError::IntegerOverflow {
            field: "relay service record length",
        })?,
        "relay service record length",
    )?;
    cursor.write_u8(lengths.address_count, "relay address count")?;
    cursor.write_u8(lengths.pin_count, "relay SPKI pin count")?;
    cursor.write_bytes(service.relay_id.as_bytes(), "relay ID")?;
    cursor.write_u16(service.carriers.bits(), "relay carrier mask")?;
    cursor.write_u16(service.priority, "relay service priority")?;
    cursor.write_u32(service.max_datagram_size, "relay maximum datagram size")?;
    cursor.write_u32(
        service.allocation_lifetime_seconds,
        "relay allocation lifetime",
    )?;
    cursor.write_u32(service.idle_timeout_seconds, "relay idle timeout")?;
    cursor.write_u64(service.credential_issued_at, "relay credential issue time")?;
    cursor.write_u64(
        service.credential_expires_at,
        "relay credential expiry time",
    )?;
    cursor.write_u8(lengths.hostname, "relay hostname length")?;
    cursor.write_u8(lengths.tls_name, "relay TLS name length")?;
    cursor.write_u8(lengths.username, "relay username length")?;
    cursor.write_u8(lengths.secret, "relay secret length")?;
    cursor.write_u8(lengths.region, "relay region length")?;
    cursor.write_u8(service.trust.bits(), "relay TLS trust")?;
    cursor.write_u16(0, "relay service reserved")?;
    cursor.write_u16(service.ports.turn_udp, "TURN UDP port")?;
    cursor.write_u16(service.ports.turn_tcp, "TURN TCP port")?;
    cursor.write_u16(service.ports.turn_tls, "TURN TLS port")?;
    cursor.write_u16(service.ports.secure_websocket, "relay WebSocket port")?;
    cursor.write_bytes(service.hostname.as_bytes(), "relay hostname")?;
    cursor.write_bytes(service.tls_server_name.as_bytes(), "relay TLS server name")?;
    cursor.write_bytes(service.credential_username, "relay credential username")?;
    cursor.write_bytes(service.credential_secret, "relay credential secret")?;
    cursor.write_bytes(service.region.as_bytes(), "relay region label")?;
    let string_length = service_strings_length(service)?;
    let padding_length = align_to_four(string_length)? - string_length;
    cursor.write_bytes(&[0; 3][..padding_length], "relay service string padding")?;
    Ok(cursor.position())
}

fn encode_relay_addresses(
    addresses: &[RelayAddress],
    output: &mut [u8],
    mut position: usize,
) -> Result<usize, CodecError> {
    for address in addresses {
        let end = position.checked_add(RELAY_ADDRESS_RECORD_LENGTH).ok_or(
            CodecError::IntegerOverflow {
                field: "relay address record end",
            },
        )?;
        let remaining = output.len().saturating_sub(position);
        let record = output
            .get_mut(position..end)
            .ok_or(CodecError::OutputTooSmall {
                field: "relay address record",
                offset: position,
                needed: RELAY_ADDRESS_RECORD_LENGTH,
                remaining,
            })?;
        encode_relay_address(*address, record, position)?;
        position = end;
    }
    Ok(position)
}

fn encode_relay_pins(
    pins: &[[u8; 32]],
    output: &mut [u8],
    mut position: usize,
) -> Result<usize, CodecError> {
    for pin in pins {
        let end = position
            .checked_add(32)
            .ok_or(CodecError::IntegerOverflow {
                field: "relay SPKI pin end",
            })?;
        let remaining = output.len().saturating_sub(position);
        let destination = output
            .get_mut(position..end)
            .ok_or(CodecError::OutputTooSmall {
                field: "relay SPKI pin",
                offset: position,
                needed: 32,
                remaining,
            })?;
        destination.copy_from_slice(pin);
        position = end;
    }
    Ok(position)
}

/// Borrowed validated priority-sorted relay service list.
#[derive(Clone)]
pub struct RelayServiceListView<'a> {
    count: u8,
    records: &'a [u8],
}

impl<'a> RelayServiceListView<'a> {
    /// Decodes one complete relay service list.
    ///
    /// # Errors
    ///
    /// Returns [`CodecError`] for invalid count, reserved bytes, service
    /// record, trailing bytes, duplicate, or non-canonical order.
    pub fn decode(input: &'a [u8]) -> Result<Self, CodecError> {
        let mut cursor = ReadCursor::new(input, 0);
        let count = cursor.read_u8("relay service count")?;
        validate_count(count, MAX_RELAY_SERVICES, "relay service count", 1)?;
        if cursor.read_array::<3>("relay service list reserved")? != [0; 3] {
            return Err(CodecError::NonZeroReserved {
                field: "relay service list reserved",
                offset: 1,
            });
        }
        let records = input.get(4..).ok_or(CodecError::Truncated {
            field: "relay service records",
            offset: input.len(),
            needed: 4_usize.saturating_sub(input.len()),
            remaining: 0,
        })?;
        let mut position = 0_usize;
        let mut previous = None;
        for index in 0..usize::from(count) {
            let input = records.get(position..).ok_or(CodecError::Truncated {
                field: "relay service record",
                offset: 4_usize.saturating_add(position),
                needed: 1,
                remaining: 0,
            })?;
            let (service, consumed) =
                RelayServiceView::decode_prefix(input, 4_usize.saturating_add(position))?;
            let key = (service.priority(), service.relay_id());
            if previous.is_some_and(|prior| prior >= key) {
                return Err(CodecError::NestedRecordsOutOfOrder {
                    context: "relay service list",
                    index,
                });
            }
            previous = Some(key);
            position = position
                .checked_add(consumed)
                .ok_or(CodecError::IntegerOverflow {
                    field: "relay service list position",
                })?;
        }
        validate_record_length(records.len(), position, "relay service records")?;
        Ok(Self { count, records })
    }

    /// Returns the number of relay services.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.count as usize
    }

    /// Returns `false`; a valid list always has one service.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        false
    }

    /// Iterates over validated relay services.
    #[must_use]
    pub const fn services(&self) -> RelayServiceIter<'a> {
        RelayServiceIter {
            records: self.records,
            position: 0,
            remaining: self.count,
        }
    }
}

/// Iterator over validated variable-size relay service records.
#[derive(Clone)]
pub struct RelayServiceIter<'a> {
    records: &'a [u8],
    position: usize,
    remaining: u8,
}

impl<'a> Iterator for RelayServiceIter<'a> {
    type Item = RelayServiceView<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.remaining == 0 {
            return None;
        }
        let input = self.records.get(self.position..)?;
        let (service, consumed) = RelayServiceView::decode_prefix(input, self.position).ok()?;
        self.position = self.position.checked_add(consumed)?;
        self.remaining -= 1;
        Some(service)
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        let remaining = usize::from(self.remaining);
        (remaining, Some(remaining))
    }
}

impl ExactSizeIterator for RelayServiceIter<'_> {}
impl std::iter::FusedIterator for RelayServiceIter<'_> {}

/// Encodes a priority-then-ID-sorted relay service list.
///
/// # Errors
///
/// Returns [`CodecError`] for invalid count, service, order, length arithmetic,
/// or insufficient output capacity.
pub fn encode_relay_service_list(
    services: &[RelayServiceRef<'_>],
    output: &mut [u8],
) -> Result<usize, CodecError> {
    let count = u8::try_from(services.len()).map_err(|_| CodecError::ValueOutOfRange {
        field: "relay service count",
        actual: u64::try_from(services.len()).unwrap_or(u64::MAX),
        minimum: 1,
        maximum: u64::from(MAX_RELAY_SERVICES),
    })?;
    validate_count(count, MAX_RELAY_SERVICES, "relay service count", 1)?;
    let mut encoded_length = 4_usize;
    let mut previous = None;
    for (index, service) in services.iter().copied().enumerate() {
        service.validate()?;
        let key = (service.priority, service.relay_id);
        if previous.is_some_and(|prior| prior >= key) {
            return Err(CodecError::NestedRecordsOutOfOrder {
                context: "relay service list",
                index,
            });
        }
        previous = Some(key);
        encoded_length = encoded_length.checked_add(service.encoded_len()?).ok_or(
            CodecError::IntegerOverflow {
                field: "relay service list length",
            },
        )?;
    }
    if output.len() < encoded_length {
        return Err(CodecError::OutputTooSmall {
            field: "relay service list",
            offset: 0,
            needed: encoded_length,
            remaining: output.len(),
        });
    }
    {
        let mut cursor = WriteCursor::new(output, 0);
        cursor.write_u8(count, "relay service count")?;
        cursor.write_bytes(&[0; 3], "relay service list reserved")?;
    }
    let mut position = 4_usize;
    for service in services {
        let length = service.encoded_len()?;
        let end = position
            .checked_add(length)
            .ok_or(CodecError::IntegerOverflow {
                field: "relay service record end",
            })?;
        let remaining = output.len().saturating_sub(position);
        let record = output
            .get_mut(position..end)
            .ok_or(CodecError::OutputTooSmall {
                field: "relay service record",
                offset: position,
                needed: length,
                remaining,
            })?;
        encode_relay_service(*service, record)?;
        position = end;
    }
    Ok(encoded_length)
}

fn validate_service_scalars(service: RelayServiceRef<'_>) -> Result<(), CodecError> {
    validate_service_identity_and_limits(service)?;
    validate_service_credentials(service)?;
    validate_service_delivery(service)?;
    let length = relay_service_encoded_len_unchecked(service)?;
    let _ = u16::try_from(length).map_err(|_| CodecError::ValueOutOfRange {
        field: "relay service record length",
        actual: u64::try_from(length).unwrap_or(u64::MAX),
        minimum: u64::try_from(RELAY_SERVICE_HEADER_LENGTH).unwrap_or(u64::MAX),
        maximum: u64::from(u16::MAX),
    })?;
    Ok(())
}

fn validate_service_identity_and_limits(service: RelayServiceRef<'_>) -> Result<(), CodecError> {
    if service.relay_id.is_zero() {
        return Err(CodecError::ZeroField { field: "relay ID" });
    }
    let _ = RelayCarrierMask::from_bits(service.carriers.bits())?;
    validate_bounded_u32(
        service.max_datagram_size,
        MIN_ENDPOINT_DATAGRAM_SIZE,
        MAX_ENDPOINT_DATAGRAM_SIZE,
        "relay maximum datagram size",
    )?;
    validate_bounded_u32(
        service.allocation_lifetime_seconds,
        60,
        3_600,
        "relay allocation lifetime",
    )?;
    validate_bounded_u32(
        service.idle_timeout_seconds,
        30,
        3_600,
        "relay idle timeout",
    )?;
    Ok(())
}

fn validate_service_credentials(service: RelayServiceRef<'_>) -> Result<(), CodecError> {
    if service.credential_issued_at >= service.credential_expires_at {
        return Err(CodecError::InvalidTimeRange {
            not_before: service.credential_issued_at,
            not_after: service.credential_expires_at,
        });
    }
    let lifetime = service.credential_expires_at - service.credential_issued_at;
    if lifetime > MAX_RELAY_CREDENTIAL_LIFETIME_SECONDS {
        return Err(CodecError::LifetimeTooLong {
            actual: lifetime,
            maximum: MAX_RELAY_CREDENTIAL_LIFETIME_SECONDS,
        });
    }
    validate_dns_name(service.hostname, "relay hostname", true)?;
    validate_dns_name(service.tls_server_name, "relay TLS server name", true)?;
    validate_graphic_ascii(
        service.credential_username,
        "relay credential username",
        1,
        MAX_RELAY_USERNAME_LENGTH,
        true,
    )?;
    validate_length(
        service.credential_secret.len(),
        MIN_RELAY_SECRET_LENGTH,
        MAX_RELAY_SECRET_LENGTH,
        "relay credential secret length",
    )?;
    validate_graphic_ascii(
        service.region.as_bytes(),
        "relay region label",
        0,
        MAX_RELAY_REGION_LENGTH,
        true,
    )?;
    Ok(())
}

fn validate_service_delivery(service: RelayServiceRef<'_>) -> Result<(), CodecError> {
    validate_count_usize(
        service.addresses.len(),
        usize::from(MAX_RELAY_ADDRESSES),
        "relay address count",
        0,
    )?;
    validate_count_usize(
        service.spki_pins.len(),
        usize::from(MAX_RELAY_SPKI_PINS),
        "relay SPKI pin count",
        0,
    )?;
    if service.addresses.is_empty() && service.hostname.is_empty() {
        return Err(CodecError::InvalidControlFieldCombination {
            message_type: 0x0060,
            detail: "relay service requires an address or hostname",
        });
    }
    validate_carrier_port(
        service.carriers,
        RelayCarrierMask::TURN_UDP,
        service.ports.turn_udp,
        "TURN UDP port",
    )?;
    validate_carrier_port(
        service.carriers,
        RelayCarrierMask::TURN_TCP,
        service.ports.turn_tcp,
        "TURN TCP port",
    )?;
    validate_carrier_port(
        service.carriers,
        RelayCarrierMask::TURN_TLS,
        service.ports.turn_tls,
        "TURN TLS port",
    )?;
    validate_carrier_port(
        service.carriers,
        RelayCarrierMask::SECURE_WEBSOCKET,
        service.ports.secure_websocket,
        "relay WebSocket port",
    )?;
    validate_trust(
        service.carriers,
        service.trust,
        service.tls_server_name,
        service.spki_pins.len(),
    )?;
    Ok(())
}

fn validate_decoded_service(service: &RelayServiceView<'_>) -> Result<(), CodecError> {
    let addresses = service.addresses().collect::<Vec<_>>();
    let pins = service.spki_pins().copied().collect::<Vec<_>>();
    RelayServiceRef {
        relay_id: service.relay_id,
        carriers: service.carriers,
        priority: service.priority,
        max_datagram_size: service.max_datagram_size,
        allocation_lifetime_seconds: service.allocation_lifetime_seconds,
        idle_timeout_seconds: service.idle_timeout_seconds,
        credential_issued_at: service.credential_issued_at,
        credential_expires_at: service.credential_expires_at,
        hostname: service.hostname,
        tls_server_name: service.tls_server_name,
        credential_username: service.credential_username,
        credential_secret: service.credential_secret,
        region: service.region,
        trust: service.trust,
        ports: service.ports,
        addresses: &addresses,
        spki_pins: &pins,
    }
    .validate()
}

fn validate_carrier_port(
    carriers: RelayCarrierMask,
    carrier: RelayCarrierMask,
    port: u16,
    field: &'static str,
) -> Result<(), CodecError> {
    if carriers.contains(carrier) != (port != 0) {
        return Err(CodecError::InconsistentField {
            context: "relay carrier mask and ports",
            field,
        });
    }
    Ok(())
}

fn validate_trust(
    carriers: RelayCarrierMask,
    trust: RelayTrustRequirements,
    tls_server_name: &str,
    pin_count: usize,
) -> Result<(), CodecError> {
    let _ = RelayTrustRequirements::from_bits(trust.bits())?;
    if carriers.requires_tls() == trust.is_empty() {
        return Err(CodecError::InconsistentField {
            context: "relay secure carriers and TLS trust",
            field: "trust requirements",
        });
    }
    if trust.contains(RelayTrustRequirements::WEB_PKI) && tls_server_name.is_empty() {
        return Err(CodecError::InconsistentField {
            context: "relay Web PKI trust",
            field: "TLS server name",
        });
    }
    if trust.contains(RelayTrustRequirements::SPKI_PIN) != (pin_count > 0) {
        return Err(CodecError::InconsistentField {
            context: "relay SPKI trust",
            field: "SPKI pin count",
        });
    }
    Ok(())
}

fn validate_relay_addresses(addresses: &[RelayAddress]) -> Result<(), CodecError> {
    let mut previous = None;
    for (index, address) in addresses.iter().copied().enumerate() {
        address.validate()?;
        if previous.is_some_and(|prior: RelayAddress| prior.sort_cmp(address) != Ordering::Less) {
            return Err(CodecError::NestedRecordsOutOfOrder {
                context: "relay address list",
                index,
            });
        }
        previous = Some(address);
    }
    Ok(())
}

fn validate_spki_pins(pins: &[[u8; 32]]) -> Result<(), CodecError> {
    for (index, pair) in pins.windows(2).enumerate() {
        if pair[0] >= pair[1] {
            return Err(CodecError::NestedRecordsOutOfOrder {
                context: "relay SPKI pin list",
                index: index + 1,
            });
        }
    }
    Ok(())
}

fn validate_relay_address_records(
    records: &[u8],
    count: u8,
    base_offset: usize,
) -> Result<(), CodecError> {
    let mut previous = None;
    for index in 0..usize::from(count) {
        let position =
            index
                .checked_mul(RELAY_ADDRESS_RECORD_LENGTH)
                .ok_or(CodecError::IntegerOverflow {
                    field: "relay address record offset",
                })?;
        let address = decode_relay_address_at(records, position, base_offset)?;
        if previous.is_some_and(|prior: RelayAddress| prior.sort_cmp(address) != Ordering::Less) {
            return Err(CodecError::NestedRecordsOutOfOrder {
                context: "relay address list",
                index,
            });
        }
        previous = Some(address);
    }
    Ok(())
}

fn validate_spki_pin_records(
    records: &[u8],
    count: u8,
    base_offset: usize,
) -> Result<(), CodecError> {
    let mut previous: Option<&[u8]> = None;
    for index in 0..usize::from(count) {
        let position = index.checked_mul(32).ok_or(CodecError::IntegerOverflow {
            field: "relay SPKI pin offset",
        })?;
        let pin =
            records
                .get(position..position.saturating_add(32))
                .ok_or(CodecError::Truncated {
                    field: "relay SPKI pin",
                    offset: base_offset.saturating_add(position),
                    needed: 32,
                    remaining: records.len().saturating_sub(position),
                })?;
        if previous.is_some_and(|prior| prior >= pin) {
            return Err(CodecError::NestedRecordsOutOfOrder {
                context: "relay SPKI pin list",
                index,
            });
        }
        previous = Some(pin);
    }
    Ok(())
}

fn validate_relay_ip(address: IpAddr) -> Result<(), CodecError> {
    let invalid = match address {
        IpAddr::V4(address) => {
            address.is_unspecified() || address.is_multicast() || address == Ipv4Addr::BROADCAST
        }
        IpAddr::V6(address) => {
            address.is_unspecified()
                || address.is_multicast()
                || address.is_unicast_link_local()
                || address.to_ipv4_mapped().is_some()
        }
    };
    if invalid {
        return Err(CodecError::InvalidEndpointAddress {
            family: "relay service",
        });
    }
    Ok(())
}

fn validate_dns_name(name: &str, field: &'static str, allow_empty: bool) -> Result<(), CodecError> {
    if name.is_empty() && allow_empty {
        return Ok(());
    }
    validate_length(name.len(), 1, MAX_RELAY_DNS_NAME_LENGTH, field)?;
    let mut offset = 0_usize;
    for label in name.split('.') {
        if label.is_empty() || label.len() > 63 {
            return Err(CodecError::InvalidTextCharacter { field, offset });
        }
        let bytes = label.as_bytes();
        for (index, byte) in bytes.iter().copied().enumerate() {
            let valid = byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-';
            if !valid || ((index == 0 || index + 1 == bytes.len()) && byte == b'-') {
                return Err(CodecError::InvalidTextCharacter {
                    field,
                    offset: offset + index,
                });
            }
        }
        offset = offset.saturating_add(label.len() + 1);
    }
    Ok(())
}

fn validate_graphic_ascii(
    bytes: &[u8],
    field: &'static str,
    minimum: usize,
    maximum: usize,
    allow_space: bool,
) -> Result<(), CodecError> {
    validate_length(bytes.len(), minimum, maximum, field)?;
    for (offset, byte) in bytes.iter().copied().enumerate() {
        let valid = if allow_space {
            (0x20..=0x7e).contains(&byte)
        } else {
            (0x21..=0x7e).contains(&byte)
        };
        if !valid {
            return Err(CodecError::InvalidTextCharacter { field, offset });
        }
    }
    Ok(())
}

fn validate_length(
    actual: usize,
    minimum: usize,
    maximum: usize,
    field: &'static str,
) -> Result<(), CodecError> {
    if !(minimum..=maximum).contains(&actual) {
        return Err(CodecError::ValueOutOfRange {
            field,
            actual: u64::try_from(actual).unwrap_or(u64::MAX),
            minimum: u64::try_from(minimum).unwrap_or(u64::MAX),
            maximum: u64::try_from(maximum).unwrap_or(u64::MAX),
        });
    }
    Ok(())
}

fn validate_count(
    actual: u8,
    maximum: u8,
    field: &'static str,
    minimum: u8,
) -> Result<(), CodecError> {
    if !(minimum..=maximum).contains(&actual) {
        return Err(CodecError::ValueOutOfRange {
            field,
            actual: u64::from(actual),
            minimum: u64::from(minimum),
            maximum: u64::from(maximum),
        });
    }
    Ok(())
}

fn validate_count_usize(
    actual: usize,
    maximum: usize,
    field: &'static str,
    minimum: usize,
) -> Result<(), CodecError> {
    validate_length(actual, minimum, maximum, field)
}

fn validate_bounded_u32(
    actual: u32,
    minimum: u32,
    maximum: u32,
    field: &'static str,
) -> Result<(), CodecError> {
    if !(minimum..=maximum).contains(&actual) {
        return Err(CodecError::ValueOutOfRange {
            field,
            actual: u64::from(actual),
            minimum: u64::from(minimum),
            maximum: u64::from(maximum),
        });
    }
    Ok(())
}

fn service_strings_length(service: RelayServiceRef<'_>) -> Result<usize, CodecError> {
    service
        .hostname
        .len()
        .checked_add(service.tls_server_name.len())
        .and_then(|value| value.checked_add(service.credential_username.len()))
        .and_then(|value| value.checked_add(service.credential_secret.len()))
        .and_then(|value| value.checked_add(service.region.len()))
        .ok_or(CodecError::IntegerOverflow {
            field: "relay service strings length",
        })
}

fn relay_service_encoded_len(service: RelayServiceRef<'_>) -> Result<usize, CodecError> {
    service.validate()?;
    relay_service_encoded_len_unchecked(service)
}

fn relay_service_encoded_len_unchecked(service: RelayServiceRef<'_>) -> Result<usize, CodecError> {
    let address_length = service
        .addresses
        .len()
        .checked_mul(RELAY_ADDRESS_RECORD_LENGTH)
        .ok_or(CodecError::IntegerOverflow {
            field: "relay address records length",
        })?;
    let pin_length =
        service
            .spki_pins
            .len()
            .checked_mul(32)
            .ok_or(CodecError::IntegerOverflow {
                field: "relay SPKI pin records length",
            })?;
    RELAY_SERVICE_HEADER_LENGTH
        .checked_add(align_to_four(service_strings_length(service)?)?)
        .and_then(|value| value.checked_add(address_length))
        .and_then(|value| value.checked_add(pin_length))
        .ok_or(CodecError::IntegerOverflow {
            field: "relay service record length",
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

fn decode_text<'a>(bytes: &'a [u8], field: &'static str) -> Result<&'a str, CodecError> {
    std::str::from_utf8(bytes).map_err(|error| CodecError::InvalidUtf8 {
        field,
        offset: error.valid_up_to(),
    })
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

fn decode_ip_slot(family: u8, slot: [u8; 16]) -> Result<IpAddr, CodecError> {
    match family {
        4 => {
            if slot[4..].iter().any(|byte| *byte != 0) {
                return Err(CodecError::InvalidEndpointAddress {
                    family: "relay IPv4",
                });
            }
            Ok(IpAddr::V4(Ipv4Addr::new(
                slot[0], slot[1], slot[2], slot[3],
            )))
        }
        6 => {
            let address = Ipv6Addr::from(slot);
            if address.to_ipv4_mapped().is_some() {
                return Err(CodecError::InvalidEndpointAddress {
                    family: "relay IPv6",
                });
            }
            Ok(IpAddr::V6(address))
        }
        value => Err(CodecError::InvalidEnumValue {
            field: "relay address family",
            value: u64::from(value),
        }),
    }
}

fn encode_relay_address(
    address: RelayAddress,
    output: &mut [u8],
    base_offset: usize,
) -> Result<(), CodecError> {
    address.validate()?;
    let (family, slot) = encode_ip_slot(address.address);
    let mut cursor = WriteCursor::new(output, base_offset);
    cursor.write_u8(family, "relay address family")?;
    cursor.write_u8(address.priority, "relay address priority")?;
    cursor.write_u16(0, "relay address reserved")?;
    cursor.write_bytes(&slot, "relay address")?;
    Ok(())
}

fn decode_relay_address_at(
    records: &[u8],
    position: usize,
    base_offset: usize,
) -> Result<RelayAddress, CodecError> {
    let end =
        position
            .checked_add(RELAY_ADDRESS_RECORD_LENGTH)
            .ok_or(CodecError::IntegerOverflow {
                field: "relay address record end",
            })?;
    let record = records.get(position..end).ok_or(CodecError::Truncated {
        field: "relay address record",
        offset: base_offset.saturating_add(position),
        needed: RELAY_ADDRESS_RECORD_LENGTH,
        remaining: records.len().saturating_sub(position),
    })?;
    let mut cursor = ReadCursor::new(record, base_offset.saturating_add(position));
    let family = cursor.read_u8("relay address family")?;
    let priority = cursor.read_u8("relay address priority")?;
    let reserved_offset = base_offset
        .saturating_add(position)
        .saturating_add(cursor.position());
    if cursor.read_u16("relay address reserved")? != 0 {
        return Err(CodecError::NonZeroReserved {
            field: "relay address reserved",
            offset: reserved_offset,
        });
    }
    let slot = cursor.read_array("relay address")?;
    let address = RelayAddress {
        priority,
        address: decode_ip_slot(family, slot)?,
    };
    address.validate()?;
    Ok(address)
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    use stella_common::RelayId;

    use super::{
        encode_relay_service, encode_relay_service_list, service_strings_length, CodecError,
        RelayAddress, RelayCarrierMask, RelayPorts, RelayServiceListView, RelayServiceRef,
        RelayServiceView, RelayTrustRequirements, MAX_RELAY_CREDENTIAL_LIFETIME_SECONDS,
        MIN_RELAY_SECRET_LENGTH, RELAY_SERVICE_HEADER_LENGTH,
    };

    const USERNAME: &[u8] = b"node 0123456789abcdef";
    const SECRET: &[u8] = b"0123456789abcdef0123456789abcdef";

    fn carriers() -> RelayCarrierMask {
        RelayCarrierMask::from_bits(
            RelayCarrierMask::TURN_UDP.bits()
                | RelayCarrierMask::TURN_TLS.bits()
                | RelayCarrierMask::SECURE_WEBSOCKET.bits(),
        )
        .expect("test carriers are registered")
    }

    fn trust() -> RelayTrustRequirements {
        RelayTrustRequirements::from_bits(
            RelayTrustRequirements::WEB_PKI.bits() | RelayTrustRequirements::SPKI_PIN.bits(),
        )
        .expect("test trust requirements are registered")
    }

    fn service<'a>(
        relay_id: u8,
        priority: u16,
        addresses: &'a [RelayAddress],
        pins: &'a [[u8; 32]],
    ) -> RelayServiceRef<'a> {
        RelayServiceRef {
            relay_id: RelayId::from_bytes([relay_id; 16]),
            carriers: carriers(),
            priority,
            max_datagram_size: 1_200,
            allocation_lifetime_seconds: 600,
            idle_timeout_seconds: 120,
            credential_issued_at: 1_000,
            credential_expires_at: 1_600,
            hostname: "relay.example.com",
            tls_server_name: "relay.example.com",
            credential_username: USERNAME,
            credential_secret: SECRET,
            region: "test region",
            trust: trust(),
            ports: RelayPorts {
                turn_udp: 3_478,
                turn_tcp: 0,
                turn_tls: 443,
                secure_websocket: 443,
            },
            addresses,
            spki_pins: pins,
        }
    }

    fn addresses() -> [RelayAddress; 2] {
        [
            RelayAddress {
                priority: 0,
                address: IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10)),
            },
            RelayAddress {
                priority: 1,
                address: IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 10)),
            },
        ]
    }

    #[test]
    fn relay_service_round_trips_and_redacts_credentials() {
        let addresses = addresses();
        let pins = [[1; 32], [2; 32]];
        let service = service(1, 10, &addresses, &pins);
        let mut encoded = vec![0; service.encoded_len().expect("service length")];

        assert_eq!(
            encode_relay_service(service, &mut encoded),
            Ok(encoded.len())
        );
        let decoded = RelayServiceView::decode(&encoded).expect("decode relay service");
        assert_eq!(decoded.relay_id(), service.relay_id);
        assert_eq!(decoded.carriers(), service.carriers);
        assert_eq!(decoded.priority(), service.priority);
        assert_eq!(decoded.max_datagram_size(), service.max_datagram_size);
        assert_eq!(
            decoded.allocation_lifetime_seconds(),
            service.allocation_lifetime_seconds
        );
        assert_eq!(decoded.idle_timeout_seconds(), service.idle_timeout_seconds);
        assert_eq!(decoded.credential_issued_at(), service.credential_issued_at);
        assert_eq!(
            decoded.credential_expires_at(),
            service.credential_expires_at
        );
        assert_eq!(decoded.hostname(), service.hostname);
        assert_eq!(decoded.tls_server_name(), service.tls_server_name);
        assert_eq!(decoded.credential_username(), USERNAME);
        assert_eq!(decoded.credential_secret(), SECRET);
        assert_eq!(decoded.region(), service.region);
        assert_eq!(decoded.trust(), service.trust);
        assert_eq!(decoded.ports(), service.ports);
        assert_eq!(decoded.addresses().collect::<Vec<_>>(), addresses);
        assert_eq!(
            decoded.spki_pins().copied().collect::<Vec<_>>(),
            pins.to_vec()
        );
        assert_eq!(decoded.encoded_len(), encoded.len());

        let encoded_debug = format!("{service:?}");
        let decoded_debug = format!("{decoded:?}");
        let username = std::str::from_utf8(USERNAME).expect("test username is UTF-8");
        let secret = std::str::from_utf8(SECRET).expect("test secret is UTF-8");
        assert!(!encoded_debug.contains(username));
        assert!(!encoded_debug.contains(secret));
        assert!(!decoded_debug.contains(username));
        assert!(!decoded_debug.contains(secret));
    }

    #[test]
    fn relay_service_list_round_trips_in_priority_then_id_order() {
        let addresses = addresses();
        let pins = [[1; 32], [2; 32]];
        let first = service(1, 10, &addresses, &pins);
        let second = service(2, 10, &addresses, &pins);
        let services = [first, second];
        let length = 4 + services
            .iter()
            .map(|service| service.encoded_len().expect("service length"))
            .sum::<usize>();
        let mut encoded = vec![0; length];

        assert_eq!(
            encode_relay_service_list(&services, &mut encoded),
            Ok(length)
        );
        let decoded = RelayServiceListView::decode(&encoded).expect("decode relay list");
        assert_eq!(decoded.len(), 2);
        assert!(!decoded.is_empty());
        assert_eq!(
            decoded
                .services()
                .map(|service| service.relay_id())
                .collect::<Vec<_>>(),
            vec![first.relay_id, second.relay_id]
        );

        assert!(matches!(
            encode_relay_service_list(&[second, first], &mut encoded),
            Err(CodecError::NestedRecordsOutOfOrder {
                context: "relay service list",
                index: 1,
            })
        ));
    }

    #[test]
    fn relay_service_requires_consistent_carriers_ports_and_tls_trust() {
        let addresses = addresses();
        let pins = [[1; 32], [2; 32]];

        let mut missing_port = service(1, 10, &addresses, &pins);
        missing_port.ports.turn_tls = 0;
        assert!(matches!(
            missing_port.validate(),
            Err(CodecError::InconsistentField {
                context: "relay carrier mask and ports",
                field: "TURN TLS port",
            })
        ));

        let mut missing_trust = service(1, 10, &addresses, &pins);
        missing_trust.trust = RelayTrustRequirements::NONE;
        assert!(matches!(
            missing_trust.validate(),
            Err(CodecError::InconsistentField {
                context: "relay secure carriers and TLS trust",
                field: "trust requirements",
            })
        ));

        let mut missing_name = service(1, 10, &addresses, &pins);
        missing_name.tls_server_name = "";
        assert!(matches!(
            missing_name.validate(),
            Err(CodecError::InconsistentField {
                context: "relay Web PKI trust",
                field: "TLS server name",
            })
        ));

        let mut missing_pin = service(1, 10, &addresses, &[]);
        missing_pin.trust = trust();
        assert!(matches!(
            missing_pin.validate(),
            Err(CodecError::InconsistentField {
                context: "relay SPKI trust",
                field: "SPKI pin count",
            })
        ));
    }

    #[test]
    fn relay_service_rejects_invalid_credentials_and_ordering() {
        let addresses = addresses();
        let pins = [[1; 32], [2; 32]];

        let mut expired = service(1, 10, &addresses, &pins);
        expired.credential_expires_at = expired.credential_issued_at;
        assert!(matches!(
            expired.validate(),
            Err(CodecError::InvalidTimeRange { .. })
        ));

        let mut too_long = service(1, 10, &addresses, &pins);
        too_long.credential_expires_at =
            too_long.credential_issued_at + MAX_RELAY_CREDENTIAL_LIFETIME_SECONDS + 1;
        assert!(matches!(
            too_long.validate(),
            Err(CodecError::LifetimeTooLong { .. })
        ));

        let short_secret = [0; MIN_RELAY_SECRET_LENGTH - 1];
        let mut invalid_secret = service(1, 10, &addresses, &pins);
        invalid_secret.credential_secret = &short_secret;
        assert!(matches!(
            invalid_secret.validate(),
            Err(CodecError::ValueOutOfRange {
                field: "relay credential secret length",
                ..
            })
        ));

        let reversed_addresses = [addresses[1], addresses[0]];
        let invalid_addresses = service(1, 10, &reversed_addresses, &pins);
        assert!(matches!(
            invalid_addresses.validate(),
            Err(CodecError::NestedRecordsOutOfOrder {
                context: "relay address list",
                index: 1,
            })
        ));

        let reversed_pins = [pins[1], pins[0]];
        let invalid_pins = service(1, 10, &addresses, &reversed_pins);
        assert!(matches!(
            invalid_pins.validate(),
            Err(CodecError::NestedRecordsOutOfOrder {
                context: "relay SPKI pin list",
                index: 1,
            })
        ));
    }

    #[test]
    fn relay_service_decode_rejects_padding_reserved_and_trailing_bytes() {
        let addresses = addresses();
        let pins = [[1; 32], [2; 32]];
        let service = service(1, 10, &addresses, &pins);
        let mut encoded = vec![0; service.encoded_len().expect("service length")];
        encode_relay_service(service, &mut encoded).expect("encode relay service");

        let padding_offset =
            RELAY_SERVICE_HEADER_LENGTH + service_strings_length(service).expect("string length");
        let mut invalid_padding = encoded.clone();
        invalid_padding[padding_offset] = 1;
        assert!(matches!(
            RelayServiceView::decode(&invalid_padding),
            Err(CodecError::NonZeroReserved {
                field: "relay service string padding",
                ..
            })
        ));

        let mut invalid_reserved = encoded.clone();
        invalid_reserved[58] = 1;
        assert!(matches!(
            RelayServiceView::decode(&invalid_reserved),
            Err(CodecError::NonZeroReserved {
                field: "relay service reserved",
                offset: 58,
            })
        ));

        encoded.push(0);
        assert!(matches!(
            RelayServiceView::decode(&encoded),
            Err(CodecError::TrailingBytes { .. })
        ));
    }
}
