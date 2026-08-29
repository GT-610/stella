//! Nested control-field value codecs.

use std::{
    cmp::Ordering,
    net::{Ipv4Addr, Ipv6Addr},
};

use stella_common::NetworkId;

use crate::{
    common::validate_record_length,
    cursor::{ReadCursor, WriteCursor},
    CodecError,
};

/// Maximum entries in a supported-version list.
pub const MAX_SUPPORTED_VERSIONS: u8 = 32;

/// Maximum numeric endpoints published by one node in one network.
pub const MAX_ENDPOINTS: u8 = 8;

/// Minimum receivable Stella datagram advertised by an endpoint.
pub const MIN_ENDPOINT_DATAGRAM_SIZE: u32 = 1_200;

/// Largest UDP payload accepted as a Stella datagram.
pub const MAX_ENDPOINT_DATAGRAM_SIZE: u32 = 65_507;

/// Maximum entries in a version 0.1 network-revision list.
pub const MAX_NETWORK_REVISIONS: u16 = 256;

const VERSION_ENTRY_LENGTH: usize = 4;
const IPV4_ENDPOINT_LENGTH: usize = 16;
const IPV6_ENDPOINT_LENGTH: usize = 28;
const NETWORK_REVISION_ENTRY_LENGTH: usize = 32;

/// One protocol version and cryptographic suite advertisement.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct VersionEntry {
    /// Protocol major version.
    pub major: u8,
    /// Protocol minor version.
    pub minor: u8,
    /// Cryptographic suite registry value.
    pub suite_id: u16,
}

impl VersionEntry {
    /// Version 0.1 with its mandatory suite.
    pub const V0_1_SUITE_1: Self = Self {
        major: 0,
        minor: 1,
        suite_id: 1,
    };

    /// Decodes exactly one four-byte version entry.
    ///
    /// # Errors
    ///
    /// Returns [`CodecError`] when `input` is not exactly four bytes.
    pub fn decode(input: &[u8]) -> Result<Self, CodecError> {
        validate_record_length(input.len(), VERSION_ENTRY_LENGTH, "version entry")?;
        let mut cursor = ReadCursor::new(input, 0);
        Ok(Self {
            major: cursor.read_u8("version major")?,
            minor: cursor.read_u8("version minor")?,
            suite_id: cursor.read_u16("suite ID")?,
        })
    }

    /// Encodes one version entry into the first four bytes of `output`.
    ///
    /// # Errors
    ///
    /// Returns [`CodecError`] when `output` is too small.
    pub fn encode(self, output: &mut [u8]) -> Result<(), CodecError> {
        let mut cursor = WriteCursor::new(output, 0);
        cursor.write_u8(self.major, "version major")?;
        cursor.write_u8(self.minor, "version minor")?;
        cursor.write_u16(self.suite_id, "suite ID")?;
        Ok(())
    }
}

/// Borrowed validated supported-version list.
#[derive(Clone)]
pub struct VersionListView<'a> {
    count: u8,
    entries: &'a [u8],
}

impl<'a> VersionListView<'a> {
    /// Decodes a complete ordered-preference version list.
    ///
    /// # Errors
    ///
    /// Returns [`CodecError`] when the count, reserved bytes, total length, or
    /// uniqueness requirement is invalid.
    pub fn decode(input: &'a [u8]) -> Result<Self, CodecError> {
        let mut cursor = ReadCursor::new(input, 0);
        let count = cursor.read_u8("version count")?;
        if !(1..=MAX_SUPPORTED_VERSIONS).contains(&count) {
            return Err(CodecError::ValueOutOfRange {
                field: "version count",
                actual: u64::from(count),
                minimum: 1,
                maximum: u64::from(MAX_SUPPORTED_VERSIONS),
            });
        }
        let reserved = cursor.read_array::<3>("version list reserved")?;
        if reserved != [0; 3] {
            return Err(CodecError::NonZeroReserved {
                field: "version list reserved",
                offset: 1,
            });
        }
        let entries_length = usize::from(count).checked_mul(VERSION_ENTRY_LENGTH).ok_or(
            CodecError::IntegerOverflow {
                field: "version list length",
            },
        )?;
        let expected_length =
            4_usize
                .checked_add(entries_length)
                .ok_or(CodecError::IntegerOverflow {
                    field: "version list length",
                })?;
        validate_record_length(input.len(), expected_length, "version list")?;
        let entries = cursor.read_slice(entries_length, "version entries")?;

        for current_index in 0..usize::from(count) {
            let current = version_entry_at(entries, current_index)?;
            for previous_index in 0..current_index {
                if current == version_entry_at(entries, previous_index)? {
                    return Err(CodecError::DuplicateNestedEntry {
                        context: "version list",
                        index: current_index,
                    });
                }
            }
        }
        Ok(Self { count, entries })
    }

    /// Returns the number of advertised entries.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.count as usize
    }

    /// Returns `false`; a valid version list always contains at least one entry.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        false
    }

    /// Iterates from most to least preferred entry.
    #[must_use]
    pub const fn entries(&self) -> VersionIter<'a> {
        VersionIter {
            entries: self.entries,
            position: 0,
        }
    }
}

/// Iterator over validated version entries.
#[derive(Clone)]
pub struct VersionIter<'a> {
    entries: &'a [u8],
    position: usize,
}

impl Iterator for VersionIter<'_> {
    type Item = VersionEntry;

    fn next(&mut self) -> Option<Self::Item> {
        let end = self.position.checked_add(VERSION_ENTRY_LENGTH)?;
        let bytes = self.entries.get(self.position..end)?;
        self.position = end;
        VersionEntry::decode(bytes).ok()
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        let count = self.entries.len().saturating_sub(self.position) / VERSION_ENTRY_LENGTH;
        (count, Some(count))
    }
}

impl ExactSizeIterator for VersionIter<'_> {}
impl std::iter::FusedIterator for VersionIter<'_> {}

/// Encodes a unique, preference-ordered supported-version list.
///
/// # Errors
///
/// Returns [`CodecError`] when the count is outside 1 through 32, an entry is
/// duplicated, arithmetic overflows, or `output` is too small.
pub fn encode_version_list(
    entries: &[VersionEntry],
    output: &mut [u8],
) -> Result<usize, CodecError> {
    let count = u8::try_from(entries.len()).map_err(|_| CodecError::ValueOutOfRange {
        field: "version count",
        actual: u64::try_from(entries.len()).unwrap_or(u64::MAX),
        minimum: 1,
        maximum: u64::from(MAX_SUPPORTED_VERSIONS),
    })?;
    if !(1..=MAX_SUPPORTED_VERSIONS).contains(&count) {
        return Err(CodecError::ValueOutOfRange {
            field: "version count",
            actual: u64::from(count),
            minimum: 1,
            maximum: u64::from(MAX_SUPPORTED_VERSIONS),
        });
    }
    for (current_index, current) in entries.iter().enumerate() {
        if entries[..current_index].contains(current) {
            return Err(CodecError::DuplicateNestedEntry {
                context: "version list",
                index: current_index,
            });
        }
    }
    let entries_length =
        entries
            .len()
            .checked_mul(VERSION_ENTRY_LENGTH)
            .ok_or(CodecError::IntegerOverflow {
                field: "version list length",
            })?;
    let encoded_length =
        4_usize
            .checked_add(entries_length)
            .ok_or(CodecError::IntegerOverflow {
                field: "version list length",
            })?;
    if output.len() < encoded_length {
        return Err(CodecError::OutputTooSmall {
            field: "version list",
            offset: 0,
            needed: encoded_length,
            remaining: output.len(),
        });
    }
    let mut cursor = WriteCursor::new(output, 0);
    cursor.write_u8(count, "version count")?;
    cursor.write_bytes(&[0; 3], "version list reserved")?;
    for entry in entries {
        cursor.write_u8(entry.major, "version major")?;
        cursor.write_u8(entry.minor, "version minor")?;
        cursor.write_u16(entry.suite_id, "suite ID")?;
    }
    Ok(cursor.position())
}

/// Numeric UDP endpoint published through the control plane.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Endpoint {
    /// UDP over IPv4.
    UdpIpv4 {
        /// Lower values are attempted first.
        priority: u8,
        /// Non-zero UDP port.
        port: u16,
        /// Maximum receivable Stella datagram.
        max_datagram_size: u32,
        /// Unicast numeric IPv4 address.
        address: Ipv4Addr,
    },
    /// UDP over IPv6.
    UdpIpv6 {
        /// Lower values are attempted first.
        priority: u8,
        /// Non-zero UDP port.
        port: u16,
        /// Maximum receivable Stella datagram.
        max_datagram_size: u32,
        /// Unicast numeric IPv6 address.
        address: Ipv6Addr,
    },
}

impl Endpoint {
    /// Returns the endpoint priority.
    #[must_use]
    pub const fn priority(self) -> u8 {
        match self {
            Self::UdpIpv4 { priority, .. } | Self::UdpIpv6 { priority, .. } => priority,
        }
    }

    /// Returns the registered endpoint kind byte.
    #[must_use]
    pub const fn kind(self) -> u8 {
        match self {
            Self::UdpIpv4 { .. } => 1,
            Self::UdpIpv6 { .. } => 2,
        }
    }

    /// Returns the UDP port.
    #[must_use]
    pub const fn port(self) -> u16 {
        match self {
            Self::UdpIpv4 { port, .. } | Self::UdpIpv6 { port, .. } => port,
        }
    }

    /// Returns the advertised receive datagram limit.
    #[must_use]
    pub const fn max_datagram_size(self) -> u32 {
        match self {
            Self::UdpIpv4 {
                max_datagram_size, ..
            }
            | Self::UdpIpv6 {
                max_datagram_size, ..
            } => max_datagram_size,
        }
    }

    /// Returns whether the numeric address is loopback.
    #[must_use]
    pub const fn is_loopback(self) -> bool {
        match self {
            Self::UdpIpv4 { address, .. } => address.is_loopback(),
            Self::UdpIpv6 { address, .. } => address.is_loopback(),
        }
    }

    /// Returns the self-sized record length.
    #[must_use]
    pub const fn encoded_len(self) -> usize {
        match self {
            Self::UdpIpv4 { .. } => IPV4_ENDPOINT_LENGTH,
            Self::UdpIpv6 { .. } => IPV6_ENDPOINT_LENGTH,
        }
    }

    /// Validates transport-independent endpoint invariants.
    ///
    /// Loopback is structurally valid; the caller permits it only for an
    /// explicitly configured local test network.
    ///
    /// # Errors
    ///
    /// Returns [`CodecError`] for port zero, a datagram limit outside 1,200
    /// through 65,507, an unspecified/multicast/broadcast address, or an
    /// IPv4-mapped IPv6 address.
    pub fn validate(self) -> Result<(), CodecError> {
        if self.port() == 0 {
            return Err(CodecError::ZeroField {
                field: "endpoint UDP port",
            });
        }
        let datagram = self.max_datagram_size();
        if !(MIN_ENDPOINT_DATAGRAM_SIZE..=MAX_ENDPOINT_DATAGRAM_SIZE).contains(&datagram) {
            return Err(CodecError::ValueOutOfRange {
                field: "endpoint maximum datagram size",
                actual: u64::from(datagram),
                minimum: u64::from(MIN_ENDPOINT_DATAGRAM_SIZE),
                maximum: u64::from(MAX_ENDPOINT_DATAGRAM_SIZE),
            });
        }
        match self {
            Self::UdpIpv4 { address, .. } => {
                if address.is_unspecified()
                    || address.is_multicast()
                    || address == Ipv4Addr::BROADCAST
                {
                    return Err(CodecError::InvalidEndpointAddress { family: "IPv4" });
                }
            }
            Self::UdpIpv6 { address, .. } => {
                if address.is_unspecified()
                    || address.is_multicast()
                    || address.to_ipv4_mapped().is_some()
                {
                    return Err(CodecError::InvalidEndpointAddress { family: "IPv6" });
                }
            }
        }
        Ok(())
    }

    fn sort_cmp(self, other: Self) -> Ordering {
        self.priority()
            .cmp(&other.priority())
            .then_with(|| self.kind().cmp(&other.kind()))
            .then_with(|| endpoint_address_bytes(self).cmp(&endpoint_address_bytes(other)))
            .then_with(|| self.port().cmp(&other.port()))
    }
}

/// Borrowed validated endpoint set.
#[derive(Clone)]
pub struct EndpointSetView<'a> {
    count: u8,
    records: &'a [u8],
}

impl<'a> EndpointSetView<'a> {
    /// Decodes a complete canonical endpoint set.
    ///
    /// # Errors
    ///
    /// Returns [`CodecError`] for an excessive count, non-zero reserved byte,
    /// malformed record, unusable address, incorrect total length, duplicate,
    /// or non-canonical order.
    pub fn decode(input: &'a [u8]) -> Result<Self, CodecError> {
        let mut cursor = ReadCursor::new(input, 0);
        let count = cursor.read_u8("endpoint count")?;
        if count > MAX_ENDPOINTS {
            return Err(CodecError::ValueOutOfRange {
                field: "endpoint count",
                actual: u64::from(count),
                minimum: 0,
                maximum: u64::from(MAX_ENDPOINTS),
            });
        }
        if cursor.read_array::<3>("endpoint set reserved")? != [0; 3] {
            return Err(CodecError::NonZeroReserved {
                field: "endpoint set reserved",
                offset: 1,
            });
        }
        let records = input.get(4..).ok_or(CodecError::Truncated {
            field: "endpoint records",
            offset: input.len(),
            needed: 4_usize.saturating_sub(input.len()),
            remaining: 0,
        })?;
        validate_endpoint_records(records, count, 4)?;
        Ok(Self { count, records })
    }

    /// Returns the endpoint count.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.count as usize
    }

    /// Returns whether no endpoints are published.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.count == 0
    }

    /// Iterates over validated endpoint values.
    #[must_use]
    pub const fn endpoints(&self) -> EndpointIter<'a> {
        EndpointIter::new(self.records, self.count)
    }
}

/// Iterator over validated endpoints.
#[derive(Clone)]
pub struct EndpointIter<'a> {
    records: &'a [u8],
    position: usize,
    remaining: u8,
}

impl<'a> EndpointIter<'a> {
    pub(crate) const fn new(records: &'a [u8], count: u8) -> Self {
        Self {
            records,
            position: 0,
            remaining: count,
        }
    }
}

impl Iterator for EndpointIter<'_> {
    type Item = Endpoint;

    fn next(&mut self) -> Option<Self::Item> {
        if self.remaining == 0 {
            return None;
        }
        let (endpoint, length) = decode_endpoint_record(self.records, self.position, 0).ok()?;
        self.position = self.position.checked_add(length)?;
        self.remaining -= 1;
        Some(endpoint)
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        let remaining = usize::from(self.remaining);
        (remaining, Some(remaining))
    }
}

impl ExactSizeIterator for EndpointIter<'_> {}
impl std::iter::FusedIterator for EndpointIter<'_> {}

/// Encodes a canonical endpoint set.
///
/// # Errors
///
/// Returns [`CodecError`] for an invalid count, endpoint, duplicate/order
/// violation, arithmetic overflow, or insufficient output capacity.
pub fn encode_endpoint_set(endpoints: &[Endpoint], output: &mut [u8]) -> Result<usize, CodecError> {
    let count = u8::try_from(endpoints.len()).map_err(|_| CodecError::ValueOutOfRange {
        field: "endpoint count",
        actual: u64::try_from(endpoints.len()).unwrap_or(u64::MAX),
        minimum: 0,
        maximum: u64::from(MAX_ENDPOINTS),
    })?;
    if count > MAX_ENDPOINTS {
        return Err(CodecError::ValueOutOfRange {
            field: "endpoint count",
            actual: u64::from(count),
            minimum: 0,
            maximum: u64::from(MAX_ENDPOINTS),
        });
    }
    let records_length = endpoint_records_encoded_len(endpoints)?;
    let encoded_length =
        4_usize
            .checked_add(records_length)
            .ok_or(CodecError::IntegerOverflow {
                field: "endpoint set length",
            })?;
    if output.len() < encoded_length {
        return Err(CodecError::OutputTooSmall {
            field: "endpoint set",
            offset: 0,
            needed: encoded_length,
            remaining: output.len(),
        });
    }
    {
        let mut cursor = WriteCursor::new(output, 0);
        cursor.write_u8(count, "endpoint count")?;
        cursor.write_bytes(&[0; 3], "endpoint set reserved")?;
    }
    let output_length = output.len();
    let records_output = output
        .get_mut(4..encoded_length)
        .ok_or(CodecError::OutputTooSmall {
            field: "endpoint records",
            offset: 4,
            needed: records_length,
            remaining: output_length.saturating_sub(4),
        })?;
    encode_endpoint_records_at(endpoints, records_output, 4)?;
    Ok(encoded_length)
}

/// One network's accepted epoch and snapshot revision.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NetworkRevision {
    /// Non-zero virtual network identifier.
    pub network_id: NetworkId,
    /// Non-zero accepted controller epoch.
    pub controller_epoch: u64,
    /// Non-zero last accepted snapshot revision.
    pub snapshot_revision: u64,
}

impl NetworkRevision {
    /// Validates non-zero revision fields.
    ///
    /// # Errors
    ///
    /// Returns [`CodecError::ZeroField`] when the network, epoch, or revision
    /// is zero.
    pub fn validate(self) -> Result<(), CodecError> {
        if self.network_id.is_zero() {
            return Err(CodecError::ZeroField {
                field: "network ID",
            });
        }
        if self.controller_epoch == 0 {
            return Err(CodecError::ZeroField {
                field: "controller epoch",
            });
        }
        if self.snapshot_revision == 0 {
            return Err(CodecError::ZeroField {
                field: "snapshot revision",
            });
        }
        Ok(())
    }
}

/// Borrowed validated network-revision list.
#[derive(Clone)]
pub struct NetworkRevisionListView<'a> {
    count: u16,
    entries: &'a [u8],
}

impl<'a> NetworkRevisionListView<'a> {
    /// Decodes one canonical network-revision list.
    ///
    /// # Errors
    ///
    /// Returns [`CodecError`] for an excessive count, reserved bytes, length
    /// mismatch, zero field, or non-increasing network ID order.
    pub fn decode(input: &'a [u8]) -> Result<Self, CodecError> {
        let mut cursor = ReadCursor::new(input, 0);
        let count = cursor.read_u16("network revision count")?;
        if count > MAX_NETWORK_REVISIONS {
            return Err(CodecError::ValueOutOfRange {
                field: "network revision count",
                actual: u64::from(count),
                minimum: 0,
                maximum: u64::from(MAX_NETWORK_REVISIONS),
            });
        }
        let reserved_offset = cursor.position();
        if cursor.read_u16("network revision reserved")? != 0 {
            return Err(CodecError::NonZeroReserved {
                field: "network revision reserved",
                offset: reserved_offset,
            });
        }
        let entries_length = usize::from(count)
            .checked_mul(NETWORK_REVISION_ENTRY_LENGTH)
            .ok_or(CodecError::IntegerOverflow {
                field: "network revision list length",
            })?;
        let expected_length =
            4_usize
                .checked_add(entries_length)
                .ok_or(CodecError::IntegerOverflow {
                    field: "network revision list length",
                })?;
        validate_record_length(input.len(), expected_length, "network revision list")?;
        let entries = cursor.read_slice(entries_length, "network revision entries")?;
        let mut previous = None;
        for index in 0..usize::from(count) {
            let revision = network_revision_at(entries, index)?;
            revision.validate()?;
            if let Some(previous_id) = previous {
                if previous_id >= revision.network_id {
                    return Err(CodecError::NestedRecordsOutOfOrder {
                        context: "network revision list",
                        index,
                    });
                }
            }
            previous = Some(revision.network_id);
        }
        Ok(Self { count, entries })
    }

    /// Returns the number of per-network entries.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.count as usize
    }

    /// Returns whether the list has no active network entries.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.count == 0
    }

    /// Iterates over validated revision values.
    #[must_use]
    pub const fn revisions(&self) -> NetworkRevisionIter<'a> {
        NetworkRevisionIter {
            entries: self.entries,
            position: 0,
        }
    }
}

/// Iterator over validated network revisions.
#[derive(Clone)]
pub struct NetworkRevisionIter<'a> {
    entries: &'a [u8],
    position: usize,
}

impl Iterator for NetworkRevisionIter<'_> {
    type Item = NetworkRevision;

    fn next(&mut self) -> Option<Self::Item> {
        let end = self.position.checked_add(NETWORK_REVISION_ENTRY_LENGTH)?;
        let bytes = self.entries.get(self.position..end)?;
        self.position = end;
        decode_network_revision(bytes).ok()
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        let count =
            self.entries.len().saturating_sub(self.position) / NETWORK_REVISION_ENTRY_LENGTH;
        (count, Some(count))
    }
}

impl ExactSizeIterator for NetworkRevisionIter<'_> {}
impl std::iter::FusedIterator for NetworkRevisionIter<'_> {}

/// Encodes a network-ID-sorted revision list.
///
/// # Errors
///
/// Returns [`CodecError`] for an excessive count, zero field, order violation,
/// arithmetic overflow, or insufficient output capacity.
pub fn encode_network_revision_list(
    revisions: &[NetworkRevision],
    output: &mut [u8],
) -> Result<usize, CodecError> {
    let count = u16::try_from(revisions.len()).map_err(|_| CodecError::ValueOutOfRange {
        field: "network revision count",
        actual: u64::try_from(revisions.len()).unwrap_or(u64::MAX),
        minimum: 0,
        maximum: u64::from(MAX_NETWORK_REVISIONS),
    })?;
    if count > MAX_NETWORK_REVISIONS {
        return Err(CodecError::ValueOutOfRange {
            field: "network revision count",
            actual: u64::from(count),
            minimum: 0,
            maximum: u64::from(MAX_NETWORK_REVISIONS),
        });
    }
    let mut previous = None;
    for (index, revision) in revisions.iter().copied().enumerate() {
        revision.validate()?;
        if let Some(previous_id) = previous {
            if previous_id >= revision.network_id {
                return Err(CodecError::NestedRecordsOutOfOrder {
                    context: "network revision list",
                    index,
                });
            }
        }
        previous = Some(revision.network_id);
    }
    let entries_length = revisions
        .len()
        .checked_mul(NETWORK_REVISION_ENTRY_LENGTH)
        .ok_or(CodecError::IntegerOverflow {
            field: "network revision list length",
        })?;
    let encoded_length =
        4_usize
            .checked_add(entries_length)
            .ok_or(CodecError::IntegerOverflow {
                field: "network revision list length",
            })?;
    if output.len() < encoded_length {
        return Err(CodecError::OutputTooSmall {
            field: "network revision list",
            offset: 0,
            needed: encoded_length,
            remaining: output.len(),
        });
    }
    let mut cursor = WriteCursor::new(output, 0);
    cursor.write_u16(count, "network revision count")?;
    cursor.write_u16(0, "network revision reserved")?;
    for revision in revisions {
        cursor.write_bytes(revision.network_id.as_bytes(), "network ID")?;
        cursor.write_u64(revision.controller_epoch, "controller epoch")?;
        cursor.write_u64(revision.snapshot_revision, "snapshot revision")?;
    }
    Ok(cursor.position())
}

fn version_entry_at(entries: &[u8], index: usize) -> Result<VersionEntry, CodecError> {
    let start = index
        .checked_mul(VERSION_ENTRY_LENGTH)
        .ok_or(CodecError::IntegerOverflow {
            field: "version entry offset",
        })?;
    let end = start
        .checked_add(VERSION_ENTRY_LENGTH)
        .ok_or(CodecError::IntegerOverflow {
            field: "version entry end",
        })?;
    let bytes = entries.get(start..end).ok_or(CodecError::Truncated {
        field: "version entry",
        offset: start,
        needed: VERSION_ENTRY_LENGTH,
        remaining: entries.len().saturating_sub(start),
    })?;
    VersionEntry::decode(bytes)
}

pub(crate) fn validate_endpoint_records(
    records: &[u8],
    count: u8,
    base_offset: usize,
) -> Result<(), CodecError> {
    let mut position = 0;
    let mut previous: Option<Endpoint> = None;
    for index in 0..usize::from(count) {
        let (endpoint, length) = decode_endpoint_record(records, position, base_offset)?;
        if let Some(previous_endpoint) = previous {
            if previous_endpoint.sort_cmp(endpoint) != Ordering::Less {
                return Err(CodecError::NestedRecordsOutOfOrder {
                    context: "endpoint records",
                    index,
                });
            }
        }
        previous = Some(endpoint);
        position = position
            .checked_add(length)
            .ok_or(CodecError::IntegerOverflow {
                field: "endpoint records position",
            })?;
    }
    validate_record_length(records.len(), position, "endpoint records")
}

pub(crate) fn endpoint_records_encoded_len(endpoints: &[Endpoint]) -> Result<usize, CodecError> {
    let mut encoded_length = 0_usize;
    let mut previous: Option<Endpoint> = None;
    for (index, endpoint) in endpoints.iter().copied().enumerate() {
        endpoint.validate()?;
        if let Some(previous_endpoint) = previous {
            if previous_endpoint.sort_cmp(endpoint) != Ordering::Less {
                return Err(CodecError::NestedRecordsOutOfOrder {
                    context: "endpoint records",
                    index,
                });
            }
        }
        previous = Some(endpoint);
        encoded_length = encoded_length.checked_add(endpoint.encoded_len()).ok_or(
            CodecError::IntegerOverflow {
                field: "endpoint records length",
            },
        )?;
    }
    Ok(encoded_length)
}

pub(crate) fn encode_endpoint_records_at(
    endpoints: &[Endpoint],
    output: &mut [u8],
    base_offset: usize,
) -> Result<usize, CodecError> {
    let required = endpoint_records_encoded_len(endpoints)?;
    if output.len() < required {
        return Err(CodecError::OutputTooSmall {
            field: "endpoint records",
            offset: base_offset,
            needed: required,
            remaining: output.len(),
        });
    }
    let mut cursor = WriteCursor::new(output, base_offset);
    for endpoint in endpoints {
        encode_endpoint_record(*endpoint, &mut cursor)?;
    }
    Ok(cursor.position())
}

pub(crate) fn decode_endpoint_record(
    records: &[u8],
    position: usize,
    base_offset: usize,
) -> Result<(Endpoint, usize), CodecError> {
    let remaining = records.get(position..).ok_or(CodecError::Truncated {
        field: "endpoint record",
        offset: base_offset.saturating_add(position),
        needed: 1,
        remaining: 0,
    })?;
    let mut cursor = ReadCursor::new(remaining, base_offset.saturating_add(position));
    let kind = cursor.read_u8("endpoint kind")?;
    let priority = cursor.read_u8("endpoint priority")?;
    let record_length = usize::from(cursor.read_u16("endpoint record length")?);
    let expected_length = match kind {
        1 => IPV4_ENDPOINT_LENGTH,
        2 => IPV6_ENDPOINT_LENGTH,
        _ => return Err(CodecError::UnsupportedEndpointKind { kind }),
    };
    if record_length != expected_length {
        return Err(CodecError::LengthMismatch {
            field: "endpoint record",
            expected: expected_length,
            actual: record_length,
        });
    }
    if remaining.len() < record_length {
        return Err(CodecError::Truncated {
            field: "endpoint record",
            offset: base_offset.saturating_add(position),
            needed: record_length,
            remaining: remaining.len(),
        });
    }
    let port = cursor.read_u16("endpoint UDP port")?;
    let reserved_offset = base_offset
        .saturating_add(position)
        .saturating_add(cursor.position());
    if cursor.read_u16("endpoint reserved")? != 0 {
        return Err(CodecError::NonZeroReserved {
            field: "endpoint reserved",
            offset: reserved_offset,
        });
    }
    let max_datagram_size = cursor.read_u32("endpoint maximum datagram size")?;
    let endpoint = match kind {
        1 => Endpoint::UdpIpv4 {
            priority,
            port,
            max_datagram_size,
            address: Ipv4Addr::from(cursor.read_array::<4>("IPv4 address")?),
        },
        2 => Endpoint::UdpIpv6 {
            priority,
            port,
            max_datagram_size,
            address: Ipv6Addr::from(cursor.read_array::<16>("IPv6 address")?),
        },
        _ => return Err(CodecError::UnsupportedEndpointKind { kind }),
    };
    endpoint.validate()?;
    Ok((endpoint, record_length))
}

fn encode_endpoint_record(
    endpoint: Endpoint,
    cursor: &mut WriteCursor<'_>,
) -> Result<(), CodecError> {
    endpoint.validate()?;
    cursor.write_u8(endpoint.kind(), "endpoint kind")?;
    cursor.write_u8(endpoint.priority(), "endpoint priority")?;
    cursor.write_u16(
        u16::try_from(endpoint.encoded_len()).map_err(|_| CodecError::IntegerOverflow {
            field: "endpoint record length",
        })?,
        "endpoint record length",
    )?;
    cursor.write_u16(endpoint.port(), "endpoint UDP port")?;
    cursor.write_u16(0, "endpoint reserved")?;
    cursor.write_u32(
        endpoint.max_datagram_size(),
        "endpoint maximum datagram size",
    )?;
    match endpoint {
        Endpoint::UdpIpv4 { address, .. } => {
            cursor.write_bytes(&address.octets(), "IPv4 address")?;
        }
        Endpoint::UdpIpv6 { address, .. } => {
            cursor.write_bytes(&address.octets(), "IPv6 address")?;
        }
    }
    Ok(())
}

fn endpoint_address_bytes(endpoint: Endpoint) -> [u8; 16] {
    match endpoint {
        Endpoint::UdpIpv4 { address, .. } => {
            let mut output = [0; 16];
            output[..4].copy_from_slice(&address.octets());
            output
        }
        Endpoint::UdpIpv6 { address, .. } => address.octets(),
    }
}

fn network_revision_at(entries: &[u8], index: usize) -> Result<NetworkRevision, CodecError> {
    let start =
        index
            .checked_mul(NETWORK_REVISION_ENTRY_LENGTH)
            .ok_or(CodecError::IntegerOverflow {
                field: "network revision offset",
            })?;
    let end =
        start
            .checked_add(NETWORK_REVISION_ENTRY_LENGTH)
            .ok_or(CodecError::IntegerOverflow {
                field: "network revision end",
            })?;
    let bytes = entries.get(start..end).ok_or(CodecError::Truncated {
        field: "network revision entry",
        offset: start,
        needed: NETWORK_REVISION_ENTRY_LENGTH,
        remaining: entries.len().saturating_sub(start),
    })?;
    decode_network_revision(bytes)
}

fn decode_network_revision(bytes: &[u8]) -> Result<NetworkRevision, CodecError> {
    validate_record_length(
        bytes.len(),
        NETWORK_REVISION_ENTRY_LENGTH,
        "network revision entry",
    )?;
    let mut cursor = ReadCursor::new(bytes, 0);
    Ok(NetworkRevision {
        network_id: NetworkId::from_bytes(cursor.read_array("network ID")?),
        controller_epoch: cursor.read_u64("controller epoch")?,
        snapshot_revision: cursor.read_u64("snapshot revision")?,
    })
}

#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, Ipv6Addr};

    use stella_common::NetworkId;

    use super::{
        encode_endpoint_set, encode_network_revision_list, encode_version_list, Endpoint,
        EndpointSetView, NetworkRevision, NetworkRevisionListView, VersionEntry, VersionListView,
    };
    use crate::CodecError;

    fn endpoints() -> [Endpoint; 2] {
        [
            Endpoint::UdpIpv4 {
                priority: 10,
                port: 4_242,
                max_datagram_size: 1_200,
                address: Ipv4Addr::new(192, 0, 2, 1),
            },
            Endpoint::UdpIpv6 {
                priority: 20,
                port: 4_243,
                max_datagram_size: 1_500,
                address: Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, 1),
            },
        ]
    }

    #[test]
    fn version_list_round_trips_and_rejects_duplicates() {
        let entries = [
            VersionEntry::V0_1_SUITE_1,
            VersionEntry {
                major: 0,
                minor: 1,
                suite_id: 2,
            },
        ];
        let mut encoded = [0; 12];
        assert_eq!(encode_version_list(&entries, &mut encoded), Ok(12));
        assert_eq!(encoded, [2, 0, 0, 0, 0, 1, 0, 1, 0, 1, 0, 2]);
        let decoded = VersionListView::decode(&encoded).expect("valid version list");
        assert_eq!(decoded.len(), 2);
        assert!(!decoded.is_empty());
        assert_eq!(decoded.entries().collect::<Vec<_>>(), entries);
        assert_eq!(
            encode_version_list(&[entries[0], entries[0]], &mut encoded),
            Err(CodecError::DuplicateNestedEntry {
                context: "version list",
                index: 1,
            })
        );
    }

    #[test]
    fn endpoint_set_matches_canonical_records_and_round_trips() {
        let mut encoded = [0; 48];
        assert_eq!(encode_endpoint_set(&endpoints(), &mut encoded), Ok(48));
        assert_eq!(&encoded[..4], &[2, 0, 0, 0]);
        assert_eq!(
            &encoded[4..20],
            &[1, 10, 0, 16, 0x10, 0x92, 0, 0, 0, 0, 4, 0xb0, 192, 0, 2, 1]
        );
        assert_eq!(&encoded[20..24], &[2, 20, 0, 28]);
        let decoded = EndpointSetView::decode(&encoded).expect("valid endpoint set");
        assert_eq!(decoded.len(), 2);
        assert!(!decoded.is_empty());
        assert_eq!(decoded.endpoints().collect::<Vec<_>>(), endpoints());
        assert!(!endpoints()[0].is_loopback());
    }

    #[test]
    fn endpoints_reject_unusable_addresses_limits_and_order() {
        let invalid = Endpoint::UdpIpv4 {
            priority: 0,
            port: 1,
            max_datagram_size: 1_200,
            address: Ipv4Addr::UNSPECIFIED,
        };
        assert_eq!(
            invalid.validate(),
            Err(CodecError::InvalidEndpointAddress { family: "IPv4" })
        );

        let mapped = Endpoint::UdpIpv6 {
            priority: 0,
            port: 1,
            max_datagram_size: 1_200,
            address: Ipv4Addr::new(192, 0, 2, 1).to_ipv6_mapped(),
        };
        assert_eq!(
            mapped.validate(),
            Err(CodecError::InvalidEndpointAddress { family: "IPv6" })
        );

        let mut reversed = endpoints();
        reversed.reverse();
        let mut output = [0; 48];
        assert_eq!(
            encode_endpoint_set(&reversed, &mut output),
            Err(CodecError::NestedRecordsOutOfOrder {
                context: "endpoint records",
                index: 1,
            })
        );
    }

    #[test]
    fn empty_endpoint_set_and_loopback_are_structurally_valid() {
        let mut empty = [0xff; 4];
        assert_eq!(encode_endpoint_set(&[], &mut empty), Ok(4));
        assert_eq!(empty, [0; 4]);
        assert!(EndpointSetView::decode(&empty)
            .expect("valid empty set")
            .is_empty());

        let loopback = Endpoint::UdpIpv4 {
            priority: 0,
            port: 1,
            max_datagram_size: 1_200,
            address: Ipv4Addr::LOCALHOST,
        };
        assert_eq!(loopback.validate(), Ok(()));
        assert!(loopback.is_loopback());
    }

    #[test]
    fn network_revision_list_round_trips_and_enforces_order() {
        let revisions = [
            NetworkRevision {
                network_id: NetworkId::from_bytes([1; 16]),
                controller_epoch: 2,
                snapshot_revision: 3,
            },
            NetworkRevision {
                network_id: NetworkId::from_bytes([2; 16]),
                controller_epoch: 4,
                snapshot_revision: 5,
            },
        ];
        let mut encoded = [0; 68];
        assert_eq!(
            encode_network_revision_list(&revisions, &mut encoded),
            Ok(68)
        );
        let decoded = NetworkRevisionListView::decode(&encoded).expect("valid network revisions");
        assert_eq!(decoded.len(), 2);
        assert!(!decoded.is_empty());
        assert_eq!(decoded.revisions().collect::<Vec<_>>(), revisions);

        assert_eq!(
            encode_network_revision_list(&[revisions[1], revisions[0]], &mut encoded),
            Err(CodecError::NestedRecordsOutOfOrder {
                context: "network revision list",
                index: 1,
            })
        );
    }
}
