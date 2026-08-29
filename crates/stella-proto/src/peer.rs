//! Nested peer record and peer list codecs.

use stella_common::{ControllerId, NetworkId, NodeId};

use crate::{
    common::validate_record_length,
    cursor::{ReadCursor, WriteCursor},
    nested::{encode_endpoint_records_at, endpoint_records_encoded_len, validate_endpoint_records},
    CodecError, Endpoint, EndpointIter, MembershipGrantView, MAX_ENDPOINTS,
    MEMBERSHIP_GRANT_LENGTH,
};

/// Fixed bytes in a peer record before endpoint records.
pub const PEER_RECORD_FIXED_LENGTH: usize = 292;

/// Largest peer record with eight IPv6 endpoints.
pub const MAX_PEER_RECORD_LENGTH: usize = 516;

/// Maximum peers carried by a version 0.1 peer list.
pub const MAX_PEER_LIST_ENTRIES: u16 = 255;

/// Borrowed input used to encode one peer record.
#[derive(Clone, Copy)]
pub struct PeerRecordRef<'a> {
    node_id: NodeId,
    node_public_key: [u8; 32],
    membership_grant: &'a [u8; MEMBERSHIP_GRANT_LENGTH],
    endpoints: &'a [Endpoint],
}

impl<'a> PeerRecordRef<'a> {
    /// Creates a peer record after validating its grant and endpoint metadata.
    ///
    /// # Errors
    ///
    /// Returns [`CodecError`] when the grant is malformed, its node identity
    /// or public key differs from the record, the endpoint count exceeds eight,
    /// or endpoint records are invalid or unsorted.
    pub fn new(
        node_id: NodeId,
        node_public_key: [u8; 32],
        membership_grant: &'a [u8; MEMBERSHIP_GRANT_LENGTH],
        endpoints: &'a [Endpoint],
    ) -> Result<Self, CodecError> {
        if endpoints.len() > usize::from(MAX_ENDPOINTS) {
            return Err(CodecError::ValueOutOfRange {
                field: "peer endpoint count",
                actual: u64::try_from(endpoints.len()).unwrap_or(u64::MAX),
                minimum: 0,
                maximum: u64::from(MAX_ENDPOINTS),
            });
        }
        let grant = MembershipGrantView::decode(membership_grant)?.grant();
        validate_peer_identity(
            node_id,
            &node_public_key,
            grant.node_id,
            &grant.node_public_key,
        )?;
        let _endpoint_length = endpoint_records_encoded_len(endpoints)?;
        Ok(Self {
            node_id,
            node_public_key,
            membership_grant,
            endpoints,
        })
    }

    /// Returns the peer node identity.
    #[must_use]
    pub const fn node_id(self) -> NodeId {
        self.node_id
    }

    /// Returns the peer Ed25519 public key.
    #[must_use]
    pub const fn node_public_key(self) -> [u8; 32] {
        self.node_public_key
    }

    /// Borrows the exact encoded membership grant.
    #[must_use]
    pub const fn membership_grant(self) -> &'a [u8; MEMBERSHIP_GRANT_LENGTH] {
        self.membership_grant
    }

    /// Borrows the canonical endpoint sequence.
    #[must_use]
    pub const fn endpoints(self) -> &'a [Endpoint] {
        self.endpoints
    }

    /// Returns the exact encoded peer record length.
    ///
    /// # Errors
    ///
    /// Returns [`CodecError`] when endpoint size arithmetic overflows.
    pub fn encoded_len(self) -> Result<usize, CodecError> {
        PEER_RECORD_FIXED_LENGTH
            .checked_add(endpoint_records_encoded_len(self.endpoints)?)
            .ok_or(CodecError::IntegerOverflow {
                field: "peer record length",
            })
    }
}

/// Borrowed validated peer record.
#[derive(Clone)]
pub struct PeerRecordView<'a> {
    encoded_length: usize,
    node_id: NodeId,
    node_public_key: [u8; 32],
    membership_grant: MembershipGrantView<'a>,
    endpoint_count: u8,
    endpoint_records: &'a [u8],
}

impl<'a> PeerRecordView<'a> {
    /// Decodes one exact self-sized peer record.
    ///
    /// # Errors
    ///
    /// Returns [`CodecError`] when its length, alignment, endpoint count,
    /// reserved byte, grant, identity consistency, or endpoint records are
    /// invalid.
    pub fn decode(input: &'a [u8]) -> Result<Self, CodecError> {
        let (record, consumed) = Self::decode_prefix(input, 0)?;
        validate_record_length(input.len(), consumed, "peer record")?;
        Ok(record)
    }

    pub(crate) fn decode_prefix(
        input: &'a [u8],
        base_offset: usize,
    ) -> Result<(Self, usize), CodecError> {
        let mut cursor = ReadCursor::new(input, base_offset);
        let record_length = usize::from(cursor.read_u16("peer record length")?);
        if !(PEER_RECORD_FIXED_LENGTH..=MAX_PEER_RECORD_LENGTH).contains(&record_length) {
            return Err(CodecError::ValueOutOfRange {
                field: "peer record length",
                actual: u64::try_from(record_length).unwrap_or(u64::MAX),
                minimum: u64::try_from(PEER_RECORD_FIXED_LENGTH).unwrap_or(u64::MAX),
                maximum: u64::try_from(MAX_PEER_RECORD_LENGTH).unwrap_or(u64::MAX),
            });
        }
        if record_length % 4 != 0 {
            return Err(CodecError::UnalignedHeaderLength {
                actual: record_length,
            });
        }
        if input.len() < record_length {
            return Err(CodecError::Truncated {
                field: "peer record",
                offset: base_offset,
                needed: record_length,
                remaining: input.len(),
            });
        }
        let endpoint_count = cursor.read_u8("peer endpoint count")?;
        if endpoint_count > MAX_ENDPOINTS {
            return Err(CodecError::ValueOutOfRange {
                field: "peer endpoint count",
                actual: u64::from(endpoint_count),
                minimum: 0,
                maximum: u64::from(MAX_ENDPOINTS),
            });
        }
        let reserved_offset = base_offset.saturating_add(cursor.position());
        if cursor.read_u8("peer record reserved")? != 0 {
            return Err(CodecError::NonZeroReserved {
                field: "peer record reserved",
                offset: reserved_offset,
            });
        }
        let node_id = NodeId::from_bytes(cursor.read_array("peer node ID")?);
        let node_public_key = cursor.read_array("peer public key")?;
        let grant_bytes = cursor.read_slice(MEMBERSHIP_GRANT_LENGTH, "membership grant")?;
        let membership_grant = MembershipGrantView::decode(grant_bytes)?;
        let grant = membership_grant.grant();
        validate_peer_identity(
            node_id,
            &node_public_key,
            grant.node_id,
            &grant.node_public_key,
        )?;

        let endpoint_length = record_length.checked_sub(PEER_RECORD_FIXED_LENGTH).ok_or(
            CodecError::IntegerOverflow {
                field: "peer endpoint records length",
            },
        )?;
        let endpoint_records =
            input
                .get(PEER_RECORD_FIXED_LENGTH..record_length)
                .ok_or(CodecError::Truncated {
                    field: "peer endpoint records",
                    offset: base_offset.saturating_add(PEER_RECORD_FIXED_LENGTH),
                    needed: endpoint_length,
                    remaining: input.len().saturating_sub(PEER_RECORD_FIXED_LENGTH),
                })?;
        validate_endpoint_records(
            endpoint_records,
            endpoint_count,
            base_offset.saturating_add(PEER_RECORD_FIXED_LENGTH),
        )?;
        Ok((
            Self {
                encoded_length: record_length,
                node_id,
                node_public_key,
                membership_grant,
                endpoint_count,
                endpoint_records,
            },
            record_length,
        ))
    }

    /// Returns the peer node identity.
    #[must_use]
    pub const fn node_id(&self) -> NodeId {
        self.node_id
    }

    /// Returns the peer Ed25519 public key.
    #[must_use]
    pub const fn node_public_key(&self) -> [u8; 32] {
        self.node_public_key
    }

    /// Returns the decoded signed membership grant.
    #[must_use]
    pub fn membership_grant(&self) -> MembershipGrantView<'a> {
        self.membership_grant.clone()
    }

    /// Iterates over the peer's validated endpoints.
    #[must_use]
    pub const fn endpoints(&self) -> EndpointIter<'a> {
        EndpointIter::new(self.endpoint_records, self.endpoint_count)
    }

    /// Returns the exact self-sized record length.
    #[must_use]
    pub const fn encoded_len(&self) -> usize {
        self.encoded_length
    }

    /// Validates network-scoped fields against authenticated snapshot context.
    ///
    /// # Errors
    ///
    /// Returns [`CodecError::InconsistentField`] when the grant's network,
    /// controller, or epoch differs from the enclosing snapshot.
    pub fn validate_context(
        &self,
        network_id: NetworkId,
        controller_id: ControllerId,
        controller_epoch: u64,
    ) -> Result<(), CodecError> {
        let grant = self.membership_grant.grant();
        validate_peer_context(grant.network_id == network_id, "network ID")?;
        validate_peer_context(grant.controller_id == controller_id, "controller ID")?;
        validate_peer_context(
            grant.controller_epoch == controller_epoch,
            "controller epoch",
        )?;
        Ok(())
    }
}

/// Encodes one complete peer record.
///
/// # Errors
///
/// Returns [`CodecError`] when the record is invalid, its length overflows, or
/// `output` is too small.
pub fn encode_peer_record(
    record: PeerRecordRef<'_>,
    output: &mut [u8],
) -> Result<usize, CodecError> {
    let encoded_length = record.encoded_len()?;
    if output.len() < encoded_length {
        return Err(CodecError::OutputTooSmall {
            field: "peer record",
            offset: 0,
            needed: encoded_length,
            remaining: output.len(),
        });
    }
    let endpoint_count =
        u8::try_from(record.endpoints.len()).map_err(|_| CodecError::ValueOutOfRange {
            field: "peer endpoint count",
            actual: u64::try_from(record.endpoints.len()).unwrap_or(u64::MAX),
            minimum: 0,
            maximum: u64::from(MAX_ENDPOINTS),
        })?;
    let mut cursor = WriteCursor::new(output, 0);
    cursor.write_u16(
        u16::try_from(encoded_length).map_err(|_| CodecError::IntegerOverflow {
            field: "peer record length",
        })?,
        "peer record length",
    )?;
    cursor.write_u8(endpoint_count, "peer endpoint count")?;
    cursor.write_u8(0, "peer record reserved")?;
    cursor.write_bytes(record.node_id.as_bytes(), "peer node ID")?;
    cursor.write_bytes(&record.node_public_key, "peer public key")?;
    cursor.write_bytes(record.membership_grant, "membership grant")?;
    let output_length = output.len();
    let endpoint_output = output
        .get_mut(PEER_RECORD_FIXED_LENGTH..encoded_length)
        .ok_or(CodecError::OutputTooSmall {
            field: "peer endpoint records",
            offset: PEER_RECORD_FIXED_LENGTH,
            needed: encoded_length.saturating_sub(PEER_RECORD_FIXED_LENGTH),
            remaining: output_length.saturating_sub(PEER_RECORD_FIXED_LENGTH),
        })?;
    encode_endpoint_records_at(record.endpoints, endpoint_output, PEER_RECORD_FIXED_LENGTH)?;
    Ok(encoded_length)
}

/// Borrowed validated peer list.
#[derive(Clone)]
pub struct PeerListView<'a> {
    count: u16,
    records: &'a [u8],
}

impl<'a> PeerListView<'a> {
    /// Decodes a complete node-ID-sorted peer list.
    ///
    /// # Errors
    ///
    /// Returns [`CodecError`] for an excessive count, reserved bytes, malformed
    /// peer record, trailing bytes, or non-increasing node ID order.
    pub fn decode(input: &'a [u8]) -> Result<Self, CodecError> {
        let mut cursor = ReadCursor::new(input, 0);
        let count = cursor.read_u16("peer count")?;
        if count > MAX_PEER_LIST_ENTRIES {
            return Err(CodecError::ValueOutOfRange {
                field: "peer count",
                actual: u64::from(count),
                minimum: 0,
                maximum: u64::from(MAX_PEER_LIST_ENTRIES),
            });
        }
        let reserved_offset = cursor.position();
        if cursor.read_u16("peer list reserved")? != 0 {
            return Err(CodecError::NonZeroReserved {
                field: "peer list reserved",
                offset: reserved_offset,
            });
        }
        let records = input.get(4..).ok_or(CodecError::Truncated {
            field: "peer records",
            offset: input.len(),
            needed: 4_usize.saturating_sub(input.len()),
            remaining: 0,
        })?;
        let mut position = 0;
        let mut previous = None;
        for index in 0..usize::from(count) {
            let record_input = records.get(position..).ok_or(CodecError::Truncated {
                field: "peer record",
                offset: 4_usize.saturating_add(position),
                needed: 1,
                remaining: 0,
            })?;
            let (record, consumed) =
                PeerRecordView::decode_prefix(record_input, 4_usize.saturating_add(position))?;
            if let Some(previous_id) = previous {
                if previous_id >= record.node_id {
                    return Err(CodecError::NestedRecordsOutOfOrder {
                        context: "peer list",
                        index,
                    });
                }
            }
            previous = Some(record.node_id);
            position = position
                .checked_add(consumed)
                .ok_or(CodecError::IntegerOverflow {
                    field: "peer list position",
                })?;
        }
        validate_record_length(records.len(), position, "peer records")?;
        Ok(Self { count, records })
    }

    /// Returns the peer count.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.count as usize
    }

    /// Returns whether the list contains no peers.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.count == 0
    }

    /// Iterates over validated peer records.
    #[must_use]
    pub const fn peers(&self) -> PeerListIter<'a> {
        PeerListIter {
            records: self.records,
            position: 0,
            remaining: self.count,
        }
    }

    /// Validates list membership against authenticated snapshot context.
    ///
    /// # Errors
    ///
    /// Returns [`CodecError`] when the count exceeds `max_flood_peers - 1`, a
    /// record names the receiving node, or a grant differs in network,
    /// controller, or epoch.
    pub fn validate_context(
        &self,
        max_flood_peers: u16,
        receiving_node: NodeId,
        network_id: NetworkId,
        controller_id: ControllerId,
        controller_epoch: u64,
    ) -> Result<(), CodecError> {
        let maximum = max_flood_peers
            .checked_sub(1)
            .ok_or(CodecError::ValueOutOfRange {
                field: "maximum flood peers",
                actual: u64::from(max_flood_peers),
                minimum: 2,
                maximum: 256,
            })?;
        if self.count > maximum {
            return Err(CodecError::ValueOutOfRange {
                field: "peer count",
                actual: u64::from(self.count),
                minimum: 0,
                maximum: u64::from(maximum),
            });
        }
        for peer in self.peers() {
            if peer.node_id == receiving_node {
                return Err(CodecError::InconsistentField {
                    context: "peer list and receiving node",
                    field: "node ID",
                });
            }
            peer.validate_context(network_id, controller_id, controller_epoch)?;
        }
        Ok(())
    }
}

/// Iterator over validated peer records.
#[derive(Clone)]
pub struct PeerListIter<'a> {
    records: &'a [u8],
    position: usize,
    remaining: u16,
}

impl<'a> Iterator for PeerListIter<'a> {
    type Item = PeerRecordView<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.remaining == 0 {
            return None;
        }
        let record_input = self.records.get(self.position..)?;
        let (record, consumed) = PeerRecordView::decode_prefix(record_input, self.position).ok()?;
        self.position = self.position.checked_add(consumed)?;
        self.remaining -= 1;
        Some(record)
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        let remaining = usize::from(self.remaining);
        (remaining, Some(remaining))
    }
}

impl ExactSizeIterator for PeerListIter<'_> {}
impl std::iter::FusedIterator for PeerListIter<'_> {}

/// Encodes a node-ID-sorted peer list.
///
/// # Errors
///
/// Returns [`CodecError`] for an excessive count, invalid record, order
/// violation, arithmetic overflow, or insufficient output capacity.
pub fn encode_peer_list(
    records: &[PeerRecordRef<'_>],
    output: &mut [u8],
) -> Result<usize, CodecError> {
    let count = u16::try_from(records.len()).map_err(|_| CodecError::ValueOutOfRange {
        field: "peer count",
        actual: u64::try_from(records.len()).unwrap_or(u64::MAX),
        minimum: 0,
        maximum: u64::from(MAX_PEER_LIST_ENTRIES),
    })?;
    if count > MAX_PEER_LIST_ENTRIES {
        return Err(CodecError::ValueOutOfRange {
            field: "peer count",
            actual: u64::from(count),
            minimum: 0,
            maximum: u64::from(MAX_PEER_LIST_ENTRIES),
        });
    }
    let mut encoded_length = 4_usize;
    let mut previous = None;
    for (index, record) in records.iter().copied().enumerate() {
        if let Some(previous_id) = previous {
            if previous_id >= record.node_id {
                return Err(CodecError::NestedRecordsOutOfOrder {
                    context: "peer list",
                    index,
                });
            }
        }
        previous = Some(record.node_id);
        encoded_length = encoded_length.checked_add(record.encoded_len()?).ok_or(
            CodecError::IntegerOverflow {
                field: "peer list length",
            },
        )?;
    }
    if output.len() < encoded_length {
        return Err(CodecError::OutputTooSmall {
            field: "peer list",
            offset: 0,
            needed: encoded_length,
            remaining: output.len(),
        });
    }
    let mut cursor = WriteCursor::new(output, 0);
    cursor.write_u16(count, "peer count")?;
    cursor.write_u16(0, "peer list reserved")?;
    let output_length = output.len();
    let mut position = 4_usize;
    for record in records {
        let record_length = record.encoded_len()?;
        let end = position
            .checked_add(record_length)
            .ok_or(CodecError::IntegerOverflow {
                field: "peer record end",
            })?;
        let record_output = output
            .get_mut(position..end)
            .ok_or(CodecError::OutputTooSmall {
                field: "peer record",
                offset: position,
                needed: record_length,
                remaining: output_length.saturating_sub(position),
            })?;
        encode_peer_record(*record, record_output)?;
        position = end;
    }
    Ok(encoded_length)
}

fn validate_peer_identity(
    node_id: NodeId,
    node_public_key: &[u8; 32],
    grant_node_id: NodeId,
    grant_public_key: &[u8; 32],
) -> Result<(), CodecError> {
    if node_id != grant_node_id {
        return Err(CodecError::InconsistentField {
            context: "peer record and membership grant",
            field: "node ID",
        });
    }
    if node_public_key != grant_public_key {
        return Err(CodecError::InconsistentField {
            context: "peer record and membership grant",
            field: "node public key",
        });
    }
    Ok(())
}

fn validate_peer_context(matches: bool, field: &'static str) -> Result<(), CodecError> {
    if !matches {
        return Err(CodecError::InconsistentField {
            context: "peer grant and snapshot",
            field,
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use stella_common::{ControllerId, GrantSerial, NetworkId, NodeId};

    use super::{
        encode_peer_list, encode_peer_record, PeerListView, PeerRecordRef, PeerRecordView,
        PEER_RECORD_FIXED_LENGTH,
    };
    use crate::{
        encode_membership_grant, CodecError, ConfidentialityPolicy, Endpoint, MembershipGrant,
        MembershipPermissions, ED25519_SIGNATURE_LENGTH, MEMBERSHIP_GRANT_LENGTH,
    };

    const SIGNATURE: [u8; ED25519_SIGNATURE_LENGTH] = [0x55; ED25519_SIGNATURE_LENGTH];

    fn endpoints() -> [Endpoint; 1] {
        [Endpoint::UdpIpv4 {
            priority: 0,
            port: 4_242,
            max_datagram_size: 1_200,
            address: Ipv4Addr::new(192, 0, 2, 1),
        }]
    }

    fn grant(node_byte: u8, serial_byte: u8) -> MembershipGrant {
        MembershipGrant {
            confidentiality: ConfidentialityPolicy::Encrypt,
            permissions: MembershipPermissions::ALL,
            network_id: NetworkId::from_bytes([1; 16]),
            node_id: NodeId::from_bytes([node_byte; 16]),
            node_public_key: [node_byte; 32],
            controller_id: ControllerId::from_bytes([2; 16]),
            controller_epoch: 3,
            not_before: 1_000,
            not_after: 2_000,
            max_frame_size: 1_514,
            max_flood_peers: 32,
            flood_rate: 100,
            flood_burst: 200,
            policy_digest: [4; 32],
            grant_serial: GrantSerial::from_bytes([serial_byte; 16]),
        }
    }

    fn encode_grant(value: MembershipGrant) -> [u8; MEMBERSHIP_GRANT_LENGTH] {
        let mut output = [0; MEMBERSHIP_GRANT_LENGTH];
        encode_membership_grant(value, &SIGNATURE, &mut output).expect("valid grant");
        output
    }

    #[test]
    fn peer_record_round_trips_grant_and_endpoints() {
        let grant = grant(10, 20);
        let grant_bytes = encode_grant(grant);
        let endpoints = endpoints();
        let record = PeerRecordRef::new(
            grant.node_id,
            grant.node_public_key,
            &grant_bytes,
            &endpoints,
        )
        .expect("valid peer record");
        let mut encoded = [0; PEER_RECORD_FIXED_LENGTH + 16];
        assert_eq!(encode_peer_record(record, &mut encoded), Ok(encoded.len()));
        assert_eq!(&encoded[..4], &[0x01, 0x34, 1, 0]);

        let decoded = PeerRecordView::decode(&encoded).expect("valid peer record");
        assert_eq!(decoded.node_id(), grant.node_id);
        assert_eq!(decoded.node_public_key(), grant.node_public_key);
        assert_eq!(decoded.membership_grant().grant(), grant);
        assert_eq!(decoded.endpoints().collect::<Vec<_>>(), endpoints);
        assert_eq!(decoded.encoded_len(), encoded.len());
        assert_eq!(
            decoded.validate_context(
                grant.network_id,
                grant.controller_id,
                grant.controller_epoch
            ),
            Ok(())
        );
    }

    #[test]
    fn peer_record_rejects_grant_identity_mismatch() {
        let grant = grant(10, 20);
        let grant_bytes = encode_grant(grant);
        let endpoints = endpoints();
        assert!(matches!(
            PeerRecordRef::new(
                NodeId::from_bytes([11; 16]),
                grant.node_public_key,
                &grant_bytes,
                &endpoints,
            ),
            Err(CodecError::InconsistentField {
                context: "peer record and membership grant",
                field: "node ID",
            })
        ));
    }

    #[test]
    fn peer_list_round_trips_and_validates_context() {
        let first_grant = grant(10, 20);
        let second_grant = grant(11, 21);
        let first_bytes = encode_grant(first_grant);
        let second_bytes = encode_grant(second_grant);
        let endpoints = endpoints();
        let first = PeerRecordRef::new(
            first_grant.node_id,
            first_grant.node_public_key,
            &first_bytes,
            &endpoints,
        )
        .expect("valid first peer");
        let second = PeerRecordRef::new(
            second_grant.node_id,
            second_grant.node_public_key,
            &second_bytes,
            &endpoints,
        )
        .expect("valid second peer");
        let mut encoded = vec![0; 4 + 2 * (PEER_RECORD_FIXED_LENGTH + 16)];
        assert_eq!(
            encode_peer_list(&[first, second], &mut encoded),
            Ok(encoded.len())
        );

        let decoded = PeerListView::decode(&encoded).expect("valid peer list");
        assert_eq!(decoded.len(), 2);
        assert!(!decoded.is_empty());
        assert_eq!(
            decoded
                .peers()
                .map(|peer| peer.node_id())
                .collect::<Vec<_>>(),
            vec![first_grant.node_id, second_grant.node_id]
        );
        assert_eq!(
            decoded.validate_context(
                32,
                NodeId::from_bytes([99; 16]),
                first_grant.network_id,
                first_grant.controller_id,
                first_grant.controller_epoch,
            ),
            Ok(())
        );
    }

    #[test]
    fn peer_list_rejects_order_receiving_node_and_limit() {
        let first_grant = grant(10, 20);
        let second_grant = grant(11, 21);
        let first_bytes = encode_grant(first_grant);
        let second_bytes = encode_grant(second_grant);
        let endpoints = endpoints();
        let first = PeerRecordRef::new(
            first_grant.node_id,
            first_grant.node_public_key,
            &first_bytes,
            &endpoints,
        )
        .expect("valid first peer");
        let second = PeerRecordRef::new(
            second_grant.node_id,
            second_grant.node_public_key,
            &second_bytes,
            &endpoints,
        )
        .expect("valid second peer");
        let mut encoded = vec![0; 4 + 2 * (PEER_RECORD_FIXED_LENGTH + 16)];
        assert_eq!(
            encode_peer_list(&[second, first], &mut encoded),
            Err(CodecError::NestedRecordsOutOfOrder {
                context: "peer list",
                index: 1,
            })
        );

        encode_peer_list(&[first, second], &mut encoded).expect("valid peer list");
        let decoded = PeerListView::decode(&encoded).expect("valid peer list");
        assert!(matches!(
            decoded.validate_context(
                32,
                first_grant.node_id,
                first_grant.network_id,
                first_grant.controller_id,
                first_grant.controller_epoch,
            ),
            Err(CodecError::InconsistentField {
                context: "peer list and receiving node",
                field: "node ID",
            })
        ));
        assert_eq!(
            decoded.validate_context(
                2,
                NodeId::from_bytes([99; 16]),
                first_grant.network_id,
                first_grant.controller_id,
                first_grant.controller_epoch,
            ),
            Err(CodecError::ValueOutOfRange {
                field: "peer count",
                actual: 2,
                minimum: 0,
                maximum: 1,
            })
        );
    }
}
