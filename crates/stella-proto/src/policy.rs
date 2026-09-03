//! Canonical virtual-network policy codec.

use stella_common::NetworkId;

use crate::{
    bounds::validate_range,
    common::validate_record_length,
    cursor::{ReadCursor, WriteCursor},
    CodecError, MAX_ETHERNET_FRAME_LENGTH,
};

/// Magic at the beginning of a canonical network policy.
pub const NETWORK_POLICY_MAGIC: [u8; 4] = *b"SNP1";

/// Current canonical network-policy format version.
pub const NETWORK_POLICY_FORMAT_VERSION: u8 = 1;

/// Exact encoded length of a canonical network policy.
pub const NETWORK_POLICY_LENGTH: usize = 64;

/// Data-plane confidentiality required by a network.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum ConfidentialityPolicy {
    /// Authenticate packets while leaving Ethernet payload bytes visible.
    AuthenticateOnly = 0,
    /// Authenticate and encrypt Ethernet payload bytes.
    Encrypt = 1,
}

impl ConfidentialityPolicy {
    /// Returns the canonical one-byte wire value.
    #[must_use]
    pub const fn as_u8(self) -> u8 {
        self as u8
    }
}

impl TryFrom<u8> for ConfidentialityPolicy {
    type Error = CodecError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::AuthenticateOnly),
            1 => Ok(Self::Encrypt),
            _ => Err(CodecError::InvalidEnumValue {
                field: "confidentiality policy",
                value: u64::from(value),
            }),
        }
    }
}

/// Canonical 64-byte network policy distributed by a controller.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NetworkPolicy {
    /// Required data-plane confidentiality.
    pub confidentiality: ConfidentialityPolicy,
    /// Largest complete Ethernet frame accepted by the network.
    pub max_frame_size: u16,
    /// Maximum number of nodes in one sender-side flood operation.
    pub max_flood_peers: u16,
    /// Maximum locally originated flood frames per second.
    pub flood_rate: u32,
    /// Maximum local flood token-bucket burst.
    pub flood_burst: u32,
    /// Remote MAC entry lifetime in seconds.
    pub mac_age_seconds: u32,
    /// Control heartbeat interval in seconds.
    pub heartbeat_seconds: u16,
    /// Controller peer-record lease in seconds.
    pub peer_lease_seconds: u16,
    /// Maximum peer session lifetime in seconds.
    pub session_lifetime_seconds: u32,
    /// Incomplete-frame reassembly timeout in milliseconds.
    pub reassembly_timeout_ms: u32,
    /// Virtual network governed by this policy.
    pub network_id: NetworkId,
    /// Non-zero monotonic policy revision.
    pub policy_revision: u64,
}

impl NetworkPolicy {
    /// Decodes one exact canonical network-policy object.
    ///
    /// # Errors
    ///
    /// Returns [`CodecError`] when the record length, magic, format version,
    /// enum, declared length, reserved field, network identifier, revision, or
    /// any policy limit is invalid.
    pub fn decode(input: &[u8]) -> Result<Self, CodecError> {
        validate_record_length(input.len(), NETWORK_POLICY_LENGTH, "network policy")?;
        let mut cursor = ReadCursor::new(input, 0);
        if cursor.read_array::<4>("network policy magic")? != NETWORK_POLICY_MAGIC {
            return Err(CodecError::InvalidObjectMagic {
                object: "network policy",
            });
        }
        let format_version = cursor.read_u8("network policy format version")?;
        if format_version != NETWORK_POLICY_FORMAT_VERSION {
            return Err(CodecError::UnsupportedObjectVersion {
                object: "network policy",
                version: format_version,
            });
        }
        let confidentiality =
            ConfidentialityPolicy::try_from(cursor.read_u8("confidentiality policy")?)?;
        let total_length = usize::from(cursor.read_u16("network policy total length")?);
        if total_length != NETWORK_POLICY_LENGTH {
            return Err(CodecError::LengthMismatch {
                field: "network policy total",
                expected: NETWORK_POLICY_LENGTH,
                actual: total_length,
            });
        }

        let max_frame_size = cursor.read_u16("maximum frame size")?;
        let max_flood_peers = cursor.read_u16("maximum flood peers")?;
        let flood_rate = cursor.read_u32("flood rate")?;
        let flood_burst = cursor.read_u32("flood burst")?;
        let mac_age_seconds = cursor.read_u32("MAC age seconds")?;
        let heartbeat_seconds = cursor.read_u16("heartbeat seconds")?;
        let peer_lease_seconds = cursor.read_u16("peer lease seconds")?;
        let session_lifetime_seconds = cursor.read_u32("session lifetime seconds")?;
        let reassembly_timeout_ms = cursor.read_u32("reassembly timeout milliseconds")?;
        let reserved_offset = cursor.position();
        let reserved = cursor.read_u32("network policy reserved")?;
        if reserved != 0 {
            return Err(CodecError::NonZeroReserved {
                field: "network policy reserved",
                offset: reserved_offset,
            });
        }
        let network_id = NetworkId::from_bytes(cursor.read_array("network ID")?);
        let policy_revision = cursor.read_u64("policy revision")?;
        let policy = Self {
            confidentiality,
            max_frame_size,
            max_flood_peers,
            flood_rate,
            flood_burst,
            mac_age_seconds,
            heartbeat_seconds,
            peer_lease_seconds,
            session_lifetime_seconds,
            reassembly_timeout_ms,
            network_id,
            policy_revision,
        };
        policy.validate()?;
        Ok(policy)
    }

    /// Encodes this policy into exactly the first 64 bytes of `output`.
    ///
    /// # Errors
    ///
    /// Returns [`CodecError`] when a policy invariant is invalid or `output`
    /// is too small.
    pub fn encode(self, output: &mut [u8]) -> Result<(), CodecError> {
        self.validate()?;
        let mut cursor = WriteCursor::new(output, 0);
        cursor.write_bytes(&NETWORK_POLICY_MAGIC, "network policy magic")?;
        cursor.write_u8(
            NETWORK_POLICY_FORMAT_VERSION,
            "network policy format version",
        )?;
        cursor.write_u8(self.confidentiality.as_u8(), "confidentiality policy")?;
        cursor.write_u16(
            u16::try_from(NETWORK_POLICY_LENGTH).map_err(|_| CodecError::IntegerOverflow {
                field: "network policy length",
            })?,
            "network policy total length",
        )?;
        cursor.write_u16(self.max_frame_size, "maximum frame size")?;
        cursor.write_u16(self.max_flood_peers, "maximum flood peers")?;
        cursor.write_u32(self.flood_rate, "flood rate")?;
        cursor.write_u32(self.flood_burst, "flood burst")?;
        cursor.write_u32(self.mac_age_seconds, "MAC age seconds")?;
        cursor.write_u16(self.heartbeat_seconds, "heartbeat seconds")?;
        cursor.write_u16(self.peer_lease_seconds, "peer lease seconds")?;
        cursor.write_u32(self.session_lifetime_seconds, "session lifetime seconds")?;
        cursor.write_u32(
            self.reassembly_timeout_ms,
            "reassembly timeout milliseconds",
        )?;
        cursor.write_u32(0, "network policy reserved")?;
        cursor.write_bytes(self.network_id.as_bytes(), "network ID")?;
        cursor.write_u64(self.policy_revision, "policy revision")?;
        Ok(())
    }

    /// Validates every canonical policy value and relationship.
    ///
    /// # Errors
    ///
    /// Returns [`CodecError`] when a limit is outside its protocol range, the
    /// flood burst is smaller than the rate, the peer lease is shorter than
    /// three heartbeat intervals, or the network ID or revision is zero.
    pub fn validate(self) -> Result<(), CodecError> {
        validate_range(
            u64::from(self.max_frame_size),
            1_514,
            u64::from(MAX_ETHERNET_FRAME_LENGTH),
            "maximum frame size",
        )?;
        validate_range(
            u64::from(self.max_flood_peers),
            2,
            256,
            "maximum flood peers",
        )?;
        validate_range(u64::from(self.flood_rate), 1, 1_000_000, "flood rate")?;
        validate_range(
            u64::from(self.flood_burst),
            u64::from(self.flood_rate),
            2_000_000,
            "flood burst",
        )?;
        validate_range(
            u64::from(self.mac_age_seconds),
            30,
            3_600,
            "MAC age seconds",
        )?;
        validate_range(
            u64::from(self.heartbeat_seconds),
            5,
            300,
            "heartbeat seconds",
        )?;
        let minimum_lease = u64::from(self.heartbeat_seconds).checked_mul(3).ok_or(
            CodecError::IntegerOverflow {
                field: "minimum peer lease",
            },
        )?;
        validate_range(
            u64::from(self.peer_lease_seconds),
            minimum_lease,
            900,
            "peer lease seconds",
        )?;
        validate_range(
            u64::from(self.session_lifetime_seconds),
            60,
            3_600,
            "session lifetime seconds",
        )?;
        validate_range(
            u64::from(self.reassembly_timeout_ms),
            500,
            10_000,
            "reassembly timeout milliseconds",
        )?;
        if self.network_id.is_zero() {
            return Err(CodecError::ZeroField {
                field: "network ID",
            });
        }
        if self.policy_revision == 0 {
            return Err(CodecError::ZeroField {
                field: "policy revision",
            });
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use stella_common::NetworkId;

    use super::{
        ConfidentialityPolicy, NetworkPolicy, NETWORK_POLICY_LENGTH, NETWORK_POLICY_MAGIC,
    };
    use crate::CodecError;

    const POLICY_BYTES: [u8; NETWORK_POLICY_LENGTH] = [
        0x53, 0x4e, 0x50, 0x31, 1, 1, 0, 64, 0x05, 0xea, 0, 32, 0, 0, 0x03, 0xe8, 0, 0, 0x07, 0xd0,
        0, 0, 0x01, 0x2c, 0, 10, 0, 30, 0, 0, 0x03, 0x84, 0, 0, 0x0b, 0xb8, 0, 0, 0, 0, 0, 1, 2, 3,
        4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 0, 0, 0, 0, 0, 0, 0, 7,
    ];

    fn policy() -> NetworkPolicy {
        NetworkPolicy {
            confidentiality: ConfidentialityPolicy::Encrypt,
            max_frame_size: 1_514,
            max_flood_peers: 32,
            flood_rate: 1_000,
            flood_burst: 2_000,
            mac_age_seconds: 300,
            heartbeat_seconds: 10,
            peer_lease_seconds: 30,
            session_lifetime_seconds: 900,
            reassembly_timeout_ms: 3_000,
            network_id: NetworkId::from_bytes([
                0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
            ]),
            policy_revision: 7,
        }
    }

    #[test]
    fn network_policy_matches_canonical_bytes_and_round_trips() {
        let mut encoded = [0; NETWORK_POLICY_LENGTH];

        assert_eq!(policy().encode(&mut encoded), Ok(()));
        assert_eq!(encoded, POLICY_BYTES);
        assert_eq!(NetworkPolicy::decode(&encoded), Ok(policy()));
    }

    #[test]
    fn network_policy_rejects_format_and_reserved_errors() {
        let mut encoded = POLICY_BYTES;
        encoded[0] ^= 1;
        assert_eq!(
            NetworkPolicy::decode(&encoded),
            Err(CodecError::InvalidObjectMagic {
                object: "network policy",
            })
        );

        encoded = POLICY_BYTES;
        encoded[4] = 2;
        assert_eq!(
            NetworkPolicy::decode(&encoded),
            Err(CodecError::UnsupportedObjectVersion {
                object: "network policy",
                version: 2,
            })
        );

        encoded = POLICY_BYTES;
        encoded[5] = 2;
        assert_eq!(
            NetworkPolicy::decode(&encoded),
            Err(CodecError::InvalidEnumValue {
                field: "confidentiality policy",
                value: 2,
            })
        );

        encoded = POLICY_BYTES;
        encoded[39] = 1;
        assert_eq!(
            NetworkPolicy::decode(&encoded),
            Err(CodecError::NonZeroReserved {
                field: "network policy reserved",
                offset: 36,
            })
        );
    }

    #[test]
    fn network_policy_validates_dependent_limits_and_nonzero_values() {
        let mut candidate = policy();
        candidate.flood_burst = candidate.flood_rate - 1;
        assert_eq!(
            candidate.validate(),
            Err(CodecError::ValueOutOfRange {
                field: "flood burst",
                actual: 999,
                minimum: 1_000,
                maximum: 2_000_000,
            })
        );

        candidate = policy();
        candidate.peer_lease_seconds = 29;
        assert_eq!(
            candidate.validate(),
            Err(CodecError::ValueOutOfRange {
                field: "peer lease seconds",
                actual: 29,
                minimum: 30,
                maximum: 900,
            })
        );

        candidate = policy();
        candidate.network_id = NetworkId::from_bytes([0; NetworkId::LENGTH]);
        assert_eq!(
            candidate.validate(),
            Err(CodecError::ZeroField {
                field: "network ID",
            })
        );

        candidate = policy();
        candidate.policy_revision = 0;
        assert_eq!(
            candidate.validate(),
            Err(CodecError::ZeroField {
                field: "policy revision",
            })
        );
    }

    #[test]
    fn network_policy_rejects_wrong_record_and_output_lengths() {
        assert_eq!(
            NetworkPolicy::decode(&POLICY_BYTES[..NETWORK_POLICY_LENGTH - 1]),
            Err(CodecError::Truncated {
                field: "network policy",
                offset: NETWORK_POLICY_LENGTH - 1,
                needed: 1,
                remaining: 0,
            })
        );
        assert_eq!(
            NetworkPolicy::decode(&[POLICY_BYTES.as_slice(), &[0]].concat()),
            Err(CodecError::TrailingBytes {
                expected: NETWORK_POLICY_LENGTH,
                actual: NETWORK_POLICY_LENGTH + 1,
            })
        );

        let mut short = [0; NETWORK_POLICY_LENGTH - 1];
        assert_eq!(
            policy().encode(&mut short),
            Err(CodecError::OutputTooSmall {
                field: "policy revision",
                offset: 56,
                needed: 8,
                remaining: 7,
            })
        );

        assert_eq!(NETWORK_POLICY_MAGIC, *b"SNP1");
    }
}
