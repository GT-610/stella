//! Signed membership-grant codec.

use std::ops::{BitOr, BitOrAssign};

use stella_common::{ControllerId, GrantSerial, NetworkId, NodeId};

use crate::{
    bounds::validate_range,
    common::validate_record_length,
    cursor::{ReadCursor, WriteCursor},
    CodecError, ConfidentialityPolicy, NetworkPolicy, MAX_ETHERNET_FRAME_LENGTH,
};

/// Magic at the beginning of a membership grant.
pub const MEMBERSHIP_GRANT_MAGIC: [u8; 4] = *b"SML1";

/// Current membership-grant format version.
pub const MEMBERSHIP_GRANT_FORMAT_VERSION: u8 = 1;

/// Exact encoded length of a membership grant.
pub const MEMBERSHIP_GRANT_LENGTH: usize = 240;

/// Length of the signed grant body before its Ed25519 signature.
pub const MEMBERSHIP_GRANT_SIGNED_BODY_LENGTH: usize = 176;

/// Length of the Ed25519 signature stored in a membership grant.
pub const ED25519_SIGNATURE_LENGTH: usize = 64;

/// Signature-domain prefix for membership grant format version 1.
pub const MEMBERSHIP_GRANT_SIGNATURE_DOMAIN: &[u8] = b"stella membership grant v1";

/// Maximum permitted membership-grant lifetime in seconds.
pub const MAX_MEMBERSHIP_GRANT_LIFETIME_SECONDS: u64 = 24 * 60 * 60;

/// Validated membership permission bits.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct MembershipPermissions(u16);

impl MembershipPermissions {
    /// No data-plane permission.
    pub const NONE: Self = Self(0);

    /// Permission to originate Ethernet frames.
    pub const SEND_DATA: Self = Self(0x0001);

    /// Permission to receive Ethernet frames.
    pub const RECEIVE_DATA: Self = Self(0x0002);

    /// All permissions defined by grant format version 1.
    pub const ALL: Self = Self(Self::SEND_DATA.0 | Self::RECEIVE_DATA.0);

    /// Validates and creates a permission mask from wire bits.
    ///
    /// # Errors
    ///
    /// Returns [`CodecError::ReservedBits`] when any undefined bit is set.
    pub fn from_bits(bits: u16) -> Result<Self, CodecError> {
        if bits & !Self::ALL.0 != 0 {
            return Err(CodecError::ReservedBits {
                field: "membership permissions",
                bits: u64::from(bits),
                allowed: u64::from(Self::ALL.0),
            });
        }
        Ok(Self(bits))
    }

    /// Returns the canonical permission bits.
    #[must_use]
    pub const fn bits(self) -> u16 {
        self.0
    }

    /// Returns whether all bits in `permission` are present.
    #[must_use]
    pub const fn contains(self, permission: Self) -> bool {
        self.0 & permission.0 == permission.0
    }

    /// Returns whether the node may originate Ethernet frames.
    #[must_use]
    pub const fn can_send_data(self) -> bool {
        self.contains(Self::SEND_DATA)
    }

    /// Returns whether the node may receive Ethernet frames.
    #[must_use]
    pub const fn can_receive_data(self) -> bool {
        self.contains(Self::RECEIVE_DATA)
    }
}

impl BitOr for MembershipPermissions {
    type Output = Self;

    fn bitor(self, rhs: Self) -> Self::Output {
        Self(self.0 | rhs.0)
    }
}

impl BitOrAssign for MembershipPermissions {
    fn bitor_assign(&mut self, rhs: Self) {
        self.0 |= rhs.0;
    }
}

/// Parsed membership-grant fields excluding the trailing signature.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MembershipGrant {
    /// Required data-plane confidentiality.
    pub confidentiality: ConfidentialityPolicy,
    /// Authorized data-plane operations.
    pub permissions: MembershipPermissions,
    /// Authorized virtual network.
    pub network_id: NetworkId,
    /// Authorized node identity.
    pub node_id: NodeId,
    /// Ed25519 public key that must derive `node_id`.
    pub node_public_key: [u8; 32],
    /// Controller identity whose key signs this grant.
    pub controller_id: ControllerId,
    /// Non-zero controller epoch authorizing this membership.
    pub controller_epoch: u64,
    /// Inclusive Unix validity start in seconds.
    pub not_before: u64,
    /// Exclusive Unix validity end in seconds.
    pub not_after: u64,
    /// Largest complete Ethernet frame accepted by the network.
    pub max_frame_size: u16,
    /// Maximum number of nodes in one sender-side flood operation.
    pub max_flood_peers: u16,
    /// Maximum locally originated flood frames per second.
    pub flood_rate: u32,
    /// Maximum local flood token-bucket burst.
    pub flood_burst: u32,
    /// SHA-256 digest of canonical network-policy bytes.
    pub policy_digest: [u8; 32],
    /// Non-zero controller-unique grant serial.
    pub grant_serial: GrantSerial,
}

impl MembershipGrant {
    /// Encodes the exact 176-byte body covered by the controller signature.
    ///
    /// # Errors
    ///
    /// Returns [`CodecError`] when a grant invariant is invalid or `output` is
    /// too small.
    pub fn encode_signed_body(self, output: &mut [u8]) -> Result<(), CodecError> {
        self.validate()?;
        let mut cursor = WriteCursor::new(output, 0);
        cursor.write_bytes(&MEMBERSHIP_GRANT_MAGIC, "membership grant magic")?;
        cursor.write_u8(
            MEMBERSHIP_GRANT_FORMAT_VERSION,
            "membership grant format version",
        )?;
        cursor.write_u8(self.confidentiality.as_u8(), "confidentiality policy")?;
        cursor.write_u16(self.permissions.bits(), "membership permissions")?;
        cursor.write_u16(
            u16::try_from(MEMBERSHIP_GRANT_LENGTH).map_err(|_| CodecError::IntegerOverflow {
                field: "membership grant length",
            })?,
            "membership grant total length",
        )?;
        cursor.write_u16(0, "membership grant reserved")?;
        cursor.write_bytes(self.network_id.as_bytes(), "network ID")?;
        cursor.write_bytes(self.node_id.as_bytes(), "node ID")?;
        cursor.write_bytes(&self.node_public_key, "node public key")?;
        cursor.write_bytes(self.controller_id.as_bytes(), "controller ID")?;
        cursor.write_u64(self.controller_epoch, "controller epoch")?;
        cursor.write_u64(self.not_before, "not before")?;
        cursor.write_u64(self.not_after, "not after")?;
        cursor.write_u16(self.max_frame_size, "maximum frame size")?;
        cursor.write_u16(self.max_flood_peers, "maximum flood peers")?;
        cursor.write_u32(self.flood_rate, "flood rate")?;
        cursor.write_u32(self.flood_burst, "flood burst")?;
        cursor.write_bytes(&self.policy_digest, "policy digest")?;
        cursor.write_bytes(self.grant_serial.as_bytes(), "grant serial")?;
        Ok(())
    }

    /// Validates every non-cryptographic membership-grant invariant.
    ///
    /// Node and controller identifier derivation, policy hashing, signature
    /// verification, current-time checks, epoch freshness, and revocation are
    /// deliberately left to the cryptographic and state layers.
    ///
    /// # Errors
    ///
    /// Returns [`CodecError`] for reserved permission bits, a zero network,
    /// epoch, or serial, an invalid time interval, an excessive lifetime, or
    /// a frame or flood limit outside protocol bounds.
    pub fn validate(self) -> Result<(), CodecError> {
        let _ = MembershipPermissions::from_bits(self.permissions.bits())?;
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
        if self.grant_serial.is_zero() {
            return Err(CodecError::ZeroField {
                field: "grant serial",
            });
        }
        if self.not_before >= self.not_after {
            return Err(CodecError::InvalidTimeRange {
                not_before: self.not_before,
                not_after: self.not_after,
            });
        }
        let lifetime =
            self.not_after
                .checked_sub(self.not_before)
                .ok_or(CodecError::IntegerOverflow {
                    field: "membership grant lifetime",
                })?;
        if lifetime > MAX_MEMBERSHIP_GRANT_LIFETIME_SECONDS {
            return Err(CodecError::LifetimeTooLong {
                actual: lifetime,
                maximum: MAX_MEMBERSHIP_GRANT_LIFETIME_SECONDS,
            });
        }
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
        Ok(())
    }

    /// Checks grant fields that must match canonical network policy.
    ///
    /// The caller supplies the SHA-256 digest of the exact encoded policy so
    /// this pure codec does not select or invoke a hashing implementation.
    ///
    /// # Errors
    ///
    /// Returns [`CodecError::InconsistentField`] for the first mismatched
    /// network, confidentiality, frame limit, flood limit, or policy digest.
    pub fn validate_policy(
        self,
        policy: NetworkPolicy,
        encoded_policy_digest: &[u8; 32],
    ) -> Result<(), CodecError> {
        validate_consistency(self.network_id == policy.network_id, "network ID")?;
        validate_consistency(
            self.confidentiality == policy.confidentiality,
            "confidentiality policy",
        )?;
        validate_consistency(
            self.max_frame_size == policy.max_frame_size,
            "maximum frame size",
        )?;
        validate_consistency(
            self.max_flood_peers == policy.max_flood_peers,
            "maximum flood peers",
        )?;
        validate_consistency(self.flood_rate == policy.flood_rate, "flood rate")?;
        validate_consistency(self.flood_burst == policy.flood_burst, "flood burst")?;
        validate_consistency(
            &self.policy_digest == encoded_policy_digest,
            "policy digest",
        )?;
        Ok(())
    }
}

/// Borrowed membership grant with exact signature input ranges.
#[derive(Clone)]
pub struct MembershipGrantView<'a> {
    grant: MembershipGrant,
    signed_body: &'a [u8; MEMBERSHIP_GRANT_SIGNED_BODY_LENGTH],
    signature: &'a [u8; ED25519_SIGNATURE_LENGTH],
}

impl<'a> MembershipGrantView<'a> {
    /// Decodes one exact membership grant without copying its signature bytes.
    ///
    /// # Errors
    ///
    /// Returns [`CodecError`] when the record length, magic, format version,
    /// enum, permissions, declared length, reserved field, identifiers,
    /// validity interval, epoch, serial, or limits are invalid.
    pub fn decode(input: &'a [u8]) -> Result<Self, CodecError> {
        validate_record_length(input.len(), MEMBERSHIP_GRANT_LENGTH, "membership grant")?;
        let mut cursor = ReadCursor::new(input, 0);
        if cursor.read_array::<4>("membership grant magic")? != MEMBERSHIP_GRANT_MAGIC {
            return Err(CodecError::InvalidObjectMagic {
                object: "membership grant",
            });
        }
        let format_version = cursor.read_u8("membership grant format version")?;
        if format_version != MEMBERSHIP_GRANT_FORMAT_VERSION {
            return Err(CodecError::UnsupportedObjectVersion {
                object: "membership grant",
                version: format_version,
            });
        }
        let confidentiality =
            ConfidentialityPolicy::try_from(cursor.read_u8("confidentiality policy")?)?;
        let permissions =
            MembershipPermissions::from_bits(cursor.read_u16("membership permissions")?)?;
        let total_length = usize::from(cursor.read_u16("membership grant total length")?);
        if total_length != MEMBERSHIP_GRANT_LENGTH {
            return Err(CodecError::LengthMismatch {
                field: "membership grant total",
                expected: MEMBERSHIP_GRANT_LENGTH,
                actual: total_length,
            });
        }
        let reserved_offset = cursor.position();
        let reserved = cursor.read_u16("membership grant reserved")?;
        if reserved != 0 {
            return Err(CodecError::NonZeroReserved {
                field: "membership grant reserved",
                offset: reserved_offset,
            });
        }

        let grant = MembershipGrant {
            confidentiality,
            permissions,
            network_id: NetworkId::from_bytes(cursor.read_array("network ID")?),
            node_id: NodeId::from_bytes(cursor.read_array("node ID")?),
            node_public_key: cursor.read_array("node public key")?,
            controller_id: ControllerId::from_bytes(cursor.read_array("controller ID")?),
            controller_epoch: cursor.read_u64("controller epoch")?,
            not_before: cursor.read_u64("not before")?,
            not_after: cursor.read_u64("not after")?,
            max_frame_size: cursor.read_u16("maximum frame size")?,
            max_flood_peers: cursor.read_u16("maximum flood peers")?,
            flood_rate: cursor.read_u32("flood rate")?,
            flood_burst: cursor.read_u32("flood burst")?,
            policy_digest: cursor.read_array("policy digest")?,
            grant_serial: GrantSerial::from_bytes(cursor.read_array("grant serial")?),
        };
        grant.validate()?;

        let signed_body_bytes =
            input
                .get(..MEMBERSHIP_GRANT_SIGNED_BODY_LENGTH)
                .ok_or(CodecError::Truncated {
                    field: "membership grant signed body",
                    offset: 0,
                    needed: MEMBERSHIP_GRANT_SIGNED_BODY_LENGTH,
                    remaining: input.len(),
                })?;
        let signed_body = <&[u8; MEMBERSHIP_GRANT_SIGNED_BODY_LENGTH]>::try_from(signed_body_bytes)
            .map_err(|_| CodecError::LengthMismatch {
                field: "membership grant signed body",
                expected: MEMBERSHIP_GRANT_SIGNED_BODY_LENGTH,
                actual: signed_body_bytes.len(),
            })?;
        let signature_bytes = input
            .get(MEMBERSHIP_GRANT_SIGNED_BODY_LENGTH..MEMBERSHIP_GRANT_LENGTH)
            .ok_or(CodecError::Truncated {
                field: "membership grant signature",
                offset: MEMBERSHIP_GRANT_SIGNED_BODY_LENGTH,
                needed: ED25519_SIGNATURE_LENGTH,
                remaining: input
                    .len()
                    .saturating_sub(MEMBERSHIP_GRANT_SIGNED_BODY_LENGTH),
            })?;
        let signature =
            <&[u8; ED25519_SIGNATURE_LENGTH]>::try_from(signature_bytes).map_err(|_| {
                CodecError::LengthMismatch {
                    field: "membership grant signature",
                    expected: ED25519_SIGNATURE_LENGTH,
                    actual: signature_bytes.len(),
                }
            })?;

        Ok(Self {
            grant,
            signed_body,
            signature,
        })
    }

    /// Returns the parsed grant fields.
    #[must_use]
    pub const fn grant(&self) -> MembershipGrant {
        self.grant
    }

    /// Borrows the exact 176 bytes covered by the controller signature.
    #[must_use]
    pub const fn signed_body(&self) -> &'a [u8; MEMBERSHIP_GRANT_SIGNED_BODY_LENGTH] {
        self.signed_body
    }

    /// Borrows the Ed25519 controller signature.
    #[must_use]
    pub const fn signature(&self) -> &'a [u8; ED25519_SIGNATURE_LENGTH] {
        self.signature
    }
}

/// Encodes a complete signed membership grant.
///
/// # Errors
///
/// Returns [`CodecError`] when a grant invariant is invalid or `output` is too
/// small.
pub fn encode_membership_grant(
    grant: MembershipGrant,
    signature: &[u8; ED25519_SIGNATURE_LENGTH],
    output: &mut [u8],
) -> Result<(), CodecError> {
    let output_length = output.len();
    let grant_output =
        output
            .get_mut(..MEMBERSHIP_GRANT_LENGTH)
            .ok_or(CodecError::OutputTooSmall {
                field: "membership grant",
                offset: 0,
                needed: MEMBERSHIP_GRANT_LENGTH,
                remaining: output_length,
            })?;
    let (signed_body, signature_output) =
        grant_output.split_at_mut(MEMBERSHIP_GRANT_SIGNED_BODY_LENGTH);
    grant.encode_signed_body(signed_body)?;
    signature_output.copy_from_slice(signature);
    Ok(())
}

fn validate_consistency(matches: bool, field: &'static str) -> Result<(), CodecError> {
    if !matches {
        return Err(CodecError::InconsistentField {
            context: "membership grant and network policy",
            field,
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use stella_common::{ControllerId, GrantSerial, NetworkId, NodeId};

    use super::{
        encode_membership_grant, MembershipGrant, MembershipGrantView, MembershipPermissions,
        ED25519_SIGNATURE_LENGTH, MAX_MEMBERSHIP_GRANT_LIFETIME_SECONDS, MEMBERSHIP_GRANT_LENGTH,
        MEMBERSHIP_GRANT_SIGNATURE_DOMAIN, MEMBERSHIP_GRANT_SIGNED_BODY_LENGTH,
    };
    use crate::{CodecError, ConfidentialityPolicy, NetworkPolicy};

    const SIGNATURE: [u8; ED25519_SIGNATURE_LENGTH] = [0x40; ED25519_SIGNATURE_LENGTH];

    fn grant() -> MembershipGrant {
        MembershipGrant {
            confidentiality: ConfidentialityPolicy::Encrypt,
            permissions: MembershipPermissions::ALL,
            network_id: NetworkId::from_bytes([
                0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
            ]),
            node_id: NodeId::from_bytes([
                16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31,
            ]),
            node_public_key: [0x20; 32],
            controller_id: ControllerId::from_bytes([
                32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47,
            ]),
            controller_epoch: 5,
            not_before: 1_000,
            not_after: 2_000,
            max_frame_size: 1_514,
            max_flood_peers: 32,
            flood_rate: 1_000,
            flood_burst: 2_000,
            policy_digest: [0x30; 32],
            grant_serial: GrantSerial::from_bytes([
                48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 62, 63,
            ]),
        }
    }

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
            network_id: grant().network_id,
            policy_revision: 7,
        }
    }

    #[test]
    fn membership_grant_matches_canonical_fields_and_round_trips() {
        let mut encoded = [0; MEMBERSHIP_GRANT_LENGTH];
        encode_membership_grant(grant(), &SIGNATURE, &mut encoded).expect("valid membership grant");

        let expected_prefix = [0x53, 0x4d, 0x4c, 0x31, 1, 1, 0, 3, 0, 240, 0, 0];
        assert_eq!(&encoded[..12], &expected_prefix);
        assert_eq!(&encoded[12..28], grant().network_id.as_bytes());
        assert_eq!(&encoded[28..44], grant().node_id.as_bytes());
        assert_eq!(&encoded[44..76], &[0x20; 32]);
        assert_eq!(&encoded[76..92], grant().controller_id.as_bytes());
        assert_eq!(&encoded[92..100], &5_u64.to_be_bytes());
        assert_eq!(&encoded[100..108], &1_000_u64.to_be_bytes());
        assert_eq!(&encoded[108..116], &2_000_u64.to_be_bytes());
        assert_eq!(
            &encoded[116..128],
            &[0x05, 0xea, 0, 32, 0, 0, 3, 0xe8, 0, 0, 7, 0xd0]
        );
        assert_eq!(&encoded[128..160], &[0x30; 32]);
        assert_eq!(&encoded[160..176], grant().grant_serial.as_bytes());
        assert_eq!(&encoded[176..], &SIGNATURE);

        let decoded = MembershipGrantView::decode(&encoded).expect("valid membership grant");
        assert_eq!(decoded.grant(), grant());
        assert_eq!(
            decoded.signed_body(),
            &encoded[..MEMBERSHIP_GRANT_SIGNED_BODY_LENGTH]
        );
        assert_eq!(decoded.signature(), &SIGNATURE);
        assert_eq!(
            MEMBERSHIP_GRANT_SIGNATURE_DOMAIN,
            b"stella membership grant v1"
        );
    }

    #[test]
    fn permissions_validate_and_combine_defined_bits() {
        let mut permissions = MembershipPermissions::SEND_DATA;
        permissions |= MembershipPermissions::RECEIVE_DATA;

        assert_eq!(permissions, MembershipPermissions::ALL);
        assert!(permissions.can_send_data());
        assert!(permissions.can_receive_data());
        assert!(MembershipPermissions::NONE.contains(MembershipPermissions::NONE));
        assert_eq!(MembershipPermissions::from_bits(3), Ok(permissions));
        assert_eq!(
            MembershipPermissions::from_bits(4),
            Err(CodecError::ReservedBits {
                field: "membership permissions",
                bits: 4,
                allowed: 3,
            })
        );
    }

    #[test]
    fn membership_grant_rejects_format_reserved_and_permission_errors() {
        let mut encoded = [0; MEMBERSHIP_GRANT_LENGTH];
        encode_membership_grant(grant(), &SIGNATURE, &mut encoded).expect("valid membership grant");

        encoded[0] ^= 1;
        assert!(matches!(
            MembershipGrantView::decode(&encoded),
            Err(CodecError::InvalidObjectMagic {
                object: "membership grant"
            })
        ));

        encode_membership_grant(grant(), &SIGNATURE, &mut encoded).expect("valid membership grant");
        encoded[6] = 0x80;
        encoded[7] = 0;
        assert!(matches!(
            MembershipGrantView::decode(&encoded),
            Err(CodecError::ReservedBits {
                field: "membership permissions",
                bits: 0x8000,
                allowed: 3,
            })
        ));

        encode_membership_grant(grant(), &SIGNATURE, &mut encoded).expect("valid membership grant");
        encoded[11] = 1;
        assert!(matches!(
            MembershipGrantView::decode(&encoded),
            Err(CodecError::NonZeroReserved {
                field: "membership grant reserved",
                offset: 10,
            })
        ));
    }

    #[test]
    fn membership_grant_validates_time_epoch_serial_and_limits() {
        let mut candidate = grant();
        candidate.controller_epoch = 0;
        assert_eq!(
            candidate.validate(),
            Err(CodecError::ZeroField {
                field: "controller epoch",
            })
        );

        candidate = grant();
        candidate.grant_serial = GrantSerial::from_bytes([0; GrantSerial::LENGTH]);
        assert_eq!(
            candidate.validate(),
            Err(CodecError::ZeroField {
                field: "grant serial",
            })
        );

        candidate = grant();
        candidate.not_after = candidate.not_before;
        assert_eq!(
            candidate.validate(),
            Err(CodecError::InvalidTimeRange {
                not_before: 1_000,
                not_after: 1_000,
            })
        );

        candidate = grant();
        candidate.not_after = candidate.not_before + MAX_MEMBERSHIP_GRANT_LIFETIME_SECONDS + 1;
        assert_eq!(
            candidate.validate(),
            Err(CodecError::LifetimeTooLong {
                actual: MAX_MEMBERSHIP_GRANT_LIFETIME_SECONDS + 1,
                maximum: MAX_MEMBERSHIP_GRANT_LIFETIME_SECONDS,
            })
        );

        candidate = grant();
        candidate.max_flood_peers = 1;
        assert_eq!(
            candidate.validate(),
            Err(CodecError::ValueOutOfRange {
                field: "maximum flood peers",
                actual: 1,
                minimum: 2,
                maximum: 256,
            })
        );
    }

    #[test]
    fn membership_grant_checks_canonical_policy_consistency() {
        assert_eq!(grant().validate_policy(policy(), &[0x30; 32]), Ok(()));

        let mut changed = policy();
        changed.max_frame_size = 1_518;
        assert_eq!(
            grant().validate_policy(changed, &[0x30; 32]),
            Err(CodecError::InconsistentField {
                context: "membership grant and network policy",
                field: "maximum frame size",
            })
        );

        assert_eq!(
            grant().validate_policy(policy(), &[0x31; 32]),
            Err(CodecError::InconsistentField {
                context: "membership grant and network policy",
                field: "policy digest",
            })
        );
    }

    #[test]
    fn membership_grant_rejects_wrong_record_and_output_lengths() {
        let mut encoded = [0; MEMBERSHIP_GRANT_LENGTH];
        encode_membership_grant(grant(), &SIGNATURE, &mut encoded).expect("valid membership grant");
        assert!(matches!(
            MembershipGrantView::decode(&encoded[..MEMBERSHIP_GRANT_LENGTH - 1]),
            Err(CodecError::Truncated {
                field: "membership grant",
                offset,
                needed: 1,
                remaining: 0,
            }) if offset == MEMBERSHIP_GRANT_LENGTH - 1
        ));

        let mut with_trailer = encoded.to_vec();
        with_trailer.push(0);
        assert!(matches!(
            MembershipGrantView::decode(&with_trailer),
            Err(CodecError::TrailingBytes {
                expected: MEMBERSHIP_GRANT_LENGTH,
                actual,
            }) if actual == MEMBERSHIP_GRANT_LENGTH + 1
        ));

        let mut short = [0; MEMBERSHIP_GRANT_LENGTH - 1];
        assert_eq!(
            encode_membership_grant(grant(), &SIGNATURE, &mut short),
            Err(CodecError::OutputTooSmall {
                field: "membership grant",
                offset: 0,
                needed: MEMBERSHIP_GRANT_LENGTH,
                remaining: MEMBERSHIP_GRANT_LENGTH - 1,
            })
        );
    }
}
