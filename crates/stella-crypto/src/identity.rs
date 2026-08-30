//! Ed25519 identity keys, signatures, and Stella identifier derivation.

use std::fmt;

use ed25519_dalek::{
    pkcs8::{DecodePrivateKey, EncodePrivateKey},
    Signature, Signer, SigningKey, VerifyingKey,
};
use stella_common::{ControllerId, NodeId};
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::{sha256_segments, CryptoError};

/// Length of an Ed25519 private seed.
pub const IDENTITY_SEED_LENGTH: usize = 32;

/// Length of a compressed Ed25519 public key.
pub const ED25519_PUBLIC_KEY_LENGTH: usize = 32;

/// Length of an Ed25519 signature.
pub const ED25519_SIGNATURE_LENGTH: usize = 64;

/// Maximum accepted Ed25519 PKCS#8 DER document length.
pub const MAX_IDENTITY_PKCS8_LENGTH: usize = 4_096;

/// Largest message assembled by the segmented signing helpers.
pub const MAX_SIGNATURE_INPUT_LENGTH: usize = 1_048_576;

/// Domain prefix used to derive a node identifier.
pub const NODE_ID_DOMAIN: &[u8] = b"stella node id v1";

/// Domain prefix used to derive a controller identifier.
pub const CONTROLLER_ID_DOMAIN: &[u8] = b"stella controller id v1";

/// Owned Ed25519 seed that redacts and clears its bytes.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct IdentitySeed([u8; IDENTITY_SEED_LENGTH]);

impl IdentitySeed {
    /// Wraps an existing Ed25519 seed for bounded secret ownership.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; IDENTITY_SEED_LENGTH]) -> Self {
        Self(bytes)
    }

    /// Generates a seed from the operating system cryptographic RNG.
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError::RandomnessUnavailable`] when the operating system
    /// random source fails.
    pub fn generate() -> Result<Self, CryptoError> {
        let mut bytes = [0_u8; IDENTITY_SEED_LENGTH];
        getrandom::fill(&mut bytes).map_err(|_| CryptoError::RandomnessUnavailable)?;
        Ok(Self(bytes))
    }

    /// Intentionally exposes the seed to a persistence or key-loading boundary.
    #[must_use]
    pub const fn expose_secret(&self) -> &[u8; IDENTITY_SEED_LENGTH] {
        &self.0
    }
}

impl fmt::Debug for IdentitySeed {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("IdentitySeed([REDACTED])")
    }
}

/// Owned PKCS#8 DER identity key that redacts and clears its bytes.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct IdentityPkcs8(Vec<u8>);

impl IdentityPkcs8 {
    /// Borrows the complete PKCS#8 DER document for persistence.
    #[must_use]
    pub fn expose_secret(&self) -> &[u8] {
        &self.0
    }
}

impl fmt::Debug for IdentityPkcs8 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("IdentityPkcs8([REDACTED])")
    }
}

/// Validated compressed Ed25519 public key.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct IdentityPublicKey([u8; ED25519_PUBLIC_KEY_LENGTH]);

impl IdentityPublicKey {
    /// Validates and constructs a compressed Ed25519 public key.
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError::InvalidEd25519PublicKey`] when the bytes are not a
    /// valid compressed Ed25519 point.
    pub fn from_bytes(bytes: [u8; ED25519_PUBLIC_KEY_LENGTH]) -> Result<Self, CryptoError> {
        let key =
            VerifyingKey::from_bytes(&bytes).map_err(|_| CryptoError::InvalidEd25519PublicKey)?;
        if key.is_weak() {
            return Err(CryptoError::InvalidEd25519PublicKey);
        }
        Ok(Self(bytes))
    }

    /// Borrows the standard compressed Ed25519 bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; ED25519_PUBLIC_KEY_LENGTH] {
        &self.0
    }

    /// Returns the standard compressed Ed25519 bytes.
    #[must_use]
    pub const fn to_bytes(self) -> [u8; ED25519_PUBLIC_KEY_LENGTH] {
        self.0
    }

    /// Verifies an Ed25519 signature over one contiguous message.
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError`] when the stored key cannot be reconstructed or
    /// the signature does not pass strict Ed25519 verification.
    pub fn verify(
        self,
        message: &[u8],
        signature: &[u8; ED25519_SIGNATURE_LENGTH],
    ) -> Result<(), CryptoError> {
        let verifying_key =
            VerifyingKey::from_bytes(&self.0).map_err(|_| CryptoError::InvalidEd25519PublicKey)?;
        let signature = Signature::from_bytes(signature);
        verifying_key
            .verify_strict(message, &signature)
            .map_err(|_| CryptoError::SignatureVerificationFailed)
    }

    /// Verifies a signature over `domain || segments[0] || ...`.
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError`] when the bounded input cannot be assembled, the
    /// public key is invalid, or signature verification fails.
    pub fn verify_segments(
        self,
        domain: &[u8],
        segments: &[&[u8]],
        signature: &[u8; ED25519_SIGNATURE_LENGTH],
    ) -> Result<(), CryptoError> {
        let message = assemble_signature_input(domain, segments)?;
        self.verify(&message, signature)
    }
}

impl fmt::Debug for IdentityPublicKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("IdentityPublicKey(")?;
        for byte in self.0 {
            write!(formatter, "{byte:02x}")?;
        }
        formatter.write_str(")")
    }
}

/// Owned Ed25519 signing key with redacted diagnostics.
pub struct IdentitySigningKey(SigningKey);

impl IdentitySigningKey {
    /// Restores a signing key from an owned secret seed.
    #[must_use]
    pub fn from_seed(seed: &IdentitySeed) -> Self {
        Self(SigningKey::from_bytes(seed.expose_secret()))
    }

    /// Restores an Ed25519 signing key from unencrypted PKCS#8 DER.
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError::InvalidIdentityPrivateKey`] when the document is
    /// empty, oversized, malformed, uses another algorithm, or has invalid
    /// Ed25519 key material.
    pub fn from_pkcs8_der(der: &[u8]) -> Result<Self, CryptoError> {
        if der.is_empty() || der.len() > MAX_IDENTITY_PKCS8_LENGTH {
            return Err(CryptoError::InvalidIdentityPrivateKey);
        }
        let signing =
            SigningKey::from_pkcs8_der(der).map_err(|_| CryptoError::InvalidIdentityPrivateKey)?;
        if signing.verifying_key().is_weak() {
            return Err(CryptoError::InvalidIdentityPrivateKey);
        }
        Ok(Self(signing))
    }

    /// Generates a new signing key with operating-system randomness.
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError::RandomnessUnavailable`] when the operating system
    /// random source fails.
    pub fn generate() -> Result<Self, CryptoError> {
        let seed = IdentitySeed::generate()?;
        Ok(Self::from_seed(&seed))
    }

    /// Returns the corresponding validated public key.
    #[must_use]
    pub fn public_key(&self) -> IdentityPublicKey {
        IdentityPublicKey(self.0.verifying_key().to_bytes())
    }

    /// Copies the private seed into a new zeroizing wrapper for persistence.
    #[must_use]
    pub fn export_seed(&self) -> IdentitySeed {
        IdentitySeed::from_bytes(self.0.to_bytes())
    }

    /// Encodes this identity as an unencrypted PKCS#8 DER document.
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError`] when the audited encoder fails or bounded
    /// secret storage cannot be allocated.
    pub fn to_pkcs8_der(&self) -> Result<IdentityPkcs8, CryptoError> {
        let document = self
            .0
            .to_pkcs8_der()
            .map_err(|_| CryptoError::IdentityPrivateKeyEncodingFailed)?;
        let encoded = document.as_bytes();
        if encoded.is_empty() || encoded.len() > MAX_IDENTITY_PKCS8_LENGTH {
            return Err(CryptoError::IdentityPrivateKeyEncodingFailed);
        }
        let mut owned = Vec::new();
        owned
            .try_reserve_exact(encoded.len())
            .map_err(|_| CryptoError::SecretMaterialAllocationFailed)?;
        owned.extend_from_slice(encoded);
        Ok(IdentityPkcs8(owned))
    }

    /// Signs one contiguous message with Ed25519.
    #[must_use]
    pub fn sign(&self, message: &[u8]) -> [u8; ED25519_SIGNATURE_LENGTH] {
        self.0.sign(message).to_bytes()
    }

    /// Signs `domain || segments[0] || ...` with exact concatenation.
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError`] when checked length arithmetic exceeds the
    /// bounded input size or storage cannot be reserved.
    pub fn sign_segments(
        &self,
        domain: &[u8],
        segments: &[&[u8]],
    ) -> Result<[u8; ED25519_SIGNATURE_LENGTH], CryptoError> {
        let message = assemble_signature_input(domain, segments)?;
        Ok(self.sign(&message))
    }
}

impl fmt::Debug for IdentitySigningKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("IdentitySigningKey([REDACTED])")
    }
}

/// Derives the stable Stella node identifier for an Ed25519 public key.
#[must_use]
pub fn derive_node_id(public_key: IdentityPublicKey) -> NodeId {
    let digest = sha256_segments(&[NODE_ID_DOMAIN, public_key.as_bytes()]);
    let mut bytes = [0_u8; NodeId::LENGTH];
    bytes.copy_from_slice(&digest[..NodeId::LENGTH]);
    NodeId::from_bytes(bytes)
}

/// Derives the stable Stella controller identifier for an Ed25519 public key.
#[must_use]
pub fn derive_controller_id(public_key: IdentityPublicKey) -> ControllerId {
    let digest = sha256_segments(&[CONTROLLER_ID_DOMAIN, public_key.as_bytes()]);
    let mut bytes = [0_u8; ControllerId::LENGTH];
    bytes.copy_from_slice(&digest[..ControllerId::LENGTH]);
    ControllerId::from_bytes(bytes)
}

/// Validates a claimed node identifier in constant time.
///
/// # Errors
///
/// Returns [`CryptoError::IdentityMismatch`] when the identifier does not match
/// the public key.
pub fn validate_node_id(claimed: NodeId, public_key: IdentityPublicKey) -> Result<(), CryptoError> {
    let derived = derive_node_id(public_key);
    validate_identifier(claimed.as_bytes(), derived.as_bytes(), "node")
}

/// Validates a claimed controller identifier in constant time.
///
/// # Errors
///
/// Returns [`CryptoError::IdentityMismatch`] when the identifier does not match
/// the public key.
pub fn validate_controller_id(
    claimed: ControllerId,
    public_key: IdentityPublicKey,
) -> Result<(), CryptoError> {
    let derived = derive_controller_id(public_key);
    validate_identifier(claimed.as_bytes(), derived.as_bytes(), "controller")
}

fn validate_identifier(
    claimed: &[u8; 16],
    derived: &[u8; 16],
    identity: &'static str,
) -> Result<(), CryptoError> {
    if !bool::from(claimed.ct_eq(derived)) {
        return Err(CryptoError::IdentityMismatch { identity });
    }
    Ok(())
}

fn assemble_signature_input(domain: &[u8], segments: &[&[u8]]) -> Result<Vec<u8>, CryptoError> {
    let mut total = domain.len();
    for segment in segments {
        total = total
            .checked_add(segment.len())
            .ok_or(CryptoError::SignatureInputTooLarge {
                actual: usize::MAX,
                maximum: MAX_SIGNATURE_INPUT_LENGTH,
            })?;
    }
    if total > MAX_SIGNATURE_INPUT_LENGTH {
        return Err(CryptoError::SignatureInputTooLarge {
            actual: total,
            maximum: MAX_SIGNATURE_INPUT_LENGTH,
        });
    }
    let mut message = Vec::new();
    message
        .try_reserve_exact(total)
        .map_err(|_| CryptoError::SignatureInputAllocationFailed)?;
    message.extend_from_slice(domain);
    for segment in segments {
        message.extend_from_slice(segment);
    }
    Ok(message)
}

#[cfg(test)]
mod tests {
    use stella_common::{ControllerId, NodeId};
    use zeroize::Zeroize;

    use super::{
        derive_controller_id, derive_node_id, validate_controller_id, validate_node_id,
        IdentityPublicKey, IdentitySeed, IdentitySigningKey, MAX_IDENTITY_PKCS8_LENGTH,
    };
    use crate::CryptoError;

    const RFC8032_SEED: [u8; 32] = [
        0x9d, 0x61, 0xb1, 0x9d, 0xef, 0xfd, 0x5a, 0x60, 0xba, 0x84, 0x4a, 0xf4, 0x92, 0xec, 0x2c,
        0xc4, 0x44, 0x49, 0xc5, 0x69, 0x7b, 0x32, 0x69, 0x19, 0x70, 0x3b, 0xac, 0x03, 0x1c, 0xae,
        0x7f, 0x60,
    ];
    const RFC8032_PUBLIC: [u8; 32] = [
        0xd7, 0x5a, 0x98, 0x01, 0x82, 0xb1, 0x0a, 0xb7, 0xd5, 0x4b, 0xfe, 0xd3, 0xc9, 0x64, 0x07,
        0x3a, 0x0e, 0xe1, 0x72, 0xf3, 0xda, 0xa6, 0x23, 0x25, 0xaf, 0x02, 0x1a, 0x68, 0xf7, 0x07,
        0x51, 0x1a,
    ];
    const RFC8032_SIGNATURE: [u8; 64] = [
        0xe5, 0x56, 0x43, 0x00, 0xc3, 0x60, 0xac, 0x72, 0x90, 0x86, 0xe2, 0xcc, 0x80, 0x6e, 0x82,
        0x8a, 0x84, 0x87, 0x7f, 0x1e, 0xb8, 0xe5, 0xd9, 0x74, 0xd8, 0x73, 0xe0, 0x65, 0x22, 0x49,
        0x01, 0x55, 0x5f, 0xb8, 0x82, 0x15, 0x90, 0xa3, 0x3b, 0xac, 0xc6, 0x1e, 0x39, 0x70, 0x1c,
        0xf9, 0xb4, 0x6b, 0xd2, 0x5b, 0xf5, 0xf0, 0x59, 0x5b, 0xbe, 0x24, 0x65, 0x51, 0x41, 0x43,
        0x8e, 0x7a, 0x10, 0x0b,
    ];

    fn signing_key() -> IdentitySigningKey {
        IdentitySigningKey::from_seed(&IdentitySeed::from_bytes(RFC8032_SEED))
    }

    #[test]
    fn ed25519_matches_rfc8032_empty_message_vector() {
        let signing = signing_key();
        let public = signing.public_key();

        assert_eq!(public.to_bytes(), RFC8032_PUBLIC);
        assert_eq!(signing.sign(b""), RFC8032_SIGNATURE);
        assert_eq!(public.verify(b"", &RFC8032_SIGNATURE), Ok(()));
    }

    #[test]
    fn strict_verification_rejects_mutated_message_and_signature() {
        let public = signing_key().public_key();
        assert_eq!(
            public.verify(b"x", &RFC8032_SIGNATURE),
            Err(CryptoError::SignatureVerificationFailed)
        );
        let mut signature = RFC8032_SIGNATURE;
        signature[0] ^= 1;
        assert_eq!(
            public.verify(b"", &signature),
            Err(CryptoError::SignatureVerificationFailed)
        );
    }

    #[test]
    fn segmented_signature_is_exact_domain_concatenation() {
        let signing = signing_key();
        let segmented = signing
            .sign_segments(b"domain", &[b"one", b"two"])
            .expect("bounded signature input");
        assert_eq!(segmented, signing.sign(b"domainonetwo"));
        assert_eq!(
            signing
                .public_key()
                .verify_segments(b"domain", &[b"one", b"two"], &segmented),
            Ok(())
        );
    }

    #[test]
    fn stella_identity_ids_match_fixed_vectors() {
        let public = IdentityPublicKey::from_bytes(RFC8032_PUBLIC).expect("valid public key");
        let node = NodeId::from_bytes([
            0x6d, 0x21, 0xf7, 0xc1, 0x58, 0x50, 0xef, 0xd5, 0xe3, 0x7b, 0x20, 0x81, 0xa8, 0x67,
            0x39, 0xb6,
        ]);
        let controller = ControllerId::from_bytes([
            0xed, 0x87, 0x3f, 0xff, 0xe0, 0x03, 0xc9, 0xd3, 0x5a, 0x8e, 0x53, 0x4d, 0x66, 0x5d,
            0xca, 0x0e,
        ]);

        assert_eq!(derive_node_id(public), node);
        assert_eq!(derive_controller_id(public), controller);
        assert_eq!(validate_node_id(node, public), Ok(()));
        assert_eq!(validate_controller_id(controller, public), Ok(()));
    }

    #[test]
    fn identity_validation_and_public_key_parsing_reject_mismatches() {
        let public = signing_key().public_key();
        assert_eq!(
            validate_node_id(NodeId::from_bytes([0; 16]), public),
            Err(CryptoError::IdentityMismatch { identity: "node" })
        );
        assert_eq!(
            IdentityPublicKey::from_bytes([0; 32]),
            Err(CryptoError::InvalidEd25519PublicKey)
        );
    }

    #[test]
    fn secrets_redact_debug_and_seed_zeroizes() {
        let mut seed = IdentitySeed::from_bytes([0x5a; 32]);
        assert_eq!(format!("{seed:?}"), "IdentitySeed([REDACTED])");
        assert_eq!(
            format!("{:?}", IdentitySigningKey::from_seed(&seed)),
            "IdentitySigningKey([REDACTED])"
        );
        seed.zeroize();
        assert_eq!(seed.expose_secret(), &[0; 32]);
    }

    #[test]
    fn pkcs8_round_trip_preserves_identity_and_redacts_der() {
        let signing = signing_key();
        let encoded = signing.to_pkcs8_der().expect("PKCS#8 encoding succeeds");
        assert_eq!(format!("{encoded:?}"), "IdentityPkcs8([REDACTED])");
        let decoded = IdentitySigningKey::from_pkcs8_der(encoded.expose_secret())
            .expect("encoded key decodes");
        assert_eq!(decoded.public_key(), signing.public_key());
        assert_eq!(decoded.sign(b"stella"), signing.sign(b"stella"));
    }

    #[test]
    fn pkcs8_decoder_rejects_empty_malformed_and_oversized_documents() {
        assert!(matches!(
            IdentitySigningKey::from_pkcs8_der(&[]),
            Err(CryptoError::InvalidIdentityPrivateKey)
        ));
        assert!(matches!(
            IdentitySigningKey::from_pkcs8_der(&[0x30, 0x01, 0]),
            Err(CryptoError::InvalidIdentityPrivateKey)
        ));
        let oversized = vec![0; MAX_IDENTITY_PKCS8_LENGTH + 1];
        assert!(matches!(
            IdentitySigningKey::from_pkcs8_der(&oversized),
            Err(CryptoError::InvalidIdentityPrivateKey)
        ));
    }
}
