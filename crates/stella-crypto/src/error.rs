//! Typed cryptographic failures without secret-bearing diagnostics.

use thiserror::Error;

/// Error returned by Stella cryptographic operations.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
#[non_exhaustive]
pub enum CryptoError {
    /// The operating system could not supply cryptographic randomness.
    #[error("operating-system cryptographic randomness is unavailable")]
    RandomnessUnavailable,
    /// A compressed Ed25519 public key is not valid.
    #[error("invalid Ed25519 public key")]
    InvalidEd25519PublicKey,
    /// An Ed25519 signature did not verify.
    #[error("Ed25519 signature verification failed")]
    SignatureVerificationFailed,
    /// A domain-separated signature input exceeds the implementation bound.
    #[error("signature input length {actual} exceeds maximum {maximum}")]
    SignatureInputTooLarge {
        /// Calculated input length.
        actual: usize,
        /// Maximum accepted input length.
        maximum: usize,
    },
    /// Bounded signature-input storage could not be reserved.
    #[error("unable to allocate bounded signature input")]
    SignatureInputAllocationFailed,
    /// A claimed identity identifier does not match its public key.
    #[error("{identity} identifier does not match its Ed25519 public key")]
    IdentityMismatch {
        /// Stable identity role name.
        identity: &'static str,
    },
    /// X25519 produced an all-zero, non-contributory shared secret.
    #[error("X25519 key agreement was non-contributory")]
    NonContributoryKeyAgreement,
    /// HKDF could not expand one of the fixed-length session outputs.
    #[error("HKDF session-key expansion failed")]
    KeyDerivationFailed,
    /// Packet sequence zero cannot be used to construct a nonce.
    #[error("protected-packet sequence number must be non-zero")]
    InvalidSequenceNumber,
    /// A bounded packet-protection input exceeds its protocol limit.
    #[error("protected input length {actual} exceeds maximum {maximum}")]
    ProtectedInputTooLarge {
        /// Calculated input length.
        actual: usize,
        /// Maximum accepted input length.
        maximum: usize,
    },
    /// Caller-provided plaintext or ciphertext output storage is too small.
    #[error("packet-protection output has {remaining} bytes but needs {needed}")]
    ProtectionOutputTooSmall {
        /// Required output length.
        needed: usize,
        /// Available output length.
        remaining: usize,
    },
    /// A session-confirmation payload prefix is not exactly 40 bytes.
    #[error("confirmation authenticated payload has length {actual}, expected {expected}")]
    InvalidConfirmationPayloadLength {
        /// Actual payload-prefix length.
        actual: usize,
        /// Required payload-prefix length.
        expected: usize,
    },
    /// Bounded temporary packet-protection storage could not be reserved.
    #[error("unable to allocate bounded packet-protection storage")]
    PacketProtectionAllocationFailed,
    /// ChaCha20-Poly1305 could not protect a structurally bounded input.
    #[error("ChaCha20-Poly1305 packet protection failed")]
    PacketProtectionFailed,
    /// A ChaCha20-Poly1305 authentication tag did not verify.
    #[error("ChaCha20-Poly1305 authentication failed")]
    AuthenticationFailed,
}
