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
}
