//! Identity, key establishment, packet protection, and replay defense for Stella.

#![forbid(unsafe_code)]

mod error;
mod hash;
mod identity;

pub use error::CryptoError;
pub use hash::{sha256_segments, SHA256_OUTPUT_LENGTH};
pub use identity::{
    derive_controller_id, derive_node_id, validate_controller_id, validate_node_id,
    IdentityPublicKey, IdentitySeed, IdentitySigningKey, CONTROLLER_ID_DOMAIN,
    ED25519_PUBLIC_KEY_LENGTH, ED25519_SIGNATURE_LENGTH, IDENTITY_SEED_LENGTH,
    MAX_SIGNATURE_INPUT_LENGTH, NODE_ID_DOMAIN,
};
