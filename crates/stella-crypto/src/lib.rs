//! Identity, key establishment, packet protection, and replay defense for Stella.

#![forbid(unsafe_code)]

mod error;
mod hash;
mod identity;
mod session;

pub use error::CryptoError;
pub use hash::{sha256_segments, SHA256_OUTPUT_LENGTH};
pub use identity::{
    derive_controller_id, derive_node_id, validate_controller_id, validate_node_id,
    IdentityPublicKey, IdentitySeed, IdentitySigningKey, CONTROLLER_ID_DOMAIN,
    ED25519_PUBLIC_KEY_LENGTH, ED25519_SIGNATURE_LENGTH, IDENTITY_SEED_LENGTH,
    MAX_SIGNATURE_INPUT_LENGTH, NODE_ID_DOMAIN,
};
pub use session::{
    derive_session_secrets, session_transcript_hash, EphemeralPublicKey, EphemeralSecret,
    SessionRole, SessionSecrets, SharedSecret, CONFIRMATION_KEY_LENGTH, DATA_KEY_LENGTH,
    INITIATOR_CONFIRMATION_INFO, INITIATOR_TO_RESPONDER_KEY_INFO,
    INITIATOR_TO_RESPONDER_NONCE_INFO, NONCE_PREFIX_LENGTH, RESPONDER_CONFIRMATION_INFO,
    RESPONDER_TO_INITIATOR_KEY_INFO, RESPONDER_TO_INITIATOR_NONCE_INFO, SESSION_TRANSCRIPT_DOMAIN,
    X25519_PUBLIC_KEY_LENGTH, X25519_SECRET_LENGTH,
};
