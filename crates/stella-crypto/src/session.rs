//! Ephemeral X25519 agreement and HKDF-SHA256 session derivation.

use std::fmt;

use hkdf::Hkdf;
use sha2::Sha256;
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::Zeroizing;

use crate::{sha256_segments, CryptoError, SHA256_OUTPUT_LENGTH};
use crate::{ConfirmationAuthenticator, PacketProtector, SessionProtectors};

/// Length of an X25519 private scalar input.
pub const X25519_SECRET_LENGTH: usize = 32;

/// Length of an X25519 public key.
pub const X25519_PUBLIC_KEY_LENGTH: usize = 32;

/// Length of one directional ChaCha20-Poly1305 data key.
pub const DATA_KEY_LENGTH: usize = 32;

/// Length of one directional packet nonce prefix.
pub const NONCE_PREFIX_LENGTH: usize = 4;

/// Length of one session-confirmation key.
pub const CONFIRMATION_KEY_LENGTH: usize = 32;

/// Domain prefix for the complete signed peer-handshake transcript.
pub const SESSION_TRANSCRIPT_DOMAIN: &[u8] = b"stella session transcript v1";

/// HKDF info for the initiator-to-responder data key.
pub const INITIATOR_TO_RESPONDER_KEY_INFO: &[u8] = b"stella data i2r key v1";

/// HKDF info for the responder-to-initiator data key.
pub const RESPONDER_TO_INITIATOR_KEY_INFO: &[u8] = b"stella data r2i key v1";

/// HKDF info for the initiator-to-responder nonce prefix.
pub const INITIATOR_TO_RESPONDER_NONCE_INFO: &[u8] = b"stella data i2r nonce v1";

/// HKDF info for the responder-to-initiator nonce prefix.
pub const RESPONDER_TO_INITIATOR_NONCE_INFO: &[u8] = b"stella data r2i nonce v1";

/// HKDF info for the initiator confirmation key.
pub const INITIATOR_CONFIRMATION_INFO: &[u8] = b"stella confirm initiator v1";

/// HKDF info for the responder confirmation key.
pub const RESPONDER_CONFIRMATION_INFO: &[u8] = b"stella confirm responder v1";

/// Local role in the signed peer-session handshake.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SessionRole {
    /// The node that sent `SESSION_INIT`.
    Initiator,
    /// The node that sent `SESSION_RESPONSE`.
    Responder,
}

/// Owned, non-cloneable ephemeral X25519 private key.
pub struct EphemeralSecret(StaticSecret);

impl EphemeralSecret {
    /// Constructs an ephemeral private key from fixed bytes.
    ///
    /// This constructor exists for deterministic tests and persisted handshake
    /// recovery. Normal handshakes should call [`Self::generate`].
    #[must_use]
    pub fn from_bytes(bytes: [u8; X25519_SECRET_LENGTH]) -> Self {
        Self(StaticSecret::from(bytes))
    }

    /// Generates a fresh ephemeral private key with operating-system randomness.
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError::RandomnessUnavailable`] when the operating system
    /// random source fails.
    pub fn generate() -> Result<Self, CryptoError> {
        let mut bytes = Zeroizing::new([0_u8; X25519_SECRET_LENGTH]);
        getrandom::fill(bytes.as_mut()).map_err(|_| CryptoError::RandomnessUnavailable)?;
        Ok(Self::from_bytes(*bytes))
    }

    /// Returns the public key corresponding to this ephemeral private key.
    #[must_use]
    pub fn public_key(&self) -> EphemeralPublicKey {
        EphemeralPublicKey(PublicKey::from(&self.0).to_bytes())
    }

    /// Consumes this private key and performs X25519 agreement.
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError::NonContributoryKeyAgreement`] when the peer key
    /// produces the all-zero shared secret.
    pub fn agree(self, peer: EphemeralPublicKey) -> Result<SharedSecret, CryptoError> {
        let peer = PublicKey::from(peer.0);
        let shared = self.0.diffie_hellman(&peer);
        if !shared.was_contributory() {
            return Err(CryptoError::NonContributoryKeyAgreement);
        }
        Ok(SharedSecret(Zeroizing::new(shared.to_bytes())))
    }
}

impl fmt::Debug for EphemeralSecret {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("EphemeralSecret([REDACTED])")
    }
}

/// Wire-format X25519 public key bytes.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct EphemeralPublicKey([u8; X25519_PUBLIC_KEY_LENGTH]);

impl EphemeralPublicKey {
    /// Constructs a peer public key from its 32-byte wire representation.
    ///
    /// X25519 accepts every byte string. Low-order inputs are rejected by the
    /// contributory check when agreement is attempted.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; X25519_PUBLIC_KEY_LENGTH]) -> Self {
        Self(bytes)
    }

    /// Borrows the 32-byte wire representation.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; X25519_PUBLIC_KEY_LENGTH] {
        &self.0
    }

    /// Returns the 32-byte wire representation.
    #[must_use]
    pub const fn to_bytes(self) -> [u8; X25519_PUBLIC_KEY_LENGTH] {
        self.0
    }
}

impl fmt::Debug for EphemeralPublicKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("EphemeralPublicKey(")?;
        for byte in self.0 {
            write!(formatter, "{byte:02x}")?;
        }
        formatter.write_str(")")
    }
}

/// Validated, non-cloneable X25519 shared secret awaiting HKDF derivation.
pub struct SharedSecret(Zeroizing<[u8; X25519_SECRET_LENGTH]>);

impl fmt::Debug for SharedSecret {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SharedSecret([REDACTED])")
    }
}

pub(crate) struct DirectionalSecrets {
    pub(crate) key: Zeroizing<[u8; DATA_KEY_LENGTH]>,
    pub(crate) nonce_prefix: [u8; NONCE_PREFIX_LENGTH],
}

/// Session material mapped to the local node's send and receive directions.
pub struct SessionSecrets {
    pub(crate) send: DirectionalSecrets,
    pub(crate) receive: DirectionalSecrets,
    pub(crate) local_confirmation: Zeroizing<[u8; CONFIRMATION_KEY_LENGTH]>,
    pub(crate) remote_confirmation: Zeroizing<[u8; CONFIRMATION_KEY_LENGTH]>,
}

impl SessionSecrets {
    /// Consumes derived material into directional packet and confirmation owners.
    #[must_use]
    pub fn into_protectors(self) -> SessionProtectors {
        SessionProtectors::new(
            PacketProtector::new(self.send.key, self.send.nonce_prefix),
            PacketProtector::new(self.receive.key, self.receive.nonce_prefix),
            ConfirmationAuthenticator::new(self.local_confirmation),
            ConfirmationAuthenticator::new(self.remote_confirmation),
        )
    }
}

impl fmt::Debug for SessionSecrets {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SessionSecrets([REDACTED])")
    }
}

/// Hashes the exact signed session-init and session-response datagrams.
#[must_use]
pub fn session_transcript_hash(
    session_init_datagram: &[u8],
    session_response_datagram: &[u8],
) -> [u8; SHA256_OUTPUT_LENGTH] {
    sha256_segments(&[
        SESSION_TRANSCRIPT_DOMAIN,
        session_init_datagram,
        session_response_datagram,
    ])
}

/// Derives and role-maps all six Stella peer-session outputs.
///
/// Each output uses an independent HKDF expansion from the same extract, with
/// the transcript hash as salt and the X25519 shared secret as input material.
///
/// # Errors
///
/// Returns [`CryptoError::KeyDerivationFailed`] if a fixed-length HKDF
/// expansion unexpectedly exceeds the algorithm limit.
pub fn derive_session_secrets(
    shared_secret: SharedSecret,
    transcript_hash: &[u8; SHA256_OUTPUT_LENGTH],
    role: SessionRole,
) -> Result<SessionSecrets, CryptoError> {
    let hkdf = Hkdf::<Sha256>::new(Some(transcript_hash), shared_secret.0.as_ref());
    drop(shared_secret);
    let initiator_to_responder = derive_directional(
        &hkdf,
        INITIATOR_TO_RESPONDER_KEY_INFO,
        INITIATOR_TO_RESPONDER_NONCE_INFO,
    )?;
    let responder_to_initiator = derive_directional(
        &hkdf,
        RESPONDER_TO_INITIATOR_KEY_INFO,
        RESPONDER_TO_INITIATOR_NONCE_INFO,
    )?;
    let initiator_confirmation = expand_secret(&hkdf, INITIATOR_CONFIRMATION_INFO)?;
    let responder_confirmation = expand_secret(&hkdf, RESPONDER_CONFIRMATION_INFO)?;

    Ok(match role {
        SessionRole::Initiator => SessionSecrets {
            send: initiator_to_responder,
            receive: responder_to_initiator,
            local_confirmation: initiator_confirmation,
            remote_confirmation: responder_confirmation,
        },
        SessionRole::Responder => SessionSecrets {
            send: responder_to_initiator,
            receive: initiator_to_responder,
            local_confirmation: responder_confirmation,
            remote_confirmation: initiator_confirmation,
        },
    })
}

fn derive_directional(
    hkdf: &Hkdf<Sha256>,
    key_info: &[u8],
    nonce_info: &[u8],
) -> Result<DirectionalSecrets, CryptoError> {
    Ok(DirectionalSecrets {
        key: expand_secret(hkdf, key_info)?,
        nonce_prefix: expand_array(hkdf, nonce_info)?,
    })
}

fn expand_secret<const LENGTH: usize>(
    hkdf: &Hkdf<Sha256>,
    info: &[u8],
) -> Result<Zeroizing<[u8; LENGTH]>, CryptoError> {
    let mut output = Zeroizing::new([0_u8; LENGTH]);
    hkdf.expand(info, output.as_mut())
        .map_err(|_| CryptoError::KeyDerivationFailed)?;
    Ok(output)
}

fn expand_array<const LENGTH: usize>(
    hkdf: &Hkdf<Sha256>,
    info: &[u8],
) -> Result<[u8; LENGTH], CryptoError> {
    let mut output = [0_u8; LENGTH];
    hkdf.expand(info, &mut output)
        .map_err(|_| CryptoError::KeyDerivationFailed)?;
    Ok(output)
}

#[cfg(test)]
mod tests {
    use hkdf::Hkdf;
    use sha2::Sha256;

    use super::{
        derive_session_secrets, session_transcript_hash, EphemeralPublicKey, EphemeralSecret,
        SessionRole,
    };
    use crate::CryptoError;

    const ALICE_SECRET: [u8; 32] = [
        0x77, 0x07, 0x6d, 0x0a, 0x73, 0x18, 0xa5, 0x7d, 0x3c, 0x16, 0xc1, 0x72, 0x51, 0xb2, 0x66,
        0x45, 0xdf, 0x4c, 0x2f, 0x87, 0xeb, 0xc0, 0x99, 0x2a, 0xb1, 0x77, 0xfb, 0xa5, 0x1d, 0xb9,
        0x2c, 0x2a,
    ];
    const ALICE_PUBLIC: [u8; 32] = [
        0x85, 0x20, 0xf0, 0x09, 0x89, 0x30, 0xa7, 0x54, 0x74, 0x8b, 0x7d, 0xdc, 0xb4, 0x3e, 0xf7,
        0x5a, 0x0d, 0xbf, 0x3a, 0x0d, 0x26, 0x38, 0x1a, 0xf4, 0xeb, 0xa4, 0xa9, 0x8e, 0xaa, 0x9b,
        0x4e, 0x6a,
    ];
    const BOB_SECRET: [u8; 32] = [
        0x5d, 0xab, 0x08, 0x7e, 0x62, 0x4a, 0x8a, 0x4b, 0x79, 0xe1, 0x7f, 0x8b, 0x83, 0x80, 0x0e,
        0xe6, 0x6f, 0x3b, 0xb1, 0x29, 0x26, 0x18, 0xb6, 0xfd, 0x1c, 0x2f, 0x8b, 0x27, 0xff, 0x88,
        0xe0, 0xeb,
    ];
    const BOB_PUBLIC: [u8; 32] = [
        0xde, 0x9e, 0xdb, 0x7d, 0x7b, 0x7d, 0xc1, 0xb4, 0xd3, 0x5b, 0x61, 0xc2, 0xec, 0xe4, 0x35,
        0x37, 0x3f, 0x83, 0x43, 0xc8, 0x5b, 0x78, 0x67, 0x4d, 0xad, 0xfc, 0x7e, 0x14, 0x6f, 0x88,
        0x2b, 0x4f,
    ];
    const SHARED_SECRET: [u8; 32] = [
        0x4a, 0x5d, 0x9d, 0x5b, 0xa4, 0xce, 0x2d, 0xe1, 0x72, 0x8e, 0x3b, 0xf4, 0x80, 0x35, 0x0f,
        0x25, 0xe0, 0x7e, 0x21, 0xc9, 0x47, 0xd1, 0x9e, 0x33, 0x76, 0xf0, 0x9b, 0x3c, 0x1e, 0x16,
        0x17, 0x42,
    ];
    const STELLA_TRANSCRIPT_HASH: [u8; 32] = [
        0xd6, 0x57, 0xdb, 0x93, 0xd3, 0x22, 0x7b, 0x65, 0x8c, 0x32, 0x69, 0x38, 0x3b, 0xdf, 0xc1,
        0xe3, 0xf7, 0x90, 0x27, 0x02, 0x8d, 0xb9, 0xcb, 0x3c, 0xb3, 0xd5, 0x64, 0x2c, 0xb5, 0x87,
        0xe2, 0x45,
    ];
    const STELLA_I2R_KEY: [u8; 32] = [
        0xad, 0x0b, 0x5e, 0x9e, 0x0e, 0x4e, 0xc8, 0xc7, 0x10, 0x4e, 0x19, 0x4f, 0xa4, 0xa3, 0xef,
        0x24, 0x83, 0x29, 0x8f, 0x32, 0xfa, 0x9f, 0x66, 0x5b, 0xa2, 0x96, 0x30, 0x71, 0xfe, 0xa5,
        0x2d, 0x37,
    ];
    const STELLA_R2I_KEY: [u8; 32] = [
        0xd8, 0x48, 0x62, 0x54, 0x0c, 0xa0, 0x74, 0xfa, 0x8c, 0xda, 0xe5, 0x97, 0xc7, 0x7d, 0x32,
        0x0d, 0x14, 0x74, 0xb6, 0x11, 0x62, 0x54, 0x59, 0xec, 0xf7, 0xd7, 0xfa, 0x18, 0xe1, 0x2c,
        0x71, 0x47,
    ];
    const STELLA_INITIATOR_CONFIRMATION: [u8; 32] = [
        0x2a, 0x9c, 0x1c, 0xb8, 0x32, 0xb6, 0xaf, 0x6d, 0xe3, 0x20, 0x3e, 0x3b, 0x4f, 0x48, 0x2a,
        0x21, 0x58, 0x37, 0xf2, 0x3f, 0x29, 0x64, 0xba, 0xce, 0x15, 0x09, 0xa7, 0xdc, 0x35, 0xdd,
        0x44, 0x8c,
    ];
    const STELLA_RESPONDER_CONFIRMATION: [u8; 32] = [
        0x4e, 0x7a, 0x91, 0x18, 0x7c, 0x16, 0xe0, 0xf4, 0x12, 0x8c, 0x9c, 0x2c, 0xeb, 0xbd, 0xf7,
        0x39, 0x62, 0xac, 0x6a, 0xe7, 0xcb, 0xcf, 0xc0, 0x39, 0x58, 0x93, 0x47, 0x47, 0x37, 0x43,
        0xc1, 0x14,
    ];

    #[test]
    fn x25519_matches_rfc7748_vector_in_both_directions() {
        let alice = EphemeralSecret::from_bytes(ALICE_SECRET);
        assert_eq!(alice.public_key().to_bytes(), ALICE_PUBLIC);
        let alice_shared = alice
            .agree(EphemeralPublicKey::from_bytes(BOB_PUBLIC))
            .expect("contributory RFC 7748 agreement");
        assert_eq!(*alice_shared.0, SHARED_SECRET);

        let bob = EphemeralSecret::from_bytes(BOB_SECRET);
        assert_eq!(bob.public_key().to_bytes(), BOB_PUBLIC);
        let bob_shared = bob
            .agree(EphemeralPublicKey::from_bytes(ALICE_PUBLIC))
            .expect("contributory RFC 7748 agreement");
        assert_eq!(*bob_shared.0, SHARED_SECRET);
    }

    #[test]
    fn x25519_rejects_non_contributory_peer_and_redacts_secrets() {
        let secret = EphemeralSecret::from_bytes(ALICE_SECRET);
        assert_eq!(format!("{secret:?}"), "EphemeralSecret([REDACTED])");
        assert!(matches!(
            secret.agree(EphemeralPublicKey::from_bytes([0; 32])),
            Err(CryptoError::NonContributoryKeyAgreement)
        ));

        let shared = EphemeralSecret::from_bytes(ALICE_SECRET)
            .agree(EphemeralPublicKey::from_bytes(BOB_PUBLIC))
            .expect("contributory RFC 7748 agreement");
        assert_eq!(format!("{shared:?}"), "SharedSecret([REDACTED])");
    }

    #[test]
    fn hkdf_matches_rfc5869_sha256_case_one() {
        let ikm = [0x0b; 22];
        let salt = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c,
        ];
        let info = [0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9];
        let expected = [
            0x3c, 0xb2, 0x5f, 0x25, 0xfa, 0xac, 0xd5, 0x7a, 0x90, 0x43, 0x4f, 0x64, 0xd0, 0x36,
            0x2f, 0x2a, 0x2d, 0x2d, 0x0a, 0x90, 0xcf, 0x1a, 0x5a, 0x4c, 0x5d, 0xb0, 0x2d, 0x56,
            0xec, 0xc4, 0xc5, 0xbf, 0x34, 0x00, 0x72, 0x08, 0xd5, 0xb8, 0x87, 0x18, 0x58, 0x65,
        ];

        let hkdf = Hkdf::<Sha256>::new(Some(&salt), &ikm);
        let mut output = [0_u8; 42];
        hkdf.expand(&info, &mut output).expect("valid HKDF length");
        assert_eq!(output, expected);
    }

    #[test]
    fn stella_transcript_and_role_mapping_are_deterministic() {
        let transcript_hash = session_transcript_hash(b"fixed init", b"fixed response");
        assert_eq!(transcript_hash, STELLA_TRANSCRIPT_HASH);
        let initiator_shared = EphemeralSecret::from_bytes(ALICE_SECRET)
            .agree(EphemeralPublicKey::from_bytes(BOB_PUBLIC))
            .expect("contributory RFC 7748 agreement");
        let responder_shared = EphemeralSecret::from_bytes(BOB_SECRET)
            .agree(EphemeralPublicKey::from_bytes(ALICE_PUBLIC))
            .expect("contributory RFC 7748 agreement");
        let initiator =
            derive_session_secrets(initiator_shared, &transcript_hash, SessionRole::Initiator)
                .expect("fixed-size session derivation");
        let responder =
            derive_session_secrets(responder_shared, &transcript_hash, SessionRole::Responder)
                .expect("fixed-size session derivation");

        assert_eq!(initiator.send.key.as_ref(), responder.receive.key.as_ref());
        assert_eq!(initiator.send.nonce_prefix, responder.receive.nonce_prefix);
        assert_eq!(initiator.receive.key.as_ref(), responder.send.key.as_ref());
        assert_eq!(initiator.receive.nonce_prefix, responder.send.nonce_prefix);
        assert_eq!(
            initiator.local_confirmation.as_ref(),
            responder.remote_confirmation.as_ref()
        );
        assert_eq!(
            initiator.remote_confirmation.as_ref(),
            responder.local_confirmation.as_ref()
        );
        assert_eq!(format!("{initiator:?}"), "SessionSecrets([REDACTED])");

        assert_eq!(initiator.send.key.as_ref(), &STELLA_I2R_KEY);
        assert_eq!(initiator.send.nonce_prefix, [0xb4, 0x96, 0xb8, 0x76]);
        assert_eq!(initiator.receive.key.as_ref(), &STELLA_R2I_KEY);
        assert_eq!(initiator.receive.nonce_prefix, [0x29, 0xb6, 0xfe, 0xcb]);
        assert_eq!(
            initiator.local_confirmation.as_ref(),
            &STELLA_INITIATOR_CONFIRMATION
        );
        assert_eq!(
            initiator.remote_confirmation.as_ref(),
            &STELLA_RESPONDER_CONFIRMATION
        );

        assert_ne!(initiator.send.key.as_ref(), initiator.receive.key.as_ref());
        assert_ne!(initiator.send.nonce_prefix, initiator.receive.nonce_prefix);
        assert_ne!(
            initiator.local_confirmation.as_ref(),
            initiator.remote_confirmation.as_ref()
        );

        let initiator_protectors = initiator.into_protectors();
        let responder_protectors = responder.into_protectors();
        let keepalive_tag = initiator_protectors
            .send()
            .authenticate_header(1, b"fixed header")
            .expect("bounded fixed header");
        assert_eq!(
            responder_protectors
                .receive()
                .verify_header(1, b"fixed header", &keepalive_tag,),
            Ok(())
        );

        let confirmation_tag = initiator_protectors
            .local_confirmation()
            .create_tag(&transcript_hash, b"fixed header", &[0; 40])
            .expect("bounded fixed confirmation");
        assert_eq!(
            responder_protectors.remote_confirmation().verify_tag(
                &transcript_hash,
                b"fixed header",
                &[0; 40],
                &confirmation_tag,
            ),
            Ok(())
        );
        assert_eq!(
            format!("{initiator_protectors:?}"),
            "SessionProtectors([REDACTED])"
        );
    }
}
