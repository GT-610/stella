//! ChaCha20-Poly1305 packet protection and session confirmation.

use std::fmt;

use chacha20poly1305::{
    aead::{AeadInOut, KeyInit},
    ChaCha20Poly1305, Key, Nonce, Tag,
};
use zeroize::Zeroizing;

use crate::{
    CryptoError, CONFIRMATION_KEY_LENGTH, DATA_KEY_LENGTH, NONCE_PREFIX_LENGTH,
    SHA256_OUTPUT_LENGTH,
};

/// Length of a ChaCha20-Poly1305 nonce.
pub const PACKET_NONCE_LENGTH: usize = 12;

/// Length of a ChaCha20-Poly1305 authentication tag.
pub const AUTHENTICATION_TAG_LENGTH: usize = 16;

/// Largest complete Stella header accepted as associated data.
pub const MAX_AUTHENTICATED_HEADER_LENGTH: usize = 1_024;

/// Largest plaintext or ciphertext protected by one operation.
pub const MAX_PROTECTED_PAYLOAD_LENGTH: usize = 9_216;

/// Largest header-plus-visible-fragment authenticate-only input.
pub const MAX_PACKET_ASSOCIATED_DATA_LENGTH: usize =
    MAX_AUTHENTICATED_HEADER_LENGTH + MAX_PROTECTED_PAYLOAD_LENGTH;

/// Domain prefix for the one-time session-confirmation tag.
pub const SESSION_CONFIRMATION_DOMAIN: &[u8] = b"stella session confirm v1";

/// Exact `SESSION_CONFIRM` payload prefix authenticated before its tag.
pub const CONFIRMATION_AUTHENTICATED_PAYLOAD_LENGTH: usize = 40;

/// One directional ChaCha20-Poly1305 key and nonce prefix.
pub struct PacketProtector {
    key: Zeroizing<[u8; DATA_KEY_LENGTH]>,
    nonce_prefix: [u8; NONCE_PREFIX_LENGTH],
}

impl PacketProtector {
    pub(crate) const fn new(
        key: Zeroizing<[u8; DATA_KEY_LENGTH]>,
        nonce_prefix: [u8; NONCE_PREFIX_LENGTH],
    ) -> Self {
        Self { key, nonce_prefix }
    }

    /// Encrypts one fragment and returns its detached authentication tag.
    ///
    /// The complete Stella header is associated data. `output` may alias
    /// neither `plaintext` nor `authenticated_header`.
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError`] for sequence zero, an oversized input,
    /// insufficient output storage, or an unexpected cipher failure.
    pub fn seal_encrypted(
        &self,
        sequence_number: u64,
        authenticated_header: &[u8],
        plaintext: &[u8],
        output: &mut [u8],
    ) -> Result<[u8; AUTHENTICATION_TAG_LENGTH], CryptoError> {
        validate_header(authenticated_header)?;
        validate_payload(plaintext)?;
        let nonce_bytes = packet_nonce(self.nonce_prefix, sequence_number)?;
        let ciphertext = output_for(plaintext.len(), output)?;
        ciphertext.copy_from_slice(plaintext);

        let nonce = Nonce::from(nonce_bytes);
        let cipher = self.cipher();
        let tag = cipher
            .encrypt_inout_detached(&nonce, authenticated_header, ciphertext.into())
            .map_err(|_| CryptoError::PacketProtectionFailed)?;
        Ok(tag.into())
    }

    /// Authenticates and decrypts one encrypted fragment into caller storage.
    ///
    /// The caller's `output` remains unchanged when tag verification fails.
    /// Plaintext is copied into it only after successful authentication.
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError`] for sequence zero, an oversized input,
    /// insufficient output storage or allocation, or a failed tag.
    pub fn open_encrypted(
        &self,
        sequence_number: u64,
        authenticated_header: &[u8],
        ciphertext: &[u8],
        tag: &[u8; AUTHENTICATION_TAG_LENGTH],
        output: &mut [u8],
    ) -> Result<usize, CryptoError> {
        validate_header(authenticated_header)?;
        validate_payload(ciphertext)?;
        let output_length = output.len();
        if output_length < ciphertext.len() {
            return Err(CryptoError::ProtectionOutputTooSmall {
                needed: ciphertext.len(),
                remaining: output_length,
            });
        }

        let mut candidate = Zeroizing::new(Vec::new());
        candidate
            .try_reserve_exact(ciphertext.len())
            .map_err(|_| CryptoError::PacketProtectionAllocationFailed)?;
        candidate.extend_from_slice(ciphertext);

        let nonce_bytes = packet_nonce(self.nonce_prefix, sequence_number)?;
        let nonce = Nonce::from(nonce_bytes);
        let tag = Tag::from(*tag);
        self.cipher()
            .decrypt_inout_detached(
                &nonce,
                authenticated_header,
                candidate.as_mut_slice().into(),
                &tag,
            )
            .map_err(|_| CryptoError::AuthenticationFailed)?;

        let plaintext = output_for(candidate.len(), output)?;
        plaintext.copy_from_slice(candidate.as_ref());
        Ok(candidate.len())
    }

    /// Creates an authenticate-only tag for an unchanged visible fragment.
    ///
    /// The conceptual associated data is `authenticated_header || fragment`;
    /// AEAD plaintext is empty.
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError`] for sequence zero, oversized input, bounded
    /// allocation failure, or an unexpected cipher failure.
    pub fn authenticate_only(
        &self,
        sequence_number: u64,
        authenticated_header: &[u8],
        fragment: &[u8],
    ) -> Result<[u8; AUTHENTICATION_TAG_LENGTH], CryptoError> {
        let associated_data = packet_associated_data(authenticated_header, fragment)?;
        self.authenticate_empty(sequence_number, &associated_data)
    }

    /// Verifies an authenticate-only tag for a visible fragment.
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError`] for sequence zero, oversized input, bounded
    /// allocation failure, or a failed authentication tag.
    pub fn verify_authenticate_only(
        &self,
        sequence_number: u64,
        authenticated_header: &[u8],
        fragment: &[u8],
        tag: &[u8; AUTHENTICATION_TAG_LENGTH],
    ) -> Result<(), CryptoError> {
        let associated_data = packet_associated_data(authenticated_header, fragment)?;
        self.verify_empty(sequence_number, &associated_data, tag)
    }

    /// Creates a tag for empty plaintext and one complete associated-data header.
    ///
    /// This is the `KEEPALIVE` protection operation.
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError`] for sequence zero, an oversized header, or an
    /// unexpected cipher failure.
    pub fn authenticate_header(
        &self,
        sequence_number: u64,
        authenticated_header: &[u8],
    ) -> Result<[u8; AUTHENTICATION_TAG_LENGTH], CryptoError> {
        validate_header(authenticated_header)?;
        self.authenticate_empty(sequence_number, authenticated_header)
    }

    /// Verifies a tag over empty plaintext and one complete header.
    ///
    /// This is the `KEEPALIVE` verification operation.
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError`] for sequence zero, an oversized header, or a
    /// failed authentication tag.
    pub fn verify_header(
        &self,
        sequence_number: u64,
        authenticated_header: &[u8],
        tag: &[u8; AUTHENTICATION_TAG_LENGTH],
    ) -> Result<(), CryptoError> {
        validate_header(authenticated_header)?;
        self.verify_empty(sequence_number, authenticated_header, tag)
    }

    fn authenticate_empty(
        &self,
        sequence_number: u64,
        associated_data: &[u8],
    ) -> Result<[u8; AUTHENTICATION_TAG_LENGTH], CryptoError> {
        let nonce_bytes = packet_nonce(self.nonce_prefix, sequence_number)?;
        let nonce = Nonce::from(nonce_bytes);
        let mut empty = [];
        let tag = self
            .cipher()
            .encrypt_inout_detached(&nonce, associated_data, empty.as_mut_slice().into())
            .map_err(|_| CryptoError::PacketProtectionFailed)?;
        Ok(tag.into())
    }

    fn verify_empty(
        &self,
        sequence_number: u64,
        associated_data: &[u8],
        tag: &[u8; AUTHENTICATION_TAG_LENGTH],
    ) -> Result<(), CryptoError> {
        let nonce_bytes = packet_nonce(self.nonce_prefix, sequence_number)?;
        let nonce = Nonce::from(nonce_bytes);
        let tag = Tag::from(*tag);
        let mut empty = [];
        self.cipher()
            .decrypt_inout_detached(&nonce, associated_data, empty.as_mut_slice().into(), &tag)
            .map_err(|_| CryptoError::AuthenticationFailed)
    }

    fn cipher(&self) -> ChaCha20Poly1305 {
        ChaCha20Poly1305::new(&Key::from(*self.key))
    }
}

impl fmt::Debug for PacketProtector {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("PacketProtector([REDACTED])")
    }
}

/// One transcript-bound key for local or remote session confirmation.
pub struct ConfirmationAuthenticator {
    key: Zeroizing<[u8; CONFIRMATION_KEY_LENGTH]>,
}

impl ConfirmationAuthenticator {
    pub(crate) const fn new(key: Zeroizing<[u8; CONFIRMATION_KEY_LENGTH]>) -> Self {
        Self { key }
    }

    /// Creates the one-time confirmation tag for exact protocol byte ranges.
    ///
    /// Associated data is the confirmation domain, transcript hash, complete
    /// header, and 40-byte authenticated payload prefix in that order. The
    /// nonce and plaintext are empty/all-zero as specified by Stella.
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError`] for oversized input, bounded allocation failure,
    /// or an unexpected cipher failure.
    pub fn create_tag(
        &self,
        transcript_hash: &[u8; SHA256_OUTPUT_LENGTH],
        authenticated_header: &[u8],
        authenticated_payload: &[u8],
    ) -> Result<[u8; AUTHENTICATION_TAG_LENGTH], CryptoError> {
        let associated_data = confirmation_associated_data(
            transcript_hash,
            authenticated_header,
            authenticated_payload,
        )?;
        let mut empty = [];
        let nonce = Nonce::default();
        let tag = self
            .cipher()
            .encrypt_inout_detached(&nonce, &associated_data, empty.as_mut_slice().into())
            .map_err(|_| CryptoError::PacketProtectionFailed)?;
        Ok(tag.into())
    }

    /// Verifies one transcript-bound session-confirmation tag.
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError`] for oversized input, bounded allocation failure,
    /// or a failed authentication tag.
    pub fn verify_tag(
        &self,
        transcript_hash: &[u8; SHA256_OUTPUT_LENGTH],
        authenticated_header: &[u8],
        authenticated_payload: &[u8],
        tag: &[u8; AUTHENTICATION_TAG_LENGTH],
    ) -> Result<(), CryptoError> {
        let associated_data = confirmation_associated_data(
            transcript_hash,
            authenticated_header,
            authenticated_payload,
        )?;
        let mut empty = [];
        let nonce = Nonce::default();
        let tag = Tag::from(*tag);
        self.cipher()
            .decrypt_inout_detached(&nonce, &associated_data, empty.as_mut_slice().into(), &tag)
            .map_err(|_| CryptoError::AuthenticationFailed)
    }

    fn cipher(&self) -> ChaCha20Poly1305 {
        ChaCha20Poly1305::new(&Key::from(*self.key))
    }
}

impl fmt::Debug for ConfirmationAuthenticator {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ConfirmationAuthenticator([REDACTED])")
    }
}

/// Packet and confirmation protectors mapped to the local handshake role.
pub struct SessionProtectors {
    send: PacketProtector,
    receive: PacketProtector,
    local_confirmation: ConfirmationAuthenticator,
    remote_confirmation: ConfirmationAuthenticator,
}

impl SessionProtectors {
    pub(crate) const fn new(
        send: PacketProtector,
        receive: PacketProtector,
        local_confirmation: ConfirmationAuthenticator,
        remote_confirmation: ConfirmationAuthenticator,
    ) -> Self {
        Self {
            send,
            receive,
            local_confirmation,
            remote_confirmation,
        }
    }

    /// Borrows the local send-direction packet protector.
    #[must_use]
    pub const fn send(&self) -> &PacketProtector {
        &self.send
    }

    /// Borrows the peer-to-local receive-direction packet protector.
    #[must_use]
    pub const fn receive(&self) -> &PacketProtector {
        &self.receive
    }

    /// Borrows the authenticator used to create this node's confirmation.
    #[must_use]
    pub const fn local_confirmation(&self) -> &ConfirmationAuthenticator {
        &self.local_confirmation
    }

    /// Borrows the authenticator used to verify the peer's confirmation.
    #[must_use]
    pub const fn remote_confirmation(&self) -> &ConfirmationAuthenticator {
        &self.remote_confirmation
    }
}

impl fmt::Debug for SessionProtectors {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SessionProtectors([REDACTED])")
    }
}

fn packet_nonce(
    nonce_prefix: [u8; NONCE_PREFIX_LENGTH],
    sequence_number: u64,
) -> Result<[u8; PACKET_NONCE_LENGTH], CryptoError> {
    if sequence_number == 0 {
        return Err(CryptoError::InvalidSequenceNumber);
    }
    let mut nonce = [0_u8; PACKET_NONCE_LENGTH];
    nonce[..NONCE_PREFIX_LENGTH].copy_from_slice(&nonce_prefix);
    nonce[NONCE_PREFIX_LENGTH..].copy_from_slice(&sequence_number.to_be_bytes());
    Ok(nonce)
}

fn validate_header(authenticated_header: &[u8]) -> Result<(), CryptoError> {
    validate_bounded_length(authenticated_header.len(), MAX_AUTHENTICATED_HEADER_LENGTH)
}

fn validate_payload(payload: &[u8]) -> Result<(), CryptoError> {
    validate_bounded_length(payload.len(), MAX_PROTECTED_PAYLOAD_LENGTH)
}

fn validate_bounded_length(actual: usize, maximum: usize) -> Result<(), CryptoError> {
    if actual > maximum {
        return Err(CryptoError::ProtectedInputTooLarge { actual, maximum });
    }
    Ok(())
}

fn output_for(length: usize, output: &mut [u8]) -> Result<&mut [u8], CryptoError> {
    let remaining = output.len();
    output
        .get_mut(..length)
        .ok_or(CryptoError::ProtectionOutputTooSmall {
            needed: length,
            remaining,
        })
}

fn packet_associated_data(
    authenticated_header: &[u8],
    fragment: &[u8],
) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
    validate_header(authenticated_header)?;
    validate_payload(fragment)?;
    assemble_associated_data(
        &[authenticated_header, fragment],
        MAX_PACKET_ASSOCIATED_DATA_LENGTH,
    )
}

fn confirmation_associated_data(
    transcript_hash: &[u8; SHA256_OUTPUT_LENGTH],
    authenticated_header: &[u8],
    authenticated_payload: &[u8],
) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
    validate_header(authenticated_header)?;
    if authenticated_payload.len() != CONFIRMATION_AUTHENTICATED_PAYLOAD_LENGTH {
        return Err(CryptoError::InvalidConfirmationPayloadLength {
            actual: authenticated_payload.len(),
            expected: CONFIRMATION_AUTHENTICATED_PAYLOAD_LENGTH,
        });
    }
    assemble_associated_data(
        &[
            SESSION_CONFIRMATION_DOMAIN,
            transcript_hash,
            authenticated_header,
            authenticated_payload,
        ],
        MAX_PACKET_ASSOCIATED_DATA_LENGTH,
    )
}

fn assemble_associated_data(
    segments: &[&[u8]],
    maximum: usize,
) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
    let mut total = 0_usize;
    for segment in segments {
        total = total
            .checked_add(segment.len())
            .ok_or(CryptoError::ProtectedInputTooLarge {
                actual: usize::MAX,
                maximum,
            })?;
    }
    validate_bounded_length(total, maximum)?;

    let mut associated_data = Zeroizing::new(Vec::new());
    associated_data
        .try_reserve_exact(total)
        .map_err(|_| CryptoError::PacketProtectionAllocationFailed)?;
    for segment in segments {
        associated_data.extend_from_slice(segment);
    }
    Ok(associated_data)
}

#[cfg(test)]
mod tests {
    use zeroize::Zeroizing;

    use super::{
        ConfirmationAuthenticator, PacketProtector, AUTHENTICATION_TAG_LENGTH,
        MAX_PROTECTED_PAYLOAD_LENGTH,
    };
    use crate::CryptoError;

    const RFC8439_KEY: [u8; 32] = [
        0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88, 0x89, 0x8a, 0x8b, 0x8c, 0x8d, 0x8e,
        0x8f, 0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97, 0x98, 0x99, 0x9a, 0x9b, 0x9c, 0x9d,
        0x9e, 0x9f,
    ];
    const RFC8439_AAD: [u8; 12] = [
        0x50, 0x51, 0x52, 0x53, 0xc0, 0xc1, 0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7,
    ];
    const RFC8439_PLAINTEXT: &[u8] = b"Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.";
    const RFC8439_CIPHERTEXT: [u8; 114] = [
        0xd3, 0x1a, 0x8d, 0x34, 0x64, 0x8e, 0x60, 0xdb, 0x7b, 0x86, 0xaf, 0xbc, 0x53, 0xef, 0x7e,
        0xc2, 0xa4, 0xad, 0xed, 0x51, 0x29, 0x6e, 0x08, 0xfe, 0xa9, 0xe2, 0xb5, 0xa7, 0x36, 0xee,
        0x62, 0xd6, 0x3d, 0xbe, 0xa4, 0x5e, 0x8c, 0xa9, 0x67, 0x12, 0x82, 0xfa, 0xfb, 0x69, 0xda,
        0x92, 0x72, 0x8b, 0x1a, 0x71, 0xde, 0x0a, 0x9e, 0x06, 0x0b, 0x29, 0x05, 0xd6, 0xa5, 0xb6,
        0x7e, 0xcd, 0x3b, 0x36, 0x92, 0xdd, 0xbd, 0x7f, 0x2d, 0x77, 0x8b, 0x8c, 0x98, 0x03, 0xae,
        0xe3, 0x28, 0x09, 0x1b, 0x58, 0xfa, 0xb3, 0x24, 0xe4, 0xfa, 0xd6, 0x75, 0x94, 0x55, 0x85,
        0x80, 0x8b, 0x48, 0x31, 0xd7, 0xbc, 0x3f, 0xf4, 0xde, 0xf0, 0x8e, 0x4b, 0x7a, 0x9d, 0xe5,
        0x76, 0xd2, 0x65, 0x86, 0xce, 0xc6, 0x4b, 0x61, 0x16,
    ];
    const RFC8439_TAG: [u8; 16] = [
        0x1a, 0xe1, 0x0b, 0x59, 0x4f, 0x09, 0xe2, 0x6a, 0x7e, 0x90, 0x2e, 0xcb, 0xd0, 0x60, 0x06,
        0x91,
    ];

    fn rfc_protector() -> PacketProtector {
        PacketProtector::new(Zeroizing::new(RFC8439_KEY), [0x07, 0, 0, 0])
    }

    #[test]
    fn encrypted_packet_matches_rfc8439_aead_vector() {
        let protector = rfc_protector();
        let sequence = 0x4041_4243_4445_4647;
        let mut ciphertext = [0_u8; RFC8439_PLAINTEXT.len()];
        let tag = protector
            .seal_encrypted(sequence, &RFC8439_AAD, RFC8439_PLAINTEXT, &mut ciphertext)
            .expect("bounded RFC 8439 input");
        assert_eq!(ciphertext, RFC8439_CIPHERTEXT);
        assert_eq!(tag, RFC8439_TAG);

        let mut plaintext = [0_u8; RFC8439_PLAINTEXT.len()];
        assert_eq!(
            protector.open_encrypted(sequence, &RFC8439_AAD, &ciphertext, &tag, &mut plaintext,),
            Ok(RFC8439_PLAINTEXT.len())
        );
        assert_eq!(plaintext, RFC8439_PLAINTEXT);
    }

    #[test]
    fn authentication_failure_does_not_overwrite_plaintext_output() {
        let protector = rfc_protector();
        let sequence = 0x4041_4243_4445_4647;
        let mut bad_tag = RFC8439_TAG;
        bad_tag[0] ^= 1;
        let mut output = [0x5a; RFC8439_PLAINTEXT.len()];

        assert_eq!(
            protector.open_encrypted(
                sequence,
                &RFC8439_AAD,
                &RFC8439_CIPHERTEXT,
                &bad_tag,
                &mut output,
            ),
            Err(CryptoError::AuthenticationFailed)
        );
        assert_eq!(output, [0x5a; RFC8439_PLAINTEXT.len()]);
    }

    #[test]
    fn authenticate_only_and_keepalive_cover_exact_visible_bytes() {
        let protector = rfc_protector();
        let header = b"fixed Stella header";
        let fragment = b"visible Ethernet fragment";
        let tag = protector
            .authenticate_only(1, header, fragment)
            .expect("bounded authenticate-only input");
        assert_eq!(
            protector.verify_authenticate_only(1, header, fragment, &tag),
            Ok(())
        );
        assert_eq!(
            protector.verify_authenticate_only(1, header, b"changed", &tag),
            Err(CryptoError::AuthenticationFailed)
        );

        let keepalive_tag = protector
            .authenticate_header(2, header)
            .expect("bounded KEEPALIVE header");
        assert_eq!(protector.verify_header(2, header, &keepalive_tag), Ok(()));
        assert_eq!(
            protector.verify_header(3, header, &keepalive_tag),
            Err(CryptoError::AuthenticationFailed)
        );
    }

    #[test]
    fn confirmation_authenticates_domain_transcript_header_and_payload() {
        let authenticator = ConfirmationAuthenticator::new(Zeroizing::new([0x42; 32]));
        let transcript_hash = [0x53; 32];
        let header = b"confirmation header";
        let payload = [0x64; 40];
        let tag = authenticator
            .create_tag(&transcript_hash, header, &payload)
            .expect("bounded confirmation input");
        assert_eq!(
            authenticator.verify_tag(&transcript_hash, header, &payload, &tag),
            Ok(())
        );

        let mut changed_transcript = transcript_hash;
        changed_transcript[0] ^= 1;
        assert_eq!(
            authenticator.verify_tag(&changed_transcript, header, &payload, &tag),
            Err(CryptoError::AuthenticationFailed)
        );
        assert_eq!(
            authenticator.create_tag(&transcript_hash, header, &payload[..39]),
            Err(CryptoError::InvalidConfirmationPayloadLength {
                actual: 39,
                expected: 40,
            })
        );
        assert_eq!(
            format!("{authenticator:?}"),
            "ConfirmationAuthenticator([REDACTED])"
        );
    }

    #[test]
    fn packet_protection_rejects_zero_oversize_and_short_output() {
        let protector = rfc_protector();
        let mut output = [0_u8; 1];
        assert_eq!(
            protector.seal_encrypted(0, b"header", b"x", &mut output),
            Err(CryptoError::InvalidSequenceNumber)
        );
        assert_eq!(
            protector.seal_encrypted(1, b"header", b"xx", &mut output),
            Err(CryptoError::ProtectionOutputTooSmall {
                needed: 2,
                remaining: 1,
            })
        );

        let oversized = vec![0_u8; MAX_PROTECTED_PAYLOAD_LENGTH + 1];
        assert_eq!(
            protector.authenticate_only(1, b"header", &oversized),
            Err(CryptoError::ProtectedInputTooLarge {
                actual: MAX_PROTECTED_PAYLOAD_LENGTH + 1,
                maximum: MAX_PROTECTED_PAYLOAD_LENGTH,
            })
        );
        assert_eq!(format!("{protector:?}"), "PacketProtector([REDACTED])");
        assert_eq!(RFC8439_TAG.len(), AUTHENTICATION_TAG_LENGTH);
    }

    #[test]
    fn stella_packet_modes_match_fixed_vectors() {
        let protector = PacketProtector::new(Zeroizing::new([0x42; 32]), [1, 2, 3, 4]);
        let header = b"fixed Stella header";
        let plaintext = b"fixed Stella payload";
        let mut ciphertext = [0_u8; 20];
        let encrypted_tag = protector
            .seal_encrypted(0x0102_0304_0506_0708, header, plaintext, &mut ciphertext)
            .expect("bounded fixed input");
        let authenticate_only_tag = protector
            .authenticate_only(9, header, plaintext)
            .expect("bounded fixed input");
        let keepalive_tag = protector
            .authenticate_header(10, header)
            .expect("bounded fixed input");

        let confirmation = ConfirmationAuthenticator::new(Zeroizing::new([0x42; 32]));
        let confirmation_tag = confirmation
            .create_tag(&[0x53; 32], header, &[0x64; 40])
            .expect("bounded fixed confirmation");

        assert_eq!(
            ciphertext,
            [
                0x97, 0xbd, 0xd7, 0xb6, 0x90, 0xfb, 0x25, 0xf8, 0xbe, 0x23, 0x5f, 0x79, 0x72, 0xa1,
                0x23, 0x53, 0x99, 0xbd, 0x64, 0xb1,
            ]
        );
        assert_eq!(
            encrypted_tag,
            [
                0x5e, 0x9d, 0x35, 0x3d, 0xe5, 0xaa, 0xc5, 0xec, 0x47, 0xdf, 0x27, 0x34, 0x23, 0x8c,
                0xf1, 0x93,
            ]
        );
        assert_eq!(
            authenticate_only_tag,
            [
                0xed, 0x22, 0x93, 0xab, 0x2a, 0x4f, 0x2b, 0x7f, 0x0e, 0xf1, 0xd6, 0x9b, 0x74, 0xa3,
                0xcd, 0xe7,
            ]
        );
        assert_eq!(
            keepalive_tag,
            [
                0x40, 0x9f, 0x14, 0x8f, 0x55, 0x0c, 0xbd, 0x67, 0x56, 0x9c, 0xbb, 0x8b, 0x7c, 0xd0,
                0xee, 0x99,
            ]
        );
        assert_eq!(
            confirmation_tag,
            [
                0x18, 0x4f, 0x08, 0xd4, 0x04, 0x96, 0x9f, 0xb6, 0x63, 0x40, 0xf3, 0x72, 0x11, 0x90,
                0xf3, 0x03,
            ]
        );
    }
}
