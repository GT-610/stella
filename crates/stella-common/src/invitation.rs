//! Versioned, self-contained invitations for the reference implementation.

use std::{
    fmt,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    str::FromStr,
};

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use thiserror::Error;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::{ControllerId, NetworkId};

const TEXT_PREFIX: &str = "stella2:";
const ENCODING_VERSION: u8 = 2;
const IPV4_FAMILY: u8 = 4;
const IPV6_FAMILY: u8 = 6;
const MAX_TLS_NAME_BYTES: usize = 253;
const TOKEN_LENGTH: usize = 32;
const CONTROLLER_PUBLIC_KEY_LENGTH: usize = 32;
const SIGNATURE_LENGTH: usize = 64;

/// Domain prefix for the controller Ed25519 signature over an invitation.
///
/// The signed message is this domain followed by the exact unsigned encoded
/// invitation bytes produced by [`JoinInvitation::unsigned_bytes`]. Carrying
/// the signature lets clients reject any invitation substituted or edited in
/// transit, since the controller identity inside binds the trust anchor.
pub const INVITATION_SIGNATURE_DOMAIN: &[u8] = b"stella invitation v1";

/// One self-contained, single-use invitation to a Stella virtual network.
///
/// Invitations are reference-implementation onboarding material, not protocol
/// messages. They carry bearer credentials and the complete controller trust
/// anchor, so they must still be delivered through a confidential channel, but
/// the embedded controller Ed25519 signature now lets clients detect any
/// in-transit substitution or tampering. Diagnostics redact the complete value,
/// and the credential bytes are zeroized on drop.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct JoinInvitation {
    #[zeroize(skip)]
    controller_address: SocketAddr,
    #[zeroize(skip)]
    tls_name: String,
    #[zeroize(skip)]
    controller_id: ControllerId,
    #[zeroize(skip)]
    spki_sha256: [u8; 32],
    #[zeroize(skip)]
    network_id: NetworkId,
    #[zeroize(skip)]
    expires_at: u64,
    #[zeroize(skip)]
    controller_public_key: [u8; CONTROLLER_PUBLIC_KEY_LENGTH],
    #[zeroize(skip)]
    signature: [u8; SIGNATURE_LENGTH],
    enrollment_token: [u8; TOKEN_LENGTH],
    join_token: [u8; TOKEN_LENGTH],
}

impl JoinInvitation {
    /// Validates and owns all public trust and single-use credential material.
    ///
    /// The returned invitation is unsigned; the controller completes it with
    /// [`Self::with_controller_signature`] before encoding it.
    ///
    /// # Errors
    ///
    /// Returns [`InvitationError`] when an identifier or token is zero, the
    /// controller port is zero, the TLS name is empty, oversized, or contains a
    /// control character, or the expiration time is zero.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        controller_address: SocketAddr,
        tls_name: String,
        controller_id: ControllerId,
        spki_sha256: [u8; 32],
        network_id: NetworkId,
        expires_at: u64,
        enrollment_token: [u8; TOKEN_LENGTH],
        join_token: [u8; TOKEN_LENGTH],
    ) -> Result<Self, InvitationError> {
        validate(
            controller_address,
            &tls_name,
            controller_id,
            network_id,
            expires_at,
            &enrollment_token,
            &join_token,
        )?;
        Ok(Self {
            controller_address,
            tls_name,
            controller_id,
            spki_sha256,
            network_id,
            expires_at,
            controller_public_key: [0; CONTROLLER_PUBLIC_KEY_LENGTH],
            signature: [0; SIGNATURE_LENGTH],
            enrollment_token,
            join_token,
        })
    }

    /// Completes the invitation with the controller's Ed25519 identity.
    ///
    /// The signature must cover [`Self::unsigned_bytes`] under
    /// [`INVITATION_SIGNATURE_DOMAIN`], and the public key must derive the
    /// invitation's controller ID.
    #[must_use]
    pub const fn with_controller_signature(
        mut self,
        controller_public_key: [u8; CONTROLLER_PUBLIC_KEY_LENGTH],
        signature: [u8; SIGNATURE_LENGTH],
    ) -> Self {
        self.controller_public_key = controller_public_key;
        self.signature = signature;
        self
    }

    /// Returns the controller Ed25519 public key carried by the invitation.
    #[must_use]
    pub const fn controller_public_key(&self) -> &[u8; CONTROLLER_PUBLIC_KEY_LENGTH] {
        &self.controller_public_key
    }

    /// Returns the controller signature carried by the invitation.
    #[must_use]
    pub const fn signature(&self) -> &[u8; SIGNATURE_LENGTH] {
        &self.signature
    }

    /// Returns the canonical byte string covered by the controller signature.
    ///
    /// The value is the complete version-2 encoding with the public-key and
    /// signature fields zeroed. The public key is not signed because it is
    /// bound instead by the signed controller ID, which is derived from it.
    /// Signing and verification both use this string under
    /// [`INVITATION_SIGNATURE_DOMAIN`].
    #[must_use]
    pub fn unsigned_bytes(&self) -> Zeroizing<Vec<u8>> {
        let mut bytes = Zeroizing::new(Vec::with_capacity(encoded_length(self)));
        self.encode_body(
            &[0; CONTROLLER_PUBLIC_KEY_LENGTH],
            &[0; SIGNATURE_LENGTH],
            &mut bytes,
        );
        bytes
    }

    /// Returns the numeric controller address clients should contact.
    #[must_use]
    pub const fn controller_address(&self) -> SocketAddr {
        self.controller_address
    }

    /// Returns the certificate name clients must validate.
    #[must_use]
    pub fn tls_name(&self) -> &str {
        &self.tls_name
    }

    /// Returns the expected Stella controller identity.
    #[must_use]
    pub const fn controller_id(&self) -> ControllerId {
        self.controller_id
    }

    /// Returns the expected controller certificate SPKI digest.
    #[must_use]
    pub const fn spki_sha256(&self) -> [u8; 32] {
        self.spki_sha256
    }

    /// Returns the target virtual network identity.
    #[must_use]
    pub const fn network_id(&self) -> NetworkId {
        self.network_id
    }

    /// Returns the invitation expiration as a Unix timestamp in seconds.
    #[must_use]
    pub const fn expires_at(&self) -> u64 {
        self.expires_at
    }

    /// Returns whether the invitation is expired at `now`.
    #[must_use]
    pub const fn is_expired_at(&self, now: u64) -> bool {
        now >= self.expires_at
    }

    /// Intentionally exposes the enrollment credential at a client boundary.
    #[must_use]
    pub const fn enrollment_token(&self) -> &[u8; TOKEN_LENGTH] {
        &self.enrollment_token
    }

    /// Intentionally exposes the network join credential at a client boundary.
    #[must_use]
    pub const fn join_token(&self) -> &[u8; TOKEN_LENGTH] {
        &self.join_token
    }

    /// Encodes the invitation as canonical unpadded base64url text.
    #[must_use]
    pub fn encode(&self) -> Zeroizing<String> {
        let mut bytes = Zeroizing::new(Vec::with_capacity(encoded_length(self)));
        self.encode_body(&self.controller_public_key, &self.signature, &mut bytes);
        Zeroizing::new(format!("{TEXT_PREFIX}{}", URL_SAFE_NO_PAD.encode(&*bytes)))
    }

    fn encode_body(
        &self,
        controller_public_key: &[u8; CONTROLLER_PUBLIC_KEY_LENGTH],
        signature: &[u8; SIGNATURE_LENGTH],
        bytes: &mut Zeroizing<Vec<u8>>,
    ) {
        bytes.push(ENCODING_VERSION);
        match self.controller_address.ip() {
            IpAddr::V4(address) => {
                bytes.push(IPV4_FAMILY);
                bytes.extend_from_slice(&address.octets());
            }
            IpAddr::V6(address) => {
                bytes.push(IPV6_FAMILY);
                bytes.extend_from_slice(&address.octets());
            }
        }
        bytes.extend_from_slice(&self.controller_address.port().to_be_bytes());
        let name_length = u16::try_from(self.tls_name.len()).unwrap_or(u16::MAX);
        bytes.extend_from_slice(&name_length.to_be_bytes());
        bytes.extend_from_slice(self.tls_name.as_bytes());
        bytes.extend_from_slice(self.controller_id.as_bytes());
        bytes.extend_from_slice(&self.spki_sha256);
        bytes.extend_from_slice(self.network_id.as_bytes());
        bytes.extend_from_slice(&self.expires_at.to_be_bytes());
        bytes.extend_from_slice(&self.enrollment_token);
        bytes.extend_from_slice(&self.join_token);
        bytes.extend_from_slice(controller_public_key);
        bytes.extend_from_slice(signature);
    }
}

impl fmt::Debug for JoinInvitation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("JoinInvitation([REDACTED])")
    }
}

impl FromStr for JoinInvitation {
    type Err = InvitationError;

    fn from_str(text: &str) -> Result<Self, Self::Err> {
        let encoded = text
            .strip_prefix(TEXT_PREFIX)
            .ok_or(InvitationError::Prefix)?;
        let bytes = Zeroizing::new(
            URL_SAFE_NO_PAD
                .decode(encoded)
                .map_err(|_| InvitationError::Base64)?,
        );
        decode(&bytes)
    }
}

/// Failure while constructing or decoding a Stella join invitation.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
#[non_exhaustive]
pub enum InvitationError {
    /// The textual version prefix is missing or unsupported.
    #[error("invitation must begin with stella2:")]
    Prefix,
    /// The invitation payload is not canonical unpadded base64url.
    #[error("invitation payload must be unpadded base64url")]
    Base64,
    /// The binary encoding version is unsupported.
    #[error("unsupported invitation encoding version {0}")]
    Version(u8),
    /// The controller address family is unsupported.
    #[error("unsupported invitation address family {0}")]
    AddressFamily(u8),
    /// The invitation ended before a complete field was available.
    #[error("invitation payload is truncated")]
    Truncated,
    /// Bytes remain after the complete invitation.
    #[error("invitation payload has trailing bytes")]
    TrailingBytes,
    /// The controller port is zero.
    #[error("invitation controller port must be non-zero")]
    ZeroPort,
    /// The TLS name is invalid UTF-8.
    #[error("invitation TLS name must be UTF-8")]
    TlsNameUtf8,
    /// The TLS name is empty, too long, or contains a control character.
    #[error("invitation TLS name is invalid")]
    TlsName,
    /// The controller identifier is zero.
    #[error("invitation controller ID must be non-zero")]
    ZeroControllerId,
    /// The network identifier is zero.
    #[error("invitation network ID must be non-zero")]
    ZeroNetworkId,
    /// The expiration time is zero.
    #[error("invitation expiration must be non-zero")]
    ZeroExpiration,
    /// One of the bearer credentials is all zero.
    #[error("invitation bearer credentials must be non-zero")]
    ZeroCredential,
    /// The carried controller public key is all zero.
    #[error("invitation controller public key must be non-zero")]
    ZeroControllerKey,
    /// The carried controller signature is all zero.
    #[error("invitation controller signature must be non-zero")]
    ZeroSignature,
}

fn validate(
    controller_address: SocketAddr,
    tls_name: &str,
    controller_id: ControllerId,
    network_id: NetworkId,
    expires_at: u64,
    enrollment_token: &[u8; TOKEN_LENGTH],
    join_token: &[u8; TOKEN_LENGTH],
) -> Result<(), InvitationError> {
    if controller_address.port() == 0 {
        return Err(InvitationError::ZeroPort);
    }
    if tls_name.is_empty()
        || tls_name.len() > MAX_TLS_NAME_BYTES
        || tls_name.chars().any(char::is_control)
    {
        return Err(InvitationError::TlsName);
    }
    if controller_id.is_zero() {
        return Err(InvitationError::ZeroControllerId);
    }
    if network_id.is_zero() {
        return Err(InvitationError::ZeroNetworkId);
    }
    if expires_at == 0 {
        return Err(InvitationError::ZeroExpiration);
    }
    if enrollment_token.iter().all(|byte| *byte == 0) || join_token.iter().all(|byte| *byte == 0) {
        return Err(InvitationError::ZeroCredential);
    }
    Ok(())
}

fn encoded_length(invitation: &JoinInvitation) -> usize {
    let address_length = match invitation.controller_address.ip() {
        IpAddr::V4(_) => 4,
        IpAddr::V6(_) => 16,
    };
    1 + 1
        + address_length
        + 2
        + 2
        + invitation.tls_name.len()
        + ControllerId::LENGTH
        + 32
        + NetworkId::LENGTH
        + 8
        + TOKEN_LENGTH * 2
        + CONTROLLER_PUBLIC_KEY_LENGTH
        + SIGNATURE_LENGTH
}

fn decode(bytes: &[u8]) -> Result<JoinInvitation, InvitationError> {
    let mut cursor = Cursor::new(bytes);
    let version = cursor.read_u8()?;
    if version != ENCODING_VERSION {
        return Err(InvitationError::Version(version));
    }
    let family = cursor.read_u8()?;
    let ip = match family {
        IPV4_FAMILY => IpAddr::V4(Ipv4Addr::from(cursor.read_array::<4>()?)),
        IPV6_FAMILY => IpAddr::V6(Ipv6Addr::from(cursor.read_array::<16>()?)),
        other => return Err(InvitationError::AddressFamily(other)),
    };
    let port = u16::from_be_bytes(cursor.read_array()?);
    let tls_name_length = usize::from(u16::from_be_bytes(cursor.read_array()?));
    let tls_name = std::str::from_utf8(cursor.read_slice(tls_name_length)?)
        .map_err(|_| InvitationError::TlsNameUtf8)?
        .to_owned();
    let controller_id = ControllerId::from_bytes(cursor.read_array()?);
    let spki_sha256 = cursor.read_array()?;
    let network_id = NetworkId::from_bytes(cursor.read_array()?);
    let expires_at = u64::from_be_bytes(cursor.read_array()?);
    let enrollment_token = cursor.read_array()?;
    let join_token = cursor.read_array()?;
    let controller_public_key = cursor.read_array()?;
    let signature = cursor.read_array()?;
    if !cursor.is_empty() {
        return Err(InvitationError::TrailingBytes);
    }
    if signature.iter().all(|byte| *byte == 0) {
        return Err(InvitationError::ZeroSignature);
    }
    if controller_public_key.iter().all(|byte| *byte == 0) {
        return Err(InvitationError::ZeroControllerKey);
    }
    JoinInvitation::new(
        SocketAddr::new(ip, port),
        tls_name,
        controller_id,
        spki_sha256,
        network_id,
        expires_at,
        enrollment_token,
        join_token,
    )
    .map(|invitation| invitation.with_controller_signature(controller_public_key, signature))
}

struct Cursor<'a> {
    bytes: &'a [u8],
    position: usize,
}

impl<'a> Cursor<'a> {
    const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, position: 0 }
    }

    fn read_u8(&mut self) -> Result<u8, InvitationError> {
        Ok(self.read_slice(1)?[0])
    }

    fn read_slice(&mut self, length: usize) -> Result<&'a [u8], InvitationError> {
        let end = self
            .position
            .checked_add(length)
            .ok_or(InvitationError::Truncated)?;
        let value = self
            .bytes
            .get(self.position..end)
            .ok_or(InvitationError::Truncated)?;
        self.position = end;
        Ok(value)
    }

    fn read_array<const N: usize>(&mut self) -> Result<[u8; N], InvitationError> {
        self.read_slice(N)?
            .try_into()
            .map_err(|_| InvitationError::Truncated)
    }

    fn is_empty(&self) -> bool {
        self.position == self.bytes.len()
    }
}

#[cfg(test)]
mod tests {
    use super::{InvitationError, JoinInvitation, CONTROLLER_PUBLIC_KEY_LENGTH, SIGNATURE_LENGTH};
    use crate::{ControllerId, NetworkId};
    use std::{net::SocketAddr, str::FromStr};

    fn invitation(address: &str) -> JoinInvitation {
        JoinInvitation::new(
            SocketAddr::from_str(address).expect("parse address"),
            "controller.example.test".to_owned(),
            ControllerId::from_bytes([0x11; 16]),
            [0x22; 32],
            NetworkId::from_bytes([0x33; 16]),
            1_900_000_000,
            [0x44; 32],
            [0x55; 32],
        )
        .expect("construct invitation")
        .with_controller_signature([0x66; 32], [0x77; 64])
    }

    #[test]
    fn invitations_round_trip_ipv4_and_ipv6_without_exposing_debug_secrets() {
        for address in ["192.0.2.10:44900", "[2001:db8::10]:44900"] {
            let original = invitation(address);
            let text = original.encode();
            let decoded = JoinInvitation::from_str(&text).expect("decode invitation");
            assert_eq!(decoded.controller_address(), original.controller_address());
            assert_eq!(decoded.tls_name(), original.tls_name());
            assert_eq!(decoded.controller_id(), original.controller_id());
            assert_eq!(decoded.spki_sha256(), original.spki_sha256());
            assert_eq!(decoded.network_id(), original.network_id());
            assert_eq!(decoded.expires_at(), original.expires_at());
            assert_eq!(decoded.enrollment_token(), original.enrollment_token());
            assert_eq!(decoded.join_token(), original.join_token());
            assert_eq!(
                *decoded.controller_public_key(),
                *original.controller_public_key()
            );
            assert_eq!(*decoded.signature(), *original.signature());
            let unsigned = original.unsigned_bytes();
            assert!(unsigned.len() > SIGNATURE_LENGTH);
            assert_eq!(
                unsigned[unsigned.len() - SIGNATURE_LENGTH..],
                [0; SIGNATURE_LENGTH]
            );
            assert_eq!(
                unsigned[unsigned.len() - SIGNATURE_LENGTH - CONTROLLER_PUBLIC_KEY_LENGTH
                    ..unsigned.len() - SIGNATURE_LENGTH],
                [0; CONTROLLER_PUBLIC_KEY_LENGTH]
            );
            assert_eq!(format!("{decoded:?}"), "JoinInvitation([REDACTED])");
        }
    }

    #[test]
    fn invitations_reject_noncanonical_and_invalid_values() {
        assert_eq!(
            JoinInvitation::from_str("not-an-invitation").expect_err("reject prefix"),
            InvitationError::Prefix
        );
        let mut encoded = invitation("192.0.2.10:44900").encode().to_string();
        encoded.push('=');
        assert_eq!(
            JoinInvitation::from_str(&encoded).expect_err("reject padded base64"),
            InvitationError::Base64
        );
        assert!(JoinInvitation::new(
            SocketAddr::from_str("192.0.2.10:44900").expect("parse address"),
            String::new(),
            ControllerId::from_bytes([0x11; 16]),
            [0x22; 32],
            NetworkId::from_bytes([0x33; 16]),
            1,
            [0x44; 32],
            [0x55; 32],
        )
        .is_err());
    }

    #[test]
    fn invitations_reject_unsigned_and_legacy_encodings() {
        let unsigned = JoinInvitation::new(
            SocketAddr::from_str("192.0.2.10:44900").expect("parse address"),
            "controller.example.test".to_owned(),
            ControllerId::from_bytes([0x11; 16]),
            [0x22; 32],
            NetworkId::from_bytes([0x33; 16]),
            1_900_000_000,
            [0x44; 32],
            [0x55; 32],
        )
        .expect("construct invitation");
        let text = unsigned.encode().to_string();
        assert_eq!(
            JoinInvitation::from_str(&text).expect_err("reject zero signature"),
            InvitationError::ZeroSignature
        );

        let zero_key = unsigned.with_controller_signature([0; 32], [0x77; 64]);
        let zero_key_text = zero_key.encode().to_string();
        assert_eq!(
            JoinInvitation::from_str(&zero_key_text).expect_err("reject zero controller key"),
            InvitationError::ZeroControllerKey
        );

        let signed_text = invitation("192.0.2.10:44900").encode().to_string();
        let mut legacy = signed_text;
        legacy.replace_range(0..7, "stella1");
        assert_eq!(
            JoinInvitation::from_str(&legacy).expect_err("reject stella1 prefix"),
            InvitationError::Prefix
        );
    }
}
