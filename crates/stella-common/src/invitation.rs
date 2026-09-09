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

const TEXT_PREFIX: &str = "stella1:";
const ENCODING_VERSION: u8 = 1;
const IPV4_FAMILY: u8 = 4;
const IPV6_FAMILY: u8 = 6;
const MAX_TLS_NAME_BYTES: usize = 253;
const TOKEN_LENGTH: usize = 32;

/// One self-contained, single-use invitation to a Stella virtual network.
///
/// Invitations are reference-implementation onboarding material, not protocol
/// messages. They contain bearer credentials and therefore must be delivered
/// through a trusted channel. Diagnostics redact the complete value, and the
/// credential bytes are zeroized on drop.
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
    enrollment_token: [u8; TOKEN_LENGTH],
    join_token: [u8; TOKEN_LENGTH],
}

impl JoinInvitation {
    /// Validates and owns all public trust and single-use credential material.
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
            enrollment_token,
            join_token,
        })
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
        Zeroizing::new(format!("{TEXT_PREFIX}{}", URL_SAFE_NO_PAD.encode(&*bytes)))
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
    #[error("invitation must begin with stella1:")]
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
    if !cursor.is_empty() {
        return Err(InvitationError::TrailingBytes);
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
    use std::{net::SocketAddr, str::FromStr};

    use super::{InvitationError, JoinInvitation};
    use crate::{ControllerId, NetworkId};

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
}
