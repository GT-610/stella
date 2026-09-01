//! Stateless short-lived relay credential issuance and verification.

use std::{fmt, str::FromStr};

use base64::{engine::general_purpose::STANDARD, Engine as _};
use hmac::{Hmac, KeyInit, Mac};
use sha2::Sha256;
use stella_common::{NodeId, RelayId};
use stella_proto::MAX_RELAY_CREDENTIAL_LIFETIME_SECONDS;
use subtle::ConstantTimeEq;
use thiserror::Error;
use zeroize::Zeroizing;

const CREDENTIAL_DOMAIN: &[u8] = b"stella relay credential v1\0";
/// Exact length of one deployment relay credential HMAC key.
pub const RELAY_CREDENTIAL_KEY_LENGTH: usize = 32;
/// Minimum supported relay credential lifetime.
pub const MIN_RELAY_CREDENTIAL_LIFETIME_SECONDS: u64 = 60;

type HmacSha256 = Hmac<Sha256>;

/// Stateless deployment authority for node-scoped short-lived relay credentials.
pub struct RelayCredentialAuthority {
    key: Zeroizing<[u8; RELAY_CREDENTIAL_KEY_LENGTH]>,
    lifetime_seconds: u64,
}

impl RelayCredentialAuthority {
    /// Creates an authority from a protected 256-bit deployment key.
    ///
    /// # Errors
    ///
    /// Returns [`RelayCredentialError`] when the lifetime is outside the
    /// protocol's supported range.
    pub fn new(
        key: [u8; RELAY_CREDENTIAL_KEY_LENGTH],
        lifetime_seconds: u64,
    ) -> Result<Self, RelayCredentialError> {
        if key.iter().all(|byte| *byte == 0) {
            return Err(RelayCredentialError::AllZeroKey);
        }
        if !(MIN_RELAY_CREDENTIAL_LIFETIME_SECONDS..=MAX_RELAY_CREDENTIAL_LIFETIME_SECONDS)
            .contains(&lifetime_seconds)
        {
            return Err(RelayCredentialError::LifetimeOutOfRange {
                actual: lifetime_seconds,
            });
        }
        Ok(Self {
            key: Zeroizing::new(key),
            lifetime_seconds,
        })
    }

    /// Issues one credential bound to a relay, node, and exclusive expiry.
    ///
    /// # Errors
    ///
    /// Returns [`RelayCredentialError`] for zero identities, clock overflow,
    /// or an unavailable HMAC construction.
    pub fn issue(
        &self,
        relay_id: RelayId,
        node_id: NodeId,
        now: u64,
    ) -> Result<RelayCredential, RelayCredentialError> {
        if relay_id.is_zero() {
            return Err(RelayCredentialError::ZeroRelayId);
        }
        if node_id.is_zero() {
            return Err(RelayCredentialError::ZeroNodeId);
        }
        let expires_at = now
            .checked_add(self.lifetime_seconds)
            .ok_or(RelayCredentialError::ExpiryOverflow)?;
        let username = Zeroizing::new(format!("{expires_at}:{node_id}").into_bytes());
        let secret = self.secret(relay_id, &username)?;
        Ok(RelayCredential {
            issued_at: now,
            expires_at,
            username,
            secret,
        })
    }

    /// Verifies a credential at `now` and returns its authenticated node.
    ///
    /// Malformed, non-canonical, expired, incorrectly scoped, or forged
    /// credentials all return `None` without exposing a detailed oracle.
    #[must_use]
    pub fn verify(
        &self,
        relay_id: RelayId,
        username: &[u8],
        secret: &[u8],
        now: u64,
    ) -> Option<NodeId> {
        if relay_id.is_zero() {
            return None;
        }
        let (expires_at, node_id) = parse_username(username)?;
        if expires_at <= now {
            return None;
        }
        let expected = self.secret(relay_id, username).ok()?;
        bool::from(expected.as_slice().ct_eq(secret)).then_some(node_id)
    }

    fn secret(
        &self,
        relay_id: RelayId,
        username: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>, RelayCredentialError> {
        let mut mac = <HmacSha256 as KeyInit>::new_from_slice(self.key.as_ref())
            .map_err(|_| RelayCredentialError::InvalidKey)?;
        mac.update(CREDENTIAL_DOMAIN);
        mac.update(relay_id.as_bytes());
        mac.update(username);
        Ok(Zeroizing::new(
            STANDARD.encode(mac.finalize().into_bytes()).into_bytes(),
        ))
    }
}

impl fmt::Debug for RelayCredentialAuthority {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RelayCredentialAuthority")
            .field("key", &"[REDACTED]")
            .field("lifetime_seconds", &self.lifetime_seconds)
            .finish()
    }
}

/// Controller-issued relay credential whose secret storage is zeroized on drop.
pub struct RelayCredential {
    issued_at: u64,
    expires_at: u64,
    username: Zeroizing<Vec<u8>>,
    secret: Zeroizing<Vec<u8>>,
}

impl RelayCredential {
    /// Returns the credential issue Unix time.
    #[must_use]
    pub const fn issued_at(&self) -> u64 {
        self.issued_at
    }

    /// Returns the exclusive credential expiry Unix time.
    #[must_use]
    pub const fn expires_at(&self) -> u64 {
        self.expires_at
    }

    /// Borrows the printable relay authentication username.
    #[must_use]
    pub fn username(&self) -> &[u8] {
        &self.username
    }

    /// Borrows the base64-encoded HMAC authentication secret.
    #[must_use]
    pub fn secret(&self) -> &[u8] {
        &self.secret
    }
}

impl fmt::Debug for RelayCredential {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RelayCredential")
            .field("issued_at", &self.issued_at)
            .field("expires_at", &self.expires_at)
            .field("username_length", &self.username.len())
            .field("secret_length", &self.secret.len())
            .finish_non_exhaustive()
    }
}

fn parse_username(username: &[u8]) -> Option<(u64, NodeId)> {
    let text = std::str::from_utf8(username).ok()?;
    let (expiry_text, node_text) = text.split_once(':')?;
    if expiry_text.is_empty()
        || node_text.is_empty()
        || node_text.contains(':')
        || (expiry_text.len() > 1 && expiry_text.starts_with('0'))
    {
        return None;
    }
    let expires_at = expiry_text.parse::<u64>().ok()?;
    let node_id = NodeId::from_str(node_text).ok()?;
    if node_id.is_zero() || node_id.to_string() != node_text {
        return None;
    }
    Some((expires_at, node_id))
}

#[derive(Debug, Error)]
/// Failure while configuring or issuing relay credentials.
#[non_exhaustive]
pub enum RelayCredentialError {
    /// An all-zero deployment key provides no meaningful secret.
    #[error("relay credential HMAC key must not be all zero")]
    AllZeroKey,
    /// The requested lifetime is outside the protocol bound.
    #[error(
        "relay credential lifetime {actual} is outside {MIN_RELAY_CREDENTIAL_LIFETIME_SECONDS}..={MAX_RELAY_CREDENTIAL_LIFETIME_SECONDS} seconds"
    )]
    LifetimeOutOfRange {
        /// Requested lifetime in seconds.
        actual: u64,
    },
    /// Relay zero is reserved and cannot receive credentials.
    #[error("relay credential cannot target the zero relay ID")]
    ZeroRelayId,
    /// Node zero is reserved and cannot own credentials.
    #[error("relay credential cannot target the zero node ID")]
    ZeroNodeId,
    /// Adding the lifetime to the issue time overflowed.
    #[error("relay credential expiry overflowed Unix time")]
    ExpiryOverflow,
    /// The fixed-width key could not initialize HMAC.
    #[error("relay credential HMAC key is invalid")]
    InvalidKey,
}

#[cfg(test)]
mod tests {
    use stella_common::{NodeId, RelayId};

    use super::{RelayCredentialAuthority, RelayCredentialError};

    #[test]
    fn credentials_are_scoped_expiring_and_redacted() {
        let authority =
            RelayCredentialAuthority::new([0x42; 32], 300).expect("valid credential authority");
        let relay_id = RelayId::from_bytes([0x11; 16]);
        let other_relay = RelayId::from_bytes([0x12; 16]);
        let node_id = NodeId::from_bytes([0xab; 16]);
        let credential = authority
            .issue(relay_id, node_id, 1_000)
            .expect("issue credential");
        assert_eq!(credential.issued_at(), 1_000);
        assert_eq!(credential.expires_at(), 1_300);
        assert_eq!(
            authority.verify(relay_id, credential.username(), credential.secret(), 1_299),
            Some(node_id)
        );
        assert_eq!(
            authority.verify(
                other_relay,
                credential.username(),
                credential.secret(),
                1_299
            ),
            None
        );
        assert_eq!(
            authority.verify(relay_id, credential.username(), credential.secret(), 1_300),
            None
        );
        let mut tampered = credential.secret().to_vec();
        tampered[0] ^= 1;
        assert_eq!(
            authority.verify(relay_id, credential.username(), &tampered, 1_299),
            None
        );
        let diagnostic = format!("{credential:?} {authority:?}");
        assert!(!diagnostic
            .contains(std::str::from_utf8(credential.username()).expect("username is ASCII")));
        assert!(!diagnostic
            .contains(std::str::from_utf8(credential.secret()).expect("secret is base64")));
    }

    #[test]
    fn lifetime_identity_and_username_encoding_are_strict() {
        assert!(matches!(
            RelayCredentialAuthority::new([0; 32], 300),
            Err(RelayCredentialError::AllZeroKey)
        ));
        assert!(matches!(
            RelayCredentialAuthority::new([0x42; 32], 59),
            Err(RelayCredentialError::LifetimeOutOfRange { actual: 59 })
        ));
        let authority =
            RelayCredentialAuthority::new([0x42; 32], 300).expect("valid credential authority");
        let relay_id = RelayId::from_bytes([0x11; 16]);
        let node_id = NodeId::from_bytes([0xab; 16]);
        assert!(matches!(
            authority.issue(RelayId::from_bytes([0; 16]), node_id, 1_000),
            Err(RelayCredentialError::ZeroRelayId)
        ));
        assert!(matches!(
            authority.issue(relay_id, NodeId::from_bytes([0; 16]), 1_000),
            Err(RelayCredentialError::ZeroNodeId)
        ));
        let credential = authority
            .issue(relay_id, node_id, 1_000)
            .expect("issue credential");
        let uppercase = std::str::from_utf8(credential.username())
            .expect("username is ASCII")
            .to_ascii_uppercase();
        assert_eq!(
            authority.verify(relay_id, uppercase.as_bytes(), credential.secret(), 1_100),
            None
        );
        assert_eq!(
            authority.verify(
                relay_id,
                format!(
                    "0{}",
                    std::str::from_utf8(credential.username()).expect("ASCII")
                )
                .as_bytes(),
                credential.secret(),
                1_100
            ),
            None
        );
    }
}
