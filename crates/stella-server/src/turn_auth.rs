//! TURN long-term credential authentication for Stella relay requests.

use std::{fmt, sync::Arc};

use hmac::{Hmac, KeyInit, Mac};
use sha2::{Digest, Sha256};
use stella_common::{NodeId, RelayId};
use stella_proto::{
    CodecError, StunAttributeType, StunClass, StunMessageView, StunPasswordAlgorithm,
    STUN_MESSAGE_INTEGRITY_SHA256_LENGTH,
};
use subtle::ConstantTimeEq;
use thiserror::Error;
use zeroize::Zeroizing;

use crate::relay_credentials::{RelayCredentialAuthority, RelayCredentialError, TurnNonceStatus};

type HmacSha256 = Hmac<Sha256>;

const REALM_PREFIX: &str = "stella-relay:";

/// Relay-scoped TURN long-term credential verifier.
pub struct TurnAuthenticator {
    authority: Arc<RelayCredentialAuthority>,
    relay_id: RelayId,
    realm: Box<[u8]>,
}

impl TurnAuthenticator {
    /// Creates an authenticator for one non-zero relay identity.
    ///
    /// # Errors
    ///
    /// Returns [`RelayCredentialError::ZeroRelayId`] for the reserved zero
    /// relay identity.
    pub fn new(
        authority: RelayCredentialAuthority,
        relay_id: RelayId,
    ) -> Result<Self, RelayCredentialError> {
        Self::new_shared(Arc::new(authority), relay_id)
    }

    pub(crate) fn new_shared(
        authority: Arc<RelayCredentialAuthority>,
        relay_id: RelayId,
    ) -> Result<Self, RelayCredentialError> {
        if relay_id.is_zero() {
            return Err(RelayCredentialError::ZeroRelayId);
        }
        let realm = format!("{REALM_PREFIX}{relay_id}")
            .into_bytes()
            .into_boxed_slice();
        Ok(Self {
            authority,
            relay_id,
            realm,
        })
    }

    /// Returns the stable relay identity authenticated by this verifier.
    #[must_use]
    pub const fn relay_id(&self) -> RelayId {
        self.relay_id
    }

    /// Borrows the canonical printable TURN realm.
    #[must_use]
    pub fn realm(&self) -> &[u8] {
        &self.realm
    }

    /// Issues a fresh stateless challenge nonce at Unix time `now`.
    ///
    /// # Errors
    ///
    /// Returns [`RelayCredentialError`] if nonce expiry overflows or the
    /// deployment HMAC key cannot be initialized.
    pub fn issue_challenge(&self, now: u64) -> Result<TurnChallenge, RelayCredentialError> {
        Ok(TurnChallenge {
            realm: self.realm.clone(),
            nonce: self.authority.issue_turn_nonce(self.relay_id, now)?,
        })
    }

    /// Authenticates one decoded TURN request and returns its node identity.
    ///
    /// The method accepts only request-class messages and the Stella SHA-256
    /// long-term credential profile. Credential, password, realm, nonce, and
    /// HMAC mismatches deliberately collapse to one unauthorized result.
    ///
    /// # Errors
    ///
    /// Returns [`TurnAuthenticationError::Unauthorized`] for absent or invalid
    /// credentials, [`TurnAuthenticationError::StaleNonce`] only after all
    /// other authentication succeeds, or
    /// [`TurnAuthenticationError::Malformed`] for duplicate or structurally
    /// invalid authentication attributes.
    pub fn authenticate(
        &self,
        message: &StunMessageView<'_>,
        now: u64,
    ) -> Result<AuthenticatedTurnRequest, TurnAuthenticationError> {
        let (authenticated, nonce_status) = self.authenticate_including_stale(message, now)?;
        if nonce_status == TurnNonceStatus::Expired {
            return Err(TurnAuthenticationError::StaleNonce);
        }
        Ok(authenticated)
    }

    pub(crate) fn authenticate_including_stale(
        &self,
        message: &StunMessageView<'_>,
        now: u64,
    ) -> Result<(AuthenticatedTurnRequest, TurnNonceStatus), TurnAuthenticationError> {
        if message.message_type().class != StunClass::Request {
            return Err(TurnAuthenticationError::Malformed {
                detail: "authentication is defined only for request messages",
            });
        }

        let attributes = AuthenticationAttributes::parse(message)?;
        if !bool::from(attributes.realm.ct_eq(&self.realm)) {
            return Err(TurnAuthenticationError::Unauthorized);
        }
        StunPasswordAlgorithm::decode(attributes.password_algorithm)
            .map_err(|_| TurnAuthenticationError::Unauthorized)?;
        let nonce_status = self
            .authority
            .verify_turn_nonce(self.relay_id, attributes.nonce, now);
        if nonce_status == TurnNonceStatus::Invalid {
            return Err(TurnAuthenticationError::Unauthorized);
        }

        let resolved = self
            .authority
            .resolve(self.relay_id, attributes.username, now)
            .ok_or(TurnAuthenticationError::Unauthorized)?;
        let key = derive_long_term_key(attributes.username, attributes.realm, &resolved.password);
        let integrity =
            message
                .message_integrity_sha256()
                .map_err(|_| TurnAuthenticationError::Malformed {
                    detail: "invalid MESSAGE-INTEGRITY-SHA256 boundary",
                })?;
        let mut mac = <HmacSha256 as KeyInit>::new_from_slice(key.as_ref())
            .map_err(|_| TurnAuthenticationError::Unauthorized)?;
        mac.update(integrity.message_type_bytes());
        mac.update(&integrity.adjusted_body_length().to_be_bytes());
        mac.update(integrity.bytes_after_length());
        let actual = mac.finalize().into_bytes();
        if !bool::from(actual.as_slice().ct_eq(integrity.value())) {
            return Err(TurnAuthenticationError::Unauthorized);
        }
        Ok((
            AuthenticatedTurnRequest {
                node_id: resolved.node_id,
                key,
            },
            nonce_status,
        ))
    }
}

impl fmt::Debug for TurnAuthenticator {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("TurnAuthenticator")
            .field("authority", &self.authority)
            .field("relay_id", &self.relay_id)
            .field("realm", &String::from_utf8_lossy(&self.realm))
            .finish()
    }
}

/// Authenticated TURN request identity and response-integrity context.
pub struct AuthenticatedTurnRequest {
    node_id: NodeId,
    key: Zeroizing<[u8; 32]>,
}

impl AuthenticatedTurnRequest {
    /// Returns the node identity bound to the controller-issued credential.
    #[must_use]
    pub const fn node_id(&self) -> NodeId {
        self.node_id
    }

    pub(crate) fn sign_encoded_message(
        &self,
        encoded: &mut [u8],
    ) -> Result<(), TurnResponseIntegrityError> {
        let (value_offset, tag) = {
            let message = StunMessageView::decode(encoded)?;
            let integrity = message.message_integrity_sha256()?;
            let mut mac = <HmacSha256 as KeyInit>::new_from_slice(self.key.as_ref())
                .map_err(|_| TurnResponseIntegrityError::InvalidKey)?;
            mac.update(integrity.message_type_bytes());
            mac.update(&integrity.adjusted_body_length().to_be_bytes());
            mac.update(integrity.bytes_after_length());
            (integrity.value_offset(), mac.finalize().into_bytes())
        };
        let end = value_offset
            .checked_add(STUN_MESSAGE_INTEGRITY_SHA256_LENGTH)
            .ok_or(TurnResponseIntegrityError::RangeOverflow)?;
        let Some(destination) = encoded.get_mut(value_offset..end) else {
            return Err(TurnResponseIntegrityError::RangeOutsideMessage);
        };
        destination.copy_from_slice(&tag);
        Ok(())
    }
}

impl fmt::Debug for AuthenticatedTurnRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AuthenticatedTurnRequest")
            .field("node_id", &self.node_id)
            .field("key", &"[REDACTED]")
            .finish()
    }
}

#[derive(Debug, Error)]
pub(crate) enum TurnResponseIntegrityError {
    #[error(transparent)]
    Codec(#[from] CodecError),
    #[error("TURN response integrity key is invalid")]
    InvalidKey,
    #[error("TURN response integrity range overflowed")]
    RangeOverflow,
    #[error("TURN response integrity range is outside the encoded message")]
    RangeOutsideMessage,
}

/// Public values required in a TURN 401 or 438 authentication challenge.
pub struct TurnChallenge {
    realm: Box<[u8]>,
    nonce: Zeroizing<Vec<u8>>,
}

impl TurnChallenge {
    /// Borrows the canonical relay realm.
    #[must_use]
    pub fn realm(&self) -> &[u8] {
        &self.realm
    }

    /// Borrows the unpadded base64url stateless nonce.
    #[must_use]
    pub fn nonce(&self) -> &[u8] {
        &self.nonce
    }

    /// Returns the only password algorithm permitted by the profile.
    #[must_use]
    pub const fn password_algorithm(&self) -> StunPasswordAlgorithm {
        StunPasswordAlgorithm::Sha256
    }
}

impl fmt::Debug for TurnChallenge {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("TurnChallenge")
            .field("realm", &String::from_utf8_lossy(&self.realm))
            .field("nonce", &"[REDACTED]")
            .finish()
    }
}

/// Safe classification of a TURN request authentication failure.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
#[non_exhaustive]
pub enum TurnAuthenticationError {
    /// Authentication is absent or invalid without a more specific oracle.
    #[error("TURN request authentication failed")]
    Unauthorized,
    /// Authentication succeeded but its stateless nonce expired.
    #[error("TURN request nonce is stale")]
    StaleNonce,
    /// Authentication attributes violate the strict Stella profile.
    #[error("malformed TURN authentication attributes: {detail}")]
    Malformed {
        /// Stable non-sensitive rule description.
        detail: &'static str,
    },
}

struct AuthenticationAttributes<'a> {
    username: &'a [u8],
    realm: &'a [u8],
    nonce: &'a [u8],
    password_algorithm: &'a [u8],
}

impl<'a> AuthenticationAttributes<'a> {
    fn parse(message: &StunMessageView<'a>) -> Result<Self, TurnAuthenticationError> {
        let mut username = None;
        let mut realm = None;
        let mut nonce = None;
        let mut password_algorithm = None;
        let mut integrity_seen = false;
        for attribute in message.attributes() {
            let attribute = attribute.map_err(|_| TurnAuthenticationError::Malformed {
                detail: "invalid attribute framing",
            })?;
            let attribute_type = attribute.attribute_type();
            if attribute_type == StunAttributeType::MESSAGE_INTEGRITY
                || attribute_type == StunAttributeType::USERHASH
            {
                return Err(TurnAuthenticationError::Malformed {
                    detail: "legacy or hashed-username authentication is unsupported",
                });
            }
            if attribute_type == StunAttributeType::USERNAME {
                set_unique(&mut username, attribute.value(), "duplicate USERNAME")?;
            } else if attribute_type == StunAttributeType::REALM {
                set_unique(&mut realm, attribute.value(), "duplicate REALM")?;
            } else if attribute_type == StunAttributeType::NONCE {
                set_unique(&mut nonce, attribute.value(), "duplicate NONCE")?;
            } else if attribute_type == StunAttributeType::PASSWORD_ALGORITHM {
                set_unique(
                    &mut password_algorithm,
                    attribute.value(),
                    "duplicate PASSWORD-ALGORITHM",
                )?;
            } else if attribute_type == StunAttributeType::MESSAGE_INTEGRITY_SHA256 {
                if integrity_seen {
                    return Err(TurnAuthenticationError::Malformed {
                        detail: "duplicate MESSAGE-INTEGRITY-SHA256",
                    });
                }
                integrity_seen = true;
            }
        }
        if !integrity_seen {
            return Err(TurnAuthenticationError::Unauthorized);
        }
        Ok(Self {
            username: username.ok_or(TurnAuthenticationError::Unauthorized)?,
            realm: realm.ok_or(TurnAuthenticationError::Unauthorized)?,
            nonce: nonce.ok_or(TurnAuthenticationError::Unauthorized)?,
            password_algorithm: password_algorithm.ok_or(TurnAuthenticationError::Unauthorized)?,
        })
    }
}

fn set_unique<'a>(
    slot: &mut Option<&'a [u8]>,
    value: &'a [u8],
    detail: &'static str,
) -> Result<(), TurnAuthenticationError> {
    if slot.replace(value).is_some() {
        return Err(TurnAuthenticationError::Malformed { detail });
    }
    Ok(())
}

fn derive_long_term_key(username: &[u8], realm: &[u8], password: &[u8]) -> Zeroizing<[u8; 32]> {
    let mut digest = Sha256::new();
    digest.update(username);
    digest.update(b":");
    digest.update(realm);
    digest.update(b":");
    digest.update(password);
    Zeroizing::new(digest.finalize().into())
}

#[cfg(test)]
mod tests {
    use hmac::{KeyInit, Mac};
    use stella_common::{NodeId, RelayId};
    use stella_proto::{
        encode_stun_message, StunAttributeRef, StunAttributeType, StunClass, StunMessageRef,
        StunMessageType, StunMessageView, StunMethod, StunPasswordAlgorithm, StunTransactionId,
    };

    use super::{derive_long_term_key, HmacSha256, TurnAuthenticationError, TurnAuthenticator};
    use crate::relay_credentials::RelayCredentialAuthority;

    const TRANSACTION_ID: StunTransactionId =
        StunTransactionId::from_bytes([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12]);

    #[test]
    fn issued_credentials_authenticate_and_diagnostics_redact_secrets() {
        let relay_id = RelayId::from_bytes([0x11; 16]);
        let node_id = NodeId::from_bytes([0x22; 16]);
        let authority =
            RelayCredentialAuthority::new([0x42; 32], 300).expect("valid credential authority");
        let credential = authority
            .issue(relay_id, node_id, 1_000)
            .expect("issue relay credential");
        let authenticator = TurnAuthenticator::new(authority, relay_id).expect("authenticator");
        let challenge = authenticator
            .issue_challenge(1_000)
            .expect("issue challenge");
        let encoded = signed_allocate_request(
            credential.username(),
            challenge.realm(),
            challenge.nonce(),
            credential.secret(),
        );
        let message = StunMessageView::decode(&encoded).expect("decode signed request");
        let authenticated = authenticator
            .authenticate(&message, 1_001)
            .expect("authenticate request");
        assert_eq!(authenticated.node_id(), node_id);
        let diagnostic = format!("{authenticator:?} {challenge:?} {authenticated:?}");
        assert!(!diagnostic
            .contains(std::str::from_utf8(challenge.nonce()).expect("nonce is printable ASCII")));
        assert!(!diagnostic.contains(
            std::str::from_utf8(credential.secret()).expect("secret is printable base64")
        ));
    }

    #[test]
    fn stale_nonce_is_reported_only_after_valid_hmac() {
        let relay_id = RelayId::from_bytes([0x31; 16]);
        let node_id = NodeId::from_bytes([0x32; 16]);
        let authority =
            RelayCredentialAuthority::new([0x43; 32], 300).expect("valid credential authority");
        let credential = authority
            .issue(relay_id, node_id, 1_000)
            .expect("issue relay credential");
        let authenticator = TurnAuthenticator::new(authority, relay_id).expect("authenticator");
        let challenge = authenticator
            .issue_challenge(1_000)
            .expect("issue challenge");
        let mut encoded = signed_allocate_request(
            credential.username(),
            challenge.realm(),
            challenge.nonce(),
            credential.secret(),
        );
        let message = StunMessageView::decode(&encoded).expect("decode signed request");
        assert!(matches!(
            authenticator.authenticate(&message, 1_120),
            Err(TurnAuthenticationError::StaleNonce)
        ));
        let integrity_offset = message
            .message_integrity_sha256()
            .expect("integrity range")
            .value_offset();
        encoded[integrity_offset] ^= 1;
        let tampered = StunMessageView::decode(&encoded).expect("decode tampered request");
        assert!(matches!(
            authenticator.authenticate(&tampered, 1_120),
            Err(TurnAuthenticationError::Unauthorized)
        ));
    }

    #[test]
    fn wrong_realm_duplicate_and_legacy_authentication_fail_closed() {
        let relay_id = RelayId::from_bytes([0x51; 16]);
        let authority =
            RelayCredentialAuthority::new([0x44; 32], 300).expect("valid credential authority");
        let node_id = NodeId::from_bytes([0x52; 16]);
        let credential = authority
            .issue(relay_id, node_id, 2_000)
            .expect("issue relay credential");
        let authenticator = TurnAuthenticator::new(authority, relay_id).expect("authenticator");
        let challenge = authenticator
            .issue_challenge(2_000)
            .expect("issue challenge");
        let wrong_realm = signed_allocate_request(
            credential.username(),
            b"stella-relay:ffffffffffffffffffffffffffffffff",
            challenge.nonce(),
            credential.secret(),
        );
        assert!(matches!(
            authenticator.authenticate(
                &StunMessageView::decode(&wrong_realm).expect("decode wrong realm request"),
                2_001
            ),
            Err(TurnAuthenticationError::Unauthorized)
        ));

        let zero_integrity = [0_u8; 32];
        let duplicate = [
            StunAttributeRef {
                attribute_type: StunAttributeType::USERNAME,
                value: credential.username(),
            },
            StunAttributeRef {
                attribute_type: StunAttributeType::USERNAME,
                value: credential.username(),
            },
            StunAttributeRef {
                attribute_type: StunAttributeType::MESSAGE_INTEGRITY_SHA256,
                value: &zero_integrity,
            },
        ];
        let duplicate = encode_request(&duplicate);
        assert!(matches!(
            authenticator.authenticate(
                &StunMessageView::decode(&duplicate).expect("decode duplicate request"),
                2_001
            ),
            Err(TurnAuthenticationError::Malformed { .. })
        ));

        let legacy_integrity = [0_u8; 20];
        let legacy = [StunAttributeRef {
            attribute_type: StunAttributeType::MESSAGE_INTEGRITY,
            value: &legacy_integrity,
        }];
        let legacy = encode_request(&legacy);
        assert!(matches!(
            authenticator.authenticate(
                &StunMessageView::decode(&legacy).expect("decode legacy request"),
                2_001
            ),
            Err(TurnAuthenticationError::Malformed { .. })
        ));
    }

    fn signed_allocate_request(
        username: &[u8],
        realm: &[u8],
        nonce: &[u8],
        password: &[u8],
    ) -> Vec<u8> {
        let mut algorithm = [0_u8; 4];
        StunPasswordAlgorithm::Sha256
            .encode(&mut algorithm)
            .expect("encode password algorithm");
        let requested_transport = [17, 0, 0, 0];
        let zero_integrity = [0_u8; 32];
        let attributes = [
            StunAttributeRef {
                attribute_type: StunAttributeType::USERNAME,
                value: username,
            },
            StunAttributeRef {
                attribute_type: StunAttributeType::REALM,
                value: realm,
            },
            StunAttributeRef {
                attribute_type: StunAttributeType::NONCE,
                value: nonce,
            },
            StunAttributeRef {
                attribute_type: StunAttributeType::PASSWORD_ALGORITHM,
                value: &algorithm,
            },
            StunAttributeRef {
                attribute_type: StunAttributeType::REQUESTED_TRANSPORT,
                value: &requested_transport,
            },
            StunAttributeRef {
                attribute_type: StunAttributeType::MESSAGE_INTEGRITY_SHA256,
                value: &zero_integrity,
            },
        ];
        let mut encoded = encode_request(&attributes);
        let message = StunMessageView::decode(&encoded).expect("decode unsigned request");
        let integrity = message
            .message_integrity_sha256()
            .expect("locate integrity range");
        let key = derive_long_term_key(username, realm, password);
        let mut mac =
            <HmacSha256 as KeyInit>::new_from_slice(key.as_ref()).expect("fixed HMAC key");
        mac.update(integrity.message_type_bytes());
        mac.update(&integrity.adjusted_body_length().to_be_bytes());
        mac.update(integrity.bytes_after_length());
        let tag = mac.finalize().into_bytes();
        let value_offset = integrity.value_offset();
        encoded[value_offset..value_offset + tag.len()].copy_from_slice(&tag);
        encoded
    }

    fn encode_request(attributes: &[StunAttributeRef<'_>]) -> Vec<u8> {
        let message = StunMessageRef {
            message_type: StunMessageType::new(StunMethod::Allocate, StunClass::Request),
            transaction_id: TRANSACTION_ID,
            attributes,
        };
        let mut encoded = vec![0_u8; message.encoded_len().expect("request length")];
        encode_stun_message(message, &mut encoded).expect("encode request");
        encoded
    }
}
