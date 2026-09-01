//! Per-node encoding of deployment STUN and relay configuration.

use std::{
    fmt,
    io::Read,
    sync::atomic::{AtomicU64, Ordering},
};

use stella_common::NodeId;
use stella_proto::{
    encode_relay_service_list, encode_stun_server_list, CodecError, RelayServiceRef,
    STUN_SERVER_RECORD_LENGTH,
};
use thiserror::Error;
use zeroize::Zeroizing;

use crate::{
    config::ConnectivityServicesConfig,
    identity::{open_protected_secret_file, IdentityFileError},
    relay_credentials::{
        RelayCredential, RelayCredentialAuthority, RelayCredentialError,
        RELAY_CREDENTIAL_KEY_LENGTH,
    },
};

pub(crate) struct ConnectivityConfigIssuer {
    config: ConnectivityServicesConfig,
    credentials: RelayCredentialAuthority,
    stun_server_list: Vec<u8>,
    next_revision: AtomicU64,
}

impl ConnectivityConfigIssuer {
    pub(crate) fn load(
        config: &ConnectivityServicesConfig,
    ) -> Result<Self, ConnectivityConfigError> {
        let key = load_credential_key(config)?;
        let credentials = RelayCredentialAuthority::new(key, config.credential_lifetime_seconds)?;
        let stun_length = 4_usize
            .checked_add(
                config
                    .stun_servers
                    .len()
                    .checked_mul(STUN_SERVER_RECORD_LENGTH)
                    .ok_or(ConnectivityConfigError::LengthOverflow)?,
            )
            .ok_or(ConnectivityConfigError::LengthOverflow)?;
        let mut stun_server_list = vec![0; stun_length];
        let encoded = encode_stun_server_list(&config.stun_servers, &mut stun_server_list)?;
        stun_server_list.truncate(encoded);
        Ok(Self {
            config: config.clone(),
            credentials,
            stun_server_list,
            next_revision: AtomicU64::new(config.revision),
        })
    }

    pub(crate) fn issue(
        &self,
        node_id: NodeId,
        now: u64,
    ) -> Result<EncodedConnectivityConfig, ConnectivityConfigError> {
        let revision = self
            .next_revision
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |revision| {
                revision.checked_add(1)
            })
            .map_err(|_| ConnectivityConfigError::RevisionExhausted)?;
        let credentials = self
            .config
            .relay_services
            .iter()
            .map(|service| self.credentials.issue(service.relay_id, node_id, now))
            .collect::<Result<Vec<_>, _>>()?;
        let services = self
            .config
            .relay_services
            .iter()
            .zip(&credentials)
            .map(|(service, credential)| service.with_credential(credential))
            .collect::<Vec<_>>();
        let relay_length = relay_service_list_length(&services)?;
        let mut relay_service_list = Zeroizing::new(vec![0; relay_length]);
        let encoded = encode_relay_service_list(&services, &mut relay_service_list)?;
        relay_service_list.truncate(encoded);
        let credential_expires_at = credentials
            .iter()
            .map(RelayCredential::expires_at)
            .min()
            .ok_or(ConnectivityConfigError::NoRelayServices)?;
        Ok(EncodedConnectivityConfig {
            revision,
            credential_expires_at,
            stun_server_list: self.stun_server_list.clone(),
            relay_service_list,
        })
    }
}

impl fmt::Debug for ConnectivityConfigIssuer {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ConnectivityConfigIssuer")
            .field("stun_server_count", &self.config.stun_servers.len())
            .field("relay_service_count", &self.config.relay_services.len())
            .field("credentials", &self.credentials)
            .finish_non_exhaustive()
    }
}

pub(crate) struct EncodedConnectivityConfig {
    revision: u64,
    credential_expires_at: u64,
    stun_server_list: Vec<u8>,
    relay_service_list: Zeroizing<Vec<u8>>,
}

impl EncodedConnectivityConfig {
    pub(crate) const fn revision(&self) -> u64 {
        self.revision
    }

    pub(crate) const fn credential_expires_at(&self) -> u64 {
        self.credential_expires_at
    }

    pub(crate) fn stun_server_list(&self) -> &[u8] {
        &self.stun_server_list
    }

    pub(crate) fn relay_service_list(&self) -> &[u8] {
        &self.relay_service_list
    }
}

impl fmt::Debug for EncodedConnectivityConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("EncodedConnectivityConfig")
            .field("revision", &self.revision)
            .field("credential_expires_at", &self.credential_expires_at)
            .field("stun_server_list_length", &self.stun_server_list.len())
            .field("relay_service_list_length", &self.relay_service_list.len())
            .finish_non_exhaustive()
    }
}

fn load_credential_key(
    config: &ConnectivityServicesConfig,
) -> Result<[u8; RELAY_CREDENTIAL_KEY_LENGTH], ConnectivityConfigError> {
    let mut file = open_protected_secret_file(&config.credential_key_path)?;
    let length = file
        .metadata()
        .map_err(|source| ConnectivityConfigError::KeyMetadata { source })?
        .len();
    if length != RELAY_CREDENTIAL_KEY_LENGTH as u64 {
        return Err(ConnectivityConfigError::KeyLength { actual: length });
    }
    let mut key = [0_u8; RELAY_CREDENTIAL_KEY_LENGTH];
    file.read_exact(&mut key)
        .map_err(|source| ConnectivityConfigError::KeyRead { source })?;
    Ok(key)
}

fn relay_service_list_length(
    services: &[RelayServiceRef<'_>],
) -> Result<usize, ConnectivityConfigError> {
    services.iter().try_fold(4_usize, |length, service| {
        length
            .checked_add(service.encoded_len()?)
            .ok_or(ConnectivityConfigError::LengthOverflow)
    })
}

#[derive(Debug, Error)]
pub(crate) enum ConnectivityConfigError {
    #[error(transparent)]
    KeyFile(#[from] IdentityFileError),
    #[error("unable to read relay credential key metadata: {source}")]
    KeyMetadata { source: std::io::Error },
    #[error("relay credential key contains {actual} bytes instead of 32")]
    KeyLength { actual: u64 },
    #[error("unable to read relay credential key: {source}")]
    KeyRead { source: std::io::Error },
    #[error(transparent)]
    Credential(#[from] RelayCredentialError),
    #[error(transparent)]
    Codec(#[from] CodecError),
    #[error("connectivity configuration length overflow")]
    LengthOverflow,
    #[error("connectivity configuration contains no relay services")]
    NoRelayServices,
    #[error("connectivity configuration revision is exhausted")]
    RevisionExhausted,
}

#[cfg(all(test, windows))]
mod tests {
    use std::{
        io::Write,
        net::{IpAddr, SocketAddr},
        path::PathBuf,
        sync::atomic::{AtomicU64, Ordering},
    };

    use stella_common::{NodeId, RelayId};
    use stella_proto::{
        RelayAddress, RelayCarrierMask, RelayPorts, RelayServiceListView, RelayTrustRequirements,
        StunServer, StunServerListView,
    };

    use super::ConnectivityConfigIssuer;
    use crate::{
        config::{ConnectivityServicesConfig, RelayServiceConfig},
        identity::create_protected_secret_file,
        relay_credentials::RelayCredentialAuthority,
    };

    static TEMP_SEQUENCE: AtomicU64 = AtomicU64::new(1);

    fn fixture() -> (PathBuf, ConnectivityServicesConfig) {
        let sequence = TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        let directory = std::env::temp_dir().join(format!(
            "stella-connectivity-config-{}-{sequence}",
            std::process::id()
        ));
        std::fs::create_dir(&directory).expect("create test directory");
        let key_path = directory.join("relay.key");
        let mut key_file = create_protected_secret_file(&key_path).expect("create protected key");
        key_file.write_all(&[0x42; 32]).expect("write key");
        key_file.sync_all().expect("sync key");
        drop(key_file);
        let relay_id = RelayId::from_bytes([0x11; 16]);
        let config = ConnectivityServicesConfig {
            revision: 7,
            credential_key_path: key_path,
            credential_lifetime_seconds: 300,
            stun_servers: vec![StunServer {
                priority: 0,
                address: SocketAddr::from(([192, 0, 2, 20], 3_478)),
            }],
            relay_services: vec![RelayServiceConfig {
                relay_id,
                carriers: RelayCarrierMask::TURN_UDP,
                priority: 0,
                max_datagram_size: 1_200,
                allocation_lifetime_seconds: 600,
                idle_timeout_seconds: 120,
                hostname: String::new(),
                tls_server_name: String::new(),
                region: String::from("test"),
                trust: RelayTrustRequirements::NONE,
                ports: RelayPorts {
                    turn_udp: 3_478,
                    turn_tcp: 0,
                    turn_tls: 0,
                    secure_websocket: 0,
                },
                addresses: vec![RelayAddress {
                    priority: 0,
                    address: IpAddr::from([192, 0, 2, 30]),
                }],
                spki_pins: Vec::new(),
            }],
        };
        (directory, config)
    }

    #[test]
    fn per_node_configuration_is_encoded_redacted_and_verifiable() {
        let (directory, config) = fixture();
        let issuer = ConnectivityConfigIssuer::load(&config).expect("load issuer");
        let node_id = NodeId::from_bytes([0x21; 16]);
        let encoded = issuer.issue(node_id, 1_000).expect("issue configuration");
        assert_eq!(encoded.revision(), 7);
        assert_eq!(encoded.credential_expires_at(), 1_300);
        assert_eq!(
            StunServerListView::decode(encoded.stun_server_list())
                .expect("decode STUN list")
                .len(),
            1
        );
        let relay = RelayServiceListView::decode(encoded.relay_service_list())
            .expect("decode relay list")
            .services()
            .next()
            .expect("relay service");
        let verifier = RelayCredentialAuthority::new([0x42; 32], 300).expect("credential verifier");
        assert_eq!(
            verifier.verify(
                relay.relay_id(),
                relay.credential_username(),
                relay.credential_secret(),
                1_299
            ),
            Some(node_id)
        );
        let diagnostic = format!("{issuer:?} {encoded:?}");
        assert!(!diagnostic
            .contains(std::str::from_utf8(relay.credential_secret()).expect("base64 secret")));
        let next = issuer.issue(node_id, 1_001).expect("issue next revision");
        assert_eq!(next.revision(), 8);
        std::fs::remove_dir_all(directory).expect("remove test directory");
    }
}
