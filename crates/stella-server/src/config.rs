//! Strict versioned controller configuration.

use std::{
    collections::BTreeSet,
    fs::File,
    io::Read,
    net::{IpAddr, SocketAddr},
    path::{Path, PathBuf},
    str::FromStr,
};

use base64::{engine::general_purpose::STANDARD, Engine as _};
use serde::Deserialize;
use stella_common::RelayId;
use stella_proto::{
    RelayAddress, RelayCarrierMask, RelayPorts, RelayServiceRef, RelayTrustRequirements,
    StunServer, MAX_RELAY_SERVICES, MAX_STUN_SERVERS,
};
use thiserror::Error;

use crate::relay_credentials::RelayCredential;

/// Supported controller configuration schema version.
pub const CONFIG_VERSION: u32 = 1;

/// Largest accepted UTF-8 controller configuration file.
pub const MAX_CONFIG_BYTES: u64 = 1_048_576;

const MAX_LOG_FILTER_BYTES: usize = 256;
const MAX_AUTHORITY_QUEUE: usize = 4_096;
const MAX_CONNECTIONS: usize = 65_535;
const MAX_OUTBOUND_MESSAGES: usize = 1_024;
const MAX_TLS_HANDSHAKE_TIMEOUT_SECONDS: u64 = 60;
const MAX_AUTHENTICATION_TIMEOUT_SECONDS: u64 = 10;
const MAX_REQUEST_TIMEOUT_SECONDS: u64 = 60;
const MAX_SHUTDOWN_TIMEOUT_SECONDS: u64 = 60;

/// Validated controller process configuration with resolved filesystem paths.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ServerConfig {
    /// Schema version loaded from the TOML document.
    pub version: u32,
    /// TCP address on which the TLS control service listens.
    pub listen: SocketAddr,
    /// redb authority database path.
    pub database_path: PathBuf,
    /// Controller Ed25519 identity PKCS#8 DER path.
    pub controller_identity_path: PathBuf,
    /// TLS server certificate chain in PEM format.
    pub tls_certificate_path: PathBuf,
    /// TLS server private key in PKCS#8 PEM or DER format.
    pub tls_private_key_path: PathBuf,
    /// Bounded runtime resource limits.
    pub limits: LimitsConfig,
    /// Structured logging configuration.
    pub logging: LoggingConfig,
    pub(crate) connectivity: Option<ConnectivityServicesConfig>,
}

impl ServerConfig {
    /// Loads, bounds, decodes, validates, and path-resolves a TOML file.
    ///
    /// Relative paths are resolved against the configuration file's parent
    /// directory, not the process working directory.
    ///
    /// # Errors
    ///
    /// Returns [`ConfigError`] for I/O failure, an oversized or non-UTF-8 file,
    /// TOML/schema errors, an unsupported version, or invalid values.
    pub fn load(path: &Path) -> Result<Self, ConfigError> {
        let file = File::open(path).map_err(|source| ConfigError::Read {
            path: path.to_path_buf(),
            source,
        })?;
        let maximum_read = MAX_CONFIG_BYTES
            .checked_add(1)
            .ok_or(ConfigError::LengthOverflow)?;
        let mut bytes = Vec::new();
        bytes
            .try_reserve_exact(
                usize::try_from(maximum_read).map_err(|_| ConfigError::LengthOverflow)?,
            )
            .map_err(|_| ConfigError::AllocationFailed)?;
        file.take(maximum_read)
            .read_to_end(&mut bytes)
            .map_err(|source| ConfigError::Read {
                path: path.to_path_buf(),
                source,
            })?;
        if u64::try_from(bytes.len()).map_err(|_| ConfigError::LengthOverflow)? > MAX_CONFIG_BYTES {
            return Err(ConfigError::TooLarge {
                maximum: MAX_CONFIG_BYTES,
            });
        }
        let text = String::from_utf8(bytes).map_err(|_| ConfigError::NotUtf8)?;
        let base = path.parent().unwrap_or_else(|| Path::new("."));
        Self::parse(&text, base)
    }

    /// Parses and validates TOML with relative paths based at `base_directory`.
    ///
    /// # Errors
    ///
    /// Returns [`ConfigError`] for TOML/schema errors, an unsupported version,
    /// or invalid operational values.
    pub fn parse(text: &str, base_directory: &Path) -> Result<Self, ConfigError> {
        let raw: RawServerConfig = toml::from_str(text).map_err(ConfigError::Parse)?;
        if raw.version != CONFIG_VERSION {
            return Err(ConfigError::UnsupportedVersion {
                actual: raw.version,
                supported: CONFIG_VERSION,
            });
        }
        if raw.listen.port() == 0 {
            return Err(ConfigError::InvalidValue {
                field: "listen",
                reason: "port must be non-zero",
            });
        }
        validate_nonempty_path(&raw.state.database, "state.database")?;
        validate_nonempty_path(&raw.identity.controller_key, "identity.controller_key")?;
        validate_nonempty_path(&raw.tls.certificate, "tls.certificate")?;
        validate_nonempty_path(&raw.tls.private_key, "tls.private_key")?;
        raw.limits.validate()?;
        raw.logging.validate()?;

        let connectivity = raw
            .connectivity
            .map(|connectivity| ConnectivityServicesConfig::from_raw(connectivity, base_directory))
            .transpose()?;
        Ok(Self {
            version: raw.version,
            listen: raw.listen,
            database_path: resolve_path(base_directory, &raw.state.database),
            controller_identity_path: resolve_path(base_directory, &raw.identity.controller_key),
            tls_certificate_path: resolve_path(base_directory, &raw.tls.certificate),
            tls_private_key_path: resolve_path(base_directory, &raw.tls.private_key),
            limits: raw.limits,
            logging: raw.logging,
            connectivity,
        })
    }

    /// Resolves one configured TURN UDP relay into executable service settings.
    ///
    /// # Errors
    ///
    /// Returns [`ConfigError`] when connectivity services are absent, the
    /// relay ID is unknown, TURN UDP is not advertised, or a numeric bound
    /// cannot be represented by this platform.
    pub fn turn_udp_relay_settings(
        &self,
        relay_id: RelayId,
    ) -> Result<TurnUdpRelaySettings, ConfigError> {
        let connectivity = self
            .connectivity
            .as_ref()
            .ok_or_else(|| invalid_connectivity("connectivity services are not configured"))?;
        let relay = connectivity
            .relay_services
            .iter()
            .find(|relay| relay.relay_id == relay_id)
            .ok_or_else(|| invalid_connectivity("requested relay ID is not configured"))?;
        if !relay.carriers.contains(RelayCarrierMask::TURN_UDP) || relay.ports.turn_udp == 0 {
            return Err(invalid_connectivity(
                "requested relay does not advertise TURN UDP",
            ));
        }
        let max_datagram_size =
            usize::try_from(relay.max_datagram_size).map_err(|_| ConfigError::LengthOverflow)?;
        Ok(TurnUdpRelaySettings {
            relay_id,
            credential_key_path: connectivity.credential_key_path.clone(),
            credential_lifetime_seconds: connectivity.credential_lifetime_seconds,
            port: relay.ports.turn_udp,
            max_datagram_size,
            allocation_lifetime_seconds: relay.allocation_lifetime_seconds,
            idle_timeout_seconds: relay.idle_timeout_seconds,
        })
    }
}

/// Executable settings derived from one advertised TURN UDP relay service.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TurnUdpRelaySettings {
    /// Stable configured relay identity.
    pub relay_id: RelayId,
    /// Protected shared credential authority key path.
    pub credential_key_path: PathBuf,
    /// Controller-issued credential lifetime used by the shared authority.
    pub credential_lifetime_seconds: u64,
    /// Advertised TURN UDP port.
    pub port: u16,
    /// Advertised relayed Stella datagram ceiling.
    pub max_datagram_size: usize,
    /// Maximum granted allocation lifetime.
    pub allocation_lifetime_seconds: u32,
    /// Allocation inactivity deadline.
    pub idle_timeout_seconds: u32,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ConnectivityServicesConfig {
    pub(crate) revision: u64,
    pub(crate) credential_key_path: PathBuf,
    pub(crate) credential_lifetime_seconds: u64,
    pub(crate) stun_servers: Vec<StunServer>,
    pub(crate) relay_services: Vec<RelayServiceConfig>,
}

impl ConnectivityServicesConfig {
    fn from_raw(raw: RawConnectivityConfig, base: &Path) -> Result<Self, ConfigError> {
        if raw.revision == 0 {
            return Err(invalid_connectivity(
                "configuration revision must be non-zero",
            ));
        }
        validate_nonempty_path(&raw.credential_key, "connectivity.credential_key")?;
        let _ = crate::relay_credentials::RelayCredentialAuthority::new(
            [1; crate::relay_credentials::RELAY_CREDENTIAL_KEY_LENGTH],
            raw.credential_lifetime_seconds,
        )
        .map_err(|_| invalid_connectivity("credential lifetime is outside protocol bounds"))?;
        if !(1..=usize::from(MAX_STUN_SERVERS)).contains(&raw.stun_servers.len()) {
            return Err(invalid_connectivity(
                "STUN server count is outside protocol bounds",
            ));
        }
        if !(1..=usize::from(MAX_RELAY_SERVICES)).contains(&raw.relays.len()) {
            return Err(invalid_connectivity(
                "relay service count is outside protocol bounds",
            ));
        }
        let stun_servers = priority_stun_servers(&raw.stun_servers)?;
        let mut relay_services = raw
            .relays
            .into_iter()
            .map(RelayServiceConfig::from_raw)
            .collect::<Result<Vec<_>, _>>()?;
        relay_services.sort_by_key(|service| (service.priority, service.relay_id));
        let mut relay_ids = BTreeSet::new();
        if relay_services
            .iter()
            .any(|service| !relay_ids.insert(service.relay_id))
        {
            return Err(invalid_connectivity("relay IDs must be unique"));
        }
        Ok(Self {
            revision: raw.revision,
            credential_key_path: resolve_path(base, &raw.credential_key),
            credential_lifetime_seconds: raw.credential_lifetime_seconds,
            stun_servers,
            relay_services,
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct RelayServiceConfig {
    pub(crate) relay_id: RelayId,
    pub(crate) carriers: RelayCarrierMask,
    pub(crate) priority: u16,
    pub(crate) max_datagram_size: u32,
    pub(crate) allocation_lifetime_seconds: u32,
    pub(crate) idle_timeout_seconds: u32,
    pub(crate) hostname: String,
    pub(crate) tls_server_name: String,
    pub(crate) region: String,
    pub(crate) trust: RelayTrustRequirements,
    pub(crate) ports: RelayPorts,
    pub(crate) addresses: Vec<RelayAddress>,
    pub(crate) spki_pins: Vec<[u8; 32]>,
}

impl RelayServiceConfig {
    fn from_raw(raw: RawRelayServiceConfig) -> Result<Self, ConfigError> {
        let relay_id = RelayId::from_str(&raw.id)
            .map_err(|_| invalid_connectivity("relay ID must be canonical hexadecimal"))?;
        let ports = RelayPorts {
            turn_udp: raw.turn_udp,
            turn_tcp: raw.turn_tcp,
            turn_tls: raw.turn_tls,
            secure_websocket: raw.secure_websocket,
        };
        let carriers = relay_carriers(ports)?;
        let addresses = priority_relay_addresses(&raw.addresses)?;
        let mut spki_pins = raw
            .spki_pins
            .iter()
            .map(|pin| decode_spki_pin(pin))
            .collect::<Result<Vec<_>, _>>()?;
        spki_pins.sort_unstable();
        if spki_pins.windows(2).any(|pair| pair[0] == pair[1]) {
            return Err(invalid_connectivity("relay SPKI pins must be unique"));
        }
        let trust_bits =
            u8::from(raw.require_web_pki) | if spki_pins.is_empty() { 0 } else { 1 << 1 };
        let trust = RelayTrustRequirements::from_bits(trust_bits)
            .map_err(|_| invalid_connectivity("relay TLS trust is invalid"))?;
        let service = Self {
            relay_id,
            carriers,
            priority: raw.priority,
            max_datagram_size: raw.max_datagram_size,
            allocation_lifetime_seconds: raw.allocation_lifetime_seconds,
            idle_timeout_seconds: raw.idle_timeout_seconds,
            hostname: raw.hostname,
            tls_server_name: raw.tls_server_name,
            region: raw.region,
            trust,
            ports,
            addresses,
            spki_pins,
        };
        service
            .as_ref(1, 301, b"placeholder", &[0; 32])
            .validate()
            .map_err(|_| invalid_connectivity("relay service violates protocol bounds"))?;
        Ok(service)
    }

    pub(crate) fn with_credential<'a>(
        &'a self,
        credential: &'a RelayCredential,
    ) -> RelayServiceRef<'a> {
        self.as_ref(
            credential.issued_at(),
            credential.expires_at(),
            credential.username(),
            credential.secret(),
        )
    }

    fn as_ref<'a>(
        &'a self,
        issued_at: u64,
        expires_at: u64,
        username: &'a [u8],
        secret: &'a [u8],
    ) -> RelayServiceRef<'a> {
        RelayServiceRef {
            relay_id: self.relay_id,
            carriers: self.carriers,
            priority: self.priority,
            max_datagram_size: self.max_datagram_size,
            allocation_lifetime_seconds: self.allocation_lifetime_seconds,
            idle_timeout_seconds: self.idle_timeout_seconds,
            credential_issued_at: issued_at,
            credential_expires_at: expires_at,
            hostname: &self.hostname,
            tls_server_name: &self.tls_server_name,
            credential_username: username,
            credential_secret: secret,
            region: &self.region,
            trust: self.trust,
            ports: self.ports,
            addresses: &self.addresses,
            spki_pins: &self.spki_pins,
        }
    }
}

fn priority_stun_servers(addresses: &[SocketAddr]) -> Result<Vec<StunServer>, ConfigError> {
    addresses
        .iter()
        .enumerate()
        .map(|(priority, address)| {
            let priority = u8::try_from(priority)
                .map_err(|_| invalid_connectivity("too many STUN servers"))?;
            let server = StunServer {
                priority,
                address: *address,
            };
            server
                .validate()
                .map_err(|_| invalid_connectivity("STUN address is not usable"))?;
            Ok(server)
        })
        .collect()
}

fn priority_relay_addresses(addresses: &[IpAddr]) -> Result<Vec<RelayAddress>, ConfigError> {
    addresses
        .iter()
        .enumerate()
        .map(|(priority, address)| {
            let priority = u8::try_from(priority)
                .map_err(|_| invalid_connectivity("too many relay addresses"))?;
            let address = RelayAddress {
                priority,
                address: *address,
            };
            address
                .validate()
                .map_err(|_| invalid_connectivity("relay address is not usable"))?;
            Ok(address)
        })
        .collect()
}

fn relay_carriers(ports: RelayPorts) -> Result<RelayCarrierMask, ConfigError> {
    let bits = u16::from(ports.turn_udp != 0)
        | (u16::from(ports.turn_tcp != 0) << 1)
        | (u16::from(ports.turn_tls != 0) << 2)
        | (u16::from(ports.secure_websocket != 0) << 3);
    RelayCarrierMask::from_bits(bits)
        .map_err(|_| invalid_connectivity("relay must enable at least one carrier"))
}

fn decode_spki_pin(text: &str) -> Result<[u8; 32], ConfigError> {
    let encoded = text
        .strip_prefix("sha256/")
        .ok_or_else(|| invalid_connectivity("relay SPKI pin must start with sha256/"))?;
    let decoded = STANDARD
        .decode(encoded)
        .map_err(|_| invalid_connectivity("relay SPKI pin is not standard base64"))?;
    if STANDARD.encode(&decoded) != encoded {
        return Err(invalid_connectivity(
            "relay SPKI pin is not canonical base64",
        ));
    }
    decoded
        .try_into()
        .map_err(|_| invalid_connectivity("relay SPKI pin must contain 32 bytes"))
}

fn invalid_connectivity(reason: &'static str) -> ConfigError {
    ConfigError::InvalidValue {
        field: "connectivity",
        reason,
    }
}

/// Bounded controller runtime limits.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
#[serde(default, deny_unknown_fields)]
pub struct LimitsConfig {
    /// Pending typed commands accepted by the authority thread.
    pub authority_queue: usize,
    /// Maximum simultaneous TLS control connections.
    pub max_connections: usize,
    /// Maximum queued outbound messages per connection.
    pub outbound_messages: usize,
    /// Deadline for completing one TLS handshake.
    pub tls_handshake_timeout_seconds: u64,
    /// Deadline for application authentication after TLS establishment.
    pub authentication_timeout_seconds: u64,
    /// Deadline for one correlated control request.
    pub request_timeout_seconds: u64,
    /// Deadline for draining active sessions during orderly shutdown.
    pub shutdown_timeout_seconds: u64,
}

impl LimitsConfig {
    fn validate(self) -> Result<(), ConfigError> {
        validate_range(
            &self.authority_queue,
            &1,
            &MAX_AUTHORITY_QUEUE,
            "limits.authority_queue",
        )?;
        validate_range(
            &self.max_connections,
            &1,
            &MAX_CONNECTIONS,
            "limits.max_connections",
        )?;
        validate_range(
            &self.outbound_messages,
            &1,
            &MAX_OUTBOUND_MESSAGES,
            "limits.outbound_messages",
        )?;
        validate_range(
            &self.tls_handshake_timeout_seconds,
            &1,
            &MAX_TLS_HANDSHAKE_TIMEOUT_SECONDS,
            "limits.tls_handshake_timeout_seconds",
        )?;
        validate_range(
            &self.authentication_timeout_seconds,
            &1,
            &MAX_AUTHENTICATION_TIMEOUT_SECONDS,
            "limits.authentication_timeout_seconds",
        )?;
        validate_range(
            &self.request_timeout_seconds,
            &1,
            &MAX_REQUEST_TIMEOUT_SECONDS,
            "limits.request_timeout_seconds",
        )?;
        validate_range(
            &self.shutdown_timeout_seconds,
            &1,
            &MAX_SHUTDOWN_TIMEOUT_SECONDS,
            "limits.shutdown_timeout_seconds",
        )
    }
}

impl Default for LimitsConfig {
    fn default() -> Self {
        Self {
            authority_queue: 256,
            max_connections: 1_024,
            outbound_messages: 64,
            tls_handshake_timeout_seconds: 10,
            authentication_timeout_seconds: 10,
            request_timeout_seconds: 10,
            shutdown_timeout_seconds: 10,
        }
    }
}

/// Structured logging settings that never contain credentials.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(default, deny_unknown_fields)]
pub struct LoggingConfig {
    /// `tracing-subscriber` environment-filter expression.
    pub filter: String,
}

impl LoggingConfig {
    fn validate(&self) -> Result<(), ConfigError> {
        if self.filter.is_empty() || self.filter.len() > MAX_LOG_FILTER_BYTES {
            return Err(ConfigError::InvalidValue {
                field: "logging.filter",
                reason: "must contain 1 through 256 UTF-8 bytes",
            });
        }
        if self.filter.chars().any(char::is_control) {
            return Err(ConfigError::InvalidValue {
                field: "logging.filter",
                reason: "must not contain control characters",
            });
        }
        Ok(())
    }
}

impl Default for LoggingConfig {
    fn default() -> Self {
        Self {
            filter: "info".to_owned(),
        }
    }
}

/// Controller configuration loading or validation failure.
#[derive(Debug, Error)]
pub enum ConfigError {
    /// The configuration file could not be opened or read.
    #[error("could not read controller configuration {path}: {source}")]
    Read {
        /// Configuration path.
        path: PathBuf,
        /// Underlying filesystem error.
        source: std::io::Error,
    },
    /// The configuration exceeds its allocation bound.
    #[error("controller configuration exceeds {maximum} bytes")]
    TooLarge {
        /// Maximum accepted size.
        maximum: u64,
    },
    /// Configuration bytes are not strict UTF-8.
    #[error("controller configuration is not valid UTF-8")]
    NotUtf8,
    /// TOML syntax or the strict schema is invalid.
    #[error("invalid controller configuration: {0}")]
    Parse(toml::de::Error),
    /// The document uses an unsupported schema version.
    #[error(
        "unsupported controller configuration version {actual}; supported version is {supported}"
    )]
    UnsupportedVersion {
        /// Version found in the document.
        actual: u32,
        /// Version implemented by this binary.
        supported: u32,
    },
    /// A named value violates its documented semantic bounds.
    #[error("invalid controller configuration field {field}: {reason}")]
    InvalidValue {
        /// Stable dotted field name.
        field: &'static str,
        /// Redacted invariant description.
        reason: &'static str,
    },
    /// Checked size arithmetic overflowed.
    #[error("controller configuration length overflow")]
    LengthOverflow,
    /// Bounded configuration storage could not be reserved.
    #[error("unable to allocate bounded controller configuration storage")]
    AllocationFailed,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawServerConfig {
    version: u32,
    listen: SocketAddr,
    state: RawStateConfig,
    identity: RawIdentityConfig,
    tls: RawTlsConfig,
    #[serde(default)]
    limits: LimitsConfig,
    #[serde(default)]
    logging: LoggingConfig,
    connectivity: Option<RawConnectivityConfig>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawConnectivityConfig {
    revision: u64,
    credential_key: PathBuf,
    #[serde(default = "default_relay_credential_lifetime")]
    credential_lifetime_seconds: u64,
    stun_servers: Vec<SocketAddr>,
    relays: Vec<RawRelayServiceConfig>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawRelayServiceConfig {
    id: String,
    priority: u16,
    #[serde(default = "default_relay_datagram_size")]
    max_datagram_size: u32,
    #[serde(default = "default_relay_allocation_lifetime")]
    allocation_lifetime_seconds: u32,
    #[serde(default = "default_relay_idle_timeout")]
    idle_timeout_seconds: u32,
    #[serde(default)]
    hostname: String,
    #[serde(default)]
    tls_server_name: String,
    #[serde(default)]
    region: String,
    #[serde(default)]
    require_web_pki: bool,
    #[serde(default)]
    turn_udp: u16,
    #[serde(default)]
    turn_tcp: u16,
    #[serde(default)]
    turn_tls: u16,
    #[serde(default)]
    secure_websocket: u16,
    #[serde(default)]
    addresses: Vec<IpAddr>,
    #[serde(default)]
    spki_pins: Vec<String>,
}

const fn default_relay_credential_lifetime() -> u64 {
    300
}

const fn default_relay_datagram_size() -> u32 {
    1_200
}

const fn default_relay_allocation_lifetime() -> u32 {
    600
}

const fn default_relay_idle_timeout() -> u32 {
    120
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawStateConfig {
    database: PathBuf,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawIdentityConfig {
    controller_key: PathBuf,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawTlsConfig {
    certificate: PathBuf,
    private_key: PathBuf,
}

fn validate_nonempty_path(path: &Path, field: &'static str) -> Result<(), ConfigError> {
    if path.as_os_str().is_empty() {
        return Err(ConfigError::InvalidValue {
            field,
            reason: "path must not be empty",
        });
    }
    Ok(())
}

fn resolve_path(base: &Path, path: &Path) -> PathBuf {
    if path.is_absolute() {
        path.to_path_buf()
    } else {
        base.join(path)
    }
}

fn validate_range<T>(
    actual: &T,
    minimum: &T,
    maximum: &T,
    field: &'static str,
) -> Result<(), ConfigError>
where
    T: Ord,
{
    if actual < minimum || actual > maximum {
        return Err(ConfigError::InvalidValue {
            field,
            reason: "value is outside the supported range",
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::{
        path::{Path, PathBuf},
        sync::atomic::{AtomicU64, Ordering},
    };

    use base64::{engine::general_purpose::STANDARD, Engine as _};
    use stella_proto::{RelayCarrierMask, RelayTrustRequirements};

    use super::{
        ConfigError, LimitsConfig, LoggingConfig, ServerConfig, CONFIG_VERSION, MAX_CONFIG_BYTES,
    };

    static TEMP_SEQUENCE: AtomicU64 = AtomicU64::new(1);

    const VALID_CONFIG: &str = r#"
version = 1
listen = "127.0.0.1:44900"

[state]
database = "state/controller.redb"

[identity]
controller_key = "secrets/controller.pk8"

[tls]
certificate = "secrets/tls-cert.pem"
private_key = "secrets/tls-key.pem"
"#;

    fn temp_directory() -> PathBuf {
        let sequence = TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        std::env::temp_dir().join(format!(
            "stella-server-config-{}-{sequence}",
            std::process::id()
        ))
    }

    #[test]
    fn valid_minimal_config_resolves_paths_and_defaults() {
        let base = Path::new("C:/stella");
        let config = ServerConfig::parse(VALID_CONFIG, base).expect("valid configuration");
        assert_eq!(config.version, CONFIG_VERSION);
        assert_eq!(config.listen.to_string(), "127.0.0.1:44900");
        assert_eq!(config.database_path, base.join("state/controller.redb"));
        assert_eq!(
            config.controller_identity_path,
            base.join("secrets/controller.pk8")
        );
        assert_eq!(config.limits, LimitsConfig::default());
        assert_eq!(config.logging, LoggingConfig::default());
        assert!(config.connectivity.is_none());
    }

    #[test]
    fn connectivity_services_are_protocol_validated_and_canonicalized() {
        let pin = format!("sha256/{}", STANDARD.encode([1_u8; 32]));
        let document = format!(
            "{VALID_CONFIG}\n[connectivity]\nrevision = 7\ncredential_key = \"secrets/relay-credential.key\"\ncredential_lifetime_seconds = 300\nstun_servers = [\"192.0.2.20:3478\", \"[2001:db8::20]:3478\"]\n\n[[connectivity.relays]]\nid = \"02020202020202020202020202020202\"\npriority = 20\nhostname = \"relay-b.example.com\"\ntls_server_name = \"relay-b.example.com\"\nregion = \"backup\"\nrequire_web_pki = true\nturn_tls = 443\naddresses = [\"192.0.2.31\"]\n\n[[connectivity.relays]]\nid = \"01010101010101010101010101010101\"\npriority = 10\nhostname = \"relay-a.example.com\"\ntls_server_name = \"relay-a.example.com\"\nregion = \"primary\"\nturn_udp = 3478\nturn_tls = 443\naddresses = [\"192.0.2.30\", \"2001:db8::30\"]\nspki_pins = [\"{pin}\"]\n"
        );
        let parsed = ServerConfig::parse(&document, Path::new("C:/stella"))
            .expect("valid connectivity services");
        let relay_id = "01010101010101010101010101010101"
            .parse()
            .expect("valid relay ID");
        let settings = parsed
            .turn_udp_relay_settings(relay_id)
            .expect("resolve TURN UDP settings");
        assert_eq!(settings.relay_id, relay_id);
        assert_eq!(
            settings.credential_key_path,
            Path::new("C:/stella/secrets/relay-credential.key")
        );
        assert_eq!(settings.credential_lifetime_seconds, 300);
        assert_eq!(settings.port, 3478);
        assert_eq!(settings.max_datagram_size, 1_200);
        assert_eq!(settings.allocation_lifetime_seconds, 600);
        assert_eq!(settings.idle_timeout_seconds, 120);

        let connectivity = parsed.connectivity.expect("connectivity configured");
        assert_eq!(connectivity.revision, 7);
        assert_eq!(
            connectivity.credential_key_path,
            Path::new("C:/stella/secrets/relay-credential.key")
        );
        assert_eq!(connectivity.stun_servers.len(), 2);
        assert_eq!(connectivity.stun_servers[0].priority, 0);
        assert_eq!(connectivity.stun_servers[1].priority, 1);
        assert_eq!(connectivity.relay_services.len(), 2);
        let primary = &connectivity.relay_services[0];
        assert_eq!(primary.priority, 10);
        assert!(primary.carriers.contains(RelayCarrierMask::TURN_UDP));
        assert!(primary.carriers.contains(RelayCarrierMask::TURN_TLS));
        assert!(primary.trust.contains(RelayTrustRequirements::SPKI_PIN));
        assert_eq!(primary.addresses[0].priority, 0);
        assert_eq!(primary.addresses[1].priority, 1);
        assert_eq!(primary.spki_pins, vec![[1; 32]]);
    }

    #[test]
    fn unknown_fields_and_versions_are_rejected() {
        let unknown = VALID_CONFIG.replace("version = 1", "version = 1\nsecret = true");
        assert!(matches!(
            ServerConfig::parse(&unknown, Path::new(".")),
            Err(ConfigError::Parse(_))
        ));
        let future = VALID_CONFIG.replace("version = 1", "version = 2");
        assert!(matches!(
            ServerConfig::parse(&future, Path::new(".")),
            Err(ConfigError::UnsupportedVersion {
                actual: 2,
                supported: 1
            })
        ));
    }

    #[test]
    fn invalid_addresses_paths_limits_and_filters_are_rejected() {
        let zero_port = VALID_CONFIG.replace("127.0.0.1:44900", "127.0.0.1:0");
        assert!(matches!(
            ServerConfig::parse(&zero_port, Path::new(".")),
            Err(ConfigError::InvalidValue {
                field: "listen",
                ..
            })
        ));

        let empty_path =
            VALID_CONFIG.replace("database = \"state/controller.redb\"", "database = \"\"");
        assert!(matches!(
            ServerConfig::parse(&empty_path, Path::new(".")),
            Err(ConfigError::InvalidValue {
                field: "state.database",
                ..
            })
        ));

        let invalid_limit = format!("{VALID_CONFIG}\n[limits]\nauthority_queue = 0\n");
        assert!(matches!(
            ServerConfig::parse(&invalid_limit, Path::new(".")),
            Err(ConfigError::InvalidValue {
                field: "limits.authority_queue",
                ..
            })
        ));

        let invalid_filter = format!("{VALID_CONFIG}\n[logging]\nfilter = \"bad\\nfilter\"\n");
        assert!(matches!(
            ServerConfig::parse(&invalid_filter, Path::new(".")),
            Err(ConfigError::InvalidValue {
                field: "logging.filter",
                ..
            })
        ));

        let no_carrier = format!(
            "{VALID_CONFIG}\n[connectivity]\nrevision = 1\ncredential_key = \"relay.key\"\nstun_servers = [\"192.0.2.20:3478\"]\n\n[[connectivity.relays]]\nid = \"01010101010101010101010101010101\"\npriority = 0\naddresses = [\"192.0.2.30\"]\n"
        );
        assert!(matches!(
            ServerConfig::parse(&no_carrier, Path::new(".")),
            Err(ConfigError::InvalidValue {
                field: "connectivity",
                ..
            })
        ));

        let invalid_stun = format!(
            "{VALID_CONFIG}\n[connectivity]\nrevision = 1\ncredential_key = \"relay.key\"\nstun_servers = [\"127.0.0.1:3478\"]\nrelays = []\n"
        );
        assert!(matches!(
            ServerConfig::parse(&invalid_stun, Path::new(".")),
            Err(ConfigError::InvalidValue {
                field: "connectivity",
                ..
            })
        ));
    }

    #[test]
    fn explicit_limits_and_absolute_paths_are_preserved() {
        let config = format!(
            "{VALID_CONFIG}\n[limits]\nauthority_queue = 4\nmax_connections = 5\noutbound_messages = 6\ntls_handshake_timeout_seconds = 7\nauthentication_timeout_seconds = 8\nrequest_timeout_seconds = 9\nshutdown_timeout_seconds = 10\n\n[logging]\nfilter = \"stella_server=debug\"\n"
        )
        .replace(
            "database = \"state/controller.redb\"",
            "database = \"C:/absolute/controller.redb\"",
        );
        let parsed =
            ServerConfig::parse(&config, Path::new("C:/base")).expect("explicit values are valid");
        assert_eq!(
            parsed.database_path,
            Path::new("C:/absolute/controller.redb")
        );
        assert_eq!(parsed.limits.authority_queue, 4);
        assert_eq!(parsed.limits.tls_handshake_timeout_seconds, 7);
        assert_eq!(parsed.limits.authentication_timeout_seconds, 8);
        assert_eq!(parsed.limits.request_timeout_seconds, 9);
        assert_eq!(parsed.limits.shutdown_timeout_seconds, 10);
        assert_eq!(parsed.logging.filter, "stella_server=debug");
    }

    #[test]
    fn file_loader_bounds_utf8_and_resolves_against_parent() {
        let directory = temp_directory();
        std::fs::create_dir(&directory).expect("create isolated test directory");
        let config_path = directory.join("server.toml");
        std::fs::write(&config_path, VALID_CONFIG).expect("write valid config");
        let loaded = ServerConfig::load(&config_path).expect("load valid config");
        assert_eq!(
            loaded.database_path,
            directory.join("state/controller.redb")
        );

        std::fs::write(&config_path, [0xff]).expect("write invalid UTF-8");
        assert!(matches!(
            ServerConfig::load(&config_path),
            Err(ConfigError::NotUtf8)
        ));

        let oversized_length =
            usize::try_from(MAX_CONFIG_BYTES + 1).expect("configuration bound fits usize");
        std::fs::write(&config_path, vec![b' '; oversized_length]).expect("write oversized config");
        assert!(matches!(
            ServerConfig::load(&config_path),
            Err(ConfigError::TooLarge { .. })
        ));
        std::fs::remove_dir_all(&directory).expect("remove isolated test directory");
    }
}
