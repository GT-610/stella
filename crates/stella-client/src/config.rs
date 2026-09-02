//! Strict versioned Windows client configuration.

use std::{
    cmp::Ordering,
    fs::File,
    io::Read,
    net::{IpAddr, SocketAddr},
    path::{Path, PathBuf},
    str::FromStr,
};

use serde::Deserialize;
use stella_common::{ControllerId, HexParseError, NetworkId};
use stella_proto::{encode_endpoint_set, CodecError, Endpoint, MAX_ENDPOINTS};
use thiserror::Error;

use crate::{ControllerTrust, SpkiPin, SpkiPinParseError};

/// Supported client configuration schema version.
pub const CONFIG_VERSION: u32 = 1;

/// Largest accepted UTF-8 client configuration file.
pub const MAX_CONFIG_BYTES: u64 = 1_048_576;

const MAX_DISPLAY_NAME_BYTES: usize = 64;
const MAX_ADAPTER_NAME_BYTES: usize = 128;
const MAX_LOG_FILTER_BYTES: usize = 256;
const MAX_ENDPOINT_SET_LENGTH: usize = 4 + 8 * 28;

/// Validated persistent client configuration with resolved paths.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ClientConfig {
    /// Schema version loaded from TOML.
    pub version: u32,
    /// Numeric address plus independent TLS and Stella trust anchors.
    pub controller: ControllerTrust,
    /// Protected node identity PKCS#8 DER path.
    pub identity_path: PathBuf,
    /// Human-readable name supplied only during enrollment.
    pub display_name: String,
    /// Local UDP socket bind address.
    pub udp_bind: SocketAddr,
    /// Optional explicit HTTP proxy used for controller TLS and secure WebSocket relay.
    pub https_proxy: Option<SocketAddr>,
    /// Canonically ordered numeric endpoints published after joining.
    pub advertised_endpoints: Vec<Endpoint>,
    /// Durable desired memberships in stable network-ID order.
    pub networks: Vec<ConfiguredNetwork>,
    /// Structured logging filter without credentials.
    pub log_filter: String,
}

impl ClientConfig {
    /// Loads, bounds, decodes, validates, and path-resolves a TOML file.
    ///
    /// # Errors
    ///
    /// Returns [`ClientConfigError`] for I/O, size, UTF-8, schema, trust,
    /// endpoint, path, text, duplicate-network, or version failure.
    pub fn load(path: &Path) -> Result<Self, ClientConfigError> {
        let file = File::open(path).map_err(|source| ClientConfigError::Read {
            path: path.to_path_buf(),
            source,
        })?;
        let maximum_read = MAX_CONFIG_BYTES
            .checked_add(1)
            .ok_or(ClientConfigError::LengthOverflow)?;
        let mut bytes = Vec::new();
        bytes
            .try_reserve_exact(
                usize::try_from(maximum_read).map_err(|_| ClientConfigError::LengthOverflow)?,
            )
            .map_err(|_| ClientConfigError::AllocationFailed)?;
        file.take(maximum_read)
            .read_to_end(&mut bytes)
            .map_err(|source| ClientConfigError::Read {
                path: path.to_path_buf(),
                source,
            })?;
        if u64::try_from(bytes.len()).map_err(|_| ClientConfigError::LengthOverflow)?
            > MAX_CONFIG_BYTES
        {
            return Err(ClientConfigError::TooLarge {
                maximum: MAX_CONFIG_BYTES,
            });
        }
        let text = String::from_utf8(bytes).map_err(|_| ClientConfigError::NotUtf8)?;
        Self::parse(&text, path.parent().unwrap_or_else(|| Path::new(".")))
    }

    /// Parses and validates TOML with relative paths rooted at `base_directory`.
    ///
    /// # Errors
    ///
    /// Returns [`ClientConfigError`] for strict schema or semantic failure.
    pub fn parse(text: &str, base_directory: &Path) -> Result<Self, ClientConfigError> {
        let raw: RawClientConfig = toml::from_str(text).map_err(ClientConfigError::Parse)?;
        if raw.version != CONFIG_VERSION {
            return Err(ClientConfigError::UnsupportedVersion {
                actual: raw.version,
                supported: CONFIG_VERSION,
            });
        }
        validate_path(&raw.identity.node_key, "identity.node_key")?;
        validate_text(
            &raw.identity.display_name,
            1,
            MAX_DISPLAY_NAME_BYTES,
            "identity.display_name",
        )?;
        validate_text(
            &raw.logging.filter,
            1,
            MAX_LOG_FILTER_BYTES,
            "logging.filter",
        )?;

        let controller_id = ControllerId::from_str(&raw.controller.id).map_err(|source| {
            ClientConfigError::Identifier {
                field: "controller.id",
                source,
            }
        })?;
        if controller_id.is_zero() {
            return Err(invalid("controller.id", "must be non-zero"));
        }
        let pins = raw
            .controller
            .spki_pins
            .iter()
            .map(|pin| SpkiPin::from_str(pin).map_err(ClientConfigError::SpkiPin))
            .collect::<Result<Vec<_>, _>>()?;
        if let Some(proxy) = raw.transport.https_proxy {
            if proxy.port() == 0 || proxy.ip().is_unspecified() || proxy.ip().is_multicast() {
                return Err(invalid(
                    "transport.https_proxy",
                    "must use a specified unicast address and non-zero port",
                ));
            }
        }
        let controller = ControllerTrust::new(
            raw.controller.address,
            raw.controller.tls_name,
            controller_id,
            pins,
        )?
        .with_https_proxy(raw.transport.https_proxy);
        let mut advertised_endpoints = raw
            .transport
            .advertised_endpoints
            .into_iter()
            .map(RawEndpoint::into_endpoint)
            .collect::<Result<Vec<_>, _>>()?;
        advertised_endpoints.sort_by(endpoint_order);
        validate_endpoints(&advertised_endpoints)?;
        let mut networks = raw
            .networks
            .into_iter()
            .map(RawNetwork::validate)
            .collect::<Result<Vec<_>, _>>()?;
        networks.sort_by_key(|network| network.network_id);
        for pair in networks.windows(2) {
            if pair[0].network_id == pair[1].network_id {
                return Err(invalid("networks", "network IDs must be unique"));
            }
        }
        Ok(Self {
            version: raw.version,
            controller,
            identity_path: resolve_path(base_directory, &raw.identity.node_key),
            display_name: raw.identity.display_name,
            udp_bind: raw.transport.udp_bind,
            https_proxy: raw.transport.https_proxy,
            advertised_endpoints,
            networks,
            log_filter: raw.logging.filter,
        })
    }
}

/// One durable desired membership and its TAP-Windows adapter selection.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ConfiguredNetwork {
    /// Virtual network to rejoin after every reconnect.
    pub network_id: NetworkId,
    /// Exact TAP-Windows adapter display name.
    pub tap_adapter: String,
}

/// Client configuration loading or semantic validation failure.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum ClientConfigError {
    /// The configuration file could not be opened or read.
    #[error("could not read client configuration {path}: {source}")]
    Read {
        /// Configuration path.
        path: PathBuf,
        /// Underlying filesystem error.
        #[source]
        source: std::io::Error,
    },
    /// Configuration exceeds the bounded input size.
    #[error("client configuration exceeds {maximum} bytes")]
    TooLarge {
        /// Maximum accepted size.
        maximum: u64,
    },
    /// Configuration bytes are not strict UTF-8.
    #[error("client configuration is not valid UTF-8")]
    NotUtf8,
    /// TOML syntax or the strict schema is invalid.
    #[error("invalid client configuration: {0}")]
    Parse(toml::de::Error),
    /// The schema version is not implemented.
    #[error("unsupported client configuration version {actual}; supported version is {supported}")]
    UnsupportedVersion {
        /// Version found in TOML.
        actual: u32,
        /// Version implemented by this build.
        supported: u32,
    },
    /// A canonical Stella identifier could not be parsed.
    #[error("invalid client configuration field {field}: {source}")]
    Identifier {
        /// Stable dotted field name.
        field: &'static str,
        /// Hexadecimal parse failure.
        source: HexParseError,
    },
    /// One SPKI pin is malformed.
    #[error("invalid controller SPKI pin: {0}")]
    SpkiPin(SpkiPinParseError),
    /// Controller trust construction failed.
    #[error(transparent)]
    Trust(#[from] crate::ClientError),
    /// An advertised endpoint violates protocol bounds or ordering.
    #[error(transparent)]
    Endpoint(#[from] CodecError),
    /// A named value violates a documented semantic bound.
    #[error("invalid client configuration field {field}: {reason}")]
    InvalidValue {
        /// Stable dotted field name.
        field: &'static str,
        /// Non-secret invariant description.
        reason: &'static str,
    },
    /// Checked input length arithmetic overflowed.
    #[error("client configuration length overflow")]
    LengthOverflow,
    /// Bounded input allocation failed.
    #[error("unable to allocate bounded client configuration storage")]
    AllocationFailed,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawClientConfig {
    version: u32,
    controller: RawController,
    identity: RawIdentity,
    transport: RawTransport,
    #[serde(default)]
    networks: Vec<RawNetwork>,
    #[serde(default)]
    logging: RawLogging,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawController {
    address: SocketAddr,
    tls_name: String,
    id: String,
    spki_pins: Vec<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawIdentity {
    node_key: PathBuf,
    display_name: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawTransport {
    udp_bind: SocketAddr,
    #[serde(default)]
    https_proxy: Option<SocketAddr>,
    #[serde(default)]
    advertised_endpoints: Vec<RawEndpoint>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawEndpoint {
    address: SocketAddr,
    #[serde(default)]
    priority: u8,
    max_datagram_size: u32,
}

impl RawEndpoint {
    fn into_endpoint(self) -> Result<Endpoint, ClientConfigError> {
        if self.address.port() == 0 {
            return Err(invalid(
                "transport.advertised_endpoints.address",
                "port must be non-zero",
            ));
        }
        Ok(match self.address.ip() {
            IpAddr::V4(address) => Endpoint::UdpIpv4 {
                priority: self.priority,
                port: self.address.port(),
                max_datagram_size: self.max_datagram_size,
                address,
            },
            IpAddr::V6(address) => Endpoint::UdpIpv6 {
                priority: self.priority,
                port: self.address.port(),
                max_datagram_size: self.max_datagram_size,
                address,
            },
        })
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawNetwork {
    id: String,
    tap_adapter: String,
}

impl RawNetwork {
    fn validate(self) -> Result<ConfiguredNetwork, ClientConfigError> {
        let network_id =
            NetworkId::from_str(&self.id).map_err(|source| ClientConfigError::Identifier {
                field: "networks.id",
                source,
            })?;
        if network_id.is_zero() {
            return Err(invalid("networks.id", "must be non-zero"));
        }
        validate_text(
            &self.tap_adapter,
            1,
            MAX_ADAPTER_NAME_BYTES,
            "networks.tap_adapter",
        )?;
        Ok(ConfiguredNetwork {
            network_id,
            tap_adapter: self.tap_adapter,
        })
    }
}

#[derive(Deserialize)]
#[serde(default, deny_unknown_fields)]
struct RawLogging {
    filter: String,
}

impl Default for RawLogging {
    fn default() -> Self {
        Self {
            filter: "info,stella_client=info".to_owned(),
        }
    }
}

fn validate_endpoints(endpoints: &[Endpoint]) -> Result<(), ClientConfigError> {
    if endpoints.len() > usize::from(MAX_ENDPOINTS) {
        return Err(invalid(
            "transport.advertised_endpoints",
            "at most eight endpoints are allowed",
        ));
    }
    let mut output = [0_u8; MAX_ENDPOINT_SET_LENGTH];
    encode_endpoint_set(endpoints, &mut output)?;
    Ok(())
}

fn endpoint_order(left: &Endpoint, right: &Endpoint) -> Ordering {
    left.priority()
        .cmp(&right.priority())
        .then_with(|| left.kind().cmp(&right.kind()))
        .then_with(|| endpoint_ip_bytes(*left).cmp(&endpoint_ip_bytes(*right)))
        .then_with(|| left.port().cmp(&right.port()))
}

fn endpoint_ip_bytes(endpoint: Endpoint) -> [u8; 16] {
    match endpoint {
        Endpoint::UdpIpv4 { address, .. } => {
            let octets = address.octets();
            let mut output = [0_u8; 16];
            output[..4].copy_from_slice(&octets);
            output
        }
        Endpoint::UdpIpv6 { address, .. } => address.octets(),
    }
}

fn validate_path(path: &Path, field: &'static str) -> Result<(), ClientConfigError> {
    if path.as_os_str().is_empty() {
        return Err(invalid(field, "path must not be empty"));
    }
    Ok(())
}

fn validate_text(
    value: &str,
    minimum: usize,
    maximum: usize,
    field: &'static str,
) -> Result<(), ClientConfigError> {
    if !(minimum..=maximum).contains(&value.len()) {
        return Err(invalid(field, "text length is outside the supported range"));
    }
    if value.chars().any(char::is_control) {
        return Err(invalid(field, "control characters are not allowed"));
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

const fn invalid(field: &'static str, reason: &'static str) -> ClientConfigError {
    ClientConfigError::InvalidValue { field, reason }
}

#[cfg(test)]
mod tests {
    use std::{
        path::{Path, PathBuf},
        sync::atomic::{AtomicU64, Ordering},
    };

    use super::{ClientConfig, ClientConfigError, CONFIG_VERSION, MAX_CONFIG_BYTES};

    static TEMP_SEQUENCE: AtomicU64 = AtomicU64::new(1);

    const VALID: &str = r#"
version = 1

[controller]
address = "127.0.0.1:44900"
tls_name = "localhost"
id = "11111111111111111111111111111111"
spki_pins = ["sha256/AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE="]

[identity]
node_key = "secrets/node.pk8"
display_name = "Windows node"

[transport]
udp_bind = "0.0.0.0:45100"
https_proxy = "127.0.0.1:8080"

[[transport.advertised_endpoints]]
address = "192.0.2.10:45100"
priority = 10
max_datagram_size = 1200

[[networks]]
id = "22222222222222222222222222222222"
tap_adapter = "Stella LAN"
"#;

    fn temp_directory() -> PathBuf {
        let sequence = TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        std::env::temp_dir().join(format!(
            "stella-client-config-{}-{sequence}",
            std::process::id()
        ))
    }

    #[test]
    fn minimal_config_resolves_paths_and_builds_trust() {
        let base = Path::new("C:/stella");
        let config = ClientConfig::parse(VALID, base).expect("valid client configuration");
        assert_eq!(config.version, CONFIG_VERSION);
        assert_eq!(config.identity_path, base.join("secrets/node.pk8"));
        assert_eq!(config.controller.address().to_string(), "127.0.0.1:44900");
        assert_eq!(
            config.https_proxy,
            Some("127.0.0.1:8080".parse().expect("proxy address"))
        );
        assert_eq!(config.controller.https_proxy(), config.https_proxy);
        assert_eq!(config.advertised_endpoints.len(), 1);
        assert_eq!(config.networks.len(), 1);
        assert_eq!(config.log_filter, "info,stella_client=info");
    }

    #[test]
    fn initialization_config_may_have_no_networks() {
        let without_network = VALID
            .lines()
            .take_while(|line| *line != "[[networks]]")
            .collect::<Vec<_>>()
            .join("\n");
        let config = ClientConfig::parse(&without_network, Path::new("C:/stella"))
            .expect("pre-join configuration is valid");
        assert!(config.networks.is_empty());
    }

    #[test]
    fn unknown_fields_tokens_and_duplicate_networks_are_rejected() {
        let unknown = VALID.replace("version = 1", "version = 1\njoin_token = \"secret\"");
        assert!(matches!(
            ClientConfig::parse(&unknown, Path::new(".")),
            Err(ClientConfigError::Parse(_))
        ));
        let duplicate = format!(
            "{VALID}\n[[networks]]\nid = \"22222222222222222222222222222222\"\ntap_adapter = \"Other\"\n"
        );
        assert!(matches!(
            ClientConfig::parse(&duplicate, Path::new(".")),
            Err(ClientConfigError::InvalidValue {
                field: "networks",
                ..
            })
        ));
    }

    #[test]
    fn versions_pins_addresses_and_text_are_strict() {
        let future = VALID.replace("version = 1", "version = 2");
        assert!(matches!(
            ClientConfig::parse(&future, Path::new(".")),
            Err(ClientConfigError::UnsupportedVersion { actual: 2, .. })
        ));
        let pin = VALID.replace("sha256/AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=", "bad");
        assert!(matches!(
            ClientConfig::parse(&pin, Path::new(".")),
            Err(ClientConfigError::SpkiPin(_))
        ));
        let zero_port = VALID.replace("192.0.2.10:45100", "192.0.2.10:0");
        assert!(matches!(
            ClientConfig::parse(&zero_port, Path::new(".")),
            Err(ClientConfigError::InvalidValue { .. })
        ));
        let bad_proxy = VALID.replace("127.0.0.1:8080", "0.0.0.0:8080");
        assert!(matches!(
            ClientConfig::parse(&bad_proxy, Path::new(".")),
            Err(ClientConfigError::InvalidValue {
                field: "transport.https_proxy",
                ..
            })
        ));
        let bad_name = VALID.replace("Windows node", "Windows\\nnode");
        assert!(ClientConfig::parse(&bad_name, Path::new(".")).is_err());
    }

    #[test]
    fn file_loader_bounds_utf8_and_uses_config_parent() {
        let directory = temp_directory();
        std::fs::create_dir(&directory).expect("create test directory");
        let path = directory.join("client.toml");
        std::fs::write(&path, VALID).expect("write valid configuration");
        let loaded = ClientConfig::load(&path).expect("load valid configuration");
        assert_eq!(loaded.identity_path, directory.join("secrets/node.pk8"));

        std::fs::write(&path, [0xff]).expect("write invalid UTF-8");
        assert!(matches!(
            ClientConfig::load(&path),
            Err(ClientConfigError::NotUtf8)
        ));
        let oversized = usize::try_from(MAX_CONFIG_BYTES + 1).expect("bound fits usize");
        std::fs::write(&path, vec![b' '; oversized]).expect("write oversized input");
        assert!(matches!(
            ClientConfig::load(&path),
            Err(ClientConfigError::TooLarge { .. })
        ));
        std::fs::remove_dir_all(directory).expect("remove test directory");
    }
}
