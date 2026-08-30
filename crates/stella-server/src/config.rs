//! Strict versioned controller configuration.

use std::{
    fs::File,
    io::Read,
    net::SocketAddr,
    path::{Path, PathBuf},
};

use serde::Deserialize;
use thiserror::Error;

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

        Ok(Self {
            version: raw.version,
            listen: raw.listen,
            database_path: resolve_path(base_directory, &raw.state.database),
            controller_identity_path: resolve_path(base_directory, &raw.identity.controller_key),
            tls_certificate_path: resolve_path(base_directory, &raw.tls.certificate),
            tls_private_key_path: resolve_path(base_directory, &raw.tls.private_key),
            limits: raw.limits,
            logging: raw.logging,
        })
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
