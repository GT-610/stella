//! Transactional controller deployment initialization.

use std::{
    fs::{File, OpenOptions},
    io::Write,
    net::SocketAddr,
    path::{Path, PathBuf},
};

use stella_common::ControllerId;
use stella_crypto::derive_controller_id;
use thiserror::Error;

use crate::{
    config::ServerConfig,
    identity::{create_controller_identity, IdentityFileError},
    store::{AuthorityStore, StoreError},
    tls::{
        create_self_signed_tls_identity, GeneratedTlsIdentity, TlsIdentityError,
        DEFAULT_TLS_VALIDITY_DAYS,
    },
};

const DATABASE_RELATIVE_PATH: &str = "state/controller.redb";
const CONTROLLER_KEY_RELATIVE_PATH: &str = "secrets/controller.pk8";
const TLS_CERTIFICATE_RELATIVE_PATH: &str = "secrets/tls-cert.pem";
const TLS_PRIVATE_KEY_RELATIVE_PATH: &str = "secrets/tls-key.pem";

/// Inputs for a create-new controller deployment.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BootstrapOptions {
    /// TCP address written to the generated configuration.
    pub listen: SocketAddr,
    /// Additional DNS names or IP addresses for the generated certificate.
    pub tls_subject_alt_names: Vec<String>,
    /// Generated certificate validity in days.
    pub tls_validity_days: u16,
}

impl Default for BootstrapOptions {
    fn default() -> Self {
        Self {
            listen: SocketAddr::from(([0, 0, 0, 0], 44_900)),
            tls_subject_alt_names: Vec::new(),
            tls_validity_days: DEFAULT_TLS_VALIDITY_DAYS,
        }
    }
}

/// Public trust information returned by successful initialization.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BootstrapResult {
    /// Controller ID derived from the new Stella signing identity.
    pub controller_id: ControllerId,
    /// SHA-256 digest of the generated TLS `SubjectPublicKeyInfo`.
    pub tls_spki_sha256: [u8; 32],
    /// Generated TLS certificate expiration as a Unix timestamp.
    pub tls_not_after_unix: i64,
}

/// Creates a complete controller deployment without overwriting any target.
///
/// Relative state and secret paths are rooted beside `config_path`. Missing
/// directories are created. A failure removes only files and empty directories
/// successfully created by this invocation.
///
/// # Errors
///
/// Returns [`BootstrapError`] for an invalid listen address, existing or
/// inaccessible targets, directory creation failure, identity or database
/// initialization failure, generated configuration rejection, or rollback
/// failure.
pub fn initialize_controller(
    config_path: &Path,
    options: &BootstrapOptions,
) -> Result<BootstrapResult, BootstrapError> {
    validate_options(options)?;
    let paths = DeploymentPaths::new(config_path)?;
    paths.preflight()?;
    let mut changes = CreatedChanges::default();
    match initialize_inner(&paths, options, &mut changes) {
        Ok(result) => Ok(result),
        Err(cause) => Err(changes.rollback(cause)),
    }
}

fn initialize_inner(
    paths: &DeploymentPaths,
    options: &BootstrapOptions,
    changes: &mut CreatedChanges,
) -> Result<BootstrapResult, BootstrapError> {
    ensure_directory(&paths.base_directory, &mut changes.directories)?;
    ensure_directory(parent_required(&paths.database)?, &mut changes.directories)?;
    ensure_directory(
        parent_required(&paths.controller_key)?,
        &mut changes.directories,
    )?;

    let controller_identity = create_controller_identity(&paths.controller_key)?;
    changes.files.push(paths.controller_key.clone());
    let controller_id = derive_controller_id(controller_identity.public_key());
    drop(controller_identity);

    let tls = create_self_signed_tls_identity(
        &paths.tls_certificate,
        &paths.tls_private_key,
        &options.tls_subject_alt_names,
        options.tls_validity_days,
    )?;
    changes.files.push(paths.tls_private_key.clone());
    changes.files.push(paths.tls_certificate.clone());

    let store = match AuthorityStore::initialize(&paths.database, controller_id) {
        Ok(store) => store,
        Err(error) => {
            if paths.database.exists() {
                changes.files.push(paths.database.clone());
            }
            return Err(BootstrapError::Store(error));
        }
    };
    changes.files.push(paths.database.clone());
    drop(store);

    let document = configuration_document(options.listen);
    write_create_new(&paths.config, document.as_bytes())?;
    changes.files.push(paths.config.clone());
    let loaded = ServerConfig::load(&paths.config)?;
    paths.verify_loaded_configuration(&loaded)?;

    Ok(result(controller_id, tls))
}

fn result(controller_id: ControllerId, tls: GeneratedTlsIdentity) -> BootstrapResult {
    BootstrapResult {
        controller_id,
        tls_spki_sha256: tls.spki_sha256,
        tls_not_after_unix: tls.not_after_unix,
    }
}

fn validate_options(options: &BootstrapOptions) -> Result<(), BootstrapError> {
    if options.listen.port() == 0 {
        return Err(BootstrapError::InvalidListenAddress);
    }
    Ok(())
}

fn configuration_document(listen: SocketAddr) -> String {
    format!(
        "version = 1\nlisten = \"{listen}\"\n\n[state]\ndatabase = \"{DATABASE_RELATIVE_PATH}\"\n\n[identity]\ncontroller_key = \"{CONTROLLER_KEY_RELATIVE_PATH}\"\n\n[tls]\ncertificate = \"{TLS_CERTIFICATE_RELATIVE_PATH}\"\nprivate_key = \"{TLS_PRIVATE_KEY_RELATIVE_PATH}\"\n\n[limits]\nauthority_queue = 256\nmax_connections = 1024\noutbound_messages = 64\nauthentication_timeout_seconds = 10\nrequest_timeout_seconds = 10\n\n[logging]\nfilter = \"info,stella_server=info\"\n"
    )
}

fn write_create_new(path: &Path, bytes: &[u8]) -> Result<(), BootstrapError> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(|source| BootstrapError::CreateFile {
            path: path.to_path_buf(),
            source,
        })?;
    if let Err(error) = write_and_sync(&mut file, path, bytes) {
        drop(file);
        return Err(cleanup_partial_file(path, error));
    }
    Ok(())
}

fn write_and_sync(file: &mut File, path: &Path, bytes: &[u8]) -> Result<(), BootstrapError> {
    file.write_all(bytes)
        .map_err(|source| BootstrapError::WriteFile {
            path: path.to_path_buf(),
            source,
        })?;
    file.sync_all().map_err(|source| BootstrapError::SyncFile {
        path: path.to_path_buf(),
        source,
    })
}

fn cleanup_partial_file(path: &Path, cause: BootstrapError) -> BootstrapError {
    match std::fs::remove_file(path) {
        Ok(()) => cause,
        Err(source) => BootstrapError::RollbackFailed {
            path: path.to_path_buf(),
            cause: Box::new(cause),
            source,
        },
    }
}

fn ensure_directory(path: &Path, created: &mut Vec<PathBuf>) -> Result<(), BootstrapError> {
    if path.as_os_str().is_empty() {
        return Ok(());
    }
    match std::fs::metadata(path) {
        Ok(metadata) if metadata.is_dir() => return Ok(()),
        Ok(_) => {
            return Err(BootstrapError::NotDirectory {
                path: path.to_path_buf(),
            });
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(source) => {
            return Err(BootstrapError::Inspect {
                path: path.to_path_buf(),
                source,
            });
        }
    }
    if let Some(parent) = path.parent() {
        ensure_directory(parent, created)?;
    }
    match std::fs::create_dir(path) {
        Ok(()) => created.push(path.to_path_buf()),
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
            let metadata = std::fs::metadata(path).map_err(|source| BootstrapError::Inspect {
                path: path.to_path_buf(),
                source,
            })?;
            if !metadata.is_dir() {
                return Err(BootstrapError::NotDirectory {
                    path: path.to_path_buf(),
                });
            }
        }
        Err(source) => {
            return Err(BootstrapError::CreateDirectory {
                path: path.to_path_buf(),
                source,
            });
        }
    }
    Ok(())
}

fn parent_required(path: &Path) -> Result<&Path, BootstrapError> {
    path.parent().ok_or_else(|| BootstrapError::MissingParent {
        path: path.to_path_buf(),
    })
}

#[derive(Debug)]
struct DeploymentPaths {
    base_directory: PathBuf,
    config: PathBuf,
    database: PathBuf,
    controller_key: PathBuf,
    tls_certificate: PathBuf,
    tls_private_key: PathBuf,
}

impl DeploymentPaths {
    fn new(config_path: &Path) -> Result<Self, BootstrapError> {
        if config_path.as_os_str().is_empty() {
            return Err(BootstrapError::EmptyConfigPath);
        }
        let base_directory = config_path
            .parent()
            .filter(|path| !path.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new("."))
            .to_path_buf();
        Ok(Self {
            database: base_directory.join(DATABASE_RELATIVE_PATH),
            controller_key: base_directory.join(CONTROLLER_KEY_RELATIVE_PATH),
            tls_certificate: base_directory.join(TLS_CERTIFICATE_RELATIVE_PATH),
            tls_private_key: base_directory.join(TLS_PRIVATE_KEY_RELATIVE_PATH),
            base_directory,
            config: config_path.to_path_buf(),
        })
    }

    fn preflight(&self) -> Result<(), BootstrapError> {
        for path in [
            &self.config,
            &self.database,
            &self.controller_key,
            &self.tls_certificate,
            &self.tls_private_key,
        ] {
            match std::fs::symlink_metadata(path) {
                Ok(_) => {
                    return Err(BootstrapError::TargetExists { path: path.clone() });
                }
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(source) => {
                    return Err(BootstrapError::Inspect {
                        path: path.clone(),
                        source,
                    });
                }
            }
        }
        Ok(())
    }

    fn verify_loaded_configuration(&self, config: &ServerConfig) -> Result<(), BootstrapError> {
        if config.database_path != self.database
            || config.controller_identity_path != self.controller_key
            || config.tls_certificate_path != self.tls_certificate
            || config.tls_private_key_path != self.tls_private_key
        {
            return Err(BootstrapError::GeneratedConfigurationMismatch);
        }
        Ok(())
    }
}

#[derive(Default)]
struct CreatedChanges {
    files: Vec<PathBuf>,
    directories: Vec<PathBuf>,
}

impl CreatedChanges {
    fn rollback(self, cause: BootstrapError) -> BootstrapError {
        let mut first_failure = None;
        for path in self.files.into_iter().rev() {
            if let Err(source) = std::fs::remove_file(&path) {
                if source.kind() != std::io::ErrorKind::NotFound && first_failure.is_none() {
                    first_failure = Some((path, source));
                }
            }
        }
        for path in self.directories.into_iter().rev() {
            if let Err(source) = std::fs::remove_dir(&path) {
                if source.kind() != std::io::ErrorKind::NotFound && first_failure.is_none() {
                    first_failure = Some((path, source));
                }
            }
        }
        match first_failure {
            Some((path, source)) => BootstrapError::RollbackFailed {
                path,
                cause: Box::new(cause),
                source,
            },
            None => cause,
        }
    }
}

/// Controller deployment initialization failure.
#[derive(Debug, Error)]
pub enum BootstrapError {
    /// The configuration path is empty.
    #[error("controller configuration path must not be empty")]
    EmptyConfigPath,
    /// The listen port is zero.
    #[error("controller listen port must be non-zero")]
    InvalidListenAddress,
    /// A deployment target already exists.
    #[error("controller initialization target already exists: {path}")]
    TargetExists {
        /// Existing target.
        path: PathBuf,
    },
    /// A path could not be inspected.
    #[error("unable to inspect controller initialization path {path}")]
    Inspect {
        /// Inspected path.
        path: PathBuf,
        /// Underlying filesystem failure.
        #[source]
        source: std::io::Error,
    },
    /// A required parent path does not exist lexically.
    #[error("controller initialization path has no parent: {path}")]
    MissingParent {
        /// Path without a parent.
        path: PathBuf,
    },
    /// An existing parent path is not a directory.
    #[error("controller initialization parent is not a directory: {path}")]
    NotDirectory {
        /// Rejected parent path.
        path: PathBuf,
    },
    /// A directory could not be created.
    #[error("unable to create controller directory {path}")]
    CreateDirectory {
        /// Requested directory.
        path: PathBuf,
        /// Underlying filesystem failure.
        #[source]
        source: std::io::Error,
    },
    /// A public deployment file could not be created.
    #[error("unable to create controller file {path}")]
    CreateFile {
        /// Requested file.
        path: PathBuf,
        /// Underlying filesystem failure.
        #[source]
        source: std::io::Error,
    },
    /// A deployment file could not be written.
    #[error("unable to write controller file {path}")]
    WriteFile {
        /// Requested file.
        path: PathBuf,
        /// Underlying filesystem failure.
        #[source]
        source: std::io::Error,
    },
    /// A deployment file could not be synchronized.
    #[error("unable to sync controller file {path}")]
    SyncFile {
        /// Requested file.
        path: PathBuf,
        /// Underlying filesystem failure.
        #[source]
        source: std::io::Error,
    },
    /// The generated configuration did not resolve to its intended files.
    #[error("generated controller configuration resolved to unexpected paths")]
    GeneratedConfigurationMismatch,
    /// Controller identity initialization failed.
    #[error(transparent)]
    Identity(#[from] IdentityFileError),
    /// TLS identity initialization failed.
    #[error(transparent)]
    Tls(#[from] TlsIdentityError),
    /// Authority database initialization failed.
    #[error(transparent)]
    Store(#[from] StoreError),
    /// Generated configuration loading or validation failed.
    #[error(transparent)]
    Config(#[from] crate::config::ConfigError),
    /// A best-effort rollback could not remove one created path.
    #[error("unable to roll back controller path {path} after {cause}")]
    RollbackFailed {
        /// Created path that remains.
        path: PathBuf,
        /// Initialization failure that triggered rollback.
        cause: Box<BootstrapError>,
        /// Cleanup filesystem failure.
        #[source]
        source: std::io::Error,
    },
}

#[cfg(all(test, windows))]
mod tests {
    use std::{
        path::PathBuf,
        sync::atomic::{AtomicU64, Ordering},
    };

    use stella_crypto::derive_controller_id;

    use super::{initialize_controller, BootstrapError, BootstrapOptions};
    use crate::{
        config::ServerConfig, identity::load_controller_identity, store::AuthorityStore,
        tls::load_tls_server_config,
    };

    static TEMP_SEQUENCE: AtomicU64 = AtomicU64::new(1);

    fn temp_directory() -> PathBuf {
        let sequence = TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        std::env::temp_dir().join(format!(
            "stella-bootstrap-{}-{sequence}",
            std::process::id()
        ))
    }

    #[test]
    fn complete_deployment_is_create_new_and_self_consistent() {
        let directory = temp_directory();
        let config_path = directory.join("server.toml");
        let result = initialize_controller(
            &config_path,
            &BootstrapOptions {
                listen: "127.0.0.1:44901".parse().expect("valid listen address"),
                tls_subject_alt_names: vec!["controller.example.test".to_owned()],
                ..BootstrapOptions::default()
            },
        )
        .expect("initialize deployment");
        let config = ServerConfig::load(&config_path).expect("load generated configuration");
        assert_eq!(config.listen.to_string(), "127.0.0.1:44901");
        let identity = load_controller_identity(&config.controller_identity_path)
            .expect("load generated controller identity");
        assert_eq!(
            result.controller_id,
            derive_controller_id(identity.public_key())
        );
        drop(identity);
        load_tls_server_config(&config.tls_certificate_path, &config.tls_private_key_path)
            .expect("load generated TLS identity");
        let store = AuthorityStore::open(&config.database_path, result.controller_id)
            .expect("open generated authority store");
        drop(store);
        assert!(matches!(
            initialize_controller(&config_path, &BootstrapOptions::default()),
            Err(BootstrapError::TargetExists { .. })
        ));
        std::fs::remove_dir_all(&directory).expect("remove test directory");
    }

    #[test]
    fn invalid_options_and_existing_targets_create_nothing_else() {
        let directory = temp_directory();
        let config_path = directory.join("server.toml");
        let options = BootstrapOptions {
            listen: "127.0.0.1:0".parse().expect("valid socket syntax"),
            ..BootstrapOptions::default()
        };
        assert!(matches!(
            initialize_controller(&config_path, &options),
            Err(BootstrapError::InvalidListenAddress)
        ));
        assert!(!directory.exists());

        std::fs::create_dir(&directory).expect("create test directory");
        std::fs::write(&config_path, "owned by operator").expect("create existing target");
        assert!(matches!(
            initialize_controller(&config_path, &BootstrapOptions::default()),
            Err(BootstrapError::TargetExists { .. })
        ));
        assert_eq!(
            std::fs::read_to_string(&config_path).expect("read existing target"),
            "owned by operator"
        );
        assert!(!directory.join("state").exists());
        assert!(!directory.join("secrets").exists());
        std::fs::remove_dir_all(&directory).expect("remove test directory");
    }
}
