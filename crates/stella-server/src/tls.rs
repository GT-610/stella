//! TLS identity generation and strict TLS 1.3 server configuration.

use std::{
    fs::{File, OpenOptions},
    io::{BufReader, Read, Write},
    path::{Path, PathBuf},
    sync::Arc,
};

use rcgen::{
    CertificateParams, DnType, ExtendedKeyUsagePurpose, KeyPair, KeyUsagePurpose, PublicKeyData,
    PKCS_ED25519,
};
use stella_crypto::sha256_segments;
use thiserror::Error;
use time::{Duration, OffsetDateTime};
use tokio_rustls::rustls::{
    self,
    pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer},
    version::TLS13,
    ServerConfig,
};
use zeroize::Zeroizing;

use crate::identity::{
    create_protected_secret_file, open_protected_secret_file, IdentityFileError,
};

/// Default lifetime of a generated self-signed TLS certificate.
pub const DEFAULT_TLS_VALIDITY_DAYS: u16 = 825;

/// Maximum accepted lifetime of a generated self-signed TLS certificate.
pub const MAX_TLS_VALIDITY_DAYS: u16 = 3_650;

/// Maximum number of subject alternative names in a generated certificate.
pub const MAX_TLS_SUBJECT_ALT_NAMES: usize = 32;

/// Maximum accepted TLS certificate-chain file size.
pub const MAX_TLS_CERTIFICATE_BYTES: usize = 65_536;

/// Maximum accepted TLS private-key file size.
pub const MAX_TLS_PRIVATE_KEY_BYTES: usize = 16_384;

const MAX_TLS_CERTIFICATES: usize = 8;
const CERTIFICATE_CLOCK_SKEW_MINUTES: i64 = 5;

/// Public information returned after creating a TLS identity.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct GeneratedTlsIdentity {
    /// SHA-256 digest of the exact DER `SubjectPublicKeyInfo`.
    pub spki_sha256: [u8; 32],
    /// Certificate expiration as a Unix timestamp in seconds.
    pub not_after_unix: i64,
}

/// Creates a protected Ed25519 private key and matching self-signed certificate.
///
/// Loopback DNS and IP names are always included. Additional names are
/// validated by `rcgen`, sorted, deduplicated, and bounded. Neither target is
/// overwritten. If writing the certificate fails after the private key was
/// created, the new key is removed before the error is returned.
///
/// # Errors
///
/// Returns [`TlsIdentityError`] for an invalid validity period or subject name,
/// randomness or certificate-generation failure, an existing target, an
/// insecure private-key path, write or sync failure, or failed rollback.
pub fn create_self_signed_tls_identity(
    certificate_path: &Path,
    private_key_path: &Path,
    additional_subject_alt_names: &[String],
    validity_days: u16,
) -> Result<GeneratedTlsIdentity, TlsIdentityError> {
    validate_validity_days(validity_days)?;
    ensure_target_absent(certificate_path)?;
    ensure_target_absent(private_key_path)?;
    let subject_alt_names = subject_alt_names(additional_subject_alt_names)?;
    let now = OffsetDateTime::now_utc();
    let not_before = now
        .checked_sub(Duration::minutes(CERTIFICATE_CLOCK_SKEW_MINUTES))
        .ok_or(TlsIdentityError::CertificateTimeOverflow)?;
    let not_after = now
        .checked_add(Duration::days(i64::from(validity_days)))
        .ok_or(TlsIdentityError::CertificateTimeOverflow)?;

    let key_pair = KeyPair::generate_for(&PKCS_ED25519)?;
    let mut parameters = CertificateParams::new(subject_alt_names)?;
    parameters.not_before = not_before;
    parameters.not_after = not_after;
    parameters
        .distinguished_name
        .push(DnType::CommonName, "Stella Controller");
    parameters.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    parameters.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
    let certificate = parameters.self_signed(&key_pair)?;
    let spki_sha256 = sha256_segments(&[&key_pair.subject_public_key_info()]);
    let private_key_pem = Zeroizing::new(key_pair.serialize_pem());

    write_protected(private_key_path, private_key_pem.as_bytes())?;
    if let Err(error) = write_public(certificate_path, certificate.pem().as_bytes()) {
        return Err(cleanup_after_certificate_failure(private_key_path, error));
    }

    Ok(GeneratedTlsIdentity {
        spki_sha256,
        not_after_unix: not_after.unix_timestamp(),
    })
}

/// Loads a bounded certificate chain and protected PKCS#8 key into rustls.
///
/// The returned configuration uses the explicit `ring` provider and TLS 1.3
/// only. Client certificates and early data are disabled. Constructing the
/// configuration also verifies that the private key is compatible with the
/// leaf certificate.
///
/// # Errors
///
/// Returns [`TlsIdentityError`] for insecure files, oversized input, malformed
/// PEM or DER, an empty or excessive certificate chain, a missing or non-PKCS#8
/// private key, unexpected PEM items, or a certificate/key mismatch.
pub fn load_tls_server_config(
    certificate_path: &Path,
    private_key_path: &Path,
) -> Result<Arc<ServerConfig>, TlsIdentityError> {
    let certificate_file =
        File::open(certificate_path).map_err(|source| TlsIdentityError::Open {
            path: certificate_path.to_path_buf(),
            source,
        })?;
    let certificate_bytes = read_bounded(
        certificate_file,
        certificate_path,
        MAX_TLS_CERTIFICATE_BYTES,
    )?;
    let private_key_file = open_protected_secret_file(private_key_path)?;
    let private_key_bytes = read_bounded(
        private_key_file,
        private_key_path,
        MAX_TLS_PRIVATE_KEY_BYTES,
    )?;
    let certificates = parse_certificates(certificate_path, &certificate_bytes)?;
    let private_key = parse_private_key(private_key_path, &private_key_bytes)?;

    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let builder = ServerConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&TLS13])
        .map_err(TlsIdentityError::TlsConfiguration)?;
    let mut configuration = builder
        .with_no_client_auth()
        .with_single_cert(certificates, private_key)
        .map_err(TlsIdentityError::TlsConfiguration)?;
    configuration.max_early_data_size = 0;
    Ok(Arc::new(configuration))
}

fn validate_validity_days(validity_days: u16) -> Result<(), TlsIdentityError> {
    if validity_days == 0 || validity_days > MAX_TLS_VALIDITY_DAYS {
        return Err(TlsIdentityError::InvalidValidityDays {
            actual: validity_days,
            maximum: MAX_TLS_VALIDITY_DAYS,
        });
    }
    Ok(())
}

fn subject_alt_names(additional: &[String]) -> Result<Vec<String>, TlsIdentityError> {
    if additional.len() > MAX_TLS_SUBJECT_ALT_NAMES.saturating_sub(3) {
        return Err(TlsIdentityError::TooManySubjectAltNames {
            actual: additional.len().saturating_add(3),
            maximum: MAX_TLS_SUBJECT_ALT_NAMES,
        });
    }
    let mut names = Vec::with_capacity(additional.len().saturating_add(3));
    names.extend([
        "localhost".to_owned(),
        "127.0.0.1".to_owned(),
        "::1".to_owned(),
    ]);
    for name in additional {
        if name.is_empty() || name.len() > 253 || name.chars().any(char::is_control) {
            return Err(TlsIdentityError::InvalidSubjectAltName);
        }
        names.push(name.clone());
    }
    names.sort();
    names.dedup();
    Ok(names)
}

fn ensure_target_absent(path: &Path) -> Result<(), TlsIdentityError> {
    match std::fs::symlink_metadata(path) {
        Ok(_) => Err(TlsIdentityError::TargetExists {
            path: path.to_path_buf(),
        }),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(source) => Err(TlsIdentityError::Inspect {
            path: path.to_path_buf(),
            source,
        }),
    }
}

fn write_protected(path: &Path, bytes: &[u8]) -> Result<(), TlsIdentityError> {
    let mut file = create_protected_secret_file(path)?;
    write_and_sync(&mut file, path, bytes).map_err(|error| {
        drop(file);
        cleanup_partial(path, error)
    })
}

fn write_public(path: &Path, bytes: &[u8]) -> Result<(), TlsIdentityError> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(|source| TlsIdentityError::Create {
            path: path.to_path_buf(),
            source,
        })?;
    write_and_sync(&mut file, path, bytes).map_err(|error| {
        drop(file);
        cleanup_partial(path, error)
    })
}

fn write_and_sync(file: &mut File, path: &Path, bytes: &[u8]) -> Result<(), TlsIdentityError> {
    file.write_all(bytes)
        .map_err(|source| TlsIdentityError::Write {
            path: path.to_path_buf(),
            source,
        })?;
    file.sync_all().map_err(|source| TlsIdentityError::Sync {
        path: path.to_path_buf(),
        source,
    })
}

fn cleanup_partial(path: &Path, cause: TlsIdentityError) -> TlsIdentityError {
    match std::fs::remove_file(path) {
        Ok(()) => cause,
        Err(source) => TlsIdentityError::CleanupFailed {
            path: path.to_path_buf(),
            cause: Box::new(cause),
            source,
        },
    }
}

fn cleanup_after_certificate_failure(
    private_key_path: &Path,
    cause: TlsIdentityError,
) -> TlsIdentityError {
    match std::fs::remove_file(private_key_path) {
        Ok(()) => cause,
        Err(source) => TlsIdentityError::CleanupFailed {
            path: private_key_path.to_path_buf(),
            cause: Box::new(cause),
            source,
        },
    }
}

fn read_bounded(
    mut file: File,
    path: &Path,
    maximum: usize,
) -> Result<Zeroizing<Vec<u8>>, TlsIdentityError> {
    let maximum_u64 = u64::try_from(maximum).map_err(|_| TlsIdentityError::LengthOverflow)?;
    let metadata = file
        .metadata()
        .map_err(|source| TlsIdentityError::Inspect {
            path: path.to_path_buf(),
            source,
        })?;
    if !metadata.is_file() {
        return Err(TlsIdentityError::NotRegularFile {
            path: path.to_path_buf(),
        });
    }
    if metadata.len() > maximum_u64 {
        return Err(TlsIdentityError::TooLarge {
            path: path.to_path_buf(),
            actual: metadata.len(),
            maximum,
        });
    }
    let mut bytes = Zeroizing::new(Vec::with_capacity(maximum));
    (&mut file)
        .take(maximum_u64.saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(|source| TlsIdentityError::Read {
            path: path.to_path_buf(),
            source,
        })?;
    if bytes.len() > maximum {
        return Err(TlsIdentityError::TooLarge {
            path: path.to_path_buf(),
            actual: u64::try_from(bytes.len()).map_err(|_| TlsIdentityError::LengthOverflow)?,
            maximum,
        });
    }
    Ok(bytes)
}

fn parse_certificates(
    path: &Path,
    bytes: &[u8],
) -> Result<Vec<CertificateDer<'static>>, TlsIdentityError> {
    let mut reader = BufReader::new(bytes);
    let mut certificates = Vec::new();
    for item in rustls_pemfile::read_all(&mut reader) {
        match item.map_err(|source| TlsIdentityError::ParsePem {
            path: path.to_path_buf(),
            source,
        })? {
            rustls_pemfile::Item::X509Certificate(certificate) => {
                certificates.push(certificate);
                if certificates.len() > MAX_TLS_CERTIFICATES {
                    return Err(TlsIdentityError::TooManyCertificates {
                        actual: certificates.len(),
                        maximum: MAX_TLS_CERTIFICATES,
                    });
                }
            }
            _ => {
                return Err(TlsIdentityError::UnexpectedPemItem {
                    path: path.to_path_buf(),
                    expected: "CERTIFICATE",
                });
            }
        }
    }
    if certificates.is_empty() {
        return Err(TlsIdentityError::MissingCertificate {
            path: path.to_path_buf(),
        });
    }
    Ok(certificates)
}

fn parse_private_key(
    path: &Path,
    bytes: &[u8],
) -> Result<PrivateKeyDer<'static>, TlsIdentityError> {
    if bytes.starts_with(b"-----BEGIN") {
        let mut reader = BufReader::new(bytes);
        let mut key = None;
        for item in rustls_pemfile::read_all(&mut reader) {
            match item.map_err(|source| TlsIdentityError::ParsePem {
                path: path.to_path_buf(),
                source,
            })? {
                rustls_pemfile::Item::Pkcs8Key(candidate) if key.is_none() => {
                    key = Some(PrivateKeyDer::Pkcs8(candidate));
                }
                _ => {
                    return Err(TlsIdentityError::UnexpectedPemItem {
                        path: path.to_path_buf(),
                        expected: "exactly one PRIVATE KEY",
                    });
                }
            }
        }
        key.ok_or_else(|| TlsIdentityError::MissingPrivateKey {
            path: path.to_path_buf(),
        })
    } else if bytes.is_empty() {
        Err(TlsIdentityError::MissingPrivateKey {
            path: path.to_path_buf(),
        })
    } else {
        Ok(PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(
            bytes.to_vec(),
        )))
    }
}

/// TLS certificate, key, permission, parsing, or configuration failure.
#[derive(Debug, Error)]
pub enum TlsIdentityError {
    /// The requested validity is zero or above the supported bound.
    #[error("TLS certificate validity {actual} days is outside 1 through {maximum}")]
    InvalidValidityDays {
        /// Requested validity.
        actual: u16,
        /// Largest accepted validity.
        maximum: u16,
    },
    /// Too many subject alternative names were requested.
    #[error("TLS certificate has {actual} subject alternative names; maximum is {maximum}")]
    TooManySubjectAltNames {
        /// Total requested names including defaults.
        actual: usize,
        /// Maximum accepted names.
        maximum: usize,
    },
    /// One subject alternative name violates local syntax or size bounds.
    #[error("TLS subject alternative name must contain 1 through 253 non-control bytes")]
    InvalidSubjectAltName,
    /// Certificate validity arithmetic overflowed.
    #[error("TLS certificate validity cannot be represented")]
    CertificateTimeOverflow,
    /// A create-new target already exists.
    #[error("TLS identity target already exists: {path}")]
    TargetExists {
        /// Existing path.
        path: PathBuf,
    },
    /// A target could not be inspected.
    #[error("unable to inspect TLS identity file {path}")]
    Inspect {
        /// Inspected path.
        path: PathBuf,
        /// Underlying filesystem failure.
        #[source]
        source: std::io::Error,
    },
    /// A public TLS file could not be created.
    #[error("unable to create TLS identity file {path}")]
    Create {
        /// Requested path.
        path: PathBuf,
        /// Underlying filesystem failure.
        #[source]
        source: std::io::Error,
    },
    /// An existing TLS file could not be opened.
    #[error("unable to open TLS identity file {path}")]
    Open {
        /// Requested path.
        path: PathBuf,
        /// Underlying filesystem failure.
        #[source]
        source: std::io::Error,
    },
    /// A TLS identity path is not a regular file.
    #[error("TLS identity path {path} is not a regular file")]
    NotRegularFile {
        /// Rejected path.
        path: PathBuf,
    },
    /// A TLS identity file could not be read.
    #[error("unable to read TLS identity file {path}")]
    Read {
        /// Requested path.
        path: PathBuf,
        /// Underlying filesystem failure.
        #[source]
        source: std::io::Error,
    },
    /// A TLS identity file could not be written.
    #[error("unable to write TLS identity file {path}")]
    Write {
        /// Requested path.
        path: PathBuf,
        /// Underlying filesystem failure.
        #[source]
        source: std::io::Error,
    },
    /// A TLS identity file could not be durably synchronized.
    #[error("unable to sync TLS identity file {path}")]
    Sync {
        /// Requested path.
        path: PathBuf,
        /// Underlying filesystem failure.
        #[source]
        source: std::io::Error,
    },
    /// A bounded TLS file exceeded its maximum.
    #[error("TLS identity file {path} has {actual} bytes, exceeding maximum {maximum}")]
    TooLarge {
        /// Rejected path.
        path: PathBuf,
        /// Observed bytes.
        actual: u64,
        /// Maximum accepted bytes.
        maximum: usize,
    },
    /// A size could not be represented safely.
    #[error("TLS identity length cannot be represented safely")]
    LengthOverflow,
    /// PEM syntax is malformed.
    #[error("invalid PEM in TLS identity file {path}")]
    ParsePem {
        /// Rejected path.
        path: PathBuf,
        /// PEM parser failure.
        #[source]
        source: std::io::Error,
    },
    /// A PEM file contains an item outside its strict role.
    #[error("TLS identity file {path} must contain {expected}")]
    UnexpectedPemItem {
        /// Rejected path.
        path: PathBuf,
        /// Required item description.
        expected: &'static str,
    },
    /// No certificate was present.
    #[error("TLS certificate file {path} contains no certificate")]
    MissingCertificate {
        /// Rejected path.
        path: PathBuf,
    },
    /// The certificate chain exceeds its object-count bound.
    #[error("TLS certificate chain has {actual} certificates; maximum is {maximum}")]
    TooManyCertificates {
        /// Observed certificate count.
        actual: usize,
        /// Maximum accepted count.
        maximum: usize,
    },
    /// No compatible PKCS#8 private key was present.
    #[error("TLS private-key file {path} contains no PKCS#8 private key")]
    MissingPrivateKey {
        /// Rejected path.
        path: PathBuf,
    },
    /// Native protected-file creation or verification failed.
    #[error(transparent)]
    ProtectedFile(#[from] IdentityFileError),
    /// Certificate generation or subject-name validation failed.
    #[error(transparent)]
    Generate(#[from] rcgen::Error),
    /// rustls rejected versions, certificates, keys, or their relationship.
    #[error("invalid TLS server configuration: {0}")]
    TlsConfiguration(rustls::Error),
    /// Removing a partial new file failed.
    #[error("unable to remove partial TLS identity file {path} after {cause}")]
    CleanupFailed {
        /// Partial path.
        path: PathBuf,
        /// Failure that triggered cleanup.
        cause: Box<TlsIdentityError>,
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

    use super::{
        create_self_signed_tls_identity, load_tls_server_config, TlsIdentityError,
        DEFAULT_TLS_VALIDITY_DAYS,
    };

    static TEMP_SEQUENCE: AtomicU64 = AtomicU64::new(1);

    fn temp_directory() -> PathBuf {
        let sequence = TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        std::env::temp_dir().join(format!("stella-tls-{}-{sequence}", std::process::id()))
    }

    #[test]
    fn generated_identity_loads_as_tls13_only_and_refuses_overwrite() {
        let directory = temp_directory();
        std::fs::create_dir(&directory).expect("create test directory");
        let certificate = directory.join("tls-cert.pem");
        let private_key = directory.join("tls-key.pem");
        let generated = create_self_signed_tls_identity(
            &certificate,
            &private_key,
            &["controller.example.test".to_owned()],
            DEFAULT_TLS_VALIDITY_DAYS,
        )
        .expect("create TLS identity");
        assert_ne!(generated.spki_sha256, [0; 32]);
        let configuration =
            load_tls_server_config(&certificate, &private_key).expect("load TLS identity");
        assert_eq!(configuration.max_early_data_size, 0);
        assert!(matches!(
            create_self_signed_tls_identity(
                &certificate,
                &private_key,
                &[],
                DEFAULT_TLS_VALIDITY_DAYS
            ),
            Err(TlsIdentityError::TargetExists { .. })
        ));
        std::fs::remove_dir_all(&directory).expect("remove test directory");
    }

    #[test]
    fn mismatched_and_non_pkcs8_inputs_are_rejected() {
        let directory = temp_directory();
        let other = directory.join("other");
        std::fs::create_dir_all(&other).expect("create test directories");
        let certificate = directory.join("tls-cert.pem");
        let private_key = directory.join("tls-key.pem");
        let other_certificate = other.join("tls-cert.pem");
        let other_key = other.join("tls-key.pem");
        create_self_signed_tls_identity(&certificate, &private_key, &[], DEFAULT_TLS_VALIDITY_DAYS)
            .expect("create first TLS identity");
        create_self_signed_tls_identity(
            &other_certificate,
            &other_key,
            &[],
            DEFAULT_TLS_VALIDITY_DAYS,
        )
        .expect("create second TLS identity");
        std::fs::copy(&other_certificate, &certificate).expect("replace public certificate");
        assert!(matches!(
            load_tls_server_config(&certificate, &private_key),
            Err(TlsIdentityError::TlsConfiguration(_))
        ));
        std::fs::write(&certificate, "not a certificate").expect("replace certificate text");
        assert!(matches!(
            load_tls_server_config(&certificate, &private_key),
            Err(TlsIdentityError::MissingCertificate { .. })
        ));
        std::fs::remove_dir_all(&directory).expect("remove test directory");
    }
}
