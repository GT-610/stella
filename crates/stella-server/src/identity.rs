//! Controller identity creation, loading, and native file-permission checks.

use std::{
    fs::File,
    io::{self, Read, Write},
    path::{Path, PathBuf},
};

use stella_crypto::{CryptoError, IdentitySigningKey, MAX_IDENTITY_PKCS8_LENGTH};
use thiserror::Error;
use zeroize::Zeroizing;

/// Creates a new protected controller Ed25519 identity file.
///
/// The target is never overwritten. Native permissions are hardened and
/// verified before any PKCS#8 secret bytes are written.
///
/// # Errors
///
/// Returns [`IdentityFileError`] for unsupported platforms, random generation
/// or encoding failure, an existing path, insecure native permissions, write
/// or sync failure, or failure to remove a partial new file.
pub fn create_controller_identity(path: &Path) -> Result<IdentitySigningKey, IdentityFileError> {
    let signing_key = IdentitySigningKey::generate()?;
    let document = signing_key.to_pkcs8_der()?;
    let mut file = platform::create_secure_file(path)?;
    if let Err(error) = write_identity(&mut file, path, document.expose_secret()) {
        drop(file);
        return Err(cleanup_created_file(path, error));
    }
    Ok(signing_key)
}

pub(crate) fn create_protected_secret_file(path: &Path) -> Result<File, IdentityFileError> {
    platform::create_secure_file(path)
}

pub(crate) fn open_protected_secret_file(path: &Path) -> Result<File, IdentityFileError> {
    platform::open_verified_file(path)
}

/// Loads one protected bounded controller Ed25519 PKCS#8 identity.
///
/// # Errors
///
/// Returns [`IdentityFileError`] when the file cannot be opened, is not a
/// regular non-reparse file, has an insecure native permission policy, exceeds
/// the PKCS#8 bound, cannot be read, or contains an invalid Ed25519 key.
pub fn load_controller_identity(path: &Path) -> Result<IdentitySigningKey, IdentityFileError> {
    let mut file = platform::open_verified_file(path)?;
    let metadata = file
        .metadata()
        .map_err(|source| IdentityFileError::Metadata {
            path: path.to_path_buf(),
            source,
        })?;
    let maximum = u64::try_from(MAX_IDENTITY_PKCS8_LENGTH)
        .map_err(|_| IdentityFileError::LengthConversion)?;
    if metadata.len() > maximum {
        return Err(IdentityFileError::TooLarge {
            path: path.to_path_buf(),
            actual: metadata.len(),
            maximum: MAX_IDENTITY_PKCS8_LENGTH,
        });
    }

    let mut document = Zeroizing::new(Vec::with_capacity(MAX_IDENTITY_PKCS8_LENGTH));
    (&mut file)
        .take(maximum.saturating_add(1))
        .read_to_end(&mut document)
        .map_err(|source| IdentityFileError::Read {
            path: path.to_path_buf(),
            source,
        })?;
    if document.len() > MAX_IDENTITY_PKCS8_LENGTH {
        return Err(IdentityFileError::TooLarge {
            path: path.to_path_buf(),
            actual: u64::try_from(document.len())
                .map_err(|_| IdentityFileError::LengthConversion)?,
            maximum: MAX_IDENTITY_PKCS8_LENGTH,
        });
    }
    IdentitySigningKey::from_pkcs8_der(&document).map_err(IdentityFileError::from)
}

/// Verifies the native security policy of a controller identity file.
///
/// # Errors
///
/// Returns [`IdentityFileError`] when the path cannot be opened, is not a
/// regular non-reparse file, or does not have the exact platform security
/// policy required by Stella.
pub fn verify_controller_identity_permissions(path: &Path) -> Result<(), IdentityFileError> {
    let _file = platform::open_verified_file(path)?;
    Ok(())
}

fn write_identity(file: &mut File, path: &Path, document: &[u8]) -> Result<(), IdentityFileError> {
    file.write_all(document)
        .map_err(|source| IdentityFileError::Write {
            path: path.to_path_buf(),
            source,
        })?;
    file.sync_all().map_err(|source| IdentityFileError::Sync {
        path: path.to_path_buf(),
        source,
    })
}

fn cleanup_created_file(path: &Path, cause: IdentityFileError) -> IdentityFileError {
    match std::fs::remove_file(path) {
        Ok(()) => cause,
        Err(source) => IdentityFileError::CleanupFailed {
            path: path.to_path_buf(),
            cause: Box::new(cause),
            source,
        },
    }
}

/// Controller identity persistence or native-permission failure.
#[derive(Debug, Error)]
pub enum IdentityFileError {
    /// This build does not yet implement a secure native permission backend.
    #[error("secure controller identity files are unsupported on this platform")]
    UnsupportedPlatform,
    /// A new identity file could not be created with create-new semantics.
    #[error("unable to create new controller identity file {path}")]
    Create {
        /// Requested identity path.
        path: PathBuf,
        /// Underlying filesystem failure.
        #[source]
        source: io::Error,
    },
    /// An existing identity file could not be opened.
    #[error("unable to open controller identity file {path}")]
    Open {
        /// Requested identity path.
        path: PathBuf,
        /// Underlying filesystem failure.
        #[source]
        source: io::Error,
    },
    /// File metadata could not be inspected.
    #[error("unable to inspect controller identity file {path}")]
    Metadata {
        /// Requested identity path.
        path: PathBuf,
        /// Underlying filesystem failure.
        #[source]
        source: io::Error,
    },
    /// The identity path is not a regular file.
    #[error("controller identity path {path} is not a regular file")]
    NotRegularFile {
        /// Rejected identity path.
        path: PathBuf,
    },
    /// The identity path resolves to a Windows reparse point.
    #[error("controller identity path {path} is a reparse point")]
    ReparsePoint {
        /// Rejected identity path.
        path: PathBuf,
    },
    /// Windows could not identify the current process account.
    #[error("unable to resolve the current Windows account SID")]
    CurrentAccountUnavailable,
    /// A native ACL operation failed with a Win32 status code.
    #[error("Windows ACL operation {operation} failed with status {code}")]
    WindowsAcl {
        /// Failed ACL operation.
        operation: &'static str,
        /// Win32 error status.
        code: u32,
    },
    /// An ACL wrapper returned success without applying the requested change.
    #[error("Windows ACL operation {operation} did not apply the requested change")]
    WindowsAclIncomplete {
        /// Incomplete ACL operation.
        operation: &'static str,
    },
    /// The native permission policy grants unexpected access.
    #[error("controller identity file {path} has insecure permissions: {reason}")]
    InsecurePermissions {
        /// Rejected identity path.
        path: PathBuf,
        /// Stable non-secret rejection reason.
        reason: &'static str,
    },
    /// The identity document exceeds the bounded PKCS#8 input size.
    #[error("controller identity file {path} has {actual} bytes, exceeding maximum {maximum}")]
    TooLarge {
        /// Rejected identity path.
        path: PathBuf,
        /// Observed file or read length.
        actual: u64,
        /// Maximum accepted bytes.
        maximum: usize,
    },
    /// A platform length could not be represented safely.
    #[error("controller identity length cannot be represented safely")]
    LengthConversion,
    /// Identity bytes could not be read.
    #[error("unable to read controller identity file {path}")]
    Read {
        /// Requested identity path.
        path: PathBuf,
        /// Underlying filesystem failure.
        #[source]
        source: io::Error,
    },
    /// Identity bytes could not be written.
    #[error("unable to write controller identity file {path}")]
    Write {
        /// Requested identity path.
        path: PathBuf,
        /// Underlying filesystem failure.
        #[source]
        source: io::Error,
    },
    /// Identity bytes could not be durably synchronized.
    #[error("unable to sync controller identity file {path}")]
    Sync {
        /// Requested identity path.
        path: PathBuf,
        /// Underlying filesystem failure.
        #[source]
        source: io::Error,
    },
    /// A newly created partial identity file could not be removed.
    #[error("unable to remove partial controller identity file {path} after {cause}")]
    CleanupFailed {
        /// Partial identity path.
        path: PathBuf,
        /// Failure that triggered cleanup.
        cause: Box<IdentityFileError>,
        /// Cleanup filesystem failure.
        #[source]
        source: io::Error,
    },
    /// Cryptographic key generation, encoding, or decoding failed.
    #[error(transparent)]
    Crypto(#[from] CryptoError),
}

#[cfg(windows)]
mod platform {
    use std::{
        collections::{BTreeMap, BTreeSet},
        fs::{File, OpenOptions},
        os::windows::{
            fs::{MetadataExt, OpenOptionsExt},
            io::AsRawHandle,
        },
        path::Path,
    };

    use windows_acl::{
        acl::{AceType, ACL},
        helper::{current_user, name_to_sid, sid_to_string, string_to_sid},
    };

    use super::{cleanup_created_file, IdentityFileError};

    const GENERIC_READ: u32 = 0x8000_0000;
    const GENERIC_WRITE: u32 = 0x4000_0000;
    const READ_CONTROL: u32 = 0x0002_0000;
    const WRITE_DAC: u32 = 0x0004_0000;
    const FILE_ALL_ACCESS: u32 = 0x001f_01ff;
    const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0000_0400;
    const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
    const LOCAL_SYSTEM_SID: &str = "S-1-5-18";

    pub(super) fn create_secure_file(path: &Path) -> Result<File, IdentityFileError> {
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .access_mode(GENERIC_READ | GENERIC_WRITE | READ_CONTROL | WRITE_DAC)
            .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
            .open(path)
            .map_err(|source| IdentityFileError::Create {
                path: path.to_path_buf(),
                source,
            })?;
        if let Err(error) = validate_file_kind(&file, path)
            .and_then(|()| harden_permissions(&file, path))
            .and_then(|()| verify_permissions(&file, path))
        {
            drop(file);
            return Err(cleanup_created_file(path, error));
        }
        Ok(file)
    }

    pub(super) fn open_verified_file(path: &Path) -> Result<File, IdentityFileError> {
        let file =
            OpenOptions::new()
                .read(true)
                .open(path)
                .map_err(|source| IdentityFileError::Open {
                    path: path.to_path_buf(),
                    source,
                })?;
        validate_file_kind(&file, path)?;
        verify_permissions(&file, path)?;
        Ok(file)
    }

    fn validate_file_kind(file: &File, path: &Path) -> Result<(), IdentityFileError> {
        let metadata = file
            .metadata()
            .map_err(|source| IdentityFileError::Metadata {
                path: path.to_path_buf(),
                source,
            })?;
        if !metadata.is_file() {
            return Err(IdentityFileError::NotRegularFile {
                path: path.to_path_buf(),
            });
        }
        if metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
            return Err(IdentityFileError::ReparsePoint {
                path: path.to_path_buf(),
            });
        }
        Ok(())
    }

    fn harden_permissions(file: &File, path: &Path) -> Result<(), IdentityFileError> {
        let mut acl = open_acl(file)?;
        let entries = acl.all().map_err(|code| IdentityFileError::WindowsAcl {
            operation: "enumerate",
            code,
        })?;
        let mut existing_sids = BTreeSet::new();
        for entry in entries {
            if entry.string_sid.is_empty() {
                return Err(insecure(path, "an ACL entry has no valid SID"));
            }
            existing_sids.insert(entry.string_sid);
        }
        for sid_string in existing_sids {
            let sid = string_to_sid(&sid_string).map_err(|code| IdentityFileError::WindowsAcl {
                operation: "decode existing SID",
                code,
            })?;
            let removed = acl
                .remove(sid.as_ptr().cast_mut().cast(), None, None)
                .map_err(|code| IdentityFileError::WindowsAcl {
                    operation: "remove existing entry",
                    code,
                })?;
            if removed == 0 {
                return Err(IdentityFileError::WindowsAclIncomplete {
                    operation: "remove existing entry",
                });
            }
        }

        for sid in required_principals()?.into_values() {
            let applied = acl
                .allow(sid.as_ptr().cast_mut().cast(), false, FILE_ALL_ACCESS)
                .map_err(|code| IdentityFileError::WindowsAcl {
                    operation: "grant required principal",
                    code,
                })?;
            if !applied {
                return Err(IdentityFileError::WindowsAclIncomplete {
                    operation: "grant required principal",
                });
            }
        }
        Ok(())
    }

    fn verify_permissions(file: &File, path: &Path) -> Result<(), IdentityFileError> {
        let acl = open_acl(file)?;
        let entries = acl.all().map_err(|code| IdentityFileError::WindowsAcl {
            operation: "enumerate",
            code,
        })?;
        let required = required_principals()?;
        let expected: BTreeSet<&str> = required.keys().map(String::as_str).collect();
        let mut observed = BTreeSet::new();
        for entry in entries {
            if entry.entry_type != AceType::AccessAllow {
                return Err(insecure(path, "an entry is not an access-allow ACE"));
            }
            if entry.flags != 0 {
                return Err(insecure(
                    path,
                    "an entry is inherited or has unexpected flags",
                ));
            }
            if entry.mask != FILE_ALL_ACCESS {
                return Err(insecure(path, "an entry has an unexpected access mask"));
            }
            if !expected.contains(entry.string_sid.as_str()) {
                return Err(insecure(path, "an unexpected principal has access"));
            }
            if !observed.insert(entry.string_sid) {
                return Err(insecure(path, "a required principal has duplicate entries"));
            }
        }
        if observed.len() != expected.len()
            || !observed.iter().all(|sid| expected.contains(sid.as_str()))
        {
            return Err(insecure(path, "a required principal is missing"));
        }
        Ok(())
    }

    fn open_acl(file: &File) -> Result<ACL, IdentityFileError> {
        ACL::from_file_handle(file.as_raw_handle().cast(), false).map_err(|code| {
            IdentityFileError::WindowsAcl {
                operation: "open security descriptor",
                code,
            }
        })
    }

    fn required_principals() -> Result<BTreeMap<String, Vec<u8>>, IdentityFileError> {
        let account = current_user().ok_or(IdentityFileError::CurrentAccountUnavailable)?;
        let user_sid =
            name_to_sid(&account, None).map_err(|code| IdentityFileError::WindowsAcl {
                operation: "resolve current account",
                code,
            })?;
        let user_string = sid_to_string(user_sid.as_ptr().cast_mut().cast()).map_err(|code| {
            IdentityFileError::WindowsAcl {
                operation: "format current account SID",
                code,
            }
        })?;
        let system_sid =
            string_to_sid(LOCAL_SYSTEM_SID).map_err(|code| IdentityFileError::WindowsAcl {
                operation: "decode LocalSystem SID",
                code,
            })?;
        let system_string =
            sid_to_string(system_sid.as_ptr().cast_mut().cast()).map_err(|code| {
                IdentityFileError::WindowsAcl {
                    operation: "format LocalSystem SID",
                    code,
                }
            })?;
        let mut principals = BTreeMap::new();
        principals.insert(user_string, user_sid);
        principals.insert(system_string, system_sid);
        Ok(principals)
    }

    fn insecure(path: &Path, reason: &'static str) -> IdentityFileError {
        IdentityFileError::InsecurePermissions {
            path: path.to_path_buf(),
            reason,
        }
    }

    #[cfg(test)]
    pub(super) fn grant_everyone_for_test(path: &Path) -> Result<(), IdentityFileError> {
        let file = OpenOptions::new()
            .read(true)
            .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
            .write(true)
            .access_mode(GENERIC_READ | GENERIC_WRITE | READ_CONTROL | WRITE_DAC)
            .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
            .open(path)
            .map_err(|source| IdentityFileError::Open {
                path: path.to_path_buf(),
                source,
            })?;
        let mut acl = open_acl(&file)?;
        let sid = string_to_sid("S-1-1-0").map_err(|code| IdentityFileError::WindowsAcl {
            operation: "decode Everyone SID",
            code,
        })?;
        acl.allow(sid.as_ptr().cast_mut().cast(), false, FILE_ALL_ACCESS)
            .map_err(|code| IdentityFileError::WindowsAcl {
                operation: "grant Everyone for test",
                code,
            })?;
        Ok(())
    }
}

#[cfg(target_os = "macos")]
mod platform {
    use std::{
        fs::{File, OpenOptions},
        os::unix::fs::{MetadataExt, OpenOptionsExt},
        path::Path,
    };

    use super::{cleanup_created_file, IdentityFileError};

    const SECRET_FILE_MODE: u32 = 0o600;

    pub(super) fn create_secure_file(path: &Path) -> Result<File, IdentityFileError> {
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .mode(SECRET_FILE_MODE)
            .custom_flags(libc::O_NOFOLLOW)
            .open(path)
            .map_err(|source| IdentityFileError::Create {
                path: path.to_path_buf(),
                source,
            })?;
        if let Err(error) = validate_file(&file, path) {
            drop(file);
            return Err(cleanup_created_file(path, error));
        }
        Ok(file)
    }

    pub(super) fn open_verified_file(path: &Path) -> Result<File, IdentityFileError> {
        let file = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW)
            .open(path)
            .map_err(|source| IdentityFileError::Open {
                path: path.to_path_buf(),
                source,
            })?;
        validate_file(&file, path)?;
        Ok(file)
    }

    fn validate_file(file: &File, path: &Path) -> Result<(), IdentityFileError> {
        let metadata = file
            .metadata()
            .map_err(|source| IdentityFileError::Metadata {
                path: path.to_path_buf(),
                source,
            })?;
        if !metadata.is_file() || metadata.nlink() != 1 {
            return Err(IdentityFileError::NotRegularFile {
                path: path.to_path_buf(),
            });
        }
        if metadata.mode() & 0o777 != SECRET_FILE_MODE {
            return Err(IdentityFileError::InsecurePermissions {
                path: path.to_path_buf(),
                reason: "mode must be exactly 0600",
            });
        }
        Ok(())
    }

    #[cfg(test)]
    pub(super) fn grant_everyone_for_test(path: &Path) -> Result<(), IdentityFileError> {
        let mut permissions = std::fs::metadata(path)
            .map_err(|source| IdentityFileError::Metadata {
                path: path.to_path_buf(),
                source,
            })?
            .permissions();
        std::os::unix::fs::PermissionsExt::set_mode(&mut permissions, 0o644);
        std::fs::set_permissions(path, permissions).map_err(|source| IdentityFileError::Metadata {
            path: path.to_path_buf(),
            source,
        })
    }
}

#[cfg(not(any(windows, target_os = "macos")))]
mod platform {
    use std::{fs::File, path::Path};

    use super::IdentityFileError;

    pub(super) fn create_secure_file(_path: &Path) -> Result<File, IdentityFileError> {
        Err(IdentityFileError::UnsupportedPlatform)
    }

    pub(super) fn open_verified_file(_path: &Path) -> Result<File, IdentityFileError> {
        Err(IdentityFileError::UnsupportedPlatform)
    }
}

#[cfg(test)]
mod tests {
    use std::{
        path::PathBuf,
        sync::atomic::{AtomicU64, Ordering},
    };

    #[cfg(any(windows, target_os = "macos"))]
    use std::{fs::OpenOptions, io::Write};

    use stella_crypto::MAX_IDENTITY_PKCS8_LENGTH;

    use super::{
        create_controller_identity, load_controller_identity,
        verify_controller_identity_permissions, IdentityFileError,
    };

    static TEMP_SEQUENCE: AtomicU64 = AtomicU64::new(1);

    fn temp_directory() -> PathBuf {
        let sequence = TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        std::env::temp_dir().join(format!(
            "stella-controller-identity-{}-{sequence}",
            std::process::id()
        ))
    }

    #[cfg(any(windows, target_os = "macos"))]
    #[test]
    fn identity_create_load_and_overwrite_refusal_are_secure() {
        let directory = temp_directory();
        std::fs::create_dir(&directory).expect("create test directory");
        let path = directory.join("controller.pk8");
        let created = create_controller_identity(&path).expect("create identity");
        verify_controller_identity_permissions(&path).expect("verify permissions");
        let loaded = load_controller_identity(&path).expect("load identity");
        assert_eq!(loaded.public_key(), created.public_key());
        assert!(matches!(
            create_controller_identity(&path),
            Err(IdentityFileError::Create { .. })
        ));
        drop(loaded);
        drop(created);
        std::fs::remove_dir_all(&directory).expect("remove test directory");
    }

    #[cfg(any(windows, target_os = "macos"))]
    #[test]
    fn malformed_oversized_and_permission_tampered_files_are_rejected() {
        let directory = temp_directory();
        std::fs::create_dir(&directory).expect("create test directory");
        let path = directory.join("controller.pk8");
        let signing = create_controller_identity(&path).expect("create identity");
        drop(signing);

        overwrite(&path, &[0x30, 0x01, 0]);
        assert!(matches!(
            load_controller_identity(&path),
            Err(IdentityFileError::Crypto(_))
        ));
        overwrite(&path, &vec![0; MAX_IDENTITY_PKCS8_LENGTH + 1]);
        assert!(matches!(
            load_controller_identity(&path),
            Err(IdentityFileError::TooLarge { .. })
        ));

        let replacement = create_controller_identity(&directory.join("replacement.pk8"))
            .expect("create replacement identity");
        let replacement_document = replacement
            .to_pkcs8_der()
            .expect("encode replacement identity");
        overwrite(&path, replacement_document.expose_secret());
        super::platform::grant_everyone_for_test(&path).expect("tamper permissions");
        assert!(matches!(
            load_controller_identity(&path),
            Err(IdentityFileError::InsecurePermissions { .. })
        ));
        drop(replacement_document);
        drop(replacement);
        std::fs::remove_dir_all(&directory).expect("remove test directory");
    }

    #[cfg(any(windows, target_os = "macos"))]
    fn overwrite(path: &std::path::Path, bytes: &[u8]) {
        let mut file = OpenOptions::new()
            .write(true)
            .truncate(true)
            .open(path)
            .expect("open identity for test overwrite");
        file.write_all(bytes).expect("overwrite test identity");
        file.sync_all().expect("sync test identity");
    }

    #[cfg(not(any(windows, target_os = "macos")))]
    #[test]
    fn unsupported_platform_fails_before_creating_a_file() {
        let directory = temp_directory();
        std::fs::create_dir(&directory).expect("create test directory");
        let path = directory.join("controller.pk8");
        assert!(matches!(
            create_controller_identity(&path),
            Err(IdentityFileError::UnsupportedPlatform)
        ));
        assert!(!path.exists());
        std::fs::remove_dir_all(&directory).expect("remove test directory");
    }
}
