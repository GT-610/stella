//! Protected persistent node identity files.

use std::{
    fs::File,
    io::{self, Read, Write},
    path::{Path, PathBuf},
};

use stella_crypto::{CryptoError, IdentitySigningKey, MAX_IDENTITY_PKCS8_LENGTH};
use thiserror::Error;
use zeroize::Zeroizing;

/// Creates a new protected Ed25519 node identity file.
///
/// The target is never overwritten. On Windows the DACL is protected from
/// inheritance and grants exact full access only to the current account and
/// `LocalSystem` before secret bytes are written.
///
/// # Errors
///
/// Returns [`NodeIdentityFileError`] for unsupported platforms, key creation,
/// an existing path, insecure permissions, write/sync, or cleanup failure.
pub fn create_node_identity(path: &Path) -> Result<IdentitySigningKey, NodeIdentityFileError> {
    let signing_key = IdentitySigningKey::generate()?;
    let document = signing_key.to_pkcs8_der()?;
    let mut file = platform::create_secure_file(path)?;
    if let Err(error) = write_identity(&mut file, path, document.expose_secret()) {
        drop(file);
        return Err(cleanup_created_file(path, error));
    }
    Ok(signing_key)
}

/// Loads a protected bounded PKCS#8 node identity.
///
/// Native permissions and file kind are verified before any secret bytes are
/// read. The bounded input buffer is zeroized on drop.
///
/// # Errors
///
/// Returns [`NodeIdentityFileError`] for native security, metadata, size,
/// read, or PKCS#8 decoding failure.
pub fn load_node_identity(path: &Path) -> Result<IdentitySigningKey, NodeIdentityFileError> {
    let mut file = platform::open_verified_file(path)?;
    let metadata = file
        .metadata()
        .map_err(|source| NodeIdentityFileError::Metadata {
            path: path.to_path_buf(),
            source,
        })?;
    let maximum = u64::try_from(MAX_IDENTITY_PKCS8_LENGTH)
        .map_err(|_| NodeIdentityFileError::LengthConversion)?;
    if metadata.len() > maximum {
        return Err(NodeIdentityFileError::TooLarge {
            path: path.to_path_buf(),
            actual: metadata.len(),
            maximum: MAX_IDENTITY_PKCS8_LENGTH,
        });
    }
    let mut document = Zeroizing::new(Vec::with_capacity(MAX_IDENTITY_PKCS8_LENGTH));
    (&mut file)
        .take(maximum.saturating_add(1))
        .read_to_end(&mut document)
        .map_err(|source| NodeIdentityFileError::Read {
            path: path.to_path_buf(),
            source,
        })?;
    if document.len() > MAX_IDENTITY_PKCS8_LENGTH {
        return Err(NodeIdentityFileError::TooLarge {
            path: path.to_path_buf(),
            actual: u64::try_from(document.len())
                .map_err(|_| NodeIdentityFileError::LengthConversion)?,
            maximum: MAX_IDENTITY_PKCS8_LENGTH,
        });
    }
    IdentitySigningKey::from_pkcs8_der(&document).map_err(NodeIdentityFileError::from)
}

/// Verifies the exact native security policy of a node identity file.
///
/// # Errors
///
/// Returns [`NodeIdentityFileError`] when the path is not a regular
/// non-reparse file or its native access policy is not exact.
pub fn verify_node_identity_permissions(path: &Path) -> Result<(), NodeIdentityFileError> {
    let _file = platform::open_verified_file(path)?;
    Ok(())
}

fn write_identity(
    file: &mut File,
    path: &Path,
    document: &[u8],
) -> Result<(), NodeIdentityFileError> {
    file.write_all(document)
        .map_err(|source| NodeIdentityFileError::Write {
            path: path.to_path_buf(),
            source,
        })?;
    file.sync_all()
        .map_err(|source| NodeIdentityFileError::Sync {
            path: path.to_path_buf(),
            source,
        })
}

fn cleanup_created_file(path: &Path, cause: NodeIdentityFileError) -> NodeIdentityFileError {
    match std::fs::remove_file(path) {
        Ok(()) => cause,
        Err(source) => NodeIdentityFileError::CleanupFailed {
            path: path.to_path_buf(),
            cause: Box::new(cause),
            source,
        },
    }
}

/// Node identity persistence or native-permission failure.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum NodeIdentityFileError {
    /// This build has no secure native file backend.
    #[error("secure node identity files are unsupported on this platform")]
    UnsupportedPlatform,
    /// A create-new identity file could not be opened.
    #[error("unable to create new node identity file {path}")]
    Create {
        /// Requested path.
        path: PathBuf,
        /// Underlying filesystem error.
        #[source]
        source: io::Error,
    },
    /// An existing identity file could not be opened.
    #[error("unable to open node identity file {path}")]
    Open {
        /// Requested path.
        path: PathBuf,
        /// Underlying filesystem error.
        #[source]
        source: io::Error,
    },
    /// File metadata could not be inspected.
    #[error("unable to inspect node identity file {path}")]
    Metadata {
        /// Inspected path.
        path: PathBuf,
        /// Underlying filesystem error.
        #[source]
        source: io::Error,
    },
    /// The identity path is not a regular file.
    #[error("node identity path {path} is not a regular file")]
    NotRegularFile {
        /// Rejected path.
        path: PathBuf,
    },
    /// The identity path is a Windows reparse point.
    #[error("node identity path {path} is a reparse point")]
    ReparsePoint {
        /// Rejected path.
        path: PathBuf,
    },
    /// The current Windows account SID could not be resolved.
    #[error("unable to resolve the current Windows account SID")]
    CurrentAccountUnavailable,
    /// A native ACL operation failed.
    #[error("Windows ACL operation {operation} failed with status {code}")]
    WindowsAcl {
        /// Failed operation.
        operation: &'static str,
        /// Win32 status code.
        code: u32,
    },
    /// An ACL wrapper reported success without applying the change.
    #[error("Windows ACL operation {operation} did not apply the requested change")]
    WindowsAclIncomplete {
        /// Incomplete operation.
        operation: &'static str,
    },
    /// The identity file has access beyond the exact Stella policy.
    #[error("node identity file {path} has insecure permissions: {reason}")]
    InsecurePermissions {
        /// Rejected path.
        path: PathBuf,
        /// Stable non-secret reason.
        reason: &'static str,
    },
    /// The bounded PKCS#8 input size was exceeded.
    #[error("node identity file {path} has {actual} bytes, exceeding maximum {maximum}")]
    TooLarge {
        /// Rejected path.
        path: PathBuf,
        /// Observed bytes.
        actual: u64,
        /// Maximum accepted bytes.
        maximum: usize,
    },
    /// A file length could not be represented safely.
    #[error("node identity length cannot be represented safely")]
    LengthConversion,
    /// Secret bytes could not be read.
    #[error("unable to read node identity file {path}")]
    Read {
        /// Identity path.
        path: PathBuf,
        /// Underlying filesystem error.
        #[source]
        source: io::Error,
    },
    /// Secret bytes could not be written.
    #[error("unable to write node identity file {path}")]
    Write {
        /// Identity path.
        path: PathBuf,
        /// Underlying filesystem error.
        #[source]
        source: io::Error,
    },
    /// The new identity could not be durably synchronized.
    #[error("unable to sync node identity file {path}")]
    Sync {
        /// Identity path.
        path: PathBuf,
        /// Underlying filesystem error.
        #[source]
        source: io::Error,
    },
    /// A partial newly created file could not be removed.
    #[error("unable to remove partial node identity file {path} after {cause}")]
    CleanupFailed {
        /// Partial path.
        path: PathBuf,
        /// Original failure.
        cause: Box<NodeIdentityFileError>,
        /// Cleanup failure.
        #[source]
        source: io::Error,
    },
    /// Key generation or PKCS#8 processing failed.
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

    use super::{cleanup_created_file, NodeIdentityFileError};

    const GENERIC_READ: u32 = 0x8000_0000;
    const GENERIC_WRITE: u32 = 0x4000_0000;
    const READ_CONTROL: u32 = 0x0002_0000;
    const WRITE_DAC: u32 = 0x0004_0000;
    const FILE_ALL_ACCESS: u32 = 0x001f_01ff;
    const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0000_0400;
    const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
    const LOCAL_SYSTEM_SID: &str = "S-1-5-18";

    pub(super) fn create_secure_file(path: &Path) -> Result<File, NodeIdentityFileError> {
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .access_mode(GENERIC_READ | GENERIC_WRITE | READ_CONTROL | WRITE_DAC)
            .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
            .open(path)
            .map_err(|source| NodeIdentityFileError::Create {
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

    pub(super) fn open_verified_file(path: &Path) -> Result<File, NodeIdentityFileError> {
        let file = OpenOptions::new()
            .read(true)
            .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
            .open(path)
            .map_err(|source| NodeIdentityFileError::Open {
                path: path.to_path_buf(),
                source,
            })?;
        validate_file_kind(&file, path)?;
        verify_permissions(&file, path)?;
        Ok(file)
    }

    fn validate_file_kind(file: &File, path: &Path) -> Result<(), NodeIdentityFileError> {
        let metadata = file
            .metadata()
            .map_err(|source| NodeIdentityFileError::Metadata {
                path: path.to_path_buf(),
                source,
            })?;
        if !metadata.is_file() {
            return Err(NodeIdentityFileError::NotRegularFile {
                path: path.to_path_buf(),
            });
        }
        if metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
            return Err(NodeIdentityFileError::ReparsePoint {
                path: path.to_path_buf(),
            });
        }
        Ok(())
    }

    fn harden_permissions(file: &File, path: &Path) -> Result<(), NodeIdentityFileError> {
        let mut acl = open_acl(file)?;
        let entries = acl
            .all()
            .map_err(|code| NodeIdentityFileError::WindowsAcl {
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
            let sid =
                string_to_sid(&sid_string).map_err(|code| NodeIdentityFileError::WindowsAcl {
                    operation: "decode existing SID",
                    code,
                })?;
            let removed = acl
                .remove(sid.as_ptr().cast_mut().cast(), None, None)
                .map_err(|code| NodeIdentityFileError::WindowsAcl {
                    operation: "remove existing entry",
                    code,
                })?;
            if removed == 0 {
                return Err(NodeIdentityFileError::WindowsAclIncomplete {
                    operation: "remove existing entry",
                });
            }
        }
        for sid in required_principals()?.into_values() {
            let applied = acl
                .allow(sid.as_ptr().cast_mut().cast(), false, FILE_ALL_ACCESS)
                .map_err(|code| NodeIdentityFileError::WindowsAcl {
                    operation: "grant required principal",
                    code,
                })?;
            if !applied {
                return Err(NodeIdentityFileError::WindowsAclIncomplete {
                    operation: "grant required principal",
                });
            }
        }
        Ok(())
    }

    fn verify_permissions(file: &File, path: &Path) -> Result<(), NodeIdentityFileError> {
        let acl = open_acl(file)?;
        let entries = acl
            .all()
            .map_err(|code| NodeIdentityFileError::WindowsAcl {
                operation: "enumerate",
                code,
            })?;
        let required = required_principals()?;
        let expected = required.keys().map(String::as_str).collect::<BTreeSet<_>>();
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

    fn open_acl(file: &File) -> Result<ACL, NodeIdentityFileError> {
        ACL::from_file_handle(file.as_raw_handle().cast(), false).map_err(|code| {
            NodeIdentityFileError::WindowsAcl {
                operation: "open security descriptor",
                code,
            }
        })
    }

    fn required_principals() -> Result<BTreeMap<String, Vec<u8>>, NodeIdentityFileError> {
        let account = current_user().ok_or(NodeIdentityFileError::CurrentAccountUnavailable)?;
        let user_sid =
            name_to_sid(&account, None).map_err(|code| NodeIdentityFileError::WindowsAcl {
                operation: "resolve current account",
                code,
            })?;
        let user_string = sid_to_string(user_sid.as_ptr().cast_mut().cast()).map_err(|code| {
            NodeIdentityFileError::WindowsAcl {
                operation: "format current account SID",
                code,
            }
        })?;
        let system_sid =
            string_to_sid(LOCAL_SYSTEM_SID).map_err(|code| NodeIdentityFileError::WindowsAcl {
                operation: "decode LocalSystem SID",
                code,
            })?;
        let system_string =
            sid_to_string(system_sid.as_ptr().cast_mut().cast()).map_err(|code| {
                NodeIdentityFileError::WindowsAcl {
                    operation: "format LocalSystem SID",
                    code,
                }
            })?;
        let mut principals = BTreeMap::new();
        principals.insert(user_string, user_sid);
        principals.insert(system_string, system_sid);
        Ok(principals)
    }

    fn insecure(path: &Path, reason: &'static str) -> NodeIdentityFileError {
        NodeIdentityFileError::InsecurePermissions {
            path: path.to_path_buf(),
            reason,
        }
    }

    #[cfg(test)]
    pub(super) fn grant_everyone_for_test(path: &Path) -> Result<(), NodeIdentityFileError> {
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .access_mode(GENERIC_READ | GENERIC_WRITE | READ_CONTROL | WRITE_DAC)
            .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
            .open(path)
            .map_err(|source| NodeIdentityFileError::Open {
                path: path.to_path_buf(),
                source,
            })?;
        let mut acl = open_acl(&file)?;
        let sid = string_to_sid("S-1-1-0").map_err(|code| NodeIdentityFileError::WindowsAcl {
            operation: "decode Everyone SID",
            code,
        })?;
        acl.allow(sid.as_ptr().cast_mut().cast(), false, FILE_ALL_ACCESS)
            .map_err(|code| NodeIdentityFileError::WindowsAcl {
                operation: "grant Everyone for test",
                code,
            })?;
        Ok(())
    }
}

#[cfg(not(windows))]
mod platform {
    use std::{fs::File, path::Path};

    use super::NodeIdentityFileError;

    pub(super) fn create_secure_file(_path: &Path) -> Result<File, NodeIdentityFileError> {
        Err(NodeIdentityFileError::UnsupportedPlatform)
    }

    pub(super) fn open_verified_file(_path: &Path) -> Result<File, NodeIdentityFileError> {
        Err(NodeIdentityFileError::UnsupportedPlatform)
    }
}

#[cfg(test)]
mod tests {
    use std::{
        path::PathBuf,
        sync::atomic::{AtomicU64, Ordering},
    };

    #[cfg(windows)]
    use std::{fs::OpenOptions, io::Write};

    use stella_crypto::MAX_IDENTITY_PKCS8_LENGTH;

    use super::{
        create_node_identity, load_node_identity, verify_node_identity_permissions,
        NodeIdentityFileError,
    };

    static TEMP_SEQUENCE: AtomicU64 = AtomicU64::new(1);

    fn temp_directory() -> PathBuf {
        let sequence = TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        std::env::temp_dir().join(format!(
            "stella-node-identity-{}-{sequence}",
            std::process::id()
        ))
    }

    #[cfg(windows)]
    #[test]
    fn create_load_verify_and_refuse_overwrite() {
        let directory = temp_directory();
        std::fs::create_dir(&directory).expect("create test directory");
        let path = directory.join("node.pk8");
        let created = create_node_identity(&path).expect("create node identity");
        verify_node_identity_permissions(&path).expect("verify exact DACL");
        let loaded = load_node_identity(&path).expect("load node identity");
        assert_eq!(loaded.public_key(), created.public_key());
        assert!(matches!(
            create_node_identity(&path),
            Err(NodeIdentityFileError::Create { .. })
        ));
        drop(loaded);
        drop(created);
        std::fs::remove_dir_all(directory).expect("remove test directory");
    }

    #[cfg(windows)]
    #[test]
    fn malformed_oversized_and_acl_tampered_files_are_rejected() {
        let directory = temp_directory();
        std::fs::create_dir(&directory).expect("create test directory");
        let path = directory.join("node.pk8");
        let identity = create_node_identity(&path).expect("create node identity");
        drop(identity);

        overwrite(&path, &[0x30, 0x01, 0]);
        assert!(matches!(
            load_node_identity(&path),
            Err(NodeIdentityFileError::Crypto(_))
        ));
        overwrite(&path, &vec![0; MAX_IDENTITY_PKCS8_LENGTH + 1]);
        assert!(matches!(
            load_node_identity(&path),
            Err(NodeIdentityFileError::TooLarge { .. })
        ));

        let replacement_path = directory.join("replacement.pk8");
        let replacement = create_node_identity(&replacement_path).expect("create replacement");
        let document = replacement.to_pkcs8_der().expect("encode replacement");
        overwrite(&path, document.expose_secret());
        super::platform::grant_everyone_for_test(&path).expect("tamper DACL");
        assert!(matches!(
            load_node_identity(&path),
            Err(NodeIdentityFileError::InsecurePermissions { .. })
        ));
        drop(document);
        drop(replacement);
        std::fs::remove_dir_all(directory).expect("remove test directory");
    }

    #[cfg(windows)]
    fn overwrite(path: &std::path::Path, bytes: &[u8]) {
        let mut file = OpenOptions::new()
            .write(true)
            .truncate(true)
            .open(path)
            .expect("open identity for overwrite");
        file.write_all(bytes).expect("overwrite identity");
        file.sync_all().expect("sync identity");
    }

    #[cfg(not(windows))]
    #[test]
    fn unsupported_platform_creates_nothing() {
        let directory = temp_directory();
        std::fs::create_dir(&directory).expect("create test directory");
        let path = directory.join("node.pk8");
        assert!(matches!(
            create_node_identity(&path),
            Err(NodeIdentityFileError::UnsupportedPlatform)
        ));
        assert!(!path.exists());
        std::fs::remove_dir_all(directory).expect("remove test directory");
    }
}
