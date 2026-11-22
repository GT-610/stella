//! Protected persistent identity files.

use std::{
    fs::File,
    io::{self, Read, Write},
    path::{Path, PathBuf},
};

use stella_crypto::{CryptoError, IdentitySigningKey, MAX_IDENTITY_PKCS8_LENGTH};
use thiserror::Error;
use zeroize::Zeroizing;

/// Creates a new protected Ed25519 identity file.
///
/// The target is never overwritten. Windows applies a protected exact DACL;
/// Unix requires a non-linked regular file with mode `0600`. The native
/// policy is verified before secret bytes are written, and the document is
/// placed with an atomic write so a crash never leaves a partial secret at
/// the final path.
///
/// # Errors
///
/// Returns [`IdentityFileError`] for unsupported platforms, key creation,
/// an existing path, insecure permissions, write/sync, or cleanup failure.
pub fn create_identity(path: &Path) -> Result<IdentitySigningKey, IdentityFileError> {
    let signing_key = IdentitySigningKey::generate()?;
    let document = signing_key.to_pkcs8_der()?;
    write_protected_secret(path, document.expose_secret())?;
    Ok(signing_key)
}

/// Writes one complete secret file atomically under the native policy.
///
/// The destination name is first reserved with a zero-length protected
/// placeholder, the full secret is written to a private temporary sibling,
/// and the temporary file is renamed over the placeholder. A crash therefore
/// never leaves a partially written secret at the final path, and the native
/// permissions of the destination are verified both before and after the
/// swap. A failure removes only files created by this call.
///
/// # Errors
///
/// Returns [`IdentityFileError`] when the destination exists, the parent
/// directory is not writable through the native policy, or writing, syncing,
/// renaming, or final verification fails.
pub fn write_protected_secret(path: &Path, bytes: &[u8]) -> Result<(), IdentityFileError> {
    let file_name = path.file_name().ok_or_else(|| IdentityFileError::Write {
        path: path.to_path_buf(),
        source: io::Error::new(
            io::ErrorKind::InvalidInput,
            "secret destination must name a file",
        ),
    })?;
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    // Reserve the final name so a concurrent writer cannot claim it between
    // the checks and the rename.
    let placeholder = create_protected_secret_file(path)?;
    let temporary = parent.join(format!(
        ".{}.stella-{}.tmp",
        file_name.to_string_lossy(),
        std::process::id(),
    ));
    let result = write_and_swap(&temporary, path, bytes);
    match result {
        Ok(()) => {
            drop(placeholder);
            Ok(())
        }
        Err(error) => Err(cleanup_created_file(&placeholder, path, error)),
    }
}

fn write_and_swap(temporary: &Path, path: &Path, bytes: &[u8]) -> Result<(), IdentityFileError> {
    // A create-new failure never names a file created by this call, so the
    // error returns directly: removing the path here could delete another
    // writer's pre-existing file.
    let mut file = create_protected_secret_file(temporary)?;
    let identity = CreatedFileIdentity::of(&file);
    let result = (|| {
        if let Err(error) = file.write_all(bytes) {
            return Err(IdentityFileError::Write {
                path: temporary.to_path_buf(),
                source: error,
            });
        }
        if let Err(error) = file.sync_all() {
            return Err(IdentityFileError::Sync {
                path: temporary.to_path_buf(),
                source: error,
            });
        }
        drop(file);
        std::fs::rename(temporary, path).map_err(|source| IdentityFileError::Rename {
            path: path.to_path_buf(),
            source,
        })?;
        #[cfg(unix)]
        if let Ok(directory) = std::fs::File::open(
            path.parent()
                .filter(|parent| !parent.as_os_str().is_empty())
                .unwrap_or_else(|| Path::new(".")),
        ) {
            // Best-effort directory sync so the rename survives a power loss.
            let _ = directory.sync_all();
        }
        // The swapped-in destination must still satisfy the native policy.
        drop(open_protected_secret_file(path)?);
        Ok(())
    })();
    match result {
        Ok(()) => Ok(()),
        Err(error) => Err(cleanup_swap_failure(&identity, temporary, path, error)),
    }
}

/// Cleans up a failed swap while only removing files this call created.
///
/// Before the rename the temporary names the freshly created file; after the
/// rename that identity belongs to the destination. Removing the temporary
/// first and then, when the rename already happened, the destination keeps
/// every removal bound to the created identity, so a concurrently replaced
/// path is never deleted.
fn cleanup_swap_failure(
    identity: &CreatedFileIdentity,
    temporary: &Path,
    path: &Path,
    cause: IdentityFileError,
) -> IdentityFileError {
    if identity.path_matches(temporary) {
        return cleanup_created_identity(identity, temporary, cause);
    }
    if identity.path_matches(path) {
        return cleanup_created_identity(identity, path, cause);
    }
    cause
}

/// Loads a protected bounded PKCS#8 identity.
///
/// Native permissions and file kind are verified before any secret bytes are
/// read. The bounded input buffer is zeroized on drop.
///
/// # Errors
///
/// Returns [`IdentityFileError`] for native security, metadata, size,
/// read, or PKCS#8 decoding failure.
pub fn load_identity(path: &Path) -> Result<IdentitySigningKey, IdentityFileError> {
    let mut file = open_protected_secret_file(path)?;
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

/// Creates a new secret file with verified native permissions before writing.
///
/// # Errors
/// Returns an error for an existing path or an insecure native file policy.
pub fn create_protected_secret_file(path: &Path) -> Result<File, IdentityFileError> {
    platform::create_secure_file(path)
}

/// Opens a secret file only after verifying native permissions and file kind.
///
/// # Errors
/// Returns an error for missing, linked, non-regular, or insecure files.
pub fn open_protected_secret_file(path: &Path) -> Result<File, IdentityFileError> {
    platform::open_verified_file(path)
}

/// Opens a secret file for reading and writing after verifying the native
/// permissions and file kind.
///
/// Update-capable handles exist for callers that must flush recent writes;
/// on Windows `sync_all` needs write access on the handle. The policy
/// verification is identical to [`open_protected_secret_file`].
///
/// # Errors
/// Returns an error for missing, linked, non-regular, or insecure files.
pub fn open_protected_secret_file_for_update(path: &Path) -> Result<File, IdentityFileError> {
    platform::open_verified_file_for_update(path)
}

/// Identity of a file created by this process, used to bind failure cleanup.
///
/// On Unix the identity is the device and inode pair, so cleanup never
/// deletes a path that was concurrently replaced by another writer.
#[cfg(unix)]
struct CreatedFileIdentity {
    device: u64,
    inode: u64,
}

#[cfg(unix)]
impl CreatedFileIdentity {
    fn of(file: &File) -> Self {
        use std::os::unix::fs::MetadataExt;
        match file.metadata() {
            Ok(metadata) => Self {
                device: metadata.dev(),
                inode: metadata.ino(),
            },
            // An unidentifiable file is never matched again, so cleanup
            // fails closed and keeps the path in place.
            Err(_) => Self {
                device: u64::MAX,
                inode: u64::MAX,
            },
        }
    }

    fn path_matches(&self, path: &Path) -> bool {
        use std::os::unix::fs::MetadataExt;
        match std::fs::symlink_metadata(path) {
            Ok(metadata) => metadata.dev() == self.device && metadata.ino() == self.inode,
            Err(_) => false,
        }
    }
}

/// Windows file identity: the volume serial number and file index pair.
///
/// The identity is captured from the creating handle and compared against a
/// fresh no-reparse-point open of the path, so cleanup never deletes a path
/// that was concurrently replaced by another writer. Both values come from
/// the stable `GetFileInformationByHandle` binding: the std metadata
/// accessors for these fields still require the unstable
/// `windows_by_handle` feature. Windows does not guarantee unique file
/// indexes on every file system, but the comparison only ever authorizes
/// removal of a file this process just created, and every failure mode
/// fails closed.
#[cfg(windows)]
struct CreatedFileIdentity {
    volume_serial: Option<u32>,
    file_index: Option<u64>,
}

#[cfg(windows)]
impl CreatedFileIdentity {
    fn of(file: &File) -> Self {
        let (volume_serial, file_index) = native_file_identity(file);
        Self {
            volume_serial,
            file_index,
        }
    }

    fn path_matches(&self, path: &Path) -> bool {
        use std::fs::OpenOptions;
        use std::os::windows::fs::OpenOptionsExt;
        // Fail closed: an unidentifiable creation must never authorize
        // removing the path.
        let (Some(created_volume), Some(created_index)) = (self.volume_serial, self.file_index)
        else {
            return false;
        };
        // The reparse-point open does not follow links, so a replacement
        // junction or symlink is compared against its own identity and
        // never matches the created file.
        let file = OpenOptions::new()
            .read(true)
            .custom_flags(platform::FILE_FLAG_OPEN_REPARSE_POINT)
            .open(path);
        let Ok(file) = file else {
            return false;
        };
        match native_file_identity(&file) {
            (Some(volume), Some(index)) => volume == created_volume && index == created_index,
            _ => false,
        }
    }
}

/// Reads the native volume and file-index identity of an open handle.
///
/// Returns `None` components when the native query fails, which keeps every
/// comparison fail closed.
#[cfg(windows)]
#[allow(unsafe_code)]
fn native_file_identity(file: &File) -> (Option<u32>, Option<u64>) {
    use std::os::windows::io::AsRawHandle;
    use winapi::ctypes::c_void;
    use winapi::um::fileapi::{GetFileInformationByHandle, BY_HANDLE_FILE_INFORMATION};
    // SAFETY: the handle belongs to a live `File` and the pointer names a
    // `BY_HANDLE_FILE_INFORMATION` value of exactly the type the API fills.
    let mut information: BY_HANDLE_FILE_INFORMATION = unsafe { std::mem::zeroed() };
    // The std raw handle is typed against std::ffi::c_void while this winapi
    // binding expects winapi::ctypes::c_void. Both are one-byte-aligned void
    // pointer representations of the same kernel handle value, so the cast
    // only adjusts the pointer type.
    let handle = file.as_raw_handle().cast::<c_void>();
    // SAFETY: `GetFileInformationByHandle` reads the handle and writes the
    // structure; both arguments are valid for the duration of the call.
    let succeeded = unsafe { GetFileInformationByHandle(handle, &raw mut information) };
    if succeeded == 0 {
        return (None, None);
    }
    let file_index =
        (u64::from(information.nFileIndexHigh) << 32) | u64::from(information.nFileIndexLow);
    (Some(information.dwVolumeSerialNumber), Some(file_index))
}

/// Placeholder identity for platforms with no secure file backend.
///
/// Every creation and open path returns [`IdentityFileError::UnsupportedPlatform`]
/// there, so identity checks are unreachable; the type keeps the cleanup
/// helpers uniform across platform configurations.
#[cfg(not(any(windows, unix)))]
struct CreatedFileIdentity(());

#[cfg(not(any(windows, unix)))]
impl CreatedFileIdentity {
    fn of(_file: &File) -> Self {
        Self(())
    }

    fn path_matches(&self, _path: &Path) -> bool {
        // Unreachable on unsupported platforms; the field keeps this stub
        // shaped like the real backends.
        self.0;
        true
    }
}

/// Removes a file this process created, but only if the path still names it.
///
/// The cleanup is bound to the creating file's identity (device and inode on
/// Unix) so a concurrent replacement of the path cannot make the cleanup
/// delete another principal's file.
fn cleanup_created_file(file: &File, path: &Path, cause: IdentityFileError) -> IdentityFileError {
    cleanup_created_identity(&CreatedFileIdentity::of(file), path, cause)
}

/// Removes a path only while it still names the given created file.
fn cleanup_created_identity(
    identity: &CreatedFileIdentity,
    path: &Path,
    cause: IdentityFileError,
) -> IdentityFileError {
    if !identity.path_matches(path) {
        return cause;
    }
    match std::fs::remove_file(path) {
        // A concurrently removed path is already clean; the original cause is
        // what the caller needs to see.
        Ok(()) => cause,
        Err(error) if error.kind() == io::ErrorKind::NotFound => cause,
        Err(source) => IdentityFileError::CleanupFailed {
            path: path.to_path_buf(),
            cause: Box::new(cause),
            source,
        },
    }
}

/// Identity persistence or native-permission failure.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum IdentityFileError {
    /// This build has no secure native file backend.
    #[error("secure identity files are unsupported on this platform")]
    UnsupportedPlatform,
    /// A create-new identity file could not be opened.
    #[error("unable to create new identity file {path}")]
    Create {
        /// Requested path.
        path: PathBuf,
        /// Underlying filesystem error.
        #[source]
        source: io::Error,
    },
    /// An existing identity file could not be opened.
    #[error("unable to open identity file {path}")]
    Open {
        /// Requested path.
        path: PathBuf,
        /// Underlying filesystem error.
        #[source]
        source: io::Error,
    },
    /// File metadata could not be inspected.
    #[error("unable to inspect identity file {path}")]
    Metadata {
        /// Inspected path.
        path: PathBuf,
        /// Underlying filesystem error.
        #[source]
        source: io::Error,
    },
    /// The identity path is not a regular file.
    #[error("identity path {path} is not a regular file")]
    NotRegularFile {
        /// Rejected path.
        path: PathBuf,
    },
    /// The identity path is a Windows reparse point.
    #[error("identity path {path} is a reparse point")]
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
    #[error("identity file {path} has insecure permissions: {reason}")]
    InsecurePermissions {
        /// Rejected path.
        path: PathBuf,
        /// Stable non-secret reason.
        reason: &'static str,
    },
    /// The bounded PKCS#8 input size was exceeded.
    #[error("identity file {path} has {actual} bytes, exceeding maximum {maximum}")]
    TooLarge {
        /// Rejected path.
        path: PathBuf,
        /// Observed bytes.
        actual: u64,
        /// Maximum accepted bytes.
        maximum: usize,
    },
    /// A file length could not be represented safely.
    #[error("identity length cannot be represented safely")]
    LengthConversion,
    /// Secret bytes could not be read.
    #[error("unable to read identity file {path}")]
    Read {
        /// Identity path.
        path: PathBuf,
        /// Underlying filesystem error.
        #[source]
        source: io::Error,
    },
    /// Secret bytes could not be written.
    #[error("unable to write identity file {path}")]
    Write {
        /// Identity path.
        path: PathBuf,
        /// Underlying filesystem error.
        #[source]
        source: io::Error,
    },
    /// The new identity could not be durably synchronized.
    #[error("unable to sync identity file {path}")]
    Sync {
        /// Identity path.
        path: PathBuf,
        /// Underlying filesystem error.
        #[source]
        source: io::Error,
    },
    /// The complete secret could not be swapped into place atomically.
    #[error("unable to move the completed secret into {path}")]
    Rename {
        /// Identity path.
        path: PathBuf,
        /// Underlying filesystem error.
        #[source]
        source: io::Error,
    },
    /// A partial newly created file could not be removed.
    #[error("unable to remove partial identity file {path} after {cause}")]
    CleanupFailed {
        /// Partial path.
        path: PathBuf,
        /// Original failure.
        cause: Box<IdentityFileError>,
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

    use super::{cleanup_created_file, IdentityFileError};

    const GENERIC_READ: u32 = 0x8000_0000;
    const GENERIC_WRITE: u32 = 0x4000_0000;
    const READ_CONTROL: u32 = 0x0002_0000;
    const WRITE_DAC: u32 = 0x0004_0000;
    const FILE_ALL_ACCESS: u32 = 0x001f_01ff;
    const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0000_0400;
    pub(super) const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
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
            return Err(cleanup_created_file(&file, path, error));
        }
        Ok(file)
    }

    pub(super) fn open_verified_file(path: &Path) -> Result<File, IdentityFileError> {
        let file = OpenOptions::new()
            .read(true)
            .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
            .open(path)
            .map_err(|source| IdentityFileError::Open {
                path: path.to_path_buf(),
                source,
            })?;
        validate_file_kind(&file, path)?;
        verify_permissions(&file, path)?;
        Ok(file)
    }

    pub(super) fn open_verified_file_for_update(path: &Path) -> Result<File, IdentityFileError> {
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
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
    #[cfg(test)]
    use std::process::Command;
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
            return Err(cleanup_created_file(&file, path, error));
        }
        Ok(file)
    }

    pub(super) fn open_verified_file(path: &Path) -> Result<File, IdentityFileError> {
        let file = OpenOptions::new()
            .read(true)
            // O_NOFOLLOW rejects links; O_NONBLOCK keeps a FIFO at the path
            // from blocking the open before the regular-file check runs.
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
            .open(path)
            .map_err(|source| IdentityFileError::Open {
                path: path.to_path_buf(),
                source,
            })?;
        validate_file(&file, path)?;
        Ok(file)
    }

    pub(super) fn open_verified_file_for_update(path: &Path) -> Result<File, IdentityFileError> {
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
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
        validate_extended_acl(file, path, metadata.uid())?;
        Ok(())
    }

    fn validate_extended_acl(
        file: &File,
        path: &Path,
        owner_uid: u32,
    ) -> Result<(), IdentityFileError> {
        let grants_non_owner_access = crate::extended_acl_grants_non_owner_access(file, owner_uid)
            .map_err(|source| IdentityFileError::Metadata {
                path: path.to_path_buf(),
                source,
            })?;
        if grants_non_owner_access {
            return Err(IdentityFileError::InsecurePermissions {
                path: path.to_path_buf(),
                reason: "an extended ACL grants access to a non-owner principal",
            });
        }
        Ok(())
    }

    #[cfg(test)]
    fn install_test_acl(path: &Path, acl: &str) -> Result<(), IdentityFileError> {
        let status = Command::new("/bin/chmod")
            .args(["+a", acl])
            .arg(path)
            .status()
            .map_err(|source| IdentityFileError::Metadata {
                path: path.to_path_buf(),
                source,
            })?;
        if status.success() {
            Ok(())
        } else {
            Err(IdentityFileError::Metadata {
                path: path.to_path_buf(),
                source: std::io::Error::other("chmod could not install the test ACL"),
            })
        }
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

    #[cfg(test)]
    pub(super) fn grant_inherited_everyone_for_test(path: &Path) -> Result<(), IdentityFileError> {
        install_test_acl(path, "everyone allow read,file_inherit")
    }
}

#[cfg(all(unix, not(target_os = "macos")))]
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
            return Err(cleanup_created_file(&file, path, error));
        }
        Ok(file)
    }

    pub(super) fn open_verified_file(path: &Path) -> Result<File, IdentityFileError> {
        let file = OpenOptions::new()
            .read(true)
            // O_NOFOLLOW rejects links; O_NONBLOCK keeps a FIFO at the path
            // from blocking the open before the regular-file check runs.
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
            .open(path)
            .map_err(|source| IdentityFileError::Open {
                path: path.to_path_buf(),
                source,
            })?;
        validate_file(&file, path)?;
        Ok(file)
    }

    pub(super) fn open_verified_file_for_update(path: &Path) -> Result<File, IdentityFileError> {
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
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
        // Linux has no portable extended-ACL probe without extra crate
        // dependencies; exact owner-only mode bits and hard-link rejection
        // form the native policy.
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

#[cfg(not(any(windows, unix)))]
mod platform {
    use std::{fs::File, path::Path};

    use super::IdentityFileError;

    pub(super) fn create_secure_file(_path: &Path) -> Result<File, IdentityFileError> {
        Err(IdentityFileError::UnsupportedPlatform)
    }

    pub(super) fn open_verified_file(_path: &Path) -> Result<File, IdentityFileError> {
        Err(IdentityFileError::UnsupportedPlatform)
    }

    pub(super) fn open_verified_file_for_update(_path: &Path) -> Result<File, IdentityFileError> {
        Err(IdentityFileError::UnsupportedPlatform)
    }
}

#[cfg(test)]
mod tests {
    use std::{
        path::PathBuf,
        sync::atomic::{AtomicU64, Ordering},
    };

    #[cfg(any(windows, unix))]
    use std::{fs::OpenOptions, io::Write};

    #[cfg(any(windows, unix))]
    use stella_crypto::MAX_IDENTITY_PKCS8_LENGTH;

    #[cfg(any(windows, unix))]
    use super::load_identity;
    use super::{create_identity, IdentityFileError};

    static TEMP_SEQUENCE: AtomicU64 = AtomicU64::new(1);

    fn temp_directory() -> PathBuf {
        let sequence = TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        std::env::temp_dir().join(format!(
            "stella-node-identity-{}-{sequence}",
            std::process::id()
        ))
    }

    #[cfg(any(windows, unix))]
    #[test]
    fn create_load_verify_and_refuse_overwrite() {
        let directory = temp_directory();
        std::fs::create_dir(&directory).expect("create test directory");
        let path = directory.join("node.pk8");
        let created = create_identity(&path).expect("create identity");
        let loaded = load_identity(&path).expect("load identity");
        assert_eq!(loaded.public_key(), created.public_key());
        assert!(matches!(
            create_identity(&path),
            Err(IdentityFileError::Create { .. })
        ));
        drop(loaded);
        drop(created);
        std::fs::remove_dir_all(directory).expect("remove test directory");
    }

    #[cfg(any(windows, unix))]
    #[test]
    fn malformed_oversized_and_permission_tampered_files_are_rejected() {
        let directory = temp_directory();
        std::fs::create_dir(&directory).expect("create test directory");
        let path = directory.join("node.pk8");
        let identity = create_identity(&path).expect("create identity");
        drop(identity);

        overwrite(&path, &[0x30, 0x01, 0]);
        assert!(matches!(
            load_identity(&path),
            Err(IdentityFileError::Crypto(_))
        ));
        overwrite(&path, &vec![0; MAX_IDENTITY_PKCS8_LENGTH + 1]);
        assert!(matches!(
            load_identity(&path),
            Err(IdentityFileError::TooLarge { .. })
        ));

        let replacement_path = directory.join("replacement.pk8");
        let replacement = create_identity(&replacement_path).expect("create replacement");
        let document = replacement.to_pkcs8_der().expect("encode replacement");
        overwrite(&path, document.expose_secret());
        super::platform::grant_everyone_for_test(&path).expect("tamper permissions");
        assert!(matches!(
            load_identity(&path),
            Err(IdentityFileError::InsecurePermissions { .. })
        ));
        drop(document);
        drop(replacement);
        std::fs::remove_dir_all(directory).expect("remove test directory");
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn inherited_extended_acl_is_rejected() {
        let directory = temp_directory();
        std::fs::create_dir(&directory).expect("create test directory");
        super::platform::grant_inherited_everyone_for_test(&directory)
            .expect("grant inheritable test ACL");
        let path = directory.join("node.pk8");
        assert!(matches!(
            create_identity(&path),
            Err(IdentityFileError::InsecurePermissions { .. })
        ));
        assert!(!path.exists());
        std::fs::remove_dir_all(directory).expect("remove test directory");
    }

    #[cfg(any(windows, unix))]
    fn overwrite(path: &std::path::Path, bytes: &[u8]) {
        let mut file = OpenOptions::new()
            .write(true)
            .truncate(true)
            .open(path)
            .expect("open identity for overwrite");
        file.write_all(bytes).expect("overwrite identity");
        file.sync_all().expect("sync identity");
    }

    #[cfg(not(any(windows, unix)))]
    #[test]
    fn unsupported_platform_creates_nothing() {
        let directory = temp_directory();
        std::fs::create_dir(&directory).expect("create test directory");
        let path = directory.join("node.pk8");
        assert!(matches!(
            create_identity(&path),
            Err(IdentityFileError::UnsupportedPlatform)
        ));
        assert!(!path.exists());
        std::fs::remove_dir_all(directory).expect("remove test directory");
    }
}
