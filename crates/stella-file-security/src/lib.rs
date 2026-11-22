//! Narrow native identity-file security checks shared by Stella binaries.

#![deny(unsafe_code)]

#[cfg(target_os = "macos")]
#[allow(unsafe_code)]
mod macos;

#[cfg(target_os = "macos")]
pub use macos::extended_acl_grants_non_owner_access;

/// Returns this process's effective user ID.
///
/// Unix callers use it for ownership validation of security-relevant
/// directories, for example requiring that every ancestor of an authority
/// state file is owned by the running user or by root.
#[cfg(unix)]
#[allow(unsafe_code)]
#[must_use]
pub fn current_effective_uid() -> u32 {
    // SAFETY: `geteuid` has no preconditions.
    unsafe { libc::geteuid() }
}

mod identity;

pub use identity::{
    create_identity, create_protected_secret_file, load_identity, open_protected_secret_file,
    open_protected_secret_file_for_update, write_protected_secret, IdentityFileError,
};
