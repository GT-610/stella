//! Narrow native identity-file security checks shared by Stella binaries.

#![deny(unsafe_code)]

#[cfg(target_os = "macos")]
#[allow(unsafe_code)]
mod macos;

#[cfg(target_os = "macos")]
pub use macos::extended_acl_grants_non_owner_access;
