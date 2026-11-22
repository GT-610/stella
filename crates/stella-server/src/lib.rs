//! Self-hosted Stella control-plane server implementation.

#![forbid(unsafe_code)]

/// Creates a test fixture directory with owner-only permissions.
///
/// The authority store rejects state paths whose ancestor directories are
/// group or world writable, so fixtures must not depend on the ambient
/// umask: with `umask 0002` a plain `create_dir` yields `0775`. The umask
/// can only remove bits, so the explicit `0700` is stable on every host.
#[cfg(test)]
pub(crate) fn create_owner_only_directory(path: &std::path::Path) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        std::fs::DirBuilder::new()
            .mode(0o700)
            .create(path)
            .expect("create test directory");
    }
    #[cfg(not(unix))]
    std::fs::create_dir(path).expect("create test directory");
}

pub mod active;
pub mod authority;
pub mod authorization;
pub mod bootstrap;
pub mod config;
mod connectivity_config;
pub mod identity;
pub mod network_state;
pub mod relay_credentials;
pub mod runtime;
pub mod session;
pub mod store;
pub mod tls;
pub mod turn_auth;
pub mod turn_relay;
