//! Privilege-separated macOS TAP client and helper service.

mod protocol;
mod proxy;
mod server;

pub use proxy::{MacosTapProxyCancellation, MacosTapProxyDevice};
pub use server::{run_macos_tap_helper, MacosTapHelperConfig};

/// Default Unix socket used by the root helper and unprivileged client.
pub const DEFAULT_MACOS_HELPER_SOCKET: &str = "/var/run/stella-tap-helper.sock";
