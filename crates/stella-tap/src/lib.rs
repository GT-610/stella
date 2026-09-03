//! Safe complete-frame TAP contracts and platform backends.

#![deny(unsafe_op_in_unsafe_fn)]

mod config;
mod error;
#[cfg(target_os = "macos")]
mod macos;
#[cfg(target_os = "windows")]
mod windows;

use std::sync::Arc;

pub use config::{
    TapConfig, DEFAULT_MAX_FRAME_SIZE, DEFAULT_TAP_MTU, MAX_ETHERNET_FRAME_LENGTH, MAX_TAP_MTU,
    MIN_ETHERNET_FRAME_LENGTH, MIN_TAP_MTU,
};
pub use error::{AddressFamily, TapError, TapOperation};
#[cfg(target_os = "macos")]
pub use macos::{MacosTapCancellation, MacosTapDevice};
#[cfg(target_os = "windows")]
pub use windows::{
    WindowsTapAdapter, WindowsTapCancellation, WindowsTapDevice, WindowsTapDriverVersion,
};

/// Native TAP implementation selected for this Windows build.
#[cfg(target_os = "windows")]
pub type PlatformTapDevice = WindowsTapDevice;

/// Native TAP implementation selected for this macOS build.
#[cfg(target_os = "macos")]
pub type PlatformTapDevice = MacosTapDevice;

/// Result type returned by TAP operations.
pub type Result<T> = std::result::Result<T, TapError>;

/// Thread-safe control surface for interrupting pending TAP I/O.
pub trait TapCancellation: Send + Sync + 'static {
    /// Cancels reads and writes currently pending on the associated device.
    ///
    /// Cancellation is idempotent. Calling it when no operation is pending is
    /// successful.
    ///
    /// # Errors
    ///
    /// Returns an operating-system error when cancellation cannot be requested.
    fn cancel_pending_io(&self) -> Result<()>;
}

/// Shared cancellation control that can be moved to a shutdown coordinator.
pub type TapCancellationHandle = Arc<dyn TapCancellation>;

/// Common lifecycle and complete-frame I/O contract for platform TAP devices.
pub trait TapDevice: Send + 'static {
    /// Creates and configures a TAP device.
    ///
    /// # Errors
    ///
    /// Returns an error when the configuration is invalid, the platform is
    /// unsupported, or the operating system cannot open and configure an
    /// adapter.
    fn create(config: &TapConfig) -> Result<Self>
    where
        Self: Sized;

    /// Returns a handle that can cancel I/O while another thread owns `self`.
    #[must_use]
    fn cancellation_handle(&self) -> TapCancellationHandle;

    /// Reads one complete Ethernet frame into `buf`.
    ///
    /// `buf` must hold the configured maximum frame size. No frame prefix is
    /// exposed when the buffer or operating-system read fails.
    ///
    /// # Errors
    ///
    /// Returns a typed buffer, cancellation, lifecycle, or operating-system
    /// error.
    fn read_frame(&mut self, buf: &mut [u8]) -> Result<usize>;

    /// Writes one complete Ethernet frame in one operating-system operation.
    ///
    /// # Errors
    ///
    /// Returns an error when `frame` is outside the configured bounds, the I/O
    /// is cancelled, or the operating-system write fails.
    fn write_frame(&mut self, frame: &[u8]) -> Result<()>;

    /// Returns the adapter MAC address.
    ///
    /// # Errors
    ///
    /// Returns an error when the address cannot be queried from the operating
    /// system or the device has been closed.
    fn mac_address(&self) -> Result<[u8; 6]>;

    /// Sets the operating-system Layer-3 MTU within the driver ceiling.
    ///
    /// # Errors
    ///
    /// Returns an error when the MTU is invalid, exceeds the driver ceiling,
    /// or cannot be applied atomically.
    fn set_mtu(&mut self, mtu: u16) -> Result<()>;

    /// Sets media disconnected and releases the TAP device.
    ///
    /// # Errors
    ///
    /// Returns an error when the platform cannot complete device cleanup.
    fn destroy(self) -> Result<()>;
}
