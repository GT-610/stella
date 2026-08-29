//! Safe TAP device abstraction and platform backends.

#![deny(unsafe_op_in_unsafe_fn)]

use std::{error::Error, fmt, io};

/// Configuration used to create a TAP device.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TapConfig {
    /// Optional preferred adapter name or platform identifier.
    pub name: Option<String>,
    /// Requested Ethernet MTU.
    pub mtu: u16,
}

impl Default for TapConfig {
    fn default() -> Self {
        Self {
            name: None,
            mtu: 1_500,
        }
    }
}

/// Error returned by TAP device operations.
#[derive(Debug)]
pub enum TapError {
    /// The requested operation is not implemented on the current platform.
    UnsupportedPlatform(&'static str),
    /// The requested configuration is invalid.
    InvalidConfig(&'static str),
    /// An operating-system I/O operation failed.
    Io(io::Error),
}

impl fmt::Display for TapError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnsupportedPlatform(platform) => {
                write!(formatter, "TAP is not implemented for {platform}")
            }
            Self::InvalidConfig(reason) => write!(formatter, "invalid TAP configuration: {reason}"),
            Self::Io(error) => write!(formatter, "TAP I/O failed: {error}"),
        }
    }
}

impl Error for TapError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Io(error) => Some(error),
            Self::UnsupportedPlatform(_) | Self::InvalidConfig(_) => None,
        }
    }
}

impl From<io::Error> for TapError {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

/// Result type for TAP operations.
pub type Result<T> = std::result::Result<T, TapError>;

/// Common lifecycle and frame I/O contract implemented by platform TAP devices.
pub trait TapDevice: Send + 'static {
    /// Creates and configures a TAP device.
    ///
    /// # Errors
    ///
    /// Returns an error when the configuration is invalid, the platform is
    /// unsupported, or the operating system cannot create the adapter.
    fn create(config: &TapConfig) -> Result<Self>
    where
        Self: Sized;

    /// Reads one complete Ethernet frame into `buf`.
    ///
    /// # Errors
    ///
    /// Returns an error when the buffer cannot hold a valid frame or the
    /// operating-system read fails.
    fn read_frame(&mut self, buf: &mut [u8]) -> Result<usize>;

    /// Writes one complete Ethernet frame.
    ///
    /// # Errors
    ///
    /// Returns an error when `frame` is invalid for the adapter or the
    /// operating-system write fails.
    fn write_frame(&mut self, frame: &[u8]) -> Result<()>;

    /// Returns the adapter MAC address.
    ///
    /// # Errors
    ///
    /// Returns an error when the address cannot be queried from the operating
    /// system.
    fn mac_address(&self) -> Result<[u8; 6]>;

    /// Sets the adapter Ethernet MTU.
    ///
    /// # Errors
    ///
    /// Returns an error when the MTU is invalid or cannot be applied.
    fn set_mtu(&mut self, mtu: u16) -> Result<()>;

    /// Destroys or releases the TAP device.
    ///
    /// # Errors
    ///
    /// Returns an error when the platform cannot complete device cleanup.
    fn destroy(self) -> Result<()>;
}

#[cfg(test)]
mod tests {
    use super::TapConfig;

    #[test]
    fn default_config_uses_standard_ethernet_mtu() {
        assert_eq!(TapConfig::default().mtu, 1_500);
    }
}
