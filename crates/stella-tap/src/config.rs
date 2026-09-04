//! Platform-independent TAP configuration bounds.

use crate::{Result, TapError};

/// Smallest complete Ethernet frame Stella can carry.
pub const MIN_ETHERNET_FRAME_LENGTH: u16 = 14;

/// Protocol hard limit for one complete Ethernet frame.
pub const MAX_ETHERNET_FRAME_LENGTH: u16 = 9_216;

/// Smallest supported TAP Layer-3 MTU.
pub const MIN_TAP_MTU: u16 = 576;

/// Largest MTU that can fit the protocol frame ceiling plus Ethernet header.
pub const MAX_TAP_MTU: u16 = MAX_ETHERNET_FRAME_LENGTH - MIN_ETHERNET_FRAME_LENGTH;

/// Default TAP Layer-3 MTU.
pub const DEFAULT_TAP_MTU: u16 = 1_500;

/// Default complete untagged Ethernet frame limit.
pub const DEFAULT_MAX_FRAME_SIZE: u16 = DEFAULT_TAP_MTU + MIN_ETHERNET_FRAME_LENGTH;

/// Configuration used to open and constrain a TAP device.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TapConfig {
    /// Platform TAP selector or host-visible interface name.
    pub name: Option<String>,
    /// Optional platform peer interface name used for packet I/O.
    pub peer_name: Option<String>,
    /// Requested Layer-3 MTU.
    pub mtu: u16,
    /// Largest complete Ethernet frame accepted from or written to the device.
    pub max_frame_size: u16,
}

impl TapConfig {
    /// Validates platform-independent selector, MTU, and frame-size bounds.
    ///
    /// # Errors
    ///
    /// Returns [`TapError::InvalidConfig`] for an empty selector, an MTU
    /// outside the stable range, or an inconsistent complete-frame bound.
    pub fn validate(&self) -> Result<()> {
        if self
            .name
            .as_ref()
            .is_some_and(|name| name.trim().is_empty())
        {
            return Err(TapError::InvalidConfig {
                field: "name",
                reason: "must not be empty or whitespace",
            });
        }
        if self
            .peer_name
            .as_ref()
            .is_some_and(|name| name.trim().is_empty())
        {
            return Err(TapError::InvalidConfig {
                field: "peer name",
                reason: "must not be empty or whitespace",
            });
        }
        if self.name.as_deref() == self.peer_name.as_deref() && self.name.is_some() {
            return Err(TapError::InvalidConfig {
                field: "peer name",
                reason: "must differ from the host-visible interface name",
            });
        }
        if !(MIN_TAP_MTU..=MAX_TAP_MTU).contains(&self.mtu) {
            return Err(TapError::InvalidConfig {
                field: "mtu",
                reason: "must be between 576 and 9202 bytes",
            });
        }
        if !(MIN_ETHERNET_FRAME_LENGTH..=MAX_ETHERNET_FRAME_LENGTH).contains(&self.max_frame_size) {
            return Err(TapError::InvalidConfig {
                field: "maximum frame size",
                reason: "must be between 14 and 9216 bytes",
            });
        }
        let minimum_for_mtu =
            self.mtu
                .checked_add(MIN_ETHERNET_FRAME_LENGTH)
                .ok_or(TapError::InvalidConfig {
                    field: "maximum frame size",
                    reason: "MTU plus Ethernet header overflows",
                })?;
        if self.max_frame_size < minimum_for_mtu {
            return Err(TapError::InvalidConfig {
                field: "maximum frame size",
                reason: "must hold the MTU plus the 14-byte Ethernet header",
            });
        }
        Ok(())
    }

    pub(crate) fn validate_read_buffer(&self, length: usize) -> Result<()> {
        let needed = usize::from(self.max_frame_size);
        if length < needed {
            return Err(TapError::ReceiveBufferTooSmall {
                needed,
                remaining: length,
            });
        }
        Ok(())
    }

    pub(crate) fn validate_frame(&self, length: usize) -> Result<()> {
        let minimum = usize::from(MIN_ETHERNET_FRAME_LENGTH);
        let maximum = usize::from(self.max_frame_size);
        if !(minimum..=maximum).contains(&length) {
            return Err(TapError::FrameLength {
                actual: length,
                minimum,
                maximum,
            });
        }
        Ok(())
    }
}

impl Default for TapConfig {
    fn default() -> Self {
        Self {
            name: None,
            peer_name: None,
            mtu: DEFAULT_TAP_MTU,
            max_frame_size: DEFAULT_MAX_FRAME_SIZE,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{TapConfig, DEFAULT_MAX_FRAME_SIZE, DEFAULT_TAP_MTU, MAX_ETHERNET_FRAME_LENGTH};
    use crate::TapError;

    #[test]
    fn default_config_describes_standard_untagged_ethernet() {
        let config = TapConfig::default();
        assert_eq!(config.mtu, DEFAULT_TAP_MTU);
        assert_eq!(config.max_frame_size, DEFAULT_MAX_FRAME_SIZE);
        assert!(config.validate().is_ok());
    }

    #[test]
    fn config_rejects_empty_selector_and_inconsistent_bounds() {
        let empty_name = TapConfig {
            name: Some("  ".to_string()),
            ..TapConfig::default()
        };
        assert!(matches!(
            empty_name.validate(),
            Err(TapError::InvalidConfig { field: "name", .. })
        ));

        let empty_peer = TapConfig {
            peer_name: Some("  ".to_string()),
            ..TapConfig::default()
        };
        assert!(matches!(
            empty_peer.validate(),
            Err(TapError::InvalidConfig {
                field: "peer name",
                ..
            })
        ));

        let duplicate_peer = TapConfig {
            name: Some("feth100".to_string()),
            peer_name: Some("feth100".to_string()),
            ..TapConfig::default()
        };
        assert!(matches!(
            duplicate_peer.validate(),
            Err(TapError::InvalidConfig {
                field: "peer name",
                ..
            })
        ));

        let short_frame = TapConfig {
            max_frame_size: DEFAULT_TAP_MTU + 13,
            ..TapConfig::default()
        };
        assert!(matches!(
            short_frame.validate(),
            Err(TapError::InvalidConfig {
                field: "maximum frame size",
                ..
            })
        ));

        let oversized = TapConfig {
            max_frame_size: MAX_ETHERNET_FRAME_LENGTH + 1,
            ..TapConfig::default()
        };
        assert!(oversized.validate().is_err());
    }

    #[test]
    fn frame_and_receive_bounds_fail_before_platform_io() {
        let config = TapConfig::default();
        assert!(matches!(
            config.validate_read_buffer(1_513),
            Err(TapError::ReceiveBufferTooSmall {
                needed: 1_514,
                remaining: 1_513,
            })
        ));
        assert!(matches!(
            config.validate_frame(13),
            Err(TapError::FrameLength {
                actual: 13,
                minimum: 14,
                maximum: 1_514,
            })
        ));
        assert!(config.validate_frame(1_514).is_ok());
    }
}
