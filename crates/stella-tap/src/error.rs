//! Typed TAP errors without frame-bearing diagnostics.

use std::{fmt, io};

use thiserror::Error;

/// IP family whose Windows interface row is being configured.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AddressFamily {
    /// Internet Protocol version 4.
    Ipv4,
    /// Internet Protocol version 6.
    Ipv6,
}

impl fmt::Display for AddressFamily {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Ipv4 => formatter.write_str("IPv4"),
            Self::Ipv6 => formatter.write_str("IPv6"),
        }
    }
}

/// Stable operating-system operation attached to a TAP I/O error.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TapOperation {
    /// Acquiring exclusive ownership of a platform TAP pair.
    AcquireDeviceLock,
    /// Verifying that a persistent feth pair belongs to Stella.
    VerifyDeviceOwnership,
    /// Recording ownership after a feth pair is fully configured.
    RecordDeviceOwnership,
    /// Creating or reusing a platform TAP device.
    CreateDevice,
    /// Pairing two macOS fake-Ethernet interfaces.
    PairInterfaces,
    /// Configuring blocking behavior for frame I/O.
    ConfigureBlockingMode,
    /// Connecting to the privileged macOS TAP helper.
    ConnectHelper,
    /// Authenticating the process at the other end of the helper socket.
    AuthenticateHelper,
    /// Exchanging a bounded message with the privileged helper.
    ExchangeHelperMessage,
    /// Enumerating installed Windows network adapters.
    EnumerateAdapters,
    /// Opening the TAP userspace device path.
    OpenDevice,
    /// Querying the TAP driver version.
    QueryVersion,
    /// Querying the TAP driver MAC address.
    QueryMac,
    /// Querying a platform interface MTU.
    QueryMtu,
    /// Querying the TAP driver MTU ceiling.
    QueryDriverMtu,
    /// Changing the TAP driver's logical media state.
    SetMediaStatus,
    /// Enabling TAP-Windows 802.1Q metadata reconstruction.
    ConfigurePriority,
    /// Reading one complete Ethernet frame.
    ReadFrame,
    /// Writing one complete Ethernet frame.
    WriteFrame,
    /// Cancelling pending frame I/O.
    CancelIo,
    /// Enabling or disabling a platform TAP interface.
    SetDeviceState,
    /// Querying whether a platform TAP interface is present or enabled.
    QueryDeviceState,
    /// Setting a platform interface MTU.
    SetMtu,
    /// Querying a Windows IP interface MTU.
    QueryInterfaceMtu,
    /// Setting a Windows IP interface MTU.
    SetInterfaceMtu,
    /// Restoring a Windows IP interface MTU after partial failure.
    RollbackInterfaceMtu,
}

impl fmt::Display for TapOperation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let name = match self {
            Self::AcquireDeviceLock => "acquire device lock",
            Self::VerifyDeviceOwnership => "verify device ownership",
            Self::RecordDeviceOwnership => "record device ownership",
            Self::CreateDevice => "create device",
            Self::PairInterfaces => "pair interfaces",
            Self::ConfigureBlockingMode => "configure blocking mode",
            Self::ConnectHelper => "connect TAP helper",
            Self::AuthenticateHelper => "authenticate TAP helper",
            Self::ExchangeHelperMessage => "exchange TAP helper message",
            Self::EnumerateAdapters => "enumerate adapters",
            Self::OpenDevice => "open device",
            Self::QueryVersion => "query driver version",
            Self::QueryMac => "query MAC",
            Self::QueryMtu => "query MTU",
            Self::QueryDriverMtu => "query driver MTU",
            Self::SetMediaStatus => "set media status",
            Self::ConfigurePriority => "configure 802.1Q priority behavior",
            Self::ReadFrame => "read frame",
            Self::WriteFrame => "write frame",
            Self::CancelIo => "cancel I/O",
            Self::SetDeviceState => "set device state",
            Self::QueryDeviceState => "query device state",
            Self::SetMtu => "set MTU",
            Self::QueryInterfaceMtu => "query interface MTU",
            Self::SetInterfaceMtu => "set interface MTU",
            Self::RollbackInterfaceMtu => "roll back interface MTU",
        };
        formatter.write_str(name)
    }
}

/// Error returned by TAP device operations.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum TapError {
    /// The requested operation is not implemented on the current platform.
    #[error("TAP is not implemented for {0}")]
    UnsupportedPlatform(&'static str),
    /// A configuration field violates a stable bound.
    #[error("invalid TAP configuration for {field}: {reason}")]
    InvalidConfig {
        /// Stable configuration field name.
        field: &'static str,
        /// Stable validation reason without frame content.
        reason: &'static str,
    },
    /// No installed TAP-Windows adapter matches the optional selector.
    #[error("no TAP-Windows adapter matched selector {selector:?}")]
    AdapterNotFound {
        /// Friendly name or interface GUID requested by the caller.
        selector: Option<String>,
    },
    /// Automatic selection found more than one installed TAP-Windows adapter.
    #[error("TAP-Windows selector {selector:?} is ambiguous across {count} adapters")]
    AmbiguousAdapters {
        /// Explicit selector, or `None` for automatic selection.
        selector: Option<String>,
        /// Number of candidates that require an explicit selector.
        count: usize,
    },
    /// Another process already owns the selected platform TAP pair.
    #[error("TAP interface pair {name:?}/{peer_name:?} is already in use")]
    DeviceBusy {
        /// Host-visible interface name.
        name: String,
        /// Packet-I/O peer interface name.
        peer_name: String,
    },
    /// Existing feth interfaces are not covered by Stella ownership metadata.
    #[error("refusing to take ownership of unmanaged feth pair {name:?}/{peer_name:?}")]
    DeviceOwnershipConflict {
        /// Host-visible interface name.
        name: String,
        /// Packet-I/O peer interface name.
        peer_name: String,
    },
    /// The helper peer is not the privileged service Stella expected.
    #[error("macOS TAP helper peer has unexpected effective user ID {actual_uid}")]
    HelperIdentityMismatch {
        /// Effective user ID reported by the local Unix socket.
        actual_uid: u32,
    },
    /// A bounded helper message violated the versioned IPC contract.
    #[error("invalid macOS TAP helper protocol message: {reason}")]
    HelperProtocol {
        /// Stable diagnostic that never contains Ethernet frame content.
        reason: &'static str,
    },
    /// The privileged helper rejected an operation without exposing packet data.
    #[error("macOS TAP helper rejected the operation: {reason}")]
    HelperRejected {
        /// Bounded helper-side diagnostic.
        reason: String,
    },
    /// The opened device reports an unsupported TAP-Windows driver version.
    #[error("unsupported TAP-Windows driver version {major}.{minor}")]
    UnsupportedDriverVersion {
        /// Driver major version.
        major: u32,
        /// Driver minor version.
        minor: u32,
    },
    /// The TAP backend returned an all-zero or group MAC address.
    #[error("TAP device reported an invalid MAC address")]
    InvalidMacAddress,
    /// Requested runtime MTU exceeds the miniport's startup-time ceiling.
    #[error("requested TAP MTU {requested} exceeds driver ceiling {available}")]
    DriverMtuTooSmall {
        /// Requested Layer-3 MTU.
        requested: u16,
        /// MTU reported by the TAP driver.
        available: u32,
    },
    /// Configured complete-frame ceiling exceeds the miniport capability.
    #[error("requested TAP frame ceiling {requested} exceeds driver ceiling {available}")]
    DriverFrameTooSmall {
        /// Requested complete-frame ceiling.
        requested: u16,
        /// Maximum complete frame accepted from this miniport.
        available: u32,
    },
    /// Caller storage cannot hold the configured complete-frame maximum.
    #[error("receive output has {remaining} bytes but TAP requires {needed}")]
    ReceiveBufferTooSmall {
        /// Required configured complete-frame capacity.
        needed: usize,
        /// Caller output capacity.
        remaining: usize,
    },
    /// A complete frame is outside the configured Ethernet bounds.
    #[error("frame length {actual} is outside {minimum}..={maximum}")]
    FrameLength {
        /// Supplied frame length.
        actual: usize,
        /// Smallest accepted complete frame.
        minimum: usize,
        /// Configured maximum complete frame.
        maximum: usize,
    },
    /// A driver write unexpectedly reported a complete operation with fewer bytes.
    #[error("TAP write completed {actual} of {expected} frame bytes")]
    PartialFrameWrite {
        /// Required atomic frame length.
        expected: usize,
        /// Length reported by the operating system.
        actual: usize,
    },
    /// Another thread cancelled a pending frame operation.
    #[error("TAP I/O was cancelled")]
    Cancelled,
    /// The TAP device has already been destroyed or closed.
    #[error("TAP device is closed")]
    Closed,
    /// Updating the second IP family failed and rollback also failed.
    #[error("setting {failed_family} MTU failed and restoring {rollback_family} MTU also failed")]
    MtuRollbackFailed {
        /// Family whose requested update failed.
        failed_family: AddressFamily,
        /// Previously updated family whose rollback failed.
        rollback_family: AddressFamily,
        /// Original update failure.
        update: io::Error,
        /// Rollback failure.
        rollback: io::Error,
    },
    /// Updating the second feth MTU failed and restoring the first also failed.
    #[error(
        "setting MTU on {failed_interface:?} failed and restoring {rollback_interface:?} also failed"
    )]
    PairMtuRollbackFailed {
        /// Interface whose requested update failed.
        failed_interface: String,
        /// Previously updated interface whose rollback failed.
        rollback_interface: String,
        /// Original update failure.
        update: io::Error,
        /// Rollback failure.
        rollback: io::Error,
    },
    /// Querying or setting one Windows IP-family MTU failed.
    #[error("TAP operation '{operation}' failed for {family}")]
    InterfaceMtu {
        /// IP family that could not be queried or updated.
        family: AddressFamily,
        /// Stable operation name.
        operation: TapOperation,
        /// Original operating-system error.
        #[source]
        source: io::Error,
    },
    /// An operating-system TAP operation failed.
    #[error("TAP operation '{operation}' failed")]
    Io {
        /// Stable operation name.
        operation: TapOperation,
        /// Original operating-system error.
        #[source]
        source: io::Error,
    },
}

impl TapError {
    pub(crate) fn io(operation: TapOperation, source: io::Error) -> Self {
        Self::Io { operation, source }
    }
}

#[cfg(test)]
mod tests {
    use std::io;

    use super::{TapError, TapOperation};

    #[test]
    fn io_diagnostics_name_operation_without_frame_content() {
        let error = TapError::io(
            TapOperation::WriteFrame,
            io::Error::from(io::ErrorKind::PermissionDenied),
        );
        assert_eq!(error.to_string(), "TAP operation 'write frame' failed");
    }
}
