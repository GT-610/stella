//! Typed transport errors without datagram-bearing diagnostics.

use std::{fmt, io};

use thiserror::Error;

use crate::Endpoint;

/// Stable category for an operating-system socket error.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IoErrorClass {
    /// The process lacks permission for the socket operation.
    Permission,
    /// A local or remote address is invalid, unavailable, or already in use.
    Address,
    /// The destination or route is currently unreachable.
    Unreachable,
    /// A bounded operating-system resource is exhausted.
    ResourceExhausted,
    /// The operation may succeed when retried with bounded backoff.
    Transient,
    /// The socket cannot safely continue without recreation.
    Permanent,
}

/// Socket operation that produced an operating-system error.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IoOperation {
    /// Creating or binding a local socket.
    Bind,
    /// Sending one UDP datagram.
    Send,
    /// Receiving one UDP datagram.
    Receive,
}

impl fmt::Display for IoOperation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Bind => formatter.write_str("bind"),
            Self::Send => formatter.write_str("send"),
            Self::Receive => formatter.write_str("receive"),
        }
    }
}

/// Error returned by bounded-datagram transports.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum TransportError {
    /// A transport configuration field violates its stable bound.
    #[error("invalid transport configuration for {field}: {reason}")]
    InvalidConfig {
        /// Stable configuration field name.
        field: &'static str,
        /// Stable validation reason without user data.
        reason: &'static str,
    },
    /// The selected endpoint kind is not supported by this transport.
    #[error("endpoint kind is not supported by this transport")]
    UnsupportedEndpoint,
    /// The UDP destination family differs from the bound socket family.
    #[error("UDP endpoint family {remote} does not match bound family {local}")]
    AddressFamilyMismatch {
        /// Bound socket family.
        local: &'static str,
        /// Destination family.
        remote: &'static str,
    },
    /// A datagram exceeds the configured transport ceiling.
    #[error("datagram length {actual} exceeds configured maximum {maximum}")]
    DatagramTooLarge {
        /// Attempted or received datagram length.
        actual: usize,
        /// Configured maximum datagram length.
        maximum: usize,
    },
    /// Caller output cannot hold the complete received datagram.
    #[error("receive output has {remaining} bytes but complete datagram needs {needed}")]
    ReceiveBufferTooSmall {
        /// Complete datagram length.
        needed: usize,
        /// Caller output capacity.
        remaining: usize,
    },
    /// The operating system reported that a receive buffer was truncated.
    #[error("operating system truncated a UDP datagram")]
    ReceiveTruncated {
        /// Original operating-system error.
        #[source]
        source: io::Error,
    },
    /// The path rejected a datagram that was within the configured ceiling.
    #[error("path rejected {attempted}-byte datagram to {endpoint:?} as too large")]
    PathDatagramTooLarge {
        /// Destination endpoint.
        endpoint: Endpoint,
        /// Attempted datagram length.
        attempted: usize,
        /// Original operating-system size error.
        #[source]
        source: io::Error,
    },
    /// A UDP send unexpectedly reported fewer bytes than requested.
    #[error("UDP send wrote {actual} of {expected} datagram bytes")]
    PartialDatagramSend {
        /// Required atomic datagram length.
        expected: usize,
        /// Length reported by the operating system.
        actual: usize,
    },
    /// The transport is shutting down or already stopped.
    #[error("transport is shut down")]
    Shutdown,
    /// An operating-system socket operation failed.
    #[error("UDP {operation} failed with {class:?} error")]
    Io {
        /// Operation that failed.
        operation: IoOperation,
        /// Stable retry and reporting category.
        class: IoErrorClass,
        /// Remote endpoint for send failures, if any.
        endpoint: Option<Endpoint>,
        /// Original operating-system error.
        #[source]
        source: io::Error,
    },
}

pub(crate) fn io_error(
    operation: IoOperation,
    endpoint: Option<Endpoint>,
    source: io::Error,
) -> TransportError {
    TransportError::Io {
        operation,
        class: classify_io_error(&source),
        endpoint,
        source,
    }
}

fn classify_io_error(error: &io::Error) -> IoErrorClass {
    if matches!(error.raw_os_error(), Some(10_055 | 105 | 55)) {
        return IoErrorClass::ResourceExhausted;
    }
    match error.kind() {
        io::ErrorKind::PermissionDenied => IoErrorClass::Permission,
        io::ErrorKind::AddrInUse
        | io::ErrorKind::AddrNotAvailable
        | io::ErrorKind::InvalidInput => IoErrorClass::Address,
        io::ErrorKind::ConnectionRefused
        | io::ErrorKind::ConnectionReset
        | io::ErrorKind::ConnectionAborted
        | io::ErrorKind::NotConnected
        | io::ErrorKind::TimedOut => IoErrorClass::Unreachable,
        io::ErrorKind::OutOfMemory => IoErrorClass::ResourceExhausted,
        io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted => IoErrorClass::Transient,
        _ => IoErrorClass::Permanent,
    }
}

pub(crate) fn is_message_too_long(error: &io::Error) -> bool {
    match error.raw_os_error() {
        #[cfg(target_os = "windows")]
        Some(10_040) => true,
        #[cfg(any(target_os = "linux", target_os = "android"))]
        Some(90) => true,
        #[cfg(any(
            target_os = "macos",
            target_os = "ios",
            target_os = "freebsd",
            target_os = "openbsd",
            target_os = "netbsd",
            target_os = "dragonfly"
        ))]
        Some(40) => true,
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use std::io;

    use super::{classify_io_error, IoErrorClass};

    #[test]
    fn io_errors_are_grouped_without_display_parsing() {
        assert_eq!(
            classify_io_error(&io::Error::from(io::ErrorKind::PermissionDenied)),
            IoErrorClass::Permission
        );
        assert_eq!(
            classify_io_error(&io::Error::from(io::ErrorKind::AddrInUse)),
            IoErrorClass::Address
        );
        assert_eq!(
            classify_io_error(&io::Error::from(io::ErrorKind::TimedOut)),
            IoErrorClass::Unreachable
        );
        assert_eq!(
            classify_io_error(&io::Error::from(io::ErrorKind::Interrupted)),
            IoErrorClass::Transient
        );
    }
}
