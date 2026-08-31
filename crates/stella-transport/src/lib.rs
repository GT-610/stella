//! Pluggable bounded-datagram transports for Stella.

#![forbid(unsafe_code)]

mod error;
mod udp;

use std::{future::Future, net::SocketAddr, num::NonZeroU64, pin::Pin};

pub use error::{IoErrorClass, IoOperation, TransportError};
pub use udp::{
    UdpConfig, UdpTransport, DEFAULT_UDP_DATAGRAM_SIZE, MAX_UDP_DATAGRAM_SIZE,
    MIN_UDP_DATAGRAM_SIZE,
};

/// Result type returned by transport operations.
pub type Result<T> = std::result::Result<T, TransportError>;

/// Boxed object-safe future returned by asynchronous transport methods.
pub type TransportFuture<'a, T> = Pin<Box<dyn Future<Output = Result<T>> + Send + 'a>>;

/// Locally unique identifier for one validated datagram path generation.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct PathId(NonZeroU64);

impl PathId {
    /// Creates a path identifier, rejecting zero.
    #[must_use]
    pub const fn new(value: u64) -> Option<Self> {
        match NonZeroU64::new(value) {
            Some(value) => Some(Self(value)),
            None => None,
        }
    }

    /// Returns the non-zero numeric identifier.
    #[must_use]
    pub const fn get(self) -> u64 {
        self.0.get()
    }
}

impl std::fmt::Display for PathId {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.get().fmt(formatter)
    }
}

/// Transport endpoint advertised to an authorized peer.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
#[non_exhaustive]
pub enum Endpoint {
    /// UDP endpoint reachable over IPv4 or IPv6.
    Udp(SocketAddr),
}

impl Endpoint {
    /// Returns the endpoint's numeric socket address when it is UDP.
    #[must_use]
    pub const fn as_udp(&self) -> Option<SocketAddr> {
        match self {
            Self::Udp(address) => Some(*address),
        }
    }
}

impl std::fmt::Display for Endpoint {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Udp(address) => write!(formatter, "udp://{address}"),
        }
    }
}

/// Properties that upper layers need when constructing packets.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TransportCapabilities {
    /// Largest datagram payload accepted without transport fragmentation.
    pub max_datagram_size: usize,
}

/// Metadata for one complete received datagram in caller-provided storage.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReceivedDatagram {
    /// Exact numeric source endpoint reported by the socket.
    pub source: Endpoint,
    /// Number of complete datagram bytes written to caller storage.
    pub length: usize,
}

/// Replaceable asynchronous bounded-datagram transport contract.
pub trait DatagramTransport: Send + Sync {
    /// Returns the transport's conservative packet-construction limits.
    #[must_use]
    fn capabilities(&self) -> TransportCapabilities;

    /// Returns numeric local endpoints currently owned by this transport.
    ///
    /// # Errors
    ///
    /// Returns [`TransportError::Shutdown`] after local shutdown.
    fn local_endpoints(&self) -> Result<Vec<Endpoint>>;

    /// Sends one complete datagram atomically to `endpoint`.
    ///
    /// # Errors
    ///
    /// Returns a typed endpoint, size, shutdown, or operating-system error.
    fn send_to<'a>(&'a self, endpoint: &'a Endpoint, datagram: &'a [u8])
        -> TransportFuture<'a, ()>;

    /// Receives one complete datagram into `output`.
    ///
    /// Bytes are copied into `output` only after the full datagram length has
    /// been established. The buffer remains unchanged on size or I/O failure.
    ///
    /// # Errors
    ///
    /// Returns a typed size, shutdown, truncation, or operating-system error.
    fn receive<'a>(&'a self, output: &'a mut [u8]) -> TransportFuture<'a, ReceivedDatagram>;

    /// Cancels pending operations and rejects new work.
    ///
    /// Shutdown is idempotent. The owning runtime drops the transport after its
    /// bounded drain deadline to release the operating-system socket.
    fn shutdown(&self) -> TransportFuture<'_, ()>;
}

#[cfg(test)]
mod tests {
    use super::{Endpoint, PathId};

    #[test]
    fn path_ids_are_nonzero_ordered_and_displayed_canonically() {
        assert_eq!(PathId::new(0), None);
        let first = PathId::new(1).expect("non-zero path ID");
        let second = PathId::new(2).expect("non-zero path ID");
        assert!(first < second);
        assert_eq!(first.get(), 1);
        assert_eq!(first.to_string(), "1");
    }

    #[test]
    fn transport_endpoints_include_their_carrier_in_diagnostics() {
        let endpoint = Endpoint::Udp("127.0.0.1:44900".parse().expect("UDP endpoint"));
        assert_eq!(endpoint.to_string(), "udp://127.0.0.1:44900");
    }
}
