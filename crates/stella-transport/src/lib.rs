//! Pluggable bounded-datagram transports for Stella.

#![forbid(unsafe_code)]

mod error;
mod udp;

use std::{future::Future, net::SocketAddr, pin::Pin};

pub use error::{IoErrorClass, IoOperation, TransportError};
pub use udp::{
    UdpConfig, UdpTransport, DEFAULT_UDP_DATAGRAM_SIZE, MAX_UDP_DATAGRAM_SIZE,
    MIN_UDP_DATAGRAM_SIZE,
};

/// Result type returned by transport operations.
pub type Result<T> = std::result::Result<T, TransportError>;

/// Boxed object-safe future returned by asynchronous transport methods.
pub type TransportFuture<'a, T> = Pin<Box<dyn Future<Output = Result<T>> + Send + 'a>>;

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
