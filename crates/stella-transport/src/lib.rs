//! Pluggable bounded-datagram transports for Stella.

#![forbid(unsafe_code)]

mod error;
mod turn_stream;
mod udp;
mod websocket_record;

use std::{future::Future, net::SocketAddr, num::NonZeroU64, pin::Pin};

use stella_common::RelayId;

pub use error::{IoErrorClass, IoOperation, TransportError};
pub use turn_stream::{TurnStream, TurnStreamError, MAX_TURN_STREAM_RECORD_SIZE};
pub use udp::{
    UdpConfig, UdpTransport, DEFAULT_UDP_DATAGRAM_SIZE, MAX_UDP_DATAGRAM_SIZE,
    MIN_UDP_DATAGRAM_SIZE,
};
pub use websocket_record::{
    read_websocket_record, turn_websocket_config, write_websocket_record, WebSocketRecordError,
    STELLA_TURN_WEBSOCKET_PATH, STELLA_TURN_WEBSOCKET_SUBPROTOCOL,
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

/// Client-to-relay carrier attached to one relayed endpoint.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum RelayCarrier {
    /// TURN records carried over UDP.
    TurnUdp,
    /// TURN records carried over TCP.
    TurnTcp,
    /// TURN records carried over TLS over TCP.
    TurnTls,
    /// Stella TURN records carried by secure WebSocket.
    SecureWebSocket,
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
    /// Peer address reached through one of its TURN UDP relay candidates.
    TurnUdp {
        /// Stable relay identity attached to the peer candidate.
        relay_id: RelayId,
        /// Exact relayed peer address carried by the candidate.
        address: SocketAddr,
    },
    /// Peer address reached through one of its TURN TCP relay candidates.
    TurnTcp {
        /// Stable relay identity attached to the peer candidate.
        relay_id: RelayId,
        /// Exact relayed peer address carried by the candidate.
        address: SocketAddr,
    },
    /// Peer address reached through one of its TURN TLS relay candidates.
    TurnTls {
        /// Stable relay identity attached to the peer candidate.
        relay_id: RelayId,
        /// Exact relayed peer address carried by the candidate.
        address: SocketAddr,
    },
    /// Peer address reached through one of its secure WebSocket relay candidates.
    SecureWebSocket {
        /// Stable relay identity attached to the peer candidate.
        relay_id: RelayId,
        /// Exact relayed peer address carried by the candidate.
        address: SocketAddr,
    },
}

impl Endpoint {
    /// Returns the endpoint's numeric socket address when it is UDP.
    #[must_use]
    pub const fn as_udp(&self) -> Option<SocketAddr> {
        match self {
            Self::Udp(address) => Some(*address),
            Self::TurnUdp { .. }
            | Self::TurnTcp { .. }
            | Self::TurnTls { .. }
            | Self::SecureWebSocket { .. } => None,
        }
    }

    /// Returns the relay identity and peer address for a TURN UDP endpoint.
    #[must_use]
    pub const fn as_turn_udp(&self) -> Option<(RelayId, SocketAddr)> {
        match self {
            Self::Udp(_)
            | Self::TurnTcp { .. }
            | Self::TurnTls { .. }
            | Self::SecureWebSocket { .. } => None,
            Self::TurnUdp { relay_id, address } => Some((*relay_id, *address)),
        }
    }

    /// Returns the carrier, relay identity, and peer address for any relayed endpoint.
    #[must_use]
    pub const fn as_relay(&self) -> Option<(RelayCarrier, RelayId, SocketAddr)> {
        match self {
            Self::Udp(_) => None,
            Self::TurnUdp { relay_id, address } => {
                Some((RelayCarrier::TurnUdp, *relay_id, *address))
            }
            Self::TurnTcp { relay_id, address } => {
                Some((RelayCarrier::TurnTcp, *relay_id, *address))
            }
            Self::TurnTls { relay_id, address } => {
                Some((RelayCarrier::TurnTls, *relay_id, *address))
            }
            Self::SecureWebSocket { relay_id, address } => {
                Some((RelayCarrier::SecureWebSocket, *relay_id, *address))
            }
        }
    }
}

impl std::fmt::Display for Endpoint {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Udp(address) => write!(formatter, "udp://{address}"),
            Self::TurnUdp { relay_id, address } => {
                write!(formatter, "turn+udp://{relay_id}@{address}")
            }
            Self::TurnTcp { relay_id, address } => {
                write!(formatter, "turn+tcp://{relay_id}@{address}")
            }
            Self::TurnTls { relay_id, address } => {
                write!(formatter, "turn+tls://{relay_id}@{address}")
            }
            Self::SecureWebSocket { relay_id, address } => {
                write!(formatter, "turn+wss://{relay_id}@{address}")
            }
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
    use stella_common::RelayId;

    use super::{Endpoint, PathId, RelayCarrier};

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
        let relay_id = RelayId::from_bytes([0x11; 16]);
        let endpoint = Endpoint::TurnUdp {
            relay_id,
            address: "192.0.2.30:50000".parse().expect("TURN UDP endpoint"),
        };
        assert_eq!(
            endpoint.to_string(),
            "turn+udp://11111111111111111111111111111111@192.0.2.30:50000"
        );
        assert_eq!(
            endpoint.as_turn_udp(),
            Some((
                relay_id,
                "192.0.2.30:50000".parse().expect("TURN UDP endpoint")
            ))
        );
        assert_eq!(
            endpoint.as_relay(),
            Some((
                RelayCarrier::TurnUdp,
                relay_id,
                "192.0.2.30:50000".parse().expect("TURN UDP endpoint")
            ))
        );

        let stream_endpoints = [
            (
                Endpoint::TurnTcp {
                    relay_id,
                    address: "192.0.2.30:50001".parse().expect("TURN TCP endpoint"),
                },
                RelayCarrier::TurnTcp,
                "turn+tcp://11111111111111111111111111111111@192.0.2.30:50001",
            ),
            (
                Endpoint::TurnTls {
                    relay_id,
                    address: "192.0.2.30:50002".parse().expect("TURN TLS endpoint"),
                },
                RelayCarrier::TurnTls,
                "turn+tls://11111111111111111111111111111111@192.0.2.30:50002",
            ),
            (
                Endpoint::SecureWebSocket {
                    relay_id,
                    address: "192.0.2.30:50003".parse().expect("WebSocket endpoint"),
                },
                RelayCarrier::SecureWebSocket,
                "turn+wss://11111111111111111111111111111111@192.0.2.30:50003",
            ),
        ];
        for (endpoint, carrier, display) in stream_endpoints {
            assert_eq!(endpoint.to_string(), display);
            assert_eq!(
                endpoint.as_relay(),
                Some((carrier, relay_id, endpoint_address(&endpoint)))
            );
            assert_eq!(endpoint.as_turn_udp(), None);
        }
    }

    fn endpoint_address(endpoint: &Endpoint) -> std::net::SocketAddr {
        endpoint
            .as_relay()
            .map(|(_, _, address)| address)
            .expect("relayed endpoint")
    }
}
