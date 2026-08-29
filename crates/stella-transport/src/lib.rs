//! Pluggable bounded-datagram transport contracts for Stella.

#![forbid(unsafe_code)]

use std::net::SocketAddr;

/// Transport endpoint advertised to an authorized peer.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub enum Endpoint {
    /// UDP endpoint reachable over IPv4 or IPv6.
    Udp(SocketAddr),
}

/// Properties that upper layers need when constructing packets.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TransportCapabilities {
    /// Largest datagram payload accepted without transport fragmentation.
    pub max_datagram_size: usize,
}

#[cfg(test)]
mod tests {
    use super::TransportCapabilities;

    #[test]
    fn capabilities_preserve_datagram_limit() {
        let capabilities = TransportCapabilities {
            max_datagram_size: 1_500,
        };

        assert_eq!(capabilities.max_datagram_size, 1_500);
    }
}
