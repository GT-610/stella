//! Shared platform-neutral value types for Stella.

#![forbid(unsafe_code)]

/// Stable identifier of a Stella node identity.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct NodeId([u8; Self::LENGTH]);

impl NodeId {
    /// Length of a node identifier in bytes.
    pub const LENGTH: usize = 16;

    /// Creates an identifier from its canonical bytes.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; Self::LENGTH]) -> Self {
        Self(bytes)
    }

    /// Returns the canonical identifier bytes.
    #[must_use]
    pub const fn into_bytes(self) -> [u8; Self::LENGTH] {
        self.0
    }
}

/// Stable identifier of an isolated Stella virtual network.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct NetworkId([u8; Self::LENGTH]);

impl NetworkId {
    /// Length of a network identifier in bytes.
    pub const LENGTH: usize = 16;

    /// Creates an identifier from its canonical bytes.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; Self::LENGTH]) -> Self {
        Self(bytes)
    }

    /// Returns the canonical identifier bytes.
    #[must_use]
    pub const fn into_bytes(self) -> [u8; Self::LENGTH] {
        self.0
    }
}

#[cfg(test)]
mod tests {
    use super::{NetworkId, NodeId};

    #[test]
    fn identifiers_round_trip_canonical_bytes() {
        let node = [1; NodeId::LENGTH];
        let network = [2; NetworkId::LENGTH];

        assert_eq!(NodeId::from_bytes(node).into_bytes(), node);
        assert_eq!(NetworkId::from_bytes(network).into_bytes(), network);
    }
}
