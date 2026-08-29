//! Pure parsing and serialization support for the Stella wire protocol.

#![forbid(unsafe_code)]

/// First protocol major version implemented by this workspace.
pub const PROTOCOL_MAJOR: u8 = 0;

/// First protocol minor version implemented by this workspace.
pub const PROTOCOL_MINOR: u8 = 1;

/// Protocol version advertised during negotiation.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct ProtocolVersion {
    /// Incompatible format generation.
    pub major: u8,
    /// Backward-compatible feature generation within one major version.
    pub minor: u8,
}

impl ProtocolVersion {
    /// Version implemented by this crate.
    pub const CURRENT: Self = Self {
        major: PROTOCOL_MAJOR,
        minor: PROTOCOL_MINOR,
    };
}

#[cfg(test)]
mod tests {
    use super::{ProtocolVersion, PROTOCOL_MAJOR, PROTOCOL_MINOR};

    #[test]
    fn current_version_matches_constants() {
        assert_eq!(ProtocolVersion::CURRENT.major, PROTOCOL_MAJOR);
        assert_eq!(ProtocolVersion::CURRENT.minor, PROTOCOL_MINOR);
    }
}
