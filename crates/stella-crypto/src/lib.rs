//! Identity and packet-protection policy types for Stella.

#![forbid(unsafe_code)]

/// Data-plane confidentiality policy selected for a virtual network.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ConfidentialityPolicy {
    /// Authenticate packets while leaving Ethernet payload bytes visible.
    AuthenticateOnly,
    /// Authenticate and encrypt the complete Ethernet payload.
    Encrypt,
}

#[cfg(test)]
mod tests {
    use super::ConfidentialityPolicy;

    #[test]
    fn encryption_is_distinct_from_authentication_only() {
        assert_ne!(
            ConfidentialityPolicy::Encrypt,
            ConfidentialityPolicy::AuthenticateOnly
        );
    }
}
