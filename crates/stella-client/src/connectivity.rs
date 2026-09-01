//! Owned deployment connectivity configuration received from the controller.

use std::fmt;

use stella_common::RelayId;
use stella_proto::{
    RelayAddress, RelayCarrierMask, RelayPorts, RelayServiceListView, RelayServiceView,
    RelayTrustRequirements, StunServer, StunServerListView,
};
use zeroize::Zeroizing;

use crate::ClientError;

/// Complete validated STUN and relay configuration for one controller deployment.
#[derive(Clone, Eq, PartialEq)]
pub struct ConnectivityConfigState {
    revision: u64,
    stun_servers: Vec<StunServer>,
    relay_services: Vec<RelayServiceState>,
}

impl ConnectivityConfigState {
    /// Returns the deployment-scoped monotonic configuration revision.
    #[must_use]
    pub const fn revision(&self) -> u64 {
        self.revision
    }

    /// Returns numeric STUN services in controller preference order.
    #[must_use]
    pub fn stun_servers(&self) -> &[StunServer] {
        &self.stun_servers
    }

    /// Returns relay services in controller preference order.
    #[must_use]
    pub fn relay_services(&self) -> &[RelayServiceState] {
        &self.relay_services
    }

    pub(crate) fn from_wire(
        revision: u64,
        stun_server_list: &[u8],
        relay_service_list: &[u8],
        now: u64,
    ) -> Result<Self, ClientError> {
        if revision == 0 {
            return Err(ClientError::InvalidConnectivityConfigRevision);
        }
        let stun_servers = StunServerListView::decode(stun_server_list)?
            .servers()
            .collect();
        let relay_services = RelayServiceListView::decode(relay_service_list)?
            .services()
            .map(|service| RelayServiceState::from_view(&service, now))
            .collect::<Result<Vec<_>, _>>()?;
        Ok(Self {
            revision,
            stun_servers,
            relay_services,
        })
    }
}

impl fmt::Debug for ConnectivityConfigState {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ConnectivityConfigState")
            .field("revision", &self.revision)
            .field("stun_server_count", &self.stun_servers.len())
            .field("relay_service_count", &self.relay_services.len())
            .finish_non_exhaustive()
    }
}

/// One owned relay service with controller-issued credentials for this node.
#[derive(Clone, Eq, PartialEq)]
pub struct RelayServiceState {
    relay_id: RelayId,
    carriers: RelayCarrierMask,
    priority: u16,
    max_datagram_size: u32,
    allocation_lifetime_seconds: u32,
    idle_timeout_seconds: u32,
    credential_issued_at: u64,
    credential_expires_at: u64,
    hostname: String,
    tls_server_name: String,
    credential_username: Zeroizing<Vec<u8>>,
    credential_secret: Zeroizing<Vec<u8>>,
    region: String,
    trust: RelayTrustRequirements,
    ports: RelayPorts,
    addresses: Vec<RelayAddress>,
    spki_pins: Vec<[u8; 32]>,
}

impl RelayServiceState {
    /// Returns the stable relay service identity.
    #[must_use]
    pub const fn relay_id(&self) -> RelayId {
        self.relay_id
    }

    /// Returns supported client-to-relay carriers.
    #[must_use]
    pub const fn carriers(&self) -> RelayCarrierMask {
        self.carriers
    }

    /// Returns the service preference, where lower values are preferred.
    #[must_use]
    pub const fn priority(&self) -> u16 {
        self.priority
    }

    /// Returns the maximum complete Stella datagram accepted by the relay.
    #[must_use]
    pub const fn max_datagram_size(&self) -> u32 {
        self.max_datagram_size
    }

    /// Returns the advertised allocation lifetime in seconds.
    #[must_use]
    pub const fn allocation_lifetime_seconds(&self) -> u32 {
        self.allocation_lifetime_seconds
    }

    /// Returns the allocation idle timeout in seconds.
    #[must_use]
    pub const fn idle_timeout_seconds(&self) -> u32 {
        self.idle_timeout_seconds
    }

    /// Returns the controller credential issue Unix time.
    #[must_use]
    pub const fn credential_issued_at(&self) -> u64 {
        self.credential_issued_at
    }

    /// Returns the exclusive controller credential expiry Unix time.
    #[must_use]
    pub const fn credential_expires_at(&self) -> u64 {
        self.credential_expires_at
    }

    /// Returns the optional canonical relay DNS hostname.
    #[must_use]
    pub fn hostname(&self) -> &str {
        &self.hostname
    }

    /// Returns the optional canonical relay TLS server name.
    #[must_use]
    pub fn tls_server_name(&self) -> &str {
        &self.tls_server_name
    }

    /// Borrows the relay authentication username.
    #[must_use]
    pub fn credential_username(&self) -> &[u8] {
        &self.credential_username
    }

    /// Borrows the opaque relay authentication secret.
    #[must_use]
    pub fn credential_secret(&self) -> &[u8] {
        &self.credential_secret
    }

    /// Returns the optional deployment region label.
    #[must_use]
    pub fn region(&self) -> &str {
        &self.region
    }

    /// Returns required TLS certificate checks.
    #[must_use]
    pub const fn trust(&self) -> RelayTrustRequirements {
        self.trust
    }

    /// Returns carrier-specific relay listener ports.
    #[must_use]
    pub const fn ports(&self) -> RelayPorts {
        self.ports
    }

    /// Returns numeric service addresses in canonical preference order.
    #[must_use]
    pub fn addresses(&self) -> &[RelayAddress] {
        &self.addresses
    }

    /// Returns accepted SHA-256 SPKI pins in canonical order.
    #[must_use]
    pub fn spki_pins(&self) -> &[[u8; 32]] {
        &self.spki_pins
    }

    fn from_view(service: &RelayServiceView<'_>, now: u64) -> Result<Self, ClientError> {
        if service.credential_expires_at() <= now {
            return Err(ClientError::RelayCredentialExpired {
                relay_id: service.relay_id(),
                now,
                expires_at: service.credential_expires_at(),
            });
        }
        Ok(Self {
            relay_id: service.relay_id(),
            carriers: service.carriers(),
            priority: service.priority(),
            max_datagram_size: service.max_datagram_size(),
            allocation_lifetime_seconds: service.allocation_lifetime_seconds(),
            idle_timeout_seconds: service.idle_timeout_seconds(),
            credential_issued_at: service.credential_issued_at(),
            credential_expires_at: service.credential_expires_at(),
            hostname: service.hostname().to_owned(),
            tls_server_name: service.tls_server_name().to_owned(),
            credential_username: Zeroizing::new(service.credential_username().to_vec()),
            credential_secret: Zeroizing::new(service.credential_secret().to_vec()),
            region: service.region().to_owned(),
            trust: service.trust(),
            ports: service.ports(),
            addresses: service.addresses().collect(),
            spki_pins: service.spki_pins().copied().collect(),
        })
    }
}

impl fmt::Debug for RelayServiceState {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RelayServiceState")
            .field("relay_id", &self.relay_id)
            .field("carriers", &self.carriers)
            .field("priority", &self.priority)
            .field("max_datagram_size", &self.max_datagram_size)
            .field(
                "allocation_lifetime_seconds",
                &self.allocation_lifetime_seconds,
            )
            .field("idle_timeout_seconds", &self.idle_timeout_seconds)
            .field("credential_issued_at", &self.credential_issued_at)
            .field("credential_expires_at", &self.credential_expires_at)
            .field("hostname", &self.hostname)
            .field("tls_server_name", &self.tls_server_name)
            .field(
                "credential_username_length",
                &self.credential_username.len(),
            )
            .field("credential_secret_length", &self.credential_secret.len())
            .field("region", &self.region)
            .field("trust", &self.trust)
            .field("ports", &self.ports)
            .field("address_count", &self.addresses.len())
            .field("spki_pin_count", &self.spki_pins.len())
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use std::net::SocketAddr;

    use stella_common::RelayId;
    use stella_proto::{
        encode_relay_service_list, encode_stun_server_list, RelayAddress, RelayCarrierMask,
        RelayPorts, RelayServiceRef, RelayTrustRequirements, StunServer,
    };

    use super::ConnectivityConfigState;
    use crate::ClientError;

    fn encoded_config(expires_at: u64) -> (Vec<u8>, Vec<u8>) {
        let stun_servers = [StunServer {
            priority: 0,
            address: SocketAddr::from(([192, 0, 2, 20], 3_478)),
        }];
        let mut stun_bytes = vec![0; 28];
        encode_stun_server_list(&stun_servers, &mut stun_bytes).expect("encode STUN list");

        let addresses = [RelayAddress {
            priority: 0,
            address: "192.0.2.30".parse().expect("relay address"),
        }];
        let service = RelayServiceRef {
            relay_id: RelayId::from_bytes([1; 16]),
            carriers: RelayCarrierMask::TURN_UDP,
            priority: 0,
            max_datagram_size: 1_200,
            allocation_lifetime_seconds: 600,
            idle_timeout_seconds: 120,
            credential_issued_at: expires_at - 600,
            credential_expires_at: expires_at,
            hostname: "",
            tls_server_name: "",
            credential_username: b"node 1",
            credential_secret: b"0123456789abcdef",
            region: "test",
            trust: RelayTrustRequirements::NONE,
            ports: RelayPorts {
                turn_udp: 3_478,
                turn_tcp: 0,
                turn_tls: 0,
                secure_websocket: 0,
            },
            addresses: &addresses,
            spki_pins: &[],
        };
        let mut relay_bytes = vec![0; 4 + service.encoded_len().expect("relay service length")];
        encode_relay_service_list(&[service], &mut relay_bytes).expect("encode relay list");
        (stun_bytes, relay_bytes)
    }

    #[test]
    fn configuration_is_owned_redacted_and_rejects_expired_credentials() {
        let (mut stun_bytes, mut relay_bytes) = encoded_config(1_600);
        let state = ConnectivityConfigState::from_wire(7, &stun_bytes, &relay_bytes, 1_100)
            .expect("valid connectivity configuration");
        stun_bytes.fill(0);
        relay_bytes.fill(0);
        assert_eq!(state.revision(), 7);
        assert_eq!(state.stun_servers().len(), 1);
        let relay = &state.relay_services()[0];
        assert_eq!(relay.relay_id(), RelayId::from_bytes([1; 16]));
        assert_eq!(relay.credential_username(), b"node 1");
        assert_eq!(relay.credential_secret(), b"0123456789abcdef");
        let diagnostic = format!("{relay:?}");
        assert!(!diagnostic.contains("node 1"));
        assert!(!diagnostic.contains("0123456789abcdef"));

        let (stun_bytes, relay_bytes) = encoded_config(1_600);
        assert!(matches!(
            ConnectivityConfigState::from_wire(8, &stun_bytes, &relay_bytes, 1_600),
            Err(ClientError::RelayCredentialExpired {
                expires_at: 1_600,
                now: 1_600,
                ..
            })
        ));
        assert!(matches!(
            ConnectivityConfigState::from_wire(0, &stun_bytes, &relay_bytes, 1_100),
            Err(ClientError::InvalidConnectivityConfigRevision)
        ));
    }
}
