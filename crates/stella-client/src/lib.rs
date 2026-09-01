//! Stella client control and data-plane runtime.

#![forbid(unsafe_code)]

mod active;
mod config;
mod control;
mod data_plane;
mod error;
mod handshake;
mod identity;
mod network;
#[cfg(target_os = "windows")]
mod runtime;
mod state;
mod switch;
mod tls;

pub use active::{ActiveControl, ControlUpdate, HeartbeatReport};
pub use config::{ClientConfig, ClientConfigError, ConfiguredNetwork, CONFIG_VERSION};
pub use control::{
    authenticate_controller, AuthenticatedControl, BearerCredential, ControllerTrust, Enrollment,
};
pub use data_plane::{AuthenticatedKeepalive, DataPlaneError, PeerDataSession};
pub use error::ClientError;
pub use handshake::{
    EstablishedPeerSession, HandshakeError, HandshakeEvent, HandshakeTransmission,
    InitiatorHandshake, PeerHandshakeConfig, PeerHandshakeManager, ResponderHandshake,
};
pub use identity::{
    create_node_identity, load_node_identity, verify_node_identity_permissions,
    NodeIdentityFileError,
};
pub use network::{NetworkDataError, NetworkDataPlane, NetworkOutput, RoutedDatagram};
#[cfg(target_os = "windows")]
pub use runtime::{ClientDataRuntime, RuntimeError};
pub use state::{
    GrantRefreshInput, NetworkState, PeerConnectivityState, PeerDeltaInput, PeerDeltaOperation,
    PeerState, SnapshotInput, StateError,
};
pub use switch::{FloodClass, L2Switch, PeerIngress, SwitchError, TapForwarding};
pub use tls::{SpkiPin, SpkiPinParseError};
