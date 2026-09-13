//! Stella client control and data-plane runtime.

#![forbid(unsafe_code)]

mod active;
mod config;
mod connectivity;
mod control;
mod control_field;
mod data_plane;
mod error;
mod handshake;
mod http_proxy;
mod ice;
mod identity;
mod network;
#[cfg(any(target_os = "windows", target_os = "macos"))]
mod runtime;
mod state;
#[cfg(any(target_os = "windows", target_os = "macos"))]
mod stun;
mod switch;
mod tls;
mod turn;

pub use active::{ActiveControl, ControlUpdate, HeartbeatReport};
#[cfg(target_os = "windows")]
pub use config::windows_tap_adapter_name;
pub use config::{ClientConfig, ClientConfigError, ConfiguredNetwork, CONFIG_VERSION};
pub use connectivity::{ConnectivityConfigState, RelayServiceState};
pub use control::{
    authenticate_controller, AuthenticatedControl, BearerCredential, ControllerTrust, Enrollment,
};
pub use data_plane::{AuthenticatedKeepalive, DataPlaneError, PeerDataSession};
pub use error::ClientError;
pub use handshake::{
    EstablishedPeerSession, HandshakeError, HandshakeEvent, HandshakeTransmission,
    InitiatorHandshake, PeerHandshakeConfig, PeerHandshakeManager, ResponderHandshake,
};
pub use ice::{
    IceAgent, IceError, IceNomination, IceOutput, IcePathFailure, IcePeerConfig, IceTransmission,
};
pub use identity::{create_node_identity, load_node_identity, NodeIdentityFileError};
pub use network::{NetworkDataError, NetworkDataPlane, NetworkOutput, RoutedDatagram};
#[cfg(any(target_os = "windows", target_os = "macos"))]
pub use runtime::{ClientDataRuntime, RuntimeError};
pub use state::{
    GrantRefreshInput, NetworkState, PeerConnectivityState, PeerDeltaInput, PeerDeltaOperation,
    PeerState, SnapshotInput, StateError,
};
#[cfg(any(target_os = "windows", target_os = "macos"))]
pub use stun::StunDiscoveryError;
pub use switch::{FloodClass, L2Switch, PeerIngress, SwitchError, TapForwarding};
pub use tls::{SpkiPin, SpkiPinParseError};
pub use turn::{
    TurnCredentials, TurnTcpClient, TurnTcpClientConfig, TurnTcpError, TurnTlsClient,
    TurnTlsClientConfig, TurnTlsError, TurnUdpClient, TurnUdpClientConfig, TurnUdpError,
    TurnWebSocketClient, TurnWebSocketClientConfig, TurnWebSocketError,
};
