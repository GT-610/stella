//! Stella client control and data-plane runtime.

#![forbid(unsafe_code)]

mod active;
mod config;
mod control;
mod error;
mod identity;
mod state;
mod tls;

pub use active::{ActiveControl, ControlUpdate, HeartbeatReport};
pub use config::{ClientConfig, ClientConfigError, ConfiguredNetwork, CONFIG_VERSION};
pub use control::{
    authenticate_controller, AuthenticatedControl, BearerCredential, ControllerTrust, Enrollment,
};
pub use error::ClientError;
pub use identity::{
    create_node_identity, load_node_identity, verify_node_identity_permissions,
    NodeIdentityFileError,
};
pub use state::{
    GrantRefreshInput, NetworkState, PeerDeltaInput, PeerDeltaOperation, PeerState, SnapshotInput,
    StateError,
};
pub use tls::{SpkiPin, SpkiPinParseError};
