//! Stella client control and data-plane runtime.

#![forbid(unsafe_code)]

mod active;
mod control;
mod error;
mod state;
mod tls;

pub use active::{ActiveControl, ControlUpdate, HeartbeatReport};
pub use control::{
    authenticate_controller, AuthenticatedControl, BearerCredential, ControllerTrust, Enrollment,
};
pub use error::ClientError;
pub use state::{
    GrantRefreshInput, NetworkState, PeerDeltaInput, PeerDeltaOperation, PeerState, SnapshotInput,
    StateError,
};
pub use tls::{SpkiPin, SpkiPinParseError};
