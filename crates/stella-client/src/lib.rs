//! Stella client control and data-plane runtime.

#![forbid(unsafe_code)]

mod control;
mod error;
mod tls;

pub use control::{
    authenticate_controller, AuthenticatedControl, BearerCredential, ControllerTrust, Enrollment,
};
pub use error::ClientError;
pub use tls::{SpkiPin, SpkiPinParseError};
