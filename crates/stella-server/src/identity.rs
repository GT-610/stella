//! Controller identity persistence through the shared native security boundary.

pub use stella_file_security::{
    create_identity as create_controller_identity, load_identity as load_controller_identity,
    IdentityFileError,
};
pub(crate) use stella_file_security::{open_protected_secret_file, write_protected_secret};
