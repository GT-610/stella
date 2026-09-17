//! Node identity persistence through the shared native security boundary.

pub use stella_file_security::{
    create_identity as create_node_identity, load_identity as load_node_identity,
    IdentityFileError as NodeIdentityFileError,
};
