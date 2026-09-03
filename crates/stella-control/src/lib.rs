//! Shared asynchronous mechanics for Stella TLS control connections.

#![forbid(unsafe_code)]

mod error;
mod message;
mod proof;
mod record;
mod sequence;

pub use error::ControlError;
pub use message::{MessageBuilder, OwnedControlMessage};
pub use proof::{
    controller_proof_transcript, node_proof_transcript, sign_controller_proof, sign_node_proof,
    verify_controller_proof, verify_node_proof, ControllerProofContext, NodeProofContext,
    ProofTranscript, CONTROLLER_PROOF_DOMAIN, CONTROL_EXPORTER_LABEL, CONTROL_EXPORTER_LENGTH,
    CONTROL_NONCE_LENGTH, NODE_PROOF_DOMAIN,
};
pub use record::{RecordReader, RecordWriter};
pub use sequence::{InboundSequence, OutboundSequence};
