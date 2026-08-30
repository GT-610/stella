//! Shared asynchronous mechanics for Stella TLS control connections.

#![forbid(unsafe_code)]

mod error;
mod message;
mod record;
mod sequence;

pub use error::ControlError;
pub use message::{MessageBuilder, OwnedControlMessage};
pub use record::{RecordReader, RecordWriter};
pub use sequence::{CorrelationTracker, InboundSequence, OutboundSequence, MAX_CORRELATIONS};
