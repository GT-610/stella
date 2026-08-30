//! Control-channel error definitions.

use thiserror::Error;

/// Failure while framing, building, or tracking a control connection.
#[derive(Debug, Error)]
pub enum ControlError {
    /// The underlying ordered byte stream failed.
    #[error("control carrier I/O failed: {0}")]
    Io(#[from] std::io::Error),
    /// A protocol record or field failed byte-level validation.
    #[error("invalid control protocol data: {0}")]
    Codec(#[from] stella_proto::CodecError),
    /// EOF occurred after only part of the four-byte record prefix arrived.
    #[error("control record prefix was truncated after {read} bytes")]
    TruncatedPrefix {
        /// Prefix bytes received before EOF.
        read: usize,
    },
    /// EOF occurred after only part of a declared record body arrived.
    #[error("control record was truncated after {read} of {expected} bytes")]
    TruncatedRecord {
        /// Declared record body length.
        expected: usize,
        /// Body bytes received before EOF.
        read: usize,
    },
    /// Fallible allocation for attacker-bounded input failed.
    #[error("could not allocate {requested} bytes for control data")]
    AllocationFailed {
        /// Requested allocation size.
        requested: usize,
    },
    /// Checked encoded-length arithmetic overflowed the platform size.
    #[error("control message length arithmetic overflowed")]
    LengthOverflow,
    /// A constructed message exceeds the protocol record bound.
    #[error("control message length {actual} exceeds maximum {maximum}")]
    MessageTooLarge {
        /// Constructed record length.
        actual: usize,
        /// Protocol maximum record length.
        maximum: usize,
    },
    /// The next monotonic ID cannot be represented without wrapping.
    #[error("control message ID sequence is exhausted")]
    MessageIdExhausted,
    /// An inbound message did not have the exact next expected ID.
    #[error("expected control message ID {expected}, received {actual}")]
    MessageIdMismatch {
        /// Exact next expected ID.
        expected: u64,
        /// Received ID.
        actual: u64,
    },
    /// A request ID was already outstanding.
    #[error("control request ID {message_id} is already outstanding")]
    DuplicateCorrelation {
        /// Duplicate request message ID.
        message_id: u64,
    },
    /// The bounded set of outstanding requests is full.
    #[error("control request correlation limit {maximum} reached")]
    CorrelationLimit {
        /// Configured maximum number of outstanding requests.
        maximum: usize,
    },
    /// A response referred to no outstanding request.
    #[error("control response has unknown correlation ID {correlation_id}")]
    UnknownCorrelation {
        /// Unknown response correlation ID.
        correlation_id: u64,
    },
    /// A zero message ID was supplied where a request ID is required.
    #[error("control request message ID must be non-zero")]
    ZeroCorrelation,
}
