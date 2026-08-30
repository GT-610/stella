//! Per-connection message sequence and request correlation state.

use std::collections::BTreeSet;

use crate::{ControlError, MessageBuilder, OwnedControlMessage};

/// Protocol maximum outstanding correlated requests per connection.
pub const MAX_CORRELATIONS: usize = 256;

/// Monotonic sender-local message-ID allocator.
#[derive(Debug)]
pub struct OutboundSequence {
    next: Option<u64>,
}

impl OutboundSequence {
    /// Starts a new TLS connection at message ID 1.
    #[must_use]
    pub const fn new() -> Self {
        Self { next: Some(1) }
    }

    /// Builds one message and advances its ID only after encoding succeeds.
    ///
    /// # Errors
    ///
    /// Returns [`ControlError`] when the sequence is exhausted or the builder
    /// cannot produce a valid bounded message. A build failure leaves the next
    /// ID unchanged so no transmitted sequence gap is created.
    pub fn build(&mut self, builder: MessageBuilder) -> Result<OwnedControlMessage, ControlError> {
        let current = self.next.ok_or(ControlError::MessageIdExhausted)?;
        let message = builder.build_with_id(current)?;
        self.next = current.checked_add(1);
        Ok(message)
    }
}

impl Default for OutboundSequence {
    fn default() -> Self {
        Self::new()
    }
}

/// Exact receiver-side message-ID continuity validator.
#[derive(Debug)]
pub struct InboundSequence {
    expected: Option<u64>,
}

impl InboundSequence {
    /// Starts a new TLS connection expecting message ID 1.
    #[must_use]
    pub const fn new() -> Self {
        Self { expected: Some(1) }
    }

    /// Accepts only the exact next message ID and then advances the sequence.
    ///
    /// # Errors
    ///
    /// Returns [`ControlError::MessageIdMismatch`] for a zero, duplicate, gap,
    /// or lower ID, and [`ControlError::MessageIdExhausted`] after accepting
    /// `u64::MAX`.
    pub fn accept(&mut self, actual: u64) -> Result<(), ControlError> {
        let expected = self.expected.ok_or(ControlError::MessageIdExhausted)?;
        if actual != expected {
            return Err(ControlError::MessageIdMismatch { expected, actual });
        }
        self.expected = expected.checked_add(1);
        Ok(())
    }
}

impl Default for InboundSequence {
    fn default() -> Self {
        Self::new()
    }
}

/// Bounded outstanding request IDs awaiting direct responses.
#[derive(Debug)]
pub struct CorrelationTracker {
    outstanding: BTreeSet<u64>,
}

impl CorrelationTracker {
    /// Creates an empty tracker with the protocol limit of 256 requests.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            outstanding: BTreeSet::new(),
        }
    }

    /// Registers a non-zero sent request message ID.
    ///
    /// # Errors
    ///
    /// Returns [`ControlError`] for zero, a duplicate ID, or a full tracker.
    pub fn register(&mut self, message_id: u64) -> Result<(), ControlError> {
        if message_id == 0 {
            return Err(ControlError::ZeroCorrelation);
        }
        if self.outstanding.contains(&message_id) {
            return Err(ControlError::DuplicateCorrelation { message_id });
        }
        if self.outstanding.len() >= MAX_CORRELATIONS {
            return Err(ControlError::CorrelationLimit {
                maximum: MAX_CORRELATIONS,
            });
        }
        self.outstanding.insert(message_id);
        Ok(())
    }

    /// Completes and removes exactly one known response correlation ID.
    ///
    /// # Errors
    ///
    /// Returns [`ControlError::UnknownCorrelation`] for zero, unknown,
    /// duplicate, or already completed responses.
    pub fn complete(&mut self, correlation_id: u64) -> Result<(), ControlError> {
        if !self.outstanding.remove(&correlation_id) {
            return Err(ControlError::UnknownCorrelation { correlation_id });
        }
        Ok(())
    }

    /// Returns the number of outstanding requests.
    #[must_use]
    pub fn len(&self) -> usize {
        self.outstanding.len()
    }

    /// Returns whether no request is awaiting a response.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.outstanding.is_empty()
    }
}

impl Default for CorrelationTracker {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use stella_proto::{ControlFieldType, ControlMessageType};

    use super::{CorrelationTracker, InboundSequence, OutboundSequence, MAX_CORRELATIONS};
    use crate::{ControlError, MessageBuilder};

    fn join_builder() -> MessageBuilder {
        let mut builder = MessageBuilder::new(ControlMessageType::JoinRequest);
        builder
            .push_field(ControlFieldType::NetworkId, &[1; 16])
            .expect("valid network ID");
        builder
    }

    #[test]
    fn outbound_and_inbound_sequences_require_exact_continuity() {
        let mut outbound = OutboundSequence::new();
        let mut inbound = InboundSequence::new();
        for expected in 1..=3 {
            let message = outbound.build(join_builder()).expect("sequence available");
            let message_id = message.header().expect("valid message").message_id;
            assert_eq!(message_id, expected);
            inbound.accept(message_id).expect("exact inbound ID");
        }
        assert!(matches!(
            inbound.accept(5),
            Err(ControlError::MessageIdMismatch {
                expected: 4,
                actual: 5
            })
        ));
        inbound.accept(4).expect("failed ID did not advance state");
    }

    #[test]
    fn outbound_sequence_never_wraps() {
        let mut sequence = OutboundSequence {
            next: Some(u64::MAX),
        };
        let message = sequence
            .build(join_builder())
            .expect("maximum ID may be issued once");
        assert_eq!(
            message.header().expect("valid message").message_id,
            u64::MAX
        );
        assert!(matches!(
            sequence.build(join_builder()),
            Err(ControlError::MessageIdExhausted)
        ));
    }

    #[test]
    fn correlations_are_bounded_and_complete_once() {
        let mut tracker = CorrelationTracker::new();
        for message_id in 1..=u64::try_from(MAX_CORRELATIONS).expect("limit fits u64") {
            tracker.register(message_id).expect("within limit");
        }
        assert_eq!(tracker.len(), MAX_CORRELATIONS);
        assert!(matches!(
            tracker.register(257),
            Err(ControlError::CorrelationLimit {
                maximum: MAX_CORRELATIONS
            })
        ));
        tracker.complete(1).expect("known request");
        assert!(matches!(
            tracker.complete(1),
            Err(ControlError::UnknownCorrelation { correlation_id: 1 })
        ));
        tracker.register(257).expect("capacity was released");
    }

    #[test]
    fn zero_and_duplicate_requests_are_rejected() {
        let mut tracker = CorrelationTracker::new();
        assert!(matches!(
            tracker.register(0),
            Err(ControlError::ZeroCorrelation)
        ));
        tracker.register(7).expect("first request");
        assert!(matches!(
            tracker.register(7),
            Err(ControlError::DuplicateCorrelation { message_id: 7 })
        ));
    }
}
