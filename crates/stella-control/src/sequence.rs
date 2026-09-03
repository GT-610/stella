//! Per-connection message sequence state.

use crate::{ControlError, MessageBuilder, OwnedControlMessage};

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

#[cfg(test)]
mod tests {
    use stella_proto::{ControlFieldType, ControlMessageType};

    use super::{InboundSequence, OutboundSequence};
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
}
