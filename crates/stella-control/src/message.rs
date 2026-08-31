//! Owned control messages and canonical construction.

use std::fmt;

use stella_proto::{
    control_fields_encoded_len, encode_control_message, ControlFieldRef, ControlFieldType,
    ControlHeader, ControlMessageType, ControlMessageView, ProtocolVersion, CONTROL_HEADER_LENGTH,
    MAX_CONTROL_RECORD_LENGTH,
};

use crate::ControlError;

#[derive(Eq, PartialEq)]
struct OwnedControlField {
    field_type: ControlFieldType,
    value: Vec<u8>,
}

impl OwnedControlField {
    fn new(field_type: ControlFieldType, value: &[u8]) -> Result<Self, ControlError> {
        ControlFieldRef::new(field_type, value)?;
        let mut owned = Vec::new();
        owned
            .try_reserve_exact(value.len())
            .map_err(|_| ControlError::AllocationFailed {
                requested: value.len(),
            })?;
        owned.extend_from_slice(value);
        Ok(Self {
            field_type,
            value: owned,
        })
    }

    fn as_ref(&self) -> Result<ControlFieldRef<'_>, ControlError> {
        Ok(ControlFieldRef::new(self.field_type, &self.value)?)
    }
}

impl fmt::Debug for OwnedControlField {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("OwnedControlField")
            .field("field_type", &self.field_type)
            .field("value_length", &self.value.len())
            .finish_non_exhaustive()
    }
}

/// Builder for one negotiated control message with owned field bytes.
///
/// Fields are not reordered. Callers must add them in strictly increasing
/// numeric type order, and the protocol codec validates required and optional
/// fields when [`crate::OutboundSequence::build`] is called.
#[derive(Debug)]
pub struct MessageBuilder {
    version: ProtocolVersion,
    message_type: ControlMessageType,
    correlation_id: u64,
    fields: Vec<OwnedControlField>,
}

impl MessageBuilder {
    /// Starts a message with no fields and correlation ID zero.
    #[must_use]
    pub const fn new(message_type: ControlMessageType) -> Self {
        Self {
            version: ProtocolVersion::CURRENT,
            message_type,
            correlation_id: 0,
            fields: Vec::new(),
        }
    }

    /// Selects the already negotiated operational protocol version.
    ///
    /// Version 0.1 remains the default. The immutable `SERVER_HELLO`
    /// negotiation envelope always uses version bytes `0.0`.
    #[must_use]
    pub const fn with_version(mut self, version: ProtocolVersion) -> Self {
        self.version = version;
        self
    }

    /// Sets the triggering request ID for a direct response.
    #[must_use]
    pub const fn with_correlation(mut self, correlation_id: u64) -> Self {
        self.correlation_id = correlation_id;
        self
    }

    /// Copies and validates one field value into the builder.
    ///
    /// Diagnostics expose only field type and length, never field contents.
    ///
    /// # Errors
    ///
    /// Returns [`ControlError`] when the registered field value is invalid or
    /// its owned storage cannot be allocated.
    pub fn push_field(
        &mut self,
        field_type: ControlFieldType,
        value: &[u8],
    ) -> Result<(), ControlError> {
        let field = OwnedControlField::new(field_type, value)?;
        self.fields
            .try_reserve(1)
            .map_err(|_| ControlError::AllocationFailed {
                requested: self.fields.len().saturating_add(1),
            })?;
        self.fields.push(field);
        Ok(())
    }

    pub(crate) fn build_with_id(
        self,
        message_id: u64,
    ) -> Result<OwnedControlMessage, ControlError> {
        let mut field_refs = Vec::new();
        field_refs
            .try_reserve_exact(self.fields.len())
            .map_err(|_| ControlError::AllocationFailed {
                requested: self.fields.len(),
            })?;
        for field in &self.fields {
            field_refs.push(field.as_ref()?);
        }
        let body_length = control_fields_encoded_len(&field_refs)?;
        let record_length = CONTROL_HEADER_LENGTH
            .checked_add(body_length)
            .ok_or(ControlError::LengthOverflow)?;
        if record_length > MAX_CONTROL_RECORD_LENGTH {
            return Err(ControlError::MessageTooLarge {
                actual: record_length,
                maximum: MAX_CONTROL_RECORD_LENGTH,
            });
        }
        let body_length = u32::try_from(body_length).map_err(|_| ControlError::LengthOverflow)?;
        let version = if self.message_type == ControlMessageType::ServerHello {
            ProtocolVersion { major: 0, minor: 0 }
        } else {
            self.version
        };
        let header = ControlHeader {
            version,
            message_type: self.message_type,
            flags: 0,
            header_length: u16::try_from(CONTROL_HEADER_LENGTH).map_err(|_| {
                ControlError::AllocationFailed {
                    requested: CONTROL_HEADER_LENGTH,
                }
            })?,
            body_length,
            message_id,
            correlation_id: self.correlation_id,
        };

        let mut bytes = Vec::new();
        bytes
            .try_reserve_exact(record_length)
            .map_err(|_| ControlError::AllocationFailed {
                requested: record_length,
            })?;
        bytes.resize(record_length, 0);
        let encoded = encode_control_message(header, &[], &field_refs, &mut bytes)?;
        bytes.truncate(encoded);
        OwnedControlMessage::new(bytes)
    }
}

/// Owned and fully validated control message without its four-byte prefix.
#[derive(Clone, Eq, PartialEq)]
pub struct OwnedControlMessage {
    bytes: Vec<u8>,
}

impl OwnedControlMessage {
    /// Validates and takes ownership of one complete control message body.
    ///
    /// # Errors
    ///
    /// Returns [`ControlError`] when the record violates any control codec
    /// invariant.
    pub fn new(bytes: Vec<u8>) -> Result<Self, ControlError> {
        ControlMessageView::decode(&bytes)?;
        Ok(Self { bytes })
    }

    /// Borrows the exact encoded message bytes without the outer prefix.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Recreates a validated borrowed view into this owned message.
    ///
    /// # Errors
    ///
    /// Returns [`ControlError`] if memory corruption or an implementation bug
    /// has invalidated the stored bytes.
    pub fn view(&self) -> Result<ControlMessageView<'_>, ControlError> {
        Ok(ControlMessageView::decode(&self.bytes)?)
    }

    /// Returns the decoded fixed header.
    ///
    /// # Errors
    ///
    /// Returns [`ControlError`] if the internally stored message is invalid.
    pub fn header(&self) -> Result<ControlHeader, ControlError> {
        Ok(self.view()?.header())
    }

    /// Returns the encoded message length without the outer prefix.
    #[must_use]
    pub fn len(&self) -> usize {
        self.bytes.len()
    }

    /// Returns whether this message has no encoded bytes.
    ///
    /// A successfully constructed message is never empty; this method is
    /// supplied alongside [`Self::len`] for conventional collection APIs.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }

    pub(crate) fn from_validated_bytes(bytes: Vec<u8>) -> Self {
        Self { bytes }
    }
}

impl fmt::Debug for OwnedControlMessage {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let header = ControlMessageView::decode(&self.bytes)
            .map(|view| view.header())
            .ok();
        formatter
            .debug_struct("OwnedControlMessage")
            .field("header", &header)
            .field("encoded_length", &self.bytes.len())
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use stella_proto::{ControlFieldType, ControlMessageType, ProtocolVersion};

    use super::MessageBuilder;
    use crate::OutboundSequence;

    #[test]
    fn builder_owns_fields_and_redacts_diagnostics() {
        let token = [0x5a; 32];
        let mut builder = MessageBuilder::new(ControlMessageType::JoinRequest);
        builder
            .push_field(ControlFieldType::NetworkId, &[1; 16])
            .expect("valid network ID");
        builder
            .push_field(ControlFieldType::JoinToken, &token)
            .expect("valid join token");
        let diagnostics = format!("{builder:?}");
        assert!(!diagnostics.contains("5a"));

        let message = OutboundSequence::new()
            .build(builder)
            .expect("valid join request");
        let header = message.header().expect("stored message remains valid");
        assert_eq!(header.message_id, 1);
        assert_eq!(header.message_type, ControlMessageType::JoinRequest);
        assert!(!message.is_empty());
    }

    #[test]
    fn codec_rejects_out_of_order_fields() {
        let mut builder = MessageBuilder::new(ControlMessageType::JoinRequest);
        builder
            .push_field(ControlFieldType::JoinToken, &[2; 32])
            .expect("valid join token");
        builder
            .push_field(ControlFieldType::NetworkId, &[1; 16])
            .expect("valid network ID");
        let mut sequence = OutboundSequence::new();
        assert!(sequence.build(builder).is_err());

        let mut valid = MessageBuilder::new(ControlMessageType::JoinRequest);
        valid
            .push_field(ControlFieldType::NetworkId, &[1; 16])
            .expect("valid network ID");
        let message = sequence
            .build(valid)
            .expect("failed construction did not consume an ID");
        assert_eq!(message.header().expect("valid message").message_id, 1);
    }

    #[test]
    fn builder_uses_explicit_negotiated_version_for_connectivity_messages() {
        let mut builder = MessageBuilder::new(ControlMessageType::ConnectivityUpdate)
            .with_version(ProtocolVersion::V0_2);
        builder
            .push_field(ControlFieldType::NetworkId, &[1; 16])
            .expect("valid network ID");
        let message = OutboundSequence::new()
            .build(builder)
            .expect("version 0.2 connectivity withdrawal");
        assert_eq!(
            message.header().expect("valid message").version,
            ProtocolVersion::V0_2
        );

        let mut unsupported = MessageBuilder::new(ControlMessageType::ConnectivityUpdate);
        unsupported
            .push_field(ControlFieldType::NetworkId, &[1; 16])
            .expect("valid network ID");
        assert!(OutboundSequence::new().build(unsupported).is_err());
    }
}
