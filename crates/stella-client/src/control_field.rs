use stella_control::OwnedControlMessage;
use stella_proto::ControlFieldType;

use crate::ClientError;

pub(crate) fn field_value(
    message: &OwnedControlMessage,
    field: ControlFieldType,
) -> Result<&[u8], ClientError> {
    let view = message.view()?;
    view.fields()
        .find_map(|candidate| (candidate.field_type() == Some(field)).then(|| candidate.value()))
        .ok_or(ClientError::MissingField {
            message_type: view.header().message_type,
            field,
        })
}

pub(crate) fn optional_field_value(
    message: &OwnedControlMessage,
    field: ControlFieldType,
) -> Result<Option<&[u8]>, ClientError> {
    Ok(message
        .view()?
        .fields()
        .find_map(|candidate| (candidate.field_type() == Some(field)).then(|| candidate.value())))
}

pub(crate) fn fixed_array<const N: usize>(
    value: &[u8],
    field: &'static str,
) -> Result<[u8; N], ClientError> {
    value
        .try_into()
        .map_err(|_| ClientError::InvalidFieldWidth { field })
}

pub(crate) fn decode_u16(value: &[u8], field: &'static str) -> Result<u16, ClientError> {
    Ok(u16::from_be_bytes(fixed_array(value, field)?))
}

pub(crate) fn decode_u64(value: &[u8], field: &'static str) -> Result<u64, ClientError> {
    Ok(u64::from_be_bytes(fixed_array(value, field)?))
}
