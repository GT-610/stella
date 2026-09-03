use crate::CodecError;

pub(crate) fn validate_range(
    actual: u64,
    minimum: u64,
    maximum: u64,
    field: &'static str,
) -> Result<(), CodecError> {
    if !(minimum..=maximum).contains(&actual) {
        return Err(CodecError::ValueOutOfRange {
            field,
            actual,
            minimum,
            maximum,
        });
    }
    Ok(())
}
