//! Four-byte-aligned data-plane header extensions.

use crate::{cursor::ReadCursor, cursor::WriteCursor, CodecError};

const EXTENSION_PREFIX_LENGTH: usize = 4;
const CRITICAL_EXTENSION_BIT: u16 = 0x8000;

/// A borrowed Stella header extension value.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ExtensionRef<'a> {
    extension_type: u16,
    value: &'a [u8],
}

impl<'a> ExtensionRef<'a> {
    /// Creates an encodable version 0.1 non-critical extension.
    ///
    /// No extension semantics are registered in version 0.1, so critical
    /// extension types are rejected.
    ///
    /// # Errors
    ///
    /// Returns [`CodecError`] for type zero, a critical type, or a value that
    /// cannot fit the 16-bit wire length.
    pub fn new(extension_type: u16, value: &'a [u8]) -> Result<Self, CodecError> {
        validate_extension_type(extension_type, 0)?;
        u16::try_from(value.len()).map_err(|_| CodecError::LengthMismatch {
            field: "extension value",
            expected: usize::from(u16::MAX),
            actual: value.len(),
        })?;
        Ok(Self {
            extension_type,
            value,
        })
    }

    /// Returns the complete 16-bit extension type.
    #[must_use]
    pub const fn extension_type(self) -> u16 {
        self.extension_type
    }

    /// Returns whether the critical bit is set.
    #[must_use]
    pub const fn is_critical(self) -> bool {
        self.extension_type & CRITICAL_EXTENSION_BIT != 0
    }

    /// Borrows the extension value without its prefix or padding.
    #[must_use]
    pub const fn value(self) -> &'a [u8] {
        self.value
    }

    /// Returns the encoded prefix, value, and padding length.
    ///
    /// # Errors
    ///
    /// Returns [`CodecError::IntegerOverflow`] if the platform cannot
    /// represent the aligned encoded length.
    pub fn encoded_len(self) -> Result<usize, CodecError> {
        padded_extension_length(self.value.len())
    }
}

/// Iterator over an extension block that has already passed validation.
#[derive(Clone, Debug)]
pub struct ExtensionIter<'a> {
    bytes: &'a [u8],
    position: usize,
}

impl<'a> ExtensionIter<'a> {
    pub(crate) const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, position: 0 }
    }

    /// Validates an extension block and returns an iterator over its values.
    ///
    /// Offsets in returned errors are relative to the beginning of `bytes`.
    ///
    /// # Errors
    ///
    /// Returns [`CodecError`] when an extension is truncated, has an invalid
    /// type or critical bit, or contains non-zero padding.
    pub fn decode(bytes: &'a [u8]) -> Result<Self, CodecError> {
        validate_extension_block(bytes, 0)?;
        Ok(Self::new(bytes))
    }
}

impl<'a> Iterator for ExtensionIter<'a> {
    type Item = ExtensionRef<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        let prefix_end = self.position.checked_add(EXTENSION_PREFIX_LENGTH)?;
        let prefix = self.bytes.get(self.position..prefix_end)?;
        let extension_type = u16::from_be_bytes([prefix[0], prefix[1]]);
        let value_length = usize::from(u16::from_be_bytes([prefix[2], prefix[3]]));
        let value_end = prefix_end.checked_add(value_length)?;
        let value = self.bytes.get(prefix_end..value_end)?;
        let encoded_length = padded_extension_length(value_length).ok()?;
        self.position = self.position.checked_add(encoded_length)?;
        Some(ExtensionRef {
            extension_type,
            value,
        })
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        let remaining = self.bytes.len().saturating_sub(self.position);
        (0, Some(remaining / EXTENSION_PREFIX_LENGTH))
    }
}

impl std::iter::FusedIterator for ExtensionIter<'_> {}

pub(crate) fn validate_extension_block(bytes: &[u8], base_offset: usize) -> Result<(), CodecError> {
    let mut cursor = ReadCursor::new(bytes, base_offset);
    while cursor.position() < bytes.len() {
        let extension_offset = base_offset.saturating_add(cursor.position());
        let extension_type = cursor.read_u16("extension type")?;
        let value_length = usize::from(cursor.read_u16("extension length")?);
        validate_extension_type(extension_type, extension_offset)?;
        let _value = cursor.read_slice(value_length, "extension value")?;
        let encoded_length = padded_extension_length(value_length)?;
        let padding_length = encoded_length
            .checked_sub(EXTENSION_PREFIX_LENGTH + value_length)
            .ok_or(CodecError::IntegerOverflow {
                field: "extension padding",
            })?;
        let padding_offset = base_offset.saturating_add(cursor.position());
        let padding = cursor.read_slice(padding_length, "extension padding")?;
        if padding.iter().any(|byte| *byte != 0) {
            return Err(CodecError::NonZeroReserved {
                field: "extension padding",
                offset: padding_offset,
            });
        }
    }
    Ok(())
}

/// Returns the exact encoded length of an extension sequence.
///
/// # Errors
///
/// Returns [`CodecError::IntegerOverflow`] when the combined aligned length
/// cannot be represented by the platform.
pub fn extensions_encoded_len(extensions: &[ExtensionRef<'_>]) -> Result<usize, CodecError> {
    extensions.iter().try_fold(0_usize, |total, extension| {
        total
            .checked_add(extension.encoded_len()?)
            .ok_or(CodecError::IntegerOverflow {
                field: "extension block",
            })
    })
}

/// Encodes an aligned extension sequence into `output`.
///
/// Padding bytes are always written as zero. The returned value is the number
/// of bytes written; extra output capacity is left unchanged.
///
/// # Errors
///
/// Returns [`CodecError`] when an extension is invalid, length arithmetic
/// overflows, or `output` is too small.
pub fn encode_extensions(
    extensions: &[ExtensionRef<'_>],
    output: &mut [u8],
) -> Result<usize, CodecError> {
    encode_extension_block_at(extensions, output, 0)
}

pub(crate) fn encode_extension_block_at(
    extensions: &[ExtensionRef<'_>],
    output: &mut [u8],
    base_offset: usize,
) -> Result<usize, CodecError> {
    let required = extensions_encoded_len(extensions)?;
    if output.len() < required {
        return Err(CodecError::OutputTooSmall {
            field: "extension block",
            offset: base_offset,
            needed: required,
            remaining: output.len(),
        });
    }

    let mut cursor = WriteCursor::new(output, base_offset);
    for extension in extensions {
        validate_extension_type(
            extension.extension_type,
            base_offset.saturating_add(cursor.position()),
        )?;
        let value_length =
            u16::try_from(extension.value.len()).map_err(|_| CodecError::LengthMismatch {
                field: "extension value",
                expected: usize::from(u16::MAX),
                actual: extension.value.len(),
            })?;
        cursor.write_u16(extension.extension_type, "extension type")?;
        cursor.write_u16(value_length, "extension length")?;
        cursor.write_bytes(extension.value, "extension value")?;
        let padding_length = extension.encoded_len()?.saturating_sub(
            EXTENSION_PREFIX_LENGTH
                .checked_add(extension.value.len())
                .ok_or(CodecError::IntegerOverflow {
                    field: "extension padding",
                })?,
        );
        cursor.write_bytes(&[0_u8; 3][..padding_length], "extension padding")?;
    }
    Ok(cursor.position())
}

fn validate_extension_type(extension_type: u16, offset: usize) -> Result<(), CodecError> {
    if extension_type == 0 {
        return Err(CodecError::InvalidExtensionType { offset });
    }
    if extension_type & CRITICAL_EXTENSION_BIT != 0 {
        return Err(CodecError::UnknownCriticalExtension {
            extension_type,
            offset,
        });
    }
    Ok(())
}

fn padded_extension_length(value_length: usize) -> Result<usize, CodecError> {
    let unpadded =
        EXTENSION_PREFIX_LENGTH
            .checked_add(value_length)
            .ok_or(CodecError::IntegerOverflow {
                field: "extension length",
            })?;
    unpadded
        .checked_add(3)
        .map(|length| length & !3)
        .ok_or(CodecError::IntegerOverflow {
            field: "extension alignment",
        })
}

#[cfg(test)]
mod tests {
    use super::{encode_extensions, validate_extension_block, ExtensionIter, ExtensionRef};
    use crate::CodecError;

    #[test]
    fn extension_block_round_trips_and_zeros_padding() {
        let extensions = [
            ExtensionRef::new(1, &[0xaa]).expect("valid extension"),
            ExtensionRef::new(2, &[0xbb, 0xcc, 0xdd, 0xee]).expect("valid extension"),
        ];
        let mut encoded = [0xff; 16];

        assert_eq!(encode_extensions(&extensions, &mut encoded), Ok(16));
        assert_eq!(
            encoded,
            [0, 1, 0, 1, 0xaa, 0, 0, 0, 0, 2, 0, 4, 0xbb, 0xcc, 0xdd, 0xee]
        );
        assert_eq!(validate_extension_block(&encoded, 104), Ok(()));
        assert_eq!(ExtensionIter::new(&encoded).collect::<Vec<_>>(), extensions);
    }

    #[test]
    fn extensions_reject_zero_critical_truncation_and_nonzero_padding() {
        assert_eq!(
            ExtensionRef::new(0, &[]),
            Err(CodecError::InvalidExtensionType { offset: 0 })
        );
        assert_eq!(
            ExtensionRef::new(0x8001, &[]),
            Err(CodecError::UnknownCriticalExtension {
                extension_type: 0x8001,
                offset: 0,
            })
        );
        assert_eq!(
            validate_extension_block(&[0, 1, 0, 2, 0xaa], 32),
            Err(CodecError::Truncated {
                field: "extension value",
                offset: 36,
                needed: 2,
                remaining: 1,
            })
        );
        assert_eq!(
            validate_extension_block(&[0, 1, 0, 1, 0xaa, 1, 0, 0], 32),
            Err(CodecError::NonZeroReserved {
                field: "extension padding",
                offset: 37,
            })
        );
    }
}
