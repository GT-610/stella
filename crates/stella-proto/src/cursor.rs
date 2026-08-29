use crate::CodecError;

pub(crate) struct ReadCursor<'a> {
    bytes: &'a [u8],
    position: usize,
    base_offset: usize,
}

impl<'a> ReadCursor<'a> {
    pub(crate) const fn new(bytes: &'a [u8], base_offset: usize) -> Self {
        Self {
            bytes,
            position: 0,
            base_offset,
        }
    }

    pub(crate) const fn position(&self) -> usize {
        self.position
    }

    pub(crate) fn read_array<const LENGTH: usize>(
        &mut self,
        field: &'static str,
    ) -> Result<[u8; LENGTH], CodecError> {
        let start = self.position;
        let end = start
            .checked_add(LENGTH)
            .ok_or(CodecError::IntegerOverflow { field })?;
        let remaining = self.bytes.len().saturating_sub(start);
        let source = self.bytes.get(start..end).ok_or(CodecError::Truncated {
            field,
            offset: self.base_offset.saturating_add(start),
            needed: LENGTH,
            remaining,
        })?;
        let mut output = [0_u8; LENGTH];
        output.copy_from_slice(source);
        self.position = end;
        Ok(output)
    }

    pub(crate) fn read_u8(&mut self, field: &'static str) -> Result<u8, CodecError> {
        self.read_array::<1>(field).map(|bytes| bytes[0])
    }

    pub(crate) fn read_u16(&mut self, field: &'static str) -> Result<u16, CodecError> {
        self.read_array(field).map(u16::from_be_bytes)
    }

    pub(crate) fn read_u32(&mut self, field: &'static str) -> Result<u32, CodecError> {
        self.read_array(field).map(u32::from_be_bytes)
    }

    pub(crate) fn read_u64(&mut self, field: &'static str) -> Result<u64, CodecError> {
        self.read_array(field).map(u64::from_be_bytes)
    }

    pub(crate) fn read_slice(
        &mut self,
        length: usize,
        field: &'static str,
    ) -> Result<&'a [u8], CodecError> {
        let start = self.position;
        let end = start
            .checked_add(length)
            .ok_or(CodecError::IntegerOverflow { field })?;
        let remaining = self.bytes.len().saturating_sub(start);
        let output = self.bytes.get(start..end).ok_or(CodecError::Truncated {
            field,
            offset: self.base_offset.saturating_add(start),
            needed: length,
            remaining,
        })?;
        self.position = end;
        Ok(output)
    }
}

pub(crate) struct WriteCursor<'a> {
    bytes: &'a mut [u8],
    position: usize,
    base_offset: usize,
}

impl<'a> WriteCursor<'a> {
    pub(crate) const fn new(bytes: &'a mut [u8], base_offset: usize) -> Self {
        Self {
            bytes,
            position: 0,
            base_offset,
        }
    }

    pub(crate) const fn position(&self) -> usize {
        self.position
    }

    pub(crate) fn write_bytes(
        &mut self,
        value: &[u8],
        field: &'static str,
    ) -> Result<(), CodecError> {
        let start = self.position;
        let end = start
            .checked_add(value.len())
            .ok_or(CodecError::IntegerOverflow { field })?;
        let remaining = self.bytes.len().saturating_sub(start);
        let destination = self
            .bytes
            .get_mut(start..end)
            .ok_or(CodecError::OutputTooSmall {
                field,
                offset: self.base_offset.saturating_add(start),
                needed: value.len(),
                remaining,
            })?;
        destination.copy_from_slice(value);
        self.position = end;
        Ok(())
    }

    pub(crate) fn write_u8(&mut self, value: u8, field: &'static str) -> Result<(), CodecError> {
        self.write_bytes(&[value], field)
    }

    pub(crate) fn write_u16(&mut self, value: u16, field: &'static str) -> Result<(), CodecError> {
        self.write_bytes(&value.to_be_bytes(), field)
    }

    pub(crate) fn write_u32(&mut self, value: u32, field: &'static str) -> Result<(), CodecError> {
        self.write_bytes(&value.to_be_bytes(), field)
    }

    pub(crate) fn write_u64(&mut self, value: u64, field: &'static str) -> Result<(), CodecError> {
        self.write_bytes(&value.to_be_bytes(), field)
    }
}
