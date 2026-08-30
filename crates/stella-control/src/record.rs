//! Bounded asynchronous control-record I/O.

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use stella_proto::{
    decode_control_record_length, encode_control_record_length, ControlMessageView,
    CONTROL_RECORD_PREFIX_LENGTH,
};

use crate::{ControlError, OwnedControlMessage};

/// Reads complete owned control records from an ordered asynchronous stream.
#[derive(Debug)]
pub struct RecordReader<R> {
    inner: R,
}

impl<R> RecordReader<R>
where
    R: AsyncRead + Unpin,
{
    /// Wraps an ordered asynchronous byte stream.
    #[must_use]
    pub const fn new(inner: R) -> Self {
        Self { inner }
    }

    /// Reads and validates the next complete message.
    ///
    /// `Ok(None)` means EOF occurred exactly between records. EOF after any
    /// prefix or body byte is reported as truncation.
    ///
    /// # Errors
    ///
    /// Returns [`ControlError`] for I/O failure, truncated input, an invalid
    /// declared length, allocation failure, or an invalid control message.
    pub async fn read_message(&mut self) -> Result<Option<OwnedControlMessage>, ControlError> {
        let mut prefix = [0_u8; CONTROL_RECORD_PREFIX_LENGTH];
        let prefix_read = read_until_full(&mut self.inner, &mut prefix).await?;
        if prefix_read == 0 {
            return Ok(None);
        }
        if prefix_read != CONTROL_RECORD_PREFIX_LENGTH {
            return Err(ControlError::TruncatedPrefix { read: prefix_read });
        }

        let record_length = decode_control_record_length(&prefix)?;
        let mut bytes = Vec::new();
        bytes
            .try_reserve_exact(record_length)
            .map_err(|_| ControlError::AllocationFailed {
                requested: record_length,
            })?;
        bytes.resize(record_length, 0);
        let record_read = read_until_full(&mut self.inner, &mut bytes).await?;
        if record_read != record_length {
            return Err(ControlError::TruncatedRecord {
                expected: record_length,
                read: record_read,
            });
        }
        ControlMessageView::decode(&bytes)?;
        Ok(Some(OwnedControlMessage::from_validated_bytes(bytes)))
    }

    /// Returns the wrapped stream.
    #[must_use]
    pub fn into_inner(self) -> R {
        self.inner
    }
}

/// Writes complete control records to an ordered asynchronous stream.
#[derive(Debug)]
pub struct RecordWriter<W> {
    inner: W,
}

impl<W> RecordWriter<W>
where
    W: AsyncWrite + Unpin,
{
    /// Wraps an ordered asynchronous byte stream.
    #[must_use]
    pub const fn new(inner: W) -> Self {
        Self { inner }
    }

    /// Writes one four-byte prefix followed by one complete message.
    ///
    /// # Errors
    ///
    /// Returns [`ControlError`] when the length cannot be encoded or the
    /// underlying stream fails.
    pub async fn write_message(
        &mut self,
        message: &OwnedControlMessage,
    ) -> Result<(), ControlError> {
        let mut prefix = [0_u8; CONTROL_RECORD_PREFIX_LENGTH];
        encode_control_record_length(message.len(), &mut prefix)?;
        self.inner.write_all(&prefix).await?;
        self.inner.write_all(message.as_bytes()).await?;
        Ok(())
    }

    /// Flushes buffered carrier output.
    ///
    /// # Errors
    ///
    /// Returns [`ControlError`] when the underlying stream cannot flush.
    pub async fn flush(&mut self) -> Result<(), ControlError> {
        self.inner.flush().await?;
        Ok(())
    }

    /// Shuts down the writing side of the carrier.
    ///
    /// # Errors
    ///
    /// Returns [`ControlError`] when the underlying stream cannot shut down.
    pub async fn shutdown(&mut self) -> Result<(), ControlError> {
        self.inner.shutdown().await?;
        Ok(())
    }

    /// Returns the wrapped stream.
    #[must_use]
    pub fn into_inner(self) -> W {
        self.inner
    }
}

async fn read_until_full<R>(reader: &mut R, output: &mut [u8]) -> Result<usize, std::io::Error>
where
    R: AsyncRead + Unpin,
{
    let mut read = 0_usize;
    while read < output.len() {
        let count = reader.read(&mut output[read..]).await?;
        if count == 0 {
            break;
        }
        read = read.saturating_add(count);
    }
    Ok(read)
}

#[cfg(test)]
mod tests {
    use tokio::io::{duplex, AsyncWriteExt};

    use stella_proto::{
        encode_control_record_length, ControlFieldType, ControlMessageType,
        MAX_CONTROL_RECORD_LENGTH,
    };

    use super::{RecordReader, RecordWriter};
    use crate::{ControlError, MessageBuilder, OutboundSequence};

    fn join_message(message_id: u64) -> crate::OwnedControlMessage {
        let mut sequence = OutboundSequence::new();
        let mut message = None;
        for _ in 0..message_id {
            let mut builder = MessageBuilder::new(ControlMessageType::JoinRequest);
            builder
                .push_field(ControlFieldType::NetworkId, &[1; 16])
                .expect("valid network ID");
            message = Some(sequence.build(builder).expect("valid join message"));
        }
        message.expect("message ID is non-zero")
    }

    #[tokio::test]
    async fn fragmented_prefix_and_body_are_reassembled() {
        let message = join_message(1);
        let mut wire = [0_u8; 4];
        encode_control_record_length(message.len(), &mut wire).expect("valid length");
        let mut complete = wire.to_vec();
        complete.extend_from_slice(message.as_bytes());

        let (mut sender, receiver) = duplex(8);
        let writer = tokio::spawn(async move {
            for byte in complete {
                sender.write_all(&[byte]).await.expect("duplex write");
            }
            sender.shutdown().await.expect("duplex shutdown");
        });
        let mut reader = RecordReader::new(receiver);
        let decoded = reader
            .read_message()
            .await
            .expect("fragmented record succeeds")
            .expect("record available");
        assert_eq!(decoded, message);
        assert!(reader.read_message().await.expect("clean EOF").is_none());
        writer.await.expect("writer task succeeds");
    }

    #[tokio::test]
    async fn coalesced_records_remain_distinct() {
        let first = join_message(1);
        let second = join_message(2);
        let capacity = 2 * (4 + first.len());
        let (sender, receiver) = duplex(capacity);
        let mut writer = RecordWriter::new(sender);
        writer.write_message(&first).await.expect("first write");
        writer.write_message(&second).await.expect("second write");
        writer.shutdown().await.expect("writer shutdown");

        let mut reader = RecordReader::new(receiver);
        assert_eq!(
            reader.read_message().await.expect("first read"),
            Some(first)
        );
        assert_eq!(
            reader.read_message().await.expect("second read"),
            Some(second)
        );
        assert!(reader.read_message().await.expect("clean EOF").is_none());
    }

    #[tokio::test]
    async fn truncated_prefix_and_body_are_distinguished() {
        let (mut sender, receiver) = duplex(8);
        sender.write_all(&[0, 0]).await.expect("partial prefix");
        sender.shutdown().await.expect("shutdown");
        let error = RecordReader::new(receiver)
            .read_message()
            .await
            .expect_err("prefix is truncated");
        assert!(matches!(error, ControlError::TruncatedPrefix { read: 2 }));

        let message = join_message(1);
        let (mut sender, receiver) = duplex(message.len());
        let mut prefix = [0_u8; 4];
        encode_control_record_length(message.len(), &mut prefix).expect("valid length");
        sender.write_all(&prefix).await.expect("prefix");
        sender
            .write_all(&message.as_bytes()[..10])
            .await
            .expect("partial body");
        sender.shutdown().await.expect("shutdown");
        let error = RecordReader::new(receiver)
            .read_message()
            .await
            .expect_err("body is truncated");
        assert!(matches!(
            error,
            ControlError::TruncatedRecord { expected, read: 10 } if expected == message.len()
        ));
    }

    #[tokio::test]
    async fn oversized_length_fails_before_body_read() {
        let (mut sender, receiver) = duplex(4);
        let oversized = u32::try_from(MAX_CONTROL_RECORD_LENGTH + 1)
            .expect("protocol maximum fits u32")
            .to_be_bytes();
        sender.write_all(&oversized).await.expect("prefix");
        let error = RecordReader::new(receiver)
            .read_message()
            .await
            .expect_err("oversized record rejected");
        assert!(matches!(error, ControlError::Codec(_)));
    }
}
