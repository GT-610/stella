//! Bounded asynchronous control-record I/O.

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use stella_proto::{
    decode_control_record_length, encode_control_record_length, ControlMessageView,
    CONTROL_RECORD_PREFIX_LENGTH,
};

use crate::{ControlError, OwnedControlMessage};

/// Reads complete owned control records from an ordered asynchronous stream.
pub struct RecordReader<R> {
    inner: R,
    prefix: [u8; CONTROL_RECORD_PREFIX_LENGTH],
    prefix_read: usize,
    bytes: Vec<u8>,
    record_read: usize,
}

impl<R> std::fmt::Debug for RecordReader<R> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RecordReader")
            .field("prefix_read", &self.prefix_read)
            .field("record_read", &self.record_read)
            .finish_non_exhaustive()
    }
}

impl<R> RecordReader<R>
where
    R: AsyncRead + Unpin,
{
    /// Wraps an ordered asynchronous byte stream.
    #[must_use]
    pub const fn new(inner: R) -> Self {
        Self {
            inner,
            prefix: [0; CONTROL_RECORD_PREFIX_LENGTH],
            prefix_read: 0,
            bytes: Vec::new(),
            record_read: 0,
        }
    }

    /// Reads and validates the next complete message.
    ///
    /// `Ok(None)` means EOF occurred exactly between records. EOF after any
    /// prefix or body byte is reported as truncation. Cancelling this future
    /// retains progress; resume using the same reader. Errors are terminal for
    /// the carrier. Debug output never includes partially read credentials.
    ///
    /// # Errors
    ///
    /// Returns [`ControlError`] for I/O failure, truncated input, an invalid
    /// declared length, allocation failure, or an invalid control message.
    pub async fn read_message(&mut self) -> Result<Option<OwnedControlMessage>, ControlError> {
        read_until_full(&mut self.inner, &mut self.prefix, &mut self.prefix_read).await?;
        if self.prefix_read == 0 {
            return Ok(None);
        }
        if self.prefix_read != CONTROL_RECORD_PREFIX_LENGTH {
            return Err(ControlError::TruncatedPrefix {
                read: self.prefix_read,
            });
        }
        if self.bytes.is_empty() {
            let length = decode_control_record_length(&self.prefix)?;
            self.bytes
                .try_reserve_exact(length)
                .map_err(|_| ControlError::AllocationFailed { requested: length })?;
            self.bytes.resize(length, 0);
        }
        read_until_full(&mut self.inner, &mut self.bytes, &mut self.record_read).await?;
        if self.record_read != self.bytes.len() {
            return Err(ControlError::TruncatedRecord {
                expected: self.bytes.len(),
                read: self.record_read,
            });
        }
        ControlMessageView::decode(&self.bytes)?;
        self.prefix_read = 0;
        self.record_read = 0;
        Ok(Some(OwnedControlMessage::from_validated_bytes(
            std::mem::take(&mut self.bytes),
        )))
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

async fn read_until_full<R>(
    reader: &mut R,
    output: &mut [u8],
    read: &mut usize,
) -> Result<(), std::io::Error>
where
    R: AsyncRead + Unpin,
{
    while *read < output.len() {
        let count = reader.read(&mut output[*read..]).await?;
        if count == 0 {
            break;
        }
        *read += count;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::future::Future;
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
    async fn cancellation_at_every_byte_preserves_two_record_boundaries() {
        let message = join_message(1);
        let mut prefix = [0; 4];
        encode_control_record_length(message.len(), &mut prefix).expect("length");
        let wire = [prefix.as_slice(), message.as_bytes()].concat();
        let (mut sender, receiver) = duplex(wire.len() * 2);
        let mut reader = RecordReader::new(receiver);
        for byte in &wire[..wire.len() - 1] {
            sender.write_all(&[*byte]).await.expect("partial write");
            let mut future = std::pin::pin!(reader.read_message());
            std::future::poll_fn(|cx| {
                assert!(future.as_mut().poll(cx).is_pending());
                std::task::Poll::Ready(())
            })
            .await;
        }
        sender
            .write_all(&wire[wire.len() - 1..])
            .await
            .expect("last byte");
        sender.write_all(&wire).await.expect("next record");
        assert_eq!(
            reader.read_message().await.expect("first"),
            Some(message.clone())
        );
        assert_eq!(reader.read_message().await.expect("second"), Some(message));
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
