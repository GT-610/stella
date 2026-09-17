//! Bounded TURN record framing over reliable byte streams.

use stella_proto::decode_turn_stream_record_length;
use thiserror::Error;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

const TURN_STREAM_PREFIX_LENGTH: usize = 4;

/// Largest framed TURN record accepted by the reference stream transport.
///
/// This is the larger of a maximally aligned STUN record and a `ChannelData`
/// record with the full 16-bit payload plus stream padding.
pub const MAX_TURN_STREAM_RECORD_SIZE: usize = 65_552;

/// Failure while reading or writing one complete TURN stream record.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum TurnStreamError {
    /// A configured record bound cannot contain TURN's smallest prefix.
    #[error("TURN stream record limit {actual} is outside {minimum} through {maximum}")]
    InvalidLimit {
        /// Rejected configured limit.
        actual: usize,
        /// Smallest accepted limit.
        minimum: usize,
        /// Absolute protocol framing limit.
        maximum: usize,
    },
    /// A declared record exceeds the configured allocation bound.
    #[error("TURN stream record length {actual} exceeds configured maximum {maximum}")]
    RecordTooLarge {
        /// Declared complete record length.
        actual: usize,
        /// Configured complete record limit.
        maximum: usize,
    },
    /// A caller attempted to write a partial or concatenated record.
    #[error("TURN stream write contains {actual} bytes but declares {expected}")]
    RecordLengthMismatch {
        /// Length derived from the record prefix.
        expected: usize,
        /// Actual supplied slice length.
        actual: usize,
    },
    /// The TURN record prefix is structurally invalid.
    #[error(transparent)]
    Codec(#[from] stella_proto::CodecError),
    /// Reading a complete record from the underlying stream failed.
    #[error("unable to read TURN stream record")]
    Read {
        /// Underlying byte-stream failure.
        #[source]
        source: std::io::Error,
    },
    /// Writing a complete record to the underlying stream failed.
    #[error("unable to write TURN stream record")]
    Write {
        /// Underlying byte-stream failure.
        #[source]
        source: std::io::Error,
    },
}

/// Reliable byte stream that preserves exact TURN STUN and `ChannelData` records.
pub struct TurnStream<S> {
    stream: S,
    max_record_size: usize,
    prefix: [u8; TURN_STREAM_PREFIX_LENGTH],
    prefix_read: usize,
    record: Vec<u8>,
    record_read: usize,
}

impl<S> TurnStream<S> {
    /// Wraps one byte stream with a bounded complete-record contract.
    ///
    /// # Errors
    ///
    /// Returns [`TurnStreamError::InvalidLimit`] when `max_record_size` cannot
    /// hold the four-byte prefix or exceeds the protocol framing ceiling.
    pub fn new(stream: S, max_record_size: usize) -> Result<Self, TurnStreamError> {
        if !(TURN_STREAM_PREFIX_LENGTH..=MAX_TURN_STREAM_RECORD_SIZE).contains(&max_record_size) {
            return Err(TurnStreamError::InvalidLimit {
                actual: max_record_size,
                minimum: TURN_STREAM_PREFIX_LENGTH,
                maximum: MAX_TURN_STREAM_RECORD_SIZE,
            });
        }
        Ok(Self {
            stream,
            max_record_size,
            prefix: [0; TURN_STREAM_PREFIX_LENGTH],
            prefix_read: 0,
            record: Vec::new(),
            record_read: 0,
        })
    }

    /// Consumes the framing layer and returns the underlying byte stream.
    #[must_use]
    pub fn into_inner(self) -> S {
        self.stream
    }
}

impl<S> TurnStream<S>
where
    S: AsyncRead + Unpin,
{
    /// Reads exactly one complete TURN stream record.
    ///
    /// The returned bytes retain standard `ChannelData` stream padding. A
    /// subsequent call starts at the next record even when the operating
    /// system supplied several records in one read. Cancellation retains partial
    /// progress in this object; callers must close the carrier after any error.
    ///
    /// # Errors
    ///
    /// Returns [`TurnStreamError`] for malformed prefixes, oversized declared
    /// records, premature EOF, or underlying stream failures.
    pub async fn read_record(&mut self) -> Result<Vec<u8>, TurnStreamError> {
        read_pending(&mut self.stream, &mut self.prefix, &mut self.prefix_read).await?;
        if self.record.is_empty() {
            let length = decode_turn_stream_record_length(&self.prefix)?;
            self.validate_length(length)?;
            self.record = vec![0; length];
            self.record[..TURN_STREAM_PREFIX_LENGTH].copy_from_slice(&self.prefix);
            self.record_read = TURN_STREAM_PREFIX_LENGTH;
        }
        read_pending(&mut self.stream, &mut self.record, &mut self.record_read).await?;
        self.prefix_read = 0;
        self.record_read = 0;
        Ok(std::mem::take(&mut self.record))
    }
}

impl<S> TurnStream<S>
where
    S: AsyncWrite + Unpin,
{
    /// Writes exactly one complete TURN stream record and flushes it.
    ///
    /// # Errors
    ///
    /// Returns [`TurnStreamError`] for short, malformed, oversized, partial,
    /// concatenated, or unwritable records.
    pub async fn write_record(&mut self, record: &[u8]) -> Result<(), TurnStreamError> {
        let prefix = record.get(..TURN_STREAM_PREFIX_LENGTH).ok_or(
            TurnStreamError::RecordLengthMismatch {
                expected: TURN_STREAM_PREFIX_LENGTH,
                actual: record.len(),
            },
        )?;
        let expected = decode_turn_stream_record_length(prefix)?;
        self.validate_length(expected)?;
        if record.len() != expected {
            return Err(TurnStreamError::RecordLengthMismatch {
                expected,
                actual: record.len(),
            });
        }
        self.stream
            .write_all(record)
            .await
            .map_err(|source| TurnStreamError::Write { source })?;
        self.stream
            .flush()
            .await
            .map_err(|source| TurnStreamError::Write { source })
    }
}

impl<S> TurnStream<S> {
    fn validate_length(&self, length: usize) -> Result<(), TurnStreamError> {
        if length > self.max_record_size {
            return Err(TurnStreamError::RecordTooLarge {
                actual: length,
                maximum: self.max_record_size,
            });
        }
        Ok(())
    }
}

async fn read_pending<S: AsyncRead + Unpin>(
    stream: &mut S,
    buffer: &mut [u8],
    read: &mut usize,
) -> Result<(), TurnStreamError> {
    while *read < buffer.len() {
        let count = stream
            .read(&mut buffer[*read..])
            .await
            .map_err(|source| TurnStreamError::Read { source })?;
        if count == 0 {
            return Err(TurnStreamError::Read {
                source: std::io::Error::from(std::io::ErrorKind::UnexpectedEof),
            });
        }
        *read += count;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::future::Future;
    use stella_proto::{
        encode_stun_message, encode_turn_channel_data_stream, StunClass, StunMessageRef,
        StunMessageType, StunMethod, StunTransactionId, TurnChannelNumber,
    };
    use tokio::io::{duplex, AsyncWriteExt};

    use super::{TurnStream, TurnStreamError, MAX_TURN_STREAM_RECORD_SIZE};

    fn binding_request() -> Vec<u8> {
        let message = StunMessageRef {
            message_type: StunMessageType::new(StunMethod::Binding, StunClass::Request),
            transaction_id: StunTransactionId::from_bytes([0x11; 12]),
            attributes: &[],
        };
        let mut encoded = vec![0_u8; 20];
        let length = encode_stun_message(message, &mut encoded).expect("encode Binding request");
        encoded.truncate(length);
        encoded
    }

    fn channel_data() -> Vec<u8> {
        let mut encoded = vec![0_u8; 12];
        let length = encode_turn_channel_data_stream(
            TurnChannelNumber::new(0x4000).expect("channel number"),
            b"abcde",
            &mut encoded,
        )
        .expect("encode stream ChannelData");
        encoded.truncate(length);
        encoded
    }

    #[tokio::test]
    async fn cancelled_reads_preserve_stun_and_channel_boundaries() {
        for record in [binding_request(), channel_data()] {
            let (mut writer, reader) = duplex(128);
            let mut framed = TurnStream::new(reader, 128).expect("framing");
            for byte in &record[..record.len() - 1] {
                writer.write_all(&[*byte]).await.expect("partial byte");
                let mut future = std::pin::pin!(framed.read_record());
                std::future::poll_fn(|cx| {
                    assert!(future.as_mut().poll(cx).is_pending());
                    std::task::Poll::Ready(())
                })
                .await;
            }
            writer
                .write_all(&record[record.len() - 1..])
                .await
                .expect("last byte");
            writer.write_all(&record).await.expect("following record");
            assert_eq!(framed.read_record().await.expect("resumed record"), record);
            assert_eq!(
                framed.read_record().await.expect("following record"),
                record
            );
        }
    }

    #[tokio::test]
    async fn fragmented_and_coalesced_reads_preserve_record_boundaries() {
        let (mut writer, reader) = duplex(128);
        let stun = binding_request();
        let channel = channel_data();
        let expected_stun = stun.clone();
        let expected_channel = channel.clone();
        let writer_task = tokio::spawn(async move {
            writer
                .write_all(&stun[..3])
                .await
                .expect("write prefix fragment");
            writer
                .write_all(&stun[3..])
                .await
                .expect("write STUN suffix");
            writer.write_all(&channel).await.expect("write ChannelData");
        });
        let mut stream = TurnStream::new(reader, 128).expect("create TURN stream");
        assert_eq!(
            stream.read_record().await.expect("read STUN"),
            expected_stun
        );
        assert_eq!(
            stream.read_record().await.expect("read ChannelData"),
            expected_channel
        );
        writer_task.await.expect("writer task");
    }

    #[tokio::test]
    async fn writes_reject_partial_concatenated_and_oversized_records() {
        let (stream, peer) = duplex(128);
        let mut framed = TurnStream::new(stream, 32).expect("create TURN stream");
        let record = binding_request();
        assert!(matches!(
            framed.write_record(&record[..10]).await,
            Err(TurnStreamError::RecordLengthMismatch {
                expected: 20,
                actual: 10
            })
        ));
        let mut concatenated = record.clone();
        concatenated.extend_from_slice(&record);
        assert!(matches!(
            framed.write_record(&concatenated).await,
            Err(TurnStreamError::RecordLengthMismatch {
                expected: 20,
                actual: 40
            })
        ));
        let oversized = channel_data();
        let (small, _peer) = duplex(128);
        let mut framed = TurnStream::new(small, 8).expect("small TURN stream");
        assert!(matches!(
            framed.write_record(&oversized).await,
            Err(TurnStreamError::RecordTooLarge {
                actual: 12,
                maximum: 8
            })
        ));
        drop(peer);
    }

    #[test]
    fn limits_are_bounded_by_the_wire_format() {
        let (stream, _peer) = duplex(1);
        assert!(matches!(
            TurnStream::new(stream, 3),
            Err(TurnStreamError::InvalidLimit { .. })
        ));
        let (stream, _peer) = duplex(1);
        assert!(matches!(
            TurnStream::new(stream, MAX_TURN_STREAM_RECORD_SIZE + 1),
            Err(TurnStreamError::InvalidLimit { .. })
        ));
    }
}
