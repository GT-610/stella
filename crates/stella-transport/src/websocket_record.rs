//! Strict one-message-per-record framing for the Stella TURN WebSocket carrier.

use futures_util::{Sink, SinkExt, Stream, StreamExt};
use stella_proto::{decode_turn_stream_record_length, CodecError};
use thiserror::Error;
use tokio_tungstenite::tungstenite::{protocol::WebSocketConfig, Error as WebSocketError, Message};

use crate::MAX_TURN_STREAM_RECORD_SIZE;

/// Fixed HTTP path for the Stella TURN secure WebSocket carrier.
pub const STELLA_TURN_WEBSOCKET_PATH: &str = "/stella/turn/v1";

/// Required WebSocket subprotocol for Stella TURN records.
pub const STELLA_TURN_WEBSOCKET_SUBPROTOCOL: &str = "stella-turn.v1";

const TURN_RECORD_PREFIX_LENGTH: usize = 4;

/// Failure while validating or carrying one complete TURN WebSocket record.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum WebSocketRecordError {
    /// A configured record ceiling cannot contain a TURN prefix or exceeds the wire limit.
    #[error("TURN WebSocket record limit {actual} is outside {minimum} through {maximum}")]
    InvalidLimit {
        /// Rejected configured limit.
        actual: usize,
        /// Smallest accepted limit.
        minimum: usize,
        /// Largest accepted limit.
        maximum: usize,
    },
    /// WebSocket framing, protocol handling, or underlying I/O failed.
    #[error(transparent)]
    WebSocket(#[from] WebSocketError),
    /// TURN record framing was malformed.
    #[error(transparent)]
    Codec(#[from] CodecError),
    /// The peer closed the WebSocket before another TURN record arrived.
    #[error("TURN WebSocket connection closed")]
    Closed,
    /// Text data is never a TURN record.
    #[error("TURN WebSocket rejected a text message")]
    TextMessage,
    /// An empty binary message cannot contain a TURN record.
    #[error("TURN WebSocket rejected an empty binary message")]
    EmptyRecord,
    /// A complete binary message exceeded the configured record ceiling.
    #[error("TURN WebSocket record length {actual} exceeds configured maximum {maximum}")]
    RecordTooLarge {
        /// Rejected complete record length.
        actual: usize,
        /// Configured complete-record ceiling.
        maximum: usize,
    },
    /// The binary message contains a partial record or bytes after the declared record.
    #[error("TURN WebSocket record declares {expected} bytes but message contains {actual}")]
    RecordLengthMismatch {
        /// Length derived from the TURN prefix.
        expected: usize,
        /// Complete binary message length.
        actual: usize,
    },
    /// `ChannelData` alignment padding must be all zero in the Stella profile.
    #[error("TURN WebSocket ChannelData padding must be zero")]
    NonZeroPadding,
    /// A raw WebSocket frame escaped message reassembly unexpectedly.
    #[error("TURN WebSocket exposed an unexpected raw frame")]
    RawFrame,
}

/// Creates a bounded WebSocket configuration for complete TURN records.
///
/// Compression is not enabled by `tokio-tungstenite`; callers must also reject
/// extension headers during the HTTP upgrade.
///
/// # Errors
///
/// Returns [`WebSocketRecordError::InvalidLimit`] when `max_record_size` is
/// smaller than a TURN prefix or larger than the protocol framing ceiling.
pub fn turn_websocket_config(
    max_record_size: usize,
) -> Result<WebSocketConfig, WebSocketRecordError> {
    validate_limit(max_record_size)?;
    let mut config = WebSocketConfig::default();
    config.max_message_size = Some(max_record_size);
    config.max_frame_size = Some(max_record_size);
    config.accept_unmasked_frames = false;
    Ok(config)
}

/// Reads the next complete binary TURN record, ignoring WebSocket control messages.
///
/// Fragmented binary messages are reassembled by `tokio-tungstenite` before
/// this function validates their exact TURN boundary.
///
/// # Errors
///
/// Returns [`WebSocketRecordError`] for malformed WebSocket or TURN framing,
/// text, empty, oversized, partial, concatenated, or non-canonically padded
/// records, and for connection closure.
pub async fn read_websocket_record<S>(
    stream: &mut S,
    max_record_size: usize,
) -> Result<Vec<u8>, WebSocketRecordError>
where
    S: Stream<Item = Result<Message, WebSocketError>> + Unpin,
{
    validate_limit(max_record_size)?;
    loop {
        let message = stream.next().await.ok_or(WebSocketRecordError::Closed)??;
        match message {
            Message::Binary(record) => {
                validate_record(&record, max_record_size)?;
                return Ok(record.to_vec());
            }
            Message::Text(_) => return Err(WebSocketRecordError::TextMessage),
            Message::Close(_) => return Err(WebSocketRecordError::Closed),
            Message::Ping(_) | Message::Pong(_) => {}
            Message::Frame(_) => return Err(WebSocketRecordError::RawFrame),
        }
    }
}

/// Writes exactly one validated TURN record as one binary WebSocket message.
///
/// # Errors
///
/// Returns [`WebSocketRecordError`] for invalid limits, malformed or oversized
/// TURN records, non-zero `ChannelData` padding, WebSocket framing, or I/O failure.
pub async fn write_websocket_record<S>(
    sink: &mut S,
    record: &[u8],
    max_record_size: usize,
) -> Result<(), WebSocketRecordError>
where
    S: Sink<Message, Error = WebSocketError> + Unpin,
{
    validate_limit(max_record_size)?;
    validate_record(record, max_record_size)?;
    sink.send(Message::Binary(record.to_vec().into())).await?;
    Ok(())
}

fn validate_limit(max_record_size: usize) -> Result<(), WebSocketRecordError> {
    if !(TURN_RECORD_PREFIX_LENGTH..=MAX_TURN_STREAM_RECORD_SIZE).contains(&max_record_size) {
        return Err(WebSocketRecordError::InvalidLimit {
            actual: max_record_size,
            minimum: TURN_RECORD_PREFIX_LENGTH,
            maximum: MAX_TURN_STREAM_RECORD_SIZE,
        });
    }
    Ok(())
}

fn validate_record(record: &[u8], maximum: usize) -> Result<(), WebSocketRecordError> {
    if record.is_empty() {
        return Err(WebSocketRecordError::EmptyRecord);
    }
    if record.len() > maximum {
        return Err(WebSocketRecordError::RecordTooLarge {
            actual: record.len(),
            maximum,
        });
    }
    let prefix = record.get(..TURN_RECORD_PREFIX_LENGTH).ok_or(
        WebSocketRecordError::RecordLengthMismatch {
            expected: TURN_RECORD_PREFIX_LENGTH,
            actual: record.len(),
        },
    )?;
    let expected = decode_turn_stream_record_length(prefix)?;
    if record.len() != expected {
        return Err(WebSocketRecordError::RecordLengthMismatch {
            expected,
            actual: record.len(),
        });
    }
    if prefix[0] & 0xc0 == 0x40 {
        let data_length = usize::from(u16::from_be_bytes([prefix[2], prefix[3]]));
        let unpadded = TURN_RECORD_PREFIX_LENGTH.checked_add(data_length).ok_or(
            CodecError::IntegerOverflow {
                field: "TURN WebSocket ChannelData length",
            },
        )?;
        if record[unpadded..].iter().any(|byte| *byte != 0) {
            return Err(WebSocketRecordError::NonZeroPadding);
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use futures_util::{SinkExt, StreamExt};
    use stella_proto::{
        encode_stun_message, encode_turn_channel_data_stream, StunClass, StunMessageRef,
        StunMessageType, StunMethod, StunTransactionId, TurnChannelNumber,
    };
    use tokio::io::duplex;
    use tokio_tungstenite::{
        tungstenite::{protocol::Role, Message},
        WebSocketStream,
    };

    use super::{
        read_websocket_record, turn_websocket_config, validate_record, write_websocket_record,
        WebSocketRecordError,
    };

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

    #[test]
    fn records_require_exact_lengths_limits_and_zero_padding() {
        let stun = binding_request();
        validate_record(&stun, 64).expect("valid STUN record");
        let channel = channel_data();
        validate_record(&channel, 64).expect("valid ChannelData record");

        assert!(matches!(
            validate_record(&[], 64),
            Err(WebSocketRecordError::EmptyRecord)
        ));
        assert!(matches!(
            validate_record(&stun[..10], 64),
            Err(WebSocketRecordError::RecordLengthMismatch { .. })
        ));
        let mut concatenated = stun.clone();
        concatenated.extend_from_slice(&stun);
        assert!(matches!(
            validate_record(&concatenated, 64),
            Err(WebSocketRecordError::RecordLengthMismatch { .. })
        ));
        assert!(matches!(
            validate_record(&stun, 8),
            Err(WebSocketRecordError::RecordTooLarge { .. })
        ));
        let mut non_zero_padding = channel;
        *non_zero_padding.last_mut().expect("padding byte") = 1;
        assert!(matches!(
            validate_record(&non_zero_padding, 64),
            Err(WebSocketRecordError::NonZeroPadding)
        ));
    }

    #[tokio::test]
    async fn binary_messages_round_trip_while_control_messages_are_skipped() {
        let (client_io, server_io) = duplex(512);
        let config = turn_websocket_config(128).expect("WebSocket config");
        let client = WebSocketStream::from_raw_socket(client_io, Role::Client, Some(config)).await;
        let server = WebSocketStream::from_raw_socket(server_io, Role::Server, Some(config)).await;
        let (mut client_sink, mut client_stream) = client.split();
        let (mut server_sink, mut server_stream) = server.split();
        let expected = binding_request();

        server_sink
            .send(Message::Ping(b"probe".to_vec().into()))
            .await
            .expect("send ping");
        write_websocket_record(&mut server_sink, &expected, 128)
            .await
            .expect("write TURN record");
        assert_eq!(
            read_websocket_record(&mut client_stream, 128)
                .await
                .expect("read TURN record"),
            expected
        );

        client_sink.close().await.expect("close client sink");
        let _close = server_stream.next().await;
    }

    #[tokio::test]
    async fn text_and_empty_binary_messages_are_rejected() {
        let (client_io, server_io) = duplex(512);
        let config = turn_websocket_config(128).expect("WebSocket config");
        let client = WebSocketStream::from_raw_socket(client_io, Role::Client, Some(config)).await;
        let server = WebSocketStream::from_raw_socket(server_io, Role::Server, Some(config)).await;
        let (mut client_sink, _client_stream) = client.split();
        let (_server_sink, mut server_stream) = server.split();

        client_sink
            .send(Message::Text("not TURN".into()))
            .await
            .expect("send text");
        assert!(matches!(
            read_websocket_record(&mut server_stream, 128).await,
            Err(WebSocketRecordError::TextMessage)
        ));
        client_sink
            .send(Message::Binary(Vec::new().into()))
            .await
            .expect("send empty binary");
        assert!(matches!(
            read_websocket_record(&mut server_stream, 128).await,
            Err(WebSocketRecordError::EmptyRecord)
        ));
    }
}
