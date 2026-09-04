//! Versioned, bounded wire format for the local TAP helper.

use std::io::{self, Read, Write};

use crate::TapConfig;

const VERSION: u16 = 1;
const MAX_MESSAGE_LENGTH: usize = 10_240;
const MAX_DIAGNOSTIC_LENGTH: usize = 512;

const OPEN: u8 = 1;
const READ: u8 = 2;
const WRITE: u8 = 3;
const SET_MTU: u8 = 4;
const CLOSE: u8 = 5;
const CANCEL: u8 = 6;
const OPENED: u8 = 0x81;
const OK: u8 = 0x82;
const FRAME: u8 = 0x83;
const ERROR: u8 = 0xff;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum RemoteErrorKind {
    Cancelled,
    DeviceBusy,
    OwnershipConflict,
    Rejected,
}

impl RemoteErrorKind {
    const fn code(self) -> u8 {
        match self {
            Self::Cancelled => 1,
            Self::DeviceBusy => 2,
            Self::OwnershipConflict => 3,
            Self::Rejected => 255,
        }
    }

    fn from_code(code: u8) -> io::Result<Self> {
        match code {
            1 => Ok(Self::Cancelled),
            2 => Ok(Self::DeviceBusy),
            3 => Ok(Self::OwnershipConflict),
            255 => Ok(Self::Rejected),
            _ => Err(invalid("unknown helper error kind")),
        }
    }
}

#[derive(Debug, Eq, PartialEq)]
pub(super) enum ClientMessage {
    Open(TapConfig),
    Read { request_id: u64, capacity: u16 },
    Write { request_id: u64, frame: Vec<u8> },
    SetMtu { request_id: u64, mtu: u16 },
    Close { request_id: u64 },
    Cancel,
}

#[derive(Debug, Eq, PartialEq)]
pub(super) enum ServerMessage {
    Opened {
        mac_address: [u8; 6],
    },
    Ok {
        request_id: u64,
    },
    Frame {
        request_id: u64,
        frame: Vec<u8>,
    },
    Error {
        request_id: u64,
        kind: RemoteErrorKind,
        reason: String,
    },
}

pub(super) fn write_client(writer: &mut impl Write, message: &ClientMessage) -> io::Result<()> {
    let mut payload = header(match message {
        ClientMessage::Open(_) => OPEN,
        ClientMessage::Read { .. } => READ,
        ClientMessage::Write { .. } => WRITE,
        ClientMessage::SetMtu { .. } => SET_MTU,
        ClientMessage::Close { .. } => CLOSE,
        ClientMessage::Cancel => CANCEL,
    });
    match message {
        ClientMessage::Open(config) => {
            push_string(&mut payload, config.name.as_deref().unwrap_or_default())?;
            push_string(
                &mut payload,
                config.peer_name.as_deref().unwrap_or_default(),
            )?;
            push_u16(&mut payload, config.mtu);
            push_u16(&mut payload, config.max_frame_size);
        }
        ClientMessage::Read {
            request_id,
            capacity,
        } => {
            push_u64(&mut payload, *request_id);
            push_u16(&mut payload, *capacity);
        }
        ClientMessage::Write { request_id, frame } => {
            push_u64(&mut payload, *request_id);
            push_bytes(&mut payload, frame)?;
        }
        ClientMessage::SetMtu { request_id, mtu } => {
            push_u64(&mut payload, *request_id);
            push_u16(&mut payload, *mtu);
        }
        ClientMessage::Close { request_id } => push_u64(&mut payload, *request_id),
        ClientMessage::Cancel => {}
    }
    write_packet(writer, &payload)
}

pub(super) fn read_client(reader: &mut impl Read) -> io::Result<ClientMessage> {
    let packet = read_packet(reader)?;
    let mut decoder = Decoder::new(&packet)?;
    let message = match decoder.opcode {
        OPEN => {
            let name = decoder.string()?;
            let peer_name = decoder.string()?;
            ClientMessage::Open(TapConfig {
                name: Some(name),
                peer_name: Some(peer_name),
                mtu: decoder.u16()?,
                max_frame_size: decoder.u16()?,
            })
        }
        READ => ClientMessage::Read {
            request_id: decoder.u64()?,
            capacity: decoder.u16()?,
        },
        WRITE => ClientMessage::Write {
            request_id: decoder.u64()?,
            frame: decoder.bytes()?.to_vec(),
        },
        SET_MTU => ClientMessage::SetMtu {
            request_id: decoder.u64()?,
            mtu: decoder.u16()?,
        },
        CLOSE => ClientMessage::Close {
            request_id: decoder.u64()?,
        },
        CANCEL => ClientMessage::Cancel,
        _ => return Err(invalid("unknown helper request opcode")),
    };
    decoder.finish()?;
    Ok(message)
}

pub(super) fn write_server(writer: &mut impl Write, message: &ServerMessage) -> io::Result<()> {
    let mut payload = header(match message {
        ServerMessage::Opened { .. } => OPENED,
        ServerMessage::Ok { .. } => OK,
        ServerMessage::Frame { .. } => FRAME,
        ServerMessage::Error { .. } => ERROR,
    });
    match message {
        ServerMessage::Opened { mac_address } => payload.extend_from_slice(mac_address),
        ServerMessage::Ok { request_id } => push_u64(&mut payload, *request_id),
        ServerMessage::Frame { request_id, frame } => {
            push_u64(&mut payload, *request_id);
            push_bytes(&mut payload, frame)?;
        }
        ServerMessage::Error {
            request_id,
            kind,
            reason,
        } => {
            push_u64(&mut payload, *request_id);
            payload.push(kind.code());
            let bounded = truncate_utf8(reason, MAX_DIAGNOSTIC_LENGTH);
            push_string(&mut payload, bounded)?;
        }
    }
    write_packet(writer, &payload)
}

pub(super) fn read_server(reader: &mut impl Read) -> io::Result<ServerMessage> {
    let packet = read_packet(reader)?;
    let mut decoder = Decoder::new(&packet)?;
    let message = match decoder.opcode {
        OPENED => {
            let bytes = decoder.take(6)?;
            let mut mac_address = [0_u8; 6];
            mac_address.copy_from_slice(bytes);
            ServerMessage::Opened { mac_address }
        }
        OK => ServerMessage::Ok {
            request_id: decoder.u64()?,
        },
        FRAME => ServerMessage::Frame {
            request_id: decoder.u64()?,
            frame: decoder.bytes()?.to_vec(),
        },
        ERROR => ServerMessage::Error {
            request_id: decoder.u64()?,
            kind: RemoteErrorKind::from_code(decoder.u8()?)?,
            reason: decoder.string()?,
        },
        _ => return Err(invalid("unknown helper response opcode")),
    };
    decoder.finish()?;
    Ok(message)
}

fn header(opcode: u8) -> Vec<u8> {
    let mut payload = Vec::with_capacity(32);
    push_u16(&mut payload, VERSION);
    payload.push(opcode);
    payload
}

fn write_packet(writer: &mut impl Write, payload: &[u8]) -> io::Result<()> {
    if payload.len() > MAX_MESSAGE_LENGTH {
        return Err(invalid("helper message exceeds its size limit"));
    }
    let length = u32::try_from(payload.len()).map_err(io::Error::other)?;
    writer.write_all(&length.to_be_bytes())?;
    writer.write_all(payload)?;
    writer.flush()
}

fn read_packet(reader: &mut impl Read) -> io::Result<Vec<u8>> {
    let mut length = [0_u8; 4];
    reader.read_exact(&mut length)?;
    let length = usize::try_from(u32::from_be_bytes(length)).map_err(io::Error::other)?;
    if !(3..=MAX_MESSAGE_LENGTH).contains(&length) {
        return Err(invalid("helper message has an invalid size"));
    }
    let mut payload = vec![0_u8; length];
    reader.read_exact(&mut payload)?;
    Ok(payload)
}

fn push_u16(output: &mut Vec<u8>, value: u16) {
    output.extend_from_slice(&value.to_be_bytes());
}

fn push_u64(output: &mut Vec<u8>, value: u64) {
    output.extend_from_slice(&value.to_be_bytes());
}

fn push_bytes(output: &mut Vec<u8>, value: &[u8]) -> io::Result<()> {
    let length = u16::try_from(value.len()).map_err(io::Error::other)?;
    push_u16(output, length);
    output.extend_from_slice(value);
    Ok(())
}

fn push_string(output: &mut Vec<u8>, value: &str) -> io::Result<()> {
    push_bytes(output, value.as_bytes())
}

fn truncate_utf8(value: &str, maximum: usize) -> &str {
    if value.len() <= maximum {
        return value;
    }
    let mut end = maximum;
    while !value.is_char_boundary(end) {
        end -= 1;
    }
    &value[..end]
}

struct Decoder<'a> {
    input: &'a [u8],
    offset: usize,
    opcode: u8,
}

impl<'a> Decoder<'a> {
    fn new(input: &'a [u8]) -> io::Result<Self> {
        let mut decoder = Self {
            input,
            offset: 0,
            opcode: 0,
        };
        let version = decoder.u16()?;
        if version != VERSION {
            return Err(invalid("unsupported helper protocol version"));
        }
        decoder.opcode = decoder.u8()?;
        Ok(decoder)
    }

    fn u8(&mut self) -> io::Result<u8> {
        Ok(self.take(1)?[0])
    }

    fn u16(&mut self) -> io::Result<u16> {
        let value: [u8; 2] = self
            .take(2)?
            .try_into()
            .map_err(|_| invalid("invalid 16-bit helper field"))?;
        Ok(u16::from_be_bytes(value))
    }

    fn u64(&mut self) -> io::Result<u64> {
        let value: [u8; 8] = self
            .take(8)?
            .try_into()
            .map_err(|_| invalid("invalid 64-bit helper field"))?;
        Ok(u64::from_be_bytes(value))
    }

    fn bytes(&mut self) -> io::Result<&'a [u8]> {
        let length = usize::from(self.u16()?);
        self.take(length)
    }

    fn string(&mut self) -> io::Result<String> {
        String::from_utf8(self.bytes()?.to_vec()).map_err(|_| invalid("helper string is not UTF-8"))
    }

    fn take(&mut self, length: usize) -> io::Result<&'a [u8]> {
        let end = self
            .offset
            .checked_add(length)
            .ok_or_else(|| invalid("helper field length overflow"))?;
        let value = self
            .input
            .get(self.offset..end)
            .ok_or_else(|| invalid("truncated helper message"))?;
        self.offset = end;
        Ok(value)
    }

    fn finish(self) -> io::Result<()> {
        if self.offset == self.input.len() {
            Ok(())
        } else {
            Err(invalid("helper message has trailing bytes"))
        }
    }
}

fn invalid(reason: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, reason)
}

#[cfg(test)]
mod tests {
    use super::{
        read_client, read_server, write_client, write_server, ClientMessage, RemoteErrorKind,
        ServerMessage,
    };
    use crate::TapConfig;

    #[test]
    fn round_trips_every_helper_message_without_frame_logging() {
        let requests = [
            ClientMessage::Open(TapConfig {
                name: Some("feth100".to_owned()),
                peer_name: Some("feth101".to_owned()),
                mtu: 1_500,
                max_frame_size: 1_514,
            }),
            ClientMessage::Read {
                request_id: 1,
                capacity: 1_514,
            },
            ClientMessage::Write {
                request_id: 2,
                frame: vec![0xab; 60],
            },
            ClientMessage::SetMtu {
                request_id: 3,
                mtu: 1_400,
            },
            ClientMessage::Close { request_id: 4 },
            ClientMessage::Cancel,
        ];
        for request in requests {
            let mut wire = Vec::new();
            write_client(&mut wire, &request).expect("encode request");
            assert_eq!(
                read_client(&mut wire.as_slice()).expect("decode request"),
                request
            );
        }

        let responses = [
            ServerMessage::Opened {
                mac_address: [0x02, 1, 2, 3, 4, 5],
            },
            ServerMessage::Ok { request_id: 1 },
            ServerMessage::Frame {
                request_id: 2,
                frame: vec![0xcd; 60],
            },
            ServerMessage::Error {
                request_id: 3,
                kind: RemoteErrorKind::Rejected,
                reason: "redacted".to_owned(),
            },
        ];
        for response in responses {
            let mut wire = Vec::new();
            write_server(&mut wire, &response).expect("encode response");
            assert_eq!(
                read_server(&mut wire.as_slice()).expect("decode response"),
                response
            );
        }
    }

    #[test]
    fn rejects_unbounded_and_trailing_messages() {
        let mut oversized = (20_000_u32).to_be_bytes().to_vec();
        oversized.extend([0_u8; 3]);
        assert!(read_client(&mut oversized.as_slice()).is_err());

        let mut wire = Vec::new();
        write_client(&mut wire, &ClientMessage::Cancel).expect("encode cancel");
        let length = u32::from_be_bytes(wire[..4].try_into().expect("length prefix"));
        wire[..4].copy_from_slice(&(length + 1).to_be_bytes());
        wire.push(0);
        assert!(read_client(&mut wire.as_slice()).is_err());
    }
}
