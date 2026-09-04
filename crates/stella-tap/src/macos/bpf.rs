//! Complete-frame BPF receive path with strict batch parsing.

use std::{
    collections::VecDeque,
    ffi::CString,
    io,
    mem::{offset_of, size_of},
    os::fd::OwnedFd,
};

use super::{interrupt::Interrupt, sys};

const REQUESTED_BUFFER_LENGTH: usize = 128 * 1024;
const MAX_BPF_DEVICES: usize = 5_000;
const BPF_ALIGNMENT: usize = size_of::<i32>();
const CAPTURED_LENGTH_OFFSET: usize = offset_of!(libc::bpf_hdr, bh_caplen);
const ORIGINAL_LENGTH_OFFSET: usize = offset_of!(libc::bpf_hdr, bh_datalen);
const HEADER_LENGTH_OFFSET: usize = offset_of!(libc::bpf_hdr, bh_hdrlen);
// XNU deliberately excludes the C structure's trailing padding from SIZEOF_BPF_HDR.
const MIN_HEADER_LENGTH: usize = HEADER_LENGTH_OFFSET + size_of::<u16>();

pub(super) struct BpfReceiver {
    fd: OwnedFd,
    batch: Vec<u8>,
    frames: VecDeque<Vec<u8>>,
}

impl BpfReceiver {
    pub(super) fn open(interface: &str) -> io::Result<Self> {
        let fd = open_available_bpf()?;
        sys::set_cloexec(&fd)?;
        sys::set_nonblocking(&fd)?;
        let buffer_length = sys::configure_bpf(&fd, interface, REQUESTED_BUFFER_LENGTH)?;
        if buffer_length < MIN_HEADER_LENGTH + 14 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "BPF returned an unusably small capture buffer",
            ));
        }
        Ok(Self {
            fd,
            batch: vec![0; buffer_length],
            frames: VecDeque::new(),
        })
    }

    pub(super) fn read_frame(
        &mut self,
        output: &mut [u8],
        interrupt: &Interrupt,
    ) -> io::Result<usize> {
        loop {
            if let Some(frame) = self.frames.pop_front() {
                if output.len() < frame.len() {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "BPF frame exceeds receive output",
                    ));
                }
                output[..frame.len()].copy_from_slice(&frame);
                return Ok(frame.len());
            }

            match sys::poll_interruptible(&self.fd, libc::POLLIN, interrupt.read_fd())? {
                sys::PollReady::Cancelled => {
                    return Err(io::Error::from(io::ErrorKind::Interrupted));
                }
                sys::PollReady::Io => match sys::read(&self.fd, &mut self.batch) {
                    Ok(0) => {
                        return Err(io::Error::new(
                            io::ErrorKind::UnexpectedEof,
                            "BPF device returned end of file",
                        ));
                    }
                    Ok(length) => parse_batch(&self.batch[..length], &mut self.frames)?,
                    Err(error) if error.kind() == io::ErrorKind::WouldBlock => {}
                    Err(error) => return Err(error),
                },
            }
        }
    }
}

fn open_available_bpf() -> io::Result<OwnedFd> {
    for index in 0..MAX_BPF_DEVICES {
        let path = CString::new(format!("/dev/bpf{index}")).map_err(io::Error::other)?;
        match sys::open_file(
            path.as_c_str(),
            libc::O_RDWR | libc::O_CLOEXEC | libc::O_NONBLOCK,
        ) {
            Ok(fd) => return Ok(fd),
            Err(error) if error.raw_os_error() == Some(libc::EBUSY) => {}
            Err(error) if error.kind() == io::ErrorKind::NotFound && index != 0 => break,
            Err(error) => return Err(error),
        }
    }
    Err(io::Error::new(
        io::ErrorKind::NotFound,
        "no available BPF device",
    ))
}

fn parse_batch(batch: &[u8], frames: &mut VecDeque<Vec<u8>>) -> io::Result<()> {
    let mut offset = 0_usize;
    while offset < batch.len() {
        let remaining = batch.len() - offset;
        if remaining < MIN_HEADER_LENGTH {
            return Err(invalid_batch("truncated BPF header"));
        }
        let header_length = usize::from(read_u16(batch, offset + HEADER_LENGTH_OFFSET));
        let captured_length = read_u32(batch, offset + CAPTURED_LENGTH_OFFSET) as usize;
        let original_length = read_u32(batch, offset + ORIGINAL_LENGTH_OFFSET) as usize;
        if header_length < MIN_HEADER_LENGTH {
            return Err(invalid_batch("BPF header length is too small"));
        }
        if captured_length == 0 || captured_length != original_length {
            return Err(invalid_batch("BPF returned an empty or truncated frame"));
        }
        let frame_start = offset
            .checked_add(header_length)
            .ok_or_else(|| invalid_batch("BPF frame offset overflow"))?;
        let frame_end = frame_start
            .checked_add(captured_length)
            .ok_or_else(|| invalid_batch("BPF frame length overflow"))?;
        if frame_end > batch.len() {
            return Err(invalid_batch("BPF frame extends beyond its batch"));
        }
        frames.push_back(batch[frame_start..frame_end].to_vec());

        if frame_end == batch.len() {
            offset = batch.len();
            continue;
        }

        let record_length = header_length
            .checked_add(captured_length)
            .ok_or_else(|| invalid_batch("BPF record length overflow"))?;
        let step = record_length
            .checked_add(BPF_ALIGNMENT - 1)
            .map(|length| length & !(BPF_ALIGNMENT - 1))
            .ok_or_else(|| invalid_batch("BPF alignment overflow"))?;
        if step < MIN_HEADER_LENGTH || offset.checked_add(step).is_none() {
            return Err(invalid_batch("BPF record cannot advance"));
        }
        let next = offset + step;
        if next > batch.len() {
            return Err(invalid_batch("BPF alignment extends beyond its batch"));
        }
        offset = next;
    }
    if frames.is_empty() {
        return Err(invalid_batch("BPF batch contained no frames"));
    }
    Ok(())
}

fn read_u16(batch: &[u8], offset: usize) -> u16 {
    let mut bytes = [0_u8; size_of::<u16>()];
    bytes.copy_from_slice(&batch[offset..offset + size_of::<u16>()]);
    u16::from_ne_bytes(bytes)
}

fn read_u32(batch: &[u8], offset: usize) -> u32 {
    let mut bytes = [0_u8; size_of::<u32>()];
    bytes.copy_from_slice(&batch[offset..offset + size_of::<u32>()]);
    u32::from_ne_bytes(bytes)
}

fn invalid_batch(reason: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, reason)
}

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;

    use super::{
        parse_batch, BPF_ALIGNMENT, CAPTURED_LENGTH_OFFSET, HEADER_LENGTH_OFFSET,
        MIN_HEADER_LENGTH, ORIGINAL_LENGTH_OFFSET,
    };

    fn record(frame: &[u8], captured_length: Option<u32>, trailing_padding: bool) -> Vec<u8> {
        let frame_length = u32::try_from(frame.len()).expect("test frame length fits u32");
        let record_length = MIN_HEADER_LENGTH + frame.len();
        let output_length = if trailing_padding {
            (record_length + BPF_ALIGNMENT - 1) & !(BPF_ALIGNMENT - 1)
        } else {
            record_length
        };
        let mut output = vec![0_u8; output_length];
        output[CAPTURED_LENGTH_OFFSET..CAPTURED_LENGTH_OFFSET + 4]
            .copy_from_slice(&captured_length.unwrap_or(frame_length).to_ne_bytes());
        output[ORIGINAL_LENGTH_OFFSET..ORIGINAL_LENGTH_OFFSET + 4]
            .copy_from_slice(&frame_length.to_ne_bytes());
        output[HEADER_LENGTH_OFFSET..HEADER_LENGTH_OFFSET + 2].copy_from_slice(
            &u16::try_from(MIN_HEADER_LENGTH)
                .expect("header fits u16")
                .to_ne_bytes(),
        );
        output[MIN_HEADER_LENGTH..MIN_HEADER_LENGTH + frame.len()].copy_from_slice(frame);
        output
    }

    #[test]
    fn accepts_xnu_header_without_c_structure_tail_padding() {
        assert!(MIN_HEADER_LENGTH < std::mem::size_of::<libc::bpf_hdr>());
        let frame = vec![0x33; 60];
        let mut frames = VecDeque::new();
        parse_batch(&record(&frame, None, false), &mut frames)
            .expect("parse XNU-sized unpadded final record");
        assert_eq!(frames.pop_front().as_deref(), Some(frame.as_slice()));
        assert!(frames.is_empty());
    }

    fn padded_record(frame: &[u8], captured_length: Option<u32>) -> Vec<u8> {
        record(frame, captured_length, true)
    }

    fn malformed_record(frame: &[u8], captured_length: Option<u32>) -> Vec<u8> {
        let mut output = padded_record(frame, captured_length);
        if output.len() == MIN_HEADER_LENGTH + frame.len() {
            output.push(0);
        }
        output
    }

    #[test]
    fn parses_every_frame_from_one_bpf_batch() {
        let first = vec![0x11; 60];
        let second = vec![0x22; 4_096];
        let mut batch = padded_record(&first, None);
        batch.extend(record(&second, None, false));
        let mut frames = VecDeque::new();
        parse_batch(&batch, &mut frames).expect("parse complete batch");
        assert_eq!(frames.pop_front().as_deref(), Some(first.as_slice()));
        assert_eq!(frames.pop_front().as_deref(), Some(second.as_slice()));
        assert!(frames.is_empty());
    }

    #[test]
    fn rejects_truncated_and_malformed_bpf_records() {
        let mut frames = VecDeque::new();
        assert!(parse_batch(&[0_u8; 3], &mut frames).is_err());
        assert!(parse_batch(&padded_record(&[0_u8; 60], Some(59)), &mut frames).is_err());

        let mut malformed = malformed_record(&[0_u8; 60], None);
        malformed.truncate(malformed.len() - 1);
        assert!(parse_batch(&malformed, &mut frames).is_err());
    }
}
