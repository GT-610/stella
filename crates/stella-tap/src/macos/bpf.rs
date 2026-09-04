//! Complete-frame BPF receive path with strict batch parsing.

use std::{collections::VecDeque, ffi::CString, io, mem::size_of, os::fd::OwnedFd};

use super::{interrupt::Interrupt, sys};

const REQUESTED_BUFFER_LENGTH: usize = 128 * 1024;
const MAX_BPF_DEVICES: usize = 5_000;
const HEADER_LENGTH: usize = size_of::<libc::bpf_hdr>();

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
        if buffer_length < HEADER_LENGTH + 14 {
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
        if remaining < HEADER_LENGTH {
            return Err(invalid_batch("truncated BPF header"));
        }
        // SAFETY: `remaining` covers a complete header; unaligned reads are required for BPF records.
        let header =
            unsafe { std::ptr::read_unaligned(batch.as_ptr().add(offset).cast::<libc::bpf_hdr>()) };
        let header_length = usize::from(header.bh_hdrlen);
        let captured_length = header.bh_caplen as usize;
        let original_length = header.bh_datalen as usize;
        if header_length < HEADER_LENGTH {
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

        let record_length = header_length
            .checked_add(captured_length)
            .ok_or_else(|| invalid_batch("BPF record length overflow"))?;
        let step = record_length
            .checked_add(3)
            .map(|length| length & !3)
            .ok_or_else(|| invalid_batch("BPF alignment overflow"))?;
        if step < HEADER_LENGTH || offset.checked_add(step).is_none() {
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

fn invalid_batch(reason: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, reason)
}

#[cfg(test)]
mod tests {
    use std::{collections::VecDeque, mem::size_of};

    use super::parse_batch;

    fn record(frame: &[u8], captured_length: Option<u32>) -> Vec<u8> {
        // SAFETY: all-zero is a valid test value for the timestamp fields.
        let mut header: libc::bpf_hdr = unsafe { std::mem::zeroed() };
        header.bh_hdrlen = u16::try_from(size_of::<libc::bpf_hdr>()).expect("header fits u16");
        let frame_length = u32::try_from(frame.len()).expect("test frame length fits u32");
        header.bh_caplen = captured_length.unwrap_or(frame_length);
        header.bh_datalen = frame_length;
        let step = (usize::from(header.bh_hdrlen) + frame.len() + 3) & !3;
        let mut output = vec![0_u8; step];
        // SAFETY: output starts with enough initialized storage for an unaligned header write.
        unsafe {
            std::ptr::write_unaligned(output.as_mut_ptr().cast::<libc::bpf_hdr>(), header);
        }
        let start = usize::from(header.bh_hdrlen);
        output[start..start + frame.len()].copy_from_slice(frame);
        output
    }

    #[test]
    fn parses_every_frame_from_one_bpf_batch() {
        let first = vec![0x11; 60];
        let second = vec![0x22; 4_096];
        let mut batch = record(&first, None);
        batch.extend(record(&second, None));
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
        assert!(parse_batch(&record(&[0_u8; 60], Some(59)), &mut frames).is_err());

        let mut malformed = record(&[0_u8; 60], None);
        malformed.truncate(malformed.len() - 1);
        assert!(parse_batch(&malformed, &mut frames).is_err());
    }
}
