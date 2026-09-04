//! `AF_NDRV` complete-frame transmission.

use std::{io, os::fd::OwnedFd};

use super::{interrupt::Interrupt, sys};

pub(super) struct NdrvSender {
    fd: OwnedFd,
}

impl NdrvSender {
    pub(super) fn open(interface: &str) -> io::Result<Self> {
        let fd = sys::open_ndrv_socket()?;
        sys::set_nonblocking(&fd)?;
        sys::bind_ndrv(&fd, interface)?;
        Ok(Self { fd })
    }

    pub(super) fn write_frame(&self, frame: &[u8], interrupt: &Interrupt) -> io::Result<usize> {
        loop {
            match sys::poll_interruptible(&self.fd, libc::POLLOUT, interrupt.read_fd())? {
                sys::PollReady::Cancelled => {
                    return Err(io::Error::from(io::ErrorKind::Interrupted));
                }
                sys::PollReady::Io => match sys::write(&self.fd, frame) {
                    Err(error) if error.kind() == io::ErrorKind::WouldBlock => {}
                    result => return result,
                },
            }
        }
    }
}
