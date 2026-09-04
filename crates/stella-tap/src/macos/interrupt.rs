//! Pending-only cancellation backed by a nonblocking self-pipe.

use std::{io, os::fd::OwnedFd, sync::Mutex};

use super::sys;

pub(super) struct Interrupt {
    read: OwnedFd,
    write: OwnedFd,
}

impl Interrupt {
    pub(super) fn new() -> io::Result<Self> {
        let (read, write) = sys::pipe()?;
        Ok(Self { read, write })
    }

    pub(super) fn trigger(&self) -> io::Result<()> {
        sys::signal(&self.write)
    }

    pub(super) fn reset(&self) -> io::Result<()> {
        sys::drain(&self.read)
    }

    pub(super) const fn read_fd(&self) -> &OwnedFd {
        &self.read
    }
}

#[derive(Default)]
pub(super) struct OperationState {
    pub(super) pending: bool,
    pub(super) cancelled: bool,
}

pub(super) struct CancellationState {
    pub(super) event: Interrupt,
    pub(super) operation: Mutex<OperationState>,
}
