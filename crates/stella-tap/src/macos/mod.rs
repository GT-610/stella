//! Stella-owned macOS Layer-2 backend using persistent fake-Ethernet pairs.

mod bpf;
mod feth;
mod helper;
mod interrupt;
mod ndrv;
mod sys;

use std::{
    fmt, io,
    sync::{Arc, Weak},
};

use bpf::BpfReceiver;
use feth::FethPair;
use interrupt::{CancellationState, Interrupt, OperationState};
use ndrv::NdrvSender;

use crate::{
    Result, TapCancellation, TapCancellationHandle, TapConfig, TapDevice, TapError, TapOperation,
};

const MAX_FETH_UNIT: u16 = 9_999;

pub use helper::{
    run_macos_tap_helper, MacosTapHelperConfig, MacosTapProxyCancellation, MacosTapProxyDevice,
    DEFAULT_MACOS_HELPER_SOCKET,
};

/// Cancellation control for one currently open macOS feth pair.
#[derive(Clone)]
pub struct MacosTapCancellation {
    state: Weak<CancellationState>,
}

impl TapCancellation for MacosTapCancellation {
    fn cancel_pending_io(&self) -> Result<()> {
        let Some(state) = self.state.upgrade() else {
            return Ok(());
        };
        let mut operation = lock_operation(&state, TapOperation::CancelIo)?;
        if !operation.pending || operation.cancelled {
            return Ok(());
        }
        operation.cancelled = true;
        if let Err(source) = state.event.trigger() {
            operation.cancelled = false;
            return Err(TapError::io(TapOperation::CancelIo, source));
        }
        Ok(())
    }
}

impl fmt::Debug for MacosTapCancellation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MacosTapCancellation")
            .field("device_open", &self.state.strong_count().ne(&0))
            .finish_non_exhaustive()
    }
}

/// Exclusive complete-frame handle for one persistent macOS feth pair.
pub struct MacosTapDevice {
    receiver: BpfReceiver,
    sender: NdrvSender,
    pair: FethPair,
    state: Arc<CancellationState>,
    config: TapConfig,
    name: String,
    peer_name: String,
    mac_address: [u8; 6],
}

impl MacosTapDevice {
    fn begin_operation(&self, operation: TapOperation) -> Result<()> {
        begin_pending_operation(&self.state, operation)
    }

    fn finish_operation<T>(&self, operation: TapOperation, result: io::Result<T>) -> Result<T> {
        finish_pending_operation(&self.state, operation, result)
    }

    fn read_frame_armed<F>(&mut self, buffer: &mut [u8], armed: F) -> Result<usize>
    where
        F: FnOnce() -> Result<()>,
    {
        self.config.validate_read_buffer(buffer.len())?;
        self.begin_operation(TapOperation::ReadFrame)?;
        if let Err(error) = armed() {
            self.finish_operation(TapOperation::ReadFrame, Ok(()))?;
            return Err(error);
        }
        let result = self.receiver.read_frame(buffer, &self.state.event);
        let length = self.finish_operation(TapOperation::ReadFrame, result)?;
        self.config.validate_frame(length)?;
        Ok(length)
    }

    fn write_frame_armed<F>(&mut self, frame: &[u8], armed: F) -> Result<()>
    where
        F: FnOnce() -> Result<()>,
    {
        self.config.validate_frame(frame.len())?;
        self.begin_operation(TapOperation::WriteFrame)?;
        if let Err(error) = armed() {
            self.finish_operation(TapOperation::WriteFrame, Ok(()))?;
            return Err(error);
        }
        let result = self.sender.write_frame(frame, &self.state.event);
        let written = self.finish_operation(TapOperation::WriteFrame, result)?;
        if written != frame.len() {
            return Err(TapError::PartialFrameWrite {
                expected: frame.len(),
                actual: written,
            });
        }
        Ok(())
    }
}

impl TapDevice for MacosTapDevice {
    fn create(config: &TapConfig) -> Result<Self> {
        config.validate()?;
        let name = required_feth_name(config.name.as_deref(), "name")?;
        let peer_name = required_feth_name(config.peer_name.as_deref(), "peer name")?;
        if name == peer_name {
            return Err(TapError::InvalidConfig {
                field: "peer name",
                reason: "must differ from the host-visible interface name",
            });
        }
        let prepared = feth::PreparedFethPair::prepare(name, peer_name, config.mtu)?;
        let sender = NdrvSender::open(peer_name)
            .map_err(|source| TapError::io(TapOperation::OpenDevice, source))?;
        let receiver = BpfReceiver::open(peer_name)
            .map_err(|source| TapError::io(TapOperation::OpenDevice, source))?;
        let state = Arc::new(CancellationState {
            event: Interrupt::new()
                .map_err(|source| TapError::io(TapOperation::CancelIo, source))?,
            operation: std::sync::Mutex::new(OperationState::default()),
        });
        let mtu = prepared.effective_mtu();
        let mac_address = prepared.mac_address();
        validate_mac_address(mac_address)?;
        let pair = prepared.commit()?;
        let mut effective_config = config.clone();
        effective_config.mtu = mtu;
        Ok(Self {
            receiver,
            sender,
            pair,
            state,
            config: effective_config,
            name: name.to_owned(),
            peer_name: peer_name.to_owned(),
            mac_address,
        })
    }

    fn cancellation_handle(&self) -> TapCancellationHandle {
        Arc::new(MacosTapCancellation {
            state: Arc::downgrade(&self.state),
        })
    }

    fn read_frame(&mut self, buffer: &mut [u8]) -> Result<usize> {
        self.read_frame_armed(buffer, || Ok(()))
    }

    fn write_frame(&mut self, frame: &[u8]) -> Result<()> {
        self.write_frame_armed(frame, || Ok(()))
    }

    fn mac_address(&self) -> Result<[u8; 6]> {
        Ok(self.mac_address)
    }

    fn set_mtu(&mut self, mtu: u16) -> Result<()> {
        let mut next = self.config.clone();
        next.mtu = mtu;
        next.validate()?;
        self.pair.set_mtu(mtu)?;
        self.config = next;
        Ok(())
    }

    fn destroy(mut self) -> Result<()> {
        self.pair.disable()
    }
}

impl fmt::Debug for MacosTapDevice {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MacosTapDevice")
            .field("name", &self.name)
            .field("peer_name", &self.peer_name)
            .field("config", &self.config)
            .field("mac_address", &self.mac_address)
            .finish_non_exhaustive()
    }
}

fn required_feth_name<'a>(value: Option<&'a str>, field: &'static str) -> Result<&'a str> {
    let name = value.ok_or(TapError::InvalidConfig {
        field,
        reason: "is required on macOS",
    })?;
    let Some(index) = name.strip_prefix("feth") else {
        return Err(TapError::InvalidConfig {
            field,
            reason: "must use the feth<N> interface form",
        });
    };
    let Ok(unit) = index.parse::<u16>() else {
        return Err(TapError::InvalidConfig {
            field,
            reason: "must use the canonical feth<N> form with N in 0..=9999",
        });
    };
    if unit > MAX_FETH_UNIT || unit.to_string() != index {
        return Err(TapError::InvalidConfig {
            field,
            reason: "must use the canonical feth<N> form with N in 0..=9999",
        });
    }
    Ok(name)
}

fn validate_mac_address(address: [u8; 6]) -> Result<()> {
    if address == [0; 6] || address[0] & 1 != 0 {
        return Err(TapError::InvalidMacAddress);
    }
    Ok(())
}

fn lock_operation(
    state: &CancellationState,
    operation: TapOperation,
) -> Result<std::sync::MutexGuard<'_, OperationState>> {
    state.operation.lock().map_err(|_| {
        TapError::io(
            operation,
            io::Error::other("macOS TAP cancellation state is poisoned"),
        )
    })
}

fn begin_pending_operation(state: &CancellationState, operation: TapOperation) -> Result<()> {
    let mut pending = lock_operation(state, operation)?;
    state
        .event
        .reset()
        .map_err(|source| TapError::io(TapOperation::CancelIo, source))?;
    pending.pending = true;
    pending.cancelled = false;
    Ok(())
}

fn finish_pending_operation<T>(
    state: &CancellationState,
    operation: TapOperation,
    result: io::Result<T>,
) -> Result<T> {
    let mut pending = lock_operation(state, operation)?;
    pending.pending = false;
    let cancelled = pending.cancelled;
    pending.cancelled = false;
    state
        .event
        .reset()
        .map_err(|source| TapError::io(TapOperation::CancelIo, source))?;
    match result {
        Ok(value) => Ok(value),
        Err(_) if cancelled => Err(TapError::Cancelled),
        Err(source) => Err(TapError::io(operation, source)),
    }
}

#[cfg(test)]
mod tests {
    use std::{io, sync::Arc};

    use super::{
        begin_pending_operation, finish_pending_operation, required_feth_name,
        validate_mac_address, CancellationState, Interrupt, MacosTapCancellation, OperationState,
    };
    use crate::{TapCancellation, TapError, TapOperation};

    #[test]
    fn feth_names_are_explicit_and_numeric() {
        assert!(matches!(
            required_feth_name(Some("feth0"), "name"),
            Ok("feth0")
        ));
        assert!(matches!(
            required_feth_name(Some("feth6100"), "peer name"),
            Ok("feth6100")
        ));
        assert!(matches!(
            required_feth_name(Some("feth9999"), "peer name"),
            Ok("feth9999")
        ));
        for invalid in [
            None,
            Some(""),
            Some("feth"),
            Some("feth-1"),
            Some("feth01"),
            Some("feth10000"),
            Some("en0"),
        ] {
            assert!(matches!(
                required_feth_name(invalid, "name"),
                Err(TapError::InvalidConfig { .. })
            ));
        }
    }

    #[test]
    fn mac_address_must_be_nonzero_unicast() {
        assert!(validate_mac_address([0x02, 1, 2, 3, 4, 5]).is_ok());
        assert!(matches!(
            validate_mac_address([0; 6]),
            Err(TapError::InvalidMacAddress)
        ));
        assert!(matches!(
            validate_mac_address([0x01, 1, 2, 3, 4, 5]),
            Err(TapError::InvalidMacAddress)
        ));
    }

    #[test]
    fn cancellation_only_affects_the_current_pending_operation() {
        let state = Arc::new(CancellationState {
            event: Interrupt::new().expect("create interrupt event"),
            operation: std::sync::Mutex::new(OperationState::default()),
        });
        let cancellation = MacosTapCancellation {
            state: Arc::downgrade(&state),
        };

        cancellation
            .cancel_pending_io()
            .expect("idle cancellation is harmless");
        begin_pending_operation(&state, TapOperation::ReadFrame).expect("start pending operation");
        cancellation
            .cancel_pending_io()
            .expect("cancel pending operation");
        cancellation
            .cancel_pending_io()
            .expect("repeat pending cancellation");
        assert!(matches!(
            finish_pending_operation::<usize>(
                &state,
                TapOperation::ReadFrame,
                Err(io::Error::from(io::ErrorKind::Interrupted)),
            ),
            Err(TapError::Cancelled)
        ));

        begin_pending_operation(&state, TapOperation::ReadFrame)
            .expect("start operation after reset");
        assert!(matches!(
            finish_pending_operation(&state, TapOperation::ReadFrame, Ok(60)),
            Ok(60)
        ));

        begin_pending_operation(&state, TapOperation::WriteFrame)
            .expect("start successful cancellation race");
        cancellation
            .cancel_pending_io()
            .expect("race cancellation with completion");
        assert!(matches!(
            finish_pending_operation(&state, TapOperation::WriteFrame, Ok(60)),
            Ok(60)
        ));

        drop(state);
        cancellation
            .cancel_pending_io()
            .expect("closed-device cancellation is harmless");
    }
}
