//! macOS Layer-2 backend using a persistent fake-Ethernet pair.

use std::{
    fmt,
    fs::{DirBuilder, File, OpenOptions},
    io,
    os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt},
    path::Path,
    sync::{Arc, Mutex, Weak},
};

use fs2::FileExt;
use tun_rs::{DeviceBuilder, InterruptEvent, Layer, SyncDevice};

use crate::{
    Result, TapCancellation, TapCancellationHandle, TapConfig, TapDevice, TapError, TapOperation,
};

const LOCK_DIRECTORY: &str = "/var/run/stella";
const LOCK_DIRECTORY_MODE: u32 = 0o700;
const LOCK_FILE_MODE: u32 = 0o600;

#[derive(Default)]
struct OperationState {
    pending: bool,
    cancelled: bool,
}

struct CancellationState {
    event: InterruptEvent,
    operation: Mutex<OperationState>,
}

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
        if !operation.pending {
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
    device: SyncDevice,
    _lock: File,
    state: Arc<CancellationState>,
    config: TapConfig,
    name: String,
    peer_name: String,
    mac_address: [u8; 6],
    enabled: bool,
}

impl MacosTapDevice {
    fn begin_operation(&self, operation: TapOperation) -> Result<()> {
        let mut state = lock_operation(&self.state, operation)?;
        self.state
            .event
            .reset()
            .map_err(|source| TapError::io(TapOperation::CancelIo, source))?;
        state.pending = true;
        state.cancelled = false;
        Ok(())
    }

    fn finish_operation<T>(&self, operation: TapOperation, result: io::Result<T>) -> Result<T> {
        let mut state = lock_operation(&self.state, operation)?;
        state.pending = false;
        let cancelled = state.cancelled;
        state.cancelled = false;
        self.state
            .event
            .reset()
            .map_err(|source| TapError::io(TapOperation::CancelIo, source))?;
        match result {
            Ok(value) => Ok(value),
            Err(_) if cancelled => Err(TapError::Cancelled),
            Err(source) => Err(TapError::io(operation, source)),
        }
    }

    fn disable(&mut self) -> Result<()> {
        if !self.enabled {
            return Ok(());
        }
        self.device
            .enabled(false)
            .map_err(|source| TapError::io(TapOperation::SetDeviceState, source))?;
        self.enabled = false;
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
        let lock = acquire_pair_lock(name, peer_name)?;
        let state = Arc::new(CancellationState {
            event: InterruptEvent::new()
                .map_err(|source| TapError::io(TapOperation::CancelIo, source))?,
            operation: Mutex::new(OperationState::default()),
        });
        let device = DeviceBuilder::new()
            .name(name)
            .peer_feth(peer_name)
            .layer(Layer::L2)
            .reuse_dev(true)
            .persist(true)
            .build_sync()
            .map_err(|source| TapError::io(TapOperation::CreateDevice, source))?;
        device
            .set_nonblocking(true)
            .map_err(|source| TapError::io(TapOperation::ConfigureBlockingMode, source))?;
        let installed_mtu = device
            .mtu()
            .map_err(|source| TapError::io(TapOperation::QueryMtu, source))?;
        let mtu = config.mtu.min(installed_mtu);
        device
            .set_mtu(mtu)
            .map_err(|source| TapError::io(TapOperation::SetMtu, source))?;
        let mac_address = device
            .mac_address()
            .map_err(|source| TapError::io(TapOperation::QueryMac, source))?;
        validate_mac_address(mac_address)?;
        let mut effective_config = config.clone();
        effective_config.mtu = mtu;
        Ok(Self {
            device,
            _lock: lock,
            state,
            config: effective_config,
            name: name.to_owned(),
            peer_name: peer_name.to_owned(),
            mac_address,
            enabled: true,
        })
    }

    fn cancellation_handle(&self) -> TapCancellationHandle {
        Arc::new(MacosTapCancellation {
            state: Arc::downgrade(&self.state),
        })
    }

    fn read_frame(&mut self, buf: &mut [u8]) -> Result<usize> {
        self.config.validate_read_buffer(buf.len())?;
        self.begin_operation(TapOperation::ReadFrame)?;
        let result = self.device.recv_intr(buf, &self.state.event);
        let length = self.finish_operation(TapOperation::ReadFrame, result)?;
        self.config.validate_frame(length)?;
        Ok(length)
    }

    fn write_frame(&mut self, frame: &[u8]) -> Result<()> {
        self.config.validate_frame(frame.len())?;
        self.begin_operation(TapOperation::WriteFrame)?;
        let result = self.device.send_intr(frame, &self.state.event);
        let written = self.finish_operation(TapOperation::WriteFrame, result)?;
        if written != frame.len() {
            return Err(TapError::PartialFrameWrite {
                expected: frame.len(),
                actual: written,
            });
        }
        Ok(())
    }

    fn mac_address(&self) -> Result<[u8; 6]> {
        Ok(self.mac_address)
    }

    fn set_mtu(&mut self, mtu: u16) -> Result<()> {
        let mut next = self.config.clone();
        next.mtu = mtu;
        next.validate()?;
        self.device
            .set_mtu(mtu)
            .map_err(|source| TapError::io(TapOperation::SetMtu, source))?;
        self.config = next;
        Ok(())
    }

    fn destroy(mut self) -> Result<()> {
        self.disable()
    }
}

impl Drop for MacosTapDevice {
    fn drop(&mut self) {
        let _ = self.disable();
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
            .field("enabled", &self.enabled)
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
    if index.is_empty() || !index.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(TapError::InvalidConfig {
            field,
            reason: "must use the feth<N> interface form",
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

fn acquire_pair_lock(name: &str, peer_name: &str) -> Result<File> {
    ensure_lock_directory()?;
    let (first, second) = if name <= peer_name {
        (name, peer_name)
    } else {
        (peer_name, name)
    };
    let path = Path::new(LOCK_DIRECTORY).join(format!("tap-{first}-{second}.lock"));
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .mode(LOCK_FILE_MODE)
        .open(path)
        .map_err(|source| TapError::io(TapOperation::AcquireDeviceLock, source))?;
    match FileExt::try_lock_exclusive(&file) {
        Ok(()) => Ok(file),
        Err(source) if source.kind() == io::ErrorKind::WouldBlock => Err(TapError::DeviceBusy {
            name: name.to_owned(),
            peer_name: peer_name.to_owned(),
        }),
        Err(source) => Err(TapError::io(TapOperation::AcquireDeviceLock, source)),
    }
}

fn ensure_lock_directory() -> Result<()> {
    let mut builder = DirBuilder::new();
    builder.mode(LOCK_DIRECTORY_MODE);
    match builder.create(LOCK_DIRECTORY) {
        Ok(()) => {}
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
        Err(source) => return Err(TapError::io(TapOperation::AcquireDeviceLock, source)),
    }
    let metadata = std::fs::symlink_metadata(LOCK_DIRECTORY)
        .map_err(|source| TapError::io(TapOperation::AcquireDeviceLock, source))?;
    if !metadata.file_type().is_dir() || metadata.uid() != 0 || metadata.mode() & 0o077 != 0 {
        return Err(TapError::io(
            TapOperation::AcquireDeviceLock,
            io::Error::new(
                io::ErrorKind::PermissionDenied,
                "macOS TAP lock directory must be a root-owned private directory",
            ),
        ));
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

#[cfg(test)]
mod tests {
    use super::{required_feth_name, validate_mac_address};
    use crate::TapError;

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
        for invalid in [None, Some(""), Some("feth"), Some("feth-1"), Some("en0")] {
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
}
