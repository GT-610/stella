//! Root helper listener and fail-closed per-client device sessions.

use std::{
    fs, io,
    os::unix::{
        fs::{FileTypeExt, MetadataExt, PermissionsExt},
        net::{UnixListener, UnixStream},
    },
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicBool, AtomicUsize, Ordering},
        mpsc::{sync_channel, SyncSender, TrySendError},
        Arc, Mutex,
    },
    thread,
};

use super::protocol::{self, ClientMessage, RemoteErrorKind, ServerMessage};
use crate::{
    macos::{sys, MacosTapDevice},
    Result, TapCancellationHandle, TapConfig, TapDevice, TapError, TapOperation,
    MAX_ETHERNET_FRAME_LENGTH, MIN_ETHERNET_FRAME_LENGTH,
};

const SESSION_QUEUE_CAPACITY: usize = 1;
const MAX_HELPER_SESSIONS: usize = 64;

/// Configuration for the foreground macOS TAP helper service.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MacosTapHelperConfig {
    /// Absolute Unix socket path on which the root helper listens.
    pub socket_path: PathBuf,
    /// Only a client process with this effective user ID may open TAP pairs.
    pub allowed_uid: u32,
}

impl MacosTapHelperConfig {
    /// Creates a helper configuration for one explicitly authorized local user.
    #[must_use]
    pub fn new(socket_path: impl Into<PathBuf>, allowed_uid: u32) -> Self {
        Self {
            socket_path: socket_path.into(),
            allowed_uid,
        }
    }
}

/// Runs the root macOS TAP helper until the process is terminated.
///
/// Each accepted connection owns at most one feth pair. Peer credentials are
/// verified before parsing requests, and disconnecting a client cancels its
/// pending I/O and closes the pair fail-closed.
///
/// # Errors
///
/// Returns an error if the caller is not root, the socket cannot be prepared,
/// or accepting a local connection fails.
pub fn run_macos_tap_helper(config: &MacosTapHelperConfig) -> Result<()> {
    if sys::effective_uid() != 0 {
        return Err(TapError::io(
            TapOperation::AuthenticateHelper,
            io::Error::new(
                io::ErrorKind::PermissionDenied,
                "the macOS TAP helper must run as root",
            ),
        ));
    }
    validate_socket_path(&config.socket_path)?;
    let (listener, _socket_guard) = prepare_listener(&config.socket_path, config.allowed_uid)?;
    let active_sessions = Arc::new(AtomicUsize::new(0));
    for incoming in listener.incoming() {
        let stream =
            incoming.map_err(|source| TapError::io(TapOperation::ConnectHelper, source))?;
        if active_sessions
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |active| {
                (active < MAX_HELPER_SESSIONS).then_some(active + 1)
            })
            .is_err()
        {
            drop(stream);
            continue;
        }
        let allowed_uid = config.allowed_uid;
        let session_count = Arc::clone(&active_sessions);
        if let Err(source) = thread::Builder::new()
            .name("stella-tap-helper-session".to_owned())
            .spawn(move || {
                let _session = SessionGuard(session_count);
                let factory: DeviceFactory = Box::new(|tap_config| {
                    let device = MacosTapDevice::create(tap_config)?;
                    let cancellation = device.cancellation_handle();
                    Ok(Box::new(NativeHelperDevice {
                        device: Some(device),
                        cancellation,
                    }))
                });
                let _ = serve_connection(stream, Some(allowed_uid), factory);
            })
        {
            active_sessions.fetch_sub(1, Ordering::AcqRel);
            return Err(TapError::io(TapOperation::OpenDevice, source));
        }
    }
    Ok(())
}

struct SessionGuard(Arc<AtomicUsize>);

impl Drop for SessionGuard {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::AcqRel);
    }
}

trait HelperDevice: Send {
    fn cancellation_handle(&self) -> TapCancellationHandle;
    fn read_frame(&mut self, buffer: &mut [u8], operation: &SessionOperation) -> Result<usize>;
    fn write_frame(&mut self, frame: &[u8], operation: &SessionOperation) -> Result<()>;
    fn mac_address(&self) -> Result<[u8; 6]>;
    fn set_mtu(&mut self, mtu: u16) -> Result<()>;
    fn destroy(&mut self) -> Result<()>;
}

struct NativeHelperDevice {
    device: Option<MacosTapDevice>,
    cancellation: TapCancellationHandle,
}

impl HelperDevice for NativeHelperDevice {
    fn cancellation_handle(&self) -> TapCancellationHandle {
        Arc::clone(&self.cancellation)
    }

    fn read_frame(&mut self, buffer: &mut [u8], operation: &SessionOperation) -> Result<usize> {
        let cancellation = Arc::clone(&self.cancellation);
        self.device
            .as_mut()
            .ok_or(TapError::Closed)?
            .read_frame_armed(buffer, || operation.deliver_cancellation(&cancellation))
    }

    fn write_frame(&mut self, frame: &[u8], operation: &SessionOperation) -> Result<()> {
        let cancellation = Arc::clone(&self.cancellation);
        self.device
            .as_mut()
            .ok_or(TapError::Closed)?
            .write_frame_armed(frame, || operation.deliver_cancellation(&cancellation))
    }

    fn mac_address(&self) -> Result<[u8; 6]> {
        self.device.as_ref().ok_or(TapError::Closed)?.mac_address()
    }

    fn set_mtu(&mut self, mtu: u16) -> Result<()> {
        self.device.as_mut().ok_or(TapError::Closed)?.set_mtu(mtu)
    }

    fn destroy(&mut self) -> Result<()> {
        self.device.take().ok_or(TapError::Closed)?.destroy()
    }
}

type DeviceFactory = Box<dyn FnOnce(&TapConfig) -> Result<Box<dyn HelperDevice>> + Send + 'static>;

enum DeviceCommand {
    Read { request_id: u64, capacity: u16 },
    Write { request_id: u64, frame: Vec<u8> },
    SetMtu { request_id: u64, mtu: u16 },
    Close { request_id: u64 },
}

#[derive(Default)]
struct SessionOperationState {
    outstanding: bool,
    cancel_requested: bool,
}

#[derive(Default)]
struct SessionOperation(Mutex<SessionOperationState>);

impl SessionOperation {
    fn queue(&self) -> io::Result<()> {
        let mut state = self.lock()?;
        if state.outstanding {
            return Err(invalid_protocol(
                "helper session permits only one outstanding request",
            ));
        }
        state.outstanding = true;
        state.cancel_requested = false;
        Ok(())
    }

    fn cancel(&self, cancellation: &TapCancellationHandle) -> Result<()> {
        let should_cancel = {
            let mut state = self
                .lock()
                .map_err(|source| TapError::io(TapOperation::ExchangeHelperMessage, source))?;
            if state.outstanding {
                state.cancel_requested = true;
                true
            } else {
                false
            }
        };
        if should_cancel {
            cancellation.cancel_pending_io()?;
        }
        Ok(())
    }

    fn deliver_cancellation(&self, cancellation: &TapCancellationHandle) -> Result<()> {
        let should_cancel = {
            let mut state = self
                .lock()
                .map_err(|source| TapError::io(TapOperation::ExchangeHelperMessage, source))?;
            std::mem::take(&mut state.cancel_requested)
        };
        if should_cancel {
            cancellation.cancel_pending_io()?;
        }
        Ok(())
    }

    fn finish(&self) {
        if let Ok(mut state) = self.0.lock() {
            state.outstanding = false;
            state.cancel_requested = false;
        }
    }

    fn lock(&self) -> io::Result<std::sync::MutexGuard<'_, SessionOperationState>> {
        self.0
            .lock()
            .map_err(|_| io::Error::other("helper session operation state is poisoned"))
    }
}

fn serve_connection(
    mut stream: UnixStream,
    expected_uid: Option<u32>,
    factory: DeviceFactory,
) -> io::Result<()> {
    if let Some(expected_uid) = expected_uid {
        let (actual_uid, _) = sys::peer_credentials(&stream)?;
        if actual_uid != expected_uid {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "TAP helper rejected an unauthorized local user",
            ));
        }
    }
    let ClientMessage::Open(config) = protocol::read_client(&mut stream)? else {
        return Err(invalid_protocol(
            "first helper request must open a TAP pair",
        ));
    };
    let mut device = match factory(&config) {
        Ok(device) => device,
        Err(error) => {
            protocol::write_server(&mut stream, &error_response(0, &error))?;
            return Ok(());
        }
    };
    let mac_address = match device.mac_address() {
        Ok(mac_address) => mac_address,
        Err(error) => {
            protocol::write_server(&mut stream, &error_response(0, &error))?;
            let _ = device.destroy();
            return Ok(());
        }
    };
    protocol::write_server(&mut stream, &ServerMessage::Opened { mac_address })?;

    let cancellation = device.cancellation_handle();
    let response_stream = stream.try_clone()?;
    let shutdown = Arc::new(AtomicBool::new(false));
    let worker_shutdown = Arc::clone(&shutdown);
    let operation = Arc::new(SessionOperation::default());
    let worker_operation = Arc::clone(&operation);
    let (commands, command_receiver) = sync_channel(SESSION_QUEUE_CAPACITY);
    let worker = thread::Builder::new()
        .name("stella-tap-helper-io".to_owned())
        .spawn(move || {
            let mut response_stream = response_stream;
            let mut destroyed = false;
            while !worker_shutdown.load(Ordering::Acquire) {
                let Ok(command) = command_receiver.recv() else {
                    break;
                };
                if worker_shutdown.load(Ordering::Acquire) {
                    break;
                }
                let (response, close) = execute_command(&mut *device, command, &worker_operation);
                worker_operation.finish();
                if close {
                    destroyed = true;
                }
                if protocol::write_server(&mut response_stream, &response).is_err() || close {
                    break;
                }
            }
            if !destroyed {
                let _ = device.destroy();
            }
        })?;

    let result = read_commands(&mut stream, &commands, &cancellation, &operation);
    shutdown.store(true, Ordering::Release);
    let _ = operation.cancel(&cancellation);
    drop(commands);
    let _ = worker.join();
    result
}

fn read_commands(
    stream: &mut UnixStream,
    commands: &SyncSender<DeviceCommand>,
    cancellation: &TapCancellationHandle,
    operation: &SessionOperation,
) -> io::Result<()> {
    loop {
        let message = match protocol::read_client(stream) {
            Ok(message) => message,
            Err(error) if error.kind() == io::ErrorKind::UnexpectedEof => return Ok(()),
            Err(error) => return Err(error),
        };
        let command = match message {
            ClientMessage::Read {
                request_id,
                capacity,
            } => {
                if !(MIN_ETHERNET_FRAME_LENGTH..=MAX_ETHERNET_FRAME_LENGTH).contains(&capacity) {
                    return Err(invalid_protocol(
                        "read capacity is outside Stella frame bounds",
                    ));
                }
                DeviceCommand::Read {
                    request_id,
                    capacity,
                }
            }
            ClientMessage::Write { request_id, frame } => {
                DeviceCommand::Write { request_id, frame }
            }
            ClientMessage::SetMtu { request_id, mtu } => DeviceCommand::SetMtu { request_id, mtu },
            ClientMessage::Close { request_id } => DeviceCommand::Close { request_id },
            ClientMessage::Cancel => {
                operation
                    .cancel(cancellation)
                    .map_err(|error| io::Error::other(error.to_string()))?;
                continue;
            }
            ClientMessage::Open(_) => {
                return Err(invalid_protocol(
                    "a helper session can open only one TAP pair",
                ));
            }
        };
        operation.queue()?;
        match commands.try_send(command) {
            Ok(()) => {}
            Err(TrySendError::Full(_)) => {
                operation.finish();
                return Err(invalid_protocol(
                    "helper session has too many pending requests",
                ));
            }
            Err(TrySendError::Disconnected(_)) => {
                operation.finish();
                return Ok(());
            }
        }
    }
}

fn execute_command(
    device: &mut dyn HelperDevice,
    command: DeviceCommand,
    operation: &SessionOperation,
) -> (ServerMessage, bool) {
    match command {
        DeviceCommand::Read {
            request_id,
            capacity,
        } => {
            let mut frame = vec![0_u8; usize::from(capacity)];
            let response = match device.read_frame(&mut frame, operation) {
                Ok(length) => match frame.get(..length) {
                    Some(frame) => ServerMessage::Frame {
                        request_id,
                        frame: frame.to_vec(),
                    },
                    None => ServerMessage::Error {
                        request_id,
                        kind: RemoteErrorKind::Rejected,
                        reason: "native TAP returned an invalid frame length".to_owned(),
                    },
                },
                Err(error) => error_response(request_id, &error),
            };
            (response, false)
        }
        DeviceCommand::Write { request_id, frame } => (
            match device.write_frame(&frame, operation) {
                Ok(()) => ServerMessage::Ok { request_id },
                Err(error) => error_response(request_id, &error),
            },
            false,
        ),
        DeviceCommand::SetMtu { request_id, mtu } => (
            match device.set_mtu(mtu) {
                Ok(()) => ServerMessage::Ok { request_id },
                Err(error) => error_response(request_id, &error),
            },
            false,
        ),
        DeviceCommand::Close { request_id } => (
            match device.destroy() {
                Ok(()) => ServerMessage::Ok { request_id },
                Err(error) => error_response(request_id, &error),
            },
            true,
        ),
    }
}

fn error_response(request_id: u64, error: &TapError) -> ServerMessage {
    let kind = match error {
        TapError::Cancelled => RemoteErrorKind::Cancelled,
        TapError::DeviceBusy { .. } => RemoteErrorKind::DeviceBusy,
        TapError::DeviceOwnershipConflict { .. } => RemoteErrorKind::OwnershipConflict,
        _ => RemoteErrorKind::Rejected,
    };
    ServerMessage::Error {
        request_id,
        kind,
        reason: error.to_string(),
    }
}

fn validate_socket_path(path: &Path) -> Result<()> {
    if !path.is_absolute() {
        return Err(TapError::InvalidConfig {
            field: "helper socket path",
            reason: "must be absolute",
        });
    }
    if path.file_name().is_none() {
        return Err(TapError::InvalidConfig {
            field: "helper socket path",
            reason: "must name a Unix socket",
        });
    }
    Ok(())
}

fn prepare_listener(path: &Path, allowed_uid: u32) -> Result<(UnixListener, SocketGuard)> {
    if let Ok(metadata) = fs::symlink_metadata(path) {
        if !metadata.file_type().is_socket()
            || (metadata.uid() != 0 && metadata.uid() != allowed_uid)
        {
            return Err(TapError::io(
                TapOperation::ConnectHelper,
                io::Error::new(
                    io::ErrorKind::AlreadyExists,
                    "refusing to replace an unexpected helper socket path",
                ),
            ));
        }
        fs::remove_file(path)
            .map_err(|source| TapError::io(TapOperation::ConnectHelper, source))?;
    }
    let listener = UnixListener::bind(path)
        .map_err(|source| TapError::io(TapOperation::ConnectHelper, source))?;
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))
        .map_err(|source| TapError::io(TapOperation::ConnectHelper, source))?;
    sys::chown_path(path, allowed_uid)
        .map_err(|source| TapError::io(TapOperation::ConnectHelper, source))?;
    let metadata = fs::symlink_metadata(path)
        .map_err(|source| TapError::io(TapOperation::ConnectHelper, source))?;
    Ok((
        listener,
        SocketGuard {
            path: path.to_owned(),
            device: metadata.dev(),
            inode: metadata.ino(),
        },
    ))
}

struct SocketGuard {
    path: PathBuf,
    device: u64,
    inode: u64,
}

impl Drop for SocketGuard {
    fn drop(&mut self) {
        let Ok(metadata) = fs::symlink_metadata(&self.path) else {
            return;
        };
        if metadata.file_type().is_socket()
            && metadata.dev() == self.device
            && metadata.ino() == self.inode
        {
            let _ = fs::remove_file(&self.path);
        }
    }
}

fn invalid_protocol(reason: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, reason)
}

#[cfg(test)]
mod tests {
    use std::{
        io,
        os::unix::net::UnixStream,
        sync::{Arc, Condvar, Mutex},
        thread,
    };

    use super::{serve_connection, DeviceFactory, HelperDevice};
    use crate::{
        macos::helper::protocol::{self, ClientMessage, RemoteErrorKind, ServerMessage},
        Result, TapCancellation, TapCancellationHandle, TapConfig, TapError,
    };

    struct FakeCancellation(Arc<(Mutex<bool>, Condvar)>);

    impl TapCancellation for FakeCancellation {
        fn cancel_pending_io(&self) -> Result<()> {
            let (cancelled, ready) = &*self.0;
            *cancelled.lock().expect("lock fake cancellation") = true;
            ready.notify_all();
            Ok(())
        }
    }

    struct FakeDevice {
        cancellation: Arc<(Mutex<bool>, Condvar)>,
        destroyed: Arc<Mutex<bool>>,
    }

    impl HelperDevice for FakeDevice {
        fn cancellation_handle(&self) -> TapCancellationHandle {
            Arc::new(FakeCancellation(Arc::clone(&self.cancellation)))
        }

        fn read_frame(
            &mut self,
            _buffer: &mut [u8],
            operation: &super::SessionOperation,
        ) -> Result<usize> {
            operation.deliver_cancellation(&self.cancellation_handle())?;
            let (cancelled, ready) = &*self.cancellation;
            let mut cancelled = cancelled.lock().expect("lock fake read");
            while !*cancelled {
                cancelled = ready.wait(cancelled).expect("wait for fake cancellation");
            }
            *cancelled = false;
            Err(TapError::Cancelled)
        }

        fn write_frame(
            &mut self,
            _frame: &[u8],
            operation: &super::SessionOperation,
        ) -> Result<()> {
            operation.deliver_cancellation(&self.cancellation_handle())?;
            Ok(())
        }

        fn mac_address(&self) -> Result<[u8; 6]> {
            Ok([0x02, 1, 2, 3, 4, 5])
        }

        fn set_mtu(&mut self, _mtu: u16) -> Result<()> {
            Ok(())
        }

        fn destroy(&mut self) -> Result<()> {
            *self.destroyed.lock().expect("lock destroyed state") = true;
            Ok(())
        }
    }

    #[test]
    fn session_cancels_pending_io_and_closes_device() {
        let (mut client, server) = UnixStream::pair().expect("create helper socket pair");
        let destroyed = Arc::new(Mutex::new(false));
        let factory_destroyed = Arc::clone(&destroyed);
        let factory: DeviceFactory = Box::new(move |_| {
            Ok(Box::new(FakeDevice {
                cancellation: Arc::new((Mutex::new(false), Condvar::new())),
                destroyed: factory_destroyed,
            }))
        });
        let worker = thread::spawn(move || serve_connection(server, None, factory));
        protocol::write_client(&mut client, &ClientMessage::Open(TapConfig::default()))
            .expect("open fake TAP");
        assert!(matches!(
            protocol::read_server(&mut client).expect("read opened"),
            ServerMessage::Opened { .. }
        ));
        protocol::write_client(
            &mut client,
            &ClientMessage::Read {
                request_id: 1,
                capacity: 1_514,
            },
        )
        .expect("request pending read");
        protocol::write_client(&mut client, &ClientMessage::Cancel).expect("cancel read");
        assert!(matches!(
            protocol::read_server(&mut client).expect("read cancellation"),
            ServerMessage::Error {
                request_id: 1,
                kind: RemoteErrorKind::Cancelled,
                ..
            }
        ));
        protocol::write_client(&mut client, &ClientMessage::Close { request_id: 2 })
            .expect("close fake TAP");
        assert!(matches!(
            protocol::read_server(&mut client).expect("read close"),
            ServerMessage::Ok { request_id: 2 }
        ));
        drop(client);
        worker
            .join()
            .expect("helper session did not panic")
            .expect("helper session succeeded");
        assert!(*destroyed.lock().expect("read destroyed state"));
    }

    #[test]
    fn session_disconnect_destroys_device_without_close_request() {
        let (mut client, server) = UnixStream::pair().expect("create helper socket pair");
        let destroyed = Arc::new(Mutex::new(false));
        let factory_destroyed = Arc::clone(&destroyed);
        let factory: DeviceFactory = Box::new(move |_| {
            Ok(Box::new(FakeDevice {
                cancellation: Arc::new((Mutex::new(false), Condvar::new())),
                destroyed: factory_destroyed,
            }))
        });
        let worker = thread::spawn(move || serve_connection(server, None, factory));
        protocol::write_client(&mut client, &ClientMessage::Open(TapConfig::default()))
            .expect("open fake TAP");
        let _ = protocol::read_server(&mut client).expect("read opened");
        protocol::write_client(
            &mut client,
            &ClientMessage::Read {
                request_id: 1,
                capacity: 1_514,
            },
        )
        .expect("queue read before disconnect");
        drop(client);
        worker
            .join()
            .expect("helper session did not panic")
            .expect("helper session succeeded");
        assert!(*destroyed.lock().expect("read destroyed state"));
    }

    #[test]
    fn session_rejects_the_wrong_peer_uid_before_open() {
        let (_client, server) = UnixStream::pair().expect("create helper socket pair");
        let actual_uid = super::sys::effective_uid();
        let unexpected_uid = actual_uid.wrapping_add(1);
        let factory: DeviceFactory = Box::new(|_| panic!("unauthorized factory must not run"));
        let error = serve_connection(server, Some(unexpected_uid), factory)
            .expect_err("wrong peer must be rejected");
        assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
    }

    #[test]
    fn production_helper_requires_root() {
        if super::sys::effective_uid() != 0 {
            let config = super::MacosTapHelperConfig::new("/tmp/not-used.sock", 1);
            assert!(matches!(
                super::run_macos_tap_helper(&config),
                Err(TapError::Io {
                    operation: crate::TapOperation::AuthenticateHelper,
                    source,
                }) if source.kind() == io::ErrorKind::PermissionDenied
            ));
        }
    }
}
