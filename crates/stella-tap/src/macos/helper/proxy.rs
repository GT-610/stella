//! Unprivileged `TapDevice` proxy for the local root helper.

use std::{
    fmt, io,
    net::Shutdown,
    os::unix::net::UnixStream,
    path::Path,
    sync::{Arc, Mutex, Weak},
};

use super::{
    protocol::{self, ClientMessage, RemoteErrorKind, ServerMessage},
    DEFAULT_MACOS_HELPER_SOCKET,
};
use crate::{
    macos::sys, Result, TapCancellation, TapCancellationHandle, TapConfig, TapDevice, TapError,
    TapOperation,
};

struct ProxyOperationState {
    pending: bool,
    closed: bool,
}

struct ProxyShared {
    writer: Mutex<UnixStream>,
    operation: Mutex<ProxyOperationState>,
}

/// Cancellation handle for an unprivileged macOS TAP helper connection.
#[derive(Clone)]
pub struct MacosTapProxyCancellation {
    state: Weak<ProxyShared>,
}

impl TapCancellation for MacosTapProxyCancellation {
    fn cancel_pending_io(&self) -> Result<()> {
        let Some(state) = self.state.upgrade() else {
            return Ok(());
        };
        let mut writer = lock(&state.writer, TapOperation::CancelIo)?;
        let operation = lock(&state.operation, TapOperation::CancelIo)?;
        if !operation.pending || operation.closed {
            return Ok(());
        }
        protocol::write_client(&mut *writer, &ClientMessage::Cancel)
            .map_err(|source| TapError::io(TapOperation::ExchangeHelperMessage, source))
    }
}

impl fmt::Debug for MacosTapProxyCancellation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MacosTapProxyCancellation")
            .field("connected", &self.state.strong_count().ne(&0))
            .finish_non_exhaustive()
    }
}

/// Complete-frame macOS TAP client backed by the privileged local helper.
pub struct MacosTapProxyDevice {
    reader: UnixStream,
    shared: Arc<ProxyShared>,
    config: TapConfig,
    mac_address: [u8; 6],
    next_request_id: u64,
}

impl MacosTapProxyDevice {
    /// Connects to an explicitly selected helper socket.
    ///
    /// This is primarily useful to integration tests and non-default service
    /// layouts. Production callers normally use [`TapDevice::create`].
    ///
    /// # Errors
    ///
    /// Returns an error if the socket is unavailable, its peer is not root, or
    /// the helper rejects the TAP configuration.
    pub fn create_with_socket(config: &TapConfig, socket: &Path) -> Result<Self> {
        Self::connect(config, socket, 0)
    }

    fn connect(config: &TapConfig, socket: &Path, expected_uid: u32) -> Result<Self> {
        config.validate()?;
        let reader = UnixStream::connect(socket)
            .map_err(|source| TapError::io(TapOperation::ConnectHelper, source))?;
        Self::from_stream(config, reader, expected_uid)
    }

    fn from_stream(config: &TapConfig, mut reader: UnixStream, expected_uid: u32) -> Result<Self> {
        config.validate()?;
        let (peer_uid, _) = sys::peer_credentials(&reader)
            .map_err(|source| TapError::io(TapOperation::AuthenticateHelper, source))?;
        if peer_uid != expected_uid {
            return Err(TapError::HelperIdentityMismatch {
                actual_uid: peer_uid,
            });
        }
        let mut writer = reader
            .try_clone()
            .map_err(|source| TapError::io(TapOperation::ConnectHelper, source))?;
        protocol::write_client(&mut writer, &ClientMessage::Open(config.clone()))
            .map_err(helper_transport)?;
        let mac_address = match protocol::read_server(&mut reader).map_err(helper_transport)? {
            ServerMessage::Opened { mac_address } => mac_address,
            ServerMessage::Error {
                request_id: 0,
                kind,
                reason,
            } => return Err(remote_error(kind, reason, config)),
            _ => {
                return Err(TapError::HelperProtocol {
                    reason: "helper did not answer open with an opened message",
                });
            }
        };
        Ok(Self {
            reader,
            shared: Arc::new(ProxyShared {
                writer: Mutex::new(writer),
                operation: Mutex::new(ProxyOperationState {
                    pending: false,
                    closed: false,
                }),
            }),
            config: config.clone(),
            mac_address,
            next_request_id: 1,
        })
    }

    fn request(&mut self, message: &ClientMessage) -> Result<ServerMessage> {
        {
            let mut writer = lock(&self.shared.writer, TapOperation::ExchangeHelperMessage)?;
            let mut operation = lock(&self.shared.operation, TapOperation::ExchangeHelperMessage)?;
            if operation.closed {
                return Err(TapError::Closed);
            }
            operation.pending = true;
            if let Err(source) = protocol::write_client(&mut *writer, message) {
                operation.pending = false;
                return Err(helper_transport(source));
            }
        }
        let result = protocol::read_server(&mut self.reader).map_err(helper_transport);
        let mut operation = lock(&self.shared.operation, TapOperation::ExchangeHelperMessage)?;
        operation.pending = false;
        result
    }

    fn request_id(&mut self) -> u64 {
        let request_id = self.next_request_id;
        self.next_request_id = self.next_request_id.checked_add(1).unwrap_or(1);
        request_id
    }

    fn expect_ok(&self, expected_id: u64, response: ServerMessage) -> Result<()> {
        match response {
            ServerMessage::Ok { request_id } if request_id == expected_id => Ok(()),
            ServerMessage::Error {
                request_id,
                kind,
                reason,
            } if request_id == expected_id => Err(remote_error(kind, reason, &self.config)),
            _ => Err(TapError::HelperProtocol {
                reason: "helper response did not match the pending request",
            }),
        }
    }

    fn mark_closed(&self) {
        if let Ok(mut operation) = self.shared.operation.lock() {
            operation.pending = false;
            operation.closed = true;
        }
        if let Ok(writer) = self.shared.writer.lock() {
            let _ = writer.shutdown(Shutdown::Both);
        }
        let _ = self.reader.shutdown(Shutdown::Both);
    }
}

impl TapDevice for MacosTapProxyDevice {
    fn create(config: &TapConfig) -> Result<Self> {
        Self::connect(config, Path::new(DEFAULT_MACOS_HELPER_SOCKET), 0)
    }

    fn cancellation_handle(&self) -> TapCancellationHandle {
        Arc::new(MacosTapProxyCancellation {
            state: Arc::downgrade(&self.shared),
        })
    }

    fn read_frame(&mut self, buffer: &mut [u8]) -> Result<usize> {
        self.config.validate_read_buffer(buffer.len())?;
        let request_id = self.request_id();
        let response = self.request(&ClientMessage::Read {
            request_id,
            capacity: self.config.max_frame_size,
        })?;
        match response {
            ServerMessage::Frame {
                request_id: actual_id,
                frame,
            } if actual_id == request_id => {
                self.config.validate_frame(frame.len())?;
                let remaining = buffer.len();
                let output =
                    buffer
                        .get_mut(..frame.len())
                        .ok_or(TapError::ReceiveBufferTooSmall {
                            needed: frame.len(),
                            remaining,
                        })?;
                output.copy_from_slice(&frame);
                Ok(frame.len())
            }
            ServerMessage::Error {
                request_id: actual_id,
                kind,
                reason,
            } if actual_id == request_id => Err(remote_error(kind, reason, &self.config)),
            _ => Err(TapError::HelperProtocol {
                reason: "helper response did not match the pending read",
            }),
        }
    }

    fn write_frame(&mut self, frame: &[u8]) -> Result<()> {
        self.config.validate_frame(frame.len())?;
        let request_id = self.request_id();
        let response = self.request(&ClientMessage::Write {
            request_id,
            frame: frame.to_vec(),
        })?;
        self.expect_ok(request_id, response)
    }

    fn mac_address(&self) -> Result<[u8; 6]> {
        Ok(self.mac_address)
    }

    fn set_mtu(&mut self, mtu: u16) -> Result<()> {
        let mut next = self.config.clone();
        next.mtu = mtu;
        next.validate()?;
        let request_id = self.request_id();
        let response = self.request(&ClientMessage::SetMtu { request_id, mtu })?;
        self.expect_ok(request_id, response)?;
        self.config = next;
        Ok(())
    }

    fn destroy(mut self) -> Result<()> {
        let request_id = self.request_id();
        let response = self.request(&ClientMessage::Close { request_id });
        self.mark_closed();
        self.expect_ok(request_id, response?)
    }
}

impl Drop for MacosTapProxyDevice {
    fn drop(&mut self) {
        self.mark_closed();
    }
}

impl fmt::Debug for MacosTapProxyDevice {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MacosTapProxyDevice")
            .field("config", &self.config)
            .field("mac_address", &self.mac_address)
            .finish_non_exhaustive()
    }
}

fn helper_transport(source: io::Error) -> TapError {
    if source.kind() == io::ErrorKind::InvalidData {
        TapError::HelperProtocol {
            reason: "helper sent an invalid or out-of-bounds message",
        }
    } else {
        TapError::io(TapOperation::ExchangeHelperMessage, source)
    }
}

fn remote_error(kind: RemoteErrorKind, reason: String, config: &TapConfig) -> TapError {
    match kind {
        RemoteErrorKind::Cancelled => TapError::Cancelled,
        RemoteErrorKind::DeviceBusy => TapError::DeviceBusy {
            name: config.name.clone().unwrap_or_default(),
            peer_name: config.peer_name.clone().unwrap_or_default(),
        },
        RemoteErrorKind::OwnershipConflict => TapError::DeviceOwnershipConflict {
            name: config.name.clone().unwrap_or_default(),
            peer_name: config.peer_name.clone().unwrap_or_default(),
        },
        RemoteErrorKind::Rejected => TapError::HelperRejected { reason },
    }
}

fn lock<T>(mutex: &Mutex<T>, operation: TapOperation) -> Result<std::sync::MutexGuard<'_, T>> {
    mutex.lock().map_err(|_| {
        TapError::io(
            operation,
            io::Error::other("macOS TAP helper state is poisoned"),
        )
    })
}

#[cfg(test)]
mod tests {
    use std::{os::unix::net::UnixStream, sync::mpsc, thread, time::Duration};

    use super::MacosTapProxyDevice;
    use crate::{
        macos::{helper::protocol, sys},
        TapConfig, TapDevice, TapError,
    };

    #[test]
    fn proxy_exchanges_complete_frames_and_mtu_requests() {
        let (client, mut helper) = UnixStream::pair().expect("create mock helper socket pair");
        let server = thread::spawn(move || {
            assert!(matches!(
                protocol::read_client(&mut helper).expect("read open"),
                protocol::ClientMessage::Open(_)
            ));
            protocol::write_server(
                &mut helper,
                &protocol::ServerMessage::Opened {
                    mac_address: [0x02, 1, 2, 3, 4, 5],
                },
            )
            .expect("write opened");
            match protocol::read_client(&mut helper).expect("read write request") {
                protocol::ClientMessage::Write { request_id, frame } => {
                    assert_eq!(frame, vec![0xaa; 60]);
                    protocol::write_server(
                        &mut helper,
                        &protocol::ServerMessage::Ok { request_id },
                    )
                    .expect("ack write");
                }
                request => panic!("unexpected request: {request:?}"),
            }
            match protocol::read_client(&mut helper).expect("read frame request") {
                protocol::ClientMessage::Read { request_id, .. } => {
                    protocol::write_server(
                        &mut helper,
                        &protocol::ServerMessage::Frame {
                            request_id,
                            frame: vec![0xbb; 60],
                        },
                    )
                    .expect("return frame");
                }
                request => panic!("unexpected request: {request:?}"),
            }
            match protocol::read_client(&mut helper).expect("read MTU request") {
                protocol::ClientMessage::SetMtu { request_id, mtu } => {
                    assert_eq!(mtu, 1_400);
                    protocol::write_server(
                        &mut helper,
                        &protocol::ServerMessage::Ok { request_id },
                    )
                    .expect("ack MTU");
                }
                request => panic!("unexpected request: {request:?}"),
            }
            match protocol::read_client(&mut helper).expect("read close request") {
                protocol::ClientMessage::Close { request_id } => {
                    protocol::write_server(
                        &mut helper,
                        &protocol::ServerMessage::Ok { request_id },
                    )
                    .expect("ack close");
                }
                request => panic!("unexpected request: {request:?}"),
            }
        });

        let config = TapConfig {
            name: Some("feth100".to_owned()),
            peer_name: Some("feth101".to_owned()),
            mtu: 1_500,
            max_frame_size: 1_514,
        };
        let uid = sys::effective_uid();
        let mut proxy =
            MacosTapProxyDevice::from_stream(&config, client, uid).expect("connect to mock helper");
        assert_eq!(
            proxy.mac_address().expect("proxy MAC"),
            [0x02, 1, 2, 3, 4, 5]
        );
        proxy.write_frame(&[0xaa; 60]).expect("proxy write");
        let mut frame = vec![0_u8; 1_514];
        let length = proxy.read_frame(&mut frame).expect("proxy read");
        assert_eq!(&frame[..length], &[0xbb; 60]);
        proxy.set_mtu(1_400).expect("proxy MTU");
        proxy.destroy().expect("proxy close");
        server.join().expect("mock helper did not panic");
    }

    #[test]
    fn proxy_cancellation_interrupts_only_the_pending_request() {
        let (client, mut helper) = UnixStream::pair().expect("create mock helper socket pair");
        let (pending, pending_receiver) = mpsc::channel();
        let server = thread::spawn(move || {
            let _ = protocol::read_client(&mut helper).expect("read open");
            protocol::write_server(
                &mut helper,
                &protocol::ServerMessage::Opened {
                    mac_address: [0x02, 1, 2, 3, 4, 5],
                },
            )
            .expect("write opened");
            let request_id = match protocol::read_client(&mut helper).expect("read frame request") {
                protocol::ClientMessage::Read { request_id, .. } => request_id,
                request => panic!("unexpected request: {request:?}"),
            };
            pending.send(()).expect("announce pending request");
            assert!(matches!(
                protocol::read_client(&mut helper).expect("read cancellation"),
                protocol::ClientMessage::Cancel
            ));
            protocol::write_server(
                &mut helper,
                &protocol::ServerMessage::Error {
                    request_id,
                    kind: protocol::RemoteErrorKind::Cancelled,
                    reason: "TAP I/O was cancelled".to_owned(),
                },
            )
            .expect("return cancellation");
        });
        let config = TapConfig {
            name: Some("feth100".to_owned()),
            peer_name: Some("feth101".to_owned()),
            mtu: 1_500,
            max_frame_size: 1_514,
        };
        let uid = sys::effective_uid();
        let proxy =
            MacosTapProxyDevice::from_stream(&config, client, uid).expect("open mock helper");
        let cancellation = proxy.cancellation_handle();
        cancellation
            .cancel_pending_io()
            .expect("idle cancellation is harmless");
        let reader = thread::spawn(move || {
            let mut proxy = proxy;
            let mut frame = [0_u8; 1_514];
            proxy.read_frame(&mut frame)
        });
        pending_receiver
            .recv_timeout(Duration::from_secs(2))
            .expect("proxy read became pending");
        cancellation
            .cancel_pending_io()
            .expect("cancel pending proxy read");
        assert!(matches!(
            reader.join().expect("proxy reader did not panic"),
            Err(TapError::Cancelled)
        ));
        server.join().expect("mock helper did not panic");
    }
}
