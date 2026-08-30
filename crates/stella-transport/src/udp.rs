//! Tokio-managed single-family UDP transport.

use std::{fmt, net::SocketAddr};

use socket2::{Domain, Protocol, Socket, Type};
use tokio::{
    net::UdpSocket,
    sync::{watch, Mutex},
};

use crate::{
    error::{io_error, is_message_too_long},
    DatagramTransport, Endpoint, IoOperation, ReceivedDatagram, Result, TransportCapabilities,
    TransportError, TransportFuture,
};

/// Minimum UDP datagram size advertised by Stella version 0.1.
pub const MIN_UDP_DATAGRAM_SIZE: usize = 1_200;

/// Absolute Stella version 0.1 UDP payload ceiling.
pub const MAX_UDP_DATAGRAM_SIZE: usize = 65_507;

/// Default conservative UDP datagram size.
pub const DEFAULT_UDP_DATAGRAM_SIZE: usize = MIN_UDP_DATAGRAM_SIZE;

const UDP_RECEIVE_SCRATCH_LENGTH: usize = u16::MAX as usize;

/// Configuration for one single-family UDP transport instance.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct UdpConfig {
    /// Numeric local address and port to bind.
    pub bind_address: SocketAddr,
    /// Advertised and enforced datagram size ceiling.
    pub max_datagram_size: usize,
}

impl UdpConfig {
    /// Constructs a UDP configuration with the conservative 1,200-byte limit.
    #[must_use]
    pub const fn new(bind_address: SocketAddr) -> Self {
        Self {
            bind_address,
            max_datagram_size: DEFAULT_UDP_DATAGRAM_SIZE,
        }
    }

    fn validate(self) -> Result<()> {
        if !(MIN_UDP_DATAGRAM_SIZE..=MAX_UDP_DATAGRAM_SIZE).contains(&self.max_datagram_size) {
            return Err(TransportError::InvalidConfig {
                field: "maximum datagram size",
                reason: "must be between 1200 and 65507 bytes",
            });
        }
        Ok(())
    }
}

/// One Tokio UDP socket implementing the Stella datagram contract.
pub struct UdpTransport {
    socket: UdpSocket,
    local_address: SocketAddr,
    capabilities: TransportCapabilities,
    receive_scratch: Mutex<Vec<u8>>,
    shutdown: watch::Sender<bool>,
}

impl UdpTransport {
    /// Creates, configures, and binds one non-blocking UDP socket.
    ///
    /// IPv6 sockets have `IPV6_V6ONLY` enabled before bind so one instance has
    /// an unambiguous address family.
    ///
    /// # Errors
    ///
    /// Returns a typed configuration or operating-system bind error.
    pub async fn bind(config: UdpConfig) -> Result<Self> {
        config.validate()?;
        let socket = create_bound_socket(config.bind_address)?;
        let socket = UdpSocket::from_std(socket)
            .map_err(|error| io_error(IoOperation::Bind, None, error))?;
        socket
            .writable()
            .await
            .map_err(|error| io_error(IoOperation::Bind, None, error))?;
        let local_address = socket
            .local_addr()
            .map_err(|error| io_error(IoOperation::Bind, None, error))?;
        let (shutdown, _receiver) = watch::channel(false);

        Ok(Self {
            socket,
            local_address,
            capabilities: TransportCapabilities {
                max_datagram_size: config.max_datagram_size,
            },
            receive_scratch: Mutex::new(vec![0_u8; UDP_RECEIVE_SCRATCH_LENGTH]),
            shutdown,
        })
    }

    /// Returns the numeric address assigned by the operating system.
    #[must_use]
    pub const fn local_address(&self) -> SocketAddr {
        self.local_address
    }

    fn is_shutdown(&self) -> bool {
        *self.shutdown.borrow()
    }

    fn check_family(&self, remote: SocketAddr) -> Result<()> {
        if self.local_address.is_ipv4() == remote.is_ipv4() {
            return Ok(());
        }
        Err(TransportError::AddressFamilyMismatch {
            local: address_family(self.local_address),
            remote: address_family(remote),
        })
    }
}

impl DatagramTransport for UdpTransport {
    fn capabilities(&self) -> TransportCapabilities {
        self.capabilities
    }

    fn local_endpoints(&self) -> Result<Vec<Endpoint>> {
        if self.is_shutdown() {
            return Err(TransportError::Shutdown);
        }
        Ok(vec![Endpoint::Udp(self.local_address)])
    }

    fn send_to<'a>(
        &'a self,
        endpoint: &'a Endpoint,
        datagram: &'a [u8],
    ) -> TransportFuture<'a, ()> {
        Box::pin(async move {
            if self.is_shutdown() {
                return Err(TransportError::Shutdown);
            }
            let remote = endpoint
                .as_udp()
                .ok_or(TransportError::UnsupportedEndpoint)?;
            self.check_family(remote)?;
            if datagram.len() > self.capabilities.max_datagram_size {
                return Err(TransportError::DatagramTooLarge {
                    actual: datagram.len(),
                    maximum: self.capabilities.max_datagram_size,
                });
            }

            let mut shutdown = self.shutdown.subscribe();
            if *shutdown.borrow() {
                return Err(TransportError::Shutdown);
            }
            let result = tokio::select! {
                biased;
                _ = shutdown.changed() => return Err(TransportError::Shutdown),
                result = self.socket.send_to(datagram, remote) => result,
            };
            let sent = match result {
                Ok(sent) => sent,
                Err(error) if is_message_too_long(&error) => {
                    return Err(TransportError::PathDatagramTooLarge {
                        endpoint: endpoint.clone(),
                        attempted: datagram.len(),
                        source: error,
                    });
                }
                Err(error) => {
                    return Err(io_error(IoOperation::Send, Some(endpoint.clone()), error));
                }
            };
            if sent != datagram.len() {
                return Err(TransportError::PartialDatagramSend {
                    expected: datagram.len(),
                    actual: sent,
                });
            }
            Ok(())
        })
    }

    fn receive<'a>(&'a self, output: &'a mut [u8]) -> TransportFuture<'a, ReceivedDatagram> {
        Box::pin(async move {
            if self.is_shutdown() {
                return Err(TransportError::Shutdown);
            }
            let mut shutdown = self.shutdown.subscribe();
            if *shutdown.borrow() {
                return Err(TransportError::Shutdown);
            }
            let mut scratch = tokio::select! {
                biased;
                _ = shutdown.changed() => return Err(TransportError::Shutdown),
                scratch = self.receive_scratch.lock() => scratch,
            };
            let received = tokio::select! {
                biased;
                _ = shutdown.changed() => return Err(TransportError::Shutdown),
                result = self.socket.recv_from(scratch.as_mut_slice()) => result,
            };
            let (length, source) = match received {
                Ok(received) => received,
                Err(error) if is_message_too_long(&error) => {
                    return Err(TransportError::ReceiveTruncated { source: error });
                }
                Err(error) => {
                    return Err(io_error(IoOperation::Receive, None, error));
                }
            };
            if length > self.capabilities.max_datagram_size {
                clear_received(&mut scratch, length);
                return Err(TransportError::DatagramTooLarge {
                    actual: length,
                    maximum: self.capabilities.max_datagram_size,
                });
            }
            if output.len() < length {
                clear_received(&mut scratch, length);
                return Err(TransportError::ReceiveBufferTooSmall {
                    needed: length,
                    remaining: output.len(),
                });
            }
            let remaining = output.len();
            let Some(destination) = output.get_mut(..length) else {
                clear_received(&mut scratch, length);
                return Err(TransportError::ReceiveBufferTooSmall {
                    needed: length,
                    remaining,
                });
            };
            let Some(datagram) = scratch.get(..length) else {
                scratch.fill(0);
                return Err(TransportError::ReceiveTruncated {
                    source: std::io::Error::new(
                        std::io::ErrorKind::UnexpectedEof,
                        "UDP receive length exceeds scratch buffer",
                    ),
                });
            };
            destination.copy_from_slice(datagram);
            clear_received(&mut scratch, length);
            Ok(ReceivedDatagram {
                source: Endpoint::Udp(source),
                length,
            })
        })
    }

    fn shutdown(&self) -> TransportFuture<'_, ()> {
        Box::pin(async move {
            self.shutdown.send_replace(true);
            self.receive_scratch.lock().await.fill(0);
            Ok(())
        })
    }
}

impl Drop for UdpTransport {
    fn drop(&mut self) {
        self.receive_scratch.get_mut().fill(0);
    }
}

impl fmt::Debug for UdpTransport {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("UdpTransport")
            .field("local_address", &self.local_address)
            .field("capabilities", &self.capabilities)
            .field("shutdown", &self.is_shutdown())
            .finish_non_exhaustive()
    }
}

fn clear_received(scratch: &mut [u8], length: usize) {
    if let Some(datagram) = scratch.get_mut(..length) {
        datagram.fill(0);
    } else {
        scratch.fill(0);
    }
}

fn create_bound_socket(address: SocketAddr) -> Result<std::net::UdpSocket> {
    let domain = Domain::for_address(address);
    let socket = Socket::new(domain, Type::DGRAM, Some(Protocol::UDP))
        .map_err(|error| io_error(IoOperation::Bind, None, error))?;
    if address.is_ipv6() {
        socket
            .set_only_v6(true)
            .map_err(|error| io_error(IoOperation::Bind, None, error))?;
    }
    socket
        .set_nonblocking(true)
        .map_err(|error| io_error(IoOperation::Bind, None, error))?;
    socket
        .bind(&address.into())
        .map_err(|error| io_error(IoOperation::Bind, None, error))?;
    Ok(socket.into())
}

const fn address_family(address: SocketAddr) -> &'static str {
    match address {
        SocketAddr::V4(_) => "IPv4",
        SocketAddr::V6(_) => "IPv6",
    }
}

#[cfg(test)]
mod tests {
    use std::{
        net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
        sync::Arc,
        time::Duration,
    };

    use tokio::time::timeout;

    use super::{UdpConfig, UdpTransport, DEFAULT_UDP_DATAGRAM_SIZE};
    use crate::{DatagramTransport, Endpoint, IoErrorClass, TransportError};

    #[tokio::test]
    async fn ipv4_loopback_preserves_boundaries_source_and_limits() {
        let sender = bind_loopback(IpAddr::V4(Ipv4Addr::LOCALHOST)).await;
        let receiver = bind_loopback(IpAddr::V4(Ipv4Addr::LOCALHOST)).await;
        let receiver_endpoint = Endpoint::Udp(receiver.local_address());

        let maximum = vec![0x5a; DEFAULT_UDP_DATAGRAM_SIZE];
        sender
            .send_to(&receiver_endpoint, &maximum)
            .await
            .expect("maximum-size loopback send");
        let mut output = vec![0_u8; DEFAULT_UDP_DATAGRAM_SIZE];
        let metadata = receiver
            .receive(&mut output)
            .await
            .expect("complete loopback receive");
        assert_eq!(metadata.length, maximum.len());
        assert_eq!(metadata.source, Endpoint::Udp(sender.local_address()));
        assert_eq!(output, maximum);

        let oversized = vec![0_u8; DEFAULT_UDP_DATAGRAM_SIZE + 1];
        assert!(matches!(
            sender.send_to(&receiver_endpoint, &oversized).await,
            Err(TransportError::DatagramTooLarge {
                actual,
                maximum: DEFAULT_UDP_DATAGRAM_SIZE,
            }) if actual == oversized.len()
        ));
    }

    #[tokio::test]
    async fn receive_buffer_failure_never_exposes_a_prefix() {
        let sender = bind_loopback(IpAddr::V4(Ipv4Addr::LOCALHOST)).await;
        let receiver = bind_loopback(IpAddr::V4(Ipv4Addr::LOCALHOST)).await;
        let payload = b"complete datagram";
        sender
            .send_to(&Endpoint::Udp(receiver.local_address()), payload)
            .await
            .expect("loopback send");

        let mut output = [0x5a; 4];
        assert!(matches!(
            receiver.receive(&mut output).await,
            Err(TransportError::ReceiveBufferTooSmall { needed, remaining })
                if needed == payload.len() && remaining == output.len()
        ));
        assert_eq!(output, [0x5a; 4]);
    }

    #[tokio::test]
    async fn oversized_received_datagram_is_dropped_without_output() {
        let receiver = bind_loopback(IpAddr::V4(Ipv4Addr::LOCALHOST)).await;
        let sender = std::net::UdpSocket::bind(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0))
            .expect("raw loopback sender bind");
        let payload = vec![0x31; DEFAULT_UDP_DATAGRAM_SIZE + 1];
        sender
            .send_to(&payload, receiver.local_address())
            .expect("raw oversized loopback send");

        let mut output = vec![0x5a; DEFAULT_UDP_DATAGRAM_SIZE];
        assert!(matches!(
            receiver.receive(&mut output).await,
            Err(TransportError::DatagramTooLarge {
                actual,
                maximum: DEFAULT_UDP_DATAGRAM_SIZE,
            }) if actual == payload.len()
        ));
        assert_eq!(output, vec![0x5a; DEFAULT_UDP_DATAGRAM_SIZE]);
    }

    #[tokio::test]
    async fn pending_receive_is_cancelled_by_shutdown() {
        let transport = Arc::new(bind_loopback(IpAddr::V4(Ipv4Addr::LOCALHOST)).await);
        let receiving = Arc::clone(&transport);
        let task = tokio::spawn(async move {
            let mut output = [0_u8; 32];
            receiving.receive(&mut output).await
        });
        tokio::task::yield_now().await;
        transport.shutdown().await.expect("idempotent shutdown");

        assert!(matches!(
            timeout(Duration::from_secs(1), task)
                .await
                .expect("receive cancellation deadline")
                .expect("receive task did not panic"),
            Err(TransportError::Shutdown)
        ));
        assert!(transport.shutdown().await.is_ok());
        assert!(matches!(
            transport.local_endpoints(),
            Err(TransportError::Shutdown)
        ));
    }

    #[tokio::test]
    async fn endpoint_family_must_match_bound_socket() {
        let transport = bind_loopback(IpAddr::V4(Ipv4Addr::LOCALHOST)).await;
        let endpoint = Endpoint::Udp(SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), 9));
        assert!(matches!(
            transport.send_to(&endpoint, b"x").await,
            Err(TransportError::AddressFamilyMismatch {
                local: "IPv4",
                remote: "IPv6",
            })
        ));
    }

    #[tokio::test]
    async fn ipv6_loopback_preserves_source_family() {
        let sender = match UdpTransport::bind(UdpConfig::new(SocketAddr::new(
            IpAddr::V6(Ipv6Addr::LOCALHOST),
            0,
        )))
        .await
        {
            Ok(transport) => transport,
            Err(TransportError::Io {
                class: IoErrorClass::Address,
                ..
            }) => return,
            Err(error) => panic!("unexpected IPv6 bind failure: {error}"),
        };
        let receiver = bind_loopback(IpAddr::V6(Ipv6Addr::LOCALHOST)).await;
        sender
            .send_to(&Endpoint::Udp(receiver.local_address()), b"ipv6")
            .await
            .expect("IPv6 loopback send");
        let mut output = [0_u8; 16];
        let metadata = receiver
            .receive(&mut output)
            .await
            .expect("IPv6 loopback receive");
        assert_eq!(&output[..metadata.length], b"ipv6");
        assert!(metadata.source.as_udp().expect("UDP source").is_ipv6());
    }

    #[tokio::test]
    async fn configuration_enforces_protocol_datagram_bounds() {
        let mut config = UdpConfig::new(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0));
        config.max_datagram_size = DEFAULT_UDP_DATAGRAM_SIZE - 1;
        assert!(matches!(
            UdpTransport::bind(config).await,
            Err(TransportError::InvalidConfig {
                field: "maximum datagram size",
                ..
            })
        ));
    }

    #[tokio::test]
    async fn transport_trait_is_object_safe() {
        let transport = bind_loopback(IpAddr::V4(Ipv4Addr::LOCALHOST)).await;
        let dynamic: &dyn DatagramTransport = &transport;
        assert_eq!(
            dynamic.capabilities().max_datagram_size,
            DEFAULT_UDP_DATAGRAM_SIZE
        );
        assert_eq!(dynamic.local_endpoints().expect("active endpoint").len(), 1);
    }

    async fn bind_loopback(address: IpAddr) -> UdpTransport {
        UdpTransport::bind(UdpConfig::new(SocketAddr::new(address, 0)))
            .await
            .expect("loopback UDP bind")
    }
}
