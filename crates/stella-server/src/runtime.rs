//! Bounded TLS listener lifecycle for the controller process.

use std::{
    error::Error,
    future::Future,
    net::SocketAddr,
    num::NonZeroUsize,
    path::Path,
    pin::Pin,
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use stella_common::ControllerId;
use stella_crypto::{derive_controller_id, IdentitySigningKey};
use thiserror::Error;
use tokio::{
    net::{TcpListener, TcpStream},
    sync::{watch, OwnedSemaphorePermit, Semaphore},
    task::JoinSet,
    time::{interval, timeout, MissedTickBehavior},
};
use tokio_rustls::{server::TlsStream, TlsAcceptor};

use crate::{
    authority::{AuthorityError, AuthorityHandle, AuthorityThread},
    config::{ConfigError, LimitsConfig, ServerConfig},
    connectivity_config::{ConnectivityConfigError, ConnectivityConfigIssuer},
    identity::{load_controller_identity, IdentityFileError},
    store::{AuthorityStore, StoreError},
    tls::{load_tls_server_config, TlsIdentityError},
};

const LEASE_MAINTENANCE_INTERVAL: Duration = Duration::from_secs(1);

/// Boxed error returned by one authenticated control-session handler.
pub type SessionError = Box<dyn Error + Send + Sync + 'static>;

/// Result returned by one authenticated control-session handler.
pub type SessionResult = Result<(), SessionError>;

/// Boxed future produced by a control-session handler.
pub type SessionFuture = Pin<Box<dyn Future<Output = SessionResult> + Send + 'static>>;

/// Shared callable that serves one successfully negotiated TLS connection.
pub type SessionHandler = Arc<dyn Fn(AcceptedSession) -> SessionFuture + Send + Sync + 'static>;

/// Shared immutable authority and lifecycle context for one TLS session.
#[derive(Clone)]
pub struct SessionContext {
    authority: AuthorityHandle,
    controller_identity: Arc<IdentitySigningKey>,
    controller_id: ControllerId,
    limits: LimitsConfig,
    connectivity: Option<Arc<ConnectivityConfigIssuer>>,
    shutdown: watch::Receiver<bool>,
}

impl SessionContext {
    /// Returns the serialized authority command handle.
    #[must_use]
    pub const fn authority(&self) -> &AuthorityHandle {
        &self.authority
    }

    /// Returns the protected controller signing identity.
    #[must_use]
    pub fn controller_identity(&self) -> &IdentitySigningKey {
        &self.controller_identity
    }

    /// Returns the controller ID derived from the signing identity.
    #[must_use]
    pub const fn controller_id(&self) -> ControllerId {
        self.controller_id
    }

    /// Returns validated per-session resource and deadline limits.
    #[must_use]
    pub const fn limits(&self) -> LimitsConfig {
        self.limits
    }

    pub(crate) fn connectivity(&self) -> Option<&ConnectivityConfigIssuer> {
        self.connectivity.as_deref()
    }

    /// Returns a receiver that changes to `true` when shutdown begins.
    #[must_use]
    pub fn shutdown(&self) -> watch::Receiver<bool> {
        self.shutdown.clone()
    }
}

/// One TLS 1.3 connection admitted by the bounded controller runtime.
pub struct AcceptedSession {
    stream: TlsStream<TcpStream>,
    peer_addr: SocketAddr,
    context: SessionContext,
}

impl AcceptedSession {
    /// Returns the numeric TCP peer address used only for diagnostics.
    #[must_use]
    pub const fn peer_addr(&self) -> SocketAddr {
        self.peer_addr
    }

    /// Borrows the shared authority and lifecycle context.
    #[must_use]
    pub const fn context(&self) -> &SessionContext {
        &self.context
    }

    /// Splits the admitted connection into its owned stream, peer, and context.
    #[must_use]
    pub fn into_parts(self) -> (TlsStream<TcpStream>, SocketAddr, SessionContext) {
        (self.stream, self.peer_addr, self.context)
    }
}

/// Loads a deployment and serves bounded TLS sessions until shutdown.
///
/// Configuration, controller identity, TLS identity, database binding, and all
/// persisted invariants are validated before TCP is bound. `shutdown` may be a
/// Ctrl+C future in production or a deterministic signal in tests.
///
/// # Errors
///
/// Returns [`RuntimeError`] for configuration, identity, TLS, persistence,
/// authority-thread, bind, accept, clock, maintenance, or shutdown failure.
pub async fn run_controller(
    config_path: &Path,
    shutdown: impl Future<Output = ()> + Send,
    handler: SessionHandler,
) -> Result<(), RuntimeError> {
    let prepared = PreparedController::load(config_path)?;
    let listener = TcpListener::bind(prepared.config.listen)
        .await
        .map_err(|source| RuntimeError::Bind {
            address: prepared.config.listen,
            source,
        })?;
    let PreparedController {
        config,
        controller_identity,
        controller_id,
        tls_acceptor,
        store,
        connectivity,
    } = prepared;
    let authority = AuthorityThread::spawn(
        store,
        NonZeroUsize::new(config.limits.authority_queue).ok_or(RuntimeError::ZeroAuthorityQueue)?,
    )?;
    let resources = ListenerResources {
        config,
        controller_identity,
        controller_id,
        tls_acceptor,
        authority: authority.handle(),
        handler,
        connectivity,
    };
    let result = serve_listener(listener, resources, shutdown).await;
    let shutdown_result = authority.shutdown().await;
    match (result, shutdown_result) {
        (Ok(()), Ok(())) => Ok(()),
        (Ok(()), Err(error)) => Err(RuntimeError::Authority(error)),
        (Err(error), _) => Err(error),
    }
}

struct PreparedController {
    config: ServerConfig,
    controller_identity: Arc<IdentitySigningKey>,
    controller_id: ControllerId,
    tls_acceptor: TlsAcceptor,
    store: AuthorityStore,
    connectivity: Option<Arc<ConnectivityConfigIssuer>>,
}

struct ListenerResources {
    config: ServerConfig,
    controller_identity: Arc<IdentitySigningKey>,
    controller_id: ControllerId,
    tls_acceptor: TlsAcceptor,
    authority: AuthorityHandle,
    handler: SessionHandler,
    connectivity: Option<Arc<ConnectivityConfigIssuer>>,
}

impl PreparedController {
    fn load(config_path: &Path) -> Result<Self, RuntimeError> {
        let config = ServerConfig::load(config_path)?;
        let controller_identity =
            Arc::new(load_controller_identity(&config.controller_identity_path)?);
        let controller_id = derive_controller_id(controller_identity.public_key());
        let tls_config =
            load_tls_server_config(&config.tls_certificate_path, &config.tls_private_key_path)?;
        let store = AuthorityStore::open(&config.database_path, controller_id)?;
        let connectivity = config
            .connectivity
            .as_ref()
            .map(ConnectivityConfigIssuer::load)
            .transpose()?
            .map(Arc::new);
        Ok(Self {
            config,
            controller_identity,
            controller_id,
            tls_acceptor: TlsAcceptor::from(tls_config),
            store,
            connectivity,
        })
    }
}

async fn serve_listener(
    listener: TcpListener,
    resources: ListenerResources,
    shutdown: impl Future<Output = ()> + Send,
) -> Result<(), RuntimeError> {
    let ListenerResources {
        config,
        controller_identity,
        controller_id,
        tls_acceptor,
        authority,
        handler,
        connectivity,
    } = resources;
    let limits = config.limits;
    let semaphore = Arc::new(Semaphore::new(limits.max_connections));
    let (shutdown_sender, shutdown_receiver) = watch::channel(false);
    let context = SessionContext {
        authority: authority.clone(),
        controller_identity,
        controller_id,
        limits,
        connectivity,
        shutdown: shutdown_receiver,
    };
    let mut tasks = JoinSet::new();
    let mut maintenance = interval(LEASE_MAINTENANCE_INTERVAL);
    maintenance.set_missed_tick_behavior(MissedTickBehavior::Skip);
    maintenance.tick().await;
    tokio::pin!(shutdown);

    tracing::info!(address = %config.listen, "controller listener ready");
    let loop_result = loop {
        tokio::select! {
            () = &mut shutdown => break Ok(()),
            joined = tasks.join_next(), if !tasks.is_empty() => {
                if let Some(Err(error)) = joined {
                    tracing::error!(error = %error, "controller connection task failed");
                }
            }
            _ = maintenance.tick() => {
                let now = match unix_time() {
                    Ok(now) => now,
                    Err(error) => break Err(error),
                };
                let expired = match authority.expire_endpoints(now).await {
                    Ok(expired) => expired,
                    Err(error) => break Err(RuntimeError::Authority(error)),
                };
                for revision in expired {
                    tracing::info!(
                        network_id = %revision.network_id,
                        snapshot_revision = revision.snapshot_revision,
                        "expired peer endpoint leases"
                    );
                }
            }
            admitted = accept_with_permit(&listener, Arc::clone(&semaphore)) => {
                let (stream, peer_addr, permit) = match admitted {
                    Ok(admitted) => admitted,
                    Err(error) => break Err(error),
                };
                spawn_connection(
                    &mut tasks,
                    tls_acceptor.clone(),
                    stream,
                    peer_addr,
                    permit,
                    context.clone(),
                    Arc::clone(&handler),
                );
            }
        }
    };

    let _shutdown_result = shutdown_sender.send(true);
    drain_connections(
        &mut tasks,
        Duration::from_secs(limits.shutdown_timeout_seconds),
    )
    .await;
    tracing::info!("controller listener stopped");
    loop_result
}

async fn accept_with_permit(
    listener: &TcpListener,
    semaphore: Arc<Semaphore>,
) -> Result<(TcpStream, SocketAddr, OwnedSemaphorePermit), RuntimeError> {
    let (stream, peer_addr) = listener
        .accept()
        .await
        .map_err(|source| RuntimeError::Accept { source })?;
    let permit = semaphore
        .acquire_owned()
        .await
        .map_err(|_| RuntimeError::ConnectionSemaphoreClosed)?;
    Ok((stream, peer_addr, permit))
}

fn spawn_connection(
    tasks: &mut JoinSet<()>,
    tls_acceptor: TlsAcceptor,
    stream: TcpStream,
    peer_addr: SocketAddr,
    permit: OwnedSemaphorePermit,
    context: SessionContext,
    handler: SessionHandler,
) {
    tasks.spawn(async move {
        let _permit = permit;
        let handshake = timeout(
            Duration::from_secs(context.limits.tls_handshake_timeout_seconds),
            tls_acceptor.accept(stream),
        )
        .await;
        let tls_stream = match handshake {
            Ok(Ok(stream)) => stream,
            Ok(Err(error)) => {
                tracing::warn!(peer = %peer_addr, error = %error, "TLS handshake failed");
                return;
            }
            Err(_) => {
                tracing::warn!(peer = %peer_addr, "TLS handshake timed out");
                return;
            }
        };
        let session = AcceptedSession {
            stream: tls_stream,
            peer_addr,
            context,
        };
        if let Err(error) = handler(session).await {
            tracing::warn!(peer = %peer_addr, error = %error, "control session failed");
        }
    });
}

async fn drain_connections(tasks: &mut JoinSet<()>, deadline: Duration) {
    let drain = async { while tasks.join_next().await.is_some() {} };
    if timeout(deadline, drain).await.is_err() {
        tasks.abort_all();
        while tasks.join_next().await.is_some() {}
    }
}

fn unix_time() -> Result<u64, RuntimeError> {
    Ok(SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| RuntimeError::ClockBeforeUnixEpoch)?
        .as_secs())
}

/// Controller runtime startup, listener, maintenance, or shutdown failure.
#[derive(Debug, Error)]
pub enum RuntimeError {
    /// Strict configuration loading failed.
    #[error(transparent)]
    Config(#[from] ConfigError),
    /// Protected controller identity loading failed.
    #[error(transparent)]
    Identity(#[from] IdentityFileError),
    /// TLS identity loading or configuration failed.
    #[error(transparent)]
    Tls(#[from] TlsIdentityError),
    /// Authority database loading or verification failed.
    #[error(transparent)]
    Store(#[from] StoreError),
    /// Authority command or worker lifecycle failed.
    #[error(transparent)]
    Authority(#[from] AuthorityError),
    /// Deployment connectivity service or credential-key loading failed.
    #[error("deployment connectivity configuration failed: {source}")]
    Connectivity {
        /// Redacted configuration or protected-key failure.
        #[source]
        source: Box<dyn Error + Send + Sync>,
    },
    /// A validated queue size unexpectedly became zero.
    #[error("authority queue capacity unexpectedly became zero")]
    ZeroAuthorityQueue,
    /// The configured TCP address could not be bound.
    #[error("unable to bind controller TCP listener at {address}: {source}")]
    Bind {
        /// Configured listen address.
        address: SocketAddr,
        /// Underlying socket failure.
        #[source]
        source: std::io::Error,
    },
    /// Accepting a TCP connection failed.
    #[error("unable to accept controller TCP connection: {source}")]
    Accept {
        /// Underlying socket failure.
        #[source]
        source: std::io::Error,
    },
    /// The internal connection semaphore was closed unexpectedly.
    #[error("controller connection semaphore closed unexpectedly")]
    ConnectionSemaphoreClosed,
    /// The host clock is earlier than the Unix epoch.
    #[error("system clock is before the Unix epoch")]
    ClockBeforeUnixEpoch,
}

impl From<ConnectivityConfigError> for RuntimeError {
    fn from(source: ConnectivityConfigError) -> Self {
        Self::Connectivity {
            source: Box::new(source),
        }
    }
}

#[cfg(all(test, windows))]
mod tests {
    use std::{
        fs::File,
        io::BufReader,
        net::SocketAddr,
        path::PathBuf,
        sync::{
            atomic::{AtomicU64, Ordering},
            Arc,
        },
        time::Duration,
    };

    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::TcpStream,
        sync::oneshot,
        time::sleep,
    };
    use tokio_rustls::{
        rustls::{self, pki_types::ServerName, version::TLS13, ClientConfig, RootCertStore},
        TlsConnector,
    };

    use super::{run_controller, SessionHandler};
    use crate::{
        bootstrap::{initialize_controller, BootstrapOptions},
        config::ServerConfig,
    };

    static TEMP_SEQUENCE: AtomicU64 = AtomicU64::new(1);

    fn temp_directory() -> PathBuf {
        let sequence = TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        std::env::temp_dir().join(format!(
            "stella-controller-runtime-{}-{sequence}",
            std::process::id()
        ))
    }

    fn reserve_loopback_address() -> SocketAddr {
        let listener =
            std::net::TcpListener::bind("127.0.0.1:0").expect("reserve loopback test address");
        listener.local_addr().expect("read reserved address")
    }

    fn client_connector(certificate_path: &std::path::Path) -> TlsConnector {
        let file = File::open(certificate_path).expect("open test certificate");
        let mut reader = BufReader::new(file);
        let certificates = rustls_pemfile::certs(&mut reader)
            .collect::<Result<Vec<_>, _>>()
            .expect("decode test certificate");
        let mut roots = RootCertStore::empty();
        for certificate in certificates {
            roots.add(certificate).expect("trust test certificate");
        }
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let client = ClientConfig::builder_with_provider(provider)
            .with_protocol_versions(&[&TLS13])
            .expect("configure TLS 1.3 client")
            .with_root_certificates(roots)
            .with_no_client_auth();
        TlsConnector::from(Arc::new(client))
    }

    async fn connect_with_retry(address: SocketAddr) -> TcpStream {
        for _ in 0..100 {
            match TcpStream::connect(address).await {
                Ok(stream) => return stream,
                Err(_) => sleep(Duration::from_millis(10)).await,
            }
        }
        TcpStream::connect(address)
            .await
            .expect("controller listener becomes ready")
    }

    #[tokio::test(flavor = "current_thread")]
    async fn loopback_tls_session_runs_and_shutdown_joins_authority() {
        let directory = temp_directory();
        let config_path = directory.join("server.toml");
        let address = reserve_loopback_address();
        let initialized = initialize_controller(
            &config_path,
            &BootstrapOptions {
                listen: address,
                ..BootstrapOptions::default()
            },
        )
        .expect("initialize controller deployment");
        let config = ServerConfig::load(&config_path).expect("load test configuration");
        let connector = client_connector(&config.tls_certificate_path);
        let expected_controller_id = initialized.controller_id;
        let handler: SessionHandler = Arc::new(move |session| {
            Box::pin(async move {
                let (mut stream, peer_addr, context) = session.into_parts();
                assert!(peer_addr.ip().is_loopback());
                assert_eq!(context.controller_id(), expected_controller_id);
                let mut shutdown = context.shutdown();
                stream.write_all(&[0x53]).await?;
                if !*shutdown.borrow() {
                    shutdown.changed().await?;
                }
                Ok::<(), super::SessionError>(())
            })
        });
        let (shutdown_sender, shutdown_receiver) = oneshot::channel();
        let server_path = config_path.clone();
        let server = tokio::spawn(async move {
            run_controller(
                &server_path,
                async move {
                    let _shutdown = shutdown_receiver.await;
                },
                handler,
            )
            .await
        });

        let tcp = connect_with_retry(address).await;
        let server_name = ServerName::try_from("localhost")
            .expect("valid test server name")
            .to_owned();
        let mut tls = connector
            .connect(server_name, tcp)
            .await
            .expect("complete TLS 1.3 handshake");
        let mut marker = [0_u8; 1];
        tls.read_exact(&mut marker)
            .await
            .expect("read session marker");
        assert_eq!(marker, [0x53]);
        shutdown_sender.send(()).expect("request server shutdown");
        server
            .await
            .expect("server task joins")
            .expect("server shuts down cleanly");
        std::fs::remove_dir_all(&directory).expect("remove test directory");
    }
}
