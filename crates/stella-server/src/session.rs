//! TLS-exporter-bound controller authentication state machine.

use std::{
    net::SocketAddr,
    str,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use stella_common::NodeId;
use stella_control::{
    sign_controller_proof, verify_node_proof, ControlError, ControllerProofContext,
    InboundSequence, MessageBuilder, NodeProofContext, OutboundSequence, RecordReader,
    RecordWriter, CONTROL_EXPORTER_LABEL, CONTROL_EXPORTER_LENGTH, CONTROL_NONCE_LENGTH,
};
use stella_crypto::{validate_node_id, CryptoError, IdentityPublicKey, ED25519_SIGNATURE_LENGTH};
use stella_proto::{
    encode_version_list, CodecError, ControlFieldType, ControlHeader, ControlMessageType,
    ProtocolVersion, VersionEntry,
};
use thiserror::Error;
use tokio::{
    net::TcpStream,
    time::{sleep, timeout},
};
use tokio_rustls::{rustls, server::TlsStream};
use zeroize::Zeroizing;

use crate::{
    authority::AuthorityError,
    runtime::{AcceptedSession, SessionContext},
    store::{BearerToken, NodeRecord},
};

const AUTHENTICATION_FAILED: u16 = 100;
const ENROLLMENT_REQUIRED: u16 = 101;
const FAILURE_DELAY_MIN_MS: u64 = 75;
const FAILURE_DELAY_SPAN_MS: u8 = 101;

/// A TLS connection whose Stella node proof and authority policy succeeded.
pub struct AuthenticatedSession {
    stream: TlsStream<TcpStream>,
    peer_addr: SocketAddr,
    context: SessionContext,
    node: NodeRecord,
    protocol_version: ProtocolVersion,
    inbound: InboundSequence,
    outbound: OutboundSequence,
}

impl AuthenticatedSession {
    /// Returns the authenticated node record committed by the authority.
    #[must_use]
    pub const fn node(&self) -> &NodeRecord {
        &self.node
    }

    /// Returns the authenticated node ID derived from the node public key.
    #[must_use]
    pub fn node_id(&self) -> NodeId {
        self.node.node_id()
    }

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

    /// Returns the operational control version selected during authentication.
    #[must_use]
    pub const fn protocol_version(&self) -> ProtocolVersion {
        self.protocol_version
    }

    /// Splits the authenticated connection into active-loop state.
    #[must_use]
    pub fn into_parts(
        self,
    ) -> (
        TlsStream<TcpStream>,
        SocketAddr,
        SessionContext,
        NodeRecord,
        ProtocolVersion,
        InboundSequence,
        OutboundSequence,
    ) {
        (
            self.stream,
            self.peer_addr,
            self.context,
            self.node,
            self.protocol_version,
            self.inbound,
            self.outbound,
        )
    }
}

/// Authenticates one admitted TLS connection as exactly one Stella node.
///
/// The configured authentication deadline covers the complete hello, proof,
/// enrollment, result, and rejection-delay flow. No active control request is
/// accepted by this function.
///
/// # Errors
///
/// Returns [`AuthenticationError`] for timeout, framing, protocol state,
/// cryptographic, clock, authority, enrollment, TLS-exporter, or carrier
/// shutdown failure.
pub async fn authenticate_session(
    session: AcceptedSession,
) -> Result<AuthenticatedSession, AuthenticationError> {
    let deadline = Duration::from_secs(session.context().limits().authentication_timeout_seconds);
    timeout(deadline, authenticate_inner(session))
        .await
        .map_err(|_| AuthenticationError::Timeout)?
}

#[allow(
    clippy::too_many_lines,
    reason = "keeping the negotiated authentication transcript linear makes version binding auditable"
)]
async fn authenticate_inner(
    session: AcceptedSession,
) -> Result<AuthenticatedSession, AuthenticationError> {
    let (mut stream, peer_addr, context) = session.into_parts();
    let mut inbound = InboundSequence::new();
    let mut outbound = OutboundSequence::new();
    let server_nonce = random_nonzero_nonce()?;
    let server_hello_id =
        send_server_hello(&mut stream, &mut outbound, &context, &server_nonce).await?;

    let (client_hello_header, client_hello) = read_expected_message(
        &mut stream,
        &mut inbound,
        ControlMessageType::ClientHello,
        server_hello_id,
        None,
        parse_client_hello,
    )
    .await?;
    let protocol_version = ProtocolVersion {
        major: client_hello.selected.major,
        minor: client_hello.selected.minor,
    };
    require_protocol_version(client_hello_header.version, protocol_version)?;

    let exporter = stream
        .get_ref()
        .1
        .export_keying_material(
            [0_u8; CONTROL_EXPORTER_LENGTH],
            CONTROL_EXPORTER_LABEL,
            None,
        )
        .map_err(AuthenticationError::TlsExporter)?;
    let proof_context = ControllerProofContext::new(
        &exporter,
        &server_nonce,
        client_hello.selected,
        context.controller_id(),
    );
    let signature = sign_controller_proof(context.controller_identity(), proof_context);
    let server_proof_id = send_server_proof(
        &mut stream,
        &mut outbound,
        client_hello_header.message_id,
        protocol_version,
        &signature,
    )
    .await?;

    let (node_auth_header, node_auth) = read_expected_message(
        &mut stream,
        &mut inbound,
        ControlMessageType::NodeAuth,
        server_proof_id,
        Some(protocol_version),
        parse_node_auth,
    )
    .await?;
    let node_proof_context = NodeProofContext::new(
        &exporter,
        &server_nonce,
        &client_hello.client_nonce,
        client_hello.selected,
        context.controller_id(),
        client_hello.node_id,
    );
    if let Err(source) = verify_node_proof(
        client_hello.public_key,
        node_proof_context,
        &node_auth.signature,
    ) {
        reject_authentication(
            &mut stream,
            &mut outbound,
            node_auth_header.message_id,
            protocol_version,
            AUTHENTICATION_FAILED,
        )
        .await?;
        return Err(AuthenticationError::NodeProof { source });
    }

    let node = resolve_node_authorization(
        &mut stream,
        &mut outbound,
        &context,
        &client_hello,
        node_auth,
        node_auth_header.message_id,
        protocol_version,
    )
    .await?;

    send_auth_result(
        &mut stream,
        &mut outbound,
        node_auth_header.message_id,
        protocol_version,
        0,
    )
    .await?;
    Ok(AuthenticatedSession {
        stream,
        peer_addr,
        context,
        node,
        protocol_version,
        inbound,
        outbound,
    })
}

async fn send_server_hello(
    stream: &mut TlsStream<TcpStream>,
    outbound: &mut OutboundSequence,
    context: &SessionContext,
    server_nonce: &[u8; CONTROL_NONCE_LENGTH],
) -> Result<u64, AuthenticationError> {
    let mut versions = [0_u8; 12];
    let version_length = encode_version_list(
        &[VersionEntry::V0_2_SUITE_1, VersionEntry::V0_1_SUITE_1],
        &mut versions,
    )?;
    let server_time = unix_time()?.to_be_bytes();
    let public_key = context.controller_identity().public_key();
    let mut builder = MessageBuilder::new(ControlMessageType::ServerHello);
    builder.push_field(
        ControlFieldType::SupportedVersions,
        &versions[..version_length],
    )?;
    builder.push_field(ControlFieldType::ServerNonce, server_nonce)?;
    builder.push_field(
        ControlFieldType::ControllerId,
        context.controller_id().as_bytes(),
    )?;
    builder.push_field(ControlFieldType::ControllerPublicKey, public_key.as_bytes())?;
    builder.push_field(ControlFieldType::ServerTime, &server_time)?;
    write_built_message(stream, outbound, builder).await
}

async fn send_server_proof(
    stream: &mut TlsStream<TcpStream>,
    outbound: &mut OutboundSequence,
    correlation_id: u64,
    version: ProtocolVersion,
    signature: &[u8; ED25519_SIGNATURE_LENGTH],
) -> Result<u64, AuthenticationError> {
    let mut builder = MessageBuilder::new(ControlMessageType::ServerProof)
        .with_version(version)
        .with_correlation(correlation_id);
    builder.push_field(ControlFieldType::ControllerSignature, signature)?;
    write_built_message(stream, outbound, builder).await
}

async fn send_auth_result(
    stream: &mut TlsStream<TcpStream>,
    outbound: &mut OutboundSequence,
    correlation_id: u64,
    version: ProtocolVersion,
    status: u16,
) -> Result<u64, AuthenticationError> {
    let status = status.to_be_bytes();
    let server_time = unix_time()?.to_be_bytes();
    let mut builder = MessageBuilder::new(ControlMessageType::AuthResult)
        .with_version(version)
        .with_correlation(correlation_id);
    builder.push_field(ControlFieldType::StatusCode, &status)?;
    builder.push_field(ControlFieldType::ServerTime, &server_time)?;
    write_built_message(stream, outbound, builder).await
}

async fn write_built_message(
    stream: &mut TlsStream<TcpStream>,
    outbound: &mut OutboundSequence,
    builder: MessageBuilder,
) -> Result<u64, AuthenticationError> {
    let message = outbound.build(builder)?;
    let message_id = message.header()?.message_id;
    let mut writer = RecordWriter::new(stream);
    writer.write_message(&message).await?;
    writer.flush().await?;
    Ok(message_id)
}

async fn read_required_message(
    stream: &mut TlsStream<TcpStream>,
) -> Result<stella_control::OwnedControlMessage, AuthenticationError> {
    RecordReader::new(stream)
        .read_message()
        .await?
        .ok_or(AuthenticationError::UnexpectedEof)
}

async fn read_expected_message<T>(
    stream: &mut TlsStream<TcpStream>,
    inbound: &mut InboundSequence,
    expected_type: ControlMessageType,
    expected_correlation: u64,
    expected_version: Option<ProtocolVersion>,
    parse: fn(&stella_control::OwnedControlMessage) -> Result<T, AuthenticationError>,
) -> Result<(ControlHeader, T), AuthenticationError> {
    let message = read_required_message(stream).await?;
    let header = message.header()?;
    inbound.accept(header.message_id)?;
    if header.message_type != expected_type {
        return Err(AuthenticationError::UnexpectedMessage {
            expected: expected_type,
            actual: header.message_type,
        });
    }
    if header.correlation_id != expected_correlation {
        return Err(AuthenticationError::CorrelationMismatch {
            expected: expected_correlation,
            actual: header.correlation_id,
        });
    }
    if let Some(expected_version) = expected_version {
        require_protocol_version(header.version, expected_version)?;
    }
    Ok((header, parse(&message)?))
}

async fn reject_authentication(
    stream: &mut TlsStream<TcpStream>,
    outbound: &mut OutboundSequence,
    correlation_id: u64,
    version: ProtocolVersion,
    status: u16,
) -> Result<(), AuthenticationError> {
    let _message_id = send_auth_result(stream, outbound, correlation_id, version, status).await?;
    sleep(random_failure_delay()?).await;
    let mut writer = RecordWriter::new(stream);
    writer.shutdown().await?;
    Ok(())
}

async fn resolve_node_authorization(
    stream: &mut TlsStream<TcpStream>,
    outbound: &mut OutboundSequence,
    context: &SessionContext,
    client_hello: &ClientHello,
    node_auth: NodeAuth,
    correlation_id: u64,
    version: ProtocolVersion,
) -> Result<NodeRecord, AuthenticationError> {
    match authorize_node(context, client_hello, node_auth).await {
        Ok(node) => Ok(node),
        Err(AuthorizationFailure::EnrollmentRequired) => {
            reject_authentication(
                stream,
                outbound,
                correlation_id,
                version,
                ENROLLMENT_REQUIRED,
            )
            .await?;
            Err(AuthenticationError::Rejected {
                status: ENROLLMENT_REQUIRED,
            })
        }
        Err(AuthorizationFailure::Rejected) => {
            reject_authentication(
                stream,
                outbound,
                correlation_id,
                version,
                AUTHENTICATION_FAILED,
            )
            .await?;
            Err(AuthenticationError::Rejected {
                status: AUTHENTICATION_FAILED,
            })
        }
        Err(AuthorizationFailure::Authority(source)) => {
            reject_authentication(
                stream,
                outbound,
                correlation_id,
                version,
                AUTHENTICATION_FAILED,
            )
            .await?;
            Err(AuthenticationError::Authority(source))
        }
    }
}

struct ClientHello {
    selected: VersionEntry,
    client_nonce: [u8; CONTROL_NONCE_LENGTH],
    node_id: NodeId,
    public_key: IdentityPublicKey,
}

fn parse_client_hello(
    message: &stella_control::OwnedControlMessage,
) -> Result<ClientHello, AuthenticationError> {
    let view = message.view()?;
    let mut selected = None;
    let mut client_nonce = None;
    let mut node_id = None;
    let mut public_key = None;
    for field in view.fields() {
        match field.field_type() {
            Some(ControlFieldType::SelectedVersion) => {
                selected = Some(VersionEntry::decode(field.value())?);
            }
            Some(ControlFieldType::ClientNonce) => {
                client_nonce = Some(fixed_array(field.value(), "client nonce")?);
            }
            Some(ControlFieldType::NodeId) => {
                node_id = Some(NodeId::from_bytes(fixed_array(field.value(), "node ID")?));
            }
            Some(ControlFieldType::NodePublicKey) => {
                public_key = Some(IdentityPublicKey::from_bytes(fixed_array(
                    field.value(),
                    "node public key",
                )?)?);
            }
            _ => {}
        }
    }
    let selected = selected.ok_or(AuthenticationError::ValidatedFieldMissing {
        field: ControlFieldType::SelectedVersion,
    })?;
    if selected != VersionEntry::V0_1_SUITE_1 && selected != VersionEntry::V0_2_SUITE_1 {
        return Err(AuthenticationError::UnsupportedVersion {
            major: selected.major,
            minor: selected.minor,
            suite_id: selected.suite_id,
        });
    }
    let client_nonce = client_nonce.ok_or(AuthenticationError::ValidatedFieldMissing {
        field: ControlFieldType::ClientNonce,
    })?;
    if client_nonce.iter().all(|byte| *byte == 0) {
        return Err(AuthenticationError::ZeroClientNonce);
    }
    let node_id = node_id.ok_or(AuthenticationError::ValidatedFieldMissing {
        field: ControlFieldType::NodeId,
    })?;
    if node_id.is_zero() {
        return Err(AuthenticationError::ZeroNodeId);
    }
    let public_key = public_key.ok_or(AuthenticationError::ValidatedFieldMissing {
        field: ControlFieldType::NodePublicKey,
    })?;
    validate_node_id(node_id, public_key)?;
    Ok(ClientHello {
        selected,
        client_nonce,
        node_id,
        public_key,
    })
}

fn require_protocol_version(
    actual: ProtocolVersion,
    expected: ProtocolVersion,
) -> Result<(), AuthenticationError> {
    if actual != expected {
        return Err(AuthenticationError::ProtocolVersionMismatch { expected, actual });
    }
    Ok(())
}

struct NodeAuth {
    signature: [u8; ED25519_SIGNATURE_LENGTH],
    enrollment_token: Option<Zeroizing<[u8; 32]>>,
    display_name: Option<String>,
}

fn parse_node_auth(
    message: &stella_control::OwnedControlMessage,
) -> Result<NodeAuth, AuthenticationError> {
    let view = message.view()?;
    let mut signature = None;
    let mut enrollment_token = None;
    let mut display_name = None;
    for field in view.fields() {
        match field.field_type() {
            Some(ControlFieldType::NodeSignature) => {
                signature = Some(fixed_array(field.value(), "node signature")?);
            }
            Some(ControlFieldType::EnrollmentToken) => {
                enrollment_token = Some(Zeroizing::new(fixed_array(
                    field.value(),
                    "enrollment token",
                )?));
            }
            Some(ControlFieldType::DisplayName) => {
                display_name = Some(
                    str::from_utf8(field.value())
                        .map_err(|_| AuthenticationError::ValidatedUtf8Invalid {
                            field: "display name",
                        })?
                        .to_owned(),
                );
            }
            _ => {}
        }
    }
    Ok(NodeAuth {
        signature: signature.ok_or(AuthenticationError::ValidatedFieldMissing {
            field: ControlFieldType::NodeSignature,
        })?,
        enrollment_token,
        display_name,
    })
}

enum AuthorizationFailure {
    EnrollmentRequired,
    Rejected,
    Authority(AuthorityError),
}

async fn authorize_node(
    context: &SessionContext,
    client: &ClientHello,
    authentication: NodeAuth,
) -> Result<NodeRecord, AuthorizationFailure> {
    let existing = context
        .authority()
        .get_node(client.node_id)
        .await
        .map_err(AuthorizationFailure::Authority)?;
    if let Some(node) = existing {
        if node.public_key() != client.public_key
            || !node.enabled()
            || authentication.enrollment_token.is_some()
            || authentication.display_name.is_some()
        {
            return Err(AuthorizationFailure::Rejected);
        }
        return Ok(node);
    }

    let (token, display_name) = match (authentication.enrollment_token, authentication.display_name)
    {
        (None, None) => return Err(AuthorizationFailure::EnrollmentRequired),
        (Some(token), Some(display_name)) => (token, display_name),
        _ => return Err(AuthorizationFailure::Rejected),
    };
    let token = BearerToken::from_bytes(*token).map_err(|_| AuthorizationFailure::Rejected)?;
    context
        .authority()
        .enroll_node(
            &token,
            client.public_key,
            display_name,
            unix_time_for_authority()?,
        )
        .await
        .map_err(AuthorizationFailure::Authority)
}

fn unix_time_for_authority() -> Result<u64, AuthorizationFailure> {
    unix_time().map_err(|_| AuthorizationFailure::Rejected)
}

fn fixed_array<const N: usize>(
    value: &[u8],
    field: &'static str,
) -> Result<[u8; N], AuthenticationError> {
    value
        .try_into()
        .map_err(|_| AuthenticationError::ValidatedLengthInvalid {
            field,
            expected: N,
            actual: value.len(),
        })
}

fn random_nonzero_nonce() -> Result<[u8; CONTROL_NONCE_LENGTH], AuthenticationError> {
    let mut nonce = [0_u8; CONTROL_NONCE_LENGTH];
    loop {
        getrandom::fill(&mut nonce).map_err(|_| AuthenticationError::RandomnessUnavailable)?;
        if nonce.iter().any(|byte| *byte != 0) {
            return Ok(nonce);
        }
    }
}

fn random_failure_delay() -> Result<Duration, AuthenticationError> {
    let mut random = [0_u8; 1];
    getrandom::fill(&mut random).map_err(|_| AuthenticationError::RandomnessUnavailable)?;
    Ok(Duration::from_millis(
        FAILURE_DELAY_MIN_MS + u64::from(random[0] % FAILURE_DELAY_SPAN_MS),
    ))
}

fn unix_time() -> Result<u64, AuthenticationError> {
    Ok(SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| AuthenticationError::ClockBeforeUnixEpoch)?
        .as_secs())
}

/// Failure while authenticating an admitted controller connection.
#[derive(Debug, Error)]
pub enum AuthenticationError {
    /// The configured whole-authentication deadline elapsed.
    #[error("control authentication timed out")]
    Timeout,
    /// The peer closed cleanly before the next required authentication record.
    #[error("control peer closed before authentication completed")]
    UnexpectedEof,
    /// Control framing, message construction, sequence, or carrier I/O failed.
    #[error(transparent)]
    Control(#[from] ControlError),
    /// A protocol nested value failed decoding.
    #[error(transparent)]
    Codec(#[from] CodecError),
    /// A key or claimed identifier failed cryptographic validation.
    #[error(transparent)]
    Crypto(#[from] CryptoError),
    /// The TLS library could not export this connection's binding material.
    #[error("unable to derive the Stella TLS exporter")]
    TlsExporter(#[source] rustls::Error),
    /// Operating-system cryptographic randomness was unavailable.
    #[error("operating-system cryptographic randomness is unavailable")]
    RandomnessUnavailable,
    /// The host wall clock is earlier than the Unix epoch.
    #[error("system clock is before the Unix epoch")]
    ClockBeforeUnixEpoch,
    /// The next message had a type invalid for the authentication state.
    #[error("expected {expected:?} during authentication, received {actual:?}")]
    UnexpectedMessage {
        /// Required message type.
        expected: ControlMessageType,
        /// Received message type.
        actual: ControlMessageType,
    },
    /// A direct response did not reference the expected request.
    #[error("expected authentication correlation ID {expected}, received {actual}")]
    CorrelationMismatch {
        /// Required triggering message ID.
        expected: u64,
        /// Received correlation ID.
        actual: u64,
    },
    /// The client selected no supported version and suite tuple.
    #[error("unsupported control version {major}.{minor} suite {suite_id}")]
    UnsupportedVersion {
        /// Selected protocol major version.
        major: u8,
        /// Selected protocol minor version.
        minor: u8,
        /// Selected suite registry value.
        suite_id: u16,
    },
    /// A post-negotiation message did not use the selected header version.
    #[error("expected control version {expected:?}, received {actual:?}")]
    ProtocolVersionMismatch {
        /// Version selected in `CLIENT_HELLO`.
        expected: ProtocolVersion,
        /// Version found in the message header.
        actual: ProtocolVersion,
    },
    /// The client nonce was all zero.
    #[error("client authentication nonce must be non-zero")]
    ZeroClientNonce,
    /// The claimed node ID was all zero.
    #[error("claimed node ID must be non-zero")]
    ZeroNodeId,
    /// A validated message unexpectedly lacked a codec-required field.
    #[error("validated control message is missing required field {field:?}")]
    ValidatedFieldMissing {
        /// Field that the codec had already required.
        field: ControlFieldType,
    },
    /// A validated fixed-width field unexpectedly had another length.
    #[error("validated {field} length is {actual}, expected {expected}")]
    ValidatedLengthInvalid {
        /// Stable field name.
        field: &'static str,
        /// Required byte length.
        expected: usize,
        /// Observed byte length.
        actual: usize,
    },
    /// A codec-validated text field unexpectedly was not UTF-8.
    #[error("validated {field} is not UTF-8")]
    ValidatedUtf8Invalid {
        /// Stable field name.
        field: &'static str,
    },
    /// The node's exporter-bound proof was invalid.
    #[error("node proof verification failed")]
    NodeProof {
        /// Cryptographic verification failure.
        #[source]
        source: CryptoError,
    },
    /// Authentication was deliberately rejected with a redacted status.
    #[error("control authentication rejected with status {status}")]
    Rejected {
        /// Status sent to the unauthenticated peer.
        status: u16,
    },
    /// The serialized authority could not inspect or commit node state.
    #[error(transparent)]
    Authority(#[from] AuthorityError),
}

#[cfg(all(test, windows))]
mod tests {
    use std::{
        fs::File,
        io::BufReader,
        net::SocketAddr,
        path::{Path, PathBuf},
        sync::{
            atomic::{AtomicU64, Ordering},
            Arc,
        },
        time::{Duration, SystemTime, UNIX_EPOCH},
    };

    use stella_common::ControllerId;
    use stella_control::{
        sign_node_proof, verify_controller_proof, ControllerProofContext, InboundSequence,
        MessageBuilder, NodeProofContext, OutboundSequence, RecordReader, RecordWriter,
        CONTROL_EXPORTER_LABEL, CONTROL_EXPORTER_LENGTH, CONTROL_NONCE_LENGTH,
    };
    use stella_crypto::{derive_node_id, IdentityPublicKey, IdentitySigningKey};
    use stella_proto::{
        ControlFieldType, ControlMessageType, ProtocolVersion, VersionEntry, VersionListView,
    };
    use tokio::{
        io::AsyncReadExt,
        net::TcpStream,
        sync::{mpsc, oneshot},
        time::sleep,
    };
    use tokio_rustls::{
        client::TlsStream as ClientTlsStream,
        rustls::{self, pki_types::ServerName, version::TLS13, ClientConfig, RootCertStore},
        TlsConnector,
    };

    use super::authenticate_session;
    use crate::{
        bootstrap::{initialize_controller, BootstrapOptions},
        config::ServerConfig,
        runtime::{run_controller, SessionError, SessionHandler},
        store::{AuthorityStore, BearerToken},
    };

    static TEMP_SEQUENCE: AtomicU64 = AtomicU64::new(1);

    fn temp_directory() -> PathBuf {
        let sequence = TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        std::env::temp_dir().join(format!(
            "stella-controller-authentication-{}-{sequence}",
            std::process::id()
        ))
    }

    fn reserve_loopback_address() -> SocketAddr {
        let listener =
            std::net::TcpListener::bind("127.0.0.1:0").expect("reserve loopback address");
        listener.local_addr().expect("read reserved address")
    }

    fn client_connector(certificate_path: &Path) -> TlsConnector {
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

    async fn write_message(
        stream: &mut ClientTlsStream<TcpStream>,
        outbound: &mut OutboundSequence,
        builder: MessageBuilder,
    ) -> u64 {
        let message = outbound.build(builder).expect("build client message");
        let message_id = message.header().expect("read client header").message_id;
        let mut writer = RecordWriter::new(stream);
        writer
            .write_message(&message)
            .await
            .expect("write client message");
        writer.flush().await.expect("flush client message");
        message_id
    }

    async fn read_message(
        stream: &mut ClientTlsStream<TcpStream>,
    ) -> stella_control::OwnedControlMessage {
        RecordReader::new(stream)
            .read_message()
            .await
            .expect("read server message")
            .expect("server message is present")
    }

    fn field_value(
        message: &stella_control::OwnedControlMessage,
        wanted: ControlFieldType,
    ) -> &[u8] {
        message
            .view()
            .expect("validated server message")
            .fields()
            .find_map(|field| (field.field_type() == Some(wanted)).then(|| field.value()))
            .expect("required server field")
    }

    #[allow(
        clippy::too_many_arguments,
        clippy::too_many_lines,
        reason = "the loopback client exposes every authentication transcript input explicitly"
    )]
    async fn authenticate_client(
        connector: &TlsConnector,
        address: SocketAddr,
        expected_controller_id: ControllerId,
        node_key: &IdentitySigningKey,
        enrollment_token: Option<&BearerToken>,
        display_name: Option<&str>,
        corrupt_proof: bool,
        selected_entry: VersionEntry,
    ) -> u16 {
        let tcp = connect_with_retry(address).await;
        let server_name = ServerName::try_from("localhost")
            .expect("valid test server name")
            .to_owned();
        let mut tls = connector
            .connect(server_name, tcp)
            .await
            .expect("complete TLS 1.3 handshake");
        let mut inbound = InboundSequence::new();
        let mut outbound = OutboundSequence::new();

        let server_hello = read_message(&mut tls).await;
        let server_hello_header = server_hello.header().expect("server hello header");
        inbound
            .accept(server_hello_header.message_id)
            .expect("server hello sequence");
        assert_eq!(
            server_hello_header.message_type,
            ControlMessageType::ServerHello
        );
        assert_eq!(server_hello_header.correlation_id, 0);
        let versions = VersionListView::decode(field_value(
            &server_hello,
            ControlFieldType::SupportedVersions,
        ))
        .expect("decode supported versions");
        assert_eq!(
            versions.entries().collect::<Vec<_>>(),
            vec![VersionEntry::V0_2_SUITE_1, VersionEntry::V0_1_SUITE_1]
        );
        let server_nonce: [u8; CONTROL_NONCE_LENGTH] =
            field_value(&server_hello, ControlFieldType::ServerNonce)
                .try_into()
                .expect("server nonce width");
        assert!(server_nonce.iter().any(|byte| *byte != 0));
        let controller_id = ControllerId::from_bytes(
            field_value(&server_hello, ControlFieldType::ControllerId)
                .try_into()
                .expect("controller ID width"),
        );
        assert_eq!(controller_id, expected_controller_id);
        let controller_public_key = IdentityPublicKey::from_bytes(
            field_value(&server_hello, ControlFieldType::ControllerPublicKey)
                .try_into()
                .expect("controller key width"),
        )
        .expect("valid controller public key");

        let mut client_nonce = [0_u8; CONTROL_NONCE_LENGTH];
        getrandom::fill(&mut client_nonce).expect("generate client nonce");
        if client_nonce.iter().all(|byte| *byte == 0) {
            client_nonce[0] = 1;
        }
        let node_id = derive_node_id(node_key.public_key());
        let protocol_version = ProtocolVersion {
            major: selected_entry.major,
            minor: selected_entry.minor,
        };
        let mut selected = [0_u8; 4];
        selected_entry
            .encode(&mut selected)
            .expect("encode selected version");
        let mut client_hello = MessageBuilder::new(ControlMessageType::ClientHello)
            .with_version(protocol_version)
            .with_correlation(server_hello_header.message_id);
        client_hello
            .push_field(ControlFieldType::SelectedVersion, &selected)
            .expect("selected version field");
        client_hello
            .push_field(ControlFieldType::ClientNonce, &client_nonce)
            .expect("client nonce field");
        client_hello
            .push_field(ControlFieldType::NodeId, node_id.as_bytes())
            .expect("node ID field");
        client_hello
            .push_field(
                ControlFieldType::NodePublicKey,
                node_key.public_key().as_bytes(),
            )
            .expect("node key field");
        let client_hello_id = write_message(&mut tls, &mut outbound, client_hello).await;

        let exporter = tls
            .get_ref()
            .1
            .export_keying_material(
                [0_u8; CONTROL_EXPORTER_LENGTH],
                CONTROL_EXPORTER_LABEL,
                None,
            )
            .expect("derive client TLS exporter");
        let server_proof = read_message(&mut tls).await;
        let server_proof_header = server_proof.header().expect("server proof header");
        inbound
            .accept(server_proof_header.message_id)
            .expect("server proof sequence");
        assert_eq!(
            server_proof_header.message_type,
            ControlMessageType::ServerProof
        );
        assert_eq!(server_proof_header.version, protocol_version);
        assert_eq!(server_proof_header.correlation_id, client_hello_id);
        let controller_signature =
            field_value(&server_proof, ControlFieldType::ControllerSignature)
                .try_into()
                .expect("controller signature width");
        verify_controller_proof(
            controller_public_key,
            ControllerProofContext::new(&exporter, &server_nonce, selected_entry, controller_id),
            &controller_signature,
        )
        .expect("verify controller proof");

        let mut node_signature = sign_node_proof(
            node_key,
            NodeProofContext::new(
                &exporter,
                &server_nonce,
                &client_nonce,
                selected_entry,
                controller_id,
                node_id,
            ),
        );
        if corrupt_proof {
            node_signature[0] ^= 0x80;
        }
        let mut node_auth = MessageBuilder::new(ControlMessageType::NodeAuth)
            .with_version(protocol_version)
            .with_correlation(server_proof_header.message_id);
        node_auth
            .push_field(ControlFieldType::NodeSignature, &node_signature)
            .expect("node signature field");
        if let Some(token) = enrollment_token {
            node_auth
                .push_field(ControlFieldType::EnrollmentToken, token.expose_secret())
                .expect("enrollment token field");
        }
        if let Some(name) = display_name {
            node_auth
                .push_field(ControlFieldType::DisplayName, name.as_bytes())
                .expect("display name field");
        }
        let node_auth_id = write_message(&mut tls, &mut outbound, node_auth).await;

        let auth_result = read_message(&mut tls).await;
        let auth_result_header = auth_result.header().expect("auth result header");
        inbound
            .accept(auth_result_header.message_id)
            .expect("auth result sequence");
        assert_eq!(
            auth_result_header.message_type,
            ControlMessageType::AuthResult
        );
        assert_eq!(auth_result_header.version, protocol_version);
        assert_eq!(auth_result_header.correlation_id, node_auth_id);
        let status = u16::from_be_bytes(
            field_value(&auth_result, ControlFieldType::StatusCode)
                .try_into()
                .expect("status width"),
        );
        if status != 0 {
            let mut trailing = [0_u8; 1];
            assert_eq!(tls.read(&mut trailing).await.expect("read TLS close"), 0);
        }
        status
    }

    fn now() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("test clock after Unix epoch")
            .as_secs()
    }

    #[allow(clippy::too_many_lines)]
    #[tokio::test(flavor = "current_thread")]
    async fn loopback_authentication_enrolls_reconnects_and_redacts_failures() {
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
        let store = AuthorityStore::open(&config.database_path, initialized.controller_id)
            .expect("open authority before server");
        let enrollment_token = store
            .issue_enrollment_token(now(), now() + 3_600)
            .expect("issue enrollment token");
        drop(store);
        let connector = client_connector(&config.tls_certificate_path);

        let (authenticated_sender, mut authenticated_receiver) = mpsc::unbounded_channel();
        let handler: SessionHandler = Arc::new(move |session| {
            let authenticated_sender = authenticated_sender.clone();
            Box::pin(async move {
                let authenticated = authenticate_session(session)
                    .await
                    .map_err(|error| -> SessionError { Box::new(error) })?;
                let _sent = authenticated_sender.send(authenticated.node_id());
                Ok::<(), SessionError>(())
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

        let enrolled_key = IdentitySigningKey::generate().expect("generate enrolled identity");
        assert_eq!(
            authenticate_client(
                &connector,
                address,
                initialized.controller_id,
                &enrolled_key,
                None,
                None,
                false,
                VersionEntry::V0_1_SUITE_1,
            )
            .await,
            101
        );
        let wrong_token = BearerToken::from_bytes([0x5a; 32]).expect("non-zero wrong token");
        assert_eq!(
            authenticate_client(
                &connector,
                address,
                initialized.controller_id,
                &enrolled_key,
                Some(&wrong_token),
                Some("test node"),
                false,
                VersionEntry::V0_1_SUITE_1,
            )
            .await,
            100
        );
        assert_eq!(
            authenticate_client(
                &connector,
                address,
                initialized.controller_id,
                &enrolled_key,
                Some(&enrollment_token),
                Some("test node"),
                false,
                VersionEntry::V0_2_SUITE_1,
            )
            .await,
            0
        );
        let enrolled_id = derive_node_id(enrolled_key.public_key());
        assert_eq!(authenticated_receiver.recv().await, Some(enrolled_id));
        assert_eq!(
            authenticate_client(
                &connector,
                address,
                initialized.controller_id,
                &enrolled_key,
                None,
                None,
                false,
                VersionEntry::V0_1_SUITE_1,
            )
            .await,
            0
        );
        assert_eq!(authenticated_receiver.recv().await, Some(enrolled_id));
        assert_eq!(
            authenticate_client(
                &connector,
                address,
                initialized.controller_id,
                &enrolled_key,
                Some(&enrollment_token),
                Some("renamed node"),
                false,
                VersionEntry::V0_2_SUITE_1,
            )
            .await,
            100
        );
        let attacker_key = IdentitySigningKey::generate().expect("generate attacker identity");
        assert_eq!(
            authenticate_client(
                &connector,
                address,
                initialized.controller_id,
                &attacker_key,
                None,
                None,
                true,
                VersionEntry::V0_2_SUITE_1,
            )
            .await,
            100
        );

        shutdown_sender.send(()).expect("request server shutdown");
        server
            .await
            .expect("server task joins")
            .expect("server shuts down cleanly");
        let store = AuthorityStore::open(&config.database_path, initialized.controller_id)
            .expect("reopen authority after server");
        let stored = store
            .get_node(enrolled_id)
            .expect("read enrolled node")
            .expect("enrolled node exists");
        assert_eq!(stored.public_key(), enrolled_key.public_key());
        assert_eq!(stored.display_name(), "test node");
        assert!(stored.enabled());
        drop(store);
        std::fs::remove_dir_all(&directory).expect("remove test directory");
    }
}
