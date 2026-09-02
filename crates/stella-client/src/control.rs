//! Controller connection authentication and ordered session ownership.

use std::{
    fmt,
    net::{IpAddr, SocketAddr},
    time::Duration,
};

use stella_common::{ControllerId, NodeId};
use stella_control::{
    sign_node_proof, verify_controller_proof, ControllerProofContext, InboundSequence,
    MessageBuilder, NodeProofContext, OutboundSequence, OwnedControlMessage, RecordReader,
    RecordWriter, CONTROL_EXPORTER_LABEL, CONTROL_EXPORTER_LENGTH, CONTROL_NONCE_LENGTH,
};
use stella_crypto::{
    derive_node_id, validate_controller_id, IdentityPublicKey, IdentitySigningKey,
    ED25519_PUBLIC_KEY_LENGTH, ED25519_SIGNATURE_LENGTH,
};
use stella_proto::{
    ControlFieldType, ControlMessageType, ProtocolVersion, VersionEntry, VersionListView,
};
use tokio::{
    io::{ReadHalf, WriteHalf},
    net::TcpStream,
    sync::mpsc,
    task::JoinHandle,
};
use tokio_rustls::{client::TlsStream, rustls::pki_types::ServerName};
use zeroize::Zeroizing;

use crate::{
    http_proxy::{negotiate_http_connect, HttpConnectError},
    tls, ClientError, ConnectivityConfigState, SpkiPin,
};

const HTTP_CONNECT_TIMEOUT: Duration = Duration::from_secs(5);

/// One redacted fixed-width enrollment or join bearer credential.
#[derive(Clone)]
pub struct BearerCredential(Zeroizing<[u8; Self::LENGTH]>);

impl BearerCredential {
    /// Exact decoded credential length.
    pub const LENGTH: usize = 32;

    /// Takes ownership of decoded credential bytes.
    #[must_use]
    pub fn from_bytes(bytes: [u8; Self::LENGTH]) -> Self {
        Self(Zeroizing::new(bytes))
    }

    pub(crate) fn expose_secret(&self) -> &[u8; Self::LENGTH] {
        &self.0
    }
}

impl fmt::Debug for BearerCredential {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("BearerCredential([REDACTED])")
    }
}

/// Enrollment material sent only for a node not yet known to the controller.
#[derive(Clone, Copy, Debug)]
pub struct Enrollment<'a> {
    credential: &'a BearerCredential,
    display_name: &'a str,
}

impl<'a> Enrollment<'a> {
    /// Borrows one credential and the display name committed with enrollment.
    #[must_use]
    pub const fn new(credential: &'a BearerCredential, display_name: &'a str) -> Self {
        Self {
            credential,
            display_name,
        }
    }
}

/// Configured controller address and independent TLS/Stella trust anchors.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ControllerTrust {
    address: SocketAddr,
    tls_name: String,
    controller_id: ControllerId,
    spki_pins: Vec<SpkiPin>,
    https_proxy: Option<SocketAddr>,
}

impl ControllerTrust {
    /// Validates and owns one controller trust configuration.
    ///
    /// # Errors
    ///
    /// Returns [`ClientError`] when the TLS server name is invalid or no pin is
    /// supplied.
    pub fn new(
        address: SocketAddr,
        tls_name: String,
        controller_id: ControllerId,
        mut spki_pins: Vec<SpkiPin>,
    ) -> Result<Self, ClientError> {
        if spki_pins.is_empty() {
            return Err(ClientError::NoSpkiPins);
        }
        let _server_name = ServerName::try_from(tls_name.clone())
            .map_err(|_| ClientError::InvalidTlsServerName)?;
        spki_pins.sort_unstable();
        spki_pins.dedup();
        Ok(Self {
            address,
            tls_name,
            controller_id,
            spki_pins,
            https_proxy: None,
        })
    }

    /// Uses one numeric explicit HTTP proxy for controller TLS bootstrap.
    #[must_use]
    pub const fn with_https_proxy(mut self, https_proxy: Option<SocketAddr>) -> Self {
        self.https_proxy = https_proxy;
        self
    }

    /// Returns the numeric controller TCP address.
    #[must_use]
    pub const fn address(&self) -> SocketAddr {
        self.address
    }

    /// Returns the configured certificate server name.
    #[must_use]
    pub fn tls_name(&self) -> &str {
        &self.tls_name
    }

    /// Returns the configured Stella controller identity.
    #[must_use]
    pub const fn controller_id(&self) -> ControllerId {
        self.controller_id
    }

    /// Returns the accepted SPKI pins in canonical order.
    #[must_use]
    pub fn spki_pins(&self) -> &[SpkiPin] {
        &self.spki_pins
    }

    /// Returns the optional numeric HTTP proxy used for controller TLS.
    #[must_use]
    pub const fn https_proxy(&self) -> Option<SocketAddr> {
        self.https_proxy
    }
}

/// Authenticated TLS control stream and per-connection sequence state.
pub struct AuthenticatedControl {
    writer: RecordWriter<WriteHalf<TlsStream<TcpStream>>>,
    inbox: mpsc::Receiver<Result<OwnedControlMessage, ClientError>>,
    reader_task: JoinHandle<()>,
    pub(crate) outbound: OutboundSequence,
    controller_id: ControllerId,
    controller_public_key: IdentityPublicKey,
    node_id: NodeId,
    node_public_key: IdentityPublicKey,
    protocol_version: ProtocolVersion,
    server_time: u64,
    connectivity_config: Option<ConnectivityConfigState>,
}

impl AuthenticatedControl {
    /// Returns the authenticated controller ID.
    #[must_use]
    pub const fn controller_id(&self) -> ControllerId {
        self.controller_id
    }

    /// Returns the authenticated controller signing public key.
    #[must_use]
    pub const fn controller_public_key(&self) -> IdentityPublicKey {
        self.controller_public_key
    }

    /// Returns the node ID authenticated on this connection.
    #[must_use]
    pub const fn node_id(&self) -> NodeId {
        self.node_id
    }

    /// Returns the node public key authenticated on this connection.
    #[must_use]
    pub const fn node_public_key(&self) -> IdentityPublicKey {
        self.node_public_key
    }

    /// Returns the operational control version selected during authentication.
    #[must_use]
    pub const fn protocol_version(&self) -> ProtocolVersion {
        self.protocol_version
    }

    /// Returns the controller Unix time from the successful authentication.
    #[must_use]
    pub const fn server_time(&self) -> u64 {
        self.server_time
    }

    /// Returns the initial deployment STUN and relay configuration, when advertised.
    #[must_use]
    pub const fn connectivity_config(&self) -> Option<&ConnectivityConfigState> {
        self.connectivity_config.as_ref()
    }

    pub(crate) fn take_connectivity_config(&mut self) -> Option<ConnectivityConfigState> {
        self.connectivity_config.take()
    }

    /// Builds and writes one ordered control message, returning its message ID.
    ///
    /// # Errors
    ///
    /// Returns [`ClientError`] when message construction or carrier I/O fails.
    pub async fn write_message(&mut self, builder: MessageBuilder) -> Result<u64, ClientError> {
        let message = self
            .outbound
            .build(builder.with_version(self.protocol_version))?;
        let message_id = message_id(&message)?;
        self.writer.write_message(&message).await?;
        self.writer.flush().await?;
        Ok(message_id)
    }

    /// Reads one complete control message and enforces inbound sequence continuity.
    ///
    /// # Errors
    ///
    /// Returns [`ClientError`] when framing, decoding, carrier I/O, EOF, or the
    /// message sequence is invalid.
    pub async fn read_message(&mut self) -> Result<OwnedControlMessage, ClientError> {
        self.inbox
            .recv()
            .await
            .unwrap_or(Err(ClientError::ConnectionClosed))
    }
}

impl Drop for AuthenticatedControl {
    fn drop(&mut self) {
        self.reader_task.abort();
    }
}

impl fmt::Debug for AuthenticatedControl {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AuthenticatedControl")
            .field("controller_id", &self.controller_id)
            .field("node_id", &self.node_id)
            .field("protocol_version", &self.protocol_version)
            .field("server_time", &self.server_time)
            .field(
                "connectivity_config_revision",
                &self
                    .connectivity_config
                    .as_ref()
                    .map(ConnectivityConfigState::revision),
            )
            .finish_non_exhaustive()
    }
}

/// Establishes TLS 1.3 and completes mutual Stella control authentication.
///
/// The controller certificate must pass the configured SPKI, server-name,
/// validity, and server-auth checks. The exporter-bound controller proof is
/// verified before any enrollment credential or node proof is transmitted.
///
/// # Errors
///
/// Returns [`ClientError`] for address, TLS, framing, sequencing, correlation,
/// version, identity, proof, field, randomness, or authentication failure.
#[allow(
    clippy::too_many_lines,
    reason = "keeping the ordered authentication transcript linear makes its security review clearer"
)]
pub async fn authenticate_controller(
    trust: &ControllerTrust,
    identity: &IdentitySigningKey,
    enrollment: Option<Enrollment<'_>>,
) -> Result<AuthenticatedControl, ClientError> {
    let connection_address = trust.https_proxy().unwrap_or(trust.address());
    let mut tcp = TcpStream::connect(connection_address)
        .await
        .map_err(|source| match trust.https_proxy() {
            Some(_) => ClientError::HttpProxyIo {
                operation: "connection",
                source,
            },
            None => ClientError::Connect {
                address: trust.address(),
                source,
            },
        })?;
    if trust.https_proxy().is_some() {
        negotiate_http_connect(&mut tcp, &controller_authority(trust), HTTP_CONNECT_TIMEOUT)
            .await
            .map_err(map_http_connect_error)?;
    }
    let server_name = ServerName::try_from(trust.tls_name().to_owned())
        .map_err(|_| ClientError::InvalidTlsServerName)?;
    let mut stream = tls::connector(trust.spki_pins())?
        .connect(server_name, tcp)
        .await
        .map_err(ClientError::Tls)?;
    let mut inbound = InboundSequence::new();
    let mut outbound = OutboundSequence::new();

    let server_hello =
        read_expected(&mut stream, &mut inbound, ControlMessageType::ServerHello).await?;
    require_correlation(&server_hello, 0)?;
    let versions = VersionListView::decode(field_value(
        &server_hello,
        ControlFieldType::SupportedVersions,
    )?)?;
    let selected_entry = versions
        .entries()
        .find(|entry| *entry == VersionEntry::V0_2_SUITE_1 || *entry == VersionEntry::V0_1_SUITE_1)
        .ok_or(ClientError::NoCompatibleVersion)?;
    let protocol_version = ProtocolVersion {
        major: selected_entry.major,
        minor: selected_entry.minor,
    };
    let server_nonce = fixed_array(
        field_value(&server_hello, ControlFieldType::ServerNonce)?,
        "server nonce",
    )?;
    let controller_id = ControllerId::from_bytes(fixed_array(
        field_value(&server_hello, ControlFieldType::ControllerId)?,
        "controller ID",
    )?);
    if controller_id != trust.controller_id() {
        return Err(ClientError::ControllerIdentityMismatch);
    }
    let controller_public_key =
        IdentityPublicKey::from_bytes(fixed_array::<ED25519_PUBLIC_KEY_LENGTH>(
            field_value(&server_hello, ControlFieldType::ControllerPublicKey)?,
            "controller public key",
        )?)?;
    validate_controller_id(controller_id, controller_public_key)?;
    let _hello_server_time = decode_u64(
        field_value(&server_hello, ControlFieldType::ServerTime)?,
        "server time",
    )?;

    let client_nonce = random_nonzero_nonce()?;
    let node_id = derive_node_id(identity.public_key());
    let mut selected_bytes = [0_u8; 4];
    selected_entry.encode(&mut selected_bytes)?;
    let mut client_hello = MessageBuilder::new(ControlMessageType::ClientHello)
        .with_version(protocol_version)
        .with_correlation(message_id(&server_hello)?);
    client_hello.push_field(ControlFieldType::SelectedVersion, &selected_bytes)?;
    client_hello.push_field(ControlFieldType::ClientNonce, &client_nonce)?;
    client_hello.push_field(ControlFieldType::NodeId, node_id.as_bytes())?;
    client_hello.push_field(
        ControlFieldType::NodePublicKey,
        identity.public_key().as_bytes(),
    )?;
    let client_hello_id = write_built(&mut stream, &mut outbound, client_hello).await?;

    let exporter = stream
        .get_ref()
        .1
        .export_keying_material(
            [0_u8; CONTROL_EXPORTER_LENGTH],
            CONTROL_EXPORTER_LABEL,
            None,
        )
        .map_err(|source| ClientError::Tls(std::io::Error::other(source)))?;
    let server_proof =
        read_expected(&mut stream, &mut inbound, ControlMessageType::ServerProof).await?;
    require_protocol_version(&server_proof, protocol_version)?;
    require_correlation(&server_proof, client_hello_id)?;
    let controller_signature = fixed_array::<ED25519_SIGNATURE_LENGTH>(
        field_value(&server_proof, ControlFieldType::ControllerSignature)?,
        "controller signature",
    )?;
    verify_controller_proof(
        controller_public_key,
        ControllerProofContext::new(&exporter, &server_nonce, selected_entry, controller_id),
        &controller_signature,
    )?;

    let node_signature = sign_node_proof(
        identity,
        NodeProofContext::new(
            &exporter,
            &server_nonce,
            &client_nonce,
            selected_entry,
            controller_id,
            node_id,
        ),
    );
    let mut node_auth = MessageBuilder::new(ControlMessageType::NodeAuth)
        .with_version(protocol_version)
        .with_correlation(message_id(&server_proof)?);
    node_auth.push_field(ControlFieldType::NodeSignature, &node_signature)?;
    if let Some(enrollment) = enrollment {
        node_auth.push_field(
            ControlFieldType::EnrollmentToken,
            enrollment.credential.expose_secret(),
        )?;
        node_auth.push_field(
            ControlFieldType::DisplayName,
            enrollment.display_name.as_bytes(),
        )?;
    }
    let node_auth_id = write_built(&mut stream, &mut outbound, node_auth).await?;

    let auth_result =
        read_expected(&mut stream, &mut inbound, ControlMessageType::AuthResult).await?;
    require_protocol_version(&auth_result, protocol_version)?;
    require_correlation(&auth_result, node_auth_id)?;
    let status = decode_u16(
        field_value(&auth_result, ControlFieldType::StatusCode)?,
        "authentication status",
    )?;
    if status != 0 {
        return Err(ClientError::AuthenticationRejected { status });
    }
    let server_time = decode_u64(
        field_value(&auth_result, ControlFieldType::ServerTime)?,
        "server time",
    )?;
    let connectivity_revision = optional_u64(
        &auth_result,
        ControlFieldType::ConnectivityConfigRevision,
        "connectivity configuration revision",
    )?;
    let connectivity_config = if let Some(revision) = connectivity_revision {
        let message = read_expected(
            &mut stream,
            &mut inbound,
            ControlMessageType::ConnectivityConfig,
        )
        .await?;
        require_protocol_version(&message, protocol_version)?;
        require_correlation(&message, 0)?;
        let received_revision = decode_u64(
            field_value(&message, ControlFieldType::ConnectivityConfigRevision)?,
            "connectivity configuration revision",
        )?;
        if received_revision != revision {
            return Err(ClientError::InconsistentControlField {
                context: "AUTH_RESULT connectivity configuration",
                field: "configuration revision",
            });
        }
        Some(ConnectivityConfigState::from_wire(
            received_revision,
            field_value(&message, ControlFieldType::StunServerList)?,
            field_value(&message, ControlFieldType::RelayServiceList)?,
            server_time,
        )?)
    } else {
        None
    };

    let (read_half, write_half) = tokio::io::split(stream);
    let (sender, inbox) = mpsc::channel(32);
    let reader_task = tokio::spawn(read_authenticated_messages(
        read_half,
        inbound,
        protocol_version,
        sender,
    ));
    Ok(AuthenticatedControl {
        writer: RecordWriter::new(write_half),
        inbox,
        reader_task,
        outbound,
        controller_id,
        controller_public_key,
        node_id,
        node_public_key: identity.public_key(),
        protocol_version,
        server_time,
        connectivity_config,
    })
}

fn controller_authority(trust: &ControllerTrust) -> String {
    match trust.tls_name().parse::<IpAddr>() {
        Ok(IpAddr::V6(address)) => format!("[{address}]:{}", trust.address().port()),
        _ => format!("{}:{}", trust.tls_name(), trust.address().port()),
    }
}

fn map_http_connect_error(error: HttpConnectError) -> ClientError {
    match error {
        HttpConnectError::Timeout => ClientError::HttpProxyTimeout,
        HttpConnectError::Io { operation, source } => {
            ClientError::HttpProxyIo { operation, source }
        }
        HttpConnectError::Rejected { status_code } => {
            ClientError::HttpProxyRejected { status_code }
        }
        HttpConnectError::Invalid { detail } => ClientError::InvalidHttpProxyResponse { detail },
        HttpConnectError::DeadlineOverflow => ClientError::HttpProxyDeadlineOverflow,
    }
}

async fn read_authenticated_messages(
    read_half: ReadHalf<TlsStream<TcpStream>>,
    mut inbound: InboundSequence,
    protocol_version: ProtocolVersion,
    sender: mpsc::Sender<Result<OwnedControlMessage, ClientError>>,
) {
    let mut reader = RecordReader::new(read_half);
    loop {
        let result = match reader.read_message().await {
            Ok(Some(message)) => match message.header() {
                Ok(header) if header.version != protocol_version => {
                    Err(ClientError::ProtocolVersionMismatch {
                        expected: protocol_version,
                        actual: header.version,
                    })
                }
                Ok(header) => inbound
                    .accept(header.message_id)
                    .map(|()| message)
                    .map_err(ClientError::from),
                Err(error) => Err(ClientError::from(error)),
            },
            Ok(None) => Err(ClientError::ConnectionClosed),
            Err(error) => Err(ClientError::from(error)),
        };
        let terminal = result.is_err();
        if sender.send(result).await.is_err() || terminal {
            return;
        }
    }
}

async fn read_expected(
    stream: &mut TlsStream<TcpStream>,
    inbound: &mut InboundSequence,
    expected: ControlMessageType,
) -> Result<OwnedControlMessage, ClientError> {
    let message = RecordReader::new(stream)
        .read_message()
        .await?
        .ok_or(ClientError::ConnectionClosed)?;
    let header = message.header()?;
    inbound.accept(header.message_id)?;
    if header.message_type != expected {
        return Err(ClientError::UnexpectedMessage {
            expected,
            actual: header.message_type,
        });
    }
    Ok(message)
}

async fn write_built(
    stream: &mut TlsStream<TcpStream>,
    outbound: &mut OutboundSequence,
    builder: MessageBuilder,
) -> Result<u64, ClientError> {
    let message = outbound.build(builder)?;
    let message_id = message_id(&message)?;
    let mut writer = RecordWriter::new(stream);
    writer.write_message(&message).await?;
    writer.flush().await?;
    Ok(message_id)
}

fn field_value(
    message: &OwnedControlMessage,
    field: ControlFieldType,
) -> Result<&[u8], ClientError> {
    let view = message.view()?;
    for candidate in view.fields() {
        if candidate.field_type() == Some(field) {
            return Ok(candidate.value());
        }
    }
    Err(ClientError::MissingField {
        message_type: view.header().message_type,
        field,
    })
}

fn message_id(message: &OwnedControlMessage) -> Result<u64, ClientError> {
    Ok(message.header()?.message_id)
}

fn require_correlation(message: &OwnedControlMessage, expected: u64) -> Result<(), ClientError> {
    let actual = message.header()?.correlation_id;
    if actual != expected {
        return Err(ClientError::UnexpectedCorrelation { expected, actual });
    }
    Ok(())
}

fn require_protocol_version(
    message: &OwnedControlMessage,
    expected: ProtocolVersion,
) -> Result<(), ClientError> {
    let actual = message.header()?.version;
    if actual != expected {
        return Err(ClientError::ProtocolVersionMismatch { expected, actual });
    }
    Ok(())
}

fn fixed_array<const N: usize>(value: &[u8], field: &'static str) -> Result<[u8; N], ClientError> {
    value
        .try_into()
        .map_err(|_| ClientError::InvalidFieldWidth { field })
}

fn decode_u16(value: &[u8], field: &'static str) -> Result<u16, ClientError> {
    Ok(u16::from_be_bytes(fixed_array(value, field)?))
}

fn decode_u64(value: &[u8], field: &'static str) -> Result<u64, ClientError> {
    Ok(u64::from_be_bytes(fixed_array(value, field)?))
}

fn optional_u64(
    message: &OwnedControlMessage,
    field: ControlFieldType,
    name: &'static str,
) -> Result<Option<u64>, ClientError> {
    for candidate in message.view()?.fields() {
        if candidate.field_type() == Some(field) {
            return decode_u64(candidate.value(), name).map(Some);
        }
    }
    Ok(None)
}

fn random_nonzero_nonce() -> Result<[u8; CONTROL_NONCE_LENGTH], ClientError> {
    let mut nonce = [0_u8; CONTROL_NONCE_LENGTH];
    getrandom::fill(&mut nonce).map_err(|_| ClientError::RandomnessUnavailable)?;
    if nonce.iter().all(|byte| *byte == 0) {
        nonce[0] = 1;
    }
    Ok(nonce)
}

#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, SocketAddr};

    use stella_common::ControllerId;

    use super::{BearerCredential, ControllerTrust};
    use crate::{ClientError, SpkiPin};

    #[test]
    fn credentials_redact_and_trust_deduplicates_pins() {
        let credential = BearerCredential::from_bytes([0x5a; 32]);
        assert_eq!(format!("{credential:?}"), "BearerCredential([REDACTED])");

        let pin = SpkiPin::from_digest([1; 32]);
        let trust = ControllerTrust::new(
            SocketAddr::from((Ipv4Addr::LOCALHOST, 44900)),
            String::from("localhost"),
            ControllerId::from_bytes([2; 16]),
            vec![pin, pin],
        )
        .expect("valid trust configuration");
        assert_eq!(trust.spki_pins(), &[pin]);
        assert_eq!(trust.tls_name(), "localhost");
    }

    #[test]
    fn trust_rejects_missing_pin_and_invalid_name() {
        let address = SocketAddr::from((Ipv4Addr::LOCALHOST, 44900));
        let controller = ControllerId::from_bytes([2; 16]);
        assert!(matches!(
            ControllerTrust::new(address, String::from("localhost"), controller, Vec::new()),
            Err(ClientError::NoSpkiPins)
        ));
        assert!(matches!(
            ControllerTrust::new(
                address,
                String::from("bad name"),
                controller,
                vec![SpkiPin::from_digest([1; 32])]
            ),
            Err(ClientError::InvalidTlsServerName)
        ));
    }
}
