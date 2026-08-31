//! Headless peer used by the Windows one-TAP end-to-end verifier.

use std::{
    net::SocketAddr,
    path::PathBuf,
    str::FromStr,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use anyhow::{Context, Result};
use clap::Parser;
use stella_client::{
    authenticate_controller, load_node_identity, ActiveControl, ClientConfig, ControlUpdate,
    NetworkDataPlane, NetworkOutput,
};
use stella_common::MacAddress;
use stella_proto::{CommonHeader, PacketType, SessionRejectView};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{tcp::OwnedReadHalf, tcp::OwnedWriteHalf, TcpListener, UdpSocket},
};

const MAX_COMMAND_LENGTH: usize = 4_096;
const MAX_DATAGRAM_SIZE: usize = 1_200;
const MAINTENANCE_INTERVAL: Duration = Duration::from_millis(100);

#[derive(Debug, Parser)]
#[command(about = "Headless Stella peer for the Windows one-TAP verifier")]
struct Arguments {
    #[arg(long)]
    config: PathBuf,
    #[arg(long)]
    mac: String,
    #[arg(long, default_value = "127.0.0.1:45200")]
    control: SocketAddr,
}

enum Command {
    Inject(Vec<u8>),
    Quit,
}

#[tokio::main(flavor = "current_thread")]
#[allow(
    clippy::too_many_lines,
    reason = "the verifier keeps its ordered startup and event ownership visible in one routine"
)]
async fn main() -> Result<()> {
    let arguments = Arguments::parse();
    let config = ClientConfig::load(&arguments.config).context("could not load peer config")?;
    let configured = config
        .networks
        .first()
        .context("headless peer requires one configured network")?;
    anyhow::ensure!(
        config.networks.len() == 1,
        "headless peer requires exactly one configured network"
    );
    anyhow::ensure!(
        !config.advertised_endpoints.is_empty(),
        "headless peer requires at least one advertised endpoint"
    );
    let network_id = configured.network_id;
    let mac = MacAddress::from_str(&arguments.mac).context("invalid peer MAC address")?;
    let identity = load_node_identity(&config.identity_path).context("could not load identity")?;
    let udp = UdpSocket::bind(config.udp_bind)
        .await
        .context("could not bind headless peer UDP socket")?;
    let listener = TcpListener::bind(arguments.control)
        .await
        .context("could not bind verifier control socket")?;
    eprintln!(
        "headless verifier control is listening on {}",
        arguments.control
    );

    let connection = authenticate_controller(&config.controller, &identity, None)
        .await
        .context("controller authentication failed")?;
    let mut active = ActiveControl::new(connection);
    active
        .join_network(network_id, None)
        .await
        .context("could not rejoin network")?;
    active
        .publish_endpoints(network_id, &config.advertised_endpoints)
        .await
        .context("could not publish headless peer endpoint")?;
    let state = active
        .network(network_id)
        .cloned()
        .context("published network state is unavailable")?;
    for (peer_node_id, peer) in state.peers() {
        eprintln!(
            "headless grants local={} peer {}={}",
            state.local_grant().grant_serial,
            peer_node_id,
            peer.grant().grant_serial
        );
    }
    let started_at = std::time::Instant::now();
    let mut plane = NetworkDataPlane::new(
        state,
        mac,
        config.udp_bind,
        MAX_DATAGRAM_SIZE,
        &identity,
        Duration::ZERO,
    )
    .context("could not create headless data plane")?;
    let output = plane
        .start_handshakes(&identity, unix_time()?, Duration::ZERO)
        .context("could not start peer handshake")?;
    send_output(&udp, &plane, output, None).await?;

    let (control, _) = listener
        .accept()
        .await
        .context("could not accept verifier connection")?;
    let (mut reader, mut writer) = control.into_split();
    let (command_sender, mut commands) = tokio::sync::mpsc::channel(8);
    let command_reader = tokio::spawn(async move {
        loop {
            let command = read_command(&mut reader).await;
            let stopping = command.is_err() || matches!(command.as_ref(), Ok(Command::Quit));
            if command_sender.send(command).await.is_err() || stopping {
                return;
            }
        }
    });
    let mut udp_buffer = vec![0_u8; MAX_DATAGRAM_SIZE];
    let mut maintenance = tokio::time::interval(MAINTENANCE_INTERVAL);
    maintenance.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let heartbeat_seconds = u64::from(
        active
            .network(network_id)
            .context("network disappeared before verifier startup")?
            .policy()
            .heartbeat_seconds,
    );
    let heartbeat = tokio::time::sleep(Duration::from_secs(heartbeat_seconds));
    tokio::pin!(heartbeat);
    let mut ready_reported = false;

    loop {
        if !ready_reported && !plane.established_peers().is_empty() {
            write_line(&mut writer, "READY").await?;
            eprintln!("headless peer session is established");
            ready_reported = true;
        }
        tokio::select! {
            command = commands.recv() => {
                match command.context("verifier command reader stopped")?? {
                    Command::Inject(frame) => {
                        let output = plane
                            .accept_tap_frame(&frame, started_at.elapsed())
                            .context("headless frame injection failed")?;
                        send_output(&udp, &plane, output, Some(&mut writer)).await?;
                        write_line(&mut writer, "OK").await?;
                    }
                    Command::Quit => break,
                }
            }
            received = udp.recv_from(&mut udp_buffer) => {
                let (length, source) = received.context("headless UDP receive failed")?;
                let packet_type = CommonHeader::decode(&udp_buffer[..length]).map_or_else(
                    |_| "malformed".to_owned(),
                    |header| format!("{:?}", header.packet_type),
                );
                eprintln!("received {length} {packet_type} bytes from {source}");
                if let Ok(rejection) = SessionRejectView::decode(&udp_buffer[..length]) {
                    eprintln!("received session rejection reason: {:?}", rejection.reason());
                }
                match plane.accept_udp_datagram(
                    source,
                    &udp_buffer[..length],
                    &identity,
                    unix_time()?,
                    started_at.elapsed(),
                ) {
                    Ok(output) => send_output(&udp, &plane, output, Some(&mut writer)).await?,
                    Err(error) => eprintln!("dropped invalid peer datagram: {error}"),
                }
            }
            update = active.receive_update() => {
                let update = update.context("controller update failed")?;
                eprintln!("received controller update: {update:?}");
                match update {
                    ControlUpdate::ServerShutdown { deadline } => {
                        anyhow::bail!("controller requested shutdown with deadline {deadline}");
                    }
                    ControlUpdate::ControllerError { status, retry_after_ms } => {
                        anyhow::bail!("controller sent status {status} with retry delay {retry_after_ms:?}");
                    }
                    _ => {}
                }
                let state = active
                    .network(network_id)
                    .cloned()
                    .context("network was withdrawn during verification")?;
                plane
                    .reconcile(state, &identity, mac, started_at.elapsed())
                    .context("could not reconcile headless data plane")?;
            }
            () = &mut heartbeat => {
                active.heartbeat().await.context("headless heartbeat failed")?;
                let state = active
                    .network(network_id)
                    .cloned()
                    .context("network was withdrawn after heartbeat")?;
                plane
                    .reconcile(state, &identity, mac, started_at.elapsed())
                    .context("could not reconcile headless heartbeat state")?;
                heartbeat.as_mut().reset(
                    tokio::time::Instant::now() + Duration::from_secs(heartbeat_seconds)
                );
            }
            _ = maintenance.tick() => {
                let output = plane
                    .maintain(&identity, unix_time()?, started_at.elapsed())
                    .context("headless data-plane maintenance failed")?;
                send_output(&udp, &plane, output, Some(&mut writer)).await?;
            }
        }
    }
    command_reader
        .await
        .context("verifier command reader panicked")?;
    Ok(())
}

async fn send_output(
    udp: &UdpSocket,
    plane: &NetworkDataPlane,
    output: NetworkOutput,
    mut writer: Option<&mut OwnedWriteHalf>,
) -> Result<()> {
    let (datagrams, tap_frame) = output.into_parts();
    if !datagrams.is_empty() {
        eprintln!("sending {} peer datagram(s)", datagrams.len());
    }
    for datagram in datagrams {
        let endpoint = plane
            .transport_endpoint(datagram.path_id())
            .context("routed datagram path was withdrawn")?
            .as_udp()
            .context("headless peer only supports UDP paths")?;
        let packet_type = CommonHeader::decode(datagram.bytes()).map_or_else(
            |_| "malformed".to_owned(),
            |header| format!("{:?}", header.packet_type),
        );
        if CommonHeader::decode(datagram.bytes())
            .is_ok_and(|header| header.packet_type == PacketType::SessionReject)
        {
            if let Ok(rejection) = SessionRejectView::decode(datagram.bytes()) {
                eprintln!("session rejection reason: {:?}", rejection.reason());
            }
        }
        eprintln!(
            "sending {packet_type} on path {} to {endpoint}",
            datagram.path_id()
        );
        udp.send_to(datagram.bytes(), endpoint)
            .await
            .with_context(|| {
                format!(
                    "could not send datagram on path {} to {endpoint}",
                    datagram.path_id()
                )
            })?;
    }
    if let (Some(frame), Some(writer)) = (tap_frame, writer.as_mut()) {
        write_line(writer, &format!("FRAME {}", encode_hex(&frame))).await?;
    }
    Ok(())
}

async fn read_command(reader: &mut OwnedReadHalf) -> Result<Command> {
    let mut bytes = Vec::with_capacity(256);
    loop {
        let byte = reader
            .read_u8()
            .await
            .context("verifier control connection closed")?;
        if byte == b'\n' {
            break;
        }
        anyhow::ensure!(
            bytes.len() < MAX_COMMAND_LENGTH,
            "verifier command is too long"
        );
        if byte != b'\r' {
            bytes.push(byte);
        }
    }
    let line = std::str::from_utf8(&bytes).context("verifier command is not UTF-8")?;
    if line == "QUIT" {
        return Ok(Command::Quit);
    }
    let encoded = line
        .strip_prefix("INJECT ")
        .context("unknown verifier command")?;
    Ok(Command::Inject(decode_hex(encoded)?))
}

async fn write_line(writer: &mut OwnedWriteHalf, line: &str) -> Result<()> {
    writer
        .write_all(line.as_bytes())
        .await
        .context("could not write verifier response")?;
    writer
        .write_all(b"\n")
        .await
        .context("could not terminate verifier response")?;
    Ok(())
}

fn encode_hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        encoded.push(char::from(DIGITS[usize::from(byte >> 4)]));
        encoded.push(char::from(DIGITS[usize::from(byte & 0x0f)]));
    }
    encoded
}

fn decode_hex(encoded: &str) -> Result<Vec<u8>> {
    anyhow::ensure!(encoded.len() % 2 == 0, "hex frame has odd length");
    encoded
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let high = hex_digit(pair[0]).context("invalid high hex digit")?;
            let low = hex_digit(pair[1]).context("invalid low hex digit")?;
            Ok((high << 4) | low)
        })
        .collect()
}

const fn hex_digit(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

fn unix_time() -> Result<u64> {
    Ok(SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("system time is before the Unix epoch")?
        .as_secs())
}
