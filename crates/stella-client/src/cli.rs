//! Windows client command-line parsing, initialization, and network intent.

#[cfg(target_os = "windows")]
use std::future::Future;
use std::{
    fs::OpenOptions,
    io::Write,
    net::SocketAddr,
    path::{Path, PathBuf},
    time::Duration,
};

use anyhow::{Context, Result};
use atomic_write_file::AtomicWriteFile;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use clap::{Args, Parser, Subcommand};
use serde::Serialize;
use stella_client::{
    authenticate_controller, create_node_identity, load_node_identity, ActiveControl,
    BearerCredential, ClientConfig, Enrollment, SpkiPin,
};
#[cfg(target_os = "windows")]
use stella_client::{ClientDataRuntime, RuntimeError};
use stella_common::{ControllerId, NetworkId};
use stella_crypto::derive_node_id;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

const DEFAULT_IDENTITY_PATH: &str = "secrets/node.pk8";
const CONTROL_OPERATION_TIMEOUT: Duration = Duration::from_secs(30);
const MINIMUM_RECONNECT_DELAY: Duration = Duration::from_millis(250);
const MAXIMUM_RECONNECT_DELAY: Duration = Duration::from_secs(30);
const DEFAULT_HEARTBEAT_INTERVAL: Duration = Duration::from_secs(30);
#[cfg(target_os = "windows")]
const DATA_MAINTENANCE_INTERVAL: Duration = Duration::from_millis(100);

#[cfg(target_os = "windows")]
struct ControlSessionFailure {
    error: anyhow::Error,
    minimum_reconnect_delay: Option<Duration>,
}

#[cfg(target_os = "windows")]
enum ActiveRuntimeFailure {
    Control(ControlSessionFailure),
    Data(anyhow::Error),
    Shutdown(Result<()>),
}

#[cfg(target_os = "windows")]
enum DataDriveOutcome<T> {
    Operation(T),
    Shutdown(Result<()>),
}

#[cfg(target_os = "windows")]
impl ActiveRuntimeFailure {
    fn control(error: anyhow::Error) -> Self {
        Self::Control(ControlSessionFailure {
            error,
            minimum_reconnect_delay: None,
        })
    }

    fn control_after(error: anyhow::Error, delay: Duration) -> Self {
        Self::Control(ControlSessionFailure {
            error,
            minimum_reconnect_delay: Some(delay),
        })
    }

    fn data(error: anyhow::Error) -> Self {
        Self::Data(error)
    }
}

#[derive(Debug, Parser)]
#[command(
    name = "stella-client",
    version,
    about = "Stella Layer-2 virtual LAN client"
)]
struct Cli {
    #[arg(
        long,
        global = true,
        value_name = "PATH",
        default_value = "client.toml"
    )]
    config: PathBuf,
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Creates protected node identity and strict configuration files.
    Init(InitArgs),
    /// Authenticates, joins one network, and then persists desired membership.
    Join(JoinArgs),
    /// Stops forwarding intent and authoritatively leaves one network.
    Leave(LeaveArgs),
    /// Runs the persistent controller session and data-plane owner.
    Run,
    /// Prints local identity, controller, and desired-network state.
    Status,
}

#[derive(Clone, Debug, Args)]
struct InitArgs {
    /// Numeric TLS controller address.
    #[arg(long, value_name = "IP:PORT")]
    controller: SocketAddr,
    /// Certificate DNS name or IP name validated by TLS.
    #[arg(long)]
    tls_name: String,
    /// Expected Stella controller identity.
    #[arg(long)]
    controller_id: ControllerId,
    /// Accepted controller certificate SPKI pin; repeat for rotation overlap.
    #[arg(long = "spki-pin", required = true)]
    spki_pins: Vec<SpkiPin>,
    /// Display name used if a later join must enroll this node.
    #[arg(long)]
    display_name: String,
    /// Local UDP bind address reserved for the data plane.
    #[arg(long, default_value = "0.0.0.0:45100")]
    udp_bind: SocketAddr,
    /// Explicit HTTP proxy used for controller TLS and secure WebSocket relay.
    #[arg(long, value_name = "IP:PORT")]
    https_proxy: Option<SocketAddr>,
    /// Node PKCS#8 path, relative to the configuration file by default.
    #[arg(long, value_name = "PATH", default_value = DEFAULT_IDENTITY_PATH)]
    identity: PathBuf,
}

#[derive(Debug, Args)]
struct JoinArgs {
    /// Virtual network to join.
    #[arg(long)]
    network: NetworkId,
    /// Single-use network join token; omit when membership already exists.
    #[arg(long)]
    token: Option<CliCredential>,
    /// Single-use node enrollment token for a node unknown to the controller.
    #[arg(long)]
    enrollment_token: Option<CliCredential>,
    /// Exact TAP-Windows adapter display name for this network.
    #[arg(long)]
    tap_adapter: String,
}

#[derive(Clone, Debug, Args)]
struct LeaveArgs {
    /// Configured virtual network to leave.
    #[arg(long)]
    network: NetworkId,
}

#[derive(Clone)]
struct CliCredential(BearerCredential);

impl std::fmt::Debug for CliCredential {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("CliCredential([REDACTED])")
    }
}

impl std::str::FromStr for CliCredential {
    type Err = String;

    fn from_str(text: &str) -> std::result::Result<Self, Self::Err> {
        let decoded = URL_SAFE_NO_PAD
            .decode(text)
            .map_err(|_| "credential must be unpadded base64url".to_owned())?;
        let bytes = decoded.try_into().map_err(|value: Vec<u8>| {
            format!(
                "credential must decode to {} bytes, got {}",
                BearerCredential::LENGTH,
                value.len()
            )
        })?;
        Ok(Self(BearerCredential::from_bytes(bytes)))
    }
}

pub(crate) async fn run() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Command::Init(args) => initialize(&cli.config, &args, &mut std::io::stdout().lock()),
        Command::Join(args) => {
            join_network(&cli.config, &args, &mut std::io::stdout().lock()).await
        }
        Command::Leave(args) => {
            leave_network(&cli.config, &args, &mut std::io::stdout().lock()).await
        }
        Command::Run => Box::pin(run_client(&cli.config)).await,
        Command::Status => status(&cli.config, &mut std::io::stdout().lock()),
    }
}

async fn run_client(config_path: &Path) -> Result<()> {
    let config = ClientConfig::load(config_path).context("could not load client configuration")?;
    let identity = load_node_identity(&config.identity_path).with_context(|| {
        format!(
            "could not load node identity {}",
            config.identity_path.display()
        )
    })?;
    let filter = tracing_subscriber::EnvFilter::try_new(&config.log_filter)
        .context("invalid configured tracing filter")?;
    tracing_subscriber::registry()
        .with(filter)
        .with(tracing_subscriber::fmt::layer())
        .try_init()
        .context("could not initialize client logging")?;
    tracing::info!(config = %config_path.display(), "starting client runtime");
    #[cfg(target_os = "windows")]
    {
        supervise_control(&config, &identity, tokio::spawn(tokio::signal::ctrl_c())).await
    }
    #[cfg(not(target_os = "windows"))]
    {
        tokio::select! {
            result = supervise_control(&config, &identity) => result,
            result = tokio::signal::ctrl_c() => {
                result.context("could not wait for Ctrl+C")?;
                tracing::info!("Ctrl+C received; client forwarding state is withdrawn");
                Ok(())
            }
        }
    }
}

#[cfg(target_os = "windows")]
async fn supervise_control(
    config: &ClientConfig,
    identity: &stella_crypto::IdentitySigningKey,
    mut shutdown: tokio::task::JoinHandle<std::io::Result<()>>,
) -> Result<()> {
    let mut attempt = 0_u32;
    let mut data = None;
    let mut reconnect_delay: Option<Duration> = None;
    loop {
        if let Some(delay) = reconnect_delay.take() {
            tracing::info!(
                delay_ms = delay.as_millis(),
                data_plane_active = data.is_some(),
                "waiting before controller reconnect"
            );
            if let Some(runtime) = data.as_mut() {
                match drive_data_until(runtime, identity, tokio::time::sleep(delay), &mut shutdown)
                    .await
                {
                    Ok(DataDriveOutcome::Operation(())) => {}
                    Ok(DataDriveOutcome::Shutdown(result)) => {
                        return finish_client_shutdown(&mut data, result).await;
                    }
                    Err(error) => {
                        tracing::warn!(%error, "data plane failed during controller reconnect wait");
                        shutdown_data_runtime(&mut data).await;
                    }
                }
            } else {
                tokio::select! {
                    () = tokio::time::sleep(delay) => {}
                    result = &mut shutdown => {
                        return finish_client_shutdown(&mut data, decode_shutdown_result(result)).await;
                    }
                }
            }
        }

        let activation = if let Some(runtime) = data.as_mut() {
            match drive_data_until(
                runtime,
                identity,
                activate_control(config, identity),
                &mut shutdown,
            )
            .await
            {
                Ok(DataDriveOutcome::Operation(result)) => result,
                Ok(DataDriveOutcome::Shutdown(result)) => {
                    return finish_client_shutdown(&mut data, result).await;
                }
                Err(error) => {
                    tracing::warn!(%error, "data plane failed during controller activation");
                    shutdown_data_runtime(&mut data).await;
                    continue;
                }
            }
        } else {
            tokio::select! {
                result = activate_control(config, identity) => result,
                result = &mut shutdown => {
                    return finish_client_shutdown(&mut data, decode_shutdown_result(result)).await;
                }
            }
        };
        let active = match activation {
            Ok(active) => {
                tracing::info!(
                    networks = active.networks().len(),
                    data_plane_reused = data.is_some(),
                    "controller state is active"
                );
                attempt = 0;
                active
            }
            Err(error) => {
                tracing::warn!(error = ?error, "controller activation failed");
                reconnect_delay = Some(next_reconnect_delay(&mut attempt, None)?);
                continue;
            }
        };

        match run_active_control(config, identity, active, &mut data, &mut shutdown).await {
            Ok(()) => {}
            Err(ActiveRuntimeFailure::Control(failure)) => {
                tracing::warn!(error = ?failure.error, "active controller session ended");
                reconnect_delay = Some(next_reconnect_delay(
                    &mut attempt,
                    failure.minimum_reconnect_delay,
                )?);
            }
            Err(ActiveRuntimeFailure::Data(error)) => {
                tracing::warn!(error = ?error, "active data plane ended");
                shutdown_data_runtime(&mut data).await;
                reconnect_delay = Some(next_reconnect_delay(&mut attempt, None)?);
            }
            Err(ActiveRuntimeFailure::Shutdown(result)) => {
                return finish_client_shutdown(&mut data, result).await;
            }
        }
    }
}

#[cfg(not(target_os = "windows"))]
async fn supervise_control(
    config: &ClientConfig,
    identity: &stella_crypto::IdentitySigningKey,
) -> Result<()> {
    let mut attempt = 0_u32;
    loop {
        match activate_control(config, identity).await {
            Ok(active) => {
                tracing::info!(
                    networks = active.networks().len(),
                    "controller state is active"
                );
                attempt = 0;
                if let Err(error) = run_active_control(config, identity, active).await {
                    tracing::warn!(error = ?error, "active controller session ended");
                }
            }
            Err(error) => tracing::warn!(error = ?error, "controller activation failed"),
        }
        let cap = reconnect_cap(attempt);
        let delay = full_jitter(cap)?;
        tracing::info!(
            delay_ms = delay.as_millis(),
            "waiting before controller reconnect"
        );
        tokio::time::sleep(delay).await;
        attempt = attempt.saturating_add(1);
    }
}

async fn activate_control(
    config: &ClientConfig,
    identity: &stella_crypto::IdentitySigningKey,
) -> Result<ActiveControl> {
    let connection = tokio::time::timeout(
        CONTROL_OPERATION_TIMEOUT,
        authenticate_controller(&config.controller, identity, None),
    )
    .await
    .context("controller authentication timed out")?
    .context("controller authentication failed")?;
    let mut active = ActiveControl::new(connection);
    for network in &config.networks {
        tokio::time::timeout(
            CONTROL_OPERATION_TIMEOUT,
            active.join_network(network.network_id, None),
        )
        .await
        .with_context(|| format!("join timed out for network {}", network.network_id))?
        .with_context(|| format!("could not rejoin network {}", network.network_id))?;
    }
    Ok(active)
}

async fn publish_configured_endpoints(
    config: &ClientConfig,
    active: &mut ActiveControl,
) -> Result<()> {
    for network in &config.networks {
        tokio::time::timeout(
            CONTROL_OPERATION_TIMEOUT,
            active.publish_endpoints(network.network_id, &config.advertised_endpoints),
        )
        .await
        .with_context(|| {
            format!(
                "endpoint publication timed out for network {}",
                network.network_id
            )
        })?
        .with_context(|| {
            format!(
                "could not publish endpoints for network {}",
                network.network_id
            )
        })?;
    }
    Ok(())
}

#[cfg(target_os = "windows")]
async fn run_active_control(
    config: &ClientConfig,
    identity: &stella_crypto::IdentitySigningKey,
    mut active: ActiveControl,
    data: &mut Option<ClientDataRuntime>,
    shutdown: &mut tokio::task::JoinHandle<std::io::Result<()>>,
) -> std::result::Result<(), ActiveRuntimeFailure> {
    if data.is_none() {
        let runtime = ClientDataRuntime::start_with_connectivity(
            config,
            active.networks(),
            identity,
            active.connectivity_config(),
        )
        .await
        .context("could not start Windows UDP/TAP data plane")
        .map_err(ActiveRuntimeFailure::data)?;
        *data = Some(runtime);
    }
    let data = data.as_mut().ok_or_else(|| {
        ActiveRuntimeFailure::data(anyhow::anyhow!("Windows data runtime is unavailable"))
    })?;
    publish_configured_endpoints(config, &mut active)
        .await
        .map_err(ActiveRuntimeFailure::control)?;
    synchronize_and_publish_connectivity(&mut active, data, true).await?;
    data.reconcile(config, active.networks(), identity)
        .await
        .context("could not reconcile data plane after reachability publication")
        .map_err(ActiveRuntimeFailure::data)?;
    tracing::info!(
        udp = %data.local_udp_address(),
        networks = active.networks().len(),
        "Windows data plane is active"
    );
    run_active_io(config, identity, &mut active, data, shutdown).await
}

#[cfg(target_os = "windows")]
async fn run_active_io(
    config: &ClientConfig,
    identity: &stella_crypto::IdentitySigningKey,
    active: &mut ActiveControl,
    data: &mut ClientDataRuntime,
    shutdown: &mut tokio::task::JoinHandle<std::io::Result<()>>,
) -> std::result::Result<(), ActiveRuntimeFailure> {
    let heartbeat_sleep = tokio::time::sleep(heartbeat_interval(active));
    tokio::pin!(heartbeat_sleep);
    let mut maintenance = tokio::time::interval(DATA_MAINTENANCE_INTERVAL);
    maintenance.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        tokio::select! {
            result = &mut *shutdown => {
                return Err(ActiveRuntimeFailure::Shutdown(decode_shutdown_result(result)));
            }
            update = active.receive_update() => {
                let update = update
                    .context("could not receive controller update")
                    .map_err(ActiveRuntimeFailure::control)?;
                match &update {
                    stella_client::ControlUpdate::ServerShutdown { deadline } => {
                        return Err(ActiveRuntimeFailure::control_after(
                            anyhow::anyhow!(
                                "controller requested shutdown with deadline {deadline}"
                            ),
                            reconnect_delay_until(*deadline),
                        ));
                    }
                    stella_client::ControlUpdate::ControllerError {
                        status,
                        retry_after_ms,
                    } => {
                        let error = anyhow::anyhow!(
                            "controller sent status {status} with retry delay {retry_after_ms:?}"
                        );
                        return Err(match retry_after_ms {
                            Some(delay) => {
                                ActiveRuntimeFailure::control_after(
                                    error,
                                    Duration::from_millis(u64::from(*delay)),
                                )
                            }
                            None => ActiveRuntimeFailure::control(error),
                        });
                    }
                    _ => {}
                }
                synchronize_and_publish_connectivity(active, data, false).await?;
                tracing::debug!(?update, "applied controller update");
                data.reconcile(config, active.networks(), identity)
                    .await
                    .context("could not reconcile data plane after control update")
                    .map_err(ActiveRuntimeFailure::data)?;
                heartbeat_sleep.as_mut().reset(
                    tokio::time::Instant::now() + heartbeat_interval(active)
                );
            }
            () = &mut heartbeat_sleep => {
                let interval = heartbeat_interval(active);
                let acknowledgement_timeout = interval
                    .checked_mul(3)
                    .ok_or_else(|| anyhow::anyhow!("heartbeat timeout overflow"))
                    .map_err(ActiveRuntimeFailure::control)?;
                let report = tokio::time::timeout(acknowledgement_timeout, active.heartbeat())
                    .await
                    .context("three heartbeat acknowledgement periods elapsed")
                    .map_err(ActiveRuntimeFailure::control)?
                    .context("heartbeat failed")
                    .map_err(ActiveRuntimeFailure::control)?;
                tracing::debug!(
                    counter = report.counter(),
                    server_time = report.server_time(),
                    updated_networks = report.updated_networks().len(),
                    "controller heartbeat acknowledged"
                );
                synchronize_and_publish_connectivity(active, data, false).await?;
                data.reconcile(config, active.networks(), identity)
                    .await
                    .context("could not reconcile data plane after heartbeat")
                    .map_err(ActiveRuntimeFailure::data)?;
                heartbeat_sleep.as_mut().reset(
                    tokio::time::Instant::now() + heartbeat_interval(active)
                );
            }
            _ = maintenance.tick() => {
                data.maintain(identity)
                    .await
                    .context("data-plane maintenance failed")
                    .map_err(ActiveRuntimeFailure::data)?;
            }
            result = data.receive_next(identity) => {
                handle_data_runtime_result(result)
                    .context("data-plane I/O failed")
                    .map_err(ActiveRuntimeFailure::data)?;
                if data.take_connectivity_changed() {
                    publish_current_connectivity(active, data).await?;
                }
            }
        }
    }
}

#[cfg(target_os = "windows")]
async fn publish_current_connectivity(
    active: &mut ActiveControl,
    data: &ClientDataRuntime,
) -> std::result::Result<(), ActiveRuntimeFailure> {
    if active.connection().protocol_version() != stella_proto::ProtocolVersion::V0_2 {
        return Ok(());
    }
    let network_ids = active.networks().keys().copied().collect::<Vec<_>>();
    for network_id in network_ids {
        let generation = data
            .connectivity_generation(network_id)
            .with_context(|| format!("could not read connectivity for network {network_id}"))
            .map_err(ActiveRuntimeFailure::data)?;
        tokio::time::timeout(
            CONTROL_OPERATION_TIMEOUT,
            active.publish_connectivity(network_id, generation),
        )
        .await
        .with_context(|| format!("connectivity publication timed out for network {network_id}"))
        .map_err(ActiveRuntimeFailure::control)?
        .with_context(|| format!("could not publish connectivity for network {network_id}"))
        .map_err(ActiveRuntimeFailure::control)?;
    }
    Ok(())
}

#[cfg(target_os = "windows")]
async fn synchronize_and_publish_connectivity(
    active: &mut ActiveControl,
    data: &mut ClientDataRuntime,
    mut publish: bool,
) -> std::result::Result<(), ActiveRuntimeFailure> {
    loop {
        let control_revision = active
            .connectivity_config()
            .map(stella_client::ConnectivityConfigState::revision);
        if data.connectivity_revision() != control_revision {
            data.replace_connectivity_config(active.connectivity_config(), active.networks())
                .await
                .context("could not replace Windows relay configuration")
                .map_err(ActiveRuntimeFailure::data)?;
            publish = true;
        }
        if data
            .refresh_connectivity_generations(active.networks())
            .context("could not refresh local connectivity generations")
            .map_err(ActiveRuntimeFailure::data)?
        {
            publish = true;
        }
        if !publish {
            return Ok(());
        }
        publish_current_connectivity(active, data).await?;
        publish = false;
        let latest_revision = active
            .connectivity_config()
            .map(stella_client::ConnectivityConfigState::revision);
        if data.connectivity_revision() == latest_revision {
            return Ok(());
        }
    }
}

#[cfg(target_os = "windows")]
async fn drive_data_until<F, T>(
    data: &mut ClientDataRuntime,
    identity: &stella_crypto::IdentitySigningKey,
    operation: F,
    shutdown: &mut tokio::task::JoinHandle<std::io::Result<()>>,
) -> std::result::Result<DataDriveOutcome<T>, RuntimeError>
where
    F: Future<Output = T>,
{
    tokio::pin!(operation);
    let mut maintenance = tokio::time::interval(DATA_MAINTENANCE_INTERVAL);
    maintenance.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        tokio::select! {
            output = &mut operation => return Ok(DataDriveOutcome::Operation(output)),
            result = &mut *shutdown => {
                return Ok(DataDriveOutcome::Shutdown(decode_shutdown_result(result)));
            }
            _ = maintenance.tick() => data.maintain(identity).await?,
            result = data.receive_next(identity) => handle_data_runtime_result(result)?,
        }
    }
}

#[cfg(target_os = "windows")]
fn handle_data_runtime_result(
    result: std::result::Result<(), RuntimeError>,
) -> std::result::Result<(), RuntimeError> {
    match result {
        Ok(()) => Ok(()),
        Err(RuntimeError::Network(error)) => {
            tracing::debug!(%error, "dropped invalid peer datagram");
            Ok(())
        }
        Err(RuntimeError::Codec(error)) => {
            tracing::debug!(%error, "dropped malformed Stella datagram");
            Ok(())
        }
        Err(RuntimeError::TapWriteQueueFull { network_id }) => {
            tracing::warn!(%network_id, "dropped frame because TAP queue is full");
            Ok(())
        }
        Err(error) => Err(error),
    }
}

#[cfg(target_os = "windows")]
async fn shutdown_data_runtime(data: &mut Option<ClientDataRuntime>) {
    let Some(runtime) = data.take() else {
        return;
    };
    if let Err(error) = runtime.shutdown().await {
        tracing::warn!(%error, "data-plane shutdown failed");
    }
}

#[cfg(target_os = "windows")]
async fn finish_client_shutdown(
    data: &mut Option<ClientDataRuntime>,
    signal: Result<()>,
) -> Result<()> {
    if signal.is_ok() {
        tracing::info!("Ctrl+C received; withdrawing client forwarding state");
    }
    shutdown_data_runtime(data).await;
    signal
}

#[cfg(target_os = "windows")]
fn decode_shutdown_result(
    result: std::result::Result<std::io::Result<()>, tokio::task::JoinError>,
) -> Result<()> {
    result
        .context("Ctrl+C signal task stopped")?
        .context("could not wait for Ctrl+C")
}

#[cfg(target_os = "windows")]
fn reconnect_delay_until(deadline: u64) -> Duration {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(deadline, |duration| duration.as_secs());
    reconnect_delay_from(deadline, now)
}

#[cfg(target_os = "windows")]
const fn reconnect_delay_from(deadline: u64, now: u64) -> Duration {
    Duration::from_secs(deadline.saturating_sub(now))
}

#[cfg(target_os = "windows")]
fn next_reconnect_delay(attempt: &mut u32, minimum: Option<Duration>) -> Result<Duration> {
    let jitter = full_jitter(reconnect_cap(*attempt))?;
    *attempt = attempt.saturating_add(1);
    Ok(minimum.map_or(jitter, |delay| delay.max(jitter)))
}

#[cfg(not(target_os = "windows"))]
async fn run_active_control(
    config: &ClientConfig,
    _identity: &stella_crypto::IdentitySigningKey,
    mut active: ActiveControl,
) -> Result<()> {
    publish_configured_endpoints(config, &mut active).await?;
    loop {
        let interval = heartbeat_interval(&active);
        let deadline = tokio::time::Instant::now() + interval;
        if active.receive_update_until(deadline).await?.is_some() {
            continue;
        }
        active.heartbeat().await.context("heartbeat failed")?;
    }
}

fn heartbeat_interval(active: &ActiveControl) -> Duration {
    active
        .networks()
        .values()
        .map(|state| Duration::from_secs(u64::from(state.policy().heartbeat_seconds)))
        .min()
        .unwrap_or(DEFAULT_HEARTBEAT_INTERVAL)
}

fn reconnect_cap(attempt: u32) -> Duration {
    let exponent = attempt.min(7);
    let multiplier = 1_u32 << exponent;
    MINIMUM_RECONNECT_DELAY
        .checked_mul(multiplier)
        .unwrap_or(MAXIMUM_RECONNECT_DELAY)
        .min(MAXIMUM_RECONNECT_DELAY)
}

fn full_jitter(cap: Duration) -> Result<Duration> {
    let maximum = u64::try_from(cap.as_millis()).context("reconnect delay is too large")?;
    let mut random = [0_u8; 8];
    getrandom::fill(&mut random).context("operating-system randomness is unavailable")?;
    let milliseconds = u64::from_le_bytes(random) % maximum.saturating_add(1);
    Ok(Duration::from_millis(milliseconds))
}

async fn leave_network(config_path: &Path, args: &LeaveArgs, output: &mut dyn Write) -> Result<()> {
    let config = ClientConfig::load(config_path).context("could not load client configuration")?;
    if !config
        .networks
        .iter()
        .any(|network| network.network_id == args.network)
    {
        anyhow::bail!("network {} is not configured", args.network);
    }
    let identity = load_node_identity(&config.identity_path).with_context(|| {
        format!(
            "could not load node identity {}",
            config.identity_path.display()
        )
    })?;
    let connection = authenticate_controller(&config.controller, &identity, None)
        .await
        .context("controller authentication failed")?;
    let mut active = ActiveControl::new(connection);
    let epoch = active
        .leave_network(args.network)
        .await
        .context("controller network leave failed")?;
    remove_network_intent(config_path, args.network)?;
    writeln!(output, "network_id={}", args.network)?;
    writeln!(output, "controller_epoch={epoch}")?;
    Ok(())
}

fn status(config_path: &Path, output: &mut dyn Write) -> Result<()> {
    let config = ClientConfig::load(config_path).context("could not load client configuration")?;
    let identity = load_node_identity(&config.identity_path).with_context(|| {
        format!(
            "could not load node identity {}",
            config.identity_path.display()
        )
    })?;
    writeln!(output, "node_id={}", derive_node_id(identity.public_key()))?;
    writeln!(output, "controller_address={}", config.controller.address())?;
    writeln!(
        output,
        "controller_tls_name={}",
        config.controller.tls_name()
    )?;
    writeln!(
        output,
        "controller_id={}",
        config.controller.controller_id()
    )?;
    writeln!(output, "udp_bind={}", config.udp_bind)?;
    if let Some(proxy) = config.https_proxy {
        writeln!(output, "https_proxy={proxy}")?;
    }
    writeln!(output, "desired_networks={}", config.networks.len())?;
    for network in &config.networks {
        writeln!(
            output,
            "network={}\ttap_adapter={}",
            network.network_id, network.tap_adapter
        )?;
    }
    Ok(())
}

async fn join_network(config_path: &Path, args: &JoinArgs, output: &mut dyn Write) -> Result<()> {
    let config = ClientConfig::load(config_path).context("could not load client configuration")?;
    validate_intent_compatibility(&config, args)?;
    let identity = load_node_identity(&config.identity_path).with_context(|| {
        format!(
            "could not load node identity {}",
            config.identity_path.display()
        )
    })?;
    let enrollment = args
        .enrollment_token
        .as_ref()
        .map(|credential| Enrollment::new(&credential.0, &config.display_name));
    let connection = authenticate_controller(&config.controller, &identity, enrollment)
        .await
        .context("controller authentication failed")?;
    let mut active = ActiveControl::new(connection);
    let state = active
        .join_network(args.network, args.token.as_ref().map(|value| &value.0))
        .await
        .context("controller network join failed")?;
    let epoch = state.controller_epoch();
    let revision = state.snapshot_revision();
    persist_network_intent(config_path, args.network, &args.tap_adapter)?;
    writeln!(output, "network_id={}", args.network)?;
    writeln!(output, "controller_epoch={epoch}")?;
    writeln!(output, "snapshot_revision={revision}")?;
    Ok(())
}

fn validate_intent_compatibility(config: &ClientConfig, args: &JoinArgs) -> Result<()> {
    if let Some(existing) = config
        .networks
        .iter()
        .find(|network| network.network_id == args.network)
    {
        if existing.tap_adapter != args.tap_adapter {
            anyhow::bail!(
                "network {} is already configured for TAP adapter {:?}",
                args.network,
                existing.tap_adapter
            );
        }
    }
    Ok(())
}

fn persist_network_intent(config_path: &Path, network_id: NetworkId, tap: &str) -> Result<()> {
    let text = std::fs::read_to_string(config_path)
        .with_context(|| format!("could not reread {}", config_path.display()))?;
    let mut document = text
        .parse::<toml::Table>()
        .context("could not decode configuration for network persistence")?;
    let networks = document
        .entry("networks")
        .or_insert_with(|| toml::Value::Array(Vec::new()))
        .as_array_mut()
        .ok_or_else(|| anyhow::anyhow!("configuration networks field is not an array"))?;
    let id = network_id.to_string();
    for entry in networks.iter() {
        let table = entry
            .as_table()
            .ok_or_else(|| anyhow::anyhow!("configuration network entry is not a table"))?;
        if table.get("id").and_then(toml::Value::as_str) == Some(id.as_str()) {
            if table.get("tap_adapter").and_then(toml::Value::as_str) == Some(tap) {
                return Ok(());
            }
            anyhow::bail!("network {network_id} has a conflicting TAP adapter");
        }
    }
    let mut entry = toml::Table::new();
    entry.insert("id".to_owned(), toml::Value::String(id));
    entry.insert(
        "tap_adapter".to_owned(),
        toml::Value::String(tap.to_owned()),
    );
    networks.push(toml::Value::Table(entry));
    networks.sort_by(|left, right| {
        left.get("id")
            .and_then(toml::Value::as_str)
            .cmp(&right.get("id").and_then(toml::Value::as_str))
    });
    let encoded = toml::to_string_pretty(&document)
        .context("could not encode configuration with joined network")?;
    let base = config_path.parent().unwrap_or_else(|| Path::new("."));
    ClientConfig::parse(&encoded, base).context("updated client configuration is invalid")?;
    let mut file = AtomicWriteFile::open(config_path)
        .with_context(|| format!("could not open {} for atomic update", config_path.display()))?;
    file.write_all(encoded.as_bytes())
        .context("could not write updated client configuration")?;
    file.commit()
        .context("could not atomically commit updated client configuration")?;
    Ok(())
}

fn remove_network_intent(config_path: &Path, network_id: NetworkId) -> Result<()> {
    let text = std::fs::read_to_string(config_path)
        .with_context(|| format!("could not reread {}", config_path.display()))?;
    let mut document = text
        .parse::<toml::Table>()
        .context("could not decode configuration for network removal")?;
    let networks = document
        .get_mut("networks")
        .and_then(toml::Value::as_array_mut)
        .ok_or_else(|| anyhow::anyhow!("configuration networks field is not an array"))?;
    let id = network_id.to_string();
    let original_length = networks.len();
    networks.retain(|entry| entry.get("id").and_then(toml::Value::as_str) != Some(id.as_str()));
    if networks.len() == original_length {
        anyhow::bail!("network {network_id} is not configured");
    }
    let encoded = toml::to_string_pretty(&document)
        .context("could not encode configuration after network removal")?;
    let base = config_path.parent().unwrap_or_else(|| Path::new("."));
    ClientConfig::parse(&encoded, base).context("updated client configuration is invalid")?;
    let mut file = AtomicWriteFile::open(config_path)
        .with_context(|| format!("could not open {} for atomic update", config_path.display()))?;
    file.write_all(encoded.as_bytes())
        .context("could not write updated client configuration")?;
    file.commit()
        .context("could not atomically commit updated client configuration")?;
    Ok(())
}

fn initialize(config_path: &Path, args: &InitArgs, output: &mut dyn Write) -> Result<()> {
    let paths = InitPaths::new(config_path, &args.identity)?;
    paths.preflight()?;
    let mut created = CreatedPaths::default();
    let result = initialize_inner(&paths, args, output, &mut created);
    if let Err(error) = result {
        return Err(created.rollback(error));
    }
    Ok(())
}

fn initialize_inner(
    paths: &InitPaths,
    args: &InitArgs,
    output: &mut dyn Write,
    created: &mut CreatedPaths,
) -> Result<()> {
    ensure_directory(&paths.base_directory, &mut created.directories)?;
    ensure_directory(parent_required(&paths.identity)?, &mut created.directories)?;

    let identity = create_node_identity(&paths.identity).with_context(|| {
        format!(
            "could not create node identity {}",
            paths.identity.display()
        )
    })?;
    created.files.push(paths.identity.clone());
    let document = configuration_document(args)?;
    write_create_new(&paths.config, document.as_bytes())?;
    created.files.push(paths.config.clone());
    let loaded = ClientConfig::load(&paths.config).context("generated configuration is invalid")?;
    if loaded.identity_path != paths.identity {
        anyhow::bail!("generated configuration resolved an unexpected identity path");
    }
    writeln!(output, "node_id={}", derive_node_id(identity.public_key()))?;
    writeln!(output, "config={}", paths.config.display())?;
    Ok(())
}

fn configuration_document(args: &InitArgs) -> Result<String> {
    let document = InitialDocument {
        version: 1,
        controller: InitialController {
            address: args.controller,
            tls_name: &args.tls_name,
            id: args.controller_id.to_string(),
            spki_pins: args.spki_pins.iter().map(ToString::to_string).collect(),
        },
        identity: InitialIdentity {
            node_key: &args.identity,
            display_name: &args.display_name,
        },
        transport: InitialTransport {
            udp_bind: args.udp_bind,
            https_proxy: args.https_proxy,
            advertised_endpoints: Vec::new(),
        },
        networks: Vec::new(),
        logging: InitialLogging {
            filter: "info,stella_client=info",
        },
    };
    toml::to_string_pretty(&document).context("could not encode initial client configuration")
}

#[derive(Serialize)]
struct InitialDocument<'a> {
    version: u32,
    controller: InitialController<'a>,
    identity: InitialIdentity<'a>,
    transport: InitialTransport,
    networks: Vec<toml::Value>,
    logging: InitialLogging<'a>,
}

#[derive(Serialize)]
struct InitialController<'a> {
    address: SocketAddr,
    tls_name: &'a str,
    id: String,
    spki_pins: Vec<String>,
}

#[derive(Serialize)]
struct InitialIdentity<'a> {
    node_key: &'a Path,
    display_name: &'a str,
}

#[derive(Serialize)]
struct InitialTransport {
    udp_bind: SocketAddr,
    #[serde(skip_serializing_if = "Option::is_none")]
    https_proxy: Option<SocketAddr>,
    advertised_endpoints: Vec<toml::Value>,
}

#[derive(Serialize)]
struct InitialLogging<'a> {
    filter: &'a str,
}

struct InitPaths {
    base_directory: PathBuf,
    config: PathBuf,
    identity: PathBuf,
}

impl InitPaths {
    fn new(config: &Path, identity: &Path) -> Result<Self> {
        if config.as_os_str().is_empty() {
            anyhow::bail!("configuration path must not be empty");
        }
        if identity.as_os_str().is_empty() {
            anyhow::bail!("identity path must not be empty");
        }
        let base_directory = config
            .parent()
            .filter(|path| !path.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new("."))
            .to_path_buf();
        let identity = if identity.is_absolute() {
            identity.to_path_buf()
        } else {
            base_directory.join(identity)
        };
        Ok(Self {
            base_directory,
            config: config.to_path_buf(),
            identity,
        })
    }

    fn preflight(&self) -> Result<()> {
        for path in [&self.config, &self.identity] {
            match std::fs::symlink_metadata(path) {
                Ok(_) => anyhow::bail!("initialization target already exists: {}", path.display()),
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(error) => {
                    return Err(error)
                        .with_context(|| format!("could not inspect {}", path.display()))
                }
            }
        }
        Ok(())
    }
}

#[derive(Default)]
struct CreatedPaths {
    files: Vec<PathBuf>,
    directories: Vec<PathBuf>,
}

impl CreatedPaths {
    fn rollback(self, cause: anyhow::Error) -> anyhow::Error {
        let mut cleanup = None;
        for path in self.files.into_iter().rev() {
            if let Err(error) = std::fs::remove_file(&path) {
                if error.kind() != std::io::ErrorKind::NotFound && cleanup.is_none() {
                    cleanup = Some((path, error));
                }
            }
        }
        for path in self.directories.into_iter().rev() {
            if let Err(error) = std::fs::remove_dir(&path) {
                if error.kind() != std::io::ErrorKind::NotFound && cleanup.is_none() {
                    cleanup = Some((path, error));
                }
            }
        }
        match cleanup {
            Some((path, error)) => cause.context(format!(
                "could not roll back {} after initialization failure: {error}",
                path.display()
            )),
            None => cause,
        }
    }
}

fn ensure_directory(path: &Path, created: &mut Vec<PathBuf>) -> Result<()> {
    if path.as_os_str().is_empty() {
        return Ok(());
    }
    match std::fs::metadata(path) {
        Ok(metadata) if metadata.is_dir() => return Ok(()),
        Ok(_) => anyhow::bail!(
            "initialization parent is not a directory: {}",
            path.display()
        ),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => {
            return Err(error).with_context(|| format!("could not inspect {}", path.display()))
        }
    }
    if let Some(parent) = path.parent() {
        ensure_directory(parent, created)?;
    }
    match std::fs::create_dir(path) {
        Ok(()) => created.push(path.to_path_buf()),
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
            if !path.is_dir() {
                anyhow::bail!(
                    "initialization parent is not a directory: {}",
                    path.display()
                );
            }
        }
        Err(error) => {
            return Err(error).with_context(|| format!("could not create {}", path.display()))
        }
    }
    Ok(())
}

fn parent_required(path: &Path) -> Result<&Path> {
    path.parent()
        .ok_or_else(|| anyhow::anyhow!("path has no parent: {}", path.display()))
}

fn write_create_new(path: &Path, bytes: &[u8]) -> Result<()> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .with_context(|| format!("could not create configuration {}", path.display()))?;
    file.write_all(bytes)
        .with_context(|| format!("could not write configuration {}", path.display()))?;
    file.sync_all()
        .with_context(|| format!("could not sync configuration {}", path.display()))
}

#[cfg(test)]
mod tests {
    #[cfg(windows)]
    use std::{collections::BTreeMap, time::Duration};
    use std::{
        net::{Ipv4Addr, SocketAddr},
        path::PathBuf,
        str::FromStr,
        sync::atomic::{AtomicU64, Ordering},
    };

    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
    #[cfg(windows)]
    use stella_client::ClientDataRuntime;
    use stella_client::{load_node_identity, ClientConfig, SpkiPin};
    use stella_common::{ControllerId, NetworkId};
    #[cfg(windows)]
    use stella_crypto::{IdentitySeed, IdentitySigningKey};

    use super::{
        configuration_document, full_jitter, initialize, persist_network_intent, reconnect_cap,
        remove_network_intent, status, CliCredential, InitArgs, MAXIMUM_RECONNECT_DELAY,
    };
    #[cfg(windows)]
    use super::{drive_data_until, finish_client_shutdown, reconnect_delay_from, DataDriveOutcome};

    static TEMP_SEQUENCE: AtomicU64 = AtomicU64::new(1);

    fn directory() -> PathBuf {
        let sequence = TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        std::env::temp_dir().join(format!(
            "stella-client-init-{}-{sequence}",
            std::process::id()
        ))
    }

    fn init_args() -> InitArgs {
        InitArgs {
            controller: SocketAddr::from((Ipv4Addr::LOCALHOST, 44_900)),
            tls_name: "localhost".to_owned(),
            controller_id: ControllerId::from_bytes([0x41; 16]),
            spki_pins: vec![SpkiPin::from_digest([0x42; 32])],
            display_name: "Windows node".to_owned(),
            udp_bind: SocketAddr::from((Ipv4Addr::UNSPECIFIED, 45_100)),
            https_proxy: None,
            identity: PathBuf::from("secrets/node.pk8"),
        }
    }

    #[cfg(windows)]
    async fn data_runtime_without_tap() -> (ClientDataRuntime, IdentitySigningKey) {
        let mut args = init_args();
        args.udp_bind = SocketAddr::from((Ipv4Addr::LOCALHOST, 0));
        let document = configuration_document(&args).expect("encode test configuration");
        let config = ClientConfig::parse(&document, std::path::Path::new("."))
            .expect("parse test configuration");
        let identity = IdentitySigningKey::from_seed(&IdentitySeed::from_bytes([0x63; 32]));
        let data = ClientDataRuntime::start(&config, &BTreeMap::new(), &identity)
            .await
            .expect("start data runtime without TAP networks");
        (data, identity)
    }

    #[test]
    fn cli_credentials_require_exact_unpadded_base64url_and_redact() {
        let encoded = URL_SAFE_NO_PAD.encode([0x5a; 32]);
        let credential = CliCredential::from_str(&encoded).expect("parse credential");
        assert_eq!(format!("{credential:?}"), "CliCredential([REDACTED])");
        assert!(CliCredential::from_str(&format!("{encoded}=")).is_err());
        assert!(CliCredential::from_str(&URL_SAFE_NO_PAD.encode([0x5a; 31])).is_err());
        assert!(CliCredential::from_str("not+a+base64url+credential").is_err());
    }

    #[test]
    fn reconnect_backoff_is_capped_and_full_jitter_stays_within_cap() {
        assert_eq!(reconnect_cap(0), std::time::Duration::from_millis(250));
        assert_eq!(reconnect_cap(1), std::time::Duration::from_millis(500));
        assert_eq!(reconnect_cap(6), std::time::Duration::from_secs(16));
        assert_eq!(reconnect_cap(7), MAXIMUM_RECONNECT_DELAY);
        assert_eq!(reconnect_cap(u32::MAX), MAXIMUM_RECONNECT_DELAY);
        for _sample in 0..32 {
            assert!(full_jitter(reconnect_cap(4)).expect("generate jitter") <= reconnect_cap(4));
        }
    }

    #[cfg(windows)]
    #[tokio::test]
    async fn pending_control_operation_keeps_data_runtime_progressing() {
        let (mut data, identity) = data_runtime_without_tap().await;
        let target = data.local_udp_address();
        let operation = async move {
            let sender = tokio::net::UdpSocket::bind("127.0.0.1:0")
                .await
                .expect("bind test sender");
            sender
                .send_to(&[0xff], target)
                .await
                .expect("send malformed data-plane datagram");
            tokio::time::sleep(Duration::from_millis(100)).await;
            0x63_u8
        };
        let mut shutdown = tokio::spawn(std::future::pending::<std::io::Result<()>>());
        let output = tokio::time::timeout(
            Duration::from_secs(1),
            drive_data_until(&mut data, &identity, operation, &mut shutdown),
        )
        .await
        .expect("control operation wait remains bounded")
        .expect("data runtime remains healthy");
        assert!(matches!(output, DataDriveOutcome::Operation(0x63)));
        assert!(
            tokio::time::timeout(Duration::from_millis(25), data.receive_next(&identity))
                .await
                .is_err(),
            "the reconnect driver should have consumed the queued UDP datagram"
        );
        shutdown.abort();
        let _shutdown_result = shutdown.await;
        data.shutdown().await.expect("shutdown test data runtime");
    }

    #[cfg(windows)]
    #[tokio::test]
    async fn shutdown_signal_interrupts_control_wait_and_closes_data_runtime() {
        let (runtime, identity) = data_runtime_without_tap().await;
        let mut data = Some(runtime);
        let mut shutdown = tokio::spawn(async { Ok(()) });
        let outcome = drive_data_until(
            data.as_mut().expect("active data runtime"),
            &identity,
            std::future::pending::<()>(),
            &mut shutdown,
        )
        .await
        .expect("data runtime stays healthy until shutdown");
        let DataDriveOutcome::Shutdown(result) = outcome else {
            panic!("shutdown must interrupt the pending control operation");
        };
        finish_client_shutdown(&mut data, result)
            .await
            .expect("finish graceful client shutdown");
        assert!(data.is_none());
    }

    #[cfg(windows)]
    #[test]
    fn authenticated_shutdown_deadline_is_a_minimum_reconnect_delay() {
        assert_eq!(reconnect_delay_from(105, 100), Duration::from_secs(5));
        assert_eq!(reconnect_delay_from(99, 100), Duration::ZERO);
    }

    #[test]
    fn network_intent_update_is_valid_atomic_idempotent_and_conflict_safe() {
        let directory = directory();
        std::fs::create_dir(&directory).expect("create test directory");
        let config_path = directory.join("client.toml");
        let initial = configuration_document(&init_args()).expect("encode configuration");
        std::fs::write(&config_path, initial).expect("write configuration");
        let network_id = NetworkId::from_bytes([0x33; 16]);

        persist_network_intent(&config_path, network_id, "Stella LAN")
            .expect("persist network intent");
        let first = std::fs::read_to_string(&config_path).expect("read updated configuration");
        let loaded = ClientConfig::load(&config_path).expect("load updated configuration");
        assert_eq!(loaded.networks.len(), 1);
        assert_eq!(loaded.networks[0].network_id, network_id);
        assert_eq!(loaded.networks[0].tap_adapter, "Stella LAN");

        persist_network_intent(&config_path, network_id, "Stella LAN")
            .expect("repeat identical persistence");
        assert_eq!(
            std::fs::read_to_string(&config_path).expect("reread configuration"),
            first
        );
        assert!(persist_network_intent(&config_path, network_id, "Other TAP").is_err());
        assert_eq!(
            std::fs::read_to_string(&config_path).expect("read after conflict"),
            first
        );
        std::fs::remove_dir_all(directory).expect("remove test directory");
    }

    #[test]
    fn network_intent_removal_is_valid_atomic_and_missing_safe() {
        let directory = directory();
        std::fs::create_dir(&directory).expect("create test directory");
        let config_path = directory.join("client.toml");
        let initial = configuration_document(&init_args()).expect("encode configuration");
        std::fs::write(&config_path, initial).expect("write configuration");
        let first = NetworkId::from_bytes([0x31; 16]);
        let second = NetworkId::from_bytes([0x32; 16]);
        persist_network_intent(&config_path, first, "First TAP").expect("persist first network");
        persist_network_intent(&config_path, second, "Second TAP").expect("persist second network");

        remove_network_intent(&config_path, first).expect("remove first network");
        let remaining = ClientConfig::load(&config_path).expect("load updated configuration");
        assert_eq!(remaining.networks.len(), 1);
        assert_eq!(remaining.networks[0].network_id, second);
        let after_removal = std::fs::read_to_string(&config_path).expect("read after removal");
        assert!(remove_network_intent(&config_path, first).is_err());
        assert_eq!(
            std::fs::read_to_string(&config_path).expect("read after missing removal"),
            after_removal
        );
        std::fs::remove_dir_all(directory).expect("remove test directory");
    }

    #[cfg(windows)]
    #[test]
    fn init_is_create_new_transactional_and_self_consistent() {
        let directory = directory();
        let config_path = directory.join("client.toml");
        let args = init_args();
        let mut output = Vec::new();
        initialize(&config_path, &args, &mut output).expect("initialize client");
        let config = ClientConfig::load(&config_path).expect("load generated config");
        let identity = load_node_identity(&config.identity_path).expect("load generated identity");
        let text = String::from_utf8(output).expect("UTF-8 output");
        assert!(text.contains(&format!(
            "node_id={}",
            stella_crypto::derive_node_id(identity.public_key())
        )));
        assert!(config.networks.is_empty());
        assert!(initialize(&config_path, &args, &mut Vec::new()).is_err());
        std::fs::remove_dir_all(directory).expect("remove test directory");
    }

    #[cfg(windows)]
    #[test]
    fn status_reports_only_local_non_secret_configuration() {
        let directory = directory();
        let config_path = directory.join("client.toml");
        let args = init_args();
        initialize(&config_path, &args, &mut Vec::new()).expect("initialize client");
        persist_network_intent(
            &config_path,
            NetworkId::from_bytes([0x55; 16]),
            "Stella LAN",
        )
        .expect("persist network");

        let mut output = Vec::new();
        status(&config_path, &mut output).expect("read status");
        let text = String::from_utf8(output).expect("UTF-8 status");
        assert!(text.contains("controller_address=127.0.0.1:44900"));
        assert!(text.contains("desired_networks=1"));
        assert!(text.contains("network=55555555555555555555555555555555\ttap_adapter=Stella LAN"));
        assert!(!text.contains("node.pk8"));
        assert!(!text.contains("sha256/"));
        std::fs::remove_dir_all(directory).expect("remove test directory");
    }
}
