//! Windows client command-line parsing, initialization, and network intent.

use std::{
    fs::OpenOptions,
    io::Write,
    net::SocketAddr,
    path::{Path, PathBuf},
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
use stella_common::{ControllerId, NetworkId};
use stella_crypto::derive_node_id;

const DEFAULT_IDENTITY_PATH: &str = "secrets/node.pk8";

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
    }
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
    networks: Vec<InitialNetwork>,
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
    advertised_endpoints: Vec<InitialEndpoint>,
}

#[derive(Serialize)]
struct InitialEndpoint {
    address: SocketAddr,
    priority: u8,
    max_datagram_size: u32,
}

#[derive(Serialize)]
struct InitialNetwork {
    id: String,
    tap_adapter: String,
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
    use std::{
        net::{Ipv4Addr, SocketAddr},
        path::PathBuf,
        str::FromStr,
        sync::atomic::{AtomicU64, Ordering},
    };

    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
    use stella_client::{load_node_identity, ClientConfig, SpkiPin};
    use stella_common::{ControllerId, NetworkId};

    use super::{
        configuration_document, initialize, persist_network_intent, CliCredential, InitArgs,
    };

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
            identity: PathBuf::from("secrets/node.pk8"),
        }
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
}
