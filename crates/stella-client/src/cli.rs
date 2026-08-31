//! Command-line parsing and create-new client initialization.

use std::{
    fs::OpenOptions,
    io::Write,
    net::SocketAddr,
    path::{Path, PathBuf},
};

use anyhow::{Context, Result};
use clap::{Args, Parser, Subcommand};
use serde::Serialize;
use stella_client::{create_node_identity, ClientConfig, SpkiPin};
use stella_common::ControllerId;
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

pub(crate) fn run() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Command::Init(args) => initialize(&cli.config, &args, &mut std::io::stdout().lock()),
    }
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
        sync::atomic::{AtomicU64, Ordering},
    };

    use stella_client::{load_node_identity, ClientConfig, SpkiPin};
    use stella_common::ControllerId;

    use super::{initialize, InitArgs};

    static TEMP_SEQUENCE: AtomicU64 = AtomicU64::new(1);

    fn directory() -> PathBuf {
        let sequence = TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        std::env::temp_dir().join(format!(
            "stella-client-init-{}-{sequence}",
            std::process::id()
        ))
    }

    #[cfg(windows)]
    #[test]
    fn init_is_create_new_transactional_and_self_consistent() {
        let directory = directory();
        let config_path = directory.join("client.toml");
        let args = InitArgs {
            controller: SocketAddr::from((Ipv4Addr::LOCALHOST, 44_900)),
            tls_name: "localhost".to_owned(),
            controller_id: ControllerId::from_bytes([0x41; 16]),
            spki_pins: vec![SpkiPin::from_digest([0x42; 32])],
            display_name: "Windows node".to_owned(),
            udp_bind: SocketAddr::from((Ipv4Addr::UNSPECIFIED, 45_100)),
            identity: PathBuf::from("secrets/node.pk8"),
        };
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
