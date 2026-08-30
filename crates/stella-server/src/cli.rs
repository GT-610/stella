use std::{
    future::Future,
    io::Write,
    num::NonZeroUsize,
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

use anyhow::{anyhow, Context, Result};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use clap::{Args, Parser, Subcommand, ValueEnum};
use stella_common::{NetworkId, NodeId};
use stella_crypto::derive_controller_id;
use stella_proto::{ConfidentialityPolicy, NetworkPolicy};
use stella_server::{
    authority::{AuthorityHandle, AuthorityThread},
    bootstrap::{initialize_controller, BootstrapOptions},
    config::ServerConfig,
    identity::load_controller_identity,
    store::{AuthorityStore, BearerToken, MembershipStatus, NetworkRecord, NodeRecord},
};
use zeroize::Zeroizing;

const DEFAULT_TOKEN_TTL_SECONDS: u64 = 3_600;

#[derive(Debug, Parser)]
#[command(
    name = "stella-server",
    version,
    about = "Stella controller and authority administration"
)]
struct Cli {
    #[arg(
        long,
        global = true,
        value_name = "PATH",
        default_value = "server.toml"
    )]
    config: PathBuf,
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Creates a complete controller deployment without overwriting files.
    Init(InitArgs),
    /// Creates, inspects, and deletes virtual networks.
    Network {
        #[command(subcommand)]
        command: NetworkCommand,
    },
    /// Issues single-use node enrollment tokens.
    EnrollmentToken {
        #[command(subcommand)]
        command: EnrollmentTokenCommand,
    },
    /// Issues single-use network join tokens.
    JoinToken {
        #[command(subcommand)]
        command: JoinTokenCommand,
    },
    /// Lists and administratively enables or disables nodes.
    Node {
        #[command(subcommand)]
        command: NodeCommand,
    },
    /// Adds, removes, suspends, or resumes memberships.
    Member {
        #[command(subcommand)]
        command: MemberCommand,
    },
    /// Verifies or backs up controller authority state.
    State {
        #[command(subcommand)]
        command: StateCommand,
    },
}

#[derive(Clone, Debug, Args)]
struct InitArgs {
    #[arg(long, default_value = "0.0.0.0:44900")]
    listen: std::net::SocketAddr,
    #[arg(long = "tls-name", value_name = "DNS_OR_IP")]
    tls_names: Vec<String>,
    #[arg(long, default_value_t = stella_server::tls::DEFAULT_TLS_VALIDITY_DAYS)]
    tls_validity_days: u16,
}

#[derive(Debug, Subcommand)]
enum NetworkCommand {
    /// Creates one network with a validated canonical policy.
    Create(NetworkCreateArgs),
    /// Lists every network in stable ID order.
    List,
    /// Shows one network and all current memberships.
    Show(NetworkIdArgs),
    /// Deletes one network and all state scoped to it.
    Delete(NetworkIdArgs),
}

#[derive(Debug, Args)]
struct NetworkCreateArgs {
    #[arg(long)]
    name: String,
    #[arg(long)]
    id: Option<NetworkId>,
    #[arg(long, value_enum, default_value_t = ConfidentialityArg::Encrypt)]
    confidentiality: ConfidentialityArg,
    #[arg(long, default_value_t = 1_514)]
    max_frame_size: u16,
    #[arg(long, default_value_t = 32)]
    max_flood_peers: u16,
    #[arg(long, default_value_t = 1_000)]
    flood_rate: u32,
    #[arg(long, default_value_t = 2_000)]
    flood_burst: u32,
    #[arg(long, default_value_t = 300)]
    mac_age_seconds: u32,
    #[arg(long, default_value_t = 10)]
    heartbeat_seconds: u16,
    #[arg(long, default_value_t = 30)]
    peer_lease_seconds: u16,
    #[arg(long, default_value_t = 900)]
    session_lifetime_seconds: u32,
    #[arg(long, default_value_t = 3_000)]
    reassembly_timeout_ms: u32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, ValueEnum)]
enum ConfidentialityArg {
    AuthenticateOnly,
    Encrypt,
}

impl From<ConfidentialityArg> for ConfidentialityPolicy {
    fn from(value: ConfidentialityArg) -> Self {
        match value {
            ConfidentialityArg::AuthenticateOnly => Self::AuthenticateOnly,
            ConfidentialityArg::Encrypt => Self::Encrypt,
        }
    }
}

#[derive(Clone, Copy, Debug, Args)]
struct NetworkIdArgs {
    #[arg(long)]
    network: NetworkId,
}

#[derive(Debug, Subcommand)]
enum EnrollmentTokenCommand {
    /// Creates one token and prints it exactly once to stdout.
    Create(TokenLifetimeArgs),
}

#[derive(Debug, Subcommand)]
enum JoinTokenCommand {
    /// Creates one network-scoped token and prints it exactly once to stdout.
    Create(JoinTokenCreateArgs),
}

#[derive(Clone, Copy, Debug, Args)]
struct TokenLifetimeArgs {
    #[arg(long, default_value_t = DEFAULT_TOKEN_TTL_SECONDS)]
    ttl_seconds: u64,
}

#[derive(Clone, Copy, Debug, Args)]
struct JoinTokenCreateArgs {
    #[arg(long)]
    network: NetworkId,
    #[command(flatten)]
    lifetime: TokenLifetimeArgs,
}

#[derive(Debug, Subcommand)]
enum NodeCommand {
    /// Lists every registered node.
    List,
    /// Enables one registered node and rotates all of its grants.
    Enable(NodeIdArgs),
    /// Disables one registered node and invalidates all of its grants.
    Disable(NodeIdArgs),
}

#[derive(Clone, Copy, Debug, Args)]
struct NodeIdArgs {
    #[arg(long)]
    node: NodeId,
}

#[derive(Debug, Subcommand)]
enum MemberCommand {
    /// Adds an active membership without a join token.
    Add(MembershipArgs),
    /// Removes a membership and endpoint state.
    Remove(MembershipArgs),
    /// Suspends an existing membership.
    Suspend(MembershipArgs),
    /// Resumes an existing membership.
    Resume(MembershipArgs),
}

#[derive(Clone, Copy, Debug, Args)]
struct MembershipArgs {
    #[arg(long)]
    network: NetworkId,
    #[arg(long)]
    node: NodeId,
}

#[derive(Debug, Subcommand)]
enum StateCommand {
    /// Creates one create-new verified point-in-time redb backup.
    Backup {
        #[arg(long, value_name = "PATH")]
        output: PathBuf,
    },
    /// Walks every authority record and verifies all invariants.
    Verify,
}

pub(crate) async fn run() -> Result<()> {
    let cli = Cli::parse();
    let mut stdout = std::io::stdout().lock();
    execute(cli, &mut stdout).await
}

async fn execute(cli: Cli, output: &mut dyn Write) -> Result<()> {
    match cli.command {
        Command::Init(args) => execute_init(&cli.config, args, output),
        Command::Network { command } => execute_network(&cli.config, command, output).await,
        Command::EnrollmentToken { command } => {
            execute_enrollment_token(&cli.config, command, output).await
        }
        Command::JoinToken { command } => execute_join_token(&cli.config, command, output).await,
        Command::Node { command } => execute_node(&cli.config, command, output).await,
        Command::Member { command } => execute_member(&cli.config, command, output).await,
        Command::State { command } => execute_state(&cli.config, command, output).await,
    }
}

fn execute_init(config_path: &Path, args: InitArgs, output: &mut dyn Write) -> Result<()> {
    let result = initialize_controller(
        config_path,
        &BootstrapOptions {
            listen: args.listen,
            tls_subject_alt_names: args.tls_names,
            tls_validity_days: args.tls_validity_days,
        },
    )?;
    let pin = base64::engine::general_purpose::STANDARD.encode(result.tls_spki_sha256);
    writeln!(output, "controller_id={}", result.controller_id)
        .context("could not write controller ID")?;
    writeln!(output, "tls_spki_pin=sha256/{pin}").context("could not write TLS SPKI pin")?;
    writeln!(output, "tls_not_after={}", result.tls_not_after_unix)
        .context("could not write TLS expiration")?;
    writeln!(output, "config={}", config_path.display())
        .context("could not write configuration path")
}

async fn execute_network(
    config_path: &Path,
    command: NetworkCommand,
    output: &mut dyn Write,
) -> Result<()> {
    match command {
        NetworkCommand::Create(args) => {
            let network_id = match args.id {
                Some(network_id) => network_id,
                None => generate_network_id()?,
            };
            let now = unix_time()?;
            let policy = NetworkPolicy {
                confidentiality: args.confidentiality.into(),
                max_frame_size: args.max_frame_size,
                max_flood_peers: args.max_flood_peers,
                flood_rate: args.flood_rate,
                flood_burst: args.flood_burst,
                mac_age_seconds: args.mac_age_seconds,
                heartbeat_seconds: args.heartbeat_seconds,
                peer_lease_seconds: args.peer_lease_seconds,
                session_lifetime_seconds: args.session_lifetime_seconds,
                reassembly_timeout_ms: args.reassembly_timeout_ms,
                network_id,
                policy_revision: 1,
            };
            let record = NetworkRecord::new(policy, &args.name, now)?;
            with_authority(config_path, move |authority| async move {
                authority.create_network(record).await?;
                Ok(())
            })
            .await?;
            writeln!(output, "{network_id}").context("could not write network ID")
        }
        NetworkCommand::List => {
            let records = with_authority(config_path, |authority| async move {
                Ok(authority.list_networks().await?)
            })
            .await?;
            for record in records {
                writeln!(
                    output,
                    "{}\t{}\tepoch={}\trevision={}",
                    record.network_id(),
                    record.display_name(),
                    record.controller_epoch(),
                    record.snapshot_revision()
                )
                .context("could not write network list")?;
            }
            Ok(())
        }
        NetworkCommand::Show(args) => {
            let network_id = args.network;
            let (record, memberships) = with_authority(config_path, move |authority| async move {
                let record = authority
                    .get_network(network_id)
                    .await?
                    .ok_or_else(|| anyhow!("network {network_id} does not exist"))?;
                let memberships = authority.list_memberships(network_id).await?;
                Ok((record, memberships))
            })
            .await?;
            write_network(output, &record)?;
            for membership in memberships {
                writeln!(
                    output,
                    "member={}\tstatus={}\tpermissions=0x{:04x}\tgrant={}",
                    membership.node_id(),
                    membership_status(membership.status()),
                    membership.permissions().bits(),
                    membership.grant_serial()
                )
                .context("could not write network membership")?;
            }
            Ok(())
        }
        NetworkCommand::Delete(args) => {
            let network_id = args.network;
            let deleted = with_authority(config_path, move |authority| async move {
                Ok(authority.delete_network(network_id).await?)
            })
            .await?;
            writeln!(output, "{}", if deleted { "deleted" } else { "absent" })
                .context("could not write network deletion result")
        }
    }
}

async fn execute_enrollment_token(
    config_path: &Path,
    command: EnrollmentTokenCommand,
    output: &mut dyn Write,
) -> Result<()> {
    let EnrollmentTokenCommand::Create(args) = command;
    let (created_at, expires_at) = token_lifetime(args.ttl_seconds)?;
    let token = with_authority(config_path, move |authority| async move {
        Ok(authority
            .issue_enrollment_token(created_at, expires_at)
            .await?)
    })
    .await?;
    write_token(output, &token)
}

async fn execute_join_token(
    config_path: &Path,
    command: JoinTokenCommand,
    output: &mut dyn Write,
) -> Result<()> {
    let JoinTokenCommand::Create(args) = command;
    let network_id = args.network;
    let (created_at, expires_at) = token_lifetime(args.lifetime.ttl_seconds)?;
    let token = with_authority(config_path, move |authority| async move {
        Ok(authority
            .issue_join_token(network_id, created_at, expires_at)
            .await?)
    })
    .await?;
    write_token(output, &token)
}

async fn execute_node(
    config_path: &Path,
    command: NodeCommand,
    output: &mut dyn Write,
) -> Result<()> {
    match command {
        NodeCommand::List => {
            let nodes = with_authority(config_path, |authority| async move {
                Ok(authority.list_nodes().await?)
            })
            .await?;
            for node in nodes {
                write_node(output, &node)?;
            }
            Ok(())
        }
        NodeCommand::Enable(args) => set_node_enabled(config_path, args.node, true, output).await,
        NodeCommand::Disable(args) => set_node_enabled(config_path, args.node, false, output).await,
    }
}

async fn set_node_enabled(
    config_path: &Path,
    node_id: NodeId,
    enabled: bool,
    output: &mut dyn Write,
) -> Result<()> {
    let changed = with_authority(config_path, move |authority| async move {
        Ok(authority.set_node_enabled(node_id, enabled).await?)
    })
    .await?;
    writeln!(output, "{}", if changed { "changed" } else { "unchanged" })
        .context("could not write node state result")
}

async fn execute_member(
    config_path: &Path,
    command: MemberCommand,
    output: &mut dyn Write,
) -> Result<()> {
    let revision = match command {
        MemberCommand::Add(args) => {
            let now = unix_time()?;
            with_authority(config_path, move |authority| async move {
                Ok(authority.add_member(args.node, args.network, now).await?)
            })
            .await?
        }
        MemberCommand::Remove(args) => {
            with_authority(config_path, move |authority| async move {
                Ok(authority.leave_network(args.node, args.network).await?)
            })
            .await?
        }
        MemberCommand::Suspend(args) => {
            with_authority(config_path, move |authority| async move {
                Ok(authority
                    .set_membership_status(args.node, args.network, MembershipStatus::Suspended)
                    .await?)
            })
            .await?
        }
        MemberCommand::Resume(args) => {
            with_authority(config_path, move |authority| async move {
                Ok(authority
                    .set_membership_status(args.node, args.network, MembershipStatus::Active)
                    .await?)
            })
            .await?
        }
    };
    writeln!(
        output,
        "network={}\tepoch={}\trevision={}",
        revision.network_id, revision.controller_epoch, revision.snapshot_revision
    )
    .context("could not write membership authority revision")
}

async fn execute_state(
    config_path: &Path,
    command: StateCommand,
    output: &mut dyn Write,
) -> Result<()> {
    match command {
        StateCommand::Backup {
            output: destination,
        } => {
            let copied = with_authority(config_path, move |authority| async move {
                Ok(authority.backup_state(destination).await?)
            })
            .await?;
            writeln!(output, "bytes={copied}").context("could not write backup result")
        }
        StateCommand::Verify => {
            with_authority(config_path, |authority| async move {
                authority.verify().await?;
                Ok(())
            })
            .await?;
            writeln!(output, "ok").context("could not write verification result")
        }
    }
}

async fn with_authority<T, F, Fut>(config_path: &Path, operation: F) -> Result<T>
where
    F: FnOnce(AuthorityHandle) -> Fut,
    Fut: Future<Output = Result<T>>,
{
    let config = ServerConfig::load(config_path)
        .with_context(|| format!("could not load {}", config_path.display()))?;
    let identity =
        load_controller_identity(&config.controller_identity_path).with_context(|| {
            format!(
                "could not load controller identity {}",
                config.controller_identity_path.display()
            )
        })?;
    let controller_id = derive_controller_id(identity.public_key());
    drop(identity);
    let store = AuthorityStore::open(&config.database_path, controller_id).with_context(|| {
        format!(
            "could not open authority database {}",
            config.database_path.display()
        )
    })?;
    let capacity = NonZeroUsize::new(config.limits.authority_queue)
        .context("authority queue capacity must be non-zero")?;
    let worker = AuthorityThread::spawn(store, capacity)?;
    let result = operation(worker.handle()).await;
    let shutdown = worker.shutdown().await;
    match (result, shutdown) {
        (Ok(value), Ok(())) => Ok(value),
        (Ok(_), Err(error)) => Err(error).context("authority shutdown failed"),
        (Err(error), _) => Err(error),
    }
}

fn generate_network_id() -> Result<NetworkId> {
    let mut bytes = [0_u8; NetworkId::LENGTH];
    loop {
        getrandom::fill(&mut bytes).map_err(|_| anyhow!("operating-system randomness failed"))?;
        let network_id = NetworkId::from_bytes(bytes);
        if !network_id.is_zero() {
            return Ok(network_id);
        }
    }
}

fn token_lifetime(ttl_seconds: u64) -> Result<(u64, u64)> {
    if ttl_seconds == 0 {
        return Err(anyhow!("token lifetime must be non-zero"));
    }
    let created_at = unix_time()?;
    let expires_at = created_at
        .checked_add(ttl_seconds)
        .context("token expiry overflow")?;
    Ok((created_at, expires_at))
}

fn unix_time() -> Result<u64> {
    Ok(SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("system clock is before the Unix epoch")?
        .as_secs())
}

fn write_token(output: &mut dyn Write, token: &BearerToken) -> Result<()> {
    let encoded = Zeroizing::new(URL_SAFE_NO_PAD.encode(token.expose_secret()));
    writeln!(output, "{}", encoded.as_str()).context("could not write bearer token")
}

fn write_node(output: &mut dyn Write, node: &NodeRecord) -> Result<()> {
    writeln!(
        output,
        "{}\t{}\t{}\tcreated_at={}",
        node.node_id(),
        if node.enabled() {
            "enabled"
        } else {
            "disabled"
        },
        node.display_name(),
        node.created_at()
    )
    .context("could not write node record")
}

fn write_network(output: &mut dyn Write, record: &NetworkRecord) -> Result<()> {
    let policy = record.policy();
    writeln!(output, "id={}", record.network_id())?;
    writeln!(output, "name={}", record.display_name())?;
    writeln!(output, "created_at={}", record.created_at())?;
    writeln!(output, "controller_epoch={}", record.controller_epoch())?;
    writeln!(output, "snapshot_revision={}", record.snapshot_revision())?;
    writeln!(output, "confidentiality={:?}", policy.confidentiality)?;
    writeln!(output, "max_frame_size={}", policy.max_frame_size)?;
    writeln!(output, "max_flood_peers={}", policy.max_flood_peers)?;
    writeln!(output, "flood_rate={}", policy.flood_rate)?;
    writeln!(output, "flood_burst={}", policy.flood_burst)?;
    writeln!(output, "mac_age_seconds={}", policy.mac_age_seconds)?;
    writeln!(output, "heartbeat_seconds={}", policy.heartbeat_seconds)?;
    writeln!(output, "peer_lease_seconds={}", policy.peer_lease_seconds)?;
    writeln!(
        output,
        "session_lifetime_seconds={}",
        policy.session_lifetime_seconds
    )?;
    writeln!(
        output,
        "reassembly_timeout_ms={}",
        policy.reassembly_timeout_ms
    )?;
    writeln!(output, "policy_revision={}", policy.policy_revision)
        .context("could not write network record")
}

const fn membership_status(status: MembershipStatus) -> &'static str {
    match status {
        MembershipStatus::Active => "active",
        MembershipStatus::Suspended => "suspended",
    }
}

#[cfg(test)]
mod tests {
    use std::{
        ffi::OsString,
        path::PathBuf,
        sync::atomic::{AtomicU64, Ordering},
    };

    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
    use clap::Parser;
    use stella_crypto::{derive_controller_id, IdentitySeed, IdentitySigningKey};
    use stella_server::{
        config::ServerConfig,
        identity::create_controller_identity,
        store::{AuthorityStore, NodeRecord},
    };

    use super::{execute, Cli};

    static TEMP_SEQUENCE: AtomicU64 = AtomicU64::new(1);

    struct Fixture {
        directory: PathBuf,
        config: PathBuf,
        node_id: stella_common::NodeId,
    }

    impl Fixture {
        fn new(seed: u8) -> Self {
            let sequence = TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed);
            let directory = std::env::temp_dir().join(format!(
                "stella-server-cli-{}-{sequence}",
                std::process::id()
            ));
            std::fs::create_dir(&directory).expect("create fixture directory");
            std::fs::create_dir(directory.join("state")).expect("create state directory");
            std::fs::create_dir(directory.join("secrets")).expect("create secrets directory");
            let identity_path = directory.join("secrets/controller.pk8");
            let identity = create_controller_identity(&identity_path).expect("create identity");
            let controller_id = derive_controller_id(identity.public_key());
            drop(identity);
            let database_path = directory.join("state/controller.redb");
            let store =
                AuthorityStore::initialize(&database_path, controller_id).expect("create store");
            let signing = IdentitySigningKey::from_seed(&IdentitySeed::from_bytes([seed; 32]));
            let node = NodeRecord::new(signing.public_key(), "CLI node", 100).expect("valid node");
            let node_id = node.node_id();
            store.create_node(&node).expect("create node");
            drop(store);
            let config = directory.join("server.toml");
            std::fs::write(
                &config,
                "version = 1\nlisten = \"127.0.0.1:44900\"\n\n[state]\ndatabase = \"state/controller.redb\"\n\n[identity]\ncontroller_key = \"secrets/controller.pk8\"\n\n[tls]\ncertificate = \"secrets/tls-cert.pem\"\nprivate_key = \"secrets/tls-key.pem\"\n",
            )
            .expect("write config");
            Self {
                directory,
                config,
                node_id,
            }
        }

        async fn command(&self, arguments: &[&str]) -> Vec<u8> {
            let mut argv = vec![OsString::from("stella-server")];
            argv.push(OsString::from("--config"));
            argv.push(self.config.as_os_str().to_owned());
            argv.extend(arguments.iter().map(OsString::from));
            let cli = Cli::try_parse_from(argv).expect("parse test command");
            let mut output = Vec::new();
            execute(cli, &mut output)
                .await
                .expect("execute test command");
            output
        }

        fn cleanup(self) {
            std::fs::remove_dir_all(self.directory).expect("remove fixture directory");
        }
    }

    #[test]
    fn command_tree_rejects_missing_required_identifiers() {
        assert!(Cli::try_parse_from(["stella-server", "network", "show"]).is_err());
        assert!(
            Cli::try_parse_from(["stella-server", "member", "add", "--network", "00"]).is_err()
        );
        assert!(Cli::try_parse_from(["stella-server", "state", "verify"]).is_ok());
    }

    #[tokio::test(flavor = "current_thread")]
    async fn init_command_creates_deployment_and_prints_public_trust_material() {
        let sequence = TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        let directory = std::env::temp_dir().join(format!(
            "stella-server-cli-init-{}-{sequence}",
            std::process::id()
        ));
        let config = directory.join("server.toml");
        let cli = Cli::try_parse_from([
            OsString::from("stella-server"),
            OsString::from("--config"),
            config.as_os_str().to_owned(),
            OsString::from("init"),
            OsString::from("--listen"),
            OsString::from("127.0.0.1:44902"),
            OsString::from("--tls-name"),
            OsString::from("controller.example.test"),
        ])
        .expect("parse init command");
        let mut output = Vec::new();
        execute(cli, &mut output)
            .await
            .expect("execute init command");
        let text = String::from_utf8(output).expect("UTF-8 init output");
        assert!(text.contains("controller_id="));
        assert!(text.contains("tls_spki_pin=sha256/"));
        assert!(text.contains("tls_not_after="));
        let loaded = ServerConfig::load(&config).expect("load generated configuration");
        assert_eq!(loaded.listen.to_string(), "127.0.0.1:44902");
        std::fs::remove_dir_all(directory).expect("remove init test directory");
    }

    #[tokio::test(flavor = "current_thread")]
    async fn network_member_node_and_state_commands_execute() {
        let fixture = Fixture::new(41);
        let network = "42424242424242424242424242424242";
        let node = fixture.node_id.to_string();
        assert_eq!(
            String::from_utf8(
                fixture
                    .command(&["network", "create", "--id", network, "--name", "CLI LAN"])
                    .await
            )
            .expect("UTF-8 output")
            .trim(),
            network
        );
        fixture
            .command(&["member", "add", "--network", network, "--node", &node])
            .await;
        fixture
            .command(&["member", "suspend", "--network", network, "--node", &node])
            .await;
        let shown = String::from_utf8(
            fixture
                .command(&["network", "show", "--network", network])
                .await,
        )
        .expect("UTF-8 output");
        assert!(shown.contains("status=suspended"));
        assert_eq!(
            String::from_utf8(fixture.command(&["node", "disable", "--node", &node]).await)
                .expect("UTF-8 output")
                .trim(),
            "changed"
        );
        let backup = fixture.directory.join("state/backup.redb");
        let backup_text = backup.to_string_lossy().into_owned();
        let backed_up = String::from_utf8(
            fixture
                .command(&["state", "backup", "--output", &backup_text])
                .await,
        )
        .expect("UTF-8 output");
        assert!(backed_up.starts_with("bytes="));
        assert_eq!(
            String::from_utf8(fixture.command(&["state", "verify"]).await)
                .expect("UTF-8 output")
                .trim(),
            "ok"
        );
        fixture.cleanup();
    }

    #[tokio::test(flavor = "current_thread")]
    async fn token_and_network_delete_outputs_are_canonical() {
        let fixture = Fixture::new(43);
        let network = "44444444444444444444444444444444";
        fixture
            .command(&["network", "create", "--id", network, "--name", "Token LAN"])
            .await;
        for arguments in [
            vec!["enrollment-token", "create", "--ttl-seconds", "60"],
            vec![
                "join-token",
                "create",
                "--network",
                network,
                "--ttl-seconds",
                "60",
            ],
        ] {
            let output = fixture.command(&arguments).await;
            let encoded = std::str::from_utf8(&output).expect("UTF-8 token").trim();
            assert!(!encoded.contains('='));
            assert_eq!(
                URL_SAFE_NO_PAD.decode(encoded).expect("decode token").len(),
                32
            );
        }
        assert_eq!(
            String::from_utf8(
                fixture
                    .command(&["network", "delete", "--network", network])
                    .await
            )
            .expect("UTF-8 output")
            .trim(),
            "deleted"
        );
        fixture.cleanup();
    }
}
