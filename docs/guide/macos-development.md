# macOS development setup

## Prerequisites

- a current macOS release with built-in feth, BPF, and AF_NDRV support;
- the repository's default stable Rust toolchain with Cargo;
- Bun for the VitePress site;
- Python 3 with `pip` for the real two-node verifier;
- root access for active TAP clients and real feth tests.

Pure Rust tests, configuration parsing, documentation, and release builds do
not require root. The active macOS data plane does: this milestone intentionally
does not install a kext, DriverKit extension, privileged helper, or daemon.

## Verify the workspace

Use the default stable toolchain. The workspace keeps `rust-version = "1.85"`
as its declared minimum, but normal development does not require installing a
separate 1.85 toolchain.

```sh
cargo fmt --all -- --check
cargo test --workspace --all-targets
cargo clippy --workspace --all-targets -- -D warnings
bun run docs:build
```

## Choose feth pairs

Allocate two unused, distinct numeric feth names per Stella network. For
example, node A can use `feth100` as the host-visible interface and `feth101`
as the Stella packet-I/O peer. Do not use a physical interface, assign an IP to
the peer, or share either name with another running Stella instance.

The pair is created when the active client first opens it. Normal shutdown puts
the visible side down but leaves both interfaces in place. The next start
reuses them, so an IP address configured on the visible side can survive client
restarts until the machine reboots or an administrator deletes the interfaces.

## Initialize and join a client

Initialize the controller and client as described by the server and client CLI
guides. The macOS join adds the required peer name:

```sh
target/debug/stella-client --config /path/to/client.toml join \
  --network <id> \
  --token <unpadded-base64url-token> \
  --enrollment-token <unpadded-base64url-token> \
  --tap-adapter feth100 \
  --tap-peer feth101
```

Run the active client as root:

```sh
sudo target/debug/stella-client --config /path/to/client.toml run
```

After the log reports `macOS data plane is active`, configure only the visible
interface, or run DHCP there:

```sh
sudo ifconfig feth100 inet 10.77.0.1 netmask 255.255.255.0 up
```

Stella carries Ethernet frames; it does not assign IP addresses or provide
DHCP. Every host in one virtual network needs a compatible address plan.

## Real-device verification

Compile the ignored platform test as the normal user, then run the resulting
binary as root so Cargo artifacts stay user-owned:

```sh
cargo test -p stella-tap --test macos_tap --no-run
sudo "$(find target/debug/deps -type f -name 'macos_tap-*' -perm -111 -print -quit)" \
  --ignored --nocapture
```

Run the full real-controller, real-client scenario with four unused names:

```sh
cargo build --release -p stella-server -p stella-client
sudo ./tests/two-node-lan/run-macos.sh \
  --skip-build \
  --python /opt/homebrew/bin/python3
```

The script refuses pre-existing selected names, verifies the first run and a
same-configuration restart, writes reports and process logs to a create-new
artifact directory, and deletes only the four interfaces it confirmed this run
could create.

For a manually managed pair, stop every owning client before deletion. Deleting
one side is an administrator action and discards the persistent interface and
its current-boot IP configuration:

```sh
sudo ifconfig feth101 destroy
sudo ifconfig feth100 destroy
```
