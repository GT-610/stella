# Two-node LAN verification

## Windows

This scenario runs a real controller and two `stella-client` processes on one
Windows host. Each client exclusively owns a different TAP-Windows adapter and
a different loopback UDP port.

Windows may short-circuit ordinary IP traffic when both destination addresses
belong to the same host. The verifier therefore uses Npcap and Scapy to inject
Ethernet frames into TAP A and capture them from TAP B, then repeats the reverse
direction. A captured frame must pass through the TAP reader, Stella peer
handshake and packet protection, loopback UDP, peer decryption, and the other
TAP writer.

### Prerequisites

- elevated PowerShell;
- two distinct TAP-Windows Adapter V9 devices;
- the Rust toolchain, Python with `pip`, and working network access;
- Npcap running with loopback-independent adapter capture support.

The script installs the pinned Scapy version into its create-new artifact
directory. It does not modify the repository, assign IP addresses, rename
adapters, or delete artifacts.

If the machine has only one TAP-Windows adapter, an elevated helper downloads
the official OpenVPN `tap-windows6` release, verifies Microsoft Authenticode
signatures on `devcon.exe` and the driver, creates one additional root device,
and renames the two selected adapters:

```powershell
.\tests\two-node-lan\install-second-tap.ps1
```

The default names are `Stella Node A` and `Stella Node B`. The helper makes a
system-level driver/device change and should be run only on a test machine.

### Run

```powershell
.\tests\two-node-lan\run.ps1 `
  -LeftAdapter 'Stella Node A' `
  -RightAdapter 'Stella Node B' `
  -Python 'C:\Path\To\python.exe'
```

The scenario verifies:

- ARP request broadcast from A to B;
- directed ARP reply from B to A;
- directed IPv4 payloads in both directions;
- IPv4 broadcast;
- IPv4 multicast;
- a broadcast LAN-discovery query and directed response.

Each check injects one frame only after capture is active. A pass requires exactly
one frame with the expected Ethernet, ARP or IPv4/UDP tuple, and payload; a marker
match alone is not sufficient.

`summary.md`, `l2-report.json`, and process logs remain in the reported artifact
directory. Bearer tokens are cleared after join and are not written to those
reports or logs.

### One-TAP verification mode

When installing a second Windows device is not possible, the non-elevated
fallback keeps node A on a real TAP-Windows adapter and runs node B through the
same public `NetworkDataPlane` implementation with a bounded loopback control
channel instead of a second TAP worker:

```powershell
.\tests\two-node-lan\run-one-tap.ps1 `
  -Adapter 'Local Area Connection' `
  -Python 'C:\Path\To\python.exe'
```

Npcap injects and captures every node-A frame on the real adapter. The headless
peer exposes only complete Ethernet-frame injection and delivery, so traffic
still crosses controller authentication, endpoint publication, the four-flight
peer handshake, authenticated UDP encapsulation, replay protection, switching,
and the production Windows TAP reader and writer. It runs the same ARP,
bidirectional IPv4, broadcast, multicast, and discovery checks as the two-TAP
scenario. This mode does not replace the separate two-device lifecycle check;
it isolates that administrator-only prerequisite from end-to-end protocol and
Windows data-path verification.

The committed two-device Windows run from 2026-08-31 is archived under
`reports/windows-two-tap-2026-08-31/` with every check passing. The earlier
one-TAP fallback run remains under `reports/windows-one-tap-2026-08-31/`.

## macOS

The macOS scenario runs the same real controller, two real clients, and Scapy
verifier against two persistent feth pairs. Each pair has one host-visible
interface used by Scapy and one packet-I/O peer owned by Stella.

Prerequisites:

- macOS with `/sbin/ifconfig` and `/usr/sbin/tcpdump`;
- a root shell, because feth, BPF, and AF_NDRV access are privileged;
- the default Rust stable toolchain and Python with `pip`;
- four unused numeric feth names.

Compile and run the root-only TAP lifecycle test from the repository root:

```sh
cargo test -p stella-tap --test macos_tap --no-run
sudo "$(find target/debug/deps -type f -name 'macos_tap-*' -perm -111 -print -quit)" \
  --ignored --nocapture
```

Then build with the normal user and run the full scenario:

```sh
cargo build --release -p stella-server -p stella-client
sudo ./tests/two-node-lan/run-macos.sh \
  --skip-build \
  --python /opt/homebrew/bin/python3
```

The defaults are `feth6100/feth6101` for node A and
`feth6102/feth6103` for node B. Use `--help` to override names, ports, or
the create-new artifact directory. When release binaries have already been
built as the current user, pass `--skip-build` to avoid rebuilding under the
root invocation.

The first run verifies ARP, directed IPv4 in both directions, broadcast,
multicast, and LAN discovery. The script then stops both clients, verifies that
both pairs still exist and both host-visible interfaces are down, starts the
same configurations again, and repeats the verifier as a reuse smoke test.

`summary.md`, `l2-report.json`, `l2-reuse-report.json`, and separate process
logs remain in the reported artifact directory. Before starting, the script
refuses any pre-existing selected interface. Its cleanup trap therefore
destroys only the four names that it first confirmed were absent and that this
run could have created.
