# Windows two-node LAN verification

This scenario runs a real controller and two `stella-client` processes on one
Windows host. Each client exclusively owns a different TAP-Windows adapter and
a different loopback UDP port.

Windows may short-circuit ordinary IP traffic when both destination addresses
belong to the same host. The verifier therefore uses Npcap and Scapy to inject
Ethernet frames into TAP A and capture them from TAP B, then repeats the reverse
direction. A captured frame must pass through the TAP reader, Stella peer
handshake and packet protection, loopback UDP, peer decryption, and the other
TAP writer.

## Prerequisites

- elevated PowerShell;
- two distinct TAP-Windows Adapter V9 devices;
- the Rust toolchain, Python with `pip`, and working network access;
- Npcap running with loopback-independent adapter capture support.

The script installs the pinned Scapy version into its create-new artifact
directory. It does not modify the repository, assign IP addresses, rename
adapters, or delete artifacts.

## Run

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

`summary.md`, `l2-report.json`, and process logs remain in the reported artifact
directory. Bearer tokens are cleared after join and are not written to those
reports or logs.
