# Project status

Stella is in active pre-standard development. Protocol version 0.1 and all
public APIs may change until the first interoperable draft is declared stable.

The version 0.1 protocol draft, core codecs, cryptography, UDP transport,
self-hosted controller, and native Windows and macOS client data planes are
implemented. Windows uses pre-installed TAP-Windows adapters. macOS uses
persistent built-in feth pairs, BPF receive, and AF_NDRV transmit through the
pinned `tun-rs` 2.8.8 release.

The Windows reference path has passed end-to-end verification on one host with
two distinct real TAP adapters, covering ARP, bidirectional IPv4 unicast, IPv4
broadcast and multicast, and LAN discovery. macOS has compiled root-only
lifecycle and equivalent two-node verification scenarios; a privileged run
report has not yet been committed. Linux remains an architectural requirement
without a reference TAP backend, so its build runs only the control plane.

`stella-server` and configured Windows or root-run macOS clients can form an
experimental virtual LAN. Windows needs one installed TAP-Windows adapter per
network; macOS needs one unused persistent feth pair per network. The controller
and at least one configured relay carrier must be reachable. Clients gather
direct UDP candidates automatically and fall back through TURN UDP, TCP, TLS,
and secure WebSocket; a manually forwarded client port is not required when a
relay succeeds. Stella does not allocate IP addresses or provide DHCP. Follow
the platform development and client CLI guides, and do not treat this milestone
as a production networking release.
