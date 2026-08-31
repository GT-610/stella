# Project status

Stella is in active pre-standard development. Protocol version 0.1 and all
public APIs may change until the first interoperable draft is declared stable.

The version 0.1 protocol draft, core codecs, cryptography, UDP transport,
TAP-Windows access, self-hosted controller control plane, and Windows client
data plane are implemented. The Windows reference path has passed end-to-end
verification on one Windows host with two distinct real TAP adapters, covering
ARP, bidirectional IPv4 unicast, IPv4 broadcast and multicast, and LAN
discovery.

Linux and macOS remain architectural requirements, but their device backends
are not part of the first functional milestone.

`stella-server` and configured Windows clients can form an experimental virtual
LAN. Each client needs an installed TAP-Windows adapter and a reachable
published UDP endpoint; the controller needs reachable TLS/TCP service. Stella
does not allocate IP addresses or provide DHCP. Follow the Windows deployment
and client CLI guides for setup, and do not treat this milestone as a production
networking release.
