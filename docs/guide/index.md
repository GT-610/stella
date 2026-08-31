# Project status

Stella is in active pre-standard development. Protocol version 0.1 and all
public APIs may change until the first interoperable draft is declared stable.

The version 0.1 protocol draft, core codecs, cryptography, UDP transport,
TAP-Windows access, and self-hosted controller control plane are implemented.
The remaining Windows reference path is being built and verified in this order:

1. Windows client control connection, reconnect, and state synchronization;
2. TAP and UDP data-plane integration with peer session establishment;
3. two-node Ethernet, ARP, broadcast, and IP connectivity tests.

Linux and macOS remain architectural requirements, but their device backends
are not part of the first functional milestone.

`stella-server` can initialize, administer, and run a controller deployment.
The client and integrated data plane are not complete, so Stella cannot yet
form a usable virtual LAN. Follow the repository history and this page for
milestone status rather than treating the controller milestone as a production
networking release.
