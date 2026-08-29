# Project status

Stella is in active pre-standard development. Protocol version 0.1 and all
public APIs may change until the first interoperable draft is declared stable.

The version 0.1 protocol draft and its architecture decisions are complete.
The implementation milestone builds and verifies the Windows reference path in
this order:

1. protocol specification and architecture decisions;
2. pure codecs, security, UDP transport, and TAP-Windows access;
3. self-hosted controller and Windows client;
4. two-node Ethernet, ARP, broadcast, and IP connectivity tests.

Linux and macOS remain architectural requirements, but their device backends
are not part of the first functional milestone.

No usable network can be created from the current Phase 1 workspace yet: the
Rust binaries remain compileable scaffolds while core codecs and platform code
are implemented next. Follow the repository history and this page for milestone
status rather than treating placeholder binaries as production software.
