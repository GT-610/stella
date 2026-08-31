# Stella Windows one-TAP two-node verification

- UTC: 2026-08-31T06:36:27.9698201Z
- Git commit: `3e2fd3d31ffc1828f74155c84b62e7a3da7fc9da`
- Windows TAP node: `Local Area Connection` (`00-FF-0D-8E-CB-8C`)
- Headless Stella peer: `02-53-54-45-4C-42`
- Windows TAP IP MTU: 1340 bytes
- Controller: `127.0.0.1:44990`
- Result: PASS

- [x] ARP request A to B: Ethernet broadcast ARP request crossed from the Windows TAP to the headless peer
- [x] ARP reply B to A: Directed ARP reply crossed from the headless peer to the Windows TAP
- [x] IPv4 unicast A to B: Directed IPv4 payload crossed from the Windows TAP to the headless peer
- [x] IPv4 unicast B to A: Directed IPv4 payload crossed from the headless peer to the Windows TAP
- [x] IPv4 broadcast: IPv4 LAN broadcast reached the headless peer
- [x] IPv4 multicast: IPv4 multicast Ethernet frame reached the headless peer
- [x] Broadcast LAN discovery: Broadcast discovery query and directed response both crossed Stella

