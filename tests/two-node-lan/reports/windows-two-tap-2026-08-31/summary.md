# Stella Windows two-node LAN verification

- UTC: 2026-08-31T07:07:18.2760880Z
- Git commit: 7bcd4e5bc2a70acc5ab813b0f64112acfab1d588
- Left TAP: Stella Node A (00-FF-0D-8E-CB-8C)
- Right TAP: Stella Node B (00-FF-78-E9-28-83)
- Controller: 127.0.0.1:44990
- Result: PASS

- [x] ARP request A to B: Ethernet broadcast ARP request crossed the encrypted peer path
- [x] ARP reply B to A: Directed ARP reply crossed the reverse peer path
- [x] IPv4 unicast A to B: Directed IPv4 payload crossed from A to B
- [x] IPv4 unicast B to A: Directed IPv4 payload crossed from B to A
- [x] IPv4 broadcast: Limited LAN broadcast reached the other TAP
- [x] IPv4 multicast: IPv4 multicast Ethernet frame reached the other TAP
- [x] Broadcast LAN discovery: Broadcast discovery query and directed discovery response both crossed Stella
