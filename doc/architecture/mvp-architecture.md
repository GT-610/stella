# MVP Architecture

## 1. Purpose

This document turns the project definition and control-plane decision into a concrete first implementation target.

The MVP is not intended to prove full Layer 2 completeness.

It is intended to prove the project's main thesis:

- a TAP-backed Layer 2 virtual LAN can be exposed to games on Windows
- the project can preserve enough LAN behavior for real game discovery and joining
- the transport/control design can produce better practical game networking behavior than legacy Layer 2 overlays

## 2. MVP Scope

The MVP targets:

- two Windows hosts first
- OpenVPN `tap-windows6` as the Layer 2 interface
- one self-hosted controller
- peer-to-peer data forwarding when possible
- relay fallback when peer-to-peer is not possible
- enough Ethernet handling to support representative LAN game discovery and session join flows

The MVP does not target:

- full transparent Ethernet compatibility
- large multi-user mesh scaling
- full cross-platform support
- advanced ACL or enterprise policy features
- every multicast or legacy protocol family on day one

## 3. MVP Success Criteria

The MVP is successful if it can demonstrate all of the following:

- each host can attach to a TAP-backed virtual Ethernet interface
- both hosts can join the same virtual LAN through a self-hosted controller
- the nodes can establish a direct path when NAT conditions allow it
- the system can fall back to a relay when direct connectivity fails
- representative LAN discovery traffic can cross the overlay
- a representative game or test harness can discover and join a session
- packet flow and failure reasons are observable enough to debug

## 4. Top-Level System Model

The MVP has four primary components:

1. Controller
   - authoritative network state and coordination

2. Node agent
   - local service running on each endpoint

3. TAP interface adapter
   - reads and injects Ethernet frames on the host

4. Data transport engine
   - sends classified traffic to peers directly or via relay

At a high level:

- the controller defines who belongs to the network and helps peers find each other
- the node agent reads frames from TAP, classifies them, and forwards them over the overlay
- the transport engine tries direct peer paths first
- relay is used only when direct peer connectivity is unavailable

## 5. Component Responsibilities

### 5.1 Controller

The MVP controller is responsible for:

- network creation and network membership
- node identity registration
- node authorization into a virtual LAN
- distribution of network configuration
- exchange of peer endpoint candidates for NAT traversal
- relay assignment and relay metadata
- publication of basic compatibility and forwarding policy

The controller is not the default data path.

It should coordinate the network, not carry all traffic.

### 5.2 Node Agent

Each node agent is responsible for:

- owning the local TAP connection
- reading outbound Ethernet frames from TAP
- injecting inbound Ethernet frames into TAP
- classifying Ethernet traffic
- maintaining peer sessions
- maintaining a small local forwarding/cache state
- tracking current path status for direct and relay modes
- publishing diagnostics

### 5.3 Relay

For MVP, relay can be a simple role, even if implemented by the controller service or a closely related service.

The relay is responsible for:

- forwarding encrypted overlay packets between peers that cannot connect directly
- exposing enough metadata for nodes to measure relay viability

The relay is not responsible for:

- interpreting Layer 2 contents
- becoming the global mandatory forwarding hub

## 6. Data Model

The MVP needs a minimal but explicit control-plane data model.

### 6.1 Network

A network record should include:

- network ID
- network name
- owner or admin metadata
- membership policy
- relay policy
- basic forwarding policy
- version or revision number

### 6.2 Node Identity

A node record should include:

- node ID
- long-term public identity
- authorization status
- last-seen timestamp
- advertised endpoint candidates
- relay eligibility or assigned relay

### 6.3 Membership

A membership record should include:

- network ID
- node ID
- membership state
- issued configuration revision
- optional role flags

### 6.4 Session Coordination

For connection setup, nodes need:

- remote node ID
- remote endpoint candidates
- remote public key or session bootstrap data
- current path preference
- relay fallback metadata

## 7. Node Join Flow

The MVP join flow should be simple and explicit.

1. Node starts and loads or creates local identity
2. Node connects to controller
3. Node authenticates and requests network join
4. Controller checks membership and returns network configuration
5. Controller returns peer/session bootstrap metadata for current members
6. Node starts peer path establishment
7. Node activates TAP-backed participation in the virtual LAN

Important property:

- a node should not need the full network to be online before beginning operation

## 8. Initial Data Path

The MVP outbound path should look like this:

1. Frame arrives from TAP
2. Frame is parsed and classified
3. Forwarding decision is made
4. Frame is encapsulated into overlay transport
5. Packet is sent over direct peer path or relay path

The inbound path should look like this:

1. Overlay packet arrives
2. Transport/session checks are applied
3. Inner frame is decoded
4. Frame is accepted or dropped by policy
5. Frame is injected into TAP

## 9. First Packet Classes To Support

The MVP should intentionally start with a narrow but high-value set of traffic classes.

Priority classes:

- Ethernet broadcast
- ARP
- IPv4 unicast
- IPv4 UDP broadcast
- enough general UDP traffic to support representative game session traffic

Why these first:

- ARP and broadcast are core to LAN illusion
- IPv4 covers the dominant compatibility target for legacy and many current LAN games
- UDP broadcast is common for game discovery
- unicast IPv4 is required after discovery succeeds

Lower-priority or deferred classes:

- IPv6
- full multicast generality
- uncommon EtherTypes
- less common legacy discovery protocols unless demanded by testing
- fully transparent unknown traffic handling

## 10. Forwarding Behavior

The MVP forwarding model should be hybrid rather than fully transparent.

### 10.1 Broadcast

For MVP, Ethernet broadcast should be replicated to all active members of the virtual LAN, subject to simple safety controls.

Safety controls should include:

- burst protection
- counters
- visibility in logs

### 10.2 ARP

ARP should be forwarded correctly and visibly.

No special proxy behavior is required in the first version if plain forwarding works reliably enough, but ARP must be easy to observe and debug.

### 10.3 Unicast

IPv4 unicast should be delivered directly to the target peer when the target is known.

For MVP, the forwarding decision can rely primarily on control-plane membership information plus a simple local cache rather than a full dynamic distributed switch model.

### 10.4 Unknown Or Unsupported Traffic

Unsupported or currently unhandled traffic should:

- be counted
- be optionally logged
- default to safe drop or conservative handling depending on class

The key requirement is observability.

We must know what the MVP is failing to carry.

## 11. Transport Strategy

The MVP transport should be designed around game networking needs rather than generic tunnel semantics.

Initial transport principles:

- UDP-based transport
- encrypted node-to-node sessions
- direct peer connectivity preferred
- relay fallback when direct paths fail
- no TCP-style "everything reliable in order" assumption

The MVP does not need a sophisticated reliability stack yet, but it must not lock the project into a head-of-line-blocking design that will be hostile to games.

Important transport requirements for MVP:

- support path probing
- expose packet loss and latency measurement
- allow path switching between direct and relay
- keep packet framing suitable for future partial-reliability or FEC work

## 12. NAT Traversal Strategy

The MVP should use controller-assisted NAT traversal.

Basic process:

- nodes report endpoint candidates to controller
- controller exchanges candidate information between peers
- peers attempt direct path establishment
- on failure or timeout, nodes fall back to relay

The controller should maintain only the metadata needed for coordination, not per-packet forwarding state.

## 13. Relay Strategy

The MVP relay design should be intentionally simple.

Required behavior:

- at least one available relay path
- explicit path state: direct or relay
- path switching visible in diagnostics

Nice-to-have but not required in MVP:

- relay quality ranking
- multiple relay pools
- advanced regional selection

## 14. TAP Integration

For MVP on Windows:

- the node agent binds to an OpenVPN TAP adapter
- the adapter is treated as the local Ethernet interface for the virtual LAN
- the system reads raw Ethernet frames from TAP and injects inbound frames back into TAP

The TAP adapter is a compatibility interface.

It should not be treated as the source of product differentiation.

## 15. Local State On Each Node

Each node should persist or maintain at least:

- long-term identity
- controller endpoint configuration
- network membership cache
- peer session cache
- local forwarding diagnostics

This state should be sufficient for:

- reconnect after restart
- explaining why a path is direct or relayed
- explaining why a packet class was forwarded or dropped

## 16. Observability Requirements

The MVP must be observable from the start.

At minimum, we should expose:

- controller connection state
- network join state
- peer path state
- direct vs relay status
- packet counters by class
- broadcast and ARP counters
- dropped or unsupported frame counters
- recent session errors

Without this, debugging strange LAN-game behavior will be too slow.

## 17. Security Boundary For MVP

The MVP needs practical baseline security, even before advanced policy work.

Baseline expectations:

- each node has a stable cryptographic identity
- control-plane operations are authenticated
- data-plane sessions are encrypted
- only authorized members can join a virtual LAN
- relay cannot read inner plaintext frames

Advanced access control can wait, but membership and session authenticity cannot.

## 18. Recommended Implementation Order

The MVP should be built in this order:

1. controller and node identity bootstrap
2. TAP read/write integration on Windows
3. node join flow and network config delivery
4. peer session establishment
5. direct UDP transport
6. relay fallback
7. broadcast and ARP forwarding
8. IPv4 unicast forwarding
9. diagnostics and packet counters
10. representative game or harness validation

This order proves the architecture while keeping implementation risk contained.

## 19. First Validation Strategy

Before broad game testing, the MVP should validate against a small set of reproducible scenarios:

1. TAP loop test
   - verify frame capture and injection locally

2. two-node ARP test
   - verify address discovery across the overlay

3. two-node UDP broadcast discovery test
   - verify common LAN discovery behavior

4. two-node direct path test
   - verify peer-to-peer path establishment and frame delivery

5. two-node relay fallback test
   - verify degraded but functional connectivity when direct path fails

6. representative game or synthetic harness
   - verify discover, join, and basic session continuity

## 20. Known Risks

The MVP is likely to encounter these risks:

- TAP adapter installation and enumeration issues on Windows
- unexpected frame classes from real games
- broadcast replication creating noisy traffic under some titles
- NAT edge cases that require more traversal work than expected
- relay design becoming too coupled to controller implementation
- insufficient observability making game-specific failures hard to interpret

These risks are acceptable, but they should be tracked early.

## 21. Post-MVP Evolution

If MVP succeeds, the next stage should expand in these directions:

- richer packet-class coverage
- more complete Layer 2 behavior
- broader multicast handling
- better path quality adaptation
- improved relay strategy
- cross-platform support
- more advanced compatibility tuning for unusual LAN titles

## 22. Immediate Next Design Questions

After this MVP architecture, the next concrete documents should likely define:

1. controller API shape
2. node session and handshake model
3. overlay packet format
4. TAP adapter management details on Windows
5. diagnostics and trace format
