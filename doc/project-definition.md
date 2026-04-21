# Project Definition

## 1. Problem Statement

Many LAN games assume that all peers are connected to the same Layer 2 Ethernet segment. They may rely on one or more of the following behaviors:

- Ethernet broadcast semantics
- ARP-based address discovery
- IPv4 UDP broadcast discovery
- NetBIOS or other legacy local-discovery traffic
- Proprietary or undocumented LAN discovery packets

Existing consumer overlay solutions usually split into two categories:

- Layer 2 overlays can preserve LAN compatibility better, but may have weaker NAT traversal, higher packet loss, and worse latency under real-world network conditions
- Layer 3 overlays often have better NAT traversal and transport behavior, but fail for games that require true or near-true LAN broadcast behavior

The project exists to bridge that gap: provide a game-oriented overlay network that can eventually expose near-complete Layer 2 behavior to the operating system and games, while using a stronger transport design underneath to improve stability, latency, and packet loss performance.

## 2. Vision

Build a free and open source game-oriented virtual LAN system that:

- Presents itself as a Layer 2 Ethernet-style network to applications
- Targets high compatibility with LAN games, including unusual or undocumented discovery behavior
- Uses a modern user-space transport and coordination design to outperform traditional Layer 2 overlays in practical game networking conditions
- Prioritizes low friction, stability, and strong real-world playability over enterprise VPN features

## 3. Core Principles

- Layer 2 is the compatibility interface, not the main product differentiator
- Transport quality is the main source of user-visible value
- The architecture must support an eventual full-L2 goal without forcing full transparency in the first milestone
- Mature open components should be reused when they remove undifferentiated engineering work
- The project should remain friendly to free/open source distribution and collaboration
- Game experience matters more than theoretical elegance

## 4. Platform Assumptions

Initial platform target:

- Windows

Current Windows Layer 2 interface strategy:

- Reuse OpenVPN `tap-windows6` as the TAP device provider

Rationale:

- It provides a stable and widely deployed Windows TAP implementation
- It avoids the cost and maintenance burden of a custom signed Windows virtual NIC driver
- It lets the project focus on user-space forwarding, traversal, relay, and transport quality
- It is compatible with the project's free/open source direction

Non-goal for the near term:

- Developing and maintaining a custom Windows TAP/NDIS driver

## 5. Target Users

Primary users:

- Players who want to run old or modern LAN games over the Internet
- Users whose games depend on broadcast or other Layer 2 or near-Layer 2 discovery behavior
- Users who find existing Layer 3 overlays incompatible and existing Layer 2 overlays unreliable

Secondary users:

- Small groups of friends hosting ad-hoc private game sessions
- Open source contributors interested in practical virtual networking for games

## 6. Product Goals

The project should eventually provide:

- A virtual Layer 2 network environment suitable for LAN game discovery and play
- Better NAT traversal success and path quality than typical legacy Layer 2 gaming overlays
- Reliable fallback behavior when direct peer-to-peer connectivity is not possible
- Good enough observability to diagnose why a given game or packet flow does not work
- An architecture that can evolve from common-case compatibility toward more complete Layer 2 behavior

## 7. Non-Goals

The project is not initially trying to be:

- A general enterprise VPN
- A zero-trust corporate access platform
- A self-developed Windows driver project
- A hyper-optimized general-purpose Ethernet bridge for every operating system on day one
- A product that guarantees full compatibility with every LAN game in the first release

The project is also not assuming:

- That all traffic should be forwarded transparently from day one
- That every protocol deserves identical forwarding priority
- That transport design can be deferred until after Layer 2 forwarding is complete

## 8. Architecture Direction

The system should be designed in layers:

1. Layer 2 Interface Layer
   - Receives and injects Ethernet frames through the TAP device
   - Makes the host OS and games believe they are attached to an Ethernet-like LAN

2. Layer 2 Processing Layer
   - Parses, classifies, forwards, floods, filters, and observes Ethernet frames
   - Handles broadcast, ARP, unknown traffic, and compatibility policies

3. Data Transport Layer
   - Carries frame payloads between peers or via relays
   - Responsible for path quality, packet loss behavior, latency, jitter, congestion behavior, and fallback logic

4. Coordination / Control Plane
   - Identity, peer discovery, session establishment, NAT traversal coordination, relay selection, and membership state

5. Diagnostics / Compatibility Layer
   - Logging, packet counters, protocol visibility, game compatibility switches, safety limits, and operator insight

This layered model is important:

- TAP solves interface semantics
- The project itself must solve transport and compatibility quality

## 9. End-State Goal vs Milestone Strategy

End-state goal:

- Support a near-complete Layer 2 overlay suitable for a wide range of LAN games, including ones with unusual discovery behavior

Milestone strategy:

- Start with common and high-value traffic patterns first
- Avoid prematurely promising perfect transparent Ethernet behavior
- Preserve an architecture that can incrementally move toward a more complete L2 model

Early forwarding priorities are expected to include:

- Ethernet broadcast handling
- ARP
- IPv4 traffic
- Common UDP-based LAN discovery traffic
- Enough compatibility behavior to let representative games discover and join sessions

Later work may include:

- Broader frame-type coverage
- Smarter unknown unicast handling
- More complete multicast strategy
- Better protection against broadcast storms or pathological traffic
- Per-game compatibility tuning informed by observation rather than hardcoding first

## 10. Why This Project Can Win

The project does not need to win by owning the TAP driver.

It can win by being better at:

- NAT traversal success
- Relay fallback quality
- Loss tolerance
- Latency and jitter behavior
- Broadcast handling strategy
- Diagnostics and compatibility iteration
- Being designed specifically for LAN game scenarios instead of generic secure networking

## 11. MVP Definition

The first meaningful MVP should prove the project thesis, not full protocol completeness.

MVP target:

- Two Windows hosts
- OpenVPN TAP installed and usable on both sides
- A working virtual LAN session over the Internet
- Successful peer connectivity through direct connection when possible, with relay fallback when needed
- Correct enough forwarding for representative LAN discovery and session join behavior
- Stable enough play quality to compare favorably against ZeroTier in targeted game scenarios

MVP success indicators:

- The system can create and use a TAP-backed virtual Ethernet interface
- Peers can exchange required LAN discovery traffic for at least a small set of representative games or test harnesses
- A game session can be discovered and joined across the overlay
- Runtime behavior is observable enough to debug failures
- The design remains extensible toward more complete Layer 2 support

## 12. Technical Questions To Answer Next

The project-definition stage should immediately lead into a short list of next questions:

1. Which exact Layer 2 and Layer 3 frame classes belong in the first forwarding set?
2. What transport model best fits game traffic: raw UDP with custom reliability features, QUIC datagrams, or another design?
3. How should the control plane coordinate peer discovery, NAT traversal, and relay use?
4. What observability is required so users and developers can understand why a game does or does not work?
5. Which behaviors from existing tools are worth studying from EasyTier, Tailscale, and ZeroTier, and which are out of scope due to licensing or architecture?

## 13. Immediate Next Step

After this document, the next artifact should be a focused architecture note that turns the project definition into a concrete MVP plan.

Recommended next document:

- `doc/architecture/mvp-architecture.md`

That document should define:

- The first supported packet classes
- The first-hop data path
- Initial control-plane assumptions
- The first relay/direct-connect strategy
- What will be tested before adding broader Layer 2 completeness
