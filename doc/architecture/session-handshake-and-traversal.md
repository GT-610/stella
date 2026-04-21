# Session Handshake And Traversal

## 1. Purpose

This document defines the MVP and near-term architecture for peer session establishment, NAT traversal, and relay fallback.

It exists to answer a critical design question:

- how should two nodes discover, attempt, establish, maintain, and switch transport paths underneath the virtual Layer 2 overlay?

This is the core performance layer of the project.

Layer 2 compatibility is exposed at the TAP edge, but the actual user experience depends heavily on the quality of this lower transport and traversal system.

## 2. Core Design Principle

The project should explicitly separate:

- Layer 2 emulation and forwarding semantics
- peer session establishment and transport path management

In other words:

- the upper layer makes the host believe it is attached to a LAN
- the lower layer is responsible for finding the best way to move frames between peers

This confirms the project's two-layer model:

- bottom layer: traversal and transport
- top layer: virtual Layer 2 networking

## 3. Key Observation About Existing Systems

ZeroTier is useful here because it demonstrates that a Layer 2 virtual network can be built on top of a lower peer-to-peer transport/traversal substrate.

Architecturally, this is close to:

- bottom layer: encrypted peer path establishment, direct paths, relay fallback
- top layer: virtual Ethernet/L2 behavior

However, the project should not assume that ZeroTier's transport choices are the final answer for a game-focused system.

Also, a useful nuance from the public reference tree:

- ZeroTier is not purely "UDP or nothing"
- the public service settings and code expose `allowTcpFallbackRelay`, relay policy, direct-path negotiation, and path/bond management

So the more accurate lesson is:

- ZeroTier is primarily direct-path/UDP-oriented
- it still has explicit relay and path fallback mechanisms

That is a good architectural model even if we choose different protocol details.

## 4. Why Traversal Must Be Designed First

For this project, the traversal layer is a first-class subsystem because:

- poor direct-path success makes the overlay feel unreliable
- poor relay fallback makes the overlay feel slow
- poor path switching causes packet spikes or session instability
- all Layer 2 compatibility work becomes less valuable if transport quality is weak

This means the project should not begin with a naive:

- encapsulate Ethernet frame into UDP
- send to peer
- hope for the best

Instead, the transport layer must intentionally manage:

- candidate discovery
- NAT characterization
- direct-path establishment
- keepalive and path lifetime
- relay fallback
- path quality measurement
- path switching rules

## 5. Reference Lessons From Existing Projects

### 5.1 Tailscale

From the reference tree, Tailscale clearly separates:

- STUN and endpoint discovery
- control-plane coordination
- encrypted peer discovery messages
- DERP relay fallback
- home relay / preferred relay selection
- local port mapping support through UPnP and related mechanisms

Useful lesson:

- a strong transport system is not just "do hole punching"
- it is a coordinated system combining endpoint discovery, active probing, relay fallback, and path quality management

### 5.2 EasyTier

From the reference tree and README, EasyTier shows several useful ideas:

- automatic NAT traversal with P2P preference
- relay fallback when P2P fails
- explicit STUN information collection
- support for lazy P2P
- configurable P2P-only / disable-P2P / need-P2P behavior
- relay transport variation including QUIC and KCP options
- explicit UDP hole-punch packet flow in the connector and UDP tunnel code

Useful lesson:

- path establishment can be policy-driven
- not every peer link must be established eagerly
- on-demand or lazy direct-path warm-up can reduce unnecessary mesh overhead

### 5.3 ZeroTier

From the public portions of the reference tree, ZeroTier shows:

- direct-path negotiation and rendezvous logic
- active path tracking
- relay use through upstream or preferred relay nodes
- explicit path metrics and path selection concepts
- optional TCP fallback relay
- richer path management through bonding/multipath logic

Useful lesson:

- a peer may have multiple candidate paths
- the system should remember, validate, score, and rotate paths over time

## 6. MVP Traversal Goal

The MVP traversal layer should prove the following:

- two nodes can establish a direct encrypted path when possible
- two nodes can use a relay when direct connection is not possible
- the system can switch between path states in a visible and controlled way
- the Layer 2 overlay above this transport does not need to care whether the current path is direct or relayed

This is important:

- the Layer 2 forwarding layer should consume a stable session abstraction
- it should not need custom logic for every NAT/traversal edge case

## 7. Recommended MVP Transport Model

The MVP should use:

- UDP as the primary peer data transport
- controller-assisted endpoint exchange
- encrypted peer session establishment
- relay fallback
- persistent path health tracking

The MVP should not initially depend on:

- TCP as a normal peer data path
- always-in-order reliable transport for all traffic
- a fully general QUIC-based data plane from day one

Reason:

- game traffic usually benefits from low-latency datagram behavior
- L2 encapsulation on top of a strict ordered stream would create avoidable head-of-line blocking risk

## 8. Recommended MVP Session States

Each peer relationship should have explicit state.

Suggested states:

1. `discovered`
   - peer known through controller

2. `candidates_ready`
   - endpoint candidates and bootstrap metadata available

3. `probing`
   - direct-path establishment in progress

4. `direct_active`
   - direct UDP path is active and preferred

5. `relay_active`
   - relay path is active because direct path failed or is unavailable

6. `degraded`
   - path exists but health is poor

7. `reprobing`
   - relay is active while direct path is retried in background

These states should be visible in diagnostics.

## 9. Endpoint Candidate Model

Each node should report a set of endpoint candidates to the controller.

For MVP, candidates should include:

- observed public UDP endpoint from STUN
- local interface candidates where appropriate
- mapped endpoint if available through local port mapping
- relay reachability metadata

The controller should exchange candidate sets between peers that belong to the same virtual LAN and are allowed to connect.

## 10. NAT Characterization

The MVP should perform lightweight NAT characterization.

It does not need a perfect taxonomy, but it should know enough to guide strategy.

Useful categories for MVP:

- directly reachable or public
- likely cone-friendly
- likely port-restricted
- likely symmetric or difficult
- unknown

Why this matters:

- the probing schedule should not be identical for all peers
- relay fallback should happen faster for obviously difficult NAT combinations

EasyTier's use of STUN info and NAT-type reporting is a strong signal that this is worth doing early.

## 11. Local Port Mapping

The MVP should consider local port mapping support as part of traversal, not as an optional afterthought.

Recommended support:

- UPnP
- NAT-PMP or PCP later if needed

Why:

- direct reachability improves hole-punch success and path stability
- the benefit is especially high for home-network gaming scenarios

Tailscale's separate `portmapper` subsystem is a useful example of treating this as a dedicated capability.

## 12. Basic Handshake Flow

Recommended initial peer establishment flow:

1. Node A and Node B join the same network through the controller
2. Controller gives each node the other's identity and endpoint candidates
3. Both nodes enter `probing`
4. Both nodes send authenticated UDP probe packets to all promising candidate endpoints
5. If a valid response is received, a direct session is established
6. If no direct path succeeds within policy limits, nodes activate relay mode
7. While on relay, nodes may continue low-rate background direct probing

Important property:

- direct path establishment should be symmetric whenever possible
- both peers should transmit during the punch window, not just one side

## 13. Probe Packet Design

Probe traffic should be its own protocol, separate from normal data packets.

Probe packets should support:

- node identity binding
- anti-spoofing or integrity verification
- session bootstrap linkage
- endpoint confirmation
- optional path challenge/response

The probe protocol should also allow:

- repeated low-cost retries
- logging of which candidate succeeded
- future extensions for path scoring

Tailscale's separation of discovery messages from normal transport traffic is a good conceptual model here.

## 14. Direct Path Selection

Once multiple candidate direct paths exist, the node should choose one preferred path.

For MVP, preferred path selection can be based on:

- first successful path, then
- lowest recent RTT
- recent packet loss
- path stability

The system should remember alternate viable paths for failover or reevaluation.

ZeroTier's exposed path and bond metrics suggest this kind of path memory is worthwhile even if our first version is simpler.

## 15. Relay Design Requirements

The relay path should be treated as a real product feature, not an embarrassing fallback.

For MVP, relay should:

- work reliably when direct connectivity fails
- preserve end-to-end encryption of payloads
- expose RTT and packet counters
- support bidirectional session traffic for Layer 2 encapsulated frames

Relay should not:

- terminate or inspect inner Layer 2 payloads
- become mandatory for ordinary traffic in the common case

## 16. Relay Transport Choice

For MVP, relay can be implemented using one of these practical models:

- UDP relay
- reliable-over-UDP relay
- HTTPS/WebSocket-like relay later if censorship or firewall traversal becomes a stronger goal

Recommendation for MVP:

- start with UDP-capable relay first

Reason:

- it matches the primary transport model
- it keeps latency overhead lower
- it avoids prematurely pulling the whole data plane toward TCP-like behavior

However, the architecture should leave room for a later "hard fallback" relay over TCP or HTTPS if needed.

This is one area where ZeroTier's `allowTcpFallbackRelay` and Tailscale's DERP-over-HTTP ideas are informative.

## 17. Lazy P2P vs Eager P2P

The project should decide early whether all peer links are established immediately or on demand.

Recommended MVP choice:

- eager for two-node and very small-network MVP
- design the state machine so lazy P2P can be added later

Reason:

- eager setup is simpler and easier to debug for MVP
- lazy setup becomes more valuable once the network has more peers and relay cost matters more

EasyTier's `lazy_p2p` concept is useful inspiration for the post-MVP stage.

## 18. Path Maintenance

After a direct path is established, nodes should maintain it actively enough to survive typical NAT expiry.

Minimum requirements:

- periodic keepalive
- RTT sampling
- direct-path idle timeout handling
- transition to `degraded` when path health drops
- background reprobe when on relay

The system should avoid oscillating too aggressively between direct and relay.

## 19. Path Switching Rules

The project needs clear path switching rules from the start.

Recommended MVP rules:

- prefer direct over relay if direct is healthy
- switch from direct to relay when direct is clearly dead or badly degraded
- do not switch back to direct until the direct path passes a simple stability check
- record why a switch happened

This prevents flapping and makes debugging practical.

## 20. Relationship To Layer 2

The Layer 2 layer should not need to know about NAT traversal details.

Its contract should simply be:

- send frame to peer session
- receive frame from peer session

The session subsystem should hide whether the underlying path is:

- direct UDP
- relay UDP
- future fallback transport

This modularity is crucial.

If traversal details leak upward into the L2 forwarding logic, the project will become hard to evolve.

## 21. Observability Requirements

The traversal subsystem must be highly observable.

At minimum, expose:

- local NAT characterization
- public endpoint candidates
- local port-mapping status
- peer session state
- last direct probe result
- last successful direct path
- relay activation reason
- current path RTT
- packet loss estimate if available
- path switch history

This is essential for debugging game-specific complaints.

## 22. MVP Recommendation Summary

The recommended MVP traversal architecture is:

- controller-assisted peer metadata exchange
- STUN-based endpoint discovery
- optional local port mapping support
- authenticated UDP probe protocol
- direct UDP session preferred
- UDP relay fallback
- background reprobe while relayed
- explicit path state machine

This gives the project a stronger foundation than a pure "UDP blind punch and hope" design.

## 23. Post-MVP Opportunities

After MVP, likely improvements include:

- more advanced NAT heuristics
- multiple relay classes
- region-aware relay selection
- better path scoring
- partial reliability or FEC
- optional TCP/HTTPS hard fallback relay
- lazy direct-path establishment for larger networks
- multipath or bond-style path aggregation for special cases

## 24. Immediate Next Design Questions

After this document, the next low-level design work should define:

1. exact probe packet format
2. controller API for candidate exchange
3. relay packet envelope
4. identity and key usage for session establishment
5. path health metrics and switch thresholds
