# Architecture Decision: Control Plane Model

## 1. Scope

This document records a foundational architecture decision for the project:

- Should the project use a centralized or decentralized control model?
- Why is this decision different for Layer 2 and Layer 3 overlays?
- What control/data-plane split best matches the project's goals?

This decision is foundational because it affects:

- identity and membership management
- peer discovery
- NAT traversal coordination
- relay assignment
- broadcast-domain definition
- observability and debugging
- future protocol and deployment shape

Changing this later would be expensive, so the decision should be made early and documented clearly.

## 2. Decision Summary

The project will use:

- a self-hosted centralized control plane
- a peer-to-peer-first data plane
- relay fallback when direct connectivity is not possible

The project will not use:

- a proprietary hosted centralized control plane
- a fully decentralized architecture as the primary model

In short:

**centralized control, distributed forwarding**

## 3. Why Proprietary Centralization Is Not Acceptable

The project is intended to be free and open source.

That rules out a product model where core network coordination depends on a proprietary hosted control service. A proprietary control service would conflict with the project's intended values and would undermine self-hosting, reproducibility, and community ownership.

Acceptable centralization for this project therefore means:

- open client
- open server
- open protocol
- self-hostable deployment
- no mandatory proprietary SaaS dependency

This is compatible with free/open source goals.

## 4. Why This Decision Is Harder To Change Later

Control-plane design is not a cosmetic detail. It defines how the system thinks.

Once implemented, it influences:

- how nodes authenticate and join a network
- how network membership is represented
- how peers learn about each other
- how broadcast domains are defined
- how direct paths and relays are chosen
- how packet replication policies are applied
- how logs, debugging, and operator workflows are structured

If the project starts with one model and later tries to switch to another, major parts of the system may need redesign rather than simple refactoring.

## 5. Why Layer 3 Can Be Either Centralized or Decentralized

Layer 3 overlays solve a narrower problem than Layer 2 overlays.

At Layer 3, the core problem is usually:

- give nodes virtual IP addresses
- make packets addressed to a destination IP reach the correct node
- establish routes or tunnels between participants

This is primarily an IP reachability problem.

The minimum functional unit is usually:

- identity
- endpoint discovery
- route mapping
- tunnel establishment

That structure can be implemented in different ways.

Centralized Layer 3 designs can provide:

- easier identity and key management
- simpler peer discovery
- better policy control
- centralized NAT traversal coordination
- better operational visibility

Decentralized Layer 3 designs can still work because the system only needs to answer:

**how do I deliver this IP packet to the right node?**

That question is often compatible with weaker global coordination. Nodes can discover each other, exchange metadata, and establish tunnels without maintaining a tightly shared global broadcast environment.

This is why both of the following are viable in Layer 3:

- centralized coordination
- decentralized coordination

## 6. Why Layer 2 Pushes Harder Toward Central Coordination

Layer 2 overlays are more demanding because they do not only provide reachability. They try to preserve Ethernet-like LAN semantics.

The system must deal with:

- broadcast handling
- ARP propagation
- unknown unicast behavior
- MAC-level visibility
- membership changes inside a shared virtual LAN
- packet flooding boundaries
- compatibility with unusual or undocumented discovery traffic

This means the system is not just solving:

**how do I reach node B?**

It is also solving:

**how do all nodes behave as if they are in the same virtual switched network?**

That creates stronger coordination pressure.

## 7. Why Full Decentralization Is Less Attractive For This Project

A fully decentralized Layer 2 architecture would increase complexity in areas that are not the project's main source of user-visible value.

Examples:

- membership view synchronization becomes harder
- broadcast replication and de-duplication become harder
- peer churn handling becomes harder
- NAT traversal coordination becomes harder
- relay assignment becomes harder
- debugging failures becomes harder

Those problems are real engineering work, but they do not directly make the game experience better in the way users most care about.

The project's differentiators are expected to be:

- better traversal
- lower loss and lower jitter behavior
- better relay fallback
- stronger game compatibility
- better diagnostics

Using a decentralized architecture as the primary model would consume significant engineering effort before these differentiators are proven.

## 8. Recommended Model For This Project

The recommended model is:

- centralized control plane
- peer-to-peer-first data plane
- relay fallback

This means:

- a controller manages identity, network membership, and coordination
- peers exchange data directly whenever possible
- relay paths are used only when required

This is not equivalent to "all traffic goes through the server".

Instead:

- the controller acts like the network coordinator
- the data plane remains distributed
- Layer 2 semantics are preserved at the edge
- performance-critical traffic can still use direct peer paths

## 9. Why This Model Fits A Layer 2 Game Overlay

This model is attractive because it simplifies the hard parts that benefit from a clear authority:

- who belongs to the virtual LAN
- which nodes should receive replicated broadcast traffic
- how peers exchange traversal candidates
- which relay should be used when direct connection fails
- how network-wide compatibility or safety policies are distributed

It also preserves the parts that matter most for player experience:

- direct connectivity when possible
- low-latency data paths
- better transport behavior than legacy Layer 2 overlays
- room for protocol-aware broadcast handling without redesigning the whole topology model

## 10. Conceptual Separation: Control Plane vs Data Plane

For this project, the split should be explicit.

Control plane responsibilities:

- identity
- membership
- virtual network definition
- session establishment
- NAT traversal coordination
- relay selection
- policy distribution
- observability hooks

Data plane responsibilities:

- frame delivery
- direct path selection
- relay path use when necessary
- retransmission or loss-handling strategy
- latency/jitter behavior
- broadcast replication execution
- packet classification and forwarding

This separation helps prevent confusion between:

- centralization for coordination
- centralization for packet forwarding

The former is recommended.
The latter is not the default design goal.

## 11. Comparison With Existing Product Directions

Examples in the current problem space illustrate the tradeoff:

- Tailscale shows that Layer 3 products can use centralized coordination to maximize usability and control
- EasyTier shows that Layer 3 products can also choose a decentralized model because Layer 3 overlays are fundamentally easier to distribute
- ZeroTier shows that Layer 2 semantics often pull the design toward a stronger coordinating component, even when the implementation details vary

The important conclusion is not that one architecture is always superior.

The important conclusion is:

- Layer 3 has more freedom to choose either model
- Layer 2 has stronger reasons to prefer centralized coordination

## 12. Decision

The project adopts the following architecture direction:

- self-hosted centralized control plane
- peer-to-peer-first data plane
- relay fallback for connectivity failures

The project explicitly does not adopt:

- mandatory proprietary hosted control
- full decentralization as the primary architecture

## 13. Consequences

Positive consequences:

- simpler network membership model
- clearer virtual LAN boundaries
- easier NAT traversal coordination
- easier relay coordination
- easier debugging and observability
- better fit for iterative Layer 2 compatibility work
- consistent with free/open source self-hosting goals

Tradeoffs:

- there is a control-plane dependency
- self-hosting and deployment must be designed carefully
- controller availability affects coordination workflows
- the system is not ideologically pure in a decentralization sense

These tradeoffs are acceptable because they reduce complexity in the parts of the system that are otherwise most likely to derail early progress.

## 14. Immediate Follow-Up

This decision should feed directly into the next architecture documents.

Next topics to define:

1. what the controller stores and coordinates
2. what the first peer-connection handshake looks like
3. how traversal candidates are exchanged
4. how relay fallback is selected
5. how broadcast-domain membership is represented for MVP
6. which packet classes are supported first in the Layer 2 forwarding path

## 15. Additional Rationale: Why A Central Authority Still Makes Sense

An additional practical reason for central coordination is that a virtual LAN still needs a stable authority for network state, even if packet forwarding itself is mostly peer-to-peer.

This authority is not the same thing as "a router through which all data must pass."

Its role is closer to:

- the keeper of network membership
- the source of truth for which nodes belong to which virtual LAN
- the coordinator of path establishment
- the maintainer of routing, forwarding, and policy metadata at the control-plane level

In a physical network, users often perceive the router as the "center" of the LAN, but in practice a healthy network is made of multiple cooperating roles:

- switches maintain Layer 2 forwarding state
- routers maintain Layer 3 reachability state
- central devices often anchor policy, authority, and network stability

Our project should mirror that separation.

The controller should maintain global or authoritative state such as:

- network definitions
- member identities and authorization
- endpoint candidates and path hints
- relay policy and relay assignment
- broadcast-domain membership
- compatibility and safety policy distribution

Each node should still maintain local fast-path state such as:

- active sessions
- path quality measurements
- local MAC learning or cache state
- transport reliability state
- currently selected direct or relay path

This is another reason the project should choose centralized control rather than full decentralization.

## 16. ZeroTier As A Reference Architecture

ZeroTier is worth studying because it is a mature commercial-grade Layer 2 overlay system with a long operational history.

We are not required to copy its design, but it offers strong clues about which responsibilities naturally belong to:

- globally coordinated infrastructure
- edge nodes
- persistent authority and identity systems

Important license boundary:

- ZeroTier's `nonfree` controller code may be read for architectural understanding
- it must not be reused, copied, or adapted into this project

We should treat it as a reference for system decomposition, not as implementation source material.

## 17. High-Level ZeroTier Model

From the publicly visible repository structure and documentation, ZeroTier can be understood as having three distinct layers of responsibility:

1. Root or upstream trust anchors
   - represented by the `planet` and optional `moon` world definitions
   - these provide stable network-wide anchor points and topology/bootstrap information

2. Network controllers
   - responsible for admitting members, issuing membership credentials, and returning network configuration

3. Ordinary nodes
   - join networks, fetch controller-defined configuration, maintain peer paths, and exchange most traffic peer-to-peer

This is a useful reminder that even in a peer-to-peer overlay, there may still be multiple kinds of "central" component with different jobs.

## 18. What ZeroTier's Controller Appears To Do

Based on the public documentation and open-source interfaces, ZeroTier's controller is responsible for:

- admitting or rejecting members
- issuing certificates of membership
- issuing default network configuration
- persisting controller-managed network and member data
- exposing an API for network administration

Evidence visible in the reference tree includes:

- the controller README explicitly says every virtual network has a network controller responsible for membership admission, certificates, and default configuration
- controller data is stored under `controller.d`
- controller APIs are served under `/controller`
- metrics track controller network and member counts
- joined nodes cache network config and certificate information under `networks.d`

This reinforces the same design lesson for our project:

- network membership and network definition should be authoritative
- ordinary nodes should not have to derive all virtual LAN state through decentralized gossip alone

## 19. What ZeroTier's Nodes Appear To Do

From the open node-side code and docs, ZeroTier nodes appear to be responsible for:

- generating and holding an identity
- joining a network by network ID
- contacting the controller associated with that network
- receiving network configuration and membership credentials
- caching peer identity and network information locally
- maintaining peer connectivity and forwarding data mostly peer-to-peer

There is a particularly interesting architectural clue in the open code:

- the controller address is derived from the network ID

This indicates that ZeroTier makes the controller relationship part of the network's identity model rather than treating it as an optional external lookup.

That is a strong example of the kind of early architecture choice that shapes the entire system.

## 20. Architectural Lessons We Can Take From ZeroTier

Without copying its implementation, there are several useful lessons:

1. Layer 2 overlays still benefit from an authority for network definition
   - ZeroTier does not rely on pure decentralization for network membership and policy

2. Membership should be explicit and credentialed
   - controller-issued membership artifacts are a practical way to gate virtual LAN participation

3. Nodes should cache enough state to keep operation efficient
   - peer identities, network configs, and topology hints should not require constant full re-discovery

4. Bootstrap and network control are separate concerns
   - root/bootstrap infrastructure and per-network controllers are related but not identical roles

5. Data traffic can remain mostly peer-to-peer even when control is centralized
   - the existence of a controller does not imply that all traffic must pass through it

## 21. Lessons We Should Not Overfit From ZeroTier

There are also areas where we should be cautious.

ZeroTier solves a broader and older problem space than ours. Our project is specifically targeting a game-oriented Layer 2 overlay, so we should avoid inheriting assumptions that do not directly help that mission.

Examples of things to avoid overfitting:

- reproducing ZeroTier's exact identity and network-ID coupling
- adopting all of its topology concepts if a simpler model works for game networks
- copying enterprise-oriented complexity before proving the game-oriented MVP
- copying any implementation details from the `nonfree` controller code

We should learn from the role separation, not from brand-specific protocol details.

## 22. What This Means For Our Architecture

The ZeroTier reference strengthens, rather than weakens, the current project direction.

For our project, the most reasonable interpretation is:

- we should keep a strong authoritative controller role
- we should keep ordinary nodes simple in their control responsibilities
- we should prefer direct peer data paths wherever possible
- we should keep relay as a fallback mechanism, not the default
- we should ensure the controller owns network membership, network definition, and path-coordination metadata

Where we may intentionally differ from ZeroTier:

- a more explicitly game-oriented transport strategy
- a simpler and more self-hosting-friendly control model
- a design centered on practical LAN compatibility and playability instead of broad enterprise SDN scope
