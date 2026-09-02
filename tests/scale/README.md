# Controller membership scale validation

This validation covers the control-plane state that every large Layer-2 room
depends on before real traffic can flow. It intentionally separates repeatable
capacity checks from host-, firewall-, and Internet-dependent performance
testing.

## Automated profiles

`crates/stella-server/tests/membership_scale.rs` runs two profiles:

- 32 online members, representing the normal upper range for a game room.
- 100 online members, representing Stella's bounded stress target.

Each profile uses a real redb authority database and a network whose signed
`max_flood_peers` equals the profile size. It creates deterministic Ed25519 node
identities, activates every membership, and publishes an online lease for every
node. For every receiving node, the test then:

1. reads one coherent authority view;
2. verifies that all other nodes appear exactly once and in canonical order;
3. signs and encodes the complete version 0.2 network state;
4. decodes the peer list and verifies the expected peer count; and
5. keeps each snapshot and the aggregate encoded work within explicit memory
   ceilings.

The 100-node profile therefore validates 100 complete receiver views containing
99 peers each, or 10,000 receiver/node relationships including each local node.
It also creates a 101st known node and verifies that membership admission fails
with `NetworkFull`, proving that the configured bound is enforced rather than
allowing unbounded growth.

`crates/stella-client/tests/relay_scale.rs` runs the same 32-node and 100-node
profiles against a live TURN UDP listener. It issues a distinct authenticated
credential per node, creates every allocation concurrently, verifies that every
client receives a unique relayed address, keeps all allocations live together,
and then deletes them cleanly. The listener limit equals the profile size, so a
distinct extra node must receive TURN status 486 rather than exceeding the
configured bound.

Run the profiles with metrics visible:

```powershell
cargo test -p stella-server --test membership_scale -- --nocapture
cargo test -p stella-client --test relay_scale -- --nocapture
```

## What this does not prove

This is not a 100-machine network benchmark. It does not claim Internet relay
throughput, TAP driver throughput, simultaneous ICE convergence, or game
compatibility under load. Those require a multi-host lab and controlled network
impairment. The automated profiles establish that controller persistence,
membership limits, signed peer snapshots, and protocol encodings remain
correct and bounded at the intended room sizes.
