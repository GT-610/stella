# Protocol and runtime audit (September 2026)

This change set fixes cancelled stream reads, preserves healthy sessions across
relay and connectivity updates, and enforces handshake and receive-flood budgets.
Wire layouts, signature inputs, key derivation, version negotiation, CLI options,
configuration and stored database schemas remain compatible. No reference-project
code, including ZeroTier nonfree code, was incorporated.

## Completed batches

| Batch | Implementation and verification |
| --- | --- |
| Baseline and API cleanup | LF attributes; removed unused exported wrappers, accessors and duplicate cached fields after tracing production callers, platform code and examples. Tests use retained production entry points. |
| Cancellation safety | Control and TURN readers retain prefix/body offsets; the controller retains a split TLS reader across refreshes. Regression tests interrupt every byte boundary and verify the next record. Length/EOF rules remain unchanged. |
| Relay lifecycle | Unchanged endpoint paths retain IDs. Withdrawal removes only affected sessions and receive-only retired state. Tests cover established direct traffic, established TURN traffic, generation refresh, unrelated carrier changes, repeated notifications, direct upgrade and old-session deadlines. |
| Security | Bounded endpoint/node/network admission precedes expensive handshake operations; cached responses share that budget. INIT authentication produces a private validated value. Independent per-peer receive flood buckets run before MAC learning and TAP delivery. |
| Data and query paths | Maintained forwarding eligibility avoids constructing a complete set per frame. Packet construction uses the final buffer and unfragmented reception returns its owned plaintext. Network snapshot endpoint queries use a composite-key range in the existing read transaction. |
| Shared code and tests | Protected identity persistence moved to `stella-file-security`; duplicate native tests consolidated there. Codec tests traverse lazy iterators and mutate valid confirmations. Reassembly capacity and complete signed/AEAD vectors extend behavioral coverage. macOS joins the normal CI matrix. |
| Protocol and delivery | English normative sources and generated pages, Chinese explanations, missing Chinese ADRs, interoperability fixture documentation and this audit report are synchronized. |

Necessary fixtures, deterministic crypto inputs, mocks and assertion helpers
remain under tests. They do not provide alternative production implementations.
Native identity creation/loading retains size limits, file-type and permission
checks, failure cleanup and secret zeroization. Client/server public entry names
and error variant categories remain; shared error messages now say “identity”
instead of the component name.

## Removed Rust APIs

No empty compatibility shims replace these APIs. Rust library consumers may need
source changes; this does not change network or persisted formats.

| Component | Removed APIs |
| --- | --- |
| Client runtime | `ClientDataRuntime::local_udp_addresses`; `NetworkDataPlane::accept_udp_datagram` (use `accept_datagram`); `NetworkOutput::{datagrams,tap_frame}` (use `into_parts`); `IceOutput::{transmissions,nominations,failures,into_parts}` (use `into_all_parts`) |
| Client handshake/state | `ResponderHandshake::{respond,into_established}`; `PeerState::grant_bytes`; `SpkiPin::digest` |
| Crypto/common/transport | `IdentitySigningKey::export_seed`; `MacAddress::is_locally_administered`; `Endpoint::as_turn_udp`; `TurnStream::max_record_size` |
| Codec | `ControlFieldRef::raw_type`; `ControlMessageView::body`; `ExtensionRef::extension_type`; `SessionInitView::initiator_nonce`; `SessionResponseView::responder_nonce`; free functions `encode_control_fields` and `encode_extensions` |
| Server | `verify_controller_identity_permissions`; `AuthorityHandle::{max_queue_capacity,remaining_queue_capacity}`; `MembershipRecord::joined_at`; `EndpointLeaseRecord::updated_at`; `ConnectivityAuthorityRecord::encoded_generation` |
| TAP | `MacosTapProxyDevice::create_with_socket`; `WindowsTapDevice::installed_adapters`; `WindowsTapRemoval::removed` |

Codec tests still exercise the internal offset encoders used by complete message
encoding. Nonce validation remains in decoding even though unused view fields
were removed. Device removal remains idempotent. Public constants and error
branches required by platform, trait or protocol contracts were retained.

## Performance measurements

Windows x86-64, Rust 1.98.1, Cargo `release` optimized profile. Each series has
five sequential samples; times below are microseconds for the entire sample,
not per-frame latency. No concurrent benchmark processes were used. The packet
benchmark runs 10,000 encrypted protect/receive round trips; payload sizes are
64 or 1,400 bytes, with MTU 1,500 or 220. Switching measures 100,000 decisions
with 100 peers, including baseline eligible-set construction. The maintained-set
version builds the set before timing, matching the runtime cache. Membership
updates, sockets, TAP I/O and application throughput are outside this measurement.
Snapshot timing includes 1,000 views over eight networks with 32 nodes each;
setup is excluded. These are local microbenchmarks, not throughput guarantees.

Baseline packet/switch revision: `7c6b503`. Cache change: `5584ed8`; packet buffer
change: `33b6bba`. Snapshot benchmark baseline: `9b111b1`; range change: `3a85357`.

| Initial series | Baseline samples | Changed samples | Median before → after |
| --- | --- | --- | --- |
| Packet 64 / MTU 1500 | 55612, 49214, 48989, 50931, 49539 | 49329, 46920, 43490, 43661, 47123 | 49539 → 46920 |
| Packet 1400 / MTU 1500 | 120396, 122568, 134208, 124495, 120796 | 117116, 114580, 138688, 130084, 151922 | 122568 → 130084 |
| Packet 1400 / MTU 220 | 684596, 703352, 684447, 664708, 653612 | 651672, 690214, 739525, 659838, 657121 | 684447 → 659838 |
| Known unicast | 288548, 297168, 272932, 299643, 277072 | 5894, 10068, 5837, 5871, 9617 | 288548 → 5894 |
| Broadcast selection | 293642, 305547, 303717, 310618, 321398 | 30353, 29286, 26641, 27368, 25910 | 305547 → 27368 |
| Network snapshot | 323273, 307261, 328490, 325854, 314050 | 282120, 280000, 285855, 269203, 306879 | 323273 → 282120 |

The initial large unfragmented packet series was slower. Two additional serial
comparisons used a detached baseline checkout and the final implementation's
release test binary, running changed then baseline. Raw samples are retained to
avoid hiding this uncertainty:

| Repeat | Baseline samples | Changed samples | Median before → after |
| --- | --- | --- | --- |
| A: 64 / 1500 | 51934, 50300, 49484, 49745, 49706 | 46369, 57695, 44549, 47733, 43258 | 49745 → 46369 |
| A: 1400 / 1500 | 123138, 122810, 134843, 122632, 138575 | 131536, 120001, 118459, 109694, 110270 | 123138 → 118459 |
| A: 1400 / 220 | 679931, 677107, 657718, 713154, 676963 | 619871, 621465, 633182, 637401, 646456 | 677107 → 633182 |
| B: 64 / 1500 | 42955, 42294, 44089, 43516, 42254 | 39420, 39059, 38933, 42533, 38875 | 42955 → 39059 |
| B: 1400 / 1500 | 150258, 128376, 120660, 117367, 138258 | 113512, 119471, 122794, 121885, 126077 | 128376 → 121885 |
| B: 1400 / 220 | 682322, 665592, 655087, 665571, 699214 | 667502, 631696, 693955, 692332, 659268 | 665592 → 667502 |

The small-packet improvement repeats across all series. Larger and fragmented
packet results overlap and vary; no stable speedup is claimed for those cases.
The buffer change is retained for the repeatable small-packet gain and simpler
ownership, with byte-for-byte fixture and full correctness tests passing.
The snapshot median improved about 12.7% in its measured setup. Switching gains
apply to recipient selection with the old per-frame set construction included,
not to end-to-end encrypted broadcast throughput.

Reproduce the ignored measurement tests explicitly:

```sh
cargo test -p stella-client --release --lib benchmark_packet_round_trips -- --ignored --nocapture
cargo test -p stella-client --release --lib benchmark_switch_forwarding -- --ignored --nocapture
cargo test -p stella-server --release --lib benchmark_network_session_views -- --ignored --nocapture
```

## Verification scope

Local Windows checks include formatting, locked workspace tests and Clippy,
documentation synchronization/build and independent Python vector verification.
The two privileged Windows TAP tests were explicitly executed with administrator
rights and passed (lifecycle/I/O/cancellation and provision/reuse/open/remove);
their ignored status in the normal workspace run is not counted as execution.

```sh
cargo fmt --all -- --check
cargo test --workspace --all-targets --locked
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo test -p stella-tap --test windows_tap -- --ignored --test-threads=1
bun run docs:check
bun run docs:build
python protocol/vectors/verify.py
```

macOS native privileged feth/helper tests were **not run** on this Windows host.
The new macOS CI job runs ordinary tests and Clippy, not root/device validation.
No new two-node Npcap/Scapy physical-adapter LAN scenario was run in this audit;
existing historical reports are not evidence of a new run. Relay integration
uses a real loopback TURN service with in-process Ethernet routing.
