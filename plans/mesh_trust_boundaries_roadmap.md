# Mesh Trust Boundaries and Delivery Integrity Roadmap

Status: **PROPOSED** (audit complete; no implementation started).
Research baseline: `4add005f` (merged `main`), audited 2026-11-14.

Predecessor context:

- mesh multi-upstream forwarding:
  `plans/mesh_multi_upstream_forwarding_roadmap.md` (Phases 01-04 implemented,
  Phase 05 in qualification);
- mesh transport runtime wiring: `plans/mesh_transport_runtime_wiring.md`
  (implemented in `21fc7477`, `4add005f`);
- live topology qualification harness: `runtime/mesh-qual/`.

## Why this campaign exists

A read-only audit of the mesh and networking stack at `4add005f` found that the
TLS layer is now sound but the layers above it are not:

- the peer connection registry is keyed by a random session UUID while every
  sender looks up by node id, so **no targeted mesh message can be delivered**;
- the stream pool returns streams the peer has already closed, so even a
  successful lookup cannot carry a second exchange;
- peer role, peer trust, DHT record authorship, caller identity, and threat
  intelligence signatures are all fields the sender supplies about itself.

The handshake establishes a mutually verified QUIC session. Nothing above the
handshake survives contact with that session. The existing test suite cannot
see this because no test opens a real mesh connection between two nodes: the
unit tests construct registries directly, and
`cargo test -p synvoid-proxy --test mesh_listener_backends` reports
`running 0 tests` without `--features mesh`.

For a mesh that is meant to serve distributed WAF services, that combination is
the whole problem: the transport authenticates the *channel*, and the
application trusts the *message*. This campaign makes the message trust follow
from the channel, and makes the channel actually carry messages.

## Current state (measured, not inferred)

| Layer | State at `4add005f` |
|---|---|
| QUIC endpoint, TLS, mTLS, PoW | works; strict mode binds the peer certificate SAN to the node id |
| Peer registry | **broken**: keyed by `session_id`, looked up by `node_id` |
| Control-plane delivery (keepalive, routes, site config, seed list) | **dead**; every targeted send returns `PeerNotFound` |
| Stream reuse | **unsound**: receiver handles one exchange per stream, sender pools it |
| Message authentication | **optional**: empty signatures accepted; signer key derived from the public node id |
| Peer role/trust | **self-declared** on the wire and persisted |
| DHT record authorship | **self-certifying**: record verified against its own embedded key |
| Config realization (`[tunnel.mesh]` -> runtime) | **lossy**: `dht`, `mlkem`, `require_tier_claim`, and `origin_signing_key` do not survive the JSON bridge; `validate()` is never called |
| Data plane (HTTP over mesh) | implemented and bounded on the origin side; edge egress has no timeout, no header cap, 50 MiB buffering, and no client-IP propagation |
| Startup truthfulness | **optimistic**: zero connected peers reports running; the report counts configured seeds |

## Findings index

Severity is from the audit. `Phase` is where the finding is closed.

| ID | Severity | Finding | Phase |
|---|---|---|---|
| A1 | Critical | `peer_connections` keyed by session id, looked up by node id | 02 |
| A2 | High | Stream pool reuses streams the peer has closed | 02 |
| B1 | Critical | Unsigned `ThreatAnnounce` applied and gossiped | 04 |
| B2 | Critical | Mesh signer secret derived from the public `node_id` | 04 |
| B3 | Critical | `PeerAnnounce` self-declares GLOBAL and becomes trusted | 03, 04 |
| B4 | Critical | DHT records self-signed; `source_node_id` never bound | 04 |
| C1 | High | `auth_token` is sender-optional and `auth_keys` is empty | 03 |
| C2 | High | Accept path does not bind claimed node id to the presented key | 03 |
| C3 | High | Site config sent as one unfragmented datagram | 05 |
| C4 | High | Serverless caller identity read from the request body | 06 |
| C5 | High | Origin splices peer headers to the upstream; client IP lost | 06 |
| C6 | High | Unvalidated chunk size allocated before the body cap | 06 |
| C7 | High | Provider fanout duplicates non-idempotent requests | 06 |
| C8 | High | Raft `ClientProposal` verified over a different payload and key | 04 |
| C9 | High | Wire `is_trusted` persisted as real trust | 03 |
| C10 | High | DHT/ML-KEM/tier config unreachable; `validate()` uncalled | 07 |
| D1 | Medium | No inbound connection cap; duplicate sessions per node | 02, 06 |
| D2 | Medium | Edge response read has no timeout, no header cap, 50 MiB buffer | 06 |
| D3 | Medium | Edge accepts `Content-Length` + `Transfer-Encoding` together | 06 |
| D4 | Medium | `quic_port` and configured transport knobs are ignored | 07 |
| D5 | Medium | Node identity not durable; key written 0644; random per-call fallback | 07 |
| D6 | Medium | `origin_signing_key` DTO type mismatch disables mesh | 07 |
| D7 | Medium | Every worker process binds the same mesh port | 07 |
| D8 | Medium | Raft `truncate_after(None)` is a no-op | 04 |
| D9 | Medium | No ALPN on the mesh QUIC endpoint | 07 |
| D10 | Medium | Edge replica path hardcoded; failures swallowed | 07 |
| D11 | Medium | Startup reports healthy with zero peers; configured seed count | 05 |
| D12 | Medium | Shipped `mesh-example.toml` cannot start | 07 |

## Target model

```text
TLS session (verified cert SAN, or key-derived id)
  -> node_id            (derived, not claimed)
  -> role               (allowlist entry, not a wire bit)
  -> trust              (computed locally, not a wire bool)
  -> service authorization (peered_wafs + service_policy, unchanged)
  -> message signature  (verified against the node's registered key)
  -> state mutation     (threat intel, DHT, topology, raft)
```

Rules:

- A peer may describe itself only with values that the receiving node can
  recompute or look up. `node_id`, role, trust, and caller identity are never
  taken from a message field.
- The message signer is derived from the node's **secret** identity, never
  from a public value such as `node_id`.
- Every state-bearing message is signed and the signature is verified against
  the sender's registered key before the message is applied or relayed.
- One node id has at most one active mesh session; replay state belongs to the
  node, not to the session.
- One bidirectional stream carries exactly one exchange. If multiplexing is
  ever needed it requires a request id in the framing, not a pool.
- Control-plane state that must arrive (site config) uses a stream with an
  acknowledgement; datagrams are for hints and liveness only.
- Client identity travels in the authenticated preface, never in
  client-supplied headers.
- A peer with no registered role is an edge. Origin and global roles require an
  explicit allowlist entry.

## Decisions

| Gate | Decision |
|---|---|
| T1 — registry | `peer_connections` becomes a node-id-keyed registry with a session-id reverse index. One active session per node; takeover closes the older connection. Replay protection moves to the node entry. |
| T2 — streams | `MeshStreamPool` is deleted. Every message and every HTTP request opens a fresh bidirectional stream. No stream is reused. |
| T3 — identity | `node_id` is derived from the presented key on both dial and accept, in every TLS mode. Role comes from the allowlist; trust is computed locally. |
| T4 — shared secret | `auth_token`/`auth_keys` is deleted rather than repaired. mTLS plus the allowlist is the authentication story. |
| T5 — signer | The node identity key is the message signer. The published key becomes the Ed25519 verifying key and node ids are re-derived from it; one key covers identity, PoW, and message signatures. `global_node_key` is never a signer source. |
| T6 — config delivery | `SiteConfigSync` moves to a stream with a typed ack; datagrams remain for hints. |
| T7 — client identity | Service preface v2 carries the client IP. The origin rebuilds forwarded headers from it and drops all client-supplied variants. |
| T8 — sequencing | The loopback contract harness lands before the fixes. Each later phase adds its regression test to that harness. |
| T9 — workers | Mesh with `unified_server_workers > 1` is a startup error until multi-worker mesh is its own campaign. |
| T10 — upgrades | Wire changes carry a preface/proto version and a bounded dual-accept window with a startup deadline, mirroring the existing DHT unsigned-sync pattern. |

## Phase table

| Phase | Plan | Depends on | Primary outcome |
|---|---|---|---|
| 01 | `plans/mesh_trust_boundaries_phase_01_loopback_contract_harness.md` | audit | a two-node in-process harness and a CI step that cannot silently run zero tests |
| 02 | `plans/mesh_trust_boundaries_phase_02_peer_registry_and_stream_lifecycle.md` | 01 | a node-id-keyed registry and one-exchange-per-stream delivery |
| 03 | `plans/mesh_trust_boundaries_phase_03_authenticated_peer_identity.md` | 02 | node id, role, and trust derived from the session in every TLS mode |
| 04 | `plans/mesh_trust_boundaries_phase_04_message_and_state_authentication.md` | 03 | mandatory, registry-bound signatures for threat intel, DHT, peer announce, and raft |
| 05 | `plans/mesh_trust_boundaries_phase_05_control_plane_delivery_and_startup_truth.md` | 02 | reliable site-config delivery with acks, and truthful startup/readiness |
| 06 | `plans/mesh_trust_boundaries_phase_06_data_plane_hardening.md` | 02, 03 | authenticated client identity, bounded framing, single-provider dispatch |
| 07 | `plans/mesh_trust_boundaries_phase_07_config_realization_and_operations.md` | 01 | a lossless `[tunnel.mesh]` -> runtime bridge, durable identity, and honest docs |

Phases 05 and 06 may run in parallel once 02 and 03 are merged. Phase 04 must
not be merged before 03: signing a role that the receiver still takes from the
wire does not add authentication.

## Cross-phase invariants

- No mesh message may be delivered by iterating a map keyed by something other
  than the value the sender used.
- No lookup may succeed for a node that has no active session.
- A peer cannot cause a state mutation by asserting its own role, trust,
  authorship, or caller identity.
- A signature verification never consumes a key supplied by the message.
- No pool, cache, or registry may outlive the lifecycle of the thing it stores.
- A datagram is never the only carrier for state that must arrive.
- A client-supplied header is never promoted into the origin's trust context.
- Mesh startup either reports a specific degraded reason or fails; it never
  reports running while no peer is connected.
- Config accepted by the TOML parser is either realized at runtime or rejected
  with a startup error.
- Every phase adds at least one test that fails on the pre-phase code.

## Verification matrix

At minimum, per phase and again at closeout:

- `cargo fmt --all -- --check`
- `cargo clippy --workspace --profile ci --all-targets -- -D warnings`
- `cargo test -p synvoid-mesh --profile ci` with a **nonzero** executed-test
  count for the new contract binary
- the phase's adversarial tests (forged identity, unsigned state message,
  duplicate session, oversized chunk, partial delivery)
- `cargo xtask verify`
- `runtime/mesh-qual/qualify.sh` after Phases 02-06, unchanged
- two-node qualification with a real CA: edge request served by an origin
  upstream; unpeered node 403; unknown service 502; origin kill -> fast 502
- rolling-upgrade check: old peer against new peer and new against old during
  every window introduced by T10

## Non-goals

- Enabling the DHT, ML-KEM sessions, or tier claims. This campaign makes their
  configuration expressible; it does not make them work. That is a separate
  campaign with its own evidence.
- Multi-worker mesh. One unified worker per node remains the supported model,
  and this campaign makes the constraint explicit rather than silent.
- Replacing QUIC, adding HTTP/3 or HTTP/2 on the mesh hop, or changing the
  service-ID model.
- Live mesh config reload; listener and service changes stay restart-required.
- Distributed admin sessions or CSRF state.
- Performance tuning of the mesh hop beyond removing the stream pool.

## Success statement

Two `synvoid` nodes with a shared CA establish a session, exchange every
control message the design defines, and serve a client request end to end
through a mesh service. A peer that lies about its identity, role, trust,
authorship, or caller id is rejected at the trust boundary rather than
believed. A site config change reaches every origin or the operator is told
which origin did not receive it. The test suite proves both, in CI, on every
change.
