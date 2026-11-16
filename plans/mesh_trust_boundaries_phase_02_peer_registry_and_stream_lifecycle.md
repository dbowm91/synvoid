# Phase 02 Plan: Peer Registry and Stream Lifecycle

Status: **PROPOSED** (not started; findings verified at `4add005f`).

Registered in: `plans/roadmap.md`.
Campaign: `plans/mesh_trust_boundaries_roadmap.md`.
Predecessor: Phase 01 (contract harness).
Depends on: Phase 01 for the regression tests this phase un-ignores.

## The finding

**A1 (Critical).** `peer_connections` is a
`DashMap<String, MeshPeerConnection>` whose key is a per-session UUID, while
every sender treats the map as node-id-keyed:

- inserts: `transport.rs:4387` (accept) and `:5168` (dial), both with
  `session_id = Uuid::new_v4()` (`:4298`);
- lookups: `transport.rs:1784`, `:1909`, `:1953`, `:5916`;
  `transport_routing.rs:62`; `transport_peer.rs:5725`;
  `transports/quic.rs:81`;
- replay-state lookups that silently return `None` and therefore skip the
  check: `transport_peer.rs:3364`, `transport_dht.rs:444`, `:683`.

Consequence: `send_datagram_to_peer`, `send_message_to_peer`,
`send_message_to_peer_with_response`, health checks, and the mesh HTTP egress
all fail with `PeerNotFound`. Approximately forty call sites are affected,
including keepalive, seed-list bootstrap, route queries, site-config sync, load
reports, DNS registration, passover key exchange, serverless responses, and
upstream announcements. The live topology reproduces this immediately after a
successful handshake: `Established mesh peer connection: node-…` followed by
`Peer not found: node-…`, then 502 on every mesh-routed site.

**A2 (High).** The receiver handles exactly one exchange per bidirectional
stream and then drops both halves (`transport_peer.rs:4433-4472` dispatches to
`handle_peer_message`, which returns after one message or one HTTP exchange).
The sender returns that same stream to `MeshStreamPool`
(`transport.rs:6097`, `transport_types.rs:26-44`). A reused stream has already
been closed by the peer, so the next write fails; if a reply was left unread,
the next request/response call can also parse a stale frame as its response.
The pool is not a performance optimisation, it is a correctness defect.

## Root cause

Two lifecycle models were collapsed into one map. A connection belongs to a
node for the lifetime of the peering; a stream belongs to a single exchange.
The registry was keyed by the shortest-lived identity available, and the pool
assumed the receiver multiplexes, which it does not. Because no test exercises
a send, neither mismatch was observable.

## Fix scope

### R1 — Node-keyed registry with a reverse index

Replace the public map with a `MeshPeerRegistry` (same module as
`MeshPeerConnection`, `crates/synvoid-mesh/src/mesh/transport_types.rs`):

```text
by_node:    DashMap<NodeId, Arc<PeerSession>>
by_session: DashMap<SessionId, NodeId>
```

`PeerSession` carries what `MeshPeerConnection` carries today minus
`stream_pool`, plus `generation: u64`. `last_seen` becomes an atomic
millisecond timestamp or a `parking_lot::RwLock<Instant>`; it is written by
every receive path and must not allocate.

API (the only way to reach a session):

- `register(session) -> RegisterOutcome::{Inserted, Replaced(Arc<PeerSession>)}`
- `get(node_id) -> Option<Arc<PeerSession>>`
- `session_owner(session_id) -> Option<NodeId>`
- `remove_if_current(session_id)` — removes only when that session is still the
  node's current one
- `iter()`, `len()`, `is_empty()`, `clear()`

Make the fields private. The compiler, not a grep, is what proves the old
lookup shape is gone.

### R2 — One active session per node

The mesh model is one session per peering. On `register` for a node that
already has a session:

- return `Replaced(old)`;
- the caller closes the displaced connection with a dedicated application code
  (`0x01`, reason `"duplicate node session"`) and logs at `info` with both
  session ids;
- the new session wins. This makes the dial/accept race deterministic instead
  of producing two message loops for one node.

All cleanup paths (`transport.rs:3410`, `:3872`, `:4504`; the session exit
broadcast) must use `remove_if_current(session_id)`. A slow cleanup from a
replaced session must never evict the live one; that is what `generation` is
for.

### R3 — Replay state belongs to the node

Move `replay_protection` out of the session and into a small
`ReplayStateRegistry` keyed by node id, retained for
`replay_retention_secs` (default 300 s, matching the DHT timestamp window) after
the last session closes. Reconnecting must not reset the nonce cache; otherwise
a peer can replay a pushed record by reconnecting first.

Lookup becomes a single accessor used by every DHT/threat path; the current
`if let Some(state) = peer_connections.get(peer_id)` shape must not exist in a
form that silently skips verification when the peer is absent. A missing replay
state for a known peer is an internal error, not a pass.

### R4 — Delete the stream pool

- Remove `MeshStreamPool`, `MAX_MESH_STREAM_POOL_SIZE`, and the
  `stream_pool` field.
- Every send path opens a fresh bidirectional stream:
  `send_message_to_peer`, `send_message_to_peer_with_response`,
  `send_route_query_stream`, `perform_health_check`, and
  `proxy_http_request`.
- For HTTP, call `send_stream.finish()` after the request body so the origin
  can distinguish "no more bytes" from a stall. The origin still frames by
  `Content-Length`; finishing is a defence, not the framing.
- Do not reintroduce pooling later without a request id in the framing. The
  receiver's one-exchange-per-stream model is the contract this phase
  documents.

### R5 — Update consumers through the compiler

Set the registry field private, build, and fix every error. Do not
grep-and-patch: the following are known consumers, but the compiler is the
authority.

| Area | Files |
|---|---|
| send paths | `transport.rs:1777-2027`, `transport_routing.rs:55-105` |
| accept/dial/cleanup | `transport.rs:4058-4510`, `:5160-5175` |
| datagram and health loops | `transport.rs:2292-2320`, `:2439-2484` |
| HTTP egress | `transport.rs:5879-6103` |
| maintenance/connectivity | `transport_connection.rs:611-665`, `transports/quic.rs:78-145`, `transports/stack.rs:52-174` |
| replay consumers | `transport_peer.rs:3364`, `transport_dht.rs:444`, `:683` |

`MeshPeerConnection` is cloned into maintenance transports
(`transport.rs:445`, `transport_connection.rs:29`); the registry stays behind
one `Arc`, so those clones must not copy the map.

### R6 — Observable session state

Add `mesh_peer_sessions{node_id}` as a gauge with session age, plus counters
for `duplicate_session_replaced` and `session_registry_missing` (the internal
error from R3). `/api/mesh/status` reads `connected_peers` from the registry,
not from topology, so a stale topology entry cannot claim a connection.

## Invariants

- A registry key is a node id everywhere. No caller may pass a session id to a
  node-keyed accessor.
- A session's cleanup cannot remove a session it does not own.
- Replay state outlives the session it was created for, for at least the
  protocol replay window.
- A stream is used for exactly one exchange and is never stored after that
  exchange completes.
- Removing the pool must not change framing, timeouts, or body limits; this
  phase changes lifecycle only.

## Verification

- Un-ignore and pass: `peer_lookup_by_node_id`, `two_sequential_requests_succeed`,
  `unpeered_peer_gets_403`, `unknown_service_gets_502` in the Phase 01 harness.
- New tests: duplicate dial replaces the session and closes the old connection;
  cleanup from the replaced session does not evict the new one; replay state
  survives a reconnect and still rejects the old nonce; 32 concurrent requests
  on one peer all succeed.
- `grep -rn "stream_pool" crates/synvoid-mesh/src` returns nothing.
- `cargo test -p synvoid-mesh --profile ci` and the workspace clippy gate pass.
- Live: `runtime/mesh-qual/ctl.sh start-node origin|edge` then two sequential
  `curl` requests on 9100 both return 200; `ss -lunp` shows both endpoints;
  killing the origin produces 502 within the configured timeout, and restarting
  it restores forwarding without restarting the edge.

## Non-goals

- Stream multiplexing, request ids, or a replacement pool.
- Connection migration, 0-RTT, or multiple concurrent sessions per node.
- Changing the TLS or handshake layers; Phase 03 owns identity.
- Load or performance qualification of the new one-stream-per-exchange model.
  If throughput regresses, that is a follow-up with measurements, not a reason
  to restore the pool.
