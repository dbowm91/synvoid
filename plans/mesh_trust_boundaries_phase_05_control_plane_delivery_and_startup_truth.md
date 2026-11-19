# Phase 05 Plan: Control-Plane Delivery and Startup Truth

Status: **IMPLEMENTED** (2026-11-14; delivery contract suite green in `ea638ff9`).

Registered in: `plans/roadmap.md`.
Campaign: `plans/mesh_trust_boundaries_roadmap.md`.
Predecessor: Phase 02 (delivery).
Depends on: Phase 01 harness (`site_config_over_1mib_is_acked`).

## The finding

**C3 (High).** Site configuration is pushed to origins in a single QUIC
datagram with no size check and no acknowledgement:

- `broadcast_site_config_to_origins` embeds the full `config_json` in
  `MeshMessage::SiteConfigSync` and calls `send_datagram_to_peer`
  (`transport.rs:1799-1872`);
- QUIC datagram payload is bounded by the path MTU (roughly 1.2 KB), so
  `send_datagram` returns `TooLarge` for any realistic site config;
- the broadcast runs in a detached task and the result is logged as
  `"{success} success, {fail} failed"` (`src/admin/handlers/sites.rs:197-219`).
  The admin API has already returned 200. The operator is told a config was
  published while every origin serves the previous one.

There is no fragmentation, no ack, and no retry. The origin also applies
whatever version arrives, with no monotonicity check.

**D11 (Medium).** Mesh startup reports success without a peer:

- the startup report counts *configured* seeds, not connected peers
  (`transport.rs:2356-2381`);
- `transport.start()` discards the report and `MeshSupervisionEvent::Started`
  is still emitted (`src/worker/unified_server/mesh_attachment.rs:273-300`);
- `--mesh-agent` never calls `transport.start()` but logs "Mesh Agent is now
  active" (`src/supervisor/mesh.rs:99-118`).

A zero-peer mesh therefore passes readiness while every mesh-routed site
returns 502.

## Root cause

Control-plane state that must arrive was placed on the same best-effort,
MTU-bounded channel the mesh uses for liveness hints, and the caller was made
fire-and-forget to keep the admin request fast. Separately, "mesh started"
was defined as "the task that starts mesh did not return an error", not as
"the node has a peer".

## Fix scope

### D1 — Site config moves to a stream with an ack

- Keep `SiteConfigSync` as the payload but send it with
  `send_message_to_peer_with_response` over the Phase 02 registry. The origin
  handles it on the same stream and writes `SiteConfigAck`:

  ```text
  SiteConfigAck { request_id, site_id, applied_version, accepted, reason }
  ```

- The sender treats a missing ack, a decode failure, or `accepted: false` as a
  delivery failure for that origin. The existing 30 s response timeout is the
  delivery deadline; config sizes are small, so no chunking is needed.
- Enforce `MAX_MESSAGE_SIZE` (10 MiB) on the sender with a specific
  `SiteConfigTooLarge` error. Do not let the cap surface as a generic send
  failure.
- Delete the datagram send for `SiteConfigSync`. If a fast path is wanted
  later, add a `SiteConfigHint { site_id, version }` datagram and have the
  origin pull the body over a stream; the hint must never be the only carrier.

### D2 — Monotonic, per-origin applied version

- The origin records `applied_version` per site and rejects
  `config_version <= applied_version` with `accepted: false, reason: "stale"`
  (except an explicit force flag from the admin).
- `version` is currently `safe_unix_timestamp()` in seconds
  (`src/admin/handlers/sites.rs:195`), so two edits in the same second collide.
  Replace it with a monotonic per-site counter persisted alongside the site
  config, or `max(now, last_version + 1)`.
- Verify the signature and source authorization before applying; site config
  is state-bearing and inherits Phase 04's rules.

### D3 — Per-origin results reach the operator

- `broadcast_site_config_to_origins` returns
  `Vec<OriginDelivery { node_id, applied_version, result }>`.
- The admin handler waits for the bounded fanout and reports:
  - `200` when every origin acked;
  - `207` (or a structured JSON body with `failed`) when some did not;
  - `502` when no origin acked.
- Remove the detached `tokio::spawn`. If a future config is large enough to
  need async delivery, return an operation id and expose its status; do not
  silently discard the result.
- Record the last broadcast outcome per site so `/api/mesh/status` can show
  which origins are stale, even after the request ends.

### D4 — Startup and readiness tell the truth

- `MeshStartupPolicy` gains:
  - `allow_zero_peers` (default `false` when seeds or peers are configured);
  - `require_peer_within_secs` (default 30).
- Startup waits up to that bound for the first connected peer. If none arrives
  and zero peers are not allowed, mesh start fails with
  `MeshStartupReason::NoPeerConnected` (or enters `degraded` when
  `supervision.required = false`) instead of `Started`.
- The report's `connected_peers` is `registry.len()`, never
  `config.seeds.len()`. Report configured and connected counts separately.
- Propagate the report into `WorkerMeshStatus` and the supervisor's mesh state.
  `mesh_attachment` must not swallow it.
- `--mesh-agent` calls `transport.start()` and exits non-zero on failure. Its
  init errors stop being `warn!` for anything that prevents serving.
- `/api/mesh/status` exposes: realized node id, role, listen address and bound
  port, connected peers with session age, last error, and degraded reasons.

### D5 — Health semantics

- Mesh-backed sites already fail closed with 502 when no route exists. Readiness
  must match that: a node that cannot serve its configured mesh sites is not
  `ready`.
- Do not fail the whole worker when only mesh is degraded, unless
  `supervision.required = true`; in that case the existing supervision path
  owns the decision and the reason must name the mesh failure.

## Invariants

- No state-bearing control message travels only on a datagram.
- Every broadcast reports per-origin success; no silent partial failure.
- A config version never moves backwards on an origin.
- Readiness is a function of connected peers, not configured seeds.
- A startup path never logs "active"/"started" after it has skipped the work
  that would make it true.

## Verification

- Un-ignore and pass `site_config_over_1mib_is_acked`: a 2 MiB site config
  reaches the origin, is applied once, and the ack carries the version.
- New tests: stale version rejected; missing ack surfaces as a failed origin in
  the admin response; partial delivery returns 207 with the failing node id; a
  config larger than `MAX_MESSAGE_SIZE` fails with a typed error.
- Zero-peer startup: with seeds configured and unreachable, startup reports
  `NoPeerConnected` (or degraded) within the bound and `/api/mesh/status`
  reports `connected_peers: 0`; with `allow_zero_peers = true` it starts and
  reports degraded.
- `--mesh-agent` exits non-zero when `transport.start()` fails.
- Live: edit a site through the admin API with two origins, one stopped;
  response names the stopped origin; restart it and re-broadcast; both apply.

## Non-goals

- A distributed configuration store, Raft-replicated site configs, or
  multi-master config editing.
- Live rebinding of listeners on config change; config changes stay
  restart-required for listener topology.
- Retrying delivery in the background after the admin request returns. The
  operator gets the result and decides.
