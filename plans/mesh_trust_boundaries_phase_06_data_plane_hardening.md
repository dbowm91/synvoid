# Phase 06 Plan: Data Plane Hardening

Status: **PROPOSED** (not started; findings verified at `4add005f`).

Registered in: `plans/roadmap.md`.
Campaign: `plans/mesh_trust_boundaries_roadmap.md`.
Predecessor: Phase 02 (delivery) and Phase 03 (identity).
Depends on: Phase 01 harness (`spoofed_xff_does_not_reach_upstream`,
`oversized_chunk_is_rejected_before_alloc`).

## The finding

**C4 (High).** The `ServerlessInvokeRequest` handler builds
`CallerContext { node_id: req.caller_node_id }` (`transport_peer.rs:5144`) and
hardcodes the role to EDGE, while the authenticated `peer_node_id` is in scope
and discarded. `allowed_callers` and revocation are checked against that field
(`synvoid-serverless/src/manager.rs:233-244`), so any peer can invoke a
function scoped to another node. The `serverless_function:` preface branch also
runs before `authorize_local_upstream` (`transport_peer.rs:5840-5885` vs
`:5892-5942`), so it bypasses `peered_wafs` and `service_policy` entirely.

**C5 (High).** The origin writes the peer's raw header block to the customer
upstream (`transport_peer.rs:6053-6057`): hop-by-hop headers survive, and
`X-Forwarded-For` / `X-Real-IP` / `Forwarded` pass through unchanged. The edge
never supplies a trusted value either — `maybe_handle_mesh_backend` copies all
client headers and only appends `Content-Length`
(`synvoid-http/src/mesh_backend_dispatch.rs:88-101`), unlike the direct path
which strips and rebuilds them from the socket peer
(`synvoid-proxy/src/headers.rs:532-570`). The real client IP is lost and the
client's claim reaches the interior hop.

**C6 (High).** `chunk_size` is parsed with no bound
(`transport_peer.rs:820-826`), then `vec![0u8; chunk_size + 2]` is allocated
before the body cap is evaluated (`:853-866`). `chunk_size = usize::MAX`
aborts the process. Trigger requires `body_policy.streaming = false`; the
streaming twin has the same missing bound (`:1477`) and can wrap
`total_wire_bytes` in release builds.

**C7 (High).** `proxy_to_peer_with_fallback` spawns a request per provider up
front and only breaks after a success arrives (`proxy.rs:1091-1146`), so a
non-idempotent request executes on up to `MAX_PROVIDER_FANOUT` origins.

**D1/D2/D3 (Medium).** Inbound connections are not capped
(`max_peer_connections` gates outbound only); the edge response read has no
header cap and no timeout, buffers up to 50 MiB per in-flight request with no
concurrency limit, and accepts `Content-Length` + `Transfer-Encoding: chunked`
together while the origin rejects that combination.

## Root cause

The origin side was written as a bounded, streaming relay and the edge side as
a convenience client. The edge buffers, trusts client headers, and waits
without a deadline; the origin re-serialises nothing and enforces framing only
for its own reads. Client identity had no authenticated carrier, so it was
either dropped or taken from the client.

## Fix scope

### P1 — Authenticated client identity in the preface

Extend `service_target.rs` to version 2:

```text
+--------+---------+--------+--------+--------------+-----------+---------+
| magic  | version | flags  | len    | service_id   | meta_len  | meta    |
| 4 B    | 1 B     | 1 B    | 2 B BE | len bytes    | 2 B BE    | TLV     |
+--------+---------+--------+--------+--------------+-----------+---------+
```

- `flags` bit 0 advertises the metadata block.
- Metadata TLV fields, both mandatory when bit 0 is set:
  - `0x01` client address (4 or 16 bytes plus a family byte);
  - `0x02` client protocol (`http`/`https`, 1 byte).
- Version 1 remains accepted during the `legacy_*` window; it carries no
  client identity, so the origin behaves as it does today but **strips** all
  client-supplied forwarded headers.
- Validation: reject unknown TLV types (forward compatibility is a version
  bump), reject duplicate types, reject an address whose length does not match
  its family.
- The metadata is authored by the authenticated edge. The origin records it as
  "reported by peer X" and never merges it with a client header.

The edge passes the real client address from the request context. It must not
read `X-Forwarded-For` from the client to populate this field.

### P2 — Rebuild the upstream header block

Replace `write_all(&head.header_bytes)` with a rebuilt block:

- drop hop-by-hop headers (`Connection` and the headers it names,
  `Keep-Alive`, `Proxy-Connection`, `TE`, `Trailer`, `Transfer-Encoding`,
  `Upgrade`);
- drop `X-Forwarded-For`, `X-Real-IP`, `Forwarded`, `X-Forwarded-Proto`,
  `X-Forwarded-Host`, and `Proxy-*`;
- set exactly one `X-Forwarded-For` from the preface client address, plus
  `X-Real-IP` and `X-Forwarded-Proto`;
- preserve `Host`, recompute `Content-Length` from the framed body, and
  preserve end-to-end headers;
- reject a request whose `Host` appears twice with different values (already
  rejected at `:988-998`) and normalise the header name case.

Apply the same filter at the edge before building the mesh request, so the
interior hop receives one consistent shape even before the origin rebuilds it.

### P3 — Serverless authorization

- `CallerContext` uses `peer_node_id` and the session role from Phase 03;
  `caller_node_id` becomes audit metadata only.
- The `serverless_function:` preface maps to an authorization key and goes
  through the same `authorize_local_upstream` (or an explicit
  `[tunnel.mesh.local_serverless]` allowlist checked immediately after it).
  No dispatch before authorization.
- A denied peer gets 403; an unknown function gets 404; neither reveals
  whether another function exists.

### P4 — Bound chunk parsing before allocation

- In the buffered reader: compute
  `remaining = max_body_bytes.saturating_sub(total_wire_bytes)`; if
  `chunk_size + 2 > remaining`, return `BodyTooLarge` **before** allocating.
  Use `checked_add` for `chunk_size + 2`.
- In the streaming reader: `checked_add` for `total_wire_bytes` and for the
  remaining count; reject on overflow.
- Reject a chunk-size line longer than the trailer cap and a size with
  leading `+`/`-`/whitespace.
- Keep the existing 413 mapping; the client must not see a connection reset
  instead of a status.

### P5 — Sequential provider selection

- Replace the parallel spawn with an ordered loop over providers.
- Attempt the next provider only when the failure happened before any response
  bytes were read, and only for idempotent methods (`GET`, `HEAD`, `OPTIONS`,
  `TRACE`). For `POST`/`PUT`/`PATCH`/`DELETE`, the first provider is
  authoritative; a transport failure returns an error rather than replaying
  the body.
- Delete `MAX_PROVIDER_FANOUT`, `ProviderTaskGuard`, and the result channel.
- Record per-provider failure reasons and expose the selected provider in the
  response headers or logs for diagnosis.

### P6 — Inbound connection and request limits

- Enforce `max_peer_connections` on accept: count `registry.len()` plus
  in-flight handshakes; reject with application close code `0x02` and a
  warning naming the peer.
- Keep the per-session stream cap and add a global in-flight stream
  semaphore so N peers cannot each consume the per-session maximum.
- Add `max_concurrent_mesh_requests_per_peer` (default 64) on the egress side;
  waiting requests time out rather than queueing without bound.

### P7 — Edge response limits and framing

- Extract the origin's response-head parser into a shared helper used by both
  sides. Enforce `max_peer_http_response_header_bytes` (default 64 KiB), an
  idle timeout, and a total deadline.
- Reject `Content-Length` + `Transfer-Encoding` together with 502 rather than
  decoding one and re-emitting the other. Recompute `Content-Length` from the
  decoded body and strip `Transfer-Encoding`.
- Enforce the service policy's response cap on the edge, not only at the
  origin. The 50 MiB `MAX_HTTP_BODY_SIZE` stops being the effective limit.
- Stream the response when `body_policy.streaming` is true. If streaming is
  deferred, the buffered path must at least be bounded by the policy and by
  the per-peer semaphore, and the plan must record the deferral explicitly.

### P8 — Request body handling at the edge

`maybe_handle_mesh_backend` buffers the whole client body before forwarding.
Keep that for the first pass (the HTTP pipeline already caps it), but:

- set `Content-Length` by replacing, not appending (today `Builder::header`
  appends, producing a duplicate when the client sent one);
- skip `Transfer-Encoding` and `Content-Length` from the copied set, then set
  the single authoritative length;
- do not copy hop-by-hop or forwarded headers.

## Invariants

- Client identity reaches the origin only through the authenticated preface.
- A client-supplied forwarded header never reaches the customer upstream.
- No allocation is sized from an unvalidated length.
- A non-idempotent request is written to at most one origin.
- Every read on the mesh hop has an idle timeout and a total deadline.
- Every limit has one owner; the edge and the origin enforce the same policy.

## Verification

- Un-ignore and pass `spoofed_xff_does_not_reach_upstream` and
  `oversized_chunk_is_rejected_before_alloc`.
- New tests: client IP appears as exactly one `X-Forwarded-For` with the
  preface value; hop-by-hop headers absent at the upstream; duplicate
  `Content-Length` never appears on the wire; preface v2 round-trips and
  rejects duplicate/unknown TLV types; serverless invoke with a forged
  `caller_node_id` is denied; two providers with a POST execute exactly once;
  a 2 s origin stall times out with 504/502 rather than hanging; a 51 MiB
  response is rejected before buffering all of it; CL+TE response is 502.
- Live: `runtime/mesh-qual/qualify.sh` fixed and chunked 4 MiB bodies, 40 MiB
  response, over-cap rejection, and failover all pass.
- Confirm the origin's WAF/upstream sees the edge-reported client address, not
  the edge's socket address, in the backend access log.

## Non-goals

- Re-inspecting mesh traffic with the full WAF pipeline at the origin. The edge
  remains the inspection point; this phase makes the origin's trust context
  correct.
- HTTP/2 or HTTP/3 on the mesh hop.
- A general streaming rewrite of the edge. Bounded buffering is acceptable for
  the first pass if the caps and semaphores are real; record any deferral.
- Per-request signing of client metadata beyond the authenticated session.
