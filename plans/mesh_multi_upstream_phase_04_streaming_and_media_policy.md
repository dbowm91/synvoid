# Phase 04 Plan: Streaming and Media Policy for Mesh Forwarding

Status: **IMPLEMENTED** (see `plans/mesh_multi_upstream_forwarding_results.md`).
Campaign: `plans/mesh_multi_upstream_forwarding_roadmap.md`.
Depends on: Phase 01 (service ID transport) and Phase 02 (origin trust).

## Goal

Make the mesh forwarding contract truthful for large bodies and media, or
explicitly exclude them. The blog has multi-megabyte images and a 666 MB video;
the current mesh HTTP path caps request and response bodies at 64 KiB and
rejects chunked requests.

This phase must not pretend that the current fixed-body buffered proxy is a
media path.

## Current state

- Mesh HTTP carries one HTTP/1.x request per QUIC stream.
- Chunked request bodies are rejected with `501`
  (`crates/synvoid-mesh/src/mesh/transport_peer.rs:4361`).
- Upgrade/WebSocket requests are rejected with `503`
  (`transport_peer.rs:4300-4310`).
- Request body cap: `max_peer_http_body_bytes` default 65536
  (`crates/synvoid-config/src/mesh.rs:501-511`).
- Response body cap: `max_peer_http_response_body_bytes` default 65536.
- Mesh proxy retry/fanout buffers request bodies up to 8 MiB
  (`MAX_REPLAY_BODY_BYTES` in `crates/synvoid-mesh/src/mesh/proxy.rs`).
- Response transforms currently collect the full response before transforming
  and sending (`transport_peer.rs` around `apply_response_transforms`).
- The blog's media uses large images and a 666 MB upload; upload chunks are
  about 4 MB, still above the 64 KiB request cap.

## Decision

Choose one primary mode and state it in operator docs:

1. **Bounded buffered mode** (small APIs only):
   - raise caps only to a documented bounded size;
   - keep chunked/upgrade rejection;
   - explicitly exclude large media and uploads from mesh forwarding;
   - fail with 413/501 and a clear error.
2. **Streaming mode** (recommended for the blog):
   - forward request/response bodies incrementally over the QUIC stream;
   - support fixed-length and chunked request/response framing;
   - optionally support Range requests without materializing the whole body;
   - bound memory per stream and per service;
   - bypass or adapt response transforms for streaming bodies.
3. **Hybrid** (recommended if streaming is too large for one phase):
   - keep buffered mode for HTML/API;
   - add per-service `streaming = true` and route large media directly or
     through a dedicated streaming path;
   - document that mesh is not used for the video/media service until the
     dedicated path is qualified.

The campaign should prefer Hybrid or Streaming for the blog; Bounded Buffered
alone must be documented as a limitation, not a success.

## Workstreams

### A. Define service body policy

Add an explicit per-service policy:

- max request body;
- max response body;
- streaming enabled/disabled;
- chunked request allowed/disabled;
- transforms allowed/disabled;
- optional media-range support.

Do not rely on one global 64 KiB default for every service.

### B. Request streaming

- Preserve `Content-Length` and `Transfer-Encoding` semantics.
- Implement chunked request forwarding if streaming mode is selected.
- Keep a bounded per-stream buffer and backpressure; do not collect the whole
  body for retry/fanout when streaming is enabled.
- Disable multi-provider retry for non-replayable streaming bodies or define a
  bounded spool policy.

### C. Response streaming

- Stream the backend response head and body over the QUIC send stream.
- Do not collect the full response for transforms unless the service policy
  allows buffering.
- Decide how Range, HEAD, 204, 304, and close-delimited responses behave.
- Preserve trailers if the selected framing supports them; otherwise reject
  explicitly.

### D. Transforms

- Keep full-buffer transforms for small text/API responses.
- For streaming media, either bypass transforms or implement a streaming
  transform stage with strict bounds.
- Do not silently skip transforms without a metric/log.

### E. Blog-specific qualification

- HTML and small API: mesh forwarding acceptable.
- Images up to the configured cap: test fixed and streaming modes.
- 4 MB upload chunks: test with service cap > 4 MiB and fixed-length framing;
  chunked upload path only if chunked forwarding is enabled.
- 666 MB video: do not claim support unless streaming and Range behavior are
  tested end to end. Otherwise keep media direct to the origin/local path.
- WebSocket/CONNECT: keep rejected unless a separate upgrade design is
  approved.

## Tests

- Request body > 64 KiB with a raised service cap succeeds.
- Request body over the configured cap returns 413 before backend connect.
- Chunked request succeeds in streaming mode or is explicitly rejected in
  buffered mode with 501.
- Response body > 64 KiB with a raised cap succeeds.
- Streaming response does not require the full body in memory.
- Range and HEAD behavior are defined and tested.
- Transform-enabled text responses still transform; streaming media does not
  silently buffer or silently skip.
- Blog upload chunk size and video behavior are recorded as supported or
  explicitly unsupported.
- Backpressure/bounded-memory test under a slow consumer.

## Exit criteria

- Operator docs state exactly which body sizes, methods, and media types are
  supported through mesh.
- The blog's chosen mesh services either work under the documented streaming
  policy or are explicitly excluded.
- No service silently returns 413/501 because of an inherited 64 KiB default.
- Memory is bounded per stream/service.

## Risks

- Full-body buffering for retries conflicts with streaming; define a spool or
  disable retry for streaming.
- Transform stages may assume complete bodies; bypassing them changes
  response behavior.
- QUIC flow-control and HTTP framing need careful backpressure to avoid
  unbounded queues.
- Range support must not re-enable full-body buffering accidentally.

## Non-goals

- WebSocket/CONNECT over mesh unless separately planned.
- Changing the client-facing H1/H2/H3 stack.
- Replacing the mesh QUIC transport.
- Multi-worker stream sharing.
