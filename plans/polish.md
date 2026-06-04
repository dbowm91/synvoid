# Architecture Polish Plan

## Goal
Resolve the architectural contradictions in SynVoid's data plane and trust model without destabilizing the existing product direction.

The target end state is:
- a latency-sensitive unified worker that handles network I/O and cheap request-path work,
- a bounded CPU offload plane derived from the existing static worker,
- a clear scaling contract,
- and a complete mesh authentication story.

## Status (Last Updated: 2026-06-04)

| Phase | Status | Summary |
|-------|--------|---------|
| 1. Settle The Scaling Contract | **COMPLETE** | Docs (ADR-003, ARCHITECTURE.md, PROCESS_MANAGEMENT.md) all agree on 1+N model |
| 2. Generalize Static Worker | **COMPLETE** | `StaticWorker*` renamed to `CpuWorker*`; generic `CpuTaskRequest`/`CpuTaskResult` envelope in place; legacy message flow cleaned up (response_builder returns CpuTaskResult directly) |
| 3. Define Offload Boundaries | **COMPLETE** | Minify/compress/YARA/WASM offloaded. Inline transforms bounded by design for already-buffered upstream responses |
| 4. Backpressure & Fallback | **COMPLETE** | Per-site/global active+queue limits, 4 policy variants (FailClosed/FailOpen/SkipTransform/DegradeToInlineSmallOnly), per-task deadlines, output size caps |
| 5. IPC Layer | **COMPLETE** | Generic task envelope with kind/priority/policy/deadline/payload limits, file-backed payloads (256KB threshold), bounded in-flight per connection |
| 6. Multi-Worker Story | **DEFERRED** | Multi-worker kept as advanced mode only. Pre-bind port check fixed (`should_skip_prebind_port_check`). Cross-worker cache/state replication not implemented (correctly deferred — only needed if multi-worker is primary) |
| 7. Mesh Trust | **PARTIAL** | TLS modes (Strict/Tofu/Permissive) implemented; `verify_peer_certificate()` wired into handshake; DhtSyncRequest/DhtAntiEntropyRequest/DhtRecordPush signed; replay protection on all DHT messages; MESH-14 PKI hierarchy implemented (CertChain, NodeCertBinding, verify_certificate_chain, config-gated enforcement). DHT handler integration incomplete: `signer_public_key` not verified against `certified_public_key` in NodeCertBinding (MR-4). |
| 8. HTTP/2 Pooling | **COMPLETE** | `Http2PooledConnection` stub removed; HTTP/2 pooling via `TypedClientPool` |
| 9. Refactor Hot Paths | **COMPLETE** | 43+ modules extracted from http/; `server.rs` reduced from 1,243 to 795 lines (observability, connection types, accept loop extracted) |
| 10. Observability | **COMPLETE** | All metrics implemented: event-loop lag, queue time, active connections, offload submissions/fallbacks (unified); queue depth/duration/rejection/timeout/RSS by 6 task kinds (CPU worker) |
| WASM Offload | **COMPLETE** | WASM response transforms offloaded to CPU worker via `WasmTransformResponse` IPC payload. Reuses `WasmInstancePool` for instance reuse. `FailOpenWithLog` policy |

## Summary
The current codebase has three architectural issues that need to be resolved together:
- The public architecture docs still describe a shared-nothing multi-worker proxy model.
- ADR-003 describes a single unified async worker that should not be scaled by `unified_server_workers`.
- The current static worker is already acting as a CPU offload process, but its scope is too narrow and its interface is task-specific.

The plan below keeps the unified worker simple, generalizes the static worker into a generalized CPU worker, and closes the mesh trust gaps that are currently deferred.

## Phase 1: Settle The Scaling Contract ✅

### Decision
Pick one primary data-plane model and document it consistently.

Recommended default:
- `1 unified worker + N CPU offload workers`

Why:
- It keeps the unified worker event loop focused on I/O, routing, WAF header checks, and streaming proxying.
- It gives CPU-heavy work an explicit isolation boundary.
- It avoids pretending that more unified workers automatically solve CPU-bound latency problems.

### Required Documentation Changes
- ~~Update [ADR-003](../docs/adr/ADR-003-unified-worker-process.md) to define the unified worker as the latency-sensitive plane and the CPU workers as the offload plane.~~ ✅ Done
- ~~Update [ARCHITECTURE.md](../docs/ARCHITECTURE.md) so it no longer claims shared-nothing linear scaling as the default story if the default deployment is a single unified worker.~~ ✅ Done
- ~~Update [PROCESS_MANAGEMENT.md](../docs/PROCESS_MANAGEMENT.md) to reflect the actual role of each process type.~~ ✅ Done

### Success Criteria
- ~~The docs agree on the default process model.~~ ✅
- ~~`unified_server_workers` is no longer presented as a general-purpose scaling knob.~~ ✅
- ~~The relationship between `worker_threads`, `tcp.worker_pool_size`, and CPU offload workers is unambiguous.~~ ✅

## Phase 2: Generalize The Static Worker Into A CPU Offload Worker ✅

### Decision
Keep the existing static worker as the implementation seed, but make its role broader than static file optimization.

Recommended name:
- `CpuWorker`

### What It Should Handle
The worker should own CPU-heavy jobs that do not belong on the unified event loop:
- HTML, CSS, and JavaScript minification
- gzip and Brotli precompression
- image poisoning and transformation
- expensive body scanning
- YARA scans
- WASM/plugin execution
- serverless invocation
- other bounded heavy transforms

### What It Should Not Handle
- Socket accept
- TLS handshakes
- HTTP parsing
- routing
- cheap header and method checks
- rate limiting counters
- request streaming
- cheap WAF decisions

### Required Architectural Shift
- ~~`StaticWorker*` types, IPC messages, and functions renamed to `CpuWorker*`~~ ✅ Done (25+ files, external interfaces preserved)
- ~~Generic typed task model with request id, task kind, priority, deadline, payload size limit, structured output/error~~ ✅ Done (`CpuTaskRequest`, `CpuTaskResult`, `CpuTaskError` in ipc.rs)
- ~~Legacy task-specific IPC messages cleaned up~~ ✅ Done (`response_builder` returns `CpuTaskResult` directly)

### Success Criteria
- ~~Static optimization remains functional through compatibility wrappers.~~ ✅
- ~~New CPU-heavy tasks can be added without introducing new one-off IPC protocols.~~ ✅ (WasmTransformResponse added as example)
- ~~The worker can be reused for non-static CPU workloads.~~ ✅

## Phase 3: Define Offload Boundaries ✅

### Keep Inline In The Unified Worker
These remain in the unified worker:
- listener accept
- TLS orchestration
- HTTP parsing
- routing
- cheap WAF checks
- rate-limit accounting
- cache-hit response serving
- proxy streaming

### Offload To CPU Workers
These are offloaded:
- ~~minification~~ ✅
- ~~compression~~ ✅
- ~~image transforms~~ ✅
- ~~YARA scanning~~ ✅
- ~~WASM/plugin execution~~ ✅ (response transforms via `WasmTransformResponse`)
- serverless execution (existing `WasmExecute` handler, serverless ABI)
- heavy body inspection
- deep regex work

### Rule Of Thumb
- Inline if the work is small, bounded, and predictably cheap.
- Offload if the cost depends on body size, regex complexity, plugin behavior, or compression/transformation work.

### Success Criteria
- ~~The unified worker does not accumulate CPU-heavy responsibilities by accident.~~ ✅
- ~~New expensive features are classified before implementation, not after.~~ ✅

## Phase 4: Add Backpressure And Fallback Policy ✅

Offloading only works if it is bounded.

### Required Controls
- ~~per-site active task limit~~ ✅ (`max_active_per_site: 32`)
- ~~per-site queue limit~~ ✅ (`max_queue_per_site: 256`)
- ~~global active task limit~~ ✅ (`max_active_global: 128`)
- ~~global queue limit~~ ✅ (`max_queue_global: 1024`)
- ~~per-task deadline~~ ✅ (checked before and after execution)
- ~~per-task output size cap~~ ✅ (enforced for all task types)
- ~~worker RSS and payload memory cap~~ ✅ (`max_payload_bytes: 64MB`, `max_output_bytes: 64MB`)

### Required Task Policies
Each task declares what happens when the worker is unavailable or slow:
- ~~`FailClosed`~~ ✅ (used for YARA scans)
- ~~`FailOpenWithLog`~~ ✅ (used for WASM transforms, optional enrichment)
- ~~`SkipTransform`~~ ✅ (used for minification, compression)
- ~~`DegradeToInlineSmallOnly`~~ ✅ (used for image poisoning, inline fallback for small payloads)

### Success Criteria
- ~~A saturated CPU worker pool degrades predictably.~~ ✅
- ~~A failed CPU worker does not wedge the unified worker.~~ ✅
- ~~Queue saturation is visible and measurable.~~ ✅

## Phase 5: Make The IPC Layer Fit General Offload ✅

### Required IPC Changes
- ~~add a generic task envelope~~ ✅ (`CpuTaskRequest` with kind, priority, policy, deadline, payload/output limits)
- ~~keep typed task payloads~~ ✅ (`CpuTaskPayload` enum with 7 variants)
- ~~support bounded in-flight requests per connection~~ ✅ (configurable, default 1 per connection)
- ~~use worker selection based on queue depth or task kind~~ ✅ (`acquire_for_task_kind()` with per-task-kind overrides)
- ~~propagate deadlines~~ ✅ (deadline_unix_ms checked before and after execution)
- ~~support file-backed payloads for large bodies~~ ✅ (`apply_file_backed_payload()` with 256KB threshold)

### Payload Strategy
- ~~inline payloads for small requests~~ ✅
- ~~file-backed payloads for larger bodies~~ ✅
- ~~reject oversized payloads rather than letting IPC become a transport for arbitrarily large bodies~~ ✅

### Security Requirements
- ~~keep signed IPC mandatory for privileged work~~ ✅
- ~~keep replay protection~~ ✅
- ~~keep size caps enforced~~ ✅
- ~~keep path handling opaque to the caller~~ ✅

### Success Criteria
- ~~Unified worker can offload multiple task kinds through one transport model.~~ ✅
- ~~Large bodies do not overload the IPC channel.~~ ✅
- ~~Task cancellation and timeout behavior is deterministic.~~ ✅

## Phase 6: Fix Or Remove The Multi-Unified-Worker Story (DEFERRED)

Multi-worker is documented as advanced isolation mode, not primary scaling. Cross-worker state replication is correctly deferred.

### Completed
- ~~Stop using a normal pre-bind port conflict check for the SO_REUSEPORT path~~ ✅ (`should_skip_prebind_port_check()`)
- ~~Clarify which state is per-worker and which state is globally aggregated~~ ✅ (documented in ADR-003 and PROCESS_MANAGEMENT.md)

### Deferred (only needed if multi-worker becomes primary)
- Cross-worker cache invalidation
- Cross-worker state replication
- Metrics aggregation beyond Supervisor heartbeat sum

### Success Criteria
- ~~There is no ambiguity about whether `unified_server_workers` is a primary scaling knob.~~ ✅
- ~~Port checks do not conflict with intended shared-port behavior.~~ ✅
- State replication semantics are explicit. (Deferred — correctly not implemented)

## Phase 7: Complete Mesh Trust Architecture (PARTIAL)

### MESH-14: Peer Certificate Validation ✅

**Completed:**
- ~~Define explicit mesh TLS modes (strict, tofu, permissive)~~ ✅ (`MeshTlsMode` enum in config.rs)
- ~~Make strict the production default~~ ✅ (`#[default] Strict`)
- ~~Wire `verify_peer_certificate()` into the handshake path~~ ✅ (`verify_peer_connection_certificate_if_available()` at transport.rs:2491, 2969)
- ~~Enforce revocation checks~~ ✅ (CRL checked in `verify_peer_certificate()`)
- ~~Add tests for mode behaviors, revocation, identity binding~~ ✅ (16+ tests in cert.rs and transport.rs)
- ~~PKI hierarchy for global nodes~~ ✅ (`CertChain` struct, `verify_certificate_chain()`, `NodeCertBinding` DHT record, `GlobalNodeAnnounce` carries optional cert chain, config-gated enforcement via `require_pki_binding`)
- ~~10 tests for cert chain verification~~ ✅ (valid chain, wrong node_id, unknown CA, tampered cert/sig, issuer mismatch, multiple CAs, binding roundtrip)

### MR-4: Signed DHT Sync Requests

**Completed:**
- ~~Introduce a signed request version~~ ✅ (DhtSyncRequest, DhtAntiEntropyRequest, DhtRecordPush all have signature fields)
- ~~Add timestamp, nonce, signature, and signer public key~~ ✅
- ~~Require stable canonical bytes for signing~~ ✅ (`DhtSyncRequestSignable`, `DhtAntiEntropyRequestSignable`, `DhtRecordPushEnvelopeSignable`)
- ~~Add replay protection~~ ✅ (per-peer `ReplayProtection` with nonce+timestamp window; added to DhtAntiEntropyRequest handler)
- ~~Support only temporary legacy compatibility for unsigned peers~~ ✅ (`unsigned_sync_compat_until_unix` config)
- ~~Move to default deny for unsigned sync~~ ✅ (`require_signed_sync_requests` defaults to true)

**Remaining (PARTIAL):**
- BindP: DHT handlers verify `node_id` has a `NodeCertBinding` when `require_pki_binding=true`, but do NOT verify that `signer_public_key` matches the `certified_public_key` in that binding. The `validate_peer_node_id_binding()` path (transport_peer.rs) correctly links these, but the DHT handler path (transport_dht.rs) has the gap — it checks binding existence but not `signer_public_key` ↔ `certified_public_key` equivalence. MESH-14 infrastructure is complete; DHT handler integration is incomplete.

### Success Criteria
- ~~Mesh peer identity is not optional in production.~~ ✅ (Strict mode default)
- ~~DHT sync is authenticated.~~ ✅
- ~~Legacy compatibility is explicit and temporary.~~ ✅
- ~~L1↔L4 binding for global nodes.~~ ✅ (CertChain + NodeCertBinding + verify_certificate_chain + config-gated enforcement)

## Phase 8: Treat HTTP/2 Pooling As A Separate Concern ✅

- ~~Keep the current typed full-body HTTP/2 path if it is stable~~ ✅ (`TypedClientPool` in typed_pool.rs)
- ~~Document the streaming limitation honestly~~ ✅
- `Http2PooledConnection` stub removed; HTTP/2 pooling fully implemented via `TypedClientPool`

### Success Criteria
- ~~The codebase does not overclaim full HTTP/2 support.~~ ✅
- ~~The HTTP client story is accurate and bounded.~~ ✅

## Phase 9: Refactor Hot Paths Carefully ✅

### Current State
- 43+ modules extracted from `src/http/`
- `server.rs` reduced from 1,243 to 795 lines
- Sub-modules: `accept_loop.rs` (186), `connection_types.rs` (176), `observability.rs` (141), `request_preparation.rs` (455), `backend_dispatch.rs` (348), `traffic_control.rs` (110)

### Success Criteria
- ~~Security-sensitive request paths are easier to audit.~~ ✅
- ~~Large files become navigable without introducing behavior drift.~~ ✅

## Phase 10: Add Observability Before Broadening Offload ✅

### Unified Worker Metrics
- ~~event-loop lag~~ ✅ (`event_loop_lag_ms`)
- ~~request queue time~~ ✅ (`request_queue_samples`)
- ~~active connections~~ ✅ (`active_connections`)
- ~~body buffering bytes~~ ✅
- ~~inline CPU time per phase~~ ✅
- ~~offload submissions~~ ✅ (`offload_submissions_total`)
- ~~offload fallback counts~~ ✅ (`offload_fallbacks_total`)
- ~~timeout counts~~ ✅

### CPU Worker Metrics
- ~~queue depth by task kind~~ ✅ (6 task kinds tracked)
- ~~active tasks by task kind~~ ✅
- ~~task duration histograms~~ ✅ (p50/p95/p99 per task kind)
- ~~task rejection counts~~ ✅ (`CPU_TASK_REJECTED_TOTAL`)
- ~~task timeout counts~~ ✅ (`CPU_TASK_TIMEOUT_TOTAL`)
- ~~worker RSS~~ ✅ (`worker_rss_bytes`)
- ~~payload bytes in/out~~ ✅

### Success Criteria
- ~~The team can prove the unified worker remains responsive under CPU-heavy load.~~ ✅
- ~~CPU offload decisions are driven by data, not intuition.~~ ✅

## Acceptance Criteria
This plan is complete when:
- ~~the docs, ADRs, and code agree on the worker model~~ ✅
- ~~CPU-heavy work is offloaded through a bounded generalized worker~~ ✅
- ~~the unified worker stays focused on latency-sensitive I/O~~ ✅
- ~~mesh peer trust is enforced in production~~ ⚠️ PARTIAL (TLS modes + signed DHT sync + MESH-14 PKI hierarchy complete; DHT handler BindP integration incomplete — MR-4)
- ~~and the remaining deferred items are clearly labeled as deliberate, not accidental~~ ✅
