# Architecture Polish Plan

## Goal
Resolve the architectural contradictions in SynVoid’s data plane and trust model without destabilizing the existing product direction.

The target end state is:
- a latency-sensitive unified worker that handles network I/O and cheap request-path work,
- a bounded CPU offload plane derived from the existing static worker,
- a clear scaling contract,
- and a complete mesh authentication story.

## Summary
The current codebase has three architectural issues that need to be resolved together:
- The public architecture docs still describe a shared-nothing multi-worker proxy model.
- ADR-003 describes a single unified async worker that should not be scaled by `unified_server_workers`.
- The current static worker is already acting as a CPU offload process, but its scope is too narrow and its interface is task-specific.

The plan below keeps the unified worker simple, generalizes the static worker into a generalized CPU worker, and closes the mesh trust gaps that are currently deferred.

## Phase 1: Settle The Scaling Contract

### Decision
Pick one primary data-plane model and document it consistently.

Recommended default:
- `1 unified worker + N CPU offload workers`

Why:
- It keeps the unified worker event loop focused on I/O, routing, WAF header checks, and streaming proxying.
- It gives CPU-heavy work an explicit isolation boundary.
- It avoids pretending that more unified workers automatically solve CPU-bound latency problems.

### Required Documentation Changes
- Update [ADR-003](../docs/adr/ADR-003-unified-worker-process.md) to define the unified worker as the latency-sensitive plane and the CPU workers as the offload plane.
- Update [ARCHITECTURE.md](../docs/ARCHITECTURE.md) so it no longer claims shared-nothing linear scaling as the default story if the default deployment is a single unified worker.
- Update [PROCESS_MANAGEMENT.md](../docs/PROCESS_MANAGEMENT.md) to reflect the actual role of each process type.

### Success Criteria
- The docs agree on the default process model.
- `unified_server_workers` is no longer presented as a general-purpose scaling knob.
- The relationship between `worker_threads`, `tcp.worker_pool_size`, and CPU offload workers is unambiguous.

## Phase 2: Generalize The Static Worker Into A CPU Offload Worker

### Decision
Keep the existing static worker as the implementation seed, but make its role broader than static file optimization.

Recommended name:
- `CpuWorker`

Alternative acceptable name:
- `TransformWorker`

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
The current message set is task-specific:
- `MinifyRequest`
- `GetCompressedRequest`
- `PoisonImageRequest`

That must become a generic, typed task model with:
- request id
- task kind
- priority
- deadline
- payload size limit
- optional file-backed payload reference
- structured output
- structured error

### Success Criteria
- Static optimization remains functional through compatibility wrappers.
- New CPU-heavy tasks can be added without introducing new one-off IPC protocols.
- The worker can be reused for non-static CPU workloads.

## Phase 3: Define Offload Boundaries

### Keep Inline In The Unified Worker
These should remain in the unified worker:
- listener accept
- TLS orchestration
- HTTP parsing
- routing
- cheap WAF checks
- rate-limit accounting
- cache-hit response serving
- proxy streaming

### Offload To CPU Workers
These should move out of the unified worker when they become expensive:
- minification
- compression
- image transforms
- YARA scanning
- WASM/plugin execution
- serverless execution
- heavy body inspection
- deep regex work

### Rule Of Thumb
- Inline if the work is small, bounded, and predictably cheap.
- Offload if the cost depends on body size, regex complexity, plugin behavior, or compression/transformation work.

### Success Criteria
- The unified worker does not accumulate CPU-heavy responsibilities by accident.
- New expensive features are classified before implementation, not after.

## Phase 4: Add Backpressure And Fallback Policy

Offloading only works if it is bounded.

### Required Controls
- per-site active task limit
- per-site queue limit
- global active task limit
- global queue limit
- per-task deadline
- per-task output size cap
- worker RSS and payload memory cap

### Required Task Policies
Each task must declare what happens when the worker is unavailable or slow:
- `FailClosed`
- `FailOpenWithLog`
- `SkipTransform`
- `DegradeToInlineSmallOnly`

### Suggested Policy Defaults
- `FailClosed` for security-sensitive scans and auth-sensitive plugin execution
- `SkipTransform` for minification and compression
- `FailOpenWithLog` for optional enrichment

### Success Criteria
- A saturated CPU worker pool degrades predictably.
- A failed CPU worker does not wedge the unified worker.
- Queue saturation is visible and measurable.

## Phase 5: Make The IPC Layer Fit General Offload

### Current State
The static worker client already supports:
- signed IPC
- async connection reuse
- request ids
- timeout handling
- response demux across concurrent in-flight requests on a pooled connection

That is a good starting point, but it is not yet a general-purpose task dispatcher.

### Required IPC Changes
- add a generic task envelope
- keep typed task payloads
- support bounded in-flight requests per connection
- use worker selection based on queue depth or task kind
- propagate deadlines
- support file-backed payloads for large bodies

### Payload Strategy
- inline payloads for small requests
- file-backed payloads for larger bodies
- reject oversized payloads rather than letting IPC become a transport for arbitrarily large bodies

### Security Requirements
- keep signed IPC mandatory for privileged work
- keep replay protection
- keep size caps enforced
- keep path handling opaque to the caller

### Success Criteria
- Unified worker can offload multiple task kinds through one transport model.
- Large bodies do not overload the IPC channel.
- Task cancellation and timeout behavior is deterministic.

## Phase 6: Fix Or Remove The Multi-Unified-Worker Story

### Problem
The codebase currently mixes:
- a shared-nothing multi-worker story
- a single-worker ADR
- SO_REUSEPORT listener assumptions
- pre-bind port checks that are not compatible with the intended multi-worker flow

### Required Decision
Either:
1. treat multi-unified-worker mode as advanced and clearly documented, or
2. remove the claim that it is the primary scaling mechanism.

Recommended:
- keep it as an advanced mode only after the listener and state-sharing semantics are made correct

### Required Fixes If Multi-Worker Remains Supported
- stop using a normal pre-bind port conflict check for the SO_REUSEPORT path
- let listener creation be the source of truth
- clarify which state is per-worker and which state is globally aggregated
- make metrics aggregation supervisor-owned
- define cache invalidation and reload semantics across workers

### Success Criteria
- There is no ambiguity about whether `unified_server_workers` is a primary scaling knob.
- Port checks do not conflict with intended shared-port behavior.
- State replication semantics are explicit.

## Phase 7: Complete Mesh Trust Architecture

The mesh story is not complete until peer authentication and signed sync are wired into the connection path.

### MESH-14: Peer Certificate Validation
Current issue:
- certificate verification exists
- it is not wired into connection establishment
- permissive mode can accept peers without a CA

Plan:
1. Define explicit mesh TLS modes:
   - `strict`
   - `tofu`
   - `permissive`
2. Make `strict` the production default for mesh-enabled deployments.
3. Wire `verify_peer_certificate()` into the handshake path.
4. Bind `node_id` to certificate identity or certified public key.
5. Enforce revocation checks.
6. Add tests for unknown, revoked, mismatched, and legacy cases.

### MR-4: Signed DHT Sync Requests
Current issue:
- `DhtSyncRequest` is unsigned
- the protocol currently trusts the request shape without proving sender authenticity

Plan:
1. Introduce a signed request version.
2. Add timestamp, nonce, signature, and signer public key.
3. Require stable canonical bytes for signing.
4. Add replay protection.
5. Support only temporary legacy compatibility for unsigned peers.
6. Move to default deny for unsigned sync once rollout is complete.

### Success Criteria
- Mesh peer identity is not optional in production.
- DHT sync is authenticated.
- Legacy compatibility is explicit and temporary.

## Phase 8: Treat HTTP/2 Pooling As A Separate Concern

The HTTP/2 streaming pool limitation is real, but it is not the same class of problem as CPU offload or mesh auth.

### Plan
- keep the current typed full-body HTTP/2 path if it is stable
- document the streaming limitation honestly
- only implement full HTTP/2 streaming pooling if it materially changes supported workloads

### Success Criteria
- The codebase does not overclaim full HTTP/2 support.
- The HTTP client story is accurate and bounded.

## Phase 9: Refactor Hot Paths Carefully

### Challenge To ADR-004
Keeping huge request pipeline files intact is defensible only if the phase boundaries are truly clear and stable.

### Recommended Refactor Style
Split by architectural phase, not by arbitrary helpers:
- request parse
- routing
- WAF header checks
- body policy
- body streaming
- upstream proxy
- response transform
- error responses
- observability

### Rules
- no behavior changes in the first split
- move tests with the split
- keep orchestration readable
- avoid growing `pub(crate)` reach unnecessarily

### Success Criteria
- Security-sensitive request paths are easier to audit.
- Large files become navigable without introducing behavior drift.

## Phase 10: Add Observability Before Broadening Offload

### Unified Worker Metrics
- event-loop lag
- request queue time
- active connections
- body buffering bytes
- inline CPU time per phase
- offload submissions
- offload fallback counts
- timeout counts

### CPU Worker Metrics
- queue depth by task kind
- active tasks by task kind
- task duration histograms
- task rejection counts
- task timeout counts
- worker RSS
- payload bytes in/out
- cache hit rates

### Success Criteria
- The team can prove the unified worker remains responsive under CPU-heavy load.
- CPU offload decisions are driven by data, not intuition.

## Execution Order
1. Align the docs and architecture contract.
2. Generalize the static worker into a CPU worker.
3. Add generic task envelopes and bounded queueing.
4. Move heavy workloads into the offload plane.
5. Fix the multi-worker story or explicitly demote it.
6. Complete mesh peer authentication and signed DHT sync.
7. Update HTTP/2 documentation to match reality.
8. Refactor hot paths only after the architecture is stable.

## Acceptance Criteria
This plan is complete when:
- the docs, ADRs, and code agree on the worker model,
- CPU-heavy work is offloaded through a bounded generalized worker,
- the unified worker stays focused on latency-sensitive I/O,
- mesh peer trust is enforced in production,
- and the remaining deferred items are clearly labeled as deliberate, not accidental.
