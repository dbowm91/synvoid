# Phase 61 Plan: Eggfetch Transport Qualification and Closeout

Status: detailed implementation handoff plan (2026-09-22).

Roadmap: `plans/eggfetch_0_2_transport_consolidation_roadmap.md`.

Depends on: Phase 60 production migration and cleanup complete.

## Primary goal

Prove that the eggfetch-backed egress architecture is at least as correct, secure, capable, and operationally bounded as the pre-migration SynVoid transport; quantify the maintenance/dependency/performance result; reconcile all current-state documentation; and leave exactly one truthful transport ownership story.

This phase does not add new transport features. It qualifies the migration, corrects any residual defects found by qualification, and closes or rolls back the campaign.

## Required closeout evidence

Create:

`architecture/eggfetch_0_2_transport_closeout.md`

The closeout must record:

- pre-campaign SynVoid baseline SHA;
- eggfetch version/tag and feature set;
- proof-bearing implementation/qualification SHA;
- exact production transport owner after migration;
- retained compatibility surfaces and why each remains;
- deleted legacy machinery;
- direct/transitive dependency before/after summary;
- TLS/provider/PQ qualification;
- generic-body/streaming/trailer qualification;
- H1/H2/pool/UDS/resolved-target qualification;
- performance evidence;
- verification commands and results;
- any intentional residuals;
- final disposition of `synvoid-http-client` publication/classification.

Do not rewrite the historical Phase 34 record. Link it as superseded decision history.

## Workstream A — Full egress parity suite

Run the final production path, not a test-only adapter.

The suite must cover at least:

### Protocol and reuse

- H1 request/response;
- H1 keepalive reuse;
- H2 ALPN;
- H2 multiplexing/concurrency;
- connection close/reconnect;
- closed upstream;
- malformed/invalid destination failure.

### Request body

- empty;
- fixed bytes;
- multi-chunk generic body;
- unknown-length body;
- `StreamingWafBody`;
- H3-originated channel body;
- request-body error;
- early cancellation/drop;
- request trailers if part of the supported SynVoid contract.

### Response body

- buffered helper path;
- streaming body;
- response size limit;
- response body error;
- response trailers;
- early response drop;
- timeout while body is incomplete.

### Routing

- ordinary DNS/TCP route;
- SNI override;
- resolved/pinned addresses;
- route-cache separation across logical origins/SNI/ordered address sets;
- UDS on Unix;
- truthful unsupported UDS behavior off Unix.

### Helper/API behavior

- Basic-auth helper behavior retained where still public;
- JSON helper behavior retained where still public;
- custom headers;
- HEAD;
- status/error mapping;
- `quictunnel://` predicate/dispatch remains owned outside eggfetch.

## Workstream B — TLS and cryptographic qualification

This is a release/security gate.

Required:

- matching trusted certificate succeeds;
- hostname mismatch fails under normal verification;
- custom CA works;
- invalid/empty CA fails closed;
- native-root/default behavior remains truthful;
- chain-valid hostname-skip succeeds;
- untrusted-chain hostname-skip fails;
- SNI override uses intended certificate identity;
- explicit aws-lc provider is used for eggfetch TLS clients;
- `post-quantum` feature preserves the existing PQ preference contract;
- no provider-ambiguity panic occurs in normal/default/minimal/profile tests.

Search for remaining process-default-sensitive Rustls builders introduced or exposed by the feature graph. Correct only those necessary for deterministic provider selection; do not broaden into unrelated crypto refactoring.

Run:

```bash
cargo tree -i ring
cargo tree -i aws-lc-rs
cargo tree -i rustls
```

Record whether Ring/aws-lc package or feature multiplicity changed from Phase 58.

## Workstream C — API compatibility qualification

Use the Phase 58 export inventory as the checklist.

For every item classified compatibility-bound:

- compile the existing signature/type;
- run its retained behavior test;
- ensure root re-export path remains;
- ensure documentation does not imply a stronger stability promise than actually exists.

For concrete Hyper aliases that remain compatibility-only, verify they are not used by the migrated production modules identified in Phase 60.

Add a repository guard or focused ownership test if static imports can reliably enforce "production uses eggfetch lane; legacy concrete facade remains compatibility-only."

Do not delete compatibility code during closeout simply because it is unused internally.

If Phase 60 intentionally changed a public signature/type, Phase 61 must fail until that change is reverted or a separate explicit compatibility-breaking decision is approved outside this campaign.

## Workstream D — Dependency and maintenance-surface accounting

Capture before/after:

- direct dependencies of `synvoid-http-client`;
- transitive transport stack;
- duplicate versions of Hyper/Hyper-util/Hyper-rustls/Rustls/HTTP/HTTP-body/Tokio/Bytes;
- direct `hyperlocal`, `moka`, root-store, and client-builder ownership;
- source files/LOC in the active SynVoid generic transport implementation;
- number of active physical connection-pool implementations;
- number of TLS client-config construction implementations used in production.

The goal is not an artificial LOC target. The closeout must demonstrate that eggfetch actually removed active generic-transport maintenance ownership.

If both SynVoid and eggfetch still independently own physical H1/H2 pooling on production traffic, the consolidation objective is not met.

## Workstream E — Performance qualification

Use one host/toolchain/profile for before/after and identify the exact immutable revisions.

At minimum measure representative:

1. H1 keepalive small request throughput/latency;
2. H2 concurrent/multiplexed small requests;
3. streaming request + streaming response with approximately:
   - 1 KiB;
   - 64 KiB;
   - 1 MiB payloads where practical;
4. concurrent streaming batches;
5. early response-body drop/cancellation;
6. pool saturation/backpressure behavior.

Record throughput plus p50/p95/p99 where the harness supports it. For focused Criterion-style transport operations, record confidence intervals.

The performance target is "no material unexplained regression." Treat >5% regression in a primary comparable metric as material until explained.

A measured regression can be accepted only when:

- it is understood;
- correctness/security is improved or maintenance reduction is substantial;
- tail-latency/throughput impact is operationally acceptable;
- the rationale is explicit in the closeout.

Do not tune away a security or backpressure invariant to recover benchmark numbers.

## Workstream F — Failure and cancellation stress

Exercise bounded adverse cases:

- upstream accepts then stalls before headers;
- headers arrive then body stalls;
- body sends partial data then resets;
- DNS/connect failure;
- repeated connect failures;
- pool admission saturation;
- dropped caller future;
- server closes keepalive;
- H2 stream reset;
- invalid resolved target;
- invalid UDS path.

Verify:

- no leaked permits/leases;
- no unbounded task accumulation;
- subsequent healthy request recovers;
- timeout phase/error maps appropriately;
- no panic from Rustls provider ambiguity;
- no retry is introduced below SynVoid's retry owner.

## Workstream G — Full repository/profile qualification

Focused egress:

```bash
cargo nextest run -p synvoid-http-client -p synvoid-upstream -p synvoid-proxy -p synvoid-http -p synvoid-http3 --cargo-profile ci --profile ci
cargo test -p synvoid-http-client --doc --profile ci
```

Feature profiles:

```bash
cargo check --no-default-features
cargo check --no-default-features --features post-quantum
cargo check --no-default-features --features mesh
cargo check --no-default-features --features dns
cargo check --no-default-features --features mesh,dns
```

Repository gates:

```bash
cargo fmt --all -- --check
cargo xtask verify
cargo xtask verify-full
cargo xtask verify-release
cargo deny check
cargo audit
```

Do not claim a gate passed if it was not run. Record environmental blockers separately from product failures.

## Workstream H — Documentation and state reconciliation

Update current-state documentation to match the final implementation.

At minimum review:

- `plans/eggfetch_current_line_parity_review.md`;
- `plans/eggfetch_0_2_transport_consolidation_roadmap.md`;
- `plans/roadmap.md`;
- `architecture/public_crate_release_readiness_phase47.md` (historical pointer only; do not rewrite old evidence);
- `architecture/runtime_truthfulness_security_publication_closeout.md` (follow-up disposition);
- `architecture/crate_granularity_audit.md`;
- `architecture/http_shared.md`;
- `architecture/http_client_deep_dive.md`;
- `.opencode/skills/http_client/SKILL.md`;
- `src/http_client/AGENTS.override.md`;
- `AGENTS.md` if current-state ownership changes.

Historical documents should gain supersession pointers rather than having old facts rewritten as though they were never true.

## Workstream I — Public-crate disposition

Re-evaluate the Phase 47 classification of `synvoid-http-client`.

Preferred outcome if eggfetch adoption succeeds:

- `synvoid-http-client` remains internal/class 1-2 as a SynVoid-specific compatibility/policy adapter;
- eggfetch is the reusable public generic HTTP client;
- SynVoid does not publish a competing generic transport crate.

If a substantial compatibility facade remains because root public API requires concrete Hyper types, document that as an internal compatibility burden, not a reason to market `synvoid-http-client` as a separate general-purpose library.

## Workstream J — Closeout or rollback

### Adopted branch

Mark Phases 58-61 and the campaign closed only if:

- production uses eggfetch for qualified generic transport;
- redundant active transport machinery is gone;
- compatibility lane is narrow and justified;
- tests/security/profiles pass;
- performance is acceptable;
- docs agree.

### Retained/rollback branch

If final qualification discovers a blocker that invalidates adoption:

- switch production paths back to the proven legacy owner;
- remove eggfetch production adapter/dependency if no other use remains;
- retain the Phase 58/61 evidence;
- document the exact blocker and future revisit condition;
- restore one unambiguous production transport owner.

Do not leave a failed migration as permanent dual-path complexity.

## Acceptance criteria

Phase 61 is complete only when:

- all required parity/security/API tests pass on the final production path;
- explicit aws-lc/PQ behavior is proven;
- H1/H2 streaming, trailers, cancellation, UDS, and resolved-target behavior are qualified;
- full feature/profile/repository gates are green or environmental omissions are truthfully documented;
- performance comparison is recorded against immutable revisions;
- active generic transport ownership is singular;
- retained compatibility code is clearly distinguished from production transport;
- dependency/maintenance reduction is quantified;
- public-crate disposition is updated;
- architecture/skills/roadmaps agree;
- `architecture/eggfetch_0_2_transport_closeout.md` records the proof-bearing SHA and final branch.

## Rejection criteria

Reject closeout if it:

- treats passing unit tests as a substitute for production-path differential/black-box qualification;
- claims source compatibility while concrete public type identity changed;
- claims PQ parity without explicit provider evidence;
- ignores a hostname-skip trust-chain regression;
- ignores leaked permits/tasks under cancellation;
- accepts an unexplained >5% primary transport regression without analysis;
- leaves both physical transport implementations active by default;
- labels historical Phase 34 evidence as wrong rather than superseded by later upstream capability;
- closes planning before current-state docs identify the actual transport owner.
