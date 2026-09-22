# Phase 60 Plan: Eggfetch Consumer Migration and Legacy Transport Retirement

Status: detailed implementation handoff plan (2026-09-22).

Roadmap: `plans/eggfetch_0_2_transport_consolidation_roadmap.md`.

Depends on: Phase 59 differential parity passes.

## Primary goal

Move SynVoid production egress consumers onto the qualified eggfetch-backed transport lane in bounded batches, then remove only the legacy generic transport machinery that is truly unreachable and not required by the compatibility contract.

This phase must reduce active maintenance ownership. Merely adding eggfetch while leaving all production paths on the old implementation is not completion.

## Migration order

Migrate from lowest-risk leaf clients to the latency/security-critical reverse-proxy path.

Recommended order:

1. leaf updater/feed clients;
2. health/background HTTP clients;
3. honeypot/AI helper requests;
4. app-server/Granian helper traffic;
5. ordinary buffered proxy requests;
6. streaming reverse-proxy requests;
7. H3-originated upstream streaming requests;
8. any remaining root/server composition users.

Do not migrate all call sites in one mechanical patch.

After each batch, run focused tests for the owning crates and keep the legacy lane available for differential diagnosis until the phase-wide qualification point.

## Workstream A — Leaf updater/feed consumers

Inventory and migrate callers such as:

- GeoIP updater;
- YARA/rule feed downloader;
- other simple GET/HEAD/basic-auth update paths.

Use the eggfetch-backed internal client/helpers while preserving current:

- authentication header behavior;
- timeout;
- size limit;
- status/error mapping;
- no automatic redirect/retry behavior unless current SynVoid behavior already does so.

Do not enable eggfetch high-level auth/retry/redirect bundles solely to shorten call sites if that changes ownership semantics.

After migration, remove direct `synvoid-http-client` helper dependence from a leaf crate only if no other contract requires it.

## Workstream B — Health/background clients

Migrate upstream health checks and similar bounded background clients.

Preserve:

- interval/scheduling ownership outside the client;
- exact timeout intent;
- health success/failure classification;
- no implicit retries that make a single health probe become multiple network attempts;
- resolved/SNI/TLS policy where used.

Ensure cancellation on shutdown is not weakened by eggfetch response leases or pool admission.

## Workstream C — JSON/AI helper clients

Migrate honeypot/AI and similar JSON helpers.

SynVoid may continue to serialize JSON itself. Do not enable eggfetch's `json` feature unless it removes meaningful code/dependencies without changing behavior.

Preserve:

- request headers/content type;
- serialization errors;
- response body size/time bounds;
- status handling;
- caller-visible error mapping.

## Workstream D — App-server/internal HTTP clients

Migrate app-server/Granian and other internal HTTP clients that do not require the full proxy streaming path.

Keep logical authority/path behavior identical. If these use local loopback or UDS, use the already-qualified route rather than creating another connector implementation.

## Workstream E — Buffered proxy path

Migrate ordinary buffered upstream proxy sends after leaf/background traffic is stable.

Preserve:

- forward headers;
- Host/authority behavior;
- request/response security header flow;
- body limits;
- timeout;
- upstream selection and retry ownership;
- cache semantics;
- response transformation;
- metrics and trace points.

The transport adapter may return a different internal response body type, but the surrounding proxy pipeline must produce the same externally visible result.

## Workstream F — Streaming WAF proxy path

Migrate the true streaming path using eggfetch native generic-body execution.

The required shape is:

```text
Incoming/H3 body
   -> StreamingWafBody
   -> existing erased/generic compatibility layer as needed
   -> eggfetch execute_http_body<B>
   -> NativeResponseBody
   -> existing SynVoid streaming response pipeline
```

Do not insert:

- full request-body collection;
- a bytes-stream-only adapter that drops trailer frames;
- a second WAF scan;
- implicit retry of one-shot streaming bodies.

Preserve current one-shot/retry semantics exactly. If retry logic currently only replays buffered/idempotent bodies, keep that policy above transport.

## Workstream G — H3-originated upstream traffic

Migrate the H3-to-H1/H2 upstream bridge independently from inbound H3 server ownership.

Preserve:

- H3 request-body channel backpressure;
- WAF streaming;
- body error propagation;
- no accidental outbound H3 use;
- upstream H1/H2 ALPN behavior;
- bandwidth/worker metrics.

Do not enable eggfetch's `http3` feature for this path.

## Workstream H — Erased client/pool retirement analysis

After production migration, evaluate:

- `ErasedConnectionPool`;
- `ErasedHttpClient`;
- `PoolKey`;
- `ErasedBody` / `ErasedBodyImpl` / `BoxErasedBody`;
- custom Hyper connection checkout/checkin code.

Classify each as:

1. still required by compatibility API;
2. still required by production;
3. replaceable with standard `http_body_util` boxing;
4. dead and removable.

If the body-erasure types remain useful as a compatibility/body-shape adapter but the custom connection pool is obsolete, keep the former and delete the latter. Do not treat them as one indivisible module.

No legacy pool should remain active in production merely because public compatibility constructors still exist.

## Workstream I — Pool/cache ownership cleanup

Once production paths use eggfetch:

- remove redundant SynVoid client caches if eggfetch's configured client/pool already owns equivalent reuse;
- keep an outer per-policy client registry only if it is still needed to select immutable client configurations efficiently;
- avoid double-caching the same route/connection concept;
- ensure TLS/SNI/pool policy remains part of the outer key wherever a distinct eggfetch client is required.

A registry of configured clients is different from a second physical connection pool. Preserve the former if necessary; retire duplicate ownership of the latter.

## Workstream J — Dependency cleanup

After each removal, run `cargo tree` before deleting direct dependencies.

Candidates that may leave `synvoid-http-client` after full migration include direct ownership of:

- `hyperlocal`;
- some `hyper-rustls` construction dependencies;
- `rustls-native-certs`;
- `webpki-roots`;
- custom pool-only dependencies such as `moka`, if no remaining compatibility code needs them;
- direct `hyper-util` client builder features not otherwise needed by retained public compatibility types.

Do not remove a dependency merely because eggfetch also depends on it; the compatibility facade may still need the direct crate in its public type signatures.

Record before/after direct and transitive graphs.

## Workstream K — Compatibility lane freeze

For compatibility-bound legacy APIs that cannot be implemented on eggfetch without changing concrete type identity:

- keep them compiling;
- keep their existing behavior tests;
- document them as compatibility-only;
- ensure new production code does not use them;
- add a guard or focused test preventing production modules from drifting back to the compatibility lane where practical.

Do not mark them deprecated unless the project's API policy explicitly permits that user-visible change.

## Workstream L — Remove obsolete implementation code

Delete only code proven unused by both:

- migrated production paths;
- compatibility requirements.

Expected removal candidates may include portions of:

- `pool.rs`;
- `erased_pool.rs`;
- `tls.rs` client-config construction;
- `unix.rs`;
- request timeout/size wrapper duplication;
- client cache statics.

Keep `UpstreamTlsConfig` or compatibility helper types wherever they remain part of the stable SynVoid contract.

The target is not minimum LOC at any cost. The target is one active generic transport implementation.

## Verification after each migration batch

At minimum:

```bash
cargo fmt --all -- --check
cargo xtask test guards
cargo deny check
cargo audit
```

Run owning crate suites for each migrated batch. For the proxy/HTTP batches:

```bash
cargo nextest run -p synvoid-http-client -p synvoid-proxy -p synvoid-http -p synvoid-upstream --cargo-profile ci --profile ci
```

For H3:

```bash
cargo nextest run -p synvoid-http3 -p synvoid-http --cargo-profile ci --profile ci
```

Feature profiles after the final batch:

```bash
cargo check --no-default-features
cargo check --no-default-features --features post-quantum
cargo check --no-default-features --features mesh
cargo check --no-default-features --features dns
cargo check --no-default-features --features mesh,dns
```

Before Phase 60 closes:

```bash
cargo xtask verify
cargo xtask verify-full
```

## Acceptance criteria

Phase 60 is complete only when:

- production leaf/update/background consumers use the eggfetch lane;
- buffered reverse-proxy traffic uses the eggfetch lane;
- true streaming WAF traffic uses eggfetch native generic-body transport without full buffering;
- H3-originated upstream traffic uses the same qualified outbound H1/H2 lane;
- retry/upstream/WAF/cache policy remains owned by SynVoid;
- no production path uses the legacy physical connection pool unless a documented blocker remains;
- compatibility-bound public surfaces remain available and tested;
- obsolete pool/TLS/UDS/client-construction code is removed where safe;
- dependency cleanup is evidence-based;
- current architecture docs identify eggfetch as the active generic transport owner and distinguish any retained compatibility lane.

## Rejection criteria

Reject Phase 60 closure if:

- both transport implementations remain active on ordinary production traffic with no explicit split rationale;
- the migration changes retry count, redirect behavior, auth handling, or compression;
- streaming bodies are buffered;
- H3 inbound support is confused with eggfetch outbound H3;
- a public compatibility type is removed or changed only because in-workspace callers were migrated;
- a redundant custom pool remains active without a measured/functional requirement;
- code deletion outruns parity evidence.
