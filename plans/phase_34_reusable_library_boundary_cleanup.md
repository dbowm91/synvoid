# Phase 34 Plan: Reusable Library Boundary Cleanup and Egress Decision Gate

Status: planned (2026-09-16).

Roadmap: `plans/crate_boundary_reuse_followup_roadmap.md`.

Primary goal: tighten the reusable boundaries of `synvoid-dnssec-keystore` and `synvoid-http-client`, then make an evidence-based decision about whether SynVoid should continue owning generic HTTP transport machinery or consume `eggfetch-core` behind SynVoid-specific adapters.

This phase is deliberately a decision gate, not a mandate to replace a working client stack.

## Part A — DNSSEC keystore dependency audit

Audit every `synvoid-core` use reachable from `crates/synvoid-dnssec-keystore`.

Classify each use as:

- genuinely generic cryptographic/key-custody contract;
- DNSSEC protocol vocabulary that belongs in the keystore;
- SynVoid application/domain coupling that should be removed;
- test-only convenience.

Target state: the keystore remains a one-way custody/signing library and does not depend on unrelated SynVoid application contracts.

If `synvoid-core` is only used for a very small neutral primitive, prefer one of:

1. move that primitive into the keystore when it is custody-specific;
2. move the primitive into a lower neutral crate if it has multiple users;
3. pass the value/trait in through a narrow API;
4. retain `synvoid-core` only if removing it would duplicate a canonical protocol contract and the dependency remains low-capability.

Do not create another micro-crate solely to erase one dependency edge.

## Part B — DNSSEC public/reuse surface review

Review the keystore API as if consumed by an external DNS implementation.

Requirements:

- no raw private-key extraction API;
- opaque HSM handles remain opaque;
- software-key persistence remains atomic and permission checked;
- no `synvoid-config` types cross the public boundary;
- no Hickory, mesh, admin, Hyper, Quinn, or SQLite dependencies are introduced;
- algorithm/digest types remain DNSSEC-specific and standards-oriented;
- HSM/PKCS#11 support remains opt-in and fail-closed;
- public errors do not expose key material or provider secrets.

Add crate-level documentation/examples that demonstrate construction, key generation/loading, signing, public metadata inspection, and optional HSM use without importing the root SynVoid crate.

Publication is not required in this phase; API independence is.

## Part C — Separate SynVoid adapters from `synvoid-http-client`

Audit the client crate module-by-module:

```text
client.rs
erased_pool.rs
pool.rs
request.rs
response.rs
streaming_waf_body.rs
tls.rs
unix.rs
```

Classify code as:

- generic HTTP transport/pool;
- generic TLS/client policy;
- SynVoid config adapter;
- WAF adapter;
- metrics/logging adapter;
- Unix-socket transport;
- compatibility surface.

Move application-specific pieces upward so the generic transport core does not need to understand SynVoid policy.

Strong candidates to move out of the transport layer:

- `upstream_tls_from_site_config(...)` and any direct `synvoid-config` conversion;
- `StreamingWafBody`, `StreamingWafDecision`, and `StreamingWafScanner` coupling;
- SynVoid-specific metric names/log messages emitted by WAF adapters;
- QUIC/tunnel dispatch that depends on root tunnel composition.

Possible owners:

- `synvoid-upstream` for site/upstream TLS/config conversion;
- `synvoid-waf` or `synvoid-http` for streaming WAF body adaptation;
- root application composition for tunnel dispatch that cannot be expressed through a narrow transport trait.

Do not move generic body streaming or TLS primitives upward merely because current call sites are SynVoid-specific.

## Part D — Define SynVoid's actual egress requirements

Before comparing implementations, write a capability matrix for all production consumers of `synvoid-http-client`.

At minimum capture whether each consumer needs:

- HTTP/1.1;
- HTTP/2;
- HTTP/3;
- native roots and/or WebPKI roots;
- custom CA/certificate policy;
- post-quantum Rustls preference;
- Unix-domain-socket HTTP;
- streaming request/response bodies;
- type-erased pooled clients;
- per-request timeout/size limits;
- proxy support;
- cancellation/drain behavior;
- connection pool controls;
- observability hooks;
- request retry semantics;
- tunnel/QUIC special cases.

Consumers include proxy/upstream code, honeypot/feed fetching, GeoIP or other outbound services, admin/webhook paths, mesh-related egress where applicable, and tests/tools.

This matrix is the source of truth for the eggfetch decision.

## Part E — Compare against `eggfetch-core`

Use the current released/workspace `eggfetch-core` API and feature graph, not assumptions from earlier versions.

Evaluate:

- capability parity against Part D;
- transitive dependency delta;
- binary-size delta for default/minimal SynVoid profiles;
- TLS backend/root-store behavior;
- HTTP/2 and HTTP/3 maturity;
- streaming/body compatibility with Hyper-based SynVoid paths;
- connection-pool semantics and limits;
- Unix-socket support or clean extensibility if required;
- timeout semantics;
- observability/tracing hooks;
- error taxonomy and mapping cost;
- MSRV compatibility;
- security/advisory exposure;
- maintenance duplication removed.

Do not require eggfetch to adopt SynVoid-specific WAF/config/tunnel behavior. SynVoid should provide adapters around a general transport API.

## Part F — Decision branches

### Branch 1: adopt eggfetch

Choose this only if required capabilities are present or can be added to eggfetch as generally useful features without making eggfetch a SynVoid adapter.

Then:

1. add `eggfetch-core` behind a SynVoid-owned narrow adapter;
2. migrate one low-risk egress consumer first;
3. run parity tests and benchmarks;
4. migrate remaining consumers incrementally;
5. keep `synvoid-http-client` as a compatibility facade only as long as necessary;
6. remove duplicated Hyper/Rustls/pool ownership from SynVoid once all production users move;
7. ensure minimal/default feature profiles do not accidentally enable HTTP/3/proxy/compression features they do not need.

Any eggfetch change needed for SynVoid must be independently justified for general HTTP-client users.

### Branch 2: retain `synvoid-http-client`

Choose this if there is a material capability, dependency, security, or performance reason.

Then:

1. complete the adapter cleanup from Part C;
2. document the exact non-overlapping reason for retention;
3. reduce direct `synvoid-config`/WAF coupling where feasible;
4. make the generic client surface independently testable;
5. record which future eggfetch capability would allow consolidation.

### Forbidden branch: create another generic HTTP crate

Do not create `synvoid-http-transport`, `synvoid-egress-core`, or equivalent merely to reorganize the same Hyper/Rustls code. A new generic HTTP crate requires a documented capability that is neither appropriate in eggfetch nor specific to SynVoid.

## Part G — Parity tests

Regardless of decision, establish black-box egress tests for the required behaviors before migration/refactor.

At minimum:

- HTTP/1.1 keepalive and connection reuse;
- HTTP/2 request/response;
- TLS trust roots and invalid-certificate failure;
- configured timeout expiration;
- request/response body size limits;
- streaming body behavior;
- custom headers/auth helpers used in production;
- Unix socket HTTP if retained;
- post-quantum feature compile behavior;
- cancellation/closed upstream behavior;
- pool saturation/eviction semantics;
- error mapping expected by proxy/upstream callers.

HTTP/3 should have feature-gated tests if SynVoid production consumers require it through the egress client path.

## Part H — Dependency and security evidence

For the chosen branch, capture before/after:

```bash
cargo tree -p synvoid-http-client
cargo tree -i hyper --workspace
cargo tree -i hyper-rustls --workspace
cargo tree -i rustls --workspace
cargo tree -i eggfetch-core --workspace   # if adopted
cargo deny check
cargo audit
```

Record which crate owns egress TLS, pooling, HTTP protocol implementations, and root-store policy after the phase.

## Acceptance criteria

Phase 34 is complete only when:

- DNSSEC keystore dependency edges are justified and its API can be consumed without root SynVoid coupling;
- no raw private-key capability is added;
- SynVoid WAF/config policy is removed from the generic HTTP transport layer where technically feasible;
- a current capability matrix exists for all production egress consumers;
- eggfetch adoption or retention of `synvoid-http-client` is decided from parity/dependency/performance/security evidence;
- no redundant generic HTTP crate is created;
- if eggfetch is adopted, migration is incremental and black-box parity tests pass before old ownership is removed;
- if SynVoid's client is retained, the closeout documents the exact capability gap and future consolidation condition.

## Rejection criteria

Reject an implementation that:

- moves DNSSEC private-key handling into a broader DNS/application crate;
- adds SynVoid-specific APIs to eggfetch solely for this integration;
- replaces the HTTP client without parity tests;
- claims maintenance reduction while retaining both full transport stacks indefinitely;
- removes Unix/PQ/streaming behavior without auditing consumers;
- creates a new generic HTTP crate instead of resolving the ownership decision.

## Verification

At minimum:

```bash
cargo fmt --all -- --check
cargo check -p synvoid-dnssec-keystore --all-targets
cargo test -p synvoid-dnssec-keystore
cargo check -p synvoid-http-client --all-targets
cargo test -p synvoid-http-client
cargo test -p synvoid-upstream
cargo test -p synvoid-proxy
cargo xtask verify
cargo xtask verify-full
cargo deny check
cargo audit
cargo check --no-default-features
cargo check --no-default-features --features mesh,dns
```

If eggfetch is adopted, add its targeted integration/parity suite and verify the exact selected feature set with `cargo tree -e features`.
