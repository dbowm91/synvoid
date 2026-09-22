# Phase 62 Plan: Eggfetch Policy-Keying and Evidence Corrective Closeout

Status: complete. Proof-bearing implementation/qualification: `c3568ef4580a49edf222c5e4e6ce5d4dca904e81` (2026-09-22). Final record: `architecture/eggfetch_0_2_transport_corrective_closeout.md`.

Registered in: `plans/roadmap.md`.

Parent campaign: `plans/eggfetch_0_2_transport_consolidation_roadmap.md`.

Reopens: Phase 61 closeout only. Phases 58-60 implementation remains the working production baseline unless this corrective discovers a rollback-class defect.

Baseline reviewed: `main` at `f62bb285a2bdf6262efe9a7b859bc11bdcc35e15` (2026-09-22).

Implementation under review:

- Phase 58-60 migration: `7a6c617cf9dc16441f50da5dcff95778775b5041`.
- Phase 61 closeout/docs: `f62bb285a2bdf6262efe9a7b859bc11bdcc35e15`.
- Current transport owner: `crates/synvoid-http-client/src/eggfetch_transport.rs`.
- Current site registry: `crates/synvoid-proxy/src/client_registry.rs`.

## Primary goal

Close three concrete defects in the eggfetch 0.2 adoption without rolling back the otherwise successful migration:

1. make the outer site registry policy-aware so a lane created for one TLS/plaintext policy cannot be reused for a different policy on the same site;
2. remove the current silent substitution of a default TLS policy when a requested custom policy fails to build;
3. complete the verification/performance evidence that Phase 61 required before final closure, then reconcile all planning/architecture statuses truthfully.

This is a narrow corrective. Do not reopen the Phase 58 capability decision, replace eggfetch, redesign proxy retry policy, publish `synvoid-http-client`, or broaden the transport API.

## Why Phase 62 is required

### 1. The site registry is keyed only by `site_id`

Current `UpstreamClientRegistry` stores:

```rust
lane_clients: DashMap<String, Arc<EggfetchUpstreamClient>>
```

while callers intentionally request more than one policy for the same site.

In `crates/synvoid-http/src/upstream_proxy_dispatch_plan.rs` the no-site-TLS buffered path first requests:

```rust
UpstreamTlsConfig {
    allow_plaintext: true,
    ..UpstreamTlsConfig::default()
}
```

and the streaming plan then requests `UpstreamTlsConfig::default()`, which prohibits plaintext.

Because the outer registry key ignores policy, the first lookup wins. In the current ordering the buffered plaintext-capable lane is inserted first and the later streaming lookup receives the same lane. The code comments claim the buffered and streaming legacy defaults remain distinct, but the runtime registry collapses them.

The inner `EggfetchUpstreamClient::cached` key is already policy-aware. The defect is the outer site lifecycle registry.

### 2. Invalid requested TLS policy is silently replaced

Both `UpstreamClientRegistry::get_or_create_lane` and `ProxyServer::new_with_pool_config` currently catch lane construction failure — especially invalid/missing/empty custom CA material — and create a default verifying client instead.

That conflicts with the Phase 58/59 contract:

- invalid requested CA material must fail closed;
- a requested TLS policy must not silently become another policy;
- the translator's explicit error is intended to be meaningful configuration/transport evidence.

Default verification is not equivalent to the requested custom policy. A publicly trusted upstream could therefore still connect despite a broken configured custom CA path.

### 3. Phase 61 was marked closed without its own required evidence

The Phase 61 plan requires:

- an immutable before/after transport performance comparison;
- `cargo xtask verify-full`;
- `cargo xtask verify-release`;
- final plan/status reconciliation.

The current closeout explicitly records that the transport benchmark was not run and that `verify-full` / `verify-release` were not run. The top-level roadmap nevertheless says Phases 58-61 are complete, while the Phase 58-61 plan files and umbrella roadmap still carry handoff-plan statuses.

The implementation can remain adopted, but final closure is premature until this evidence/state gap is resolved.

## Non-goals

- No rollback to the legacy Hyper transport unless this corrective exposes a security/capability blocker.
- No deletion of the frozen compatibility surface.
- No new high-level eggfetch retry/redirect/cookie/compression policy.
- No outbound HTTP/3 adoption.
- No change to WAF policy, proxy retry selection, cache semantics, or tunnel routing.
- No broad transport optimization beyond correcting measured regressions discovered by the required benchmark.
- No change to existing pre-campaign public `synvoid-http-client` signatures/types.
- No routine-CI expansion with transport benchmarks.

## Workstream A — Pin the policy-collision regression first

Before changing the registry, add deterministic tests that fail on `f62bb285`.

Required cases:

1. **buffered-first / streaming-second, same site**
   - acquire site `s` with `allow_plaintext = true`;
   - acquire site `s` with default `allow_plaintext = false`;
   - assert the second acquisition does not reuse a lane whose effective policy permits plaintext;
   - prove an `http://` request through the strict lane is rejected before network I/O.

2. **streaming-first / buffered-second**
   - reverse the order;
   - prove the buffered lane still permits its legacy plaintext case where intended;
   - first acquisition must not permanently set site policy for later callers.

3. **TLS material separation**
   - same site with distinct `ca_cert_path`, `server_name`, or `skip_verify` policy must not collapse to one outer entry;
   - `skip_verify_reason` may be excluded from physical-pool identity if it is audit-only, but the test must document the chosen rule.

4. **invalidation**
   - `invalidate(site_id)` removes every policy variant for that site;
   - the next acquisition builds/reuses from current policy rather than a stale site entry.

5. **clear**
   - clears all site/policy entries.

Prefer tests in `synvoid-proxy` for the registry invariant plus at least one higher-level `synvoid-http` regression test that reproduces the actual buffered+streaming plan ordering.

Do not rely only on pointer inequality. Prove behavior with the plaintext gate or an explicit test-only policy fingerprint.

## Workstream B — Make the outer registry policy-aware

Replace site-only lookup identity with an explicit registry key.

Preferred shape:

```rust
#[derive(Clone, Hash, PartialEq, Eq)]
struct LaneRegistryKey {
    site_id: String,
    tls_policy: UpstreamTlsConfig,
}
```

`UpstreamTlsConfig` already implements `Hash + Eq`; using it avoids exposing the private legacy `UpstreamTlsConfigHashable` across crates.

If audit-only `skip_verify_reason` should not fragment entries, define a small crate-local normalized policy key that copies every transport-affecting field and explicitly excludes only the reason string. Do not omit:

- `verify`;
- `ca_cert_path`;
- `server_name`;
- `skip_verify`;
- `allow_plaintext`.

Keep the current fixed registry connection settings (5s connect / 100 idle-per-host / 30s idle) out of the key only while they are genuinely invariant. If callers begin supplying them, they become part of identity.

The outer registry remains a site lifecycle/invalidation layer; eggfetch remains the physical connection-pool owner underneath. Do not reintroduce separate buffered and streaming physical pools.

### Invalidation semantics

Because one site may now own multiple policy entries:

- `invalidate(site_id)` must remove every key whose `site_id` matches;
- `clear()` remains global;
- config rehash/reload must not leave a stale policy variant reachable;
- add tests for multiple-policy removal.

Avoid an O(total-sites) hot request-path scan. An O(n) invalidation operation is acceptable if invalidation is configuration/control-plane frequency; document that choice. If the registry is expected to grow materially, use a nested site -> policy map instead.

## Workstream C — Make TLS-policy construction failure truly fail closed

Remove these production behaviors:

```text
lane build fails -> warn -> use UpstreamTlsConfig::default()
```

from both:

- `UpstreamClientRegistry`;
- `ProxyServer` construction.

A malformed/missing/empty configured CA or other lane-build failure must never silently become a different connection policy.

### Preferred error propagation

First classify the affected APIs against the repository's support boundary.

`get_or_create_lane` was introduced by Phase 60, after the Phase 58 frozen `synvoid-http-client` compatibility inventory. If it has no supported external compatibility commitment, prefer making acquisition fallible:

```rust
pub fn get_or_create_lane(
    &self,
    site_id: &str,
    tls: &UpstreamTlsConfig,
) -> anyhow::Result<Arc<EggfetchUpstreamClient>>
```

and propagate the error through the HTTP/proxy composition paths to the existing upstream/configuration failure response.

For `ProxyServer`, preserve pre-existing constructor signatures unless the repository's public-surface policy explicitly permits a fallible constructor change. If construction cannot become fallible without API regression, store a terminal lane-initialization error and make every request fail before network I/O. Do not substitute default policy.

A "poisoned" or invalid-policy state is acceptable only if:

- it cannot expose a raw usable eggfetch client;
- every send/execute path checks it before I/O;
- the error includes enough context to identify the bad site/policy;
- it is test-covered;
- no panic is used as ordinary configuration handling.

### Error behavior

Use an explicit configuration/transport error, not a successful default connection.

Required black-box proof:

- configure an unreadable CA path for an otherwise publicly trusted TLS origin;
- prove no request reaches the upstream;
- prove the caller receives the expected upstream/configuration failure;
- prove replacing the CA with valid material and invalidating/reloading the site allows recovery.

This is the important distinction: "default verification is secure" is not sufficient. The requested policy must either be honored or rejected.

## Workstream D — Audit all lane acquisition sites after the key/error change

Search all production uses of:

- `get_or_create_lane`;
- `EggfetchUpstreamClient::cached`;
- `EggfetchUpstreamClient::build`.

Review at minimum:

- buffered H1 proxy plan;
- streaming H1 plan;
- streaming WAF dispatch;
- H3 buffered dispatch;
- H3 streaming dispatch;
- `ProxyServer`;
- leaf/background clients that construct lanes directly;
- root operator-lane facade.

For each direct constructor call, verify:

- requested policy is not silently replaced on error;
- plaintext default is intentional;
- site TLS takes precedence where the legacy contract did;
- policy reuse does not cross incompatible SNI/CA/skip/plaintext settings.

Add a repository guard only if it can detect a durable architectural invariant without brittle false positives. Do not create a grep guard for every constructor merely to satisfy the plan.

## Workstream E — Preserve production/compatibility lane separation

The Phase 60 freeze guard is directionally correct and must remain green.

After corrective changes:

- production still uses the eggfetch lane;
- legacy Hyper client/pool helpers remain compatibility/test-only;
- no corrective code routes requests back through legacy `HttpClient` or `ErasedHttpClient`;
- `synvoid-http-client` frozen aliases/signatures remain unchanged;
- retry, failover, WAF, cache, auth, redirect, compression, tunnel, and mesh policy remain outside eggfetch.

If a new fallible registry API is added, it is a SynVoid composition API, not a second transport abstraction.

## Workstream F — Complete immutable transport performance evidence

Phase 61 cannot be called complete without the comparison required by its own plan.

Use immutable revisions:

- **before:** `7083f339a43dd13d6c8f65e7acc9d03ee555b6ef` (planning head immediately before the Phase 58-60 production migration; runtime equivalent to the pre-campaign `e3026667` baseline);
- **after:** the Phase 62 proof-bearing implementation SHA.

Use the same benchmark harness on both revisions. If the harness does not exist at the baseline, apply the benchmark-only files as a recorded patch/worktree transplant. The baseline worktree must contain no Phase 58-62 production code.

Do not manufacture "before" data by comparing the two lanes in one post-migration tree and label it immutable baseline evidence.

### Required workloads

At minimum:

1. H1 keepalive small request;
2. H2 concurrent/multiplexed small requests;
3. streaming request + response at approximately 1 KiB;
4. streaming request + response at approximately 64 KiB;
5. streaming request + response at approximately 1 MiB;
6. concurrent streaming batch;
7. early response-body drop/cancellation;
8. optional cold client construction as a separate non-hot-path case.

Record:

- exact host/OS/CPU/toolchain/profile;
- exact before/after SHAs;
- benchmark-only patch SHA or patch hash;
- iteration/sample configuration;
- throughput;
- p50/p95/p99 where the harness supports it;
- Criterion confidence intervals for Criterion cases;
- any allocator/copy proxy already available without adding a large instrumentation dependency.

### Performance adjudication

Treat >5% regression in a primary comparable throughput/tail metric as material until explained.

If a regression is real:

- profile the adapter/pool/body path;
- correct only the demonstrated source;
- rerun the same cases;
- do not weaken TLS, WAF, backpressure, timeout, or compatibility invariants for a benchmark win.

If the environment cannot produce trustworthy immutable comparison data, Phase 62 remains evidence-incomplete; do not restore the "fully closed" wording.

## Workstream G — Run the verification gates Phase 60/61 promised

After implementation and focused tests, create a clean proof-bearing implementation commit.

On that clean tree run:

```bash
cargo fmt --all -- --check
cargo nextest run -p synvoid-http-client -p synvoid-proxy -p synvoid-http -p synvoid-http3 -p synvoid-upstream --cargo-profile ci --profile ci
cargo xtask test guards
cargo check --no-default-features
cargo check --no-default-features --features post-quantum
cargo check --no-default-features --features mesh
cargo check --no-default-features --features dns
cargo check --no-default-features --features mesh,dns
cargo deny check
cargo audit
cargo xtask verify
cargo xtask verify-full
cargo xtask verify-release
```

`verify-release` is expected to run only on a clean tree and must not publish. Commit implementation/tests/evidence inputs first, then run it.

If a gate is platform/environment-specific and cannot run, record the exact command, failure, and classification. Do not call the campaign closed merely because `cargo xtask verify` is green while the explicitly required full/release gate was skipped.

No new routine CI job is required for the benchmark.

## Workstream H — Produce corrective closeout evidence

Create:

`architecture/eggfetch_0_2_transport_corrective_closeout.md`

It must contain:

- baseline `f62bb285...`;
- corrective proof-bearing SHA;
- exact policy-collision reproduction and fix;
- registry key/invalidation design;
- TLS-policy failure behavior before/after;
- regression tests;
- immutable benchmark methodology/results;
- `verify`, `verify-full`, `verify-release`, deny/audit/profile results;
- any environmental omissions;
- final decision: adopted/closed or adopted-but-evidence-blocked.

Amend `architecture/eggfetch_0_2_transport_closeout.md` with a pointer to the corrective record. Do not erase the original Phase 61 closeout attempt; preserve it as historical evidence with an explicit supersession note.

## Workstream I — Reconcile planning/status truth

At successful closeout update:

- `plans/phase_58_eggfetch_0_2_qualification_and_compatibility.md`;
- `plans/phase_59_eggfetch_native_transport_adapter.md`;
- `plans/phase_60_eggfetch_consumer_migration_and_legacy_transport_retirement.md`;
- `plans/phase_61_eggfetch_transport_qualification_and_closeout.md`;
- this Phase 62 plan;
- `plans/eggfetch_0_2_transport_consolidation_roadmap.md`;
- `plans/roadmap.md`;
- `architecture/eggfetch_0_2_compatibility_matrix.md`;
- `architecture/eggfetch_0_2_transport_closeout.md`;
- current HTTP-client skill/AGENTS docs if implementation details changed.

Final status must distinguish:

- Phase 58-60 implementation landed at `7a6c617c...`;
- Phase 61 closeout attempt at `f62bb285...`;
- Phase 62 proof-bearing corrective implementation/qualification SHA;
- optional docs-only metadata commit.

Avoid self-referential SHA requirements: the proof-bearing implementation SHA is the tree on which final commands/benchmarks ran; a later docs-only metadata commit may record it.

## Required regression tests

At minimum add tests that would fail on the current `f62bb285` tree for:

- same site: plaintext-capable acquisition followed by strict acquisition;
- same site: strict acquisition followed by plaintext-capable acquisition;
- same site: distinct SNI values;
- same site: distinct custom CA paths;
- same site: `skip_verify` false vs true;
- invalid custom CA never reaches a publicly trusted test upstream;
- invalid custom CA recovers after valid config + site invalidation;
- invalidation removes all policy variants for one site without clearing another site;
- freeze guard still rejects production legacy-lane imports.

Use hermetic loopback/TLS fixtures; no public network dependency.

## Acceptance criteria

Phase 62 is complete only when:

- the outer registry key includes every transport-affecting policy dimension or otherwise proves equivalent separation;
- buffered and streaming no-config policies for one site cannot collapse into one lane;
- site invalidation removes all policy variants;
- invalid/missing/empty custom CA material cannot silently become default TLS policy;
- no request reaches an upstream when requested lane policy failed to construct;
- recovery after corrected policy + invalidation is proven;
- all production lane acquisition sites have been audited;
- the frozen legacy compatibility surface remains source-compatible and production-inactive;
- immutable before/after transport benchmark evidence exists for the required workloads;
- no material unexplained performance regression remains;
- `cargo xtask verify`, `verify-full`, and `verify-release` have run successfully on the proof-bearing tree, or the campaign remains explicitly open with the exact blocker;
- feature profiles, deny, audit, focused crate suites, and repo guards are green;
- Phase 58-62 plan/roadmap/architecture status agrees;
- the final corrective closeout records the proof-bearing SHA without self-reference.

## Rejection criteria

Reject Phase 62 closure if it:

- keeps `site_id` as the only outer lane-cache identity;
- fixes the observed order only by reordering buffered/streaming acquisition;
- creates separate physical pools solely to paper over the keying bug;
- treats warning + default TLS substitution as fail-closed behavior;
- panics on ordinary invalid custom-CA configuration instead of returning/rendering a controlled failure;
- weakens hostname, chain, SNI, CA, aws-lc/PQ, or plaintext policy;
- changes the frozen pre-campaign `synvoid-http-client` public aliases/signatures;
- moves retry/WAF/cache/redirect policy into eggfetch;
- labels same-tree differential benchmarks as immutable before/after evidence;
- skips `verify-full` or `verify-release` and still marks the campaign fully closed;
- rewrites Phase 61 history instead of superseding it with corrective evidence.

## Expected terminal state

The expected outcome is still the adopted branch:

- eggfetch remains the sole production generic egress transport;
- the outer SynVoid registry correctly separates site/policy lifecycles;
- invalid requested TLS policy fails before I/O;
- legacy Hyper transport remains frozen compatibility-only;
- the missing evidence is completed;
- Phases 58-62 become a coherent closed historical campaign.

Rollback should occur only if Phase 62 exposes a security/capability regression that cannot be corrected without violating the campaign invariants.
