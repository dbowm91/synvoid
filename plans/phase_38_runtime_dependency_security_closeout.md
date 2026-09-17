# Phase 38 Plan: Runtime Dependency Security Closeout and Guard Reconciliation

Status: planned (2026-09-16).

Roadmap: `plans/runtime_dependency_security_followup_roadmap.md`.
Depends on: Phase 36 and Phase 37 implementation results.

Primary goal: make the repository's security policy, advisory ignores, dependency guards, architecture docs, and release evidence exactly match the final YARA-X/Wasmtime graph after the two runtime remediations.

This phase does not introduce another runtime migration. It closes the evidence and regression-prevention gap so the repository cannot silently drift back to the pre-remediation exposure.

## Part A — Recompute the final security-sensitive graph

Run and preserve the exact output/version summary for:

```bash
cargo tree -i yara-x --workspace
cargo tree -i wasmtime --workspace
cargo tree -e features -i wasmtime@36.0.x --workspace
cargo tree -e features -i wasmtime@45.0.x --workspace   # adjust to actual YARA-X transitive line
cargo tree -i wasmtime-wasi --workspace
cargo tree -i wasi-filesystem --workspace
cargo tree -i minify-html --workspace
cargo tree -i bumpalo --workspace
cargo audit
cargo deny check
```

Do not assume versions from the plans. Record the actual lockfile graph that landed.

Expected shape if Phases 36/37 land as researched:

- direct plugin runtime: Wasmtime 36.0.15+ LTS;
- YARA-X: 1.20.x;
- transitive YARA engine: Wasmtime 45.0.3 or the version selected by the landed YARA-X release;
- no Wasmtime 40.0.4;
- no direct Wasmtime 42.0.2;
- no Wasmtime git patch;
- `wasmtime-wasi` remains absent unless the implementation explicitly changed the capability model (which requires a separate review).

## Part B — Minimize advisory ignores to the exact remaining set

Rebuild `deny.toml` and `.cargo/audit.toml` from the final `cargo audit` results.

Rules:

1. Remove all ignores that no longer match a resolved vulnerable package.
2. Do not retain old 40.x Wasmtime advisory ignores merely as history.
3. Do not retain a direct 42.0.2 RUSTSEC-2026-0269 exception after Phase 37 succeeds.
4. If the YARA-X transitive Wasmtime line remains inside the 0269 affected range, keep one exact ignore only if:
   - the vulnerable `wasmtime-wasi` filesystem implementation is still absent from the resolved graph;
   - no filesystem preopen API is reachable;
   - the dependency path is documented as `synvoid-yara -> yara-x -> wasmtime`;
   - Owner, Reviewed, Re-audit, Remove condition, and escalation metadata satisfy the existing guard policy.
5. Keep unrelated ignores only if they still reproduce on the final graph and retain current capability evidence.

The goal is not zero ignores at any cost. The goal is no stale or misleading ignore.

## Part C — Update the dependency security authority document

Rewrite the relevant portions of:

```text
architecture/dependency_security_baseline_phase25.md
```

or supersede it with a clearly linked current runtime-security closeout document if the old Phase 25 title has become misleading.

The current authority must separately describe:

- direct plugin Wasmtime version/support line/features;
- transitive YARA-X Wasmtime version/features;
- YARA-X version and GHSA-2jx3-ff3v-j7jj disposition;
- `wasmtime-wasi` reachability;
- remaining advisory exceptions;
- `minify-html`/Oxc `bumpalo` constraint status;
- source policy (crates.io vs git);
- next re-audit triggers.

Historical Phase 25 evidence should remain available, but no current document should tell implementers that >=46.0.3 is the only path out of the direct 42 line once the 36 LTS migration has landed.

## Part D — Add YARA compiled-byte boundary guards

Add repo guards that fail if executable raw compiled-rule deserialization is reintroduced into an untrusted path.

At minimum enforce:

- `crates/synvoid-mesh` must not import or call `yara_x::Rules::deserialize`;
- `crates/synvoid-upload` must not call `yara_x::Rules::deserialize` directly;
- remote/mesh update selection must not prefer compiled bytes over source;
- if `Rules::deserialize` remains anywhere in `synvoid-yara`, it must be confined to the approved local verified-artifact module/path;
- `YARA_ENGINE_VERSION` must be updated when the YARA-X major/minor engine line changes;
- old engine artifacts are rejected by tests.

Prefer semantic/structural guards where practical. If a text guard is used, make it narrow enough that legitimate comments/tests do not satisfy it accidentally.

## Part E — Add supported Wasmtime ownership guards

Update `wasmtime_baseline_guard` and related dependency-security tests so they assert the new policy rather than hard-coding 42.0.2.

Required invariants:

- direct Wasmtime belongs only to `synvoid-plugin-runtime` plus explicitly justified benchmark/dev paths;
- direct version is on the selected supported LTS major and at/above the minimum security patch;
- no direct Wasmtime git source exists unless a future evidence document explicitly authorizes it;
- `wasmtime-wasi` / `wasi-filesystem` appearance fails closed pending exposure review;
- a new direct Wasmtime major requires the security authority document to be updated;
- transitive YARA-X Wasmtime is not mistaken for the direct plugin runtime in guard messages.

Where possible, derive the resolved version/source from `Cargo.lock` rather than matching comments only.

## Part F — Fix documentation drift found during research

Correct current docs/skills that still encode pre-remediation facts.

At minimum review:

```text
AGENTS.md
SECURITY.md
architecture/crate_boundary_reuse_closeout.md
architecture/dependency_security_baseline_phase25.md
architecture/track4_dependency_security_closeout.md
architecture/track4_post_closure_corrective_report.md
architecture/plugin_runtime_sandbox.md
architecture/plugin_wasm.md
architecture/mesh.md
docs/RELEASE.md
docs/testing/verification-contract.md
.opencode/skills/supply_chain/SKILL.md
.opencode/skills/security_patterns/SKILL.md
.opencode/skills/serverless_wasm/SKILL.md
```

Specific stale item already found:

- `architecture/mesh.md` still says worker mesh supervision is explicitly deferred, while `src/worker/mesh_supervision.rs`, `src/worker/unified_server/supervision_loop.rs`, and `architecture/worker_task_lifecycle.md` document Iterations 82/85 implementation. Reconcile the overview to current behavior; do not reopen completed mesh-supervision work.

Also remove stale statements that:

- call direct 42.0.2 the current runtime after Phase 37;
- describe the direct Wasmtime git patch as required after it is removed;
- claim YARA-X 1.15 is current after Phase 36;
- imply compiled YARA blobs are preferred/executable from mesh after Part B of Phase 36;
- list advisory ignores that no longer exist.

## Part G — Security regression tests

Add/retain tests for the exact corrected boundaries:

YARA:

- malformed remote compiled bytes are ignored/rejected without deserialization;
- valid signed/approved source compiles locally and reloads atomically;
- invalid source retains/fails according to existing policy;
- old engine artifact rejected;
- local trusted artifact path, if retained, rejects digest/manifest/version mismatch;
- no panic/UB path is required to test malformed serialized bytes.

Plugin runtime:

- WASI filesystem package absence guard;
- fuel exhaustion;
- epoch deadline;
- memory/table limits;
- host-call capability denial;
- hot-reload generation isolation;
- supported LTS direct-version/source guard.

Supply chain:

- no unexpected git source;
- no expired advisory ignore metadata;
- no stale duplicate-version skip for removed Wasmtime lines;
- lockfile/source guard messages identify the responsible dependency path.

## Part H — Release and CI evidence

Run the full project verification matrix and record the actual commit/tool versions.

At minimum:

```bash
cargo fmt --all -- --check
cargo xtask verify
cargo xtask verify-full
cargo xtask verify-release
cargo audit
cargo deny check
cargo test -p synvoid-repo-guards
cargo check --no-default-features
cargo check --no-default-features --features mesh
cargo check --no-default-features --features dns
cargo check --no-default-features --features mesh,dns
```

Also run the focused Phase 36/37 suites and benches documented in those plans.

If GitHub Actions is expected to provide release proof, ensure the final commit has an attached successful workflow/status record; do not describe local-only verification as CI.

## Part I — Closeout record

Add an architecture closeout record containing:

- before/after dependency graph;
- exact landed YARA-X and Wasmtime versions;
- supported/EOL dates relevant to the direct runtime;
- advisory ignores removed/retained and why;
- proof that remote compiled YARA bytes are non-executable;
- proof that the direct git Wasmtime source is gone, if migration succeeded;
- feature-surface delta;
- performance/footprint delta;
- verification results;
- explicit remaining risks and future triggers.

Future triggers should be event-based, for example:

- YARA-X moves to a supported Wasmtime line that clears the remaining transitive advisory;
- Wasmtime 48 LTS becomes resolver-compatible because the `bumpalo` blocker disappears;
- SynVoid intentionally adds WASI filesystem capabilities;
- a new YARA serialized-artifact consumer is introduced;
- the selected direct Wasmtime LTS approaches end of support.

## Acceptance criteria

Phase 38 is complete only when:

- advisory ignores exactly match the final dependency graph;
- no obsolete 40.x/42.x Wasmtime policy remains after those paths are removed;
- current security authority documents direct and transitive Wasmtime separately;
- remote compiled YARA bytes are mechanically guarded as non-executable;
- direct Wasmtime is mechanically guarded as a supported LTS/security-patched line;
- no unexpected git dependency remains;
- stale mesh worker-supervision documentation is corrected without new implementation churn;
- focused security tests and full verification are green;
- closeout evidence distinguishes local verification from attached CI results.

## Rejection criteria

Reject a closeout that:

- leaves ignores for packages no longer in `Cargo.lock`;
- deletes an ignore while an affected package is still resolved/reachable without evidence;
- treats capability absence as equivalent to patched version;
- allows mesh/upload to regain a raw compiled YARA execution path;
- hard-codes one Wasmtime version in comments while guards inspect another;
- reports stale docs as harmless when they direct future implementers toward the wrong architecture;
- calls the work complete without `cargo audit`, `cargo deny`, repo-guard, and full verification evidence.
