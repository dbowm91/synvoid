# Phase 103 Plan: Dependency Security Re-audit and Wasmtime Remediation

Status: **CLOSED QUALIFIED** (2026-10-01).

Closeout: `architecture/dependency_security_reaudit_phase103_closeout.md`.

Registered in: `plans/roadmap.md`.

Planning baseline: `main` at
`daaa154a9bc16f1922da891ad368a7a28da35268` (2026-10-01).

Owner: security / release.

Predecessors:

- Phase 25 dependency-security baseline and time-aware advisory policy;
- Phase 37 direct Wasmtime 36 LTS migration;
- Phase 39 minify-html/Oxc compatibility fork;
- Phase 40 YARA-X 1.20 compatibility fork;
- Phase 102 eggfetch 0.2.1 patch adoption and its observation of the
  pre-existing dependency-security failure.

## Goal

Restore the repository's blocking dependency-security contract to green
without weakening policy, silencing newly discovered Wasmtime advisories,
removing supported capability, or broadening temporary forks unnecessarily.

This phase owns four related maintenance items that are now due:

1. remediate the newly issued Wasmtime advisories
   `RUSTSEC-2026-0315` and `RUSTSEC-2026-0316`;
2. perform the scheduled 2026-10-01 re-audit of the two retained advisory
   exceptions and the two temporary compatibility forks;
3. update dependency-security guards/current authority to the newly qualified
   versions and make temporary-fork review deadlines time-aware rather than
   permanently hard-coded to `2026-10-01`;
4. clean the two small Eggfetch documentation defects identified after
   Phase 102 without reopening the closed Eggfetch transport campaign.

The terminal requirement is a green exact-SHA hosted `ci` and
`dependency-security` result. This phase must not close on local-only
evidence because restoring those blocking hosted gates is the maintenance
objective.

## Current researched state — 2026-10-01

### 1. The two Wasmtime lines need different treatment

SynVoid intentionally resolves two Wasmtime lines with different owners:

- direct plugin runtime: `wasmtime 36.0.15` LTS via
  `synvoid-plugin-runtime`, plus the root bench dev-dependency;
- YARA engine runtime: `wasmtime 47.0.4` via the temporary
  `third-party/yara-x-compat` fork of official `yara-x 1.20.0`.

The new RustSec findings are:

#### RUSTSEC-2026-0315

`call_ref` / exception `catch` can under-account fuel and allow
exponential fuel amplification.

Authoritative advisory:
https://rustsec.org/advisories/RUSTSEC-2026-0315.html

Fixed ranges:

- `>=48.0.3,<49.0.0`;
- `>=49.0.1`.

Versions below 47 are explicitly unaffected. Therefore:

- direct `36.0.15`: **not affected** by 0315;
- YARA transitive `47.0.4`: **affected** and cannot be fixed within 47.x.

#### RUSTSEC-2026-0316

Dynamic component-record lifting can allocate beyond the hostcall fuel limit.

Authoritative advisory:
https://rustsec.org/advisories/RUSTSEC-2026-0316.html

Fixed ranges:

- `>=36.0.16,<37.0.0`;
- `>=48.0.3,<49.0.0`;
- `>=49.0.1`.

Therefore:

- direct `36.0.15`: affected; the supported 36 LTS patch is `36.0.16`;
- YARA transitive `47.0.4`: affected; move to at least `48.0.3`.

Wasmtime's release policy guarantees patch-release API/behavior compatibility,
so `36.0.15 -> 36.0.16` is an in-line LTS patch update. Wasmtime major
releases may change API or behavior, so `47.0.4 -> 48.0.3` requires an
explicit compatibility probe and qualification.

Wasmtime 48 is an LTS line (major divisible by 12, supported for 24 months).
`48.0.3` requires Rust 1.95; SynVoid pins Rust 1.98.1, so the current
toolchain satisfies that MSRV.

Wasmtime release policy:
https://docs.wasmtime.dev/stability-release.html

### 2. Official YARA-X cannot replace the compatibility fork yet

Latest official YARA-X release reviewed: **v1.21.0**, published 2026-09-29.

Upstream v1.21.0 and current `main` still declare:

`wasmtime = { version = "45.0.3", default-features = false }`

and Rust `1.93.0`.

Therefore switching SynVoid from its compatibility fork to stock YARA-X
1.21.0 would reintroduce an affected Wasmtime 45.x line and does **not**
satisfy the fork removal condition.

The old upstream PR #769 that SynVoid mirrored in Phase 40
(`45.0.3 -> 47.0.4`, MSRV 1.93 -> 1.94) is now **closed unmerged**
(2026-09-22). Current SynVoid docs that describe it as open/unreleased are
stale current-authority text.

No upstream YARA-X issue/PR was found that already moves the native runtime
to Wasmtime 48.0.3 for 0315/0316.

Disposition for this phase:

- retain the official YARA-X 1.20.0 source base initially;
- test a project-controlled **manifest-only** security delta
  `wasmtime 47.0.4 -> 48.0.3` and `rust-version 1.94 -> 1.95`;
- do not switch to stock 1.21.0 merely because it is newer;
- do not combine the security repair with a YARA-X 1.20 -> 1.21 feature/
  behavior upgrade unless implementation evidence proves that is necessary.

### 3. The YARA fork must be treated as a major-runtime compatibility probe

The vendored YARA native runtime directly uses Wasmtime types/APIs including
`Engine`, `Config`, `Module`, `Store`, `Linker`, `Caller`,
`FuncType`, `TypedFunc`, `Memory`, `Global`, `Val`/`ValRaw`,
module serialize/deserialize, `func_new_unchecked`, `define`, and
`instantiate`.

That surface compiled against 47.0.4, but a Wasmtime major bump is not assumed
source-compatible. The implementation must first prove that the exact
YARA-X 1.20 source tree compiles and its tests pass with 48.0.3.

If 48.0.3 requires a source-code delta inside the vendored YARA-X
`src/**` or `build.rs`, **stop the manifest-only branch**. Do not silently
turn the Phase 40 vendor into a source fork. Record the exact compile/API
break and register a narrow corrective plan before landing source-divergent
vendor code.

Mechanical metadata/provenance/comment updates are not considered YARA engine
source divergence.

### 4. Existing advisory exceptions are due for re-triage, not automatic removal

`deny.toml` and `.cargo/audit.toml` currently mirror exactly two ignores,
both with `Re-audit: 2026-10-01`. The guard intentionally treats a deadline
equal to the current UTC date as expired.

#### RUSTSEC-2023-0071 — rsa 0.9.10

Current upstream state: no fixed RSA release is available for this advisory.
The existing SynVoid exposure rationale remains potentially valid but must be
re-proven from the current graph:

- YARA RSA signing path is optional;
- SynVoid rule-feed trust uses Ed25519 rather than RSA;
- any other resolved RSA consumer must be enumerated rather than hidden by
  the YARA-only explanation.

Retain this ignore only if the current capability/reachability evidence still
supports the existing low-exposure disposition.

#### RUSTSEC-2026-0235 — rkyv 0.7.46

The 0.7 line has no patched release; remediation is on rkyv >=0.8.17.
SynVoid's direct code uses rkyv 0.8.x. The retained 0.7 line is currently via
the minification/sourcemap dependency chain.

Current upstream review still finds:

- official `minify-html` latest release is 0.18.1;
- current Lightning CSS still uses `parcel_sourcemap 2.1.1`;
- there is no demonstrated released path that removes the rkyv 0.7 instance
  while preserving SynVoid's current minification behavior.

Retain this ignore only after re-proving that the 0.7 instance remains
confined to minifier-internal sourcemap handling and is not used to deserialize
untrusted SynVoid archives/state.

For each retained ignore:

- set `Reviewed: 2026-10-01`;
- set a new bounded `Re-audit: 2026-11-01`;
- preserve or tighten the event-based removal condition;
- update `deny.toml` and `.cargo/audit.toml` together;
- record current dependency paths and capability exposure in the binding
  security baseline.

Do **not** add ignores for 0315 or 0316. Those findings have available patched
Wasmtime releases and are implementation work, not accepted residual risk.

### 5. Temporary-fork review deadlines are stale and insufficiently enforced

Both the minify-html compatibility fork and YARA-X compatibility fork carry
`Re-audit: 2026-10-01` metadata.

The advisory-ignore guard is correctly time-aware, but
`minify_fork_is_temporary_guard` and `yara_fork_is_temporary_guard`
currently assert the literal historical string `Re-audit: 2026-10-01`.
That proves the text exists but does not fail when a fork review deadline has
expired.

The implementation should generalize/reuse the existing strict
`YYYY-MM-DD` parsing and effective-current-date logic so temporary forks
also require:

- `Owner:`;
- `Reviewed: YYYY-MM-DD`;
- exactly one parseable future `Re-audit: YYYY-MM-DD`;
- `Removal condition:`.

The guard should be deterministic under
`SYNVOID_SECURITY_REVIEW_AS_OF=YYYY-MM-DD`, matching advisory-ignore
testing semantics.

Do not solve this by hard-coding `2026-11-01` into the Rust guard.

### 6. Minor Phase 102 documentation drift is isolated

Two docs-only defects are in scope for cleanup:

1. `architecture/eggfetch_0_2_1_patch_adoption_closeout.md` repeats the
   identical “Hosted CI / native qualification: not invoked” bullet.
2. The older roadmap heading still says Phase 64 “Docs Correction Active”
   although its section body and current authority correctly say Phase 64 is
   complete/closed.

Correct those statements only. Do not rewrite historical Eggfetch 0.2.0
evidence or reopen performance/runtime adjudication.

## Workstream A — freeze and reproduce the security baseline

Before editing dependencies, capture the current failure on the implementation
head:

```text
cargo tree -i wasmtime@36.0.15 --workspace
cargo tree -e features -i wasmtime@36.0.15 --workspace
cargo tree -i wasmtime@47.0.4 --workspace
cargo tree -e features -i wasmtime@47.0.4 --workspace
cargo tree -i wasmtime-wasi --workspace
cargo tree -i wasi-filesystem --workspace
cargo deny check
cargo audit
cargo test -p synvoid-repo-guards --profile ci advisory_ignores_carry_owner_and_review_metadata
```

Record which Wasmtime version each advisory applies to. Do not repeat the
Phase 102 shorthand that could be read as saying both advisories affect both
lines:

- 0315: affected 47.0.4; 36.x unaffected;
- 0316: affected 36.0.15 and 47.0.4.

Also record the current lock paths for `rsa 0.9.10`, `rkyv 0.7.46`,
`yara-x`, `minify-html`, `parcel_sourcemap`, and the two Wasmtime
instances.

## Workstream B — patch the direct 36 LTS runtime

Move the direct runtime to **Wasmtime 36.0.16**.

Update together:

- `crates/synvoid-plugin-runtime/Cargo.toml`;
- root `Cargo.toml` bench dev-dependency;
- current-version comments;
- `architecture/dependency_security_baseline_phase25.md` direct-version
  guard anchor and current authority;
- guard expectations/messages that intentionally identify the current direct
  LTS patch.

Use a targeted update and inspect the actual lock delta:

```text
cargo update -p wasmtime@36.0.15 --precise 36.0.16
```

The direct line remains Wasmtime 36 LTS. Do not move the plugin runtime to
48 merely to collapse duplicate majors.

Required direct-runtime qualification:

```text
cargo test -p synvoid-plugin-runtime --profile ci
cargo check -p synvoid-plugin-runtime --all-targets
cargo check --benches
```

Re-run the existing plugin fuel/epoch/resource-limit and pool isolation tests.
No fuel, epoch, host-call, memory, signature, or sandbox budget may be
weakened to accommodate the patch.

## Workstream C — qualify Wasmtime 48.0.3 under the YARA compatibility fork

### C1. Disposable probe first

In a disposable working copy or reversible implementation branch:

1. keep the vendored source base at official `yara-x 1.20.0`;
2. change only its native Wasmtime requirement from `47.0.4` to
   `48.0.3`;
3. update the fork MSRV from 1.94 to 1.95;
4. resolve the graph without adding git sources or new YARA features;
5. compile and run the YARA qualification suite.

At minimum:

```text
cargo check -p synvoid-yara --all-targets
cargo test -p synvoid-yara --profile ci
cargo test -p synvoid-upload --profile ci
cargo test -p synvoid-jail-runtime --profile ci
cargo test -p synvoid-repo-guards --profile ci
```

Also execute the existing YARA boundary/source-only reload tests that prove
remote compiled bytes are not reintroduced into the executable trust path.

### C2. Manifest-only success branch

If the official 1.20.0 `src/**` and `build.rs` compile/test unchanged
against 48.0.3:

- land the two-line functional manifest delta
  `wasmtime 47.0.4 -> 48.0.3`, `rust-version 1.94 -> 1.95`;
- keep all vendored YARA source byte-identical to official 1.20.0;
- rewrite the fork provenance header/README to describe the current
  project-controlled security delta, not the now-closed PR #769 as if it
  remains an upstream pending fix;
- retain the root path patch and zero-git-source policy;
- update the binding transitive-version anchor to `48.0.3`.

The final lock may legitimately include a broader Wasmtime/Cranelift family
delta because 47 -> 48 is a major runtime family update. Audit that delta
explicitly; do not accept unrelated package movement.

Expected final invariant:

- exactly two resolved Wasmtime versions:
  - `36.0.16` direct plugin-runtime LTS;
  - `48.0.3` transitive YARA LTS;
- no `47.x`, `45.x`, or `40.x` Wasmtime;
- no `wasmtime-wasi` / `wasi-filesystem`;
- no Wasmtime/YARA git source.

### C3. Source-divergence stop branch

If Wasmtime 48.0.3 requires changes to vendored YARA `src/**` or
`build.rs`:

- do not commit a source-divergent compatibility fork under Phase 103;
- capture the exact compiler/API break;
- retain Phase 103 as open/blocked;
- register a narrow corrective plan that evaluates either:
  - a minimal audited source adaptation against official YARA-X source; or
  - a newly released upstream YARA-X line that has moved to a patched
    Wasmtime runtime.

Do not fall back to a 0315/0316 ignore merely to restore CI.

## Workstream D — re-audit the two retained advisory exceptions

Re-run current graph/exposure analysis for:

- `RUSTSEC-2023-0071` / `rsa 0.9.10`;
- `RUSTSEC-2026-0235` / `rkyv 0.7.46`.

For each:

1. enumerate all current reverse dependency paths with `cargo tree -i`;
2. verify whether SynVoid invokes the vulnerable capability;
3. check current upstream fixed-version/removal state;
4. either remove the ignore because the affected package/path is gone, or
   retain it with updated evidence.

If retained, update:

- `deny.toml`: `Reviewed: 2026-10-01`, `Re-audit: 2026-11-01`;
- `.cargo/audit.toml`: mirrored set/current review summary;
- `architecture/dependency_security_baseline_phase25.md`: current evidence;
- current security/release docs that state the live review deadline.

The ignore sets must remain identical. Historical closeouts that recorded the
old 2026-10-01 deadline remain historical evidence and should not be
bulk-edited.

## Workstream E — re-audit and harden temporary compatibility-fork policy

### minify-html fork

Re-check official `minify-html` release state and its Oxc dependency line.

Current research says v0.18.1 is still the latest official release, so the
Phase 39 compatibility fork remains necessary. If implementation-time
upstream state is unchanged:

- retain the fork;
- record `Reviewed: 2026-10-01`;
- set `Re-audit: 2026-11-01`;
- preserve the existing removal condition and minification parity contract.

Do not re-vendor merely to refresh metadata.

### YARA-X fork

Re-check the latest official YARA-X release immediately before implementation.
Current research says v1.21.0 still resolves Wasmtime 45.0.3 and cannot
replace the fork safely.

After Workstream C:

- retain the fork only if official upstream still lacks a patched Wasmtime
  line;
- record current upstream release/PR status;
- set `Reviewed: 2026-10-01`;
- set `Re-audit: 2026-11-01`;
- update removal condition to require an official YARA-X release whose
  resolved Wasmtime line is clean for the advisories relevant to SynVoid's
  enabled features.

### Guard improvement

Refactor the fork guards so they validate review metadata semantically instead
of asserting a literal date string.

Prefer a small shared helper in
`tools/synvoid-repo-guards/tests/dependency_security.rs` that:

- extracts one `Reviewed:` date and one `Re-audit:` date from the
  relevant fork metadata block;
- validates strict calendar format;
- requires `Re-audit > effective_review_date()`;
- uses the existing `SYNVOID_SECURITY_REVIEW_AS_OF` override for
  deterministic tests;
- checks `Owner:` and `Removal condition:`;
- has unit tests for valid, expired, malformed, and conflicting dates.

Keep each fork's structural/security guard separate:

- minify fork still pins the intended upstream package/Oxc delta and no-git
  source;
- YARA fork still pins the intended official source base, selected Wasmtime
  version, no-git source, consumer feature contract, and source-delta policy.

Do not generalize away the security-specific invariants merely to share date
parsing.

## Workstream F — update dependency-security authority and guard anchors

Update current authority so guards and documentation describe the final
resolved graph.

At minimum inspect/update as applicable:

- `architecture/dependency_security_baseline_phase25.md`;
- `deny.toml`;
- `.cargo/audit.toml`;
- `Cargo.toml` current temporary-fork comments;
- `third-party/yara-x-compat/Cargo.toml`;
- `third-party/yara-x-compat/README.SYNVOID.md`;
- `third-party/minify-html-compat/Cargo.toml` metadata only if retained;
- its `README.SYNVOID.md` metadata if it carries current review claims;
- `crates/synvoid-plugin-runtime/Cargo.toml`;
- `crates/synvoid-yara/Cargo.toml` current-version/provenance comments;
- `SECURITY.md`;
- `docs/RELEASE.md`;
- `architecture/release_profile_matrix.md`;
- `.opencode/skills/supply_chain/SKILL.md`;
- `tools/synvoid-repo-guards/tests/dependency_security.rs`.

Expected current anchors after the successful manifest-only branch:

```text
wasmtime-direct-version = "36.0.16"
wasmtime-transitive-version = "48.0.3"
wasmtime-wasi-absent-from-lock = true
```

Replace guard assertions/messages that encode 36.0.15/47.0.4 as current
truth. Preserve explicit historical statements where the old versions are
the subject of recorded evidence.

Add current baseline sections for 0315/0316 that state fixed ranges,
resolved versions, reachable capability assessment, and why no ignore is
present.

## Workstream G — focused runtime/performance qualification

A full repository-wide performance campaign is not warranted, but the YARA
runtime crosses a Wasmtime major boundary, so run a focused before/after
comparison on the same host and fixtures.

Measure at minimum:

- representative YARA rule compilation;
- clean scan;
- matching scan;
- reload/recompile path.

Use the existing Phase 40 style of bounded evidence where possible. Record
raw command/configuration and enough repetitions to distinguish obvious
regression from host noise.

Investigate any material repeatable regression before closeout. Do not
declare a regression from a single noisy sample.

The direct 36.0.15 -> 36.0.16 patch does not require a standalone performance
campaign unless plugin-runtime tests or measurements expose a change.

## Workstream H — small Phase 102 documentation cleanup

Perform these docs-only corrections in the same maintenance tranche:

1. In
   `architecture/eggfetch_0_2_1_patch_adoption_closeout.md`, remove the
   duplicate “Hosted CI / native qualification: not invoked…” bullet,
   leaving the statement once.
2. In `plans/roadmap.md`, rename the older Eggfetch campaign heading from
   “Phase 64 Docs Correction Active” to wording that reflects Phase 64's
   closed state.

Do not alter Phase 102's disposition, implementation SHA, test evidence, or
Phase 63 performance authority.

## Workstream I — final dependency/security verification

After the final graph is resolved, run and record:

```text
cargo tree -i wasmtime@36.0.16 --workspace
cargo tree -e features -i wasmtime@36.0.16 --workspace
cargo tree -i wasmtime@48.0.3 --workspace
cargo tree -e features -i wasmtime@48.0.3 --workspace
cargo tree -i wasmtime-wasi --workspace
cargo tree -i wasi-filesystem --workspace

cargo tree -i rsa@0.9.10 --workspace
cargo tree -i rkyv@0.7.46 --workspace

cargo test -p synvoid-plugin-runtime --profile ci
cargo test -p synvoid-yara --profile ci
cargo test -p synvoid-upload --profile ci
cargo test -p synvoid-jail-runtime --profile ci
cargo test -p synvoid-repo-guards --profile ci
cargo test --test security_regression --profile ci -- --test-threads=1

cargo fmt --all -- --check
cargo clippy --profile ci --all-targets -- -D warnings
cargo deny check
cargo audit
cargo xtask verify
cargo xtask verify-full
```

If a package has no reverse path for an expected-retired version, the
corresponding `cargo tree -i` no-match is evidence and should be recorded
as such.

Also verify:

- the root/default and honestly minimal profiles still compile;
- any plugin/YARA feature profiles used by release qualification remain green;
- YARA source-only remote trust boundary remains intact;
- no `git+` package entered `Cargo.lock`;
- the advisory-ignore sets in deny/audit remain identical;
- the repo-guard tests pass with current UTC review semantics.

Run `cargo xtask verify-release` when the tree is clean enough for its
dirty-tree policy; otherwise record the exact non-product blocker and still
require the individual release security checks to pass.

## Workstream J — hosted exact-SHA proof and closeout

Unlike Phase 102, hosted proof is mandatory here.

Push the proof-bearing implementation SHA and require the normal GitHub
Actions workflow to complete with:

- `ci`: success;
- `dependency-security`: success.

Do not accept a scheduled or prior SHA as proof for the final dependency
graph.

Native sandbox/ICMP qualification lanes are not required unless this phase
touches those mechanisms; they should remain skipped under a normal push.

After green exact-SHA hosted evidence, write:

`architecture/dependency_security_reaudit_phase103_closeout.md`

The closeout must record:

- planning baseline;
- proof-bearing implementation SHA;
- closeout SHA;
- hosted workflow run ID/link;
- Wasmtime direct/transitive final versions and source paths;
- 0315/0316 disposition and absence of new ignores;
- exact Wasmtime/Cranelift lock delta;
- `wasmtime-wasi`/filesystem absence proof;
- YARA fork source-delta proof (manifest-only, if that branch succeeds);
- YARA-X latest official release reviewed and why fork removal did/did not
  trigger;
- minify-html latest official release reviewed and why fork removal did/did
  not trigger;
- retained advisory-ignore paths, capability evidence, new review deadlines,
  and removal conditions;
- focused YARA performance evidence;
- all verification results;
- documentation cleanup disposition.

Then update this plan and `plans/roadmap.md` to **CLOSED QUALIFIED**.

## Acceptance criteria

Phase 103 may close only when:

1. direct Wasmtime resolves to `36.0.16` or a newer security-patched 36 LTS
   patch explicitly re-researched at implementation time;
2. YARA's Wasmtime resolves to `48.0.3` or a newer security-patched supported
   line that has been explicitly compatibility-qualified;
3. no resolved Wasmtime version is affected by 0315/0316;
4. no ignore for 0315/0316 exists in deny/audit policy;
5. exactly the intended Wasmtime owners remain and `wasmtime-wasi` stays
   absent;
6. no git source or arbitrary contributor branch is introduced;
7. the YARA fork remains source-identical to its declared official source base
   unless a separately registered corrective explicitly authorizes source
   divergence;
8. YARA remote/source-only execution and deterministic old-artifact rejection
   remain intact;
9. the two retained advisory exceptions are freshly re-triaged or removed;
10. every retained ignore and temporary fork has future, machine-enforced
    review metadata and an event-based removal condition;
11. `cargo deny check` and `cargo audit` are green under the final policy;
12. `cargo xtask verify` and `cargo xtask verify-full` are green;
13. focused YARA runtime evidence shows no unexplained material regression;
14. the Phase 102 duplicate/stale-heading docs defects are corrected without
    rewriting historical evidence;
15. hosted `ci` and `dependency-security` both pass on the exact
    proof-bearing SHA.

## Rejection / corrective triggers

Do not close this phase by:

- adding 0315/0316 to advisory ignores when a patched release is available;
- switching to stock YARA-X 1.21.0 while it still resolves affected
  Wasmtime 45.0.3;
- depending on the closed PR #769 contributor branch;
- accepting a YARA source fork under the guise of a manifest-only security
  bump;
- moving the plugin runtime to Wasmtime 48 solely for version convergence;
- enabling WASI filesystem capabilities;
- weakening plugin fuel, epoch, resource, signature, sandbox, or host-call
  limits;
- restoring remote compiled-YARA deserialization;
- deleting RSA/rkyv ignores without proving the affected dependency path is
  gone or remediated;
- merely pushing the expired review dates forward without re-triaging current
  upstream/dependency state;
- hard-coding the next review date into guard source instead of making the
  fork-review check time-aware;
- accepting unrelated lockfile churn without explanation;
- calling local test success equivalent to the required hosted
  dependency-security proof.

Any YARA 48 compile/API break requiring vendored source modification is a
corrective-plan trigger, not permission to widen this phase silently.

## Non-goals

- No general YARA-X 1.21 feature upgrade.
- No Wasmtime-major convergence campaign.
- No plugin ABI redesign.
- No WASI enablement.
- No broad dependency refresh.
- No new supply-chain source exception.
- No replacement of `minify-html` or YARA-X with project-specific engines.
- No reopening of Eggfetch transport/performance qualification.
- No changes to deferred mesh-consensus, process-manager/IPC, or
  `synvoid-filter` architecture candidates.
