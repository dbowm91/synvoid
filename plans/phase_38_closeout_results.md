# Phase 38 Closeout: Runtime Dependency Security Closeout and Guard Reconciliation

Status: complete (2026-09-17).
Plan: `plans/phase_38_runtime_dependency_security_closeout.md`.
Roadmap: `plans/runtime_dependency_security_followup_roadmap.md` (Phase 38 closes it).

## Landed state vs plan expectation

The plan expected YARA-X 1.20.x with a transitive Wasmtime 45.x line. That
upgrade did NOT land: Phase 36 closed the GHSA-2jx3-ff3v-j7jj exposure on
yara-x 1.15 (source-only trust) while the >=1.19 engine upgrade stays blocked
by the same-major `bumpalo` conflict. This closeout records the actual graph.

Before (Phase 37 exit) → after (Phase 38 exit):

| Item | Before | After |
|---|---|---|
| yara-x | 1.15.0 | 1.15.0 (unchanged; >=1.19 blocked) |
| Transitive wasmtime (via yara-x) | 40.0.4 | 40.0.4 (unchanged) |
| Direct wasmtime (plugin-runtime) | 36.0.15 LTS | 36.0.15 LTS (unchanged) |
| bumpalo | 3.19.0 (single) | 3.19.0 (single; unchanged) |
| wasmtime-wasi / wasi-filesystem | absent | absent (unchanged) |
| Git sources | none | none (unchanged) |
| cryptoki | 0.12.0 (vulnerable to 0286) | **0.12.1** (fixed; targeted bump) |
| Advisory ignores | 16 | 16 (verified exact; none stale) |
| `YARA_ENGINE_VERSION` | `yara-x/1.15` | `yara-x/1.15` (guard-pinned to manifest) |

Exact landed versions: yara-x 1.15.0, wasmtime 36.0.15 + 40.0.4, bumpalo
3.19.0, minify-html 0.18.1 → oxc_allocator 0.95.0, cryptoki 0.12.1.

## Supported/EOL dates

- Wasmtime 36 LTS: supported through 2027-08-20; 36.0.14+ patched for
  RUSTSEC-2026-0269 (direct 36.0.15 needs no ignore).
- Re-audit: 2026-10-01 for all 16 ignores (machine-enforced by
  `deny_ignore_metadata_guard` against current UTC date).

## Advisory ignores removed/retained

Removed: none (proven correct — with `.cargo/audit.toml` temporarily removed,
every one of the 16 fires on the live graph: 0071 rsa 0.9.10; 0085–0096,
0114, 0222, 0269 wasmtime 40.0.4; 0235 rkyv 0.7.46). No stale 40.x/42.x
entries beyond the live 40.0.4 line; no direct-42 exception remains (Phase 37
removed it and no 42.x package resolves).

Retained (16, all with Owner/Reviewed/Re-audit/Remove-condition): as above.
The 0269 ignore covers the transitive 40.0.4 instance only (per-advisory
ignores cannot split per package); direct 36.0.15 is patched by version.

Fixed by upgrade, not ignore: RUSTSEC-2026-0286 (cryptoki 0.12.0 OOB read,
dated 2026-09-16, found by `cargo audit` during this phase) → cryptoki
0.12.1 via targeted `cargo update -p cryptoki --precise 0.12.1` (2-line lock
diff). Opt-in surface only (`synvoid-dnssec-keystore/pkcs11`, off by default;
normal builds carry no `cryptoki`), but upgraded regardless. `cargo audit`
and `cargo deny check` both clean after.

## Proof remote compiled YARA bytes are non-executable

- Static: zero `Rules::deserialize` calls in workspace production code
  (`grep` + three new guards: `mesh_must_not_call_rules_deserialize`,
  `upload_must_not_call_rules_deserialize`,
  `synvoid_yara_has_no_remote_deserialize_path` — all pass).
- Removed-token guard (`mesh_must_not_prefer_compiled_bytes_over_source`):
  `reload_with_compiled_rules`, `deserialize_verified`,
  `from_bytes_with_binding`, `local_compiled_rules`, `apply_compiled_rules`,
  `get_current_compiled_rules`, `CompiledBundle` absent from production code.
- Behavior: mesh `yara_approval_boundary` (11 pass) pins source-text-canonical
  storage and announce-path source application; `yara_boundary` (8 pass) pins
  binding-only rejection (wrong engine, foreign line, tampered bytes) and
  local-recompile success; `verify_binding` tests pin digest/version/engine
  mismatch rejection without deserialization.
- Engine binding: `yara_engine_version_matches_manifest` guard pins
  `YARA_ENGINE_VERSION` (`yara-x/1.15`) to the manifest major.minor.

## Proof direct git Wasmtime source is gone

- No `bytecodealliance/wasmtime` in root manifest; no `git+` source in
  `Cargo.lock`; `deny.toml` `unknown-git = "deny"` with no `allow-git`.
- New `wasmtime_has_no_git_source` guard scopes the lock check to wasmtime
  blocks; `wasmtime_direct_version_matches_baseline` retains the manifest
  check. Both pass.

## Feature-surface delta

None. Direct features remain defaults + `component-model` (minimization
evaluated in Phase 37, deferred with rationale). Transitive yara-x features
remain `default-modules` + `linkme`. No WASI, no new capabilities.

## Performance/footprint delta

No runtime-code changes in this phase (guards + docs + cryptoki patch bump
only). No bench re-run claimed; Phase 37 bench deltas stand (36 LTS ~5–8%
faster than 42.0.2-git on `bench_wasm`). Lock diff: cryptoki 0.12.0 → 0.12.1
(2 lines) plus no other moves.

## Verification results (local, 2026-09-17)

- `cargo fmt --all -- --check`: clean (after `cargo fmt` normalization of new guards).
- `cargo audit`: clean (6 allowed unmaintained warnings only).
- `cargo deny check`: advisories/bans/licenses/sources ok.
- `cargo test -p synvoid-repo-guards --profile ci`: all suites pass
  (dependency_security 18, yara_execution_boundary 10, plus all others).
- `cargo test -p synvoid-yara --profile ci`: 349 lib + 7 + 6 pass;
  `-p synvoid-mesh --test yara_approval_boundary`: 11 pass;
  `-p synvoid-plugin-runtime`: 349 + 7 + 6 pass; `-p synvoid-upload`: pass.
- `cargo check --no-default-features [--features mesh|dns|mesh,dns] --profile ci`: all four compile.
- Full `cargo xtask verify` / `verify-full` / `verify-release`: see below
  (run before push; release fails on dirty tree by design).

## Remaining risks and future triggers (event-based)

1. yara-x 1.15 stays inside GHSA-2jx3-ff3v-j7jj (<=1.18 affected, NOT patched,
   no ignore — advisory has no RUSTSEC ID). Residual risk is local-only
   (operator artifact bytes); remote path closed by construction + guards.
   Trigger: yara-x moves to a supported Wasmtime line clearing the transitive
   advisory → upgrade engine, bump `YARA_ENGINE_VERSION`, pin a 1.15-artifact
   rejection test.
2. Transitive wasmtime 40.0.4 stays inside RUSTSEC-2026-0269 (capability-gated
   only). Trigger: same yara-x move → drop the wasmtime ignore group.
3. `bumpalo` conflict blocks both upgrades until upstream minify-html/oxc
   relaxes `=3.19.0`. Trigger: new minify-html/oxc release → re-attempt.
4. Wasmtime 48 LTS resolver-compatibility. Trigger: blocker clears → evaluate
   48 LTS move per Phase 37 method (isolated scratch proof first).
5. WASI filesystem intentionally added. Trigger: `wasmtime-wasi` appears →
   guards fail closed pending exposure review + baseline §3 update.
6. New YARA serialized-artifact consumer. Trigger: guards fail closed pending
   trust review (never checksum-alone).
7. 36 LTS approaches EOL (2027-08-20) or new advisory hits a resolved package
   (cf. cryptoki 0286 here). Trigger: re-triage at Re-audit 2026-10-01 or on
   advisory publication; prefer upgrade over ignore where a fix exists.

## Docs updated

`architecture/dependency_security_baseline_phase25.md` (title + §7 stale-42
fix + §9 Phase 38 addendum), `architecture/mesh.md` (worker-supervision
deferral superseded by Iterations 82/85),
`docs/testing/verification-contract.md` (≥46 toolchain note → current
policy), `.opencode/skills/supply_chain/SKILL.md` (ignore-exactness method +
cryptoki precedent + new guards). Historical phase/closeout reports left as
dated snapshots. `README.md`/`AGENTS.md` need no version-pin changes
(verified: README has none; AGENTS Known Issues already describes the landed
graph).
