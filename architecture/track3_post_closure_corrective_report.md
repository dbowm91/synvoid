# Track 3 Post-Closure Corrective Report

Status: corrective closure evidence for `plans/track3_post_closure_corrective.md`.
Tracks 1–3 are complete; this report records only the corrective pass — it does
not duplicate the Track 3 performance or architecture reports.

## 1. Corrective revision

- Corrective implementation commit: (final commit SHA recorded at closeout)
- Base: Track 3 closeout `23949197311f1066abd4bc622c43cada615b1425`
  (Phase 24) via handoff commit `945a29b7` (corrective plan)
- Fuzz toolchain: cargo-fuzz 0.13.2, nightly rustc 1.100.0
  (`cargo 1.100.0-nightly (b2e9d5f9d 2026-09-02)`)

## 2. Workflow inventory

`.github/workflows/` contains exactly one file: `ci.yml` — a single Ubuntu
job running `cargo xtask verify`. No `fuzz-smoke` job, no
`nightly-qualification.yml`, no dedicated tarpit/mesh jobs, no per-PR fuzz
execution. Fuzz smoke is manual
(`cargo +nightly fuzz run <target> -- -runs=1000`); see the frozen
`docs/testing/verification-contract.md` §10.

## 3. Routine CI

- Local `cargo xtask verify`: PASS — 8/8 steps (fmt, clippy, core check,
  repo-guards, security regression single-threaded, 20-suite root guards with
  `--features mesh`, synvoid-core admin tests, failure injection) in ~450s on
  the corrective tree. (One transient Apple-clang-21 linker segfault on
  `async-trait` during clippy required a retry per verification-contract
  §14 BUG-002 workaround; environment-only, unrelated to the changes.)
- Remote CI (push to `main`): (status/link recorded after push).

## 4. `verify-full` result

PASS — 7/7 steps on the corrective tree: fmt, clippy, mesh-only compile,
DNS-only compile, mesh+dns compile, broad workspace nextest
(`--exclude synvoid-fuzz`), and workspace doctests, in ~565s. No new
failures; the `nextest-all` workspace run (6925 tests) is green including the
8 new `synvoid-config` seam tests.

## 5. `verify-release` result

PASS — 9/9 steps on the corrective tree (run with `--allow-dirty` since the
tree carried the corrective changes pre-commit; all other validation behavior
unchanged): full local verification, all-features clippy, release-profile
compilation, package metadata/dependency/content inspection, and per-crate
package qualification. Summary: `PRE-PUBLICATION READY WITH DEFERRED REGISTRY
CHECKS` — zero `NotPrepublishable`/`Failed` states; remaining qualifications
are `DeferredOnInternalPredecessors` per the normal manual publication order
(printed, ending with `synvoid-wasm-pow`). No `cargo publish` invoked.

## 6. Fuzz target execution table (bounded smoke, `-runs=1000`)

| Target | Command | Runs | Status | Notes |
|--------|---------|------|--------|-------|
| `http_chunked_framing` | `cargo +nightly fuzz run http_chunked_framing -- -runs=1000` | 1000 | DONE, no crash/hang | cov 242 |
| `jail_ipc_frame_decode` | `cargo +nightly fuzz run jail_ipc_frame_decode -- -runs=1000` | 1000 | DONE, no crash/hang | cov 211 |
| `http_routing_matcher` | `cargo +nightly fuzz run http_routing_matcher -- -runs=1000` | 1000 | DONE, no crash/hang | cov 3171 |
| `config_parse_validation` | `cargo +nightly fuzz run config_parse_validation -- -runs=1000` | 1000 | DONE, no crash/hang | cov 680 |

No deterministic crashes were produced, so no new crash-derived regression
tests were required. Each target completed with exit 0, an empty artifacts
directory, and no sanitizer findings.

## 7. Config fuzz target disposition

Closed. `MainConfig::from_toml_str` (`crates/synvoid-config/src/main_config.rs`)
and `SiteConfig::from_toml_str` (`crates/synvoid-config/src/site/mod.rs`) are
minimal in-memory seams shared by the production file loaders
(`from_file` delegates to the seam, then applies operator side-effects:
admin-token resolution and mesh key/identity loading for main configs).
The `config_parse_validation` target (registered in `fuzz/Cargo.toml`, driving
`synvoid-config` with `dns,mesh` features to match the production default)
covers both paths via a leading selector byte with a 16 KiB input cap. Eight
deterministic unit tests lock the seam behavior (garbage rejection, typed
validation errors, valid-config acceptance, `from_file` delegation) and pass
with and without the `dns,mesh` features.

## 8. `serder` disposition

Removed. `src/serder.rs` (migration-documentation stub + feature-gated `rkyv`
re-export, zero internal/external consumers) and `pub mod serder` in
`src/lib.rs` were deleted; canonical serialization remains
`synvoid_utils::serialization` (re-exported as `synvoid::serialization`). The
`rkyv` Cargo feature and dependency are unchanged (`cargo check --features
rkyv` passes). Still-useful serialization-strategy guidance was folded into
`architecture/utils.md` §6; `architecture/serder.md` was removed and its sole
markdown link updated. Ledger (`root_module_ledger.md`), surface audit
(`final_surface_audit.md`), release-hardening report, and admin-root ownership
docs updated; removal recorded as a breaking change in `CHANGELOG.md`
`[Unreleased]` (transitional root surface, no compatibility promises per
`architecture/semver_stability_policy.md`).

## 9. Documentation reconciliation

- `plans/roadmap.md`: header now states Tracks 1–3 are complete with this
  corrective pass as the only active handoff; "Current Architectural Position"
  carries the post-Track-3 state (canonical enforcement contract, crate-owned
  auth/challenge, WAF/HTTP composition boundaries, explicit admin/plugin
  ownership, operational jail IPC, binding distributed-state contract, zero
  `split_required`, routine CI on the final Track 3 commit).
- `architecture/ci_fuzz_failure_injection.md`: CI-integration line now states
  fuzz smoke is manual-only in the single-workflow topology; inventory grows
  20 → 21 with the high-value table closed out.
- `architecture/phase_14_fuzz_execution_report.md`: banner marks the recorded
  `fuzz-smoke`/`nightly-qualification.yml` topology as historical/superseded.
- `architecture/release_hardening_report.md`: Phase 11 section marked
  historical; config-fuzz deferral closed; `serder` removal checked.
- `architecture/track3_performance_report.md` §6: 1000-run evidence amended
  alongside the original 300-run closure rows.
- Counts reconciled to 21 targets (`docs/testing/verification-contract.md`,
  `AGENTS.md`, `architecture/overview.md`, raft-consensus skill, CHANGELOG).
- Workspace metadata corrected: 45 members / 37 `synvoid-*` crates / 35
  skills (`AGENTS.md`, `architecture/overview.md`).

## 10. Remaining accepted residuals

- Historical result/plan documents retain their original CI/fuzz topology
  descriptions where clearly labeled historical/superseded (Phase 14 report,
  Phase 11 section of the release-hardening report, 2026-05-28 review plan).
- Fuzz corpus artifacts generated by the bounded runs (`fuzz/corpus/`) are
  local-only and intentionally untracked.
