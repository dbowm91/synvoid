# Phase 36 Closeout: YARA-X Deserialization Exposure Closure

Status: partial-landing (2026-09-17). Trust-model closure complete; engine upgrade blocked.

Plan: `plans/phase_36_yara_x_deserialization_exposure_closure.md`.

## What landed (Parts A–C, E–H as applicable)

**Trust model** (the remotely-exploitable path is gone):

> Signed/approved YARA **source text** is the canonical executable input.
> Compilation occurs locally inside the YARA execution boundary. Wire
> compiled bytes are opaque/non-executable metadata.

Removed (no call site remains for remote bytes into a deserializer):

- `YaraScanner::reload_with_compiled_rules` (the `yara_x::Rules::deserialize`
  entry point) — `crates/synvoid-yara/src/engine.rs`;
- `CompiledArtifact::{deserialize_verified, from_bytes_with_binding}` —
  `crates/synvoid-yara/src/artifact.rs` (kept: `compile` for local source,
  `verify_binding` metadata-only, `rule_digest`/`version_binding`);
- `YaraRulesManager::{local_compiled_rules, get_current_compiled_rules,
  apply_compiled_rules}` + dead `fetch_compiled_rules_from_dht` —
  `crates/synvoid-mesh/src/mesh/yara_rules.rs`;
- `YaraRuleSourceType::CompiledBundle` (dead variant implying executable
  authority) — `crates/synvoid-yara/src/engine.rs`.

Rewired:

- `UploadValidator::reload_yara_rules_if_needed` recompiles source via
  `reload_with_rules`; a version bump with no acceptable source retains the
  previous generation (fail-closed per upload policy) — never a blob fallback.
- Mesh receive paths (`YaraCompiledRuleAnnounce`, DHT sync) already ignored
  compiled bytes after checksum; now nothing stores them either. Protocol
  `compiled_rules` fields stay for wire compat only.

Tests (Part A pin + Part F revalidation):

- `crates/synvoid-yara/tests/yara_boundary.rs`: engine-mismatch rejection,
  local-recompile-from-source, invalid-source-retains-generation;
- `crates/synvoid-yara/src/engine.rs` unit tests converted to source-only
  (reload/error-tracking/provenance/generation-preservation);
- `crates/synvoid-mesh/tests/yara_approval_boundary.rs`:
  `source_text_is_canonical_no_compiled_storage`,
  `mesh_origin_compiled_bytes_never_reach_execution`;
- `crates/synvoid-upload/src/lib.rs` mesh_reload: source-local-compile
  detection, no-compiled-preference (with scan proof), invalid-source
  retains previous, scan-with-new-rules, same-version noop.

Evidence: `cargo test -p synvoid-yara` (53 + 8 pass),
`cargo test -p synvoid-upload --all-features` (130 pass),
`cargo test -p synvoid-jail-runtime --all-features` (pass, incl. yara jail
load/scan/unload round-trip), mesh `yara_approval_boundary` (11 pass),
`cargo xtask verify` 10/10 locally, `cargo deny check` + `cargo audit` clean
(9 pre-existing allowed warnings).

## What did NOT land (Part D engine upgrade — blocked, not skipped)

Target `yara-x >=1.19` (GHSA-2jx3-ff3v-j7jj fix) does not resolve in this
workspace:

- yara-x 1.19.0 → `wasmtime ^43.0.2`; 1.20.0 → `wasmtime ^45.0.3`;
  wasmtime >=43 needs `bumpalo ^3.20.0`.
- `minify-html` 0.18.1 (latest) → `oxc_allocator` 0.95.0 (only 0.95.x) pins
  `bumpalo =3.19.0` exactly (non-optional dep).
- Cargo cannot split same-major selections: reproduced 2026-09-17 in an
  isolated scratch crate (`oxc_allocator =0.95.0` + `wasmtime =45.0.3`) and
  with two local crates (`bumpalo =3.19.0` vs `^3.20.0`) — same failure the
  Phase 25 baseline (§4) recorded for wasmtime 46.0.3.

Consequences (all deliberate, all documented):

- Final graph unchanged: yara-x 1.15.0 / wasmtime 40.0.4 / direct 42.0.2.
- `YARA_ENGINE_VERSION` stays `yara-x/1.15`; `COMPILED_FORMAT_VERSION` stays 1
  (envelope unchanged; engine-only incompatibility goes through the engine tag
  when the upgrade lands — foreign-line rejection probe in place).
- **No advisory ignore added** for GHSA-2jx3-ff3v-j7jj (no RUSTSEC ID mapped;
  nothing to ignore). 1.15 is never called patched. Residual risk is
  local-only bytes into a local-only deserializer (no remote path), fail-closed
  with generation retention. Disclosed in `SECURITY.md` + baseline §7.
- Re-audit with the 2026-10-01 dependency review (upstream minify-html/oxc
  release clears the pin).

## Docs updated (pruned to what changed)

- `AGENTS.md` Known Issues (Phase 36 entry), `SECURITY.md` (source-type table,
  new GHSA section), `architecture/{upload,mesh}.md` (source-type/manager rows),
  `architecture/dependency_security_baseline_phase25.md` §7 (closeout evidence),
  `.opencode/skills/{raft_consensus,supply_chain}/SKILL.md` (removed
  `deserialize_verified` sample; recorded block).
- Untouched as retained history: all prior `plans/*` and closure reports.
- `README.md` needs nothing (generic YARA mention, no version claims).

## Acceptance mapping

- [x] no mesh/remote compiled bytes can reach `Rules::deserialize` (API gone)
- [x] remote execution recompiles approved source locally
- [x] any remaining compiled API is metadata-only or removed
- [x] upload/jail/reload behavior correct under failure policies
- [x] `cargo audit`/`cargo deny` truthful (no new ignores, none removed)
- [ ] `synvoid-yara` >=1.19 — BLOCKED (above); trust closure removes the
      remote exploit path in the meantime
- [ ] old 1.15 artifacts reject under new engine — N/A until upgrade (probe
      test + bump instruction recorded in baseline §7)
- [ ] old Wasmtime 40.0.4 path absent — N/A until upgrade
