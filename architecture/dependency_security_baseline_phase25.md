# Dependency Security Baseline — Phase 25 Evidence (current through Phase 39)

Status: binding evidence for Track 4 Phase 25 (`plans/phase_25_dependency_security_baseline_and_entitlement.md`).
Owner: security / release. Reviewed: 2026-09-18 (Phase 39: minifier/Oxc
blocker remediation via temporary vendored compat fork; YARA engine still
1.15, Phase 40 owns the upgrade).
Re-audit: 2026-10-01 (all advisory ignores; see §5).

This file records version, features, and reachable capability **separately** for every
security-relevant dependency decision. It is the authority the repo guards check
against; `deny.toml` comments summarize, this file proves.

Tool versions frozen by this phase (see `docs/testing/verification-contract.md`):

| Tool | Pinned version | Pinned how |
|------|---------------|------------|
| Rust compiler | 1.98.1 | `rust-toolchain.toml` (`channel = "1.98.1"`) |
| cargo-nextest | 0.9.140 | CI `taiki-e/install-action` `tool: nextest@0.9.140` |
| cargo-deny | 0.20.2 | CI `taiki-e/install-action` `tool: cargo-deny@0.20.2` |
| cargo-audit | 0.22.2 | CI `taiki-e/install-action` `tool: cargo-audit@0.22.2` |
| GitHub Actions | SHAs in `.github/workflows/ci.yml` | immutable commit + tag comment |

Evidence commands (run 2026-09-17 for the Phase 38 closeout, advisory DB current at run time):

```bash
cargo tree -i wasmtime@36.0.15 --workspace
cargo tree -e features -i wasmtime@36.0.15 --workspace
cargo tree -i wasmtime@40.0.4 --workspace
cargo tree -e features -i wasmtime@40.0.4 --workspace
cargo tree -i yara-x --workspace
cargo audit
cargo deny check advisories
```

## 1. Direct Wasmtime path (plugin runtime)

<!-- guard-anchor: wasmtime-direct-version = "36.0.15" -->
<!-- guard-anchor: wasmtime-transitive-version = "40.0.4" (via yara-x 1.15.0) -->
<!-- guard-anchor: wasmtime-wasi-absent-from-lock = true -->

- Version: **36.0.15** (Wasmtime 36 LTS line, supported through 2027-08-20),
  from crates.io. No `[patch.crates-io]` entry, no git source (Phase 37
  removed the 42.0.2 git patch; `Cargo.lock` contains no `git+` source).
- Requested features (`crates/synvoid-plugin-runtime/Cargo.toml`): `component-model` only
  (default features still enabled; minimization evaluated and deferred — see §8).
- Consumers (`cargo tree -i wasmtime@36.0.15`, verified 2026-09-17): exactly
  `synvoid-plugin-runtime` (plus the root dev-dependency used by
  `benches/bench_wasm.rs`, pinned to the same 36.0.15).
- Reachable capability: core WASM compilation/execution + component model.
  **WASI filesystem is absent**: `synvoid-plugin-runtime` does not depend on
  `wasmtime-wasi`, no `wasmtime_wasi::` import exists in `crates/synvoid-plugin-runtime/src/`
  or `src/plugin/`, and `Cargo.lock` contains no `wasmtime-wasi`, `wasi-filesystem`,
  `wasi-common`, or `cap-std` filesystem package (only the inert `wasi`/`wasip2`/`wasip3`
  WIT type crates). The `wasi_enabled` flag in `wasm_runtime.rs` is config plumbing
  that emits a debug log only; it cannot construct a WASI filesystem context because
  the implementation crate is not linked.

## 2. Transitive Wasmtime path (YARA compilation)

- Version: **40.0.4** from crates.io, via `yara-x 1.15.0`.
- Consumers (`cargo tree -i wasmtime@40.0.4`, verified 2026-09-13): `synvoid-yara`
  (single owner since Phase 26) → `synvoid-upload`, `synvoid-jail-runtime`, root.
  `synvoid-mesh` no longer links `yara-x`.
- Enabled features (via yara-x `default-modules` + `linkme`): `cranelift`, `std`,
  `runtime`; **no `wasi` feature** in the resolved feature graph.
- Reachable capability: YARA rule bytecode compilation/execution only.
  yara-x never constructs a WASI filesystem context; rule sources are compiled from
  memory/operator-provided files through yara-x's own loader, not through
  `wasmtime-wasi` preopens. Same lockfile evidence as §1 (no `wasmtime-wasi` package).

## 3. RUSTSEC-2026-0269 assessment (GHSA-vqjp-4c8c-hfgg)

- Affected range: Wasmtime 37.0.0 through 46.0.2 except backported LTS lines.
  Patched (advisory DB `patched` array): >=24.0.13,<25.0.0; **>=36.0.14,<37.0.0**;
  >=46.0.3,<47.0.0; >=47.0.4.
- **The direct 36.0.15 LTS line is patched** (36.0.15 >= 36.0.14; additionally
  proven by a clean `cargo audit` on an isolated wasmtime-36.0.15 resolve with
  no ignores, 2026-09-17 — zero findings). The direct plugin-runtime path needs
  no 0269 ignore. The transitive 40.0.4 line (via yara-x 1.15) IS inside the
  affected range and is NOT patched; the retained per-advisory ignore covers
  that instance only (Phase 38 normalizes the final multi-version record).
  Earlier comments calling 42.0.2 "patched" referred to the 2026-04
  Winch/Cranelift advisories (0085–0096, 0114, 0222), for which 42.0.2 was a
  fixed version; 42.0.2 is gone from the graph (no direct 42.x path remains)
  and that language has been removed wherever it implied 0269 coverage.
- Vulnerable code: `wasmtime-wasi` filesystem sandboxing (trailing-slash path/symlink
  handling). Per §1–§2 the vulnerable crate is **not resolved, not linked, and not
  reachable** from either Wasmtime consumer: no filesystem preopen API is linked, so
  there is no trailing-slash path handling to trigger. This is a capability-absence
  finding from the resolved feature/reachability graph, not from package presence alone
  and not from absence of a PoC.
- Residual risk: a future feature unification could resolve `wasmtime-wasi`
  (e.g. a new dependency enabling WASI filesystem). The `wasmtime_baseline_guard`
  fails if `wasmtime-wasi` (or `wasi-filesystem`) appears in `Cargo.lock` without an
  accompanying exposure update here.

## 4. Why the direct runtime is 36 LTS (Phase 37 resolution)

Upgrade attempted 2026-09-12: `wasmtime 42.0.2 → 46.0.3` (smallest 0269-fixed
normal line at the time), `[patch.crates-io]` removal. Resolution fails
deterministically, including from a clean lockfile and in an isolated scratch crate:

- wasmtime 46.0.3 requires `bumpalo ^3.20.2`.
- `minify-html 0.18.1` (latest) → `oxc_allocator 0.95.0` (only 0.95.x) pins
  `bumpalo =3.19.0` exactly.
- Both requirements are major-version 3: Cargo unifies same-major selections and
  cannot split them, so no lockfile satisfies both. Error reproduced with
  `cargo generate-lockfile` on 2026-09-12.
- No newer minify-html exists upstream to relax the pin; dropping HTML minification
  to force the upgrade would be a product behavior change, explicitly out of scope.

Phase 37 resolution (2026-09-17, `plans/phase_37_wasmtime_lts_runtime_migration.md`):
instead of a newer unsupported normal line, the direct runtime moved to the older
*supported* 36 LTS line (36.0.15; LTS through 2027-08-20; 36.0.14+ patched for
0269). Resolver proof before touching runtime code, in an isolated scratch crate
depending on `wasmtime =36.0.15` + `bumpalo =3.19.0` + `oxc_allocator =0.95.0`:
single `bumpalo 3.19.0` in the lock (wasmtime 36's `cranelift-codegen 0.123.15`
accepts the 3.19 range), `wasmtime-wasi` absent, no git source. The workspace
lock reproduces this exactly: `wasmtime 36.0.15` + `wasmtime 40.0.4` (yara-x
transitive, unchanged), one `bumpalo 3.19.0`, no `wasmtime-wasi`, no `git+`
source. The `deny.toml` 0269 ignore is retained solely for the transitive 40.0.4
instance (per-advisory ignores cannot be split per package); Re-audit: 2026-10-01;
remove condition is now yara-x moving off wasmtime 40.x. The >=46.0.3 normal-line
upgrade (or 48 LTS) is re-attempted only after the `bumpalo` conflict clears via
an upstream minify-html/oxc release.

## 5. Guards (all in `tools/synvoid-repo-guards/tests/`)

- `wasmtime_baseline_guard` (`dependency_security.rs`): direct Wasmtime version must
  equal the version recorded here; no wasmtime git patch may exist in the root
  manifest; `wasmtime-wasi`/`wasi-filesystem` must stay absent
  from `Cargo.lock` unless this file gains a new exposure section; the 0269 ignore must
  be tracked in deny+audit with owner + remove condition, and this file must record
  the direct 36 LTS line as patched.
- `deny_ignore_metadata_guard` (`dependency_security.rs`): every `RUSTSEC-*`/`GHSA-*`
  ignore in `deny.toml` must carry `Owner:`, `Reviewed:`, a single future
  `Re-audit: YYYY-MM-DD`, and a `Remove condition:`; `Re-audit` dates on or before
  the effective current UTC date fail closed (see corrective report for the
  time-aware design; `SYNVOID_SECURITY_REVIEW_AS_OF` overrides for deterministic tests).
- Root dependency entitlement, pure-facade orphan, self-dev feature-leak, and
  verify-contract dry-run guards: see `module_ownership.rs` and
  `docs/testing/verification-contract.md`.

## 6. Dependency hygiene inventory (Phase 25 §H)

Generated 2026-09-12 from `Cargo.lock` + manifests (method: `cargo tree`, `cargo deny`,
`cargo audit`, manifest grep). Re-verified 2026-09-13 (corrective pass: `bincode` confirmed
transitive-only; `rsa` confirmed no direct root edge). Classifications: justified (keep), migrate (stable line
exists), follow-up (owner + Re-audit date).

| Item | Detail | Classification |
|------|--------|----------------|
| `dashmap 7.0.0-rc2` (prerelease, direct root) | No stable 7.x line published; concurrent map for connection pools | justified — keep; reassess when stable 7.x ships (owner: platform) |
| `notify 9.0.0-rc.3` (prerelease, direct root + plugin-runtime) | No stable 9.x line published; config hot-reload watcher | justified — keep; reassess when stable 9.x ships (owner: config) |
| `openraft 0.10.0-alpha.18` (prerelease, optional root + mesh) | 0.x line is inherently pre-1.0; mesh Raft control plane | justified — keep; track upstream stable (owner: mesh; Re-audit: 2026-10-01) |
| Duplicated `ahash` 0.7.8 / 0.8.12 | 0.7 via `parcel_sourcemap` (lightningcss chain); 0.8 direct | justified — minor build cost only, no security impact; collapses if lightningcss drops `parcel_sourcemap` |
| Duplicated `wasmtime` 40.0.4 / 36.0.15 | 40 via yara-x (single `synvoid-yara` owner); 36.0.15 direct LTS runtime (crates.io, no patch) | follow-up — collapses when yara-x moves off wasmtime 40.x; direct line needs no 0269 ignore (Re-audit: 2026-10-01) |
| Duplicated `rkyv` 0.7.46 / 0.8.x | 0.7 via `parcel_sourcemap`; direct code on 0.8 | follow-up — collapses with the same lightningcss change; 0.7 covered by RUSTSEC-2026-0235 ignore with review date |
| Native/FFI (`aws-lc-rs`, `ring` transitive, `libloading`, `bumpalo`-linked compiles) | TLS PQC backend, DNS/QUIC crypto, native-extension loading (compiled out by default + disabled by default + allowlisted) | justified — each has an owning security invariant (see `AGENTS.md`); `libloading` plugin-loader isolation complete in Phase 28 (`synvoid-native-extension` + `unsafe-native-extensions` feature, off by default) |
| Git sources | none (Phase 37 removed the wasmtime 42.0.2 patch) | justified — `deny.toml` sets `unknown-git = "deny"` with no `allow-git`; re-adding one requires baseline evidence |
| Build dependencies executing code at build time | `tonic-prost-build` (protobuf codegen, mesh admin/control APIs), `chrono` (codegen timestamps) | justified — pinned via lockfile; codegen inputs are checked-in protos |

No `cargo machete` run is recorded as authoritative: feature-gated and generated-code
cases in this workspace require project-specific interpretation (see Part E), so the
in-repo entitlement guard (`root_dependency_ownership.md` + `module_ownership.rs`)
is authoritative and machete remains optional supporting evidence.

## 7. Phase 36 addendum (2026-09-17): YARA deserialization exposure closure

Closeout evidence for `plans/phase_36_yara_x_deserialization_exposure_closure.md`
(trust-model Parts A–C complete; engine upgrade Part D blocked, documented below).

- Final `synvoid-yara` resolution: **yara-x 1.15.0** (unchanged), transitive
  **wasmtime 40.0.4** (unchanged). Direct runtime at this point in Phase 36
  was still **wasmtime 42.0.2** via `[patch.crates-io]` (removed later by
  Phase 37; see §8). Feature graph unchanged
  (`default-modules` + `linkme` on the 1.15 line; no `pulley`, no module
  removals). No parser/strictness delta: same engine line, source-only reload
  path re-validated (`cargo test -p synvoid-yara`, `-p synvoid-upload
  --all-features`, `-p synvoid-jail-runtime --all-features`, mesh
  `yara_approval_boundary`).
- Removed ignores: **none** (no ignore ever covered GHSA-2jx3-ff3v-j7jj — it
  has no RUSTSEC ID in the advisory DB, so `cargo audit`/`cargo deny` do not
  fire on it; the 16 existing ignores are unrelated and retained with their
  2026-10-01 Re-audit dates). Deliberately no new ignore was added: the 1.15
  line is NOT patched and must never be described as such.
- Trust closure (the remotely-exploitable path is gone even on 1.15):
  `YaraScanner::reload_with_compiled_rules`,
  `CompiledArtifact::{deserialize_verified, from_bytes_with_binding}`, mesh
  `local_compiled_rules` / `apply_compiled_rules` /
  `get_current_compiled_rules`, and `YaraRuleSourceType::CompiledBundle`
  removed. Upload (`reload_yara_rules_if_needed`), mesh receive paths, and the
  jail service recompile approved source text locally; a version bump with no
  acceptable source retains the previous generation. `COMPILED_FORMAT_VERSION`
  stays 1 (envelope layout unchanged; engine-only incompatibility will be
  covered by the `YARA_ENGINE_VERSION` bump when the upgrade lands).
- Upgrade block (concrete, reproduced): yara-x >=1.19 needs wasmtime >=43
  (1.19.0 → `wasmtime ^43.0.2`; 1.20.0 → `wasmtime ^45.0.3`), and wasmtime
  >=43 needs `bumpalo ^3.20.0`, while `minify-html` 0.18.1 (latest) →
  `oxc_allocator` 0.95.0 (only 0.95.x) pins `bumpalo =3.19.0` exactly. Cargo
  cannot split same-major selections (reproduced 2026-09-17 in an isolated
  scratch crate depending only on `oxc_allocator =0.95.0` + `wasmtime =45.0.3`,
  and again with two local crates pinning `bumpalo =3.19.0` vs `^3.20.0`).
   `YARA_ENGINE_VERSION` therefore stays `yara-x/1.15`; bump it (and pin a
   1.15-artifact rejection test, replacing the current foreign-line probe) when
   the upstream pin relaxes. Re-audit with the 2026-10-01 dependency review.

## 8. Phase 37 addendum (2026-09-17): direct runtime on Wasmtime 36 LTS

Closeout evidence: `plans/phase_37_closeout_results.md` (plan:
`plans/phase_37_wasmtime_lts_runtime_migration.md`).

- Landed direct version: **36.0.15** (36 LTS through 2027-08-20), crates.io, no
  patch, no git source. Requested features unchanged: `component-model` on top
  of defaults (minimization evaluated, deferred to a follow-up with rationale
  in the closeout). Consumers unchanged in shape: `synvoid-plugin-runtime` +
  root dev-dep (`benches/bench_wasm.rs`).
- Resolver proof: isolated scratch crate (`wasmtime 36.0.15` + `bumpalo
  =3.19.0` + `oxc_allocator =0.95.0`) → single `bumpalo 3.19.0`,
  `wasmtime-wasi` absent. Workspace lock matches: 36.0.15 + 40.0.4, one
  bumpalo 3.19.0, no wasi, no git.
- API parity: zero runtime-code changes (all used APIs source-compatible in
  36); 359 plugin-runtime + 20 serverless + 4 jail-runtime tests pass;
  bench compiles. Bench deltas (same host): fresh instantiate 6.88→6.54 µs,
  pooled call 305→279 ns — no regression.
- Advisory proof: DB patched range includes >=36.0.14,<37.0.0; isolated
  no-ignore `cargo audit` on 36.0.15 is clean, so the direct 36.0.15 LTS line
  is patched and needs no 0269 ignore. The retained per-advisory ignore covers
  the transitive 40.0.4 instance only (Phase 38 normalizes the record).
- Process note: use targeted `cargo update -p <pkg> --precise <v>` for version
  moves, not full `cargo generate-lockfile` (the latter floated
  `yara-x-macros`/`-parser` to 1.20.0 against `yara-x` 1.15.0 and broke the
  jail build; restored + targeted update fixed it).

## 9. Phase 38 addendum (2026-09-17): runtime-security closeout

Closeout evidence: `plans/phase_38_closeout_results.md` (plan:
`plans/phase_38_runtime_dependency_security_closeout.md`).

The Phase 38 plan expected YARA-X 1.20.x with a transitive Wasmtime 45.x line.
That upgrade did NOT land: Phase 36 closed the deserialization exposure on
yara-x 1.15 (source-only trust) while the >=1.19 engine upgrade stays blocked
by the same-major `bumpalo` conflict (§4/§7). This addendum records the actual
landed graph, not the planned one.

- Landed graph: **yara-x 1.15.0**, transitive **wasmtime 40.0.4** (via
  `synvoid-yara` only), direct **wasmtime 36.0.15 LTS** (via
  `synvoid-plugin-runtime` + root bench dev-dep), single **bumpalo 3.19.0**,
  **no `wasmtime-wasi`/`wasi-filesystem`**, **no git source**, **cryptoki
  0.12.1** (bumped 0.12.0 → 0.12.1 for RUSTSEC-2026-0286; targeted
  `cargo update -p cryptoki --precise 0.12.1`, 2-line lock diff).
- Direct vs transitive, stated separately: the direct 36.0.15 LTS line is
  PATCHED for RUSTSEC-2026-0269 (>=36.0.14) and needs no ignore (proven by a
  clean isolated no-ignore `cargo audit`); the transitive 40.0.4 line IS
  affected and capability-gated (`wasmtime-wasi` absent, no preopen API
  reachable). The per-advisory 0269 ignore covers the transitive instance
  only. Never read it as direct coverage; never call 40.0.4 patched.
- YARA-X version and GHSA-2jx3-ff3v-j7jj disposition: engine stays 1.15
  (<=1.18 affected range; NOT patched; no ignore added — the advisory has no
  RUSTSEC ID so audit/deny do not fire). The remotely-exploitable path is
  closed by construction: `reload_with_compiled_rules`,
  `CompiledArtifact::{deserialize_verified, from_bytes_with_binding}`, mesh
  `local_compiled_rules`/`apply_compiled_rules`/`get_current_compiled_rules`,
  and `YaraRuleSourceType::CompiledBundle` are removed; upload/mesh/jail
  recompile approved source locally. `YARA_ENGINE_VERSION` stays `yara-x/1.15`
  with a guard pinning it to the manifest major.minor.
- `wasmtime-wasi` reachability: absent from `Cargo.lock` (no `wasmtime-wasi`,
  `wasi-filesystem`, `wasi-common` filesystem, or `cap-std` filesystem
  packages); neither consumer links a preopen API. The
  `wasmtime_wasi_stays_absent_without_exposure_update` guard fails closed on
  appearance. Direct features remain defaults + `component-model` (minimization
  deferred with rationale in §8).
- Remaining advisory exceptions: 16 ignores, verified exact 2026-09-17 by
  removing `.cargo/audit.toml` and confirming every one fires
  (0071 rsa; 0085–0096/0114/0222/0269 wasmtime 40.0.4; 0235 rkyv 0.7.46).
  No stale 40.x/42.x entries beyond the live 40.0.4 line; no direct-42
  exception remains. Re-audit: 2026-10-01; remove condition for the wasmtime
  group is yara-x moving off wasmtime 40.x.
- `minify-html`/Oxc `bumpalo` constraint: unchanged — `minify-html` 0.18.1 →
  `oxc_allocator` 0.95.0 pins `bumpalo =3.19.0`; wasmtime >=43 needs
  `bumpalo ^3.20.0`. Blocks both the yara-x >=1.19 upgrade and any >=46/48
  direct-line move until an upstream minify-html/oxc release relaxes the pin.
- Source policy: crates.io only. `deny.toml` sets `unknown-git = "deny"` with
  no `allow-git`; `Cargo.lock` contains no `git+` source. Re-adding any git
  source requires an allow entry plus baseline evidence. The
  `wasmtime_has_no_git_source` guard scopes the check to wasmtime lock blocks.
- Next re-audit triggers (event-based): yara-x moves to a supported Wasmtime
  line clearing the transitive 0269 advisory; Wasmtime 48 LTS becomes
  resolver-compatible (bumpalo blocker clears); SynVoid intentionally adds WASI
  filesystem capabilities; a new YARA serialized-artifact consumer appears;
  the 36 LTS line approaches end of support (2027-08-20); any new advisory
  affecting a resolved package (cf. cryptoki 0286, fixed here by upgrade, not
  ignore).

## 10. Phase 39 addendum (2026-09-18): minifier/Oxc blocker remediation

Closeout evidence: `plans/phase_39_closeout_results.md` (plan:
`plans/phase_39_minify_html_oxc_blocker_remediation.md`; roadmap:
`plans/runtime_dependency_blocker_followup_roadmap.md`).

Supersedes the §9 status line "`minify-html`/Oxc `bumpalo` constraint:
unchanged": the minifier side of the conflict is now removed. YARA engine,
Wasmtime versions, advisory ignores, and source policy below are otherwise
unchanged from §9.

- Landed graph: **yara-x 1.15.0**, transitive **wasmtime 40.0.4** (via
  `synvoid-yara` only), direct **wasmtime 36.0.15 LTS** (via
  `synvoid-plugin-runtime` + root bench dev-dep), **no `wasmtime-wasi` /
  `wasi-filesystem`**, **no git source**, 16 advisory ignores unchanged
  (Re-audit: 2026-10-01). `YARA_ENGINE_VERSION` stays `yara-x/1.15`;
  Phase 40 owns the engine upgrade.
- Compatibility fork (temporary): `third-party/minify-html-compat/` vendors
  the exact released `minify-html 0.18.1` crate `src/` byte-for-byte
  (verified by recursive diff against the registry source) with a
  manifest-only delta: the five Oxc dependencies `0.95 -> 0.111`
  (`oxc_allocator`, `oxc_codegen`, `oxc_minifier`, `oxc_parser`, `oxc_span`).
  No `src/` change was needed: the sole Oxc consumer (`src/minify/js.rs`:
  `Allocator::default`, `Parser::new(..).parse()`,
  `Minifier::new(..).minify`, `Codegen::new().with_options(..).build(..)`,
  `SourceType::mjs()/default()`, `CompressOptions::safest()`,
  `MangleOptions::default()`) compiles unchanged against Oxc 0.111 (proven
  in an isolated scratch crate before vendoring). Consumed via root
  `[patch.crates-io]` path override (single-source; `synvoid-static-files`
  is the only `minify-html` consumer). Upstream public API used by SynVoid
  (`Cfg`, `minify(&[u8], &Cfg)`) is preserved and pinned by
  `crates/synvoid-static-files/tests/minify_parity.rs::upstream_minify_api_shape_is_preserved`.
- Why 0.111: first researched Oxc line whose `oxc_allocator` carries no
  external `bumpalo` edge (proven from the crates.io dependency API:
  0.111.0 deps are `allocator-api2`, `hashbrown`, `oxc_data_structures`,
  `rustc-hash` + optionals; no `bumpalo`); upstream minify-html PR #270
  independently selected the same 0.111 target (closed unmerged);
  minimizes API distance (0.150+ adds risk with no resolver benefit);
  `rust-version = 1.91.0` is below SynVoid's pinned 1.98.1. Latest release
  and master remain `minify-html` 0.18.1 / Oxc 0.95 as of 2026-09-18, so no
  official release could satisfy the removal condition yet.
- Resolver proof (workspace, 2026-09-18):
  `cargo tree -i minify-html` resolves to the vendored path;
  `oxc_allocator` resolves to **0.111.0** (no 0.95 instance remains);
  `cargo tree -i bumpalo` shows **no** `oxc_allocator`/`minify-html` edge —
  the remaining `bumpalo 3.19.0` instance is consumed only by
  `cranelift-codegen` (wasmtime 36/40), classified by consumer, not assumed.
  `cargo tree -e features -i minify-html` confirms the fork's Oxc family.
- YARA-X 1.20 probe (disposable copy, main lockfile untouched): stock
  `cargo update -p yara-x --precise 1.20.0` on the pre-fork graph fails on
  the `linkme` feature removal first (`synvoid-yara` requests `linkme`;
  yara-x >=1.19 dropped that feature — Phase 40 manifest work), masking the
  bumpalo diagnostic; the isolated scratch-crate reproduction
  (`oxc_allocator =0.95.0` + `wasmtime =45.0.3` → `bumpalo =3.19.0` vs
  `^3.20.0` unresolvable; with `oxc_allocator =0.111.0` → single
  `bumpalo 3.20.3`) is the clean bumpalo evidence. Post-fork, with `linkme`
  dropped in the disposable copy only, resolution gets past the old bumpalo
  conflict (next failure is the unrelated `wasm-bindgen` float owned by the
  admin-ui chain); after a full `cargo update` in that copy, yara-x 1.20.0
  resolves with wasmtime 36.0.15 + 45.0.3, single `bumpalo 3.20.3`, and
  `oxc_allocator` 0.111.0. Phase 40 therefore needs: `linkme` removal,
  lock float (including the wasm-bindgen chain), and engine re-validation —
  not another minifier change.
- Behavior proof: `crates/synvoid-static-files/tests/minify_parity.rs`
  (16 tests: whitespace/comments, `<pre>`/`<textarea>`, attributes/entities,
  classic + module JS, modern JS features, inline CSS + style attrs,
  JSON/LD+JSON/template data scripts, malformed/empty/fragment/UTF-8,
  never-grows invariant) passes byte-identically before and after the fork
  (all exact goldens unchanged; zero output differences to classify).
  Throughput probe (same host, 2000 iters mixed HTML/JS/CSS page, release):
  registry 0.18.1 ≈20,300 iters/s vs fork ≈23,300 iters/s (no regression;
  total output bytes identical). Dep-shape delta is one added `oxc_str`
  0.111.0 crate and the removed `oxc_allocator -> bumpalo` edge; no
  material build/binary footprint change.
- Source policy: still crates.io + workspace paths only. `deny.toml` keeps
  `unknown-git = "deny"` with **zero** `allow-git` entries; `Cargo.lock`
  contains no `git+` source. The temporary fork adds no source exception —
  it avoids one by design (path patch, not git). Temporariness is enforced
  by `minify_fork_is_temporary_guard` (`dependency_security.rs`): exactly
  one `[patch.crates-io]`, only `minify-html`, path-only, with
  owner + `Re-audit: 2026-10-01` + removal condition in both manifests.
- Removal condition: delete the root `[patch.crates-io]` section and
  `third-party/minify-html-compat/` as soon as an official minify-html
  release eliminates the Oxc 0.95 / external bumpalo 3.19 path and passes
  the parity corpus. Re-audit with the 2026-10-01 dependency review.
