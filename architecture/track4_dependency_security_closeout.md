# Track 4 Dependency-Security Closeout (Phase 31)

Status: complete. Roadmap: `plans/track4_dependency_security_capability_segregation_roadmap.md`
(Phase 31, final Track 4 closeout). Base: `6351b39d` (Phase 30); Phase 31
changes committed on top (see git log; CI logs record the final SHA).

This file is the current architecture closeout evidence required by Phase 31
Part I. Historical Track 1-3 plans/results are archival and unchanged.

## 1. Before/after high-risk dependency table

Measured 2026-09-12 via `cargo tree --workspace`, `cargo tree -i <crate>`,
`cargo tree -d`, `cargo metadata`. "Before" is the Track 4 baseline
(`f8a2690f`, pre-Phase 25); "after" is the Phase 31 tree.

| Capability | Before (pre-Track 4) | After (Phase 31) | Isolation gained |
|------------|----------------------|------------------|------------------|
| Wasmtime 42.0.2 direct runtime | Direct via `[patch.crates-io]` git, consumed broadly (plugin-runtime + root dev) | `cargo tree -i wasmtime@42.0.2`: exactly `synvoid-plugin-runtime` (+ root dev bench only) | No change in version (upgrade blocked, §6), but consumers pinned: no mesh/DNS/admin/control-plane linkage |
| Wasmtime 40.0.4 transitive (yara-x) | Via `yara-x` in `synvoid-upload` + `synvoid-mesh` (control plane linked compiler) | `cargo tree -i wasmtime@40.0.4`: `yara-x` → `synvoid-yara` → `synvoid-upload`, `synvoid-jail-runtime`, root (Phase 26: `synvoid-mesh` no longer links `yara-x`) | Mesh control plane out of scope; single `yara-x` owner (`synvoid-yara`, guard `yara_execution_boundary`) |
| `wasmtime-wasi` filesystem sandbox | Assessed as absent (baseline §1-§2) | `cargo tree -i wasmtime-wasi`: no match; absent from `Cargo.lock` (guard `wasmtime_baseline_guard`) | Capability absence re-verified; RUSTSEC-2026-0269 remains capability-gated, not patched |
| `libloading` native execution | Always in `synvoid-plugin-runtime` (sandboxed + unsafe in one crate) | `cargo tree -i libloading`: only `synvoid-native-extension` (normal build) + Windows `wintun` target edge; default `synvoid-plugin-runtime` graph links no loader (Phase 28, `unsafe-native-extensions` off by default) | Capability isolation: in-process native loading behind explicit feature + runtime gates |
| `cryptoki` PKCS#11/HSM | Root-adjacent? No root edge, but DNS key/HSM logic inside `synvoid-dns` | `cargo tree -i cryptoki`: empty on default features; present only under `synvoid-dnssec-keystore/pkcs11` via root `dns-hsm` (Phase 30, opt-in, fail-closed) | Key-custody boundary: `SealedSigningKey::sign()` + `KeyMetadata`, no private bytes out |
| Mesh protocol/identity types | Inside `synvoid-mesh` (DHT/Raft/SQLite/YARA pulled into verifiers) | `synvoid-mesh-protocol` leaf (serde/ed25519/base64 only); `synvoid-mesh` depends downward, re-exports compat; `synvoid-waf` feed client uses protocol only (Phase 27) | Verification-only consumers avoid control-plane graph (budget guard `mesh_protocol_boundary`) |
| DNSSEC private keys | Inside `synvoid-dns` (signing + transport mixed) | `synvoid-dnssec-keystore` leaf (+ optional `cryptoki`); `synvoid-dns` → keystore one-way (Phase 30, guard `dnssec_keystore_boundary`) | Custody boundary: opaque handles, 0600/atomic, HSM fail-closed, mesh anchors public-only |
| Child jail execution | Root `src/sandbox/` implementation + `--wasm-jail`/`--yara-jail` in main binary | `synvoid-jail-runtime` crate + `synvoid-wasm-jail`/`synvoid-yara-jail` binaries, exe-dir resolution, versioned IPC (Phase 29; `verify-release` fails if omitted) | Process-boundary packaging; release must ship 3 binaries atomically |
| Root direct surface | ~120 direct deps incl. 30+ with 0 src uses (ledger `migration_blocker`) | Phase 31 removed 38 unused direct edges + moved 3 test-only to `[dev-dependencies]`; `prost`/`tonic-prost` retained as codegen runtimes with exceptions | Manifest matches source entitlement (guard `root_dependency_entitlement_guard`); no high-risk capability hidden transitively into same processes (see §3) |

Root direct counts (depth-1 `cargo tree -p synvoid`): default 121 lines,
`--no-default-features` 115 lines post-cleanup (down from ~150+ pre-cleanup
including removed edges; exact pre-count varies with feature unification).

## 2. Advisory status (fresh DB 2026-09-12)

`cargo deny check`: advisories ok, bans ok, licenses ok, sources ok.
`cargo audit`: 0 errors; 9 allowed warnings (transitive unmaintained/unsound
via admin-ui yew chain: bincode, im-rc, proc-macro-error, sized-chunks, etc.;
`unmaintained`/`unsound = "workspace"` per Phase 25, so transitive notices
stay warnings, not hard errors).

16 `deny.toml` ignores retained (mirrored in `.cargo/audit.toml`), each with
dependency path, capability, wasmtime-wasi status, exposure, owner, and
review/remove-by date:

- RUSTSEC-2023-0071 (rsa Marvin; yara-x path never invoked, ed25519 used instead)
- RUSTSEC-2026-0085/0086/0087/0088/0089/0091/0092/0093/0094/0095/0096/0114
  (wasmtime 40.0.4 via yara-x; direct 42.0.2 fixed for these; mesh out of scope)
- RUSTSEC-2026-0222 (wasmtime 40.0.4 type confusion; single-engine YARA only)
- RUSTSEC-2026-0269 (WASI fs escape; BOTH 40.0.4 and 42.0.2 affected, 42.0.2
  NOT patched; capability absence: wasmtime-wasi absent from lock/graph)
- RUSTSEC-2026-0235 (rkyv 0.7.46 via parcel_sourcemap; minifier sourcemaps only)

No Track 4 temporary exception removed without a fix; all carry upstream
blockers (bumpalo conflict for ≥46.0.3, yara-x still on wasmtime 40.x) and
Re-audit date 2026-10-01 with explicit remove conditions (see `deny.toml`).
Source policy: exactly one git source
(wasmtime 42.0.2 patch, `allow-git` only it), no unknown registries, lockfile
checked in.

## 3. Process/package capability map

| Process / package | High-risk capabilities linked | Authority |
|-------------------|-------------------------------|-----------|
| `synvoid` supervisor + `UnifiedServerWorker` (default) | wasmtime 42 (via plugin-runtime), wasmtime 40 (via yara/upload/jail), yara-x (via yara), no libloading (default), no cryptoki (default) | Composition roots; worker admission reads BlockStore, not TIM |
| `synvoid` minimal (`--no-default-features`) | wasmtime 42 (plugin-runtime still linked? Yes via app-handlers/http chain), wasmtime 40 (yara still linked via upload), no mesh, no DNS, no cryptoki, no libloading | Hardened profile (README); absence branches tested |
| `synvoid-plugin-runtime` (default) | wasmtime 42 only; no libloading, no wasmtime-wasi | Sandbox boundary |
| `synvoid-native-extension` (opt-in) | libloading only; no wasmtime, no mesh, no upload | Capability isolation; off by default |
| `synvoid-yara` | yara-x + wasmtime 40 only; no mesh, no HTTP | Single execution owner |
| `synvoid-jail-runtime` (`synvoid-wasm-jail`, `synvoid-yara-jail` binaries) | wasmtime 42 (wasm) / yara-x (yara) inside child only; hook-only caps, digest re-verify | Process boundary; parent stdio pipes only |
| `synvoid-mesh` | openraft, DHT/Raft/SQLite; NO yara-x, NO wasmtime 40 (Phase 26) | Control plane; depends on `synvoid-mesh-protocol` downward |
| `synvoid-mesh-protocol` | serde/ed25519/base64 only; no DHT/Raft/SQLite/YARA/HTTP | Verification leaf |
| `synvoid-dns` (default) | hickory, rusqlite, quinn; NO cryptoki; verification-only rsa/ed25519/sha1/sha2 | Protocol/transport; signs via keystore handles |
| `synvoid-dnssec-keystore` (default) | ed25519/rsa/sha1/sha2/zeroize; NO cryptoki, NO hickory/hyper/quinn/sqlite/mesh | Custody leaf; `pkcs11` feature adds cryptoki only here |
| Request path (`src/waf/`, `src/proxy/`, `src/http/`, `synvoid-waf`, `synvoid-proxy`) | Narrow traits only; `synvoid-mesh-protocol` for verification (Ed25519/threat types), never full `synvoid-mesh`; no `is_mesh_id_blocked` | Composition boundary guards |

Rejection check: fewer root direct deps does NOT hide capability in the same
processes — the table shows each high-risk family confined to its owning
package/process with feature gates (native opt-in, HSM opt-in, mesh/DNS
feature-gated).

## 4. Final crate additions/removals

Added in Track 4 (all pass granularity retain bar, see `crate_granularity_audit.md`):

- `synvoid-mesh-protocol` (Phase 27)
- `synvoid-native-extension` (Phase 28)
- `synvoid-jail-runtime` (Phase 29)
- `synvoid-dnssec-keystore` (Phase 30)

Removed: none (Phase 31 removed 0 crates; stale empty `synvoid-testkit/` dir
already removed Phase 24). `synvoid-yara` added Phase 26 (canonical YARA owner;
counted in 42-crate total).

No merges executed. Two future simplification candidates recorded
(`synvoid-filter`, egress layering) with stability reviews required.

## 5. Rejected/deferred extraction decisions (Phase 31 re-verdict: no change)

- `synvoid-admin-server`: rejected. Admin is Axum transport composition with
  broad fan-in; reusable logic already in `synvoid-admin`. Extraction would
  relocate files with same fan-in, no dependency isolation.
- `synvoid-waf-runtime`: rejected. WafCore move blocked by GeoIP/tarpit/theme/
  upload/traffic/sqlite/worker pulls (ledger). Engine already in `synvoid-waf`.
- Egress (`http-client`/`upstream`/`tunnel`): no change. Clean layering
  (pool → balancing → transports); collapse needs scoped plan.
- `synvoid-filter` merge: deferred. Thin but stable narrow-trait boundary;
  count-only merging rejected.
- `app-server` ↔ `app-handlers`: no change. Separate for dependency isolation.
- `synvoid-sdk` umbrella: explicitly deferred. All crates internal pre-1.0
  (no external API promises); remaining root deps are composition_runtime with
  real src uses; moving re-exports would rename, not reduce, the facade surface.

## 6. Verification results

Tools (pinned): rustc 1.98.1, nextest 0.9.140, cargo-deny 0.20.2,
cargo-audit 0.22.2. See `docs/testing/verification-contract.md` §15.

| Check | Result (2026-09-12) |
|-------|---------------------|
| `cargo fmt --all -- --check` | PASS (run in verify) |
| `cargo clippy --profile ci --all-targets -- -D warnings` | PASS (verify preflight) |
| `cargo deny check` | PASS (advisories/bans/licenses/sources ok) |
| `cargo audit` | PASS (0 errors, 9 allowed transitive warnings) |
| `cargo check --no-default-features --profile ci` | PASS |
| `cargo check --no-default-features --features mesh/dns/mesh,dns/icmp-filter --profile ci` | PASS (all 4) |
| `cargo nextest run -p synvoid-repo-guards` | PASS (67/67) |
| `cargo xtask verify` (routine, 10 invocations) | PASS locally 2026-09-12 (418s, 10/10 steps; see CI for remote confirmation) |
| `cargo nextest run --workspace --exclude synvoid-fuzz` | PASS (7117 passed, 0 failed) |
| `cargo test --workspace --doc` | PASS (0 failures) |
| `cargo test --no-default-features --lib --test integration_test --test admin_router_composition` (minimal-tests) | PASS |
| `cargo clippy --all-targets --all-features -- -D warnings` | PASS |
| `cargo xtask verify-release` (clean tree, phases 1-3 incl. jail artifacts, metadata, packaging) | PASS (clean-tree run post-commit before push; `verify-release --dry-run` validated flow pre-commit) |
| `cargo tree -i wasmtime-wasi` / `cryptoki` (default) | Empty (absent) |
| Mesh partition `distributed_state_partition` | PASS (14/14) |
| Jail `synvoid-jail-runtime` + keystore `synvoid-dnssec-keystore` | PASS |
| Plugin `plugin_failure_does_not_poison_manager` | PASS (6/6) |
| DNS conformance `./scripts/dns/conformance.sh` | 7/7 internal suites PASS (external section operator-deferred; macOS bash lacks assoc arrays, Linux CI unaffected) |
| Fuzz smoke (nightly, changed parsers) | Bounded 1000-run smokes re-run on the corrective tree; see `architecture/track4_post_closure_corrective_report.md` for commands/results (Phase 31 tree was manifest/docs-only, so no parser change required a re-run at that time; corrective pass records final evidence) |

Exact commands, SHAs, and per-step timings are in CI logs (`ci` + 
`dependency-security` jobs) and the release-qualification summary
(`PRE-PUBLICATION READY WITH DEFERRED REGISTRY CHECKS` with deferred list).

## 7. Remaining explicit risks/upstream blockers

1. Wasmtime ≥46.0.3 upgrade blocked by bumpalo conflict (minify-html 0.18.1 →
   oxc_allocator 0.95.0 pins bumpalo =3.19.0; wasmtime 46 needs ^3.20.2).
   Re-attempt when upstream relaxes pin or yara-x moves off wasmtime 40.
   Tracking: baseline §4, deny 0269 Re-audit 2026-10-01 (remove condition: ≥46.0.3 upgrade unblocks).
2. yara-x 1.15 still on wasmtime 40.0.4 (12 advisories ignored with exposure
   evidence). Remove condition: yara-x upstream move off 40.x. Re-audit: 2026-10-01.
3. rkyv 0.7.46 via parcel_sourcemap (lightningcss) + macOS BUG-002 linker
   segfault (Apple clang 21, non-deterministic, Linux CI unaffected). Collapses
   if lightningcss drops parcel_sourcemap.
4. Prerelease lines with no stable alternative: dashmap 7.0.0-rc2, notify
   9.0.0-rc.3, openraft 0.10.0-alpha.18. Reassess when stable ships.
5. `synvoid-integrity` remains a non-optional root dep with 0 src uses solely
   for `origin_key_exchange` feature wiring. Future: make optional with
   `dep:` gating after semver review.
6. `prost`/`tonic-prost` retained as codegen runtimes with guard exceptions
   (OUT_DIR references, not src/). No action unless codegen backend changes.
