# Runtime Truthfulness, Security, and Publication Campaign Closeout (Phases 41–48)

Status: Phase 41–47 implemented and closed; Phase 48 corrective closeout records the final evidence. This is the canonical post-campaign evidence document. The umbrella handoff roadmap (`plans/runtime_truthfulness_security_publication_roadmap.md`) is a completed historical record; future work must open a new focused plan.

Baseline: `main` at `91732e22886451bf5c5547ea125d2a38bd58cefd` (2026-09-19, Phase 47 head).
Final commit: the `phase48:` closeout head on `main` carrying this report (resolve via `git log --oneline --grep=phase48`; implementation range above is the evidence baseline).

## 1. Phase 41–47 result table

| Phase | Commit | Landed result |
|---|---|---|
| 41 | `a3e5ab27f8ce` | fail-closed capability config preflight, process/supervisor validation, checked derived capacities |
| 42 | `0026e934e49b` | checked mmap layouts, versioned headers, file hardening, narrowed shared-state API |
| 43 | `7b2aff0be715` | bounded bcrypt executor, async auth boundaries, durable/fail-closed auth persistence |
| 44 | `220dd5dea91d` | migration from `pqc_kyber_edit` to maintained final FIPS 203 `ml-kem` |
| 45 | `69a47c68b1b1` | fail-closed DNS config truthfulness, DoQ bind fidelity, bounded persistent authoritative TCP/DoT |
| 46 | `f31e2cb07050` + `471b3b4d596c` | platform sandbox truthfulness, macOS SBPL hardening/native tests, Linux clippy correction |
| 47 | `91732e228864` | public-crate release policy; exactly `synvoid-rate-limit` 0.1.0 promoted to class 3 |

## 2. Acceptance-criterion audit summary (Workstream A, re-checked at closeout head)

All criteria below were re-checked against landed code, tests, guards, and binding docs. No runtime changes were needed: no concrete mismatch between a Phase 41–47 acceptance criterion and the landed implementation was found.

- **Phase 41** — satisfied. Reduced-feature builds reject `[dns]`, `[mesh]`, `[tunnel.mesh]`, `[icmp_filter]` (even inert `enabled = false`) via the raw-TOML preflight on the canonical `MainConfig::from_toml_str()` path (`crates/synvoid-config/src/main_config.rs`); process/supervisor validation reachable from `MainConfig::validate()`; worker/count/timeout/address bounds enforced; derived capacities use checked arithmetic; mesh restart activation/tuning fails before runtime construction. Binding: `architecture/config_feature_contract.md`. Guard: `tests/config_capability_preflight_guard.rs`.
- **Phase 42** — satisfied. All size/offset arithmetic flows through checked layout types; release builds enforce range/alignment preconditions before unsafe references; mappings carry magic+version headers with explicit creator/open-existing ownership; file paths reject symlink/non-regular misuse with `0600`/`0700` permissions; raw mutable mmap escape hatches absent (typed counter slices via `SlottedIpRateLimiter::from_shared_table`); cross-process atomic scope documented rather than implied portable. Binding: `architecture/shared_memory_atomic_contract.md`.
- **Phase 43** — satisfied. Bcrypt never runs on Tokio core threads (`synvoid-auth::PasswordCrypto` bounded semaphore + `spawn_blocking`, overload `Busy` fails closed); no auth-store lock held across bcrypt (snapshot → release → verify → reacquire + generation recheck); Basic Auth is async-only with `BackendBusy` → 503 distinct from 401 as a typed library contract (`BasicAuthResult::BackendBusy`; `BasicAuthManager` currently has no HTTP consumer outside `synvoid-auth`, so the 503 mapping is contract + test, not wired HTTP code — intentional, not a residual); auth-store replacement is temp-write + fsync + rename; corrupt/over-permissive stores fail closed via `AuthManager::try_new`; login audit bounded at insertion (`MAX_LOGIN_LOGS = 1000`). Binding: `architecture/auth.md` + `architecture/auth_deep_dive.md`.
- **Phase 44** — satisfied. `pqc_kyber` / `pqc_kyber_edit` absent from the active graph (`ml-kem` 0.3 present); final ML-KEM compatibility explicit (equal wire sizes are NOT byte-compatibility, proven by cross-impl mismatch); NIST FIPS 203 KAT, round-trip, tampered-ciphertext implicit-rejection, boundary/size, and aws-lc-rs interop evidence in `crates/synvoid-wasm-pow/src/pqc.rs` (+ `pqc/` server side); no rename-as-remediation language; guard `pqc_backend_is_maintained_ml_kem`. Binding: `architecture/pqc.md` + `architecture/wasm_pow.md` + `SECURITY.md`.
- **Phase 45** — satisfied. Deferred DNS activation rejected with typed `Unsupported { path }` errors; admin `PUT /config/dns` enforces the same validation (400); `dns.doq.bind_address` honored (IPv6-safe); authoritative TCP and DoT serve bounded persistent sequential connections (RFC 7766 reuse, no pipelining; 1000-query bound, permit held, graceful drain); TCP lifecycle has direct tests (`server/query.rs`); DoT reuses the identical bounded loop/constant with creation/defaults tests (`tests/encrypted_transport.rs`) but no DoT-specific reuse/bound/drain integration test — accepted test-granularity residual (see §4); docs/examples do not advertise deferred capabilities as active. Binding: `architecture/dns.md` + `architecture/dns_config_runtime_matrix.md`.
- **Phase 46** — satisfied. SBPL path literals escaped/canonicalized (`escape_sbpl_string_literal`); Basic is allow-default, Strict is deny-default with truthful capability reporting (level-dependent; `process_limits` numeric-only); `sandbox_init` error buffer freed via `sandbox_free_error`; native macOS child-process tests gate experimental Seatbelt support; Seatbelt clearly distinguished from App Sandbox; Linux Landlock is the production strict-isolation target. Binding: `docs/SANDBOXING.md` + `architecture/platform.md`.
- **Phase 47** — satisfied. Exactly `synvoid-rate-limit` 0.1.0 is class 3 (MSRV 1.81 with packaged-tarball evidence, consumer docs, changelog, property tests, dry-runs); no other crate carries `rust-version`/support language; `synvoid-utils`/`synvoid-core` remain internal; publication stays manual; `synvoid-http-client` remains internal — with the correction that the Phase 47 0.1.4-era eggfetch comparison is dated evidence (see §4). Binding: `architecture/public_crate_release_policy.md` + `architecture/public_crate_release_readiness_phase47.md`. Guard: `public_crate_release_policy`.

## 3. Verification commands and results (closeout head)

Local, 2026-09-19, rustc/cargo 1.98.1. Documentation/status-only changes (no runtime code touched); focused crate suites re-run at the closeout head plus the full repository gates:

- `cargo fmt --all -- --check`: pass.
- `cargo xtask test guards` (repo-guards incl. new `runtime_truthfulness_closeout` + root guards + core admin): 3/3 steps pass.
- Focused: `cargo test -p synvoid-config -p synvoid-upstream -p synvoid-auth -p synvoid-wasm-pow --profile ci`: pass; `cargo test -p synvoid-dns --profile ci` (589 lib + integration suites): pass; `cargo test -p synvoid-platform -p synvoid-rate-limit --profile ci`: pass; `cargo test -p synvoid-rate-limit --doc --profile ci` (1 doctest): pass.
- `cargo xtask verify`: 10/10 steps pass (fmt, clippy, deny, core compile, repo-guards, security regression single-threaded, root guards with `--features mesh`, core admin, admin contract with `mesh,dns,icmp-filter`, failure injection).
- `cargo xtask verify-full`: 10/10 steps pass (feature-profile compiles incl. `icmp-filter` and `mesh,dns`, minimal no-default tests, full-workspace nextest run excl. `synvoid-fuzz`, doctests).
- `cargo deny check`: exit 0 (advisories/bans/licenses/sources ok).
- `cargo audit`: exit 0 (6 allowed warnings: `atomic-polyfill`, `bincode` x2, `fxhash`, `proc-macro-error`, `proc-macro-error2` — all pre-existing allowlisted unmaintained warnings, unrelated to this phase).

## 4. Deliberate residuals / follow-ups (not campaign failures)

- **Truthfully unsupported capabilities (closed defects, not implementations):** deferred DNS features listed in §2 remain rejected at validation; recursive TCP remains single-query by design.
- **Test-granularity residual:** DoT persistent-connection reuse/bound/drain has no DoT-specific integration test (TCP lifecycle is directly tested; DoT shares the loop, constant, and limits). A future DNS-focused plan may add one; it is not a Phase 48 implementation task.
- **Accepted dependency/supply-chain residuals:** temporary `third-party/yara-x-compat` and `third-party/minify-html-compat` forks retained under guard-enforced removal conditions (official upstream releases); RUSTSEC-2023-0071 (`rsa` via yara-x `crypto`, no upstream fix) and RUSTSEC-2026-0235 (`rkyv` 0.7 via minify chain) remain ignored with dated metadata and re-audit 2026-10-01. Never describe them as patched.
- **New follow-up opened after the campaign:** current-line eggfetch parity/consolidation review — `plans/eggfetch_current_line_parity_review.md`. The Phase 47 decision was made against the then-current 0.1.4-era baseline; a newer eggfetch line now exists; `synvoid-http-client` stays internal until the full matrix is re-run with parity tests; the old matrix must not be cited as current evidence.

## 5. Public support boundary after Phase 47

Only `synvoid-rate-limit` 0.1.0 is externally supported (class 3, MSRV 1.81). Every other `synvoid-*` crate is class 1 (application-internal) or class 2 (workspace-reusable, no support promise). Publication is manual (`cargo publish` only); `cargo xtask verify-release` never publishes. Pinned by the `public_crate_release_policy` guard and recorded in `docs/releasing.md` §1a and the root README Reusable libraries section.

## 6. Security / supply-chain residuals intentionally left open

Per above: the two advisory ignores (0071, 0235) with expiry against current UTC date, the two temporary compat forks with removal conditions, and the 2026-10-01 dependency re-audit from `architecture/dependency_security_baseline_phase25.md`. Passing `cargo audit` is hygiene on the current graph, not proof that cryptographic provenance concerns are solved.

## 7. References (binding docs)

- `architecture/config_feature_contract.md` (Phase 41)
- `architecture/shared_memory_atomic_contract.md` (Phase 42)
- `architecture/auth.md` + `architecture/auth_deep_dive.md` (Phase 43)
- `architecture/pqc.md` + `architecture/wasm_pow.md` + `SECURITY.md` (Phase 44)
- `architecture/dns.md` + `architecture/dns_config_runtime_matrix.md` (Phase 45)
- `docs/SANDBOXING.md` + `architecture/platform.md` (Phase 46)
- `architecture/public_crate_release_policy.md` + `architecture/public_crate_release_readiness_phase47.md` (Phase 47)
- `architecture/agent_knowledge_maintenance.md` (audit record), `architecture/overview.md` (index)
