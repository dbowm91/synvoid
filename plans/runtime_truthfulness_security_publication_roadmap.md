# Runtime Truthfulness, Security Hardening, and Publication Readiness Roadmap

Status: complete — historical campaign record. Implementation closed through Phase 47; Phase 48 corrective closeout reconciles status/evidence. Do not extend this campaign; open a new focused plan for follow-up work.

Baseline reviewed: `main` at `03cec2235fb250e64c33f29b66258eeb0607cdbc` (2026-09-18).
Final implementation range: Phase 41 (`a3e5ab27f8ce`) through Phase 47 (`91732e228864`); closeout: Phase 48 (see `architecture/runtime_truthfulness_security_publication_closeout.md`).

## Campaign outcome (Phase 41–47)

| Phase | Commit | Result |
|---|---|---|
| 41 | `a3e5ab27f8ce` | fail-closed capability config preflight, process/supervisor validation, checked derived capacities |
| 42 | `0026e934e49b` | checked mmap layouts, versioned headers, file hardening, narrowed shared-state API |
| 43 | `7b2aff0be715` | bounded bcrypt executor, async auth boundaries, durable/fail-closed auth persistence |
| 44 | `220dd5dea91d` | migration from `pqc_kyber_edit` to maintained final FIPS 203 `ml-kem` |
| 45 | `69a47c68b1b1` | fail-closed DNS config truthfulness, DoQ bind fidelity, bounded persistent authoritative TCP/DoT |
| 46 | `f31e2cb07050` + `471b3b4d596c` | platform sandbox truthfulness, macOS SBPL hardening/native tests, Linux clippy correction |
| 47 | `91732e228864` | public-crate release policy; exactly `synvoid-rate-limit` 0.1.0 promoted to class 3 |

Closeout evidence: `architecture/runtime_truthfulness_security_publication_closeout.md` (binding post-campaign record).

## Intentional residuals (not campaign failures)

- Deferred DNS capabilities stay truthfully rejected (not implemented): RPZ, prefetch, custom trust anchors, anycast, zone transfers, dynamic UPDATE, NOTIFY, EDNS padding, QNAME privacy, firewall default/max-rules/rebinding, recursive scope responses.
- Recursive TCP stays single-query; authoritative TCP/DoT are persistent sequential (1000-query bound, permit held, graceful drain).
- macOS Seatbelt stays experimental/deprecated (`sandbox_init`, not App Sandbox); Linux Landlock is the production strict-isolation target.
- Only `synvoid-rate-limit` is class 3; all other candidates stay class 1/2 with recorded reasons.
- YARA/minify compat forks retained under their own removal conditions; RUSTSEC-2023-0071 (`rsa`) and RUSTSEC-2026-0235 (`rkyv` 0.7) remain accepted low-exposure residuals with dated re-audit.
- `synvoid-http-client` stays internal pending a fresh current-line eggfetch parity review (the Phase 47 0.1.4-era matrix is dated evidence, not a current comparison). See `plans/eggfetch_current_line_parity_review.md`.

Future work must open a new plan with its own baseline and acceptance criteria rather than silently extending this campaign.

## Original findings (historical rationale — preserved below)

Primary goal: close the concrete runtime/security residuals found after the Phase 32-40 architecture and dependency-security work, then promote only genuinely reusable crates toward external support. This is not another crate-count reduction campaign. The current ownership graph is broadly sound; this roadmap focuses on configuration truthfulness, unsafe-boundary hardening, authentication durability/CPU isolation, cryptographic dependency provenance, DNS configured-vs-runtime closure, macOS sandbox truthfulness, and a controlled public-library support policy.

## Findings that require implementation work

1. `MainConfig` conditionally compiles feature-owned fields such as `dns`, `mesh`, and `icmp_filter`, while Serde's default behavior is to ignore unknown fields. A minimal binary can therefore parse a configuration containing a disabled capability without the current typed validator ever seeing the section. The existing `#[cfg(feature = "dns")]` check for `!cfg!(feature = "dns")` is unreachable by construction.
2. `MainConfig::validate()` does not validate `process_manager` or `supervisor`. `ProcessManagerConfig` exposes unbounded `usize` counts that feed derived capacities such as `unified_server_workers + 10`.
3. `synvoid-upstream::shared_state` lays out mmap-backed cross-worker tables with unchecked size arithmetic and unsafe references to atomic values. Several alignment assertions are debug-only and the public constructors accept arbitrary dimensions.
4. Bcrypt hashing/verification runs synchronously from async paths in `synvoid-auth`, admin login, and HTTP Basic Auth. Tokio explicitly recommends bounding CPU-bound `spawn_blocking` work with a semaphore or separate CPU executor.
5. `synvoid-auth` persists a whole JSON snapshot directly to the destination path, falls back to an empty store after parse/read failure, and accumulates `login_logs` without a retention bound.
6. WASM PoW uses `pqc_kyber_edit` 0.7.2. The repository security docs still associate the path with RUSTSEC-2023-0079, while the RustSec advisory is keyed to `pqc_kyber` and reports no upstream patched version. Package renaming means advisory-tool cleanliness alone is not sufficient provenance evidence.
7. DNS exposes many fields whose runtime consumer is absent or partial. The current matrix identifies RPZ, dynamic UPDATE, NOTIFY, transfer-policy wiring, custom trust anchors, QNAME privacy, padding, prefetch, anycast details, and DoQ bind behavior among the residuals.
8. The macOS Seatbelt backend is opt-in and uses deprecated `sandbox_init`. It also hand-builds SBPL path literals and currently overstates some capability semantics. The backend should be treated as a security boundary, not as a string-generation convenience.
9. Phase 35 correctly kept reusable crates at "workspace library/no external support promise". Several are now close enough to justify a publication-readiness phase, but only after explicit MSRV/semver/API-support work. `synvoid-http-client` must not become a second externally supported generic HTTP client until the newer eggfetch line is re-evaluated.

## External guidance incorporated

- Serde: unknown fields are ignored by default; `#[serde(deny_unknown_fields)]` is the explicit fail-on-unknown mechanism. Reference: https://serde.rs/container-attrs.html#deny_unknown_fields
- Tokio: CPU-bound `spawn_blocking` tasks should be concurrency-limited because the default blocking-thread upper bound is large. Reference: https://docs.rs/tokio/latest/tokio/task/fn.spawn_blocking.html
- RustSec RUSTSEC-2023-0079: upstream `pqc_kyber` has no patched version; maintained ML-KEM alternatives are recommended. Reference: https://rustsec.org/advisories/RUSTSEC-2023-0079.html
- RustCrypto `ml-kem` implements final FIPS 203 and is an obvious migration candidate, subject to wasm32 proof in this repository. Reference: https://docs.rs/ml-kem/latest/ml_kem/
- Cargo `rust-version` is the supported-minimum toolchain contract for a published package; the repository's pinned compiler and a public crate's MSRV are separate concepts. Reference: https://doc.rust-lang.org/cargo/reference/rust-version.html
- Apple recommends App Sandbox for application bundles; the legacy `sandbox_init` interface used by CLI-style Seatbelt implementations is deprecated. SynVoid must therefore make its support claim explicit rather than pretending this is a current Apple public API.

## Phase order

### Phase 41 — Fail-closed configuration and process bounds

Plan: `plans/phase_41_fail_closed_config_and_process_bounds.md`

Make capability-bearing configuration impossible to silently ignore in reduced-feature builds, add validation ownership for process/supervisor settings, and make derived capacities checked and bounded. Include mesh supervision restart-field truthfulness; do not implement restart execution as part of this phase.

### Phase 42 — Shared-memory unsafe-boundary hardening

Plan: `plans/phase_42_shared_memory_unsafe_boundary_hardening.md`

Turn mmap layout computation into a checked, testable abstraction; narrow raw mmap exposure; enforce runtime alignment/range invariants; and verify the actual cross-process atomic assumptions and platform scope.

### Phase 43 — Authentication CPU isolation and durable persistence

Plan: `plans/phase_43_auth_cpu_and_persistence_hardening.md`

Move bcrypt work off async executor threads behind a bounded concurrency gate, make the auth store crash-safe and fail-closed on corruption, and bound login-audit growth.

### Phase 44 — PQC dependency truth and KyberSlash closure

Plan: `plans/phase_44_pqc_dependency_truth_and_kyberslash_closure.md`

Replace package-name-based ambiguity with a verifiable cryptographic dependency decision. Prefer migration from `pqc_kyber_edit` to a maintained final-ML-KEM implementation if wasm compatibility and vectors pass; otherwise establish explicit fork provenance and a short-lived removal condition.

### Phase 45 — DNS runtime-contract and protocol-completeness closure

Plan: `plans/phase_45_dns_runtime_contract_and_protocol_completeness.md`

First make every DNS setting truthful (implemented or rejected). Then close selected high-value protocol gaps, especially DoQ bind fidelity and persistent DNS-over-TCP/DoT behavior, without pretending every deferred DNS feature must be implemented in one pass.

### Phase 46 — Platform sandbox truthfulness and macOS closure

Plan: `plans/phase_46_platform_sandbox_truthfulness_and_macos_closure.md`

Harden SBPL generation, error handling, capability reporting, native verification, and documentation around the deprecated Seatbelt API. This phase is a prerequisite before considering `synvoid-platform` externally supported.

### Phase 47 — Public-crate release readiness

Plan: `plans/phase_47_public_crate_release_readiness.md`

Promote only crates that meet an explicit API/MSRV/semver/test/documentation bar. First-wave candidates are `synvoid-rate-limit` and `synvoid-mesh-protocol`; `synvoid-proxy-cache` and `synvoid-dnssec-keystore` require additional domain/security qualification. Keep `synvoid-http-client` internal until the eggfetch 0.1.5+ capability matrix is refreshed.

## Dependency order and safe parallelism

Phase 41 should land first because later configuration and feature-profile tests rely on a truthful parser/validator.

Phases 42, 43, and 44 can proceed in parallel after Phase 41 if they avoid common root-document churn. Phase 43 may add auth configuration fields; those must use the Phase 41 validation conventions.

Phase 45 can begin its matrix and tests in parallel, but any new feature activation semantics must use the Phase 41 fail-closed contract.

Phase 46 is independent of DNS/PQC implementation but should land before Phase 47 classifies `synvoid-platform`.

Phase 47 runs last as a support-policy/release gate. It may publish zero crates if the qualification evidence is insufficient; publication is not itself an acceptance criterion.

## Explicit non-goals

- No broad crate extraction or merge sweep.
- No `synvoid-filter` merge solely to reduce crate count.
- No forced collapse of `http-client` / `upstream` / `tunnel`.
- No public `synvoid-utils` support promise.
- No in-place mesh restart implementation unless a separate design proves the lifecycle/rollback model; Phase 41 only makes current unsupported behavior configuration-truthful.
- No attempt to implement all deferred DNS features merely because configuration structs exist.
- No replacement of the existing jail/process isolation protocol.
- No new generic HTTP client if eggfetch can become the single reusable owner.

## Roadmap-wide acceptance criteria

This roadmap is complete when:

- reduced-feature binaries reject configuration for capabilities they do not contain;
- process/supervisor counts and all shared-memory size derivations are bounded and checked;
- unsafe shared-memory access has documented, mechanically tested preconditions with no debug-only correctness requirement;
- bcrypt never performs CPU-hard verification/hashing directly on Tokio core threads in request paths;
- auth persistence is atomic enough to preserve the last valid store across interrupted writes, and corrupt state cannot silently become an empty authorization database;
- auth audit growth is bounded;
- the WASM PoW ML-KEM backend has a truthful advisory/provenance story and no reliance on package renaming to evade security tooling;
- DNS configuration/runtime matrices contain no "enabled but ignored" settings in supported profiles;
- macOS sandbox support claims match the behavior actually verified on macOS and SBPL generation cannot be influenced by unescaped paths;
- any crate promoted to public-candidate status has an explicit MSRV, semver/support statement, crate-local docs/examples, package dry-run evidence, deterministic tests, and no hidden SynVoid runtime requirement;
- `synvoid-http-client` is not independently published until a current eggfetch comparison proves that duplicate external maintenance is justified.

## Recommended final verification envelope

```bash
cargo fmt --all -- --check
cargo xtask verify
cargo xtask verify-full
cargo xtask verify-release
cargo deny check
cargo audit
cargo check --no-default-features
cargo check --no-default-features --features mesh
cargo check --no-default-features --features dns
cargo check --no-default-features --features mesh,dns
cargo nextest run --workspace --cargo-profile ci --profile ci --exclude synvoid-fuzz
cargo test --workspace --doc --profile ci
```

Add phase-specific native macOS, wasm32, DNS interop, auth fault-injection, and shared-memory tests as described in the detailed plans.
