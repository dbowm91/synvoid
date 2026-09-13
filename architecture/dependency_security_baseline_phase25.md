# Dependency Security Baseline — Phase 25 Evidence

Status: binding evidence for Track 4 Phase 25 (`plans/phase_25_dependency_security_baseline_and_entitlement.md`).
Owner: security / release. Reviewed: 2026-09-13. Re-audit: 2026-10-01 (all advisory ignores; see §5).

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

Evidence commands (run 2026-09-12, advisory DB current at run time):

```bash
cargo tree -i wasmtime@42.0.2 --workspace
cargo tree -e features -i wasmtime@42.0.2 --workspace
cargo tree -i wasmtime@40.0.4 --workspace
cargo tree -e features -i wasmtime@40.0.4 --workspace
cargo tree -i yara-x --workspace
cargo audit
cargo deny check advisories
```

## 1. Direct Wasmtime path (plugin runtime)

<!-- guard-anchor: wasmtime-direct-version = "42.0.2" -->
<!-- guard-anchor: wasmtime-transitive-version = "40.0.4" (via yara-x 1.15.0) -->
<!-- guard-anchor: wasmtime-wasi-absent-from-lock = true -->

- Version: **42.0.2** via `[patch.crates-io]` Git source (`tag = "v42.0.2"`).
- Requested features (`crates/synvoid-plugin-runtime/Cargo.toml`): `component-model` only.
- Consumers (`cargo tree -i wasmtime@42.0.2`): exactly `synvoid-plugin-runtime`
  (plus the root dev-dependency used by `benches/bench_wasm.rs`).
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

- Affected range: Wasmtime 37.0.0 through 46.0.2. Patched: ≥46.0.3 (<47) or ≥47.0.4.
- **Both resolved versions (direct 42.0.2, transitive 40.0.4) are inside the affected
  range. Neither is described as patched.** Earlier comments calling 42.0.2 "patched"
  referred to the 2026-04 Winch/Cranelift advisories (0085–0096, 0114, 0222), for which
  42.0.2 is a fixed version; that language has been removed wherever it implied 0269 coverage.
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

## 4. Why the direct runtime is not yet on 46.0.3

Upgrade attempted 2026-09-12: `wasmtime 42.0.2 → 46.0.3` (smallest 0269-fixed line),
`[patch.crates-io]` removal. Resolution fails deterministically, including from a
clean lockfile and in an isolated scratch crate:

- wasmtime 46.0.3 requires `bumpalo ^3.20.2`.
- `minify-html 0.18.1` (latest) → `oxc_allocator 0.95.0` (only 0.95.x) pins
  `bumpalo =3.19.0` exactly.
- Both requirements are major-version 3: Cargo unifies same-major selections and
  cannot split them, so no lockfile satisfies both. Error reproduced with
  `cargo generate-lockfile` on 2026-09-12.
- No newer minify-html exists upstream to relax the pin; dropping HTML minification
  to force the upgrade would be a product behavior change, explicitly out of scope.

Decision: keep direct Wasmtime at 42.0.2 (still fixed for the 2026-04 advisories)
under this capability-absence finding, and re-attempt the ≥46.0.3 upgrade when the
`bumpalo` conflict clears (upstream minify-html/oxc release). Re-audit: 2026-10-01.
The `deny.toml` 0269 ignore carries this owner, Re-audit date, and remove condition;
the guard below enforces expiry against the current UTC date.

## 5. Guards (all in `tools/synvoid-repo-guards/tests/`)

- `wasmtime_baseline_guard` (`dependency_security.rs`): direct Wasmtime version must
  equal the version recorded here; `wasmtime-wasi`/`wasi-filesystem` must stay absent
  from `Cargo.lock` unless this file gains a new exposure section; the 0269 ignore must
  retain owner + Phase 26 remove-by metadata.
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
| Duplicated `wasmtime` 40.0.4 / 42.0.2 | 40 via yara-x (single `synvoid-yara` owner); 42 direct runtime | follow-up — §4 owns direct ≥46.0.3 upgrade (Re-audit: 2026-10-01) |
| Duplicated `rkyv` 0.7.46 / 0.8.x | 0.7 via `parcel_sourcemap`; direct code on 0.8 | follow-up — collapses with the same lightningcss change; 0.7 covered by RUSTSEC-2026-0235 ignore with review date |
| Native/FFI (`aws-lc-rs`, `ring` transitive, `libloading`, `bumpalo`-linked compiles) | TLS PQC backend, DNS/QUIC crypto, native-extension loading (compiled out by default + disabled by default + allowlisted) | justified — each has an owning security invariant (see `AGENTS.md`); `libloading` plugin-loader isolation complete in Phase 28 (`synvoid-native-extension` + `unsafe-native-extensions` feature, off by default) |
| Git sources | exactly one: wasmtime 42.0.2 patch (this file §1/§4) | follow-up — remove with the §4 upgrade; `deny.toml` `allow-git` lists only it |
| Build dependencies executing code at build time | `tonic-prost-build` (protobuf codegen, mesh admin/control APIs), `chrono` (codegen timestamps) | justified — pinned via lockfile; codegen inputs are checked-in protos |

No `cargo machete` run is recorded as authoritative: feature-gated and generated-code
cases in this workspace require project-specific interpretation (see Part E), so the
in-repo entitlement guard (`root_dependency_ownership.md` + `module_ownership.rs`)
is authoritative and machete remains optional supporting evidence.
