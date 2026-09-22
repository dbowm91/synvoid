---
name: supply_chain
description: Rust + Python supply-chain policy — cargo-deny/audit gates, advisory-ignore rules, wasmtime baseline, pip --require-hashes. Use when adding/upgrading dependencies or touching deny.toml, audit.toml, Cargo.lock, or app-server pip installs.
---

# Skill: Supply-Chain Security

## Context

Dependency policy is a **blocking CI gate** (`dependency-security` job in
`.github/workflows/ci.yml`: `cargo deny check` + `cargo audit`, also on a
daily schedule), not advisory. Binding evidence:
`architecture/dependency_security_baseline_phase25.md` (re-audit 2026-10-01).
Pinned tools: cargo-deny 0.20.2, cargo-audit 0.22.2
(see `docs/testing/verification-contract.md`).

## When to Use

- Adding, upgrading, or removing any crate dependency
- Touching `deny.toml`, `.cargo/audit.toml`, or `Cargo.lock`
- Triaging a `cargo deny` / `cargo audit` failure in CI or `cargo xtask verify`
- Changing app-server Python installs (`crates/synvoid-app-server/`)

## Key Files

| File | Purpose |
|------|---------|
| `deny.toml` | License allowlist + advisory ignores with mandatory metadata |
| `.cargo/audit.toml` | Must mirror the `deny.toml` ignore set so both gates agree |
| `architecture/dependency_security_baseline_phase25.md` | Binding exposure evidence per ignore (version/feature/capability separation) |
| `architecture/track4_dependency_security_closeout.md` | Phase 31 closeout evidence |
| `Cargo.lock` | Lockfile; check `wasmtime` / `bumpalo` versions here, not from memory |
| `crates/synvoid-app-server/src/granian.rs` | pip install path (`require_hashes` flag) |

## Non-Negotiables

1. **Every advisory ignore needs full metadata** (enforced by
   `deny_ignore_metadata_guard`): dependency path, affected capability,
   whether `wasmtime-wasi` is resolved, exposure, `Owner:`, `Reviewed:`,
   `Re-audit:` (single machine-enforced future deadline), and a `Remove
   condition:` (upstream event, never a date). Mirror the ignore in
   `.cargo/audit.toml`. Verify ignores are exact: remove `.cargo/audit.toml`
   temporarily and confirm every ignore fires on the live graph (Phase 40:
   2 fire — 0071 rsa, 0235 rkyv 0.7.46; the 14 retired wasmtime-40.x ignores
   were removed with the 40.0.4 line). A fixable finding (cf. cryptoki
   RUSTSEC-2026-0286, fixed 0.12.0 → 0.12.1 via targeted `cargo update -p`)
   gets an upgrade, not an ignore.
2. **Never describe a capability-unreachable advisory as patched; never call
   an affected version "patched".** The direct runtime is 36.0.15 LTS from
   crates.io (supported through 2027-08-20, no git patch) and IS patched
   for RUSTSEC-2026-0269 (>=36.0.14; proven by a clean isolated `cargo
   audit` with no ignores) — it needs no 0269 ignore. The YARA transitive
   line is 47.0.4 (patched >=47.0.4) via the temporary manifest-only
   `yara-x` compat fork (`third-party/yara-x-compat/`, exact upstream
   1.20.0 sources + the unreleased upstream PR #769 two-line delta:
   wasmtime 45.0.3 → 47.0.4; root `[patch.crates-io]` path override, no git
   source). Wasmtime 40.0.4 is gone, so its 14 ignores are removed — do not
   re-add them without a version-affected wasmtime in the graph.
   `wasmtime-wasi` remains absent (capability absence still holds and is
   still guard-enforced, but it is not a substitute for version remediation).
   `yara_fork_is_temporary_guard` + `wasmtime_transitive_matches_baseline`
   enforce the fork's narrowness and removal condition (official fixed
   yara-x release).
   Phase 39 addendum: the `minify-html` side of the `bumpalo` conflict is
   REMOVED via the temporary vendored compat fork
   (`third-party/minify-html-compat/`, exact 0.18.1 `src/` + manifest-only
   Oxc 0.95 -> 0.111, root `[patch.crates-io]` path override, no git source;
   `minify_fork_is_temporary_guard` enforces single-patch + metadata +
   removal condition). Post-fork: `oxc_allocator` 0.111.0, no
   `minify-html -> bumpalo` edge; remaining `bumpalo` is cranelift/wasmtime
   only (single 3.20.3 after Phase 40). Parity corpus (`crates/synvoid-static-files/tests/minify_parity.rs`,
   16 tests) is byte-identical before/after. Phase 40 landed the yara-x 1.20
   upgrade (GHSA-2jx3-ff3v-j7jj version-remediated; `linkme` feature dropped
   as upstream removed it; `YARA_ENGINE_VERSION` is `yara-x/1.20`).
   Details in the baseline doc §10–§11.
   Phase 36 addendum: the yara-x >=1.19 upgrade (GHSA-2jx3-ff3v-j7jj fix) is
   blocked by the SAME conflict (wasmtime >=43 needs `bumpalo ^3.20.0`;
   `minify-html` 0.18.1 → `oxc_allocator` 0.95.0 pins `=3.19.0`; cargo cannot
   split same-major — reproduced 2026-09-17 in an isolated scratch crate).
   The trust-model closure (source-only execution, remote bytes never
   deserialized) lands on 1.15; never add an advisory ignore for the GHSA to
   pretend 1.15 is fine, and never call 1.15 "patched".
   Phase 38 guards: `yara_execution_boundary.rs` fails on any
   `Rules::deserialize` in mesh/upload/synvoid-yara production code, on
   removed compiled-byte tokens, and on `YARA_ENGINE_VERSION`/manifest drift;
   `dependency_security.rs` fails on broadened direct-wasmtime ownership, lock
   drift (must be exactly direct LTS + transitive YARA), git sources, or major
   moves without a baseline update.
3. **Prefer pure-Rust deps over C bindings** for new dependencies
   (serialization/crypto standards in `AGENTS.md`).
4. **pip installs fail closed on `require_hashes`**: `AppServerConfig.require_hashes`
   flows `SiteAppServerConfig` → `AppServerConfig` → `GranianConfig`
   (`crates/synvoid-config/src/site/app_server.rs`,
   `crates/synvoid-app-server/src/granian.rs`), adding `--require-hashes`
   to `pip install`. Default is `true` (missing key / `None` resolves true);
   opt out explicitly with `[app_server] require_hashes = false`.
   With it on, maintain a hashed `requirements.txt`
   (`pip hash -r <package>`). TOML: `[app_server] require_hashes = true`.
5. **Publication is manual** (`cargo publish` only, see `docs/releasing.md`);
   `cargo xtask verify-release` never publishes and fails on a dirty tree.
   Only `synvoid-rate-limit` is externally supported (class 3, MSRV 1.81);
   every other `synvoid-*` crate is class 1/2 with no support promise —
   binding policy in `architecture/public_crate_release_policy.md`, pinned by
   the `public_crate_release_policy` guard test.

## Verification

```bash
cargo deny check
cargo audit
cargo xtask test guards   # includes deny_ignore_metadata_guard
```
