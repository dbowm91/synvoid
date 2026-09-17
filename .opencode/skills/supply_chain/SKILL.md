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
   `.cargo/audit.toml`.
2. **Never call wasmtime 42.0.2 "patched" for RUSTSEC-2026-0269.**
   42.0.2 (direct, via `[patch.crates-io]`) is AFFECTED; the finding is
   closed by capability absence (`wasmtime-wasi` unreachable), not a patch.
   Transitive 40.0.4 arrives via `synvoid-yara` → `yara-x` 1.15 (YARA boundary
   only, not the WASM sandbox). Upgrade to ≥46.0.3 is blocked by a bumpalo
   conflict. Details in the baseline doc §4.
   Phase 36 addendum: the yara-x >=1.19 upgrade (GHSA-2jx3-ff3v-j7jj fix) is
   blocked by the SAME conflict (wasmtime >=43 needs `bumpalo ^3.20.0`;
   `minify-html` 0.18.1 → `oxc_allocator` 0.95.0 pins `=3.19.0`; cargo cannot
   split same-major — reproduced 2026-09-17 in an isolated scratch crate).
   The trust-model closure (source-only execution, remote bytes never
   deserialized) lands on 1.15; never add an advisory ignore for the GHSA to
   pretend 1.15 is fine, and never call 1.15 "patched".
3. **Prefer pure-Rust deps over C bindings** for new dependencies
   (serialization/crypto standards in `AGENTS.md`).
4. **pip installs honor `require_hashes`**: `AppServerConfig.require_hashes`
   flows `SiteAppServerConfig` → `AppServerConfig` → `GranianConfig`
   (`crates/synvoid-config/src/site/app_server.rs`,
   `crates/synvoid-app-server/src/granian.rs`), adding `--require-hashes`
   to `pip install`. With it on, maintain a hashed `requirements.txt`
   (`pip hash -r <package>`). TOML: `[app_server] require_hashes = true`.
5. **Publication is manual** (`cargo publish` only, see `docs/releasing.md`);
   `cargo xtask verify-release` never publishes and fails on a dirty tree.

## Verification

```bash
cargo deny check
cargo audit
cargo xtask test guards   # includes deny_ignore_metadata_guard
```
