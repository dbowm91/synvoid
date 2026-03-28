# Security & Maintainability Dependency Audit Plan

**Date**: 2026-03-27
**Scope**: MaluWAF dependency audit — CVEs, unmaintained crates, binary bloat, SECURITY.md corrections
**Constraint**: No feature reduction. Overseer/master/worker architecture must be preserved.

---

## Executive Summary

`cargo audit` reports **2 vulnerabilities** (1 high, 1 medium) and **8 unmaintained warnings**. The dependency tree has **~100 duplicate crate groups**, primarily from dual wasmtime versions (36 + 40). SECURITY.md contains two factual errors claiming migrations are "Completed" when they are not.

---

## Phase 1: SECURITY.md Corrections (No Code Risk)

### 1.1 Fix bincode migration status

**Current state in SECURITY.md**: Line 119 — `| ~~bincode~~ | ~~postcard~~ | **Completed** |`

**Reality**:
- `bincode = "1"` is still listed in `Cargo.toml:76` as a direct dependency
- `Cargo.lock` contains `bincode 1.3.3` (direct) and `bincode 2.0.1` (transitive via yara-x)
- No Rust source file contains `use bincode` — all code uses `crate::serialization::serialize_bincode` which delegates to postcard (`src/serialization.rs:46-52`)
- The `bincode` crate is a **dead direct dependency** — compiles but never linked through direct usage

**Fix**: Update SECURITY.md to reflect that `bincode` is still present as a dead dependency and add a task to remove it.

### 1.2 Fix rustls-pemfile migration status

**Current state in SECURITY.md**: Line 123 — `| ~~rustls-pemfile~~ | ~~rustls-pki-types~~ | **Completed** |`

**Reality**:
- `rustls-pemfile = "2"` is still in `Cargo.toml:146`
- Actively used in `src/http_client/mod.rs:180`:
  ```rust
  let certs: Vec<_> = rustls_pemfile::certs(&mut reader).collect::<Result<Vec<_>, _>>()?;
  ```

**Fix**: Update SECURITY.md. The migration from `rustls-pemfile` to `rustls-pki-types` PEM parsing has **not** been completed for the HTTP client code path. Mark as "In Progress" or remove the strikethrough.

### 1.3 Add missing unmaintained crates

SECURITY.md is missing these `cargo audit` findings:

| Crate | RUSTSEC | Notes |
|-------|---------|-------|
| `fxhash 0.2.1` | RUSTSEC-2025-0057 | Transitive via wasmtime 36 |
| `unicode-segmentation 1.13.1` | Yanked | Transitive via lightningcss |

### 1.4 Files to modify

- `SECURITY.md` — lines 100-124 (Known Dependency Vulnerabilities and Unmaintained Dependencies tables)

---

## Phase 2: Remove Dead `bincode` Dependency (Trivial)

### 2.1 Remove from Cargo.toml

**File**: `Cargo.toml:75-76`

```toml
# BEFORE
# Keep bincode for backwards compatibility
bincode = "1"

# AFTER (delete both lines)
```

### 2.2 Verify no breakage

- `src/serialization.rs:46-52` — `serialize_bincode`/`deserialize_bincode` use `postcard` internally, not `bincode`
- All callers use `crate::serialization::serialize_bincode` (the postcard shim), not the bincode crate directly
- Files that call the shim: `src/tunnel/quic/messages.rs`, `src/tunnel/quic/codec.rs`
- After removal, `cargo check` and `cargo test --test integration_test` should pass
- The `bincode 1.3.3` RUSTSEC-2025-0141 unmaintained warning will be eliminated for the direct dependency

**Note**: `bincode 2.0.1` remains as transitive via yara-x — this cannot be changed.

### 2.3 Update SECURITY.md

Mark bincode removal as completed rather than the migration.

---

## Phase 3: Complete `rustls-pemfile` → `rustls-pki-types` Migration

### 3.1 Current usage

**File**: `src/http_client/mod.rs:175-186`

```rust
fn load_ca_certs_from_path(
    path: &str,
) -> Result<Vec<rustls_pki_types::CertificateDer<'static>>, Box<dyn std::error::Error + Send + Sync>> {
    let file = std::fs::File::open(path)?;
    let mut reader = std::io::BufReader::new(file);
    let certs: Vec<_> = rustls_pemfile::certs(&mut reader)
        .collect::<Result<Vec<_>, _>>()?;
    if certs.is_empty() {
        return Err(format!("No certificates found in {}", path).into());
    }
    Ok(certs)
}
```

### 3.2 Replacement approach

`rustls-pki-types` provides `PemObject` trait with `pem_file_iter` and `pem_slice_iter` methods on `CertificateDer`. Replace:

```rust
// AFTER
use rustls_pki_types::{CertificateDer, pem::PemObject};

fn load_ca_certs_from_path(
    path: &str,
) -> Result<Vec<rustls_pki_types::CertificateDer<'static>>, Box<dyn std::error::Error + Send + Sync>> {
    let certs: Vec<_> = CertificateDer::pem_file_iter(path)?
        .collect::<Result<Vec<_>, _>>()?;
    if certs.is_empty() {
        return Err(format!("No certificates found in {}", path).into());
    }
    Ok(certs)
}
```

The `pem_file_iter` method reads the file directly and returns an iterator of `Result<CertificateDer<'static>, pem::Error>`. This is a drop-in replacement for the `rustls_pemfile::certs` pattern.

### 3.3 Remove from Cargo.toml

**File**: `Cargo.toml:146` — delete `rustls-pemfile = "2"`

### 3.4 Verification

- `cargo check` must pass
- Existing TLS client tests must pass
- The `rustls-pemfile` RUSTSEC-2025-0134 unmaintained warning will be eliminated

### 3.5 Files to modify

- `src/http_client/mod.rs` — `load_ca_certs_from_path` function (lines 175-186)
- `Cargo.toml` — remove `rustls-pemfile` dependency (line 146)

---

## Phase 4: Upgrade `wasmtime` 36 → 43 (Major, High Impact)

### 4.1 Problem

Two wasmtime versions coexist:
- `wasmtime 36.0.6` — direct dependency (`Cargo.toml:181-182`)
- `wasmtime 40.0.4` — transitive via `yara-x 1.14.0`

This duplicates ~80 crates including two full cranelift backends, adding an estimated 10-20MB to binary size.

### 4.2 Solution

Upgrade direct wasmtime from 36 to 43 (latest). Benefits:
- Eliminates ~80 duplicate crate entries
- Aligns closer to yara-x's wasmtime 40 (still some overlap, but reduces from 3 generations to 2)
- Picks up 7 major versions of fixes and performance improvements
- Eventually, when yara-x upgrades to 43+, all duplication is eliminated

### 4.3 API migration scope

wasmtime 36→43 is a 7-major-version jump. Key breaking changes to investigate:
- WASI snapshot exports renamed
- `wasmtime::Engine` configuration API changes
- `wasmtime_wasi` module restructuring
- Component model support changes

### 4.4 Files likely affected

- `Cargo.toml:181-182` — version bump
- WASM plugin loading code — search for `wasmtime` usage in the codebase
- `src/wasm_pow/` — WASM proof-of-work module (uses wasmtime)

### 4.5 Verification

- `cargo check` must pass
- `cargo test` must pass (especially WASM-related tests)
- Binary size comparison before/after
- Feature parity: all existing WASM plugin functionality must work

### 4.6 Risk assessment

**Medium-High**. wasmtime has aggressive deprecation policies. Each major version may remove deprecated APIs. Recommend:
1. First try `cargo check` with wasmtime 43 and fix compile errors iteratively
2. If too many breaking changes, try intermediate upgrade (36→40→43)

---

## Phase 5: Evaluate `boringtun` → `defguard_boringtun`

### 5.1 Problem

`boringtun 0.7.0` (Cloudflare) — the upstream repo is effectively archived. Last meaningful code update was 2023. The 0.7.0 crates.io publish (Jan 2026) was a metadata-only update.

### 5.2 Alternative

`defguard_boringtun 0.6.5` — community fork by Defguard, actively maintained (last update Feb 2026). Maintains API compatibility.

### 5.3 Usage

**File**: `src/tunnel/wireguard/userspace.rs:135-136`
```rust
use boringtun::noise::{Tunn, TunnResult};
use boringtun::x25519::StaticSecret;
```

### 5.4 Approach

1. Verify API compatibility between `boringtun 0.7` and `defguard_boringtun 0.6.5`
2. If compatible: swap dependency in Cargo.toml and update `use` statements
3. If not: create a thin adapter module

### 5.5 Files to modify

- `Cargo.toml:185` — change `boringtun = { version = "0.7", optional = true }` to `defguard_boringtun`
- `src/tunnel/wireguard/userspace.rs` — update import paths
- Feature flag `wireguard` in `Cargo.toml:25`

### 5.6 Risk

**Low**. The `wireguard` feature is optional and conditionally compiled. Changes are isolated.

---

## Phase 6: Evaluate `dns-parser` Replacement

### 6.1 Problem

`dns-parser 0.8.0` — last updated August 2018 (8 years old). Effectively unmaintained, though no RUSTSEC advisory exists.

### 6.2 Current usage

Used heavily in `src/dns/recursive.rs` (70 references) for:
- `dns_parser::Packet` — DNS packet parsing
- `dns_parser::QueryType` — query type enum (A, AAAA, TXT, NS, MX, etc.)

Also used in: `src/dns/recursive_cache.rs`, `src/dns/wire.rs`, `tests/dns_config_test.rs`

### 6.3 Alternative

You already depend on `hickory-proto 0.25` which provides equivalent DNS parsing functionality. hickory-proto is the successor to trust-dns and is actively maintained by the Hickory DNS project.

### 6.4 Approach

Replace `dns_parser::Packet` and `dns_parser::QueryType` with hickory-proto equivalents:
- `hickory_proto::op::Message` replaces `dns_parser::Packet`
- `hickory_proto::rr::RecordType` replaces `dns_parser::QueryType`

### 6.5 Files to modify

- `Cargo.toml:109` — remove `dns-parser = "0.8"`
- `src/dns/recursive.rs` — largest change (~70 references)
- `src/dns/recursive_cache.rs` — `From` impl for QueryType
- `src/dns/wire.rs` — packet parsing
- `tests/dns_config_test.rs` — test assertions

### 6.6 Risk

**Medium**. The dns-parser usage is extensive but mechanical (type conversions). The hickory-proto API surface is well-documented. Main risk is subtle behavioral differences in edge-case DNS parsing.

---

## Phase 7: Monitor `isbot` Staleness

### 7.1 Problem

`isbot 0.1.3` — last updated March 2022 (4 years old). Bot user-agent lists go stale as new crawlers emerge.

### 7.2 Current usage

**File**: `src/waf/bot.rs:1` — single line: `use isbot::Bots`

### 7.3 Options

1. **Keep it** — The core bot detection logic may be in your own WAF code; isbot is just one signal
2. **Fork and update** — The crate is simple (regex-based matching); fork and maintain your own UA list
3. **Replace with inline regex** — If usage is minimal, embed the patterns directly

### 7.4 Recommendation

**Defer**. This is low-priority. The crate still compiles and the concept of "known bots" doesn't change rapidly. Revisit if bot evasion becomes a real issue.

---

## Phase 8: `lightningcss` Alpha Pinning

### 8.1 Problem

`lightningcss = "1.0.0-alpha.70"` — pinned to an alpha release. The crate has been in alpha since 2022. While functionally stable, alpha versions can introduce breaking changes without semver guarantees.

### 8.2 Current status

Latest is `1.0.0-alpha.71` (published Mar 2026). You are one alpha behind.

### 8.3 Recommendation

- Bump to `"1.0.0-alpha.71"` and test CSS minification paths
- Consider pinning with `~1.0.0-alpha.70` to prevent accidental major alpha bumps
- Monitor for a stable 1.0.0 release

### 8.4 Risk

**Low**. CSS minification is a non-critical path.

---

## Phase 9: Add `cargo-deny` to CI

### 9.1 Rationale

SECURITY.md line 192 already recommends this but it's not implemented. `cargo-deny` provides:
- Automated vulnerability checking on every CI run
- License compliance checking
- Duplicate dependency warnings
- Advisory database integration

### 9.2 Approach

1. Install `cargo-deny` as a CI tool
2. Create `deny.toml` with:
   - Advisory database checks
   - License allowlist
   - Duplicate dependency thresholds
   - Unmaintained crate warnings
3. Add a CI step that runs `cargo deny check`

### 9.3 Files to create

- `deny.toml` — cargo-deny configuration

---

## Verification Checklist

After all changes:

- [ ] `cargo audit` — 0 vulnerabilities (excluding pqc_kyber/rsa no-fix items)
- [ ] `cargo check` — clean compile
- [ ] `cargo test --test integration_test` — passes
- [ ] `cargo test` — passes (full suite)
- [ ] `cargo clippy -- -D warnings` — no new warnings
- [ ] `cargo fmt --check` — clean formatting
- [ ] Binary size comparison — should be smaller after wasmtime unification
- [ ] Feature matrix: all features compile (`--features dns`, `--features wireguard`, etc.)

---

## Priority Order

| Priority | Phase | Effort | Impact |
|----------|-------|--------|--------|
| 1 | Phase 1: SECURITY.md corrections | Trivial | Documentation accuracy |
| 2 | Phase 2: Remove dead bincode | Trivial | Eliminates 1 unmaintained warning |
| 3 | Phase 3: Complete rustls-pemfile migration | Small | Eliminates 1 unmaintained warning |
| 4 | Phase 9: Add cargo-deny to CI | Small | Prevents future regressions |
| 5 | Phase 8: Bump lightningcss alpha | Trivial | Staying current |
| 6 | Phase 5: boringtun → defguard_boringtun | Medium | Avoids archived dependency |
| 7 | Phase 6: dns-parser → hickory-proto | Medium | Eliminates 8-year-old dependency |
| 8 | Phase 4: Upgrade wasmtime 36→43 | **Large** | Biggest binary size win |
| 9 | Phase 7: isbot staleness | Defer | Low priority |

---

## Out of Scope

- Architecture changes to overseer/master/worker — not affected by dependency updates
- Feature additions or removals — all changes are drop-in replacements
- `pqc_kyber` (RUSTSEC-2023-0079) — no fix available; used only in wasm-pow for PoW challenges
- `rsa` (RUSTSEC-2023-0071) — transitive via yara-x; no fix available; low exposure
