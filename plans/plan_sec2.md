# Dependency Security Audit Implementation Plan

**Date**: 2026-03-27
**Status**: Planning
**Goal**: Address security vulnerabilities and remove unmaintained dependencies

---

## Executive Summary

This plan addresses findings from a comprehensive dependency audit of MaluWAF. Key actions:
1. Remove unused `bincode` dependency
2. Complete `rustls_pemfile` → `rustls-pki-types` migration
3. Update SECURITY.md documentation
4. Keep quinn git patch pending further testing
5. Verify wasmtime security patch status

---

## Task 1: Remove `bincode` Dependency

### Files Affected
- `Cargo.toml`

### Rationale
- `bincode` is unmaintained (RUSTSEC-2025-0141)
- Migration to `postcard` was completed in `src/serialization.rs`
- No direct usage of `bincode` found in codebase
- Remaining references are transitive via `gloo-worker` in admin-ui

### Implementation
```diff
# Cargo.toml - remove line
- bincode = "1"
```

### Verification
- Run `cargo check` to ensure no breakage
- Run `cargo audit` to confirm no new issues

### Risk: **LOW**
- No direct usage in codebase
- Migration to postcard already complete

---

## Task 2: Complete `rustls_pemfile` → `rustls-pki-types` Migration

### Files Affected
- `src/http_client/mod.rs`

### Current State
The migration to `rustls-pki-types` is **partial**:
- `src/tls/cert_resolver.rs` - ✅ Uses `rustls_pki_types::pem`
- `src/mesh/cert.rs` - ✅ Uses `rustls_pki_types::pem`
- `src/tunnel/quic/tls.rs` - ✅ Uses `rustls_pki_types::pem`
- `src/http_client/mod.rs` - ❌ Still uses `rustls_pemfile::certs`

### Current Code (lines 175-186)
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

### Replacement Implementation
```rust
fn load_ca_certs_from_path(
    path: &str,
) -> Result<Vec<rustls_pki_types::CertificateDer<'static>>, Box<dyn std::error::Error + Send + Sync>> {
    use rustls_pki_types::pem::PemObject;
    use std::io::Read;
    
    let mut file = std::fs::File::open(path)?;
    let mut contents = Vec::new();
    file.read_to_end(&mut contents)?;
    
    let certs: Vec<_> = rustls_pki_types::CertificateDer::pem_slice_iter(&contents)
        .filter_map(Result::ok)
        .collect();
    
    if certs.is_empty() {
        return Err(format!("No certificates found in {}", path).into());
    }
    Ok(certs)
}
```

### Verification
- `cargo check` must pass
- Integration tests should verify TLS certificate loading

### Risk: **LOW**
- `rustls-pki-types` is actively maintained
- `CertificateDer::pem_slice_iter()` is equivalent functionality
- Other files in codebase already use this pattern

---

## Task 3: Update SECURITY.md Documentation

### Files Affected
- `SECURITY.md`

### Changes Required

#### 3.1 Add `unicode-segmentation` yanked entry
Add to "Known Dependency Vulnerabilities" table:
```markdown
| Crate | ID | Status | Notes |
|-------|-----|--------|-------|
| unicode-segmentation | - | **Yanked** | Transitive via lightningcss - upgrade lightningcss |
```

#### 3.2 Add wasmtime vulnerability documentation
Add new section after existing vulnerability entries:
```markdown
### wasmtime RUSTSEC-2025-0118
- **Issue**: Unsound API access to WebAssembly shared linear memory
- **Severity**: Low (CVSS 1.8)
- **Aliases**: CVE-2025-64345, GHSA-hc7m-r6v8-hg9q
- **Patched**: >=36.0.3
- **Current**: Using wasmtime 36.0.6 (patched)
- **Exposure**: LOW - used only for plugin sandboxing
```

#### 3.3 Update `bincode` status
Change from:
```markdown
| ~~`bincode`~~ | ~~`postcard`~~ | **Completed** | Replaced with postcard |
```

To:
```markdown
| ~~`bincode`~~ | ~~`postcard`~~ | **Completed** | Removed from Cargo.toml |
```

#### 3.4 Update `rustls-pemfile` status
Change from:
```markdown
| ~~`rustls-pemfile`~~ | ~~`rustls-pki-types`~~ | **Completed** | TLS certificate parsing |
```

To:
```markdown
| ~~`rustls-pemfile`~~ | ~~`rustls-pki-types`~~ | **Completed** | `http_client/mod.rs` migrated |
```

#### 3.5 Add cargo deny recommendation
Add to Monitoring section:
```markdown
### CI Integration

Consider using [cargo-deny](https://cargo-deny.readthedocs.io/) in CI:

```bash
cargo deny check advisories bans licenses
```

Add `deny.toml` configuration to enforce dependency policies.
```

### Verification
- Read updated SECURITY.md to verify formatting

### Risk: **NONE**
- Documentation only, no code changes

---

## Task 4: wasmtime Verification (Informational)

### Analysis Summary
- **RUSTSEC-2025-0118**: Unsound API access to shared linear memory
- **CVSS Score**: 1.8 (LOW)
- **Cargo.toml Version**: `wasmtime = "36"` (resolves to 36.0.6)
- **Patched Versions**: >=36.0.3, >=37.0.3, >=38.0.4, >=24.0.5
- **Status**: ✅ Current version is patched
- **Note**: Transitive dependency `wasmtime 40.0.4` exists via `yara-x` (also patched)

### Action Required
- No code changes needed
- Only documentation update in Task 3.2

---

## Task 5: Quinn Git Patch - Keep Pending

### Current State
- `[patch.crates-io]` section in `Cargo.toml` for `quinn-proto`
- Targets `quinn-proto-0.11.14` from git
- Fixes RUSTSEC-2026-0037 (CVE-2026-31812)

### Decision
- **Keep patch** pending further testing
- quinn 0.11.9 is now released with the fix
- Remove patch when team validates quinn 0.11.9 in staging

### Action Items
No changes to Cargo.toml required at this time. The TODO comment is already present.

---

## Task 6: Post-Implementation Verification

### Required Steps
1. `cargo check` - Ensure compilation succeeds
2. `cargo audit` - Verify no new vulnerabilities introduced
3. `cargo test --test integration_test` - Run integration tests
4. Manual testing of TLS certificate loading functionality

### Success Criteria
- [ ] `cargo check` passes
- [ ] `cargo audit` shows no new issues
- [ ] Integration tests pass
- [ ] SECURITY.md accurately reflects current state

---

## Risk Assessment Summary

| Task | Risk Level | Mitigation |
|------|------------|------------|
| Remove bincode | LOW | No direct usage confirmed |
| Complete PEM migration | LOW | Pattern already used elsewhere |
| Update SECURITY.md | NONE | Documentation only |
| Verify wasmtime | LOW | Already patched (verification only) |
| Keep quinn patch | N/A | No change |

---

## Timeline Recommendation

1. **Immediate**: Update SECURITY.md (lowest risk, immediate value)
2. **This Sprint**: Complete Tasks 1-3 together
3. **Next Sprint**: Full wasmtime 40+ upgrade with testing
4. **Ongoing**: Monitor quinn 0.11.9 release notes

---

## Open Questions

1. ~~Remove quinn git patch?~~ - **DECIDED**: Keep patch pending testing
2. ~~Wasmtime upgrade level?~~ - **DECIDED**: Verify 36.0.6 is patched, full upgrade later
3. ~~Remove unused deps?~~ - **DECIDED**: Remove bincode, complete PEM migration
