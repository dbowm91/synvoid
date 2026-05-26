# Configuration System Architecture Review

**Review Date**: 2026-05-26
**Reviewer**: AI Code Review
**Document Reviewed**: `architecture/config_deep_dive.md`
**Codebase**: `crates/synvoid-config/`

---

## Stale Items Identified

### 1. ConfigManager Line Numbers Incorrect
- **Document**: `lib.rs | ConfigManager at lines 113-233`
- **Actual**: ConfigManager struct at lines 113-119, impl block at lines 121-241
- **Issue**: Line range 113-233 is incomplete; full impl block ends at line 241

### 2. Configuration Hierarchy - Field Type Mismatches
The document uses inconsistent naming for aliased types:

| Document Field | Document Type | Actual Type | Location |
|---------------|---------------|-------------|----------|
| `ip_feeds` | `IpFeedConfig` | `MainIpFeedConfig` | main_config.rs:51, lib.rs:76 |
| `rule_feed` | `RuleFeedConfig` | `MainRuleFeedConfig` | main_config.rs:52, lib.rs:77 |
| `yara_feed` | `YaraRuleFeedConfig` | `MainYaraRuleFeedConfig` | main_config.rs:53, lib.rs:78 |

### 3. OverseerConfig References Deprecated
- **Document**: Lines 82-83 reference `overseer: OverseerConfig | Legacy process supervisor`
- **Current Architecture**: `OverseerConfig` is still present (process.rs) but Supervisor consolidates its functionality
- **Status**: Mentions "Legacy" but code still exists; architecture has evolved

### 4. Process Hierarchy Not Updated
The document shows `overseer: OverseerConfig` but the current architecture has:
- `Supervisor` - manages master lifecycle, upgrades, health monitoring
- `Master` - spawns/manages workers, handles IPC
- Unified architecture makes separate overseer unnecessary

### 5. Missing `asn_scraping` in DefaultsConfig
- **Document**: Configuration Hierarchy does not mention `asn_scraping: AsnScrapingConfig`
- **Actual**: `DefaultsConfig` has `asn_scraping: AsnScrapingConfig` at defaults.rs:49
- **Status**: Document incomplete

### 6. App Server File Descriptions Slightly Misleading
- **Document**: `site/app_server.rs` - "Granian Python ASGI/RSGI/WSGI server site config"
- **Actual**: `site/app_server.rs` contains `SiteAppServerConfig` with all optional fields
- **Document**: `app_server.rs` - "Resolved AppServerConfig for worker processes"
- **Actual**: This is correct

---

## Claims Verified / Issues Found

### Verified Claims (Accurate)

| Claim | Location | Status |
|-------|----------|--------|
| ConfigManager struct exists | lib.rs:113-119 | VERIFIED |
| load_main() method | lib.rs:132-138 | VERIFIED |
| load_site() method | lib.rs:140-150 | VERIFIED |
| discover_sites() method | lib.rs:152-198 | VERIFIED |
| reload_site() / reload_all() | lib.rs:206-241 | VERIFIED |
| get_site() method | lib.rs:200-204 | VERIFIED |
| Feature-gated modules (dns, icmp-filter, mesh) | lib.rs | VERIFIED |
| TOML + schemars + utoipa serialization | lib.rs | VERIFIED |
| SiteConfig hierarchy (site_id from domains.first()) | site/mod.rs:204-206 | VERIFIED |
| AppServerConfig propagation pattern | site/mod.rs:208-261 | VERIFIED |
| All key files exist | Table in section 1 | VERIFIED |

### Code Issues Found

#### Issue 1: `mesh` Field Access Without Feature Check in MainConfig
**Location**: `main_config.rs:133-134`
```rust
#[cfg(feature = "mesh")]
pub mesh: Option<super::MeshConfig>,
```
**Problem**: If someone uses `config.mesh` without checking `#[cfg(feature = "mesh")]`, code won't compile. This is expected Rust behavior but not documented.

#### Issue 2: Default Admin Token Generation Uses Weak Characters
**Location**: `admin.rs:190-204`
```rust
fn default_admin_token() -> String {
    use rand::Rng;
    let mut rng = rand::rng();
    let token: String = (0..32)
        .map(|_| {
            let idx = rng.random_range(0..36);  // Only 0-9, a-z
            if idx < 10 {
                (b'0' + idx) as char
            } else {
                (b'a' + idx - 10) as char
            }
        })
        .collect();
    token
}
```
**Problem**: Default token only uses lowercase letters and digits. Should include uppercase for stronger randomness. However, token is generated fresh each time if not set, so security impact is minimal.

#### Issue 3: DnsConfig Validation Incomplete
**Location**: `dns/mod.rs:174-205`
```rust
pub fn validate(&self) -> Result<(), DnsConfigError> {
    // ...
    if let DnsMode::Mesh = self.mode {
        self.mesh.validate()?;  // Only validates if mesh mode
    }
    self.anycast.validate()?;
    // Missing: zones.validate(), settings.validate(), etc.
    Ok(())
}
```
**Problem**: Several sub-configs not validated (zones, settings, dnssec, etc.)

---

## Improvement Plan

### High Priority

1. **Update ConfigManager Line Range**
   - Change "lines 113-233" to "lines 113-241" in document
   - No code change needed

2. **Document Feature-Gated Fields**
   - Add `[feature=icmp-filter]`, `[feature=dns]`, `[feature=mesh]` annotations in Configuration Hierarchy
   - Document that `mesh` is `Option<MeshConfig>` when feature enabled

3. **Add Missing asn_scraping Field**
   - Document `asn_scraping: AsnScrapingConfig` in Configuration Hierarchy
   - Add to overview of defaults.rs

### Medium Priority

4. **Unify Type Naming in Document**
   - Either use aliased names (`MainIpFeedConfig`, etc.) consistently
   - Or note that fields use type aliases

5. **Update Process Architecture Description**
   - Replace "overseer: OverseerConfig (Legacy process supervisor)" with current architecture
   - Document Supervisor + Master + UnifiedServerWorker hierarchy

6. **Add DnsConfig Sub-Validation**
   - Add missing `self.zones.validate()?`, `self.settings.validate()?` in dns/mod.rs:203

### Low Priority

7. **Enhance Admin Token Generation**
   - Consider adding uppercase characters to `default_admin_token()`
   - Security impact is minimal since token is generated fresh

8. **Add Cross-Reference to Platform Deep Dive**
   - The process architecture is detailed in `platform_deep_dive.md` - cross-reference from this document

---

## Bug Report

### Minor Bug: DnsConfig validate() Incomplete

**Severity**: Minor
**Location**: `crates/synvoid-config/src/dns/mod.rs:174-205`
**Description**: The `DnsConfig::validate()` method does not call `validate()` on all sub-configurations. Specifically:
- `self.zones.validate()` is never called
- `self.settings.validate()` is not called in all paths (only through error path)
- `self.dnssec.validate()` is not called
- `self.recursive.validate()` is not called
- `self.ratelimit.validate()` is called
- `self.rrl.validate()` is called

**Current Behavior**: Sub-configurations may have validation logic that is never executed.

**Expected Behavior**: All sub-configurations should have their `validate()` methods called.

**Suggested Fix**:
```rust
impl DnsConfig {
    pub fn validate(&self) -> Result<(), DnsConfigError> {
        if self.port == 0 {
            return Err(DnsConfigError::InvalidPort("Port cannot be zero".to_string()));
        }
        // ... existing bind_address validation ...

        self.ratelimit.validate()?;
        self.rrl.validate()?;
        // MISSING: self.settings.validate()? - only called on error path
        self.dnssec.validate()?;  // MISSING

        if let DnsMode::Mesh = self.mode {
            self.mesh.validate()?;
        }

        self.anycast.validate()?;
        self.zones.validate()?;  // MISSING
        self.recursive.validate()?;  // MISSING

        Ok(())
    }
}
```

---

## Summary

| Category | Count |
|----------|-------|
| Stale Items | 6 |
| Verified Claims | 12 |
| Code Bugs | 1 (minor) |
| High Priority Improvements | 3 |
| Medium Priority Improvements | 3 |
| Low Priority Improvements | 2 |
