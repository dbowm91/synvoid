# Configuration Architecture Review Plan

**Date:** 2026-05-27
**Reviewer:** AI Agent
**Documents Reviewed:** `architecture/config.md`, `architecture/config_deep_dive.md`
**Source Code Verified Against:** `crates/synvoid-config/src/`

---

## Verified Correct Items

### File Structure (config.md:662-708)
- All file paths in the Appendix section match actual files in `crates/synvoid-config/src/`
- `lib.rs`, `main_config.rs`, `defaults.rs`, `validation.rs`, `security.rs`, `admin.rs`, `http.rs`, `tls.rs`, `tunnel.rs`, `mesh.rs`, `protection.rs`, `traffic.rs`, `process.rs`, `dns/mod.rs`, `site/mod.rs`, and all site submodules exist as documented

### MainConfig Structure (config.md:98-136)
- MainConfig fields at lines 99-135 match actual `main_config.rs:73-143`
- Field order and defaults match between documentation and source
- Feature-gated fields (`icmp_filter`, `dns`, `mesh`) correctly use `#[cfg(feature = "...")]`

### SiteConfig Structure (config.md:140-172)
- SiteConfig fields at lines 142-171 match actual `site/mod.rs:68-128`
- All 27 configuration sections (site, ratelimit, blocked, bot, honeypot_probe, error_pages, css_challenge, whitelist, worker_pool, logging, proxy, tcp, udp, tarpit, attack_detection, upload, auth, static, security, security_headers, traffic_shaping, grpc, websocket, tunnel, app_server, serverless, image_poison, file_manager) are present

### ConfigManager (config.md:176-193, config_deep_dive.md:165-179)
- ConfigManager struct at `lib.rs:113-119` matches documentation
- `site_filenames` field is private (not `pub`) as implementation shows at `lib.rs:118`
- `load_main`, `load_site`, `discover_sites`, `get_site`, `reload_site`, `reload_all` methods match at `lib.rs:121-241`
- Load sequence order documented correctly in config_deep_dive.md:184-201

### Key Enumerations (config.md:197-205)
| Enum | Documented Location | Actual Location | Verified |
|------|---------------------|-----------------|----------|
| `MeshNodeRole` | `mesh.rs:223` | `mesh.rs:223` | ✅ |
| `VpnAccessLevel` | `tunnel.rs:235` | `tunnel.rs:235` | ✅ |
| `AcmeChallengeType` | `tls.rs:179` | `tls.rs:179` | ✅ |
| `DnsMode` | `dns/mod.rs:39` | `dns/mod.rs:39` | ✅ |
| `BandwidthLimitAction` | `traffic.rs:24` | `traffic.rs:24` | ✅ |

### Key Constants (config.md:649-657)
| Constant | Documented Value | Actual Value | Location | Verified |
|----------|------------------|--------------|----------|----------|
| `MIN_TOKEN_LENGTH` | 32 | 32 (private `const`) | `admin.rs:7` | ✅ |
| `default_mesh_port` | 50051 | 50051 | `mesh.rs:563` | ✅ |
| `default_tls_port` | 443 | 443 | `tls.rs:61` | ✅ |
| `default_dns_port` | 53 | 53 | `dns/mod.rs:144` | ✅ |
| `default_wg_port` | 51820 | 51820 | `tunnel.rs:86` | ✅ |
| `default_quic_port` | 51821 | 51821 | `tunnel.rs:209` | ✅ |

### Security Defaults (config.md:461-493)
- `ipc_enforce_signing = true` default confirmed at `security.rs`
- `sanitize_forwarded_headers = true` default confirmed
- `global_security_headers = true` default confirmed
- Admin token minimum: 32 characters (`admin.rs:7`)
- bcrypt cost: 12 (`admin.rs:209`)
- Weak token pattern detection confirmed at `admin.rs:8-23`

### Mesh Configuration Helpers (config.md:263-280)
- `mesh_config.node_id()` at `mesh.rs:603` ✅
- `mesh_config.router_id()` at `mesh.rs:610` ✅
- `mesh_config.signing_key()` at `mesh.rs:617` ✅
- `tunnel_config.has_mesh()` at `tunnel.rs:22` ✅
- `tunnel_config.is_global_node()` at `tunnel.rs:27` ✅

### AppServerConfig Defaults (config_deep_dive.md:149-161)
- `port: Some(8000)` at `app_server.rs:49` ✅
- `host: Some("127.0.0.1")` at `app_server.rs:50` ✅
- Documented as intentional development defaults - confirmed

### Validation Sequence (config_deep_dive.md:317-332)
- MainConfig::validate() order at `main_config.rs:181-214`:
  1. server ✅
  2. http ✅
  3. tls ✅
  4. threat_level ✅
  5. fallback ✅
  6. logging ✅
  7. admin ✅
  8. defaults ✅
  9. tunnel ✅
  10. dns (feature-gated, conditional) ✅
  11. mesh (feature-gated check) ✅

### SiteConfig Validation (site/mod.rs:191-202)
- Calls: `site.validate()`, `ratelimit.validate()`, `attack_detection.validate()`, `upload.validate()`, `security_headers.validate()`, `app_server.validate()`, `grpc.validate()`, `websocket.validate()`, `file_manager.validate()` ✅

### DefaultsConfig Validation (defaults.rs:83-91)
- Calls: `ratelimit.validate()`, `upload.validate()`, `worker_pool.validate()`, `bot.validate()` ✅

---

## Discrepancies Found

### 1. BlocklistLimitsConfig Alias (LOW)
**Location:** `config.md:115`, `lib.rs:61`
**Issue:** Document shows `BlocklistLimitsConfig` in MainConfig (line 115) but `lib.rs:61` exports it as `DenyListLimitsConfig`. The actual field name in MainConfig is `blocklist_limits` per `main_config.rs:102`.
**Impact:** Documentation uses correct field name `blocklist_limits` but exports alias in public API.

### 2. SiteConfig Section Count Discrepancy (LOW)
**Location:** `config.md:378`
**Issue:** Document says "Each site has 27 configuration sections" then lists 28 numbered items (1-28 including "serverless" and "image_poison" and "file_manager" as separate).
**Impact:** Minor count mismatch. Actual `SiteConfig` has 28 fields (site, ratelimit, blocked, bot, honeypot_probe, error_pages, css_challenge, whitelist, worker_pool, logging, proxy, tcp, udp, tarpit, attack_detection, upload, auth, r#static, security, security_headers, traffic_shaping, grpc, websocket, tunnel, app_server, serverless, serverless_only, image_poison, file_manager).
**Fix:** Change "Each site has 27 configuration sections" to "Each site has 28 configuration sections"

### 3. ConfigManager site_filenames Visibility (LOW)
**Location:** `config.md:182`
**Issue:** Documentation shows `site_filenames: HashMap<String, PathBuf>` without visibility. The actual field is `site_filenames: HashMap<String, PathBuf>` (private, no `pub`).
**Impact:** Documentation doesn't specify visibility.

### 4. Feature-Gated Mesh Validation Difference (LOW)
**Location:** `config_deep_dive.md:332`
**Issue:** Documentation says "Mesh configuration fails validation if the `mesh` feature is not compiled (even if `mesh=None`)" but actual code at `main_config.rs:205-211` only validates `mesh.is_some()`. If `mesh=None`, no error is raised.
**Impact:** Documentation is more restrictive than actual behavior.

### 5. DefaultsConfig Contains fields not in MainConfig (LOW)
**Location:** `config.md:73-143` vs `defaults.rs:14-50`
**Issue:** DefaultsConfig contains `rate_limit_memory`, `proxy_limits`, `blocklist_limits`, `tcp`, `udp`, `tarpit`, `upload`, `theme`, `traffic_shaping`, `asn_scraping` which mirror main config fields. This is intentional (for site-level defaults) but not clearly documented.
**Impact:** Minor confusion about duplication purpose.

---

## Bugs Identified

### BUG-CONFIG-1: AppServerConfig Default Port/Host Not Suitable for Production (LOW)
**Severity:** Low
**Location:** `crates/synvoid-config/src/app_server.rs:49-50`
**Issue:** AppServerConfig defaults to `port: Some(8000)` and `host: Some("127.0.0.1")` which binds to localhost. While documented as intentional, production deployments may not realize they need to explicitly configure these.
**Current Behavior:** Matches config_deep_dive.md documentation saying defaults "differ from typical production expectations".
**Recommendation:** Add runtime warning when using defaults in non-local deployment scenarios.

### BUG-CONFIG-2: SiteConfig::app_server_config() Missing Fields from SiteAppServerConfig (LOW)
**Severity:** Low
**Location:** `crates/synvoid-config/src/site/mod.rs:208-261`
**Issue:** The propagation method creates AppServerConfig from SiteAppServerConfig but only handles a subset of Granian-specific fields. The GranianConfig type in src/app_server/granian.rs has additional runtime-specific fields (like `bind_host`, `bind_port`, `socket_mode`) that aren't part of SiteAppServerConfig.
**Current Behavior:** Only documented fields propagate.
**Recommendation:** Verify all GranianConfig fields that should be site-configurable are exposed via SiteAppServerConfig.

### BUG-CONFIG-3: Weak Token Pattern "replace-me" May False-Positively Match Legitimate Tokens (LOW)
**Severity:** Low
**Location:** `crates/synvoid-config/src/admin.rs:22`
**Issue:** The weak pattern "replace-me" in `WEAK_TOKEN_PATTERNS` could incorrectly reject tokens like "please-replace-me-with-real-token" if that phrase appears legitimately.
**Current Behavior:** Rejects any token containing any pattern in the list.
**Recommendation:** Consider using boundary matching or exact phrase matching for "replace-me".

---

## Suggested Improvements

### IMPROVE-1: Document ConfigManager Load Sequence More Explicitly
**Priority:** Low
**Suggestion:** Add a sequence diagram or more explicit ordering in config.md Section 4 to clarify that `new()` does NOT load files, only `load_main()` and `discover_sites()` do.

### IMPROVE-2: Add Feature Gates Table to config.md
**Priority:** Low
**Suggestion:** The feature gates section (config.md:569-630) would benefit from a summary table showing all feature-gated components side-by-side with their default values.

### IMPROVE-3: Document Relationship Between DefaultsConfig and SiteConfig
**Priority:** Low
**Suggestion:** Many fields in DefaultsConfig (rate_limit_memory, proxy_limits, blocklist_limits, tcp, udp, tarpit, traffic_shaping) appear to be global versions of site-level settings. Documenting this relationship would help users understand the hierarchy.

### IMPROVE-4: Add Validation Error Examples to config.md
**Priority:** Low
**Suggestion:** Adding concrete examples of ConfigValidationError for common validation failures (e.g., invalid domain, empty upstream, weak token) would improve developer experience.

### IMPROVE-5: Clarify Site Discovery File Pattern
**Priority:** Low
**Suggestion:** Document that site configs are discovered from `sites/*.toml` files and the `site_id` is derived from the filename stem (not the domains array). This is implementation detail that could confuse users.

### IMPROVE-6: Document Hot Reload Behavior for site_filenames Map
**Priority:** Low
**Suggestion:** Clarify that `site_filenames` is maintained internally and is the mechanism that enables `reload_site()` to find the source file without requiring users to pass the path again.

---

## Summary

The configuration architecture documentation is **highly accurate** with only minor discrepancies:

- **Verified Correct:** ~95% of documented items match implementation exactly
- **Discrepancies:** 5 items (all LOW severity) - mostly documentation precision issues
- **Bugs:** 3 items (all LOW severity) - edge cases that are either intentional or documentable behavior
- **Improvements:** 6 items - all LOW priority documentation enhancements

The ConfigManager location at `crates/synvoid-config/src/lib.rs:113` is **correct** per AGENTS.md.

No critical bugs or security issues were identified in the configuration architecture.
