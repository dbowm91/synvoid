# MaluWAF Web App Stack Improvement Plan

**Last updated**: 2026-04-23
**Status**: 📋 PENDING IMPLEMENTATION

## Overview

This document details improvements for the MaluWAF built-in web app stack backends: static files, PHP-FPM, FastCGI, WASM/Serverless, and Granian (Python). The plan addresses security vulnerabilities and pool management gaps identified during a comprehensive code review.

**Total improvement items**: 6
**Priority**: Security → Pool Management → Feature Enhancements

---

## Architecture Overview

### Current Implementation Status

| Backend Type | Location | Status | Maturity |
|--------------|----------|--------|----------|
| Static Files + Directory Viewer | `src/static_files/` | ✅ Implemented with security issue | 90% |
| PHP-FPM | `src/php/mod.rs` | ✅ Implemented - PM config unused | 60% |
| FastCGI | `src/fastcgi/mod.rs` | ✅ Implemented | 75% |
| WASM/Serverless | `src/serverless/` | ✅ Implemented | 85% |
| Granian (Python) | `src/app_server/granian.rs` | ✅ Implemented | 80% |

---

## Phase 1: Security Fixes (CRITICAL)

### Item 1: Custom Template Path Traversal Vulnerability

**Severity**: CRITICAL (CVE-worthy)
**Impact**: An attacker can read arbitrary files on the server by specifying template path as `/etc/passwd` or other sensitive files
**Location**: `src/static_files/directory.rs:30-37`

#### Problem Description

The `load_directory_template()` function reads custom template paths **without validating they're within allowed directories**:

```rust
// src/static_files/directory.rs:30-37
pub fn load_directory_template(template_path: &str) -> Result<String, super::StaticError> {
    fs::read_to_string(template_path).map_err(|e| {
        super::StaticError::Internal(format!(
            "Failed to load directory template from {}: {}",
            template_path, e
        ))
    })
}
```

This function is called from `src/static_files/mod.rs:775` when a custom `directory_template_path` is configured:

```rust
// src/static_files/mod.rs:773-777
let body = if let Some(template_path) = effective_template_path.as_deref() {
    if format == "html" {
        let template = directory::load_directory_template(template_path)?;
        // ...
    }
}
```

**Security Impact**: If a site operator mistakenly or maliciously configures `directory_template_path = "/etc/passwd"`, the server will return the contents of `/etc/passwd` in the HTTP response.

#### Root Cause

- No path validation before reading the template file
- The template path is taken directly from config without checking it's within allowed paths (e.g., in a templates directory)

#### Fix Requirements

1. **Validate template path is within allowed directory**:
   - Create a configurable `template_directory` setting (default: `/etc/maluwaf/templates` or a site-specific path)
   - Use canonical path resolution to prevent `../` bypasses
   - Reject paths that escape the allowed directory

2. **Add request-time validation**:
   - Even after config validation, re-validate at request time using `fs::canonicalize()` + prefix check
   - This prevents symlink-based attacks

3. **Security headers**:
   - Add `X-Content-Type-Options: nosniff` header to directory listings

#### Implementation Steps

```rust
// Suggested fix in src/static_files/directory.rs

const DEFAULT_TEMPLATE_DIR: &str = "/etc/maluwaf/templates";

pub fn load_directory_template(
    template_path: &str,
    allowed_template_dir: Option<&str>,
) -> Result<String, super::StaticError> {
    let template_dir = allowed_template_dir.unwrap_or(DEFAULT_TEMPLATE_DIR);
    
    // Resolve both paths to canonical form
    let canonical_template_dir = std::fs::canonicalize(template_dir)
        .map_err(|e| super::StaticError::Internal(format!(
            "Invalid template directory: {}", e
        )))?;
    
    let canonical_template_path = std::fs::canonicalize(template_path)
        .map_err(|e| super::StaticError::Internal(format!(
            "Invalid template path: {}", e
        )))?;
    
    // Verify template path is within allowed directory
    if !canonical_template_path.starts_with(&canonical_template_dir) {
        return Err(super::StaticError::Forbidden(
            "Template path escapes allowed directory".to_string()
        ));
    }
    
    fs::read_to_string(&canonical_template_path).map_err(|e| {
        super::StaticError::Internal(format!(
            "Failed to load directory template from {}: {}",
            template_path, e
        ))
    })
}
```

#### Testing Requirements

1. Unit test that rejects `/etc/passwd` as template path
2. Unit test that rejects template path with `../` escape
3. Unit test that accepts valid path within allowed directory
4. Unit test that rejects symlink escapes to `/etc/passwd`

---

## Phase 2: Pool Management (HIGH PRIORITY)

### Item 2: PHP-FPM Process Manager Configuration Unused

**Severity**: HIGH
**Impact**: PM configuration fields in config are parsed but never used - PHP-FPM pool is not managed by MaluWAF
**Location**: `src/config/site/backend.rs:77-94`

#### Problem Description

PHP-FPM process management (PM) settings are defined in the config schema but **never passed to PHP-FPM or used by MaluWAF**:

```rust
// src/config/site/backend.rs:77-94
pub struct PhpConfig {
    // ... security settings ...
    
    // PM Configuration - DEFINED BUT NOT USED
    pub pm: Option<String>,              // "static", "dynamic", "ondemand"
    pub pm_max_children: Option<u32>,
    pub pm_start_servers: Option<u32>,
    pub pm_min_spare_servers: Option<u32>,
    pub pm_max_spare_servers: Option<u32>,
    pub pm_max_requests: Option<u32>,
    pub pm_status_path: Option<String>,
    // ...
}
```

The Python/Granian implementation manages its own worker processes, but PHP-FPM is externally managed - MaluWAF acts only as a FastCGI proxy.

#### Industry Best Practice Reference

From recent research (2025-2026):

```
# Best practice PHP-FPM configuration (per-site pool)
[www-api]  # separate pool for each site
listen = /run/php-api.sock
pm = dynamic
pm.max_children = 30-50  # based on RAM / worker RSS
pm.start_servers = 3-5
pm.min_spare_servers = 3
pm.max_spare_servers = 25
pm.max_requests = 500  # prevent memory fragmentation
pm.status_path = /php-fpm-status
```

#### Root Cause

MaluWAF doesn't spawn PHP-FPM pools - it expects an externally managed PHP-FPM pool and proxies requests to it.

#### Fix Options

**Option A**: Document the limitation clearly
- Add documentation that MaluWAF is a FastCGI proxy, not a PHP-FPM pool manager
- PM settings are placeholders for future implementation

**Option B**: Implement PHP-FPM pool management (significant work)
- Spawn PHP-FPM master process with custom configuration
- Manage worker lifecycle (start, stop, scale)
- Implement health checks

**Recommended**: Option A with minor fixes

#### Implementation Steps

1. **Add documentation to config defaults**:
   ```rust
   // In config defaults, add:
   // Note: PHP-FPM pool must be managed externally. 
   // MaluWAF acts as FastCGI proxy only.
   ```

2. **Add pool status reporting**:
   - Query PHP-FPM status endpoint if configured
   - Report pool health in admin UI

3. **Document in site config**:
   - Add user-facing documentation that PM settings require external PHP-FPM management

---

### Item 3: Granian Per-Site Worker Pool

**Severity**: HIGH
**Impact**: No per-site isolation - all Granian sites share a single process management
**Location**: `src/app_server/granian.rs:296-326`

#### Problem Description

Granian is spawned per-site with worker_id, but there's no:
- Per-site worker count tuning
- Per-site health monitoring
- Per-site restart isolation

```rust
// Current implementation spawns one granian per worker_id
// But multiple sites may share the same worker_id in different contexts
```

#### Root Cause

Granian supervisor is created per site but the pool management is at the application level, not site level.

#### Implementation Steps

1. **Add site-scoped GranianSupervisor**:
   - Create a `SiteGranianManager` that holds per-site supervisors
   - Track site health independently

2. **Add worker count per site**:
   ```toml
   [site.app_server]
   workers = 4  # per-site worker tuning
   blocking_threads = 4
   ```

3. **Add site-specific health monitoring**:
   - Track per-site restart counts
   - Track per-site health state

---

## Phase 3: Feature Enhancements (MEDIUM PRIORITY)

### Item 4: Directory Listing Date Filtering

**Severity**: MEDIUM
**Impact**: Users cannot filter files by modification date
**Location**: `src/theme/dir_listing.rs`

#### Problem Description

Current directory listing supports sorting and pagination, but not date filtering.

#### Implementation Steps

1. **Add query parameters**:
   - `before=timestamp` - files modified before
   - `after=timestamp` - files modified after

2. **Update filtering**:
   ```rust
   // In src/static_files/directory.rs
   fn filter_by_date(entries: Vec<DirectoryEntry>, before: Option<u64>, after: Option<u64>) -> Vec<DirectoryEntry> {
       entries.into_iter().filter(|e| {
           if let Some(before_ts) = before {
               if e.modified_timestamp >= before_ts { return false; }
           }
           if let Some(after_ts) = after {
               if e.modified_timestamp <= after_ts { return false; }
           }
           true
       }).collect()
   }
   ```

---

### Item 5: WASM Instance Pre-warming

**Severity**: LOW
**Impact**: Cold starts on WASM functions (already fast at 2-5ms, but can be faster)
**Location**: `src/serverless/instance_pool.rs`

#### Problem Description

WASM cold starts are already fast (2-5ms with wasmtime), but instance pre-warming isn't optimized.

#### Industry Benchmark (2025)

| Platform | Cold Start |
|----------|-------------|
| AWS Lambda | 100-500ms |
| Cloudflare Workers | ~5ms |
| WASM (Wasmtime) | 2-5ms |
| **MaluWAF WASM** | **2-5ms** ✅ |

#### Implementation Steps

1. **Pre-instantiate instances at startup**:
   - Use `pre_warm_instances` config if provided
   - Keep instances warm in pool

2. **Use prepared module caching**:
   - wasmtime supports compiled module caching
   - Enable for faster instantiation

---

### Item 6: FastCGI Connection Health Metrics

**Severity**: LOW
**Impact**: No visibility into FastCGI connection pool health
**Location**: `src/fastcgi/pool.rs`

#### Problem Description

FastCGI pool doesn't expose connection health metrics.

#### Implementation Steps

1. **Add connection metrics**:
   - Active connections count
   - Connection errors count
   - Average response time

2. **Expose via admin API**:
   ```rust
   pub fn get_pool_metrics(&self) -> PoolMetrics {
       PoolMetrics {
           active_connections: self.active.load(Ordering::Relaxed),
           connection_errors: self.errors.load(Ordering::Relaxed),
           avg_response_time_ms: self.response_times.average(),
       }
   }
   ```

---

## Testing Requirements

### Phase 1 Tests

1. **Template path traversal**:
   - Test: `/etc/passwd` should fail
   - Test: `../etc/passwd` should fail
   - Test: symlink to `/etc/passwd` should fail
   - Test: valid path `/etc/maluwaf/templates/custom.html` should succeed

### Phase 2 Tests

2. **PHP-FPM**:
   - Test: Verify PM settings produce warning about external management

3. **Granian**:
   - Test: Verify per-site restart isolation

### Phase 3 Tests

4. **Date filtering**:
   - Test: Filter files modified today
   - Test: Filter files modified in last week

---

## Files to Modify

| Phase | File | Changes |
|-------|------|---------|
| 1 | `src/static_files/directory.rs` | Add path validation |
| 1 | `src/static_files/mod.rs` | Pass allowed template dir |
| 2 | `src/php/mod.rs` | Add PM warning/documentation |
| 2 | `src/app_server/granian.rs` | Add site-scoped management |
| 3 | `src/static_files/directory.rs` | Add date filtering |
| 3 | `src/fastcgi/pool.rs` | Add metrics |

---

## Risk Assessment

| Item | Risk | Mitigation |
|------|------|------------|
| Template path fix | Low - clear fix | Add comprehensive tests |
| PHP-FPM PM | Low - documentation | Document clearly |
| Granian site isolation | Medium - new code | Test per-site isolation |
| Date filtering | Low - clear addition | Test edge cases |

---

## Success Criteria

### Phase 1 (Security)

- [ ] Template path traversal vulnerability fixed
- [ ] All path traversal tests pass
- [ ] No bypass via symlinks

### Phase 2 (Pool Management)

- [ ] PHP-FPM documentation added
- [ ] Granian per-site isolation implemented

### Phase 3 (Enhancements)

- [ ] Date filtering works for directory listings
- [ ] FastCGI pool metrics visible in admin UI

---

## Timeline Estimate

| Phase | Effort | Notes |
|-------|--------|-------|
| Phase 1 | 2-4 hours | Security fix - straightforward |
| Phase 2 | 4-8 hours | Documentation + minor code |
| Phase 3 | 6-12 hours | Feature additions |

---

## Related Documentation

- Admin API docs at `/api/docs`
- Site configuration in `src/config/site/`
- Theme system in `src/theme/`