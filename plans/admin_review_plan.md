# Admin API Architecture Review Plan

## Review Date: 2026-05-26
## Document: architecture/admin_deep_dive.md

---

## Stale Items Identified

### 1. Overseer References (Deprecated)
**Location in doc**: Lines 231, 753
**Issue**: References to `/system/overseer` endpoint as if Overseer is a separate process
**Current state**: SynVoid has consolidated Overseer functionality into Supervisor. The admin API still shows `/system/overseer` endpoint but the architecture now uses "Supervisor" as the single master process managing lifecycle.
**Recommendation**: Update architecture doc to replace "Overseer" with "Supervisor" terminology.

### 2. Line Number References for AdminState Structure
**Location in doc**: Line 259
**Claimed**: `src/admin/state.rs:254-264`
**Actual**: `src/admin/state.rs:257-267`
**Impact**: Minor - cosmetic discrepancy

### 3. Config Version Limit Mismatch
**Location in doc**: Line 387 (in Audit Logging section)
**Claimed**: "Stores up to 100 config versions"
**Actual**: In `src/admin/audit.rs:11`, `MAX_CONFIG_VERSIONS: usize = 100` - this is CORRECT for ConfigVersionManager, but the document's context suggests audit logs. The document incorrectly implies audit logs are limited to 100 entries.
**Correction needed**: Clarify that `audit.log` stores up to 10,000 entries (`MAX_AUDIT_LOGS` at line 10) while config versions are limited to 100.

### 4. Handler Count Inaccuracy
**Location in doc**: Line 179
**Claimed**: "28 handlers"
**Actual**: `src/admin/handlers/mod.rs` contains:
- 26 unconditional handlers
- 3 feature-gated (mesh): `behavioral_intel`, `mesh_admin`, `mesh_topology`, `yara_rules`
- Total: 26-30 depending on feature flags
**Impact**: Documentation undercounts the actual handlers.

---

## Claims Verified / Issues Found

### Authentication System

| Claim | Location in Doc | Actual Location | Status |
|-------|-----------------|-----------------|--------|
| Admin token hashing/verification | `src/admin/auth.rs:16-26` | `src/admin/auth.rs:16-26` | VERIFIED |
| AuthManager struct | `src/auth/mod.rs:91-103` | `src/auth/mod.rs:91-103` | VERIFIED |
| Session creation | `src/admin/state.rs:788-820` | `src/admin/state.rs:796-828` | VERIFIED (close) |
| CSRF validation | `src/admin/state.rs:725-741` | `src/admin/state.rs:728-748` | VERIFIED (close) |
| CSRF middleware | `src/admin/middleware.rs:185-266` | `src/admin/middleware.rs:185-266` | VERIFIED |
| YaraRateLimiter | `src/admin/state.rs:86-143` | `src/admin/state.rs:89-147` | VERIFIED |
| Auth rate limiter constants | `src/admin/auth.rs:6-8` | `src/admin/auth.rs:6-8` | VERIFIED |

### Security Features

| Feature | Document Claim | Code Implementation | Status |
|---------|---------------|-------------------|--------|
| Session cookie name | `synvoid_session` | `state.rs:6` SESSION_COOKIE_NAME | VERIFIED |
| Session TTL | 3600 seconds (1 hour) | `state.rs:318` SESSION_TTL_SECS = 3600 | VERIFIED |
| Max CSRF tokens per session | 10 | `state.rs:314` MAX_CSRF_TOKENS_PER_SESSION = 10 | VERIFIED |
| Admin brute-force attempts | 5 per 60s window | `auth.rs:6` MAX_AUTH_ATTEMPTS = 5 | VERIFIED |
| Auth lockout duration | 300 seconds | `auth.rs:7` AUTH_LOCKOUT_DURATION = 300s | VERIFIED |
| YARA submit rate limit | 10/minute | `state.rs:119` submit_limiter: 10 | VERIFIED |
| YARA broadcast_apply | 5/minute | `state.rs:119` broadcast_apply_limiter: 5 | VERIFIED |
| YARA approve_reject | 10/minute | `state.rs:119` approve_reject_limiter: 10 | VERIFIED |
| YARA status_list | 30/minute | `state.rs:119` status_list_limiter: 30 | VERIFIED |
| Constant-time CSRF comparison | Uses `subtle::ConstantTimeEq` | `state.rs:23` imported, `state.rs:737-741` used | VERIFIED |
| Dummy password timing | Prevents username enumeration | `auth.rs:14-22`, `auth/mod.rs:26-34` | VERIFIED |

### File Permissions (Security Critical)

| Item | Document Claim | Code Implementation | Status |
|------|---------------|-------------------|--------|
| Auth store directory | 0o700 | `auth/mod.rs:201` | VERIFIED |
| Auth store file | 0o600 | `auth/mod.rs:210` | VERIFIED |
| Audit log file | 0o600 | `audit.rs:78,136` | VERIFIED |

### SSRF Protection

| Claim | Implementation | Status |
|-------|---------------|--------|
| Block localhost | `alerting/mod.rs:146` | VERIFIED |
| Block 127.x.x.x | `alerting/mod.rs:147` | VERIFIED |
| Block 10.x.x.x | `alerting/mod.rs:148` | VERIFIED |
| Block 192.168.x.x | `alerting/mod.rs:149` | VERIFIED |
| Block 172.x.x.x | `alerting/mod.rs:150` | VERIFIED |

### Alerting System

| Claim | Implementation | Status |
|-------|---------------|--------|
| Supported metrics in document | `error_rate_percent`, `requests_per_second`, `blocked_per_second`, `time_validation_errors`, `unhealthy_backends`, `unhealthy_workers`, `threat_level`, `audit_write_failures` | `alerting/mod.rs:5-14` | VERIFIED |
| Alert conditions | `GreaterThan`, `LessThan`, `Equals` | `alerting/mod.rs:80-85` | VERIFIED |

---

## Improvement Plan

### High Priority

1. **Update Overseer References to Supervisor**
   - Files to update: `architecture/admin_deep_dive.md`
   - Change: Replace all "Overseer" references with "Supervisor"
   - Rationale: Architecture has evolved - Overseer is now Supervisor

2. **Clarify Config Version vs Audit Log Limits**
   - Location: `architecture/admin_deep_dive.md` line ~387
   - Issue: Document says "Stores up to 100 config versions" which is true for ConfigVersionManager
   - But the context implies audit.log limit is 100 when it's actually 10,000
   - Fix: Add explicit note that audit.log has separate limit of 10,000 entries

### Medium Priority

3. **Update Handler Count**
   - Location: `architecture/admin_deep_dive.md` line 179
   - Change: "28 handlers" -> "26+ handlers (up to 30 with mesh feature)"
   - Rationale: Accurate count reflects actual implementation

4. **Fix Line Number References**
   - Location: `architecture/admin_deep_dive.md` line 259
   - Change: `src/admin/state.rs:254-264` -> `src/admin/state.rs:257-267`
   - Rationale: Minor but reduces confusion during code reviews

5. **Add Mesh Feature Gate Notes**
   - Location: Throughout document where mesh-specific handlers are mentioned
   - Change: Add footnotes or notes indicating which handlers are feature-gated
   - Rationale: Helps readers understand which features require `--features mesh`

### Low Priority

6. **Add OpenAPI Specification Note**
   - Location: `architecture/admin_deep_dive.md` around line 374
   - Change: Note that OpenAPI spec is self-documenting via `/api/openapi.json`
   - Rationale: Improves discoverability for API consumers

---

## Bug Report

### Minor: Email Alert Implementation Incomplete

**Location**: `src/admin/alerting/mod.rs:348-373`

**Issue**: The `send_email_internal` function accepts email configuration (SMTP host, port, username, password, recipients) but only logs that it's sending email - it doesn't actually implement SMTP sending.

```rust
async fn send_email_internal(
    config: (
        Vec<String>,
        Option<String>,
        Option<u16>,
        Option<String>,
        Option<String>,
    ),
    event: &AlertEvent,
) -> Result<(), String> {
    let (recipients, smtp_host, smtp_port, username, password) = config;

    let _smtp_host = smtp_host.ok_or("SMTP host not configured")?;
    // ... extracts all config ...

    tracing::info!(
        "Sending email alert to {} recipients about: {}",
        recipients.len(),
        event.rule_name
    );

    Ok(())  // <-- Returns success without actually sending email!
}
```

**Impact**: Email alerting is configured but non-functional. Webhook alerting works correctly.

**Recommendation**: Either:
1. Implement actual SMTP sending using a crate like `lettre`
2. Document that email alerting is a planned feature
3. Remove email alerting configuration UI until implemented

---

## Summary

The admin API architecture document is **largely accurate** with only minor discrepancies:
- Most security patterns are correctly documented and implemented
- CSRF protection, rate limiting, session management all match the code
- SSRF protection is properly implemented for webhook URLs
- One implementation gap: email alerting is stubbed but not functional

The main improvement needed is updating deprecated Overseer references and clarifying the dual limits for audit logs (10,000) vs config versions (100).
