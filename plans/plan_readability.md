# Readability & Deduplication Plan

This document outlines the refactoring opportunities identified during codebase review to improve readability, reduce verbosity, and eliminate code duplication.

**Last Updated:** March 2026  
**Status:** Not Started

---

## High-Impact (7+ instances or ~40+ LOC each)

### 1. WAF: IP Blocking with Threat Intel Pattern
**Files:** `src/waf/mod.rs`  
**Locations:** Lines 757-770, 792-802, 875-885, 891-901, 935-945, 951-961, 1059-1072 (7 instances)

**Note:** Two variants exist:
- Variant A: Uses `get_threat_intel()` function call (lines 760, 878, 938)
- Variant B: Uses `self.threat_intel` field (lines 795, 894, 954)

Both variants follow the same structure but differ in threat intel source. The helper should handle both.

**Issue:** The exact same 4-6 line pattern appears 7 times:
```rust
if let Some(ref store) = self.block_store {
    store.block_ip(client_ip, "reason", duration, "global");
}
if let Some(ref threat_intel) = get_threat_intel() {
    threat_intel.announce_local_block(client_ip, "reason".to_string(), duration, "global".to_string());
}
```

**Refactor:** Add helper method to `WafCore`:
```rust
fn block_ip_with_threat_intel(&self, client_ip: IpAddr, reason: &str, duration: u64) {
    if let Some(ref store) = self.block_store {
        store.block_ip(client_ip, reason, duration, "global");
    }
    if let Some(ref ti) = self.threat_intel.or_else(get_threat_intel) {
        ti.announce_local_block(client_ip, reason.to_string(), duration, "global".to_string());
    }
}
```

**Estimated Reduction:** ~40 LOC

---

### 2. DNS DNSSEC: DNSKEY RDATA Construction
**Files:** `src/dns/dnssec.rs`  
**Locations:** Lines 176-181, 210-218, 919-928, 931-941 (4 instances)

**Issue:** Four separate functions build identical DNSKEY RDATA format `[flags(2)][protocol(1)][algorithm(1)][public_key]`:
- `generate_cds_record()` lines 176-181
- `generate_cdnskey_record()` lines 210-218
- `compute_dnskey()` lines 919-928
- `get_dnskey_record()` lines 931-941

**Refactor:** Extract to helper function:
```rust
fn build_dnskey_rdata(flags: u16, algorithm: u8, public_key: &[u8]) -> Vec<u8> {
    let mut rdata = Vec::with_capacity(4 + public_key.len());
    rdata.extend_from_slice(&flags.to_be_bytes());
    rdata.push(3); // Protocol always 3 for DNSSEC
    rdata.push(algorithm);
    rdata.extend_from_slice(public_key);
    rdata
}
```

**Estimated Reduction:** ~20 LOC

---

### 3. Config: Duplicate `default_true()` Functions
**Files:** Multiple files (7 instances)

| File | Line | Return Type |
|------|------|-------------|
| `src/config/site.rs` | 13 | `Option<bool>` |
| `src/config/dns.rs` | 884 | `bool` |
| `src/config/defaults.rs` | 345 | `bool` |
| `src/config/process.rs` | 292 | `bool` |
| `src/mesh/config.rs` | 816 | `bool` |
| `src/waf/attack_detection/config.rs` | 3 | `bool` |
| `src/integrity/config.rs` | 82 | `bool` |

**Issue:** 7 identical function definitions across the codebase.

**Refactor:** Keep one canonical version in `src/config/defaults.rs`, remove others and import.

**Estimated Reduction:** ~14 LOC (7 × 2 lines each)

---

## Medium-Impact (2-6 instances, ~30-55 LOC each)

### 4. WAF: check_honeypot Duplicate Blocks
**Files:** `src/waf/mod.rs`  
**Locations:** Lines 848-901, 908-961

**Issue:** Two nearly identical ~55 line blocks for:
- Sensitive endpoint honeypot (lines 848-901)
- IP-bound honeypot (lines 908-961)

Both contain identical probe tracking logic, threat level checking, auto-ban logic, and IP blocking.

**Refactor:** Extract common probe-handling logic:
```rust
fn handle_probe_event(&self, client_ip: IpAddr, endpoint: String, method: String, user_agent: Option<String>) {
    // Common logic from both blocks
}
```

**Estimated Reduction:** ~55 LOC

---

### 5. Process Manager: Duplicate Restart Logic
**Files:** `src/process/manager.rs`  
**Locations:** Lines 1108-1145 vs 1147-1211

**Correction:** Upon detailed review, these functions are actually quite different:
- `handle_failure_restarts()`: Handles regular worker failures with exponential backoff
- `handle_unified_worker_restart()`: Handles UnifiedServerWorker specifically with resize detection

**Issue:** Both share common patterns (restart count, backoff calculation, max attempts check) but are structurally different enough that extraction would add complexity rather than reduce it.

**Recommendation:** Lower priority - skip or mark as "needs deeper analysis"

---

### 6. DNS DNSSEC: NSEC Type Bitmap Building
**Files:** `src/dns/dnssec.rs`  
**Locations:** Lines 1065-1095 (`create_nsec_record`) vs 1353-1383 (`create_nsec3_record`)

**Issue:** Identical window/block encoding algorithm appears twice - only the target vector name differs.

**Refactor:** Extract to helper:
```rust
fn build_type_bitmap(type_bitmap: &[u16]) -> Vec<u8> {
    let mut window_blocks = Vec::new();
    let mut current_window: u8 = 0;
    let mut block_bits = Vec::new();
    // ... identical logic
}
```

**Estimated Reduction:** ~30 LOC

---

### 7. WAF: Violation Tracking Pattern
**Files:** `src/waf/mod.rs`  
**Locations:** Lines 746-774 (in `check_rate_limit`) vs 1047-1079 (in `check_attack_patterns`)

**Issue:** Both implement identical escalation logic:
1. Record violation
2. Check against threshold
3. Calculate ban duration
4. Block IP + announce
5. Clear violations

**Refactor:** Extract to helper:
```rust
fn maybe_escalate_and_block(&self, client_ip: IpAddr, violation_type: &str) -> Option<WafDecision>
```

**Estimated Reduction:** ~30 LOC

---

### 8. Process Manager: Heartbeat Handling
**Files:** `src/process/manager.rs`  
**Locations:** Lines 665-688, 808-820, 884-905

**Issue:** Three handler functions with similar patterns:
- `handle_unified_server_worker_heartbeat()` - Updates heartbeat, transitions Starting→Ready, sends event
- `handle_static_worker_heartbeat()` - Updates heartbeat, transitions Starting→Ready, stores cache stats (no event)
- `handle_heartbeat()` - Updates heartbeat, transitions Starting→Ready, sends event

**Note:** While similar, the three handlers have subtle differences (event sending, cache stats) making extraction complex. Mark as lower priority.

**Estimated Reduction:** ~20 LOC (if extracted)

---

### 9. Config: Verbose Option<bool> Pattern
**Files:** `src/config/site.rs`, `src/config/dns.rs`  
**Locations:** Throughout both files

**Issue:** Extensive use of `Option<bool>` where default is always `Some(true)` or `Some(false)`:
- `site.rs:1160-1162`: `fn default_attack_detection_enabled() -> Option<bool> { Some(true) }`
- Many similar patterns throughout

**Refactor:** Use `T` with explicit defaults instead of `Option<T>` for boolean fields.

**Estimated Reduction:** ~80 LOC

---

## Low-Impact / Readability (1-2 instances, ~5-15 LOC each)

### 10. WAF: TestModeConfig::disabled_count() Verbosity
**Files:** `src/waf/mod.rs`  
**Location:** Lines 194-202

**Current:**
```rust
pub fn disabled_count(&self) -> usize {
    let mut count = 0;
    if self.ratelimit_off { count += 1; }
    if self.attack_off { count += 1; }
    if self.bot_off { count += 1; }
    if self.challenge_off { count += 1; }
    if self.flood_off { count += 1; }
    count
}
```

**Refactor (1-liner):**
```rust
pub fn disabled_count(&self) -> usize {
    [self.ratelimit_off, self.attack_off, self.bot_off, self.challenge_off, self.flood_off]
        .into_iter()
        .filter(|&&x| x)
        .count()
}
```

**Estimated Reduction:** ~6 LOC

---

### 11. Process: Simple Getter Verbosity
**Files:** `src/process/manager.rs`  
**Locations:** Multiple (lines 327-334, 340-346, 702-705, 829-832, 862-865)

**Issue:** Many one-liner getters follow the same pattern:
```rust
pub fn get_X(&self) -> Option<T> {
    *self.X.read()
}
```

**Refactor:** Use a macro:
```rust
macro_rules! simple_getter {
    ($name:ident, $field:ident, $ty:ty) => {
        pub fn $name(&self) -> $ty { *$field.read() }
    };
}
```

**Estimated Reduction:** ~15 LOC

---

### 12. Config: Duplicate Error Types
**Files:** `src/config/site.rs`, `src/config/dns.rs`  
**Locations:** Lines 1044-1056, 1289-1318

**Issue:** Nearly identical error patterns:
- `SiteConfigValidationError` with Display/Error
- `DnsConfigError` enum with Display/Error

**Refactor:** Create generic `ConfigValidationError` in shared module.

**Estimated Reduction:** ~60 LOC

---

## Summary Table

| # | Item | Files | Est. Reduction | Priority |
|---|------|-------|----------------|----------|
| 1 | WAF IP blocking pattern | waf/mod.rs | ~40 LOC | P0 |
| 2 | DNS DNSSEC DNSKEY builder | dns/dnssec.rs | ~20 LOC | P1 |
| 3 | Config default_true() | 7 files | ~14 LOC | P1 |
| 4 | WAF check_honeypot dedup | waf/mod.rs | ~55 LOC | P2 |
| 5 | ~~Process restart logic~~ | ~~process/manager.rs~~ | ~~30 LOC~~ | ~~skipped~~ |
| 6 | DNS NSEC type bitmap | dns/dnssec.rs | ~30 LOC | P2 |
| 7 | WAF violation escalation | waf/mod.rs | ~30 LOC | P2 |
| 8 | ~~Process heartbeat~~ | ~~process/manager.rs~~ | ~~20 LOC~~ | ~~skipped~~ |
| 9 | Config Option<bool> | config/*.rs | ~80 LOC | P3 |
| 10 | WAF disabled_count | waf/mod.rs | ~6 LOC | P3 |
| 11 | ~~Process getters~~ | ~~process/manager.rs~~ | ~~15 LOC~~ | ~~skipped~~ |
| 12 | Config errors | config/*.rs | ~60 LOC | P3 |

---

## Total Estimated Reduction

**~275+ lines** (adjusted: items 5, 8, 11 were overestimated)

---

## Implementation Order

1. Item #1 (WAF IP blocking) - Highest instance count, immediate value
2. Item #2 (DNSKEY builder) - Straightforward extraction
3. Item #3 (default_true) - Simple deletion and import change
4. Item #10 (disabled_count) - Quick win, low risk
5. Item #6 (NSEC type bitmap) - Straightforward extraction
6. Item #4 (check_honeypot) - Medium complexity, significant value
7. Item #7 (violation escalation) - Similar to #4
8. Item #9, #12 - Larger refactors, lower priority

---

## Notes

- All refactoring should maintain existing behavior
- Run `cargo test --test integration_test` after each change
- Run `cargo clippy -- -D warnings` to verify no regressions
- Some items may have hidden dependencies - verify after each change
