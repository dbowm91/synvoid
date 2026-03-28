# Dependency Reduction Plan (Priority 1)

## Overview
Remove unused dependencies to reduce compile times and binary size without losing functionality.

## Verification Completed

### Dependencies Confirmed UNUSED (Safe to Remove)

| Dependency | Status | Evidence |
|------------|--------|----------|
| `ab_glyph` | ✅ Unused | Not imported anywhere in src/ or binaries |
| `flare` | ✅ Unused | Not imported anywhere in src/ or binaries |
| `base32` | ✅ N/A | Not in Cargo.toml (local implementation used instead) |
| `linked-hash-map` | ❌ Used | `src/mesh/dht/record_store.rs:8` uses it |
| `libcrux-ml-dsa` | ❌ Used | `pqc/src/dsa.rs` uses it for ML-DSA signatures |

### Correction from Initial Analysis
- `linked-hash-map` IS used - cannot remove
- `libcrux-ml-dsa` IS used in pqc crate for post-quantum signatures - cannot remove
- `base32` is NOT directly imported but there's local code in `dns/dnssec.rs` that implements base32 encoding - crate not needed

---

## Action Plan

### Step 1: Remove `ab_glyph` from Cargo.toml

**File**: `/Users/davidbowman/projects/rustwaf/Cargo.toml`

**Line 123**: Remove `ab_glyph = "0.2"`

**Rationale**: No imports found in entire codebase. Appears to be leftover from potential CAPTCHA or visual challenge feature.

---

### Step 2: Remove `flare` from Cargo.toml

**File**: `/Users/davidbowman/projects/rustwaf/Cargo.toml`

**Line 124**: Remove `flare = "0.1"`

**Rationale**: No imports found in entire codebase. Appears to be unused logging/metrics utility.

---

### Step 3: Verify Changes Compile

Run the following to verify:

```bash
cd /Users/davidbowman/projects/rustwaf
cargo check --lib
```

---

## Expected Impact

| Change | Binary Size Impact | Compile Time Impact |
|--------|-------------------|---------------------|
| Remove ab_glyph | ~100-200KB | ~5-10 seconds |
| Remove flare | ~50-100KB | ~2-5 seconds |
| **Total** | ~150-300KB | ~7-15 seconds |

---

## Notes

- These changes do NOT affect:
  - Overseer/Master/Worker architecture
  - DNS functionality
  - Mesh networking
  - WAF detection
  - Any feature flags

- After these removals, consider:
  1. Splitting tokio features from `"full"` to reduce compile time
  2. Making wasmtime optional for builds that don't need plugin support
  3. Future Priority 3: Consolidate crypto libraries (higher effort)
