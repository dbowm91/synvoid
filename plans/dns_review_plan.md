# DNS Review Plan

## Stale Items Identified

### 1. AXFR "Missing record types" Section is Wrong
**Issue**: The "Missing record types" section in `architecture/dns_deep_dive.md:77-85` incorrectly claims the following record types are missing from AXFR implementation:
- SRV, PTR, DNSKEY, RRSIG, NSEC, NSEC3, DS, CAA

**Reality**: ALL listed types ARE implemented at `src/dns/transfer.rs:829-1028`.

**Action**: Remove the incorrect section entirely (see Bug DOC-DNS-1).

### 2. DNS Cookie Server Not Integrated
**Issue**: DNS Cookie Server (`src/dns/cookie.rs`) was created but never integrated into:
- DoT (DNS-over-TLS)
- DoH (DNS-over-HTTPS)
- DoQ (DNS-over-QUIC)

All three protocols receive `None` when querying for cookie server.

**Action**: Wire `DnsCookieServer` into the DoT/DoH/DoQ receive paths.

### 3. Query Flow Reference Error
**Issue**: `from_config` doesn't exist on the query flow path.

**Action**: Replace `from_config` with `new()` constructor.

### 4. Key Files Table Missing store.rs
**Issue**: The Key Files table in documentation is missing `store.rs`.

**Action**: Add `store.rs` to the Key Files table.

---

## Bugs

### DOC-DNS-1: Remove Incorrect "Missing record types" Section
**File**: `architecture/dns_deep_dive.md`
**Lines**: 77-85
**Fix**: Delete the entire "Missing record types" section as it contains factual errors.

---

## Verification Commands

```bash
cargo check --no-default-features --features dns
cargo test --lib dns
```
