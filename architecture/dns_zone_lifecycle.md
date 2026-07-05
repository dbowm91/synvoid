# DNS Zone Lifecycle Architecture

Milestone 3 Phase 1 deliverable — documents the zone lifecycle state machine, state transitions, health metadata, and operator guidance.

---

## 1. Purpose

The zone lifecycle governs which operations are permitted on a DNS zone at any given time. It prevents inconsistent states (e.g., serving queries from a partially-loaded zone) and provides operational visibility into zone health.

---

## 2. ZoneState Enum

Source: `crates/synvoid-dns/src/server/mod.rs:245`

```rust
pub enum ZoneState {
    Loading,    // Zone is being loaded from config or persistence
    Active,     // Zone is fully loaded and serving queries
    Reloading,  // Zone is being reloaded (zone transfer, config reload)
    Disabled,   // Zone is administratively disabled
    Failed,     // Zone encountered a fatal error
    Deleting,   // Zone is being deleted
}
```

### State Descriptions

| State | Serves Queries | Accepts Updates | Accepts Transfers | Description |
|-------|---------------|-----------------|-------------------|-------------|
| `Loading` | No | No | No | Zone is being loaded from config or persistence. Intermediate state. |
| `Active` | Yes | Yes | Yes | Zone is fully loaded and serving queries. Only state that serves. |
| `Reloading` | No | No | No | Zone transfer or config reload in progress. Previous data may still be served from cache. |
| `Disabled` | No | No | No | Administratively disabled. Zone exists but does not serve. |
| `Failed` | No | No | No | Fatal error encountered (corrupt SOA, DNSSEC failure). Requires operator intervention. |
| `Deleting` | No | No | No | Zone is being removed from the server. |

---

## 3. State Transition Diagram

```
                         ┌──────────────┐
           ┌────────────►│   Loading    │◄────────────┐
           │             └──────┬───────┘             │
           │                    │                     │
           │               success                reload
           │                    │                     │
           │                    ▼                     │
           │             ┌─────────────┐              │
           │             │    Active   │──────┐       │
           │             └──────┬──────┘      │       │
           │                    │             │       │
           │       ┌────────────┼────────┐    │       │
           │       │            │        │    │       │
           │    disable      reload   delete  │       │
           │       │            │        │    │       │
           │       ▼            ▼        │    ▼       │
           │ ┌───────────┐ ┌─────────┐   │ ┌───────┐ │
           │ │ Disabled  │ │Reloading│   │ │Failed │ │
           │ └─────┬─────┘ └────┬────┘   │ └───┬───┘ │
           │       │            │        │     │     │
           │    enable       success    │  retry  disabled
           │       │            │        │     │     │
           │       └────────────┘        │     │     │
           │                             │     │     │
           │         ┌───────────────────┘     │     │
           │         │                         │     │
           │         ▼                         ▼     │
           │   ┌───────────┐            ┌──────────┐ │
           └───│ Deleting  │◄───────────│          │─┘
               └───────────┘            └──────────┘
```

---

## 4. Valid Transitions

Enforced by `Zone::set_state()` at `server/mod.rs:423`. Invalid transitions return `Err("Invalid state transition: {from} -> {to}")`.

| From | To | Trigger | Notes |
|------|----|---------|-------|
| `Loading` | `Active` | Successful zone load | Zone is ready to serve |
| `Loading` | `Failed` | Load error (corrupt data, missing SOA) | Requires operator intervention |
| `Active` | `Reloading` | Zone transfer initiated, config reload | Previous data may still be cached |
| `Active` | `Disabled` | Operator disables zone | Zone exists but stops serving |
| `Active` | `Deleting` | Operator deletes zone | Zone begins removal |
| `Active` | `Failed` | Runtime error (DNSSEC failure) | Requires operator intervention |
| `Reloading` | `Active` | Reload successful | Zone resumes serving with new data |
| `Reloading` | `Failed` | Reload error | Zone enters failed state |
| `Disabled` | `Active` | Operator re-enables zone | Zone resumes serving |
| `Disabled` | `Deleting` | Operator deletes disabled zone | Zone begins removal |
| `Failed` | `Loading` | Operator triggers retry | Zone attempts to reload |
| `Failed` | `Deleting` | Operator deletes failed zone | Zone begins removal |
| `Failed` | `Disabled` | Operator disables failed zone | Zone enters disabled state |
| `Deleting` | `Loading` | Re-create after delete | Zone is being re-added |

### Blocked Transitions

The following transitions are **not valid** and will return `Err`:

- `Loading → Reloading`, `Loading → Disabled`, `Loading → Deleting`
- `Reloading → Disabled`, `Reloading → Deleting`
- `Disabled → Loading`, `Disabled → Reloading`, `Disabled → Failed`
- `Deleting → Active`, `Deleting → Failed`, `Deleting → Disabled`
- Any state → itself (no self-transitions)

---

## 5. Zone Health Metadata

Source: `crates/synvoid-dns/src/server/mod.rs:275`

```rust
pub struct ZoneHealth {
    pub state: ZoneState,
    pub last_load_time: Option<u64>,
    pub last_error: Option<String>,
    pub record_count: usize,
    pub dnssec_state: DnssecState,
}
```

### Fields

| Field | Type | Description |
|-------|------|-------------|
| `state` | `ZoneState` | Current lifecycle state |
| `last_load_time` | `Option<u64>` | Unix timestamp of last successful load/reload. `None` if never loaded. |
| `last_error` | `Option<String>` | Error message when `state == Failed`. `None` otherwise. |
| `record_count` | `usize` | Number of resource records in the zone |
| `dnssec_state` | `DnssecState` | DNSSEC signing state (see below) |

### DnssecState

```rust
pub enum DnssecState {
    Unsigned,       // DNSSEC not configured
    KeyGeneration,  // Keys being generated
    Signed,         // Zone signed, serving authenticated responses
    KeyRollover,    // Key rollover in progress
    SigningFailed,  // DNSSEC signing failed
}
```

### Convenience Methods

- `Zone::is_serving()` → `true` only when `state == Active`
- `Zone::state()` → current `ZoneState`
- `Zone::health()` → reference to `ZoneHealth`
- `Zone::mark_active()` → sets `Active`, updates `last_load_time` and `record_count`, clears `last_error`
- `Zone::mark_failed(error)` → sets `Failed` with error message

---

## 6. SOA Validation

### Rules

1. **Exactly one SOA per zone apex** (RFC 1035 §3.3.13)
2. Zone load rejects if `count_apex_soa() != 1`
3. Runtime query handling returns SERVFAIL if SOA absent (fail-closed)

### Implementation

```rust
// server/mod.rs:493
pub fn count_apex_soa(&self) -> usize { ... }
pub fn validate_single_soa(&self) -> Result<(), String> { ... }
pub fn normalize_origin(origin: &str) -> String { ... }  // trim dots, lowercase
```

---

## 7. Serial Correctness

### RFC 1982 Serial Comparison

```rust
// server/mod.rs:406
pub fn serial_is_more_recent(s1: u32, s2: u32) -> bool {
    const HALF_RANGE: u32 = 0x80000000;
    if s1 == s2 { return false; }
    let diff = s1.wrapping_sub(s2);
    diff < HALF_RANGE
}
```

Handles wrap-around at 0x80000000 correctly.

### Monotonic Increment

```rust
// server/mod.rs:386
fn increment_serial_rfc1982(current: u32) -> u32 {
    // Uses current timestamp when possible
    // Falls back to wrapping_add(1) near wrap-around boundary
}
```

### History Retention

- `Zone::increment_serial_with_limit(max_history)` caps `ZoneHistory` entries
- Default limit: 200 entries per zone
- History entries store: previous serial, records snapshot, timestamp
- Used for IXFR delta encoding

---

## 8. Dynamic UPDATE Hardening

### Security Controls

| Control | Default | Description |
|---------|---------|-------------|
| `enabled` | `false` | Returns NOTIMP (RCODE 4) when disabled |
| `require_tsig` | `true` | TSIG authentication required |
| `allow_any` | `false` | IP allowlist enforcement |
| `allowed_ips` | `[]` | CIDR notation or `*` wildcard |

### Processing Pipeline

1. Check `enabled` flag → NOTIMP if disabled
2. Check IP allowlist → deny if not allowed
3. Parse TSIG → verify if `require_tsig` is true
4. Parse UPDATE message → validate prerequisites
5. Apply adds/deletes atomically
6. Increment serial, store history
7. Trigger cache invalidation

### Audit Safety

- MAC values are never logged
- Only client IP and zone name are recorded in logs

---

## 9. NOTIFY Hardening

### Controls

| Control | Default | Description |
|---------|---------|-------------|
| `enabled` | `false` | Returns NOTIMP when disabled |
| `also_notify` | `[]` | Secondary IPs to notify |
| Serial check | — | Skip NOTIFY if serial unchanged |
| TSIG | optional | Verify incoming NOTIFY signatures |

### Rate Limiting

Per-zone serial check in `notify_secondaries()`: if the new serial matches the last-notified serial, the NOTIFY is skipped. This prevents redundant notifications during rapid zone updates.

---

## 10. AXFR Hardening

### Security Defaults

| Control | Default | Description |
|---------|---------|-------------|
| `axfr_enabled` | **`false`** | Disabled by default (security-sensitive) |
| `tcp_only` | `true` | RFC 5936 §2: AXFR requires TCP |
| `require_tsig` | `true` | TSIG authentication required |
| `allow_wildcard_transfer` | `false` | Wildcard `*` requires explicit opt-in |

### SOA Bracketing

AXFR responses must begin and end with the zone's SOA record. This is validated during transfer processing.

---

## 11. IXFR Correctness

### History Management

- `max_history_size`: 200 (default), configurable
- When history is insufficient for requested delta → fallback to AXFR (if `ixfr_fallback_to_axfr: true`)
- RFC 1982 serial comparison determines delta applicability

---

## 12. Store Persistence

### SQLite-Backed Store

- Atomic writes via transactions
- Schema: `zones` (id, origin, created_at, updated_at) + `records` (zone_id, name, type, value, ttl, priority)
- Foreign key cascade deletes

### Volatile Mode

`ZoneStore::new_volatile()` creates an in-memory-only store backed by SQLite `:memory:`. No disk persistence. Useful for testing and ephemeral deployments.

### Corrupt Record Handling

Corrupt records are skipped with logging. The zone remains operational with the remaining valid records.

---

## 13. Cache Invalidation

All zone mutation paths trigger `cache.invalidate_zone()` with a typed `InvalidationReason`:

| Reason | Trigger | Scope |
|--------|---------|-------|
| `ZoneLoad` | Config zone loaded | Per-zone |
| `ZoneLoadFromStore` | Restored from SQLite | Per-zone |
| `RecordAdd` | Record inserted | Per-zone |
| `ZoneDelete` | Zone removed | Per-zone |
| `DynamicUpdate` | RFC 2136 update | Per-zone |
| `NotifyReceived` | Incoming NOTIFY | Per-zone |
| `ManualFlush` | Operator flush | Full cache |
| `DnssecKeyRollover` | Key rollover | Full cache |
| `RpzZoneRemoval` | RPZ zone removed | Full cache |
| `ZoneTransferAxfr` | Full zone transfer | Per-zone |
| `ZoneTransferIxfr` | Incremental transfer | Per-zone |

Per-reason Prometheus counters via `CacheMetrics.invalidations_by_reason`.

---

## 14. Operator Guidance

### Recovering from `Failed` State

1. Check `zone.health().last_error` for the failure reason
2. Fix the underlying issue (corrupt zone file, DNSSEC key problem, etc.)
3. Call the zone reload API to transition `Failed → Loading → Active`

### Disabling a Zone

Transition `Active → Disabled`. The zone stops serving queries but remains in memory. Re-enable with `Disabled → Active`.

### Deleting a Zone

Transition to `Deleting` (from `Active`, `Disabled`, or `Failed`). The zone is removed from in-memory store and cache is invalidated.

### Monitoring Zone Health

Query `zone.health()` for:
- Current state
- Last load timestamp
- Error message (if failed)
- Record count
- DNSSEC signing state

### Retry After Failure

Transition `Failed → Loading` to trigger a zone reload. If the reload succeeds, the zone transitions to `Active`. If it fails again, it returns to `Failed`.

---

## 15. Verification Commands

```bash
# Zone lifecycle state transitions
cargo test -p synvoid-dns -- zone_lifecycle
cargo test -p synvoid-dns -- zone_health

# SOA validation
cargo test -p synvoid-dns -- validate_single_soa
cargo test -p synvoid-dns -- normalize_origin

# Serial correctness
cargo test -p synvoid-dns -- serial_rfc1982

# Dynamic UPDATE
cargo test -p synvoid-dns -- update_metrics
cargo test -p synvoid-dns -- update_max_size

# NOTIFY
cargo test -p synvoid-dns -- notify_rate_limit
cargo test -p synvoid-dns -- notify_source_allowlist

# AXFR/IXFR
cargo test -p synvoid-dns -- axfr_tcp_only
cargo test -p synvoid-dns -- axfr_disabled_by_default
cargo test -p synvoid-dns -- ixfr_history

# Store persistence
cargo test -p synvoid-dns -- store_volatile
cargo test -p synvoid-dns -- store_atomic_write

# Cache invalidation
cargo test -p synvoid-dns -- cache_invalidation_axfr
```
