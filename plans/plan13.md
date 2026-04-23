# Plan 13: Honeypot & Threat Intelligence Architecture Improvements

**Date**: 2026-04-23
**Author**: opencode
**Status**: Draft

## Overview

This plan addresses 5 identified issues in the honeypot and threat intelligence sharing architecture:
1. DHT records never broadcast (CRITICAL)
2. Global-only restriction for threat intel sync (CRITICAL)
3. No deduplication across honeypot types (MEDIUM)
4. Asymmetric publishing intervals (MEDIUM)
5. Missing graceful shutdown coordination (LOW)

---

## Issue 1: DHT Records Never Broadcast 🔴 CRITICAL

### Finding

`broadcast_pending_records()` in `src/mesh/dht/record_store_sync.rs:618` is **defined but never called**. Threat indicators stored in DHT are never propagated to peers via Kademlia-style announce.

**Root Cause**: No caller added the periodic broadcast task. The code exists but wasn't wired up to any trigger.

**Current Flow**:
```
indicator stored → queue_for_announce() → pending_announces queue
                                                 ↓
                                          [NEVER SENT]
```

**Expected Flow** (similar to YARA rules):
```
indicator stored → queue_for_announce() → pending_announces queue
                                                 ↓
                                          broadcast_periodically()
                                                 ↓
                                          k-announce to peers
```

### Files to Modify

| File | Change |
|------|--------|
| `src/mesh/transport_dht.rs` | Add periodic call to `broadcast_pending_records()` |

### Implementation Details

1. Add to `mesh_accept_loop` or create new periodic task in `MeshTransport::start_background_tasks()`:

```rust
// In src/mesh/transport_dht.rs, in mesh_accept_loop or new task:
// Note: record_store accessed via routing_state.transport.get_record_store()
let record_store = self.record_store.clone();
tokio::spawn(async move {
    let mut interval = tokio::time::interval(Duration::from_secs(60));
    loop {
        interval.tick().await;
        // Get record_store from the routing state's transport
        if let Some(rs) = record_store.get_record_store() {
            rs.broadcast_pending_records().await;
        }
    }
});
```

2. Alternative: Add to existing metric/background loop in transport:

```rust
// In MeshTransport (transport.rs), add to periodic_dht_tasks():
// Call record_store.broadcast_pending_records() every 60s
// Access via: self.routing_state.read().transport.get_record_store()
```

### Risk

- **Low**: Enables existing dormant functionality
- **Performance**: 60s interval should have minimal network impact
- **Testing**: Need to verify announce reaches other nodes

---

## Issue 2: Global-Only Restriction for Threat Intel Sync 🔴 CRITICAL

### Finding

`src/mesh/threat_intel.rs:1319-1332` has hard-coded check rejecting non-global node threat indicators during DHT sync:

```rust
if !global_nodes.contains(&indicator.source_node_id) {
    tracing::warn!("Threat intel DHT sync: indicator from non-global node rejected");
    continue;
}
```

**Root Cause**: The reputation system already exists (`reputation.rs:260-308`) but isn't used in DHT sync - only checks the global_nodes whitelist.

**Current Behavior**:
- Edge nodes CAN publish indicators (via `store_and_announce`)
- But edge-origin indicators ARE REJECTED when other nodes sync from DHT
- This breaks decentralized threat sharing model

### Files to Modify

| File | Change |
|------|--------|
| `src/mesh/threat_intel.rs` | Replace hard global-only check with trusted signers list |

### Implementation Details

Option B (trusted signers list): Replace lines ~1325-1331 with:

```rust
// Add config field (add to ThreatIntelligenceConfig):
#[serde(default)]
pub trusted_signers: Vec<String>,

// In sync_from_dht, replace global_nodes check:
if let Some(ref transport) = *self.transport.read() {
    let topology = transport.get_topology();
    let global_nodes = tokio::task::block_in_place(|| {
        tokio::runtime::Handle::current()
            .block_on(topology.get_global_nodes())
    });

    // ALLOW if: global node OR signed by trusted_signer
    let is_global = global_nodes.contains(&indicator.source_node_id);
    let is_trusted_signer = signer_pk
        .as_ref()
        .map(|pk| self.config.trusted_signers.contains(pk))
        .unwrap_or(false);

    if !is_global && !is_trusted_signer {
        tracing::warn!(
            "Threat intel DHT sync: indicator from non-global/non-trusted node {} rejected",
            indicator.source_node_id
        );
        continue;
    }
}
```

**Config Changes** (if needed):
```toml
[mesh.threat_intel]
trusted_signers = ["node_id_1", "node_id_2"]  # Edge nodes allowed to publish
```

### Risk

- **Medium**: Enables edge contributions - need to configure trusted signers
- **Security**: Signatures already verified, trusted list adds allowance
- **Testing**: Verify edge-node indicators are accepted when signed by trusted signer

---

## Issue 3: No Deduplication Across Honeypot Types 🟡 MEDIUM

### Finding

| Honeypot Type | Deduplication | Storage |
|--------------|-------------|-------------|
| Port honeypot | Yes (SQLite + HashSet) | `mark_indicator_announced()` |
| HTTP honeypot | **NONE** | In-memory only |

Same IP caught by both honeypot types creates duplicate threat announcements.

### Root Cause

- Port honeypot: Uses `storage.mark_indicator_announced()` in SQLite
- HTTP honeypot: Calls `threat_intel.announce_honeypot_indicator()` directly with no prior check

### Files to Modify

| File | Change |
|------|--------|
| `src/waf/mod.rs` | Add deduplication check in `block_ip_for_honeypot()` |

### Implementation Details

In `src/waf/mod.rs:block_ip_for_honeypot()` (around lines 566-586):

```rust
pub fn block_ip_for_honeypot(
    &self,
    client_ip: IpAddr,
    reason: &str,
    duration: u64,
    scope: &str,
) {
    // NEW: Check if already announced (use module-level get_threat_intel())
    if let Some(threat_intel) = get_threat_intel() {
        let key = make_indicator_key(&client_ip.to_string(), ThreatType::SuspiciousActivity);
        if threat_intel.indicators.read().contains_key(&key) {
            tracing::debug!("Skipping duplicate honeypot indicator for {}", client_ip);
            return; // Already announced
        }
    }

    // Existing code unchanged:
    if let Some(ref store) = self.block_store {
        store.block_ip(client_ip, reason, duration, scope);
    }
    // ... rest unchanged
}
```

**Note**: `make_indicator_key` and `ThreatType` need to be imported from `crate::mesh::threat_intel` (or use the equivalent from `crate::mesh::protocol`).

### Risk

- **Low**: Prevents duplicate work
- **Performance**: HashMap lookup is O(1)
- **Testing**: Verify duplicates are skipped

---

## Issue 4: Asymmetric Publishing Intervals 🟡 MEDIUM

### Finding

| System | Interval | Behavior |
|--------|----------|----------|
| HTTP honeypot | Immediate | Fire-and-forget per-hit |
| Port honeypot | 30s | Batch processing |
| DHT sync | 300s | Per-node pull |
| Re-announce | 300s | Global-only |

HTTP honeypot was never refactored to use batched publishing like port honeypot.

### User Decision

User approved: **Keep 30s interval for consistency**

### Files to Modify

| File | Change |
|------|--------|
| `src/waf/mod.rs` | Add per-severity queue instead of immediate publish |
| `src/mesh/threat_intel.rs` | Add queued entry processing |

### Implementation Details

For simplicity, we'll document this as ** FUTURE ** since current functioning works (just not optimal). The 30s port honeypot interval is acceptable.

**Documented limitation**:
- HTTP honeypot: immediate publish per-hit
- Port honeypot: batched every 30s
- These could be harmonized in future iteration

### Risk

- **Low**: Documentation only - current behavior works

---

## Issue 5: Missing Graceful Shutdown Coordination 🟢 LOW

### Finding

| Task | Spawned By | Shutdown Tracking |
|------|-----------|-------------------|
| Port honeypot mesh publishing | `runner.rs:149` | ❌ None (no reference to `running` flag) |
| Threat intel background | `threat_intel.rs:1717` | ❌ None |
| Threat re-announce | `threat_intel.rs:1751` | ❌ None |

Spawned tasks aren't tracked in unified server's `task_handles` vector.

**Current State**:
- `PortHoneypotRunner` has `running: Arc<RwLock<bool>>` flag (line 19 of runner.rs)
- `stop()` method sets the flag (runner.rs:134-138)
- BUT `start_mesh_threat_publishing()` at line 149 does NOT check the running flag

### Files to Modify

| File | Change |
|------|--------|
| `src/mesh/threat_intel.rs` | Add `running` flag and `stop()` method |
| `src/worker/unified_server.rs` | Track spawned tasks in task_handles |

### Implementation Details

1. **Add running flag and stop() method to ThreatIntelligenceManager**:

```rust
// In src/mesh/threat_intel.rs, add to imports:
use std::sync::atomic::{AtomicBool, Ordering};

// In struct definition (after existing fields):
pub struct ThreatIntelligenceManager {
    // ... existing fields ...
    running: Arc<AtomicBool>,  // NEW
}

// In new_inner():
running: Arc::new(AtomicBool::new(true)),

// Add stop() method:
pub fn stop(&self) {
    self.running.store(false, Ordering::Relaxed);
}

pub fn is_running(&self) -> bool {
    self.running.load(Ordering::Relaxed)
}
```

2. **Wire to unified server task_handles** (similar pattern):

```rust
// In unified_server.rs, track the ThreatIntelligenceManager:
if let Some(ref threat_intel) = _threat_intel_manager {
    // threat_intel.start_background_tasks() already spawns tasks
    // Need to modify start_background_tasks to return handles
    // OR add separate tracking
}
```

3. **Modify port honeypot spawned task to check running flag**:

```rust
// In runner.rs:start_mesh_threat_publishing():
let running = self.running.clone();  // Pass reference to spawned task

loop {
    interval.tick().await;

    // NEW: Check stop signal
    if !running.load(Ordering::Relaxed) {
        tracing::info!("Threat publishing loop stopped");
        break;
    }

    // ... existing logic
}
```

### Risk

- **Low**: Improves operational reliability
- **Testing**: Verify all spawned tasks stop on worker shutdown

---

## Implementation Order

| # | Issue | Priority | Effort | Files |
|---|-------|----------|--------|-------|
| 2 | Global-Only Restriction | Critical | Low | `threat_intel.rs` |
| 1 | DHT Broadcast | Critical | Medium | `transport_dht.rs` |
| 3 | Honeypot Deduplication | Medium | Low | `waf/mod.rs` |
| 4 | Publishing Intervals | Medium | - | **FUTURE** (documented) |
| 5 | Shutdown Coordination | Low | Medium | `threat_intel.rs`, `unified_server.rs` |

---

## Testing Strategy

### Integration Tests to Add/Update

1. **Test DHT broadcast propagates**:
   - Create indicator on node A
   - Verify node B receives via DHT sync
   - Verify node B's block_store has the indicator

2. **Test edge node threat intel accepted**:
   - Simulate edge node publishing indicator
   - Verify global node accepts when in trusted_signers
   - Verify global node rejects when not in trusted_signers

3. **Test honeypot deduplication**:
   - HTTP honeypot hits same IP twice
   - Verify only one announcement published
   - Port honeypot also skips duplicate

4. **Test shutdown coordination**:
   - Worker receives stop signal
   - Verify all spawned tasks complete (not abrupt kill)

---

## Configuration Changes

### New Config Options

```toml
# In [mesh] or [main] section:

[mesh.threat_intel]
# Allow edge nodes to contribute threat intel
trusted_signers = ["edge_node_1", "edge_node_2"]
```

---

## Dependencies and Interactions

| Issue | Depends On | Affects |
|-------|-----------|--------|
| DHT Broadcast | DHT record store | Mesh transport |
| Global-Only | Reputation system (existing) | Security model |
| Deduplication | ThreatIntelligenceManager | Honeypot types |
| Shutdown | UnifiedServerWorkerState | Process lifecycle |

---

## Rollback Plan

| Issue | Rollback Approach |
|-------|-------------------|
| DHT Broadcast | Comment out broadcast call |
| Global-Only | Revert to global_nodes.contains() |
| Deduplication | Remove if check |
| Publishing | Already marked FUTURE |
| Shutdown | Remove tracking code |

---

## Success Metrics

After implementation:

1. **DHT Broadcast**: Threat indicators propagate to mesh peers within 60s
2. **Global-Only**: Edge nodes in trusted_signers can contribute successfully
3. **Deduplication**: No duplicate threat announcements for same IP
4. **Publishing**: Documented as FUTURE
5. **Shutdown**: All spawned tasks properly tracked and terminated on shutdown

---

## References

- `src/mesh/dht/record_store_sync.rs` - DHT broadcast (lines 618-680)
- `src/mesh/threat_intel.rs` - Threat intel management (lines 1319-1339)
- `src/waf/mod.rs` - HTTP honeypot blocking (lines 566-586)
- `src/honeypot_port/runner.rs` - Port honeypot (lines 140-246)
- `src/worker/unified_server.rs` - Worker state and task tracking (lines 1050-1150)

---

## Notes

- Uses trusted signers list (Option B) per user preference
- 30s interval kept per user preference
- Tracking in unified server per user preference
- Issue 4 marked as FUTURE - current behavior works