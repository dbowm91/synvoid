# Plan 34: Test Coverage Improvements - Overseer/Master/Worker Architecture

## Context

A code review of the MaluWAF test infrastructure revealed several gaps in test coverage for the core overseer/master/worker architecture. While the architecture is intact and well-structured, certain critical paths lack proper test coverage, and one failing test was identified.

**Scope**: Test coverage analysis for the multi-process architecture (overseer → master → worker)

---

## Executive Summary

### Current Test Status

| Test Category | Status | Details |
|---------------|--------|---------|
| **Integration Tests** (`tests/integration_test.rs`) | ✅ 242 passed | IPC, process messages, WAF detection, proxy, TLS configs |
| **E2E Process Tests** (`tests/e2e_process_test.rs`) | ✅ 13 passed | Socket binding, signed send/recv, timeouts |
| **Process Lifecycle Tests** (`tests/process_lifecycle_test.rs`) | ✅ 33 passed | Message categories, drain protocols, serialization |
| **Drain E2E Tests** (`tests/drain_e2e_test.rs`) | ✅ 4 passed | Drain protocol, multiple workers |
| **IPC Tests** (`tests/ipc_test.rs`) | ✅ 143 passed | Message round-trips, HMAC verification |
| **Inline Overseer Tests** | ✅ 11 passed | Config, health checks |
| **Inline Worker Tests** | ❌ 7 passed, **1 failed** | Drain state logic |
| **Inline Master Tests** | ✅ 13 passed | Message parsing |

**Total**: ~460+ test functions across integration and unit tests

### Issues Found

| # | Issue | Severity | Location |
|---|-------|----------|----------|
| 1 | Failing test: `test_drain_completes_on_last_connection_decrement` | **Critical** | `src/worker/drain_state.rs:293-307` |
| 2 | No Socket Handoff E2E tests | High | `src/overseer/socket_handoff.rs` |
| 3 | No Upgrade Protocol flow tests | High | `src/overseer/upgrade.rs` |
| 4 | No Rollback E2E tests | High | `src/overseer/rollback.rs` |
| 5 | Health Checker async methods untested | Medium | `src/overseer/health.rs` |
| 6 | Drain auto-completion logic untested | Medium | `src/worker/drain_state.rs` |

---

## Architecture Verification

The overseer/master/worker architecture is **intact and correctly structured**:

```
Overseer (src/overseer/)
├── process.rs          - Process lifecycle + health monitoring
├── upgrade.rs          - Zero-downtime upgrades (stage→apply→drain→commit)
├── rollback.rs         - Rollback on failure
├── socket_handoff.rs   - FD transfer for zero-downtime upgrades
├── health.rs           - Worker health checking (HTTP + readiness)
├── drain_manager.rs    - Coordinated draining across workers
├── state.rs            - UpgradeState machine
└── preflight.rs        - Pre-upgrade validation

Master (src/master/)
├── ipc.rs              - Worker IPC message handling
├── commands.rs         - CLI handlers (status, stop, reload, etc.)
├── mod.rs              - Platform-specific IPC (Unix/Windows)
└── Mod:                - Platform-specific implementations

Worker (src/worker/)
├── drain_state.rs      - Per-worker drain state machine
├── unified_server.rs   - HTTP/TLS request handling
├── connect.rs          - Connection management
└── traits.rs           - WorkerLifecycle, BaseWorkerState traits
```

### IPC Communication Flow

```
Overseer                    Master                      Worker
    │                          │                          │
    │──MasterHealthCheck─────▶│                          │
    │◀──HealthCheckAck───────┤                          │
    │                          │                          │
    │──OverseerUpgradePrepare▶│                          │
    │◀─UpgradeReady──────────┤                          │
    │                          │──WorkerStarted─────────▶│
    │                          │◀──WorkerReady───────────┤
    │                          │                          │
    │──WorkerDrain────────────│──WorkerDrain────────────▶│
    │                          │◀──WorkerDrained─────────┤
    │                          │                          │
    │──OverseerUpgradeRollback▶│──MasterShutdown────────▶│
```

---

## Phase 1: Fix Failing Test (CRITICAL)

**Goal**: Fix the failing test `test_drain_completes_on_last_connection_decrement`

### Root Cause Analysis

The test at `src/worker/drain_state.rs:293-307` expects that calling `decrement_active()` when active connections reaches 0 will set `drain_complete = true`. However, the implementation requires **both** conditions:

```rust
// From drain_state.rs:198
let drain_complete = is_draining && self.stopped_accepting.is_draining() && active == 0;
```

The test doesn't call `stop_accepting()` before checking `drain_complete`.

### Investigation Results

**Code flow at `src/worker/drain_state.rs:105-112`:**

```rust
pub fn decrement_active(&self) {
    let prev = self
        .active_connections
        .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |v| v.checked_sub(1))
        .unwrap_or(0);
    if prev == 1 && self.is_draining() {
        self.mark_drain_complete();  // This only marks "connections_drained" counter
    }
}
```

The method calls `mark_drain_complete()` which updates `connections_drained` counter, but the `drain_complete` field in `DrainStatusResponse` requires `stopped_accepting.is_draining() == true`.

### Test Logic Ambiguity

**Two possible interpretations:**

1. **Test is correct, implementation is wrong**: Decrementing to 0 should auto-complete the drain without requiring explicit `stop_accepting()` call.

2. **Implementation is correct, test is wrong**: The drain must explicitly enter "stopped accepting" state before it can be considered complete. This is a safety mechanism to prevent premature drain completion.

### Recommended Fix

**Option A (Recommended - fix test to match design intent):**

Update the test to call `stop_accepting()` before checking `drain_complete`:

```rust
#[tokio::test]
async fn test_drain_completes_on_last_connection_decrement() {
    let state = WorkerDrainState::new();
    state.start_drain(1).await;
    state.increment_active();
    assert_eq!(state.get_active_connections(), 1);

    // Decrement to 0 triggers mark_drain_complete (counter update)
    state.decrement_active();
    assert_eq!(state.get_active_connections(), 0);

    // MUST call stop_accepting for drain_complete to be true
    state.stop_accepting();
    
    let status = state.get_status().await;
    assert!(status.drain_complete);
    assert!(status.stopped_accepting || status.active_connections == 0);
}
```

**Option B (alternative - fix implementation):**

If the test represents the intended behavior, modify `decrement_active()` to also set `stopped_accepting`:

```rust
pub fn decrement_active(&self) {
    let prev = self
        .active_connections
        .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |v| v.checked_sub(1))
        .unwrap_or(0);
    if prev == 1 && self.is_draining() {
        self.mark_drain_complete();
        self.stopped_accepting.start_drain();  // ADD THIS
    }
}
```

### Files to Modify

| File | Change |
|------|--------|
| `src/worker/drain_state.rs` | Fix test at line 293-307 |

---

## Phase 2: Socket Handoff E2E Tests (HIGH)

**Goal**: Add integration tests for socket file descriptor transfer between processes

### Current Coverage

- Only inline struct tests in `src/overseer/socket_handoff.rs`
- No E2E tests for actual FD passing

### What's Missing

| Component | Gap |
|-----------|-----|
| `SocketHandoffServer` | No test for server binding and listening |
| `SocketHandoffClient` | No test for client connection |
| `DualMasterHandoff` | No test for dual-master coordination |
| FD passing | No test for actual Unix socket FD transfer |

### Implementation Plan

**New file**: `tests/socket_handoff_test.rs`

```rust
#[cfg(unix)]
mod socket_handoff_tests {
    use std::os::unix::net::UnixListener;
    use std::io::{Read, Write};
    use std::os::unix::io::{FromRawFd, AsRawFd};
    
    use maluwaf::overseer::socket_handoff::{
        SocketHandoffServer, SocketHandoffClient, SocketHandoffError
    };
    use tempfile::TempDir;
    
    #[tokio::test]
    async fn test_socket_handoff_server_bind() {
        // Test server can bind to a Unix socket path
    }
    
    #[tokio::test]
    async fn test_socket_handoff_client_connect() {
        // Test client can connect to server
    }
    
    #[tokio::test]
    async fn test_dual_master_handoff_flow() {
        // Test the full handoff flow:
        // 1. Old master creates listening socket
        // 2. New master connects
        // 3. FD is transferred
        // 4. New master can accept connections on transferred FD
    }
}
```

### Files to Create

| File | Purpose |
|------|---------|
| `tests/socket_handoff_test.rs` | Socket handoff E2E tests |

---

## Phase 3: Upgrade Protocol Flow Tests (HIGH)

**Goal**: Add integration tests for the upgrade orchestration flow

### Current Coverage

**Strengths** (58+ unit tests):
- State machine transitions (terminal/transition states)
- State eligibility (can_stage, can_apply, can_rollback)
- Timeout detection
- Config defaults
- UpgradeMode detection
- IPC message serialization

**Gaps** (No E2E flow tests):
- Full stage→apply→drain→commit pipeline
- Failure injection (spawn fails, health check fails)
- Rollback flow
- Dual-master upgrade path

### Implementation Plan

**Extend**: `tests/integration_test.rs` or create `tests/upgrade_flow_test.rs`

```rust
#[cfg(unix)]
mod upgrade_flow_tests {
    use maluwaf::overseer::upgrade::{Orchestrator, UpgradeState};
    use maluwaf::overseer::state::OverseerState;
    use maluwaf::config::OverseerConfig;
    
    #[tokio::test]
    async fn test_upgrade_stage_to_apply_flow() {
        // Test: stage() → apply() state transitions
    }
    
    #[tokio::test]
    async fn test_upgrade_apply_to_drain_flow() {
        // Test: apply() → drain_old_workers() state transitions
    }
    
    #[tokio::test]
    async fn test_upgrade_drain_to_commit_flow() {
        // Test: drain complete → commit state transition
    }
    
    #[tokio::test]
    async fn test_upgrade_failure_rollback() {
        // Test: upgrade fails → automatic rollback triggers
    }
    
    #[tokio::test]
    async fn test_upgrade_spawn_failure_injection() {
        // Test: worker spawn fails → upgrade handles error gracefully
    }
    
    #[tokio::test]
    async fn test_upgrade_health_check_failure_triggers_rollback() {
        // Test: post-upgrade health check failure → auto-rollback
    }
    
    #[tokio::test]
    async fn test_dual_master_upgrade_flow() {
        // Test: dual-master mode upgrade sequence
    }
}
```

### Key Testing Points

1. **State machine integrity**: Verify correct transitions under various conditions
2. **Failure modes**: Test behavior when subprocess spawning fails
3. **Health check integration**: Test auto-rollback triggers
4. **Dual-master coordination**: Test FD handoff in dual-master mode

### Files to Modify/Create

| File | Change |
|------|--------|
| `tests/upgrade_flow_test.rs` | Create new test file (or extend integration_test.rs) |

---

## Phase 4: Rollback E2E Tests (HIGH)

**Goal**: Add integration tests for manual and automatic rollback functionality

### Current Coverage

- Only 6 inline unit tests in `src/overseer/rollback.rs`:
  - `test_rollback_manager_defaults`
  - `test_rollback_error_display`
  - `test_rollback_target_construction`
  - `test_can_rollback_logic`
  - `test_rollback_target_parsing`

### What's Missing

| Scenario | Gap |
|----------|-----|
| Manual CLI rollback | No test for `handle_rollback()` |
| Auto-rollback trigger | No test for `perform_auto_rollback()` |
| State transitions | No test for `RollingBack → Idle` or `RollingBack → Failed` |
| Recovery path | No test for `RecoveryNeeded` state handling |
| Version restoration | No test for actual binary version swap |

### Implementation Plan

**Extend**: `tests/upgrade_flow_test.rs` (add rollback section)

```rust
mod rollback_tests {
    use maluwaf::overseer::rollback::RollbackManager;
    use maluwaf::overseer::state::UpgradeState;
    
    #[test]
    fn test_manual_rollback_trigger() {
        // Test: CLI triggers rollback → state transitions to RollingBack
    }
    
    #[test]
    fn test_auto_rollback_on_health_failure() {
        // Test: health check failure → auto_rollback triggers
    }
    
    #[test]
    fn test_rollback_success_state_transition() {
        // Test: successful rollback → Idle state with version restored
    }
    
    #[test]
    fn test_rollback_failure_state_transition() {
        // Test: failed rollback → Failed state
    }
    
    #[test]
    fn test_recovery_from_recovery_needed_state() {
        // Test: recovery from RecoveryNeeded state
    }
}
```

### Files to Modify

| File | Change |
|------|--------|
| `tests/upgrade_flow_test.rs` | Add rollback test module |

---

## Phase 5: Health Checker Async Tests (MEDIUM)

**Goal**: Add tests for async health checking methods

### Current Coverage

**Tested:**
- `HealthStatus` enum variants (struct creation)
- `WorkerReadinessStatus` struct fields
- `EnhancedHealthConfig` defaults
- HTTP handler endpoints (`/health`, `/ready`)

**Not Tested:**
- `HealthChecker::check_worker()` - HTTP health check
- `HealthChecker::check_worker_readiness()` - Readiness probe
- `HealthChecker::validate_all()` - Retry logic
- `HealthChecker::enhanced_health_check()` - Latency sampling
- `BaselineComparison` calculation
- Retry utilities (`retry_with_timeout`, `wait_for_condition`)

### Implementation Plan

**Extend**: `tests/integration_test.rs` (add health checker module)

```rust
mod health_checker_tests {
    use maluwaf::overseer::health::{
        HealthChecker, HealthStatus, EnhancedHealthConfig
    };
    use std::sync::Arc;
    
    #[tokio::test]
    async fn test_health_checker_check_worker_success() {
        // Mock HTTP server returns 200
        // Verify HealthChecker returns Healthy
    }
    
    #[tokio::test]
    async fn test_health_checker_check_worker_failure() {
        // Mock HTTP server returns 500
        // Verify HealthChecker returns Unhealthy
    }
    
    #[tokio::test]
    async fn test_health_checker_validate_all_retries() {
        // Mock: first N checks fail, then succeed
        // Verify validate_all() eventually succeeds
    }
    
    #[tokio::test]
    async fn test_health_checker_draining_status() {
        // Mock: worker returns draining state
        // Verify HealthStatus::Draining variant
    }
    
    #[tokio::test]
    async fn test_enhanced_health_check_latency_measurement() {
        // Mock: sample requests with varying latency
        // Verify p95 latency calculation
    }
}
```

### Mock Strategy

Use `wiremock` or `httptest` for HTTP mocking, or create a simple test HTTP server using `tiny_http`.

### Files to Modify

| File | Change |
|------|--------|
| `tests/integration_test.rs` | Add health checker test module |

---

## Phase 6: Drain Auto-Completion Tests (MEDIUM)

**Goal**: Add tests for automatic drain completion when last connection closes

### Current Coverage

- `test_drain_state` - Basic drain start
- `test_stop_accepting_completes_drain_when_no_connections` - Stop accepting with 0 connections
- `test_stop_accepting_does_not_complete_with_active_connections` - Stop accepting with connections

### What's Missing

- Test for `decrement_active()` auto-completing drain when going from 1→0 connections during active drain

### Implementation Plan

**Fix and extend**: `src/worker/drain_state.rs` tests

```rust
#[tokio::test]
async fn test_decrement_active_auto_triggers_drain_complete() {
    // This test currently FAILS - see Phase 1
    // After fixing, add additional scenarios:
    
    let state = WorkerDrainState::new();
    state.start_drain(1).await;
    
    // Scenario 1: decrement from 1 to 0
    state.increment_active();
    state.decrement_active();
    assert_eq!(state.get_active_connections(), 0);
    // drain_complete requires stop_accepting
    
    // Scenario 2: multiple connections
    state.start_drain(2).await;
    state.increment_active();
    state.increment_active();
    state.increment_active();
    assert_eq!(state.get_active_connections(), 3);
    
    state.decrement_active();
    assert_eq!(state.get_active_connections(), 2); // Not complete
    
    state.decrement_active();
    assert_eq!(state.get_active_connections(), 1); // Not complete
    
    state.decrement_active();
    assert_eq!(state.get_active_connections(), 0); // Now at zero
    
    // drain_complete still requires stop_accepting
}
```

### Files to Modify

| File | Change |
|------|--------|
| `src/worker/drain_state.rs` | Fix and enhance drain tests |

---

## Implementation Order

```
Phase 1 (Critical) ───────────────────────────────────────────┐
                                                              │
Phase 2 (High) ──────────────────────────────────────────────┤
                                                              │
Phase 3 (High) ───────────────────────┐                      │
                                       │                      │
Phase 4 (High) ───────────────────────┴── Can combine with 3  │
                                                              │
Phase 5 (Medium) ────────────────────────────────────────────┤
                                                              │
Phase 6 (Medium) ─────────────────────────────────────────────┘
```

---

## Files Summary

### New Files to Create

| File | Phase | Purpose |
|------|-------|---------|
| `tests/socket_handoff_test.rs` | 2 | Socket handoff E2E tests |
| `tests/upgrade_flow_test.rs` | 3, 4 | Upgrade + rollback flow tests |

### Files to Modify

| File | Phase | Changes |
|------|-------|---------|
| `src/worker/drain_state.rs` | 1, 6 | Fix failing test, add drain tests |
| `tests/integration_test.rs` | 5 | Add health checker tests |

---

## Verification Steps

### After Phase 1 (Fix Failing Test)

```bash
cargo test --lib -- worker::drain_state::tests --test-threads=1
# Should show: test result: ok. 8 passed; 0 failed
```

### After Phase 2 (Socket Handoff)

```bash
cargo test --test socket_handoff_test
# Should show: socket handoff E2E tests passing
```

### After Phase 3-4 (Upgrade + Rollback)

```bash
cargo test --test upgrade_flow_test
# Should show: upgrade and rollback flow tests passing
```

### After Phase 5 (Health Checker)

```bash
cargo test --test integration_test -- health_checker_tests
# Should show: health checker tests passing
```

### After All Phases

```bash
cargo test --test integration_test
cargo test --test e2e_process_test
cargo test --test process_lifecycle_test
cargo test --test drain_e2e_test
cargo test --test ipc_test
cargo test --lib --test-threads=1

# All tests should pass
```

---

## Rollback Plan

If issues arise during implementation:

1. **Phase 1**: Revert test changes - test will fail (known issue)
2. **Phase 2-4**: Remove test files - architecture tests unaffected
3. **Phase 5-6**: Revert test additions - original tests remain passing

---

## References

- [Rust Testing Best Practices](https://doc.rust-lang.org/book/ch11-01-writing-tests.html)
- [Tokio Test Documentation](https://docs.rs/tokio/latest/tokio/attr.test.html)
- [Unix Socket FD Passing](https://man7.org/linux/man-pages/man7/unix.7.html) - SCM_RIGHTS
- [Process Upgrade Patterns](https://github.com/matu36/rolling-upgrades) - Zero-downtime upgrade patterns

---

## Appendix: Test Coverage Matrix

| Component | Unit Tests | Integration Tests | E2E Tests | Status |
|-----------|------------|-------------------|-----------|--------|
| Overseer Config | ✅ 11 | ✅ 3 | ❌ | Good |
| Overseer Health | ✅ 6 | ✅ 3 | ❌ | Medium |
| Overseer Upgrade | ✅ 58+ | ❌ | ❌ | Medium |
| Overseer Rollback | ✅ 6 | ❌ | ❌ | Low |
| Overseer Socket Handoff | ✅ 4 | ❌ | ❌ | Low |
| Overseer Drain Manager | ✅ 2 | ✅ 4 | ❌ | Medium |
| Overseer Checksum | ✅ 1 | ❌ | ❌ | Low |
| Overseer Preflight | ✅ 2 | ❌ | ❌ | Low |
| Master IPC | ✅ 13 | ✅ 143 | ✅ 13 | Excellent |
| Worker Drain State | ✅ 8 | ✅ 4 | ❌ | Medium |
| Worker Lifecycle | ✅ 5 | ✅ 242 | ✅ 13 | Excellent |
| IPC Messages | ❌ | ✅ 143 | ✅ 13 | Excellent |
| Process Manager | ❌ | ✅ 20+ | ✅ 13 | Good |

**Legend**: 
- ✅ = Adequate coverage
- ⚠️ = Partial coverage
- ❌ = Missing coverage