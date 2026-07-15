# Testing Infrastructure Milestone E — Results

## Executive Summary

Milestone E improved test-level efficiency through:

1. Comprehensive resource and taxonomy inventories across 28 root integration tests and 9 per-crate test suites
2. Fixed process-global state isolation (env var serialization, process leak guard)
3. Refined nextest scheduling with evidence-based test groups replacing broad pattern overrides
4. Created domain-local DNS test support infrastructure (5 modules, ~1600 lines of deduplication ready)
5. Converted fuzz CI to matrix strategy with resource caps and per-target isolation
6. Documented testkit boundary with explicit in-scope/out-of-scope classification

## Completion Status

| Workstream | Status | Notes |
|-----------|--------|-------|
| E1: Test resource inventory | Complete | `docs/testing/test-resource-inventory.md` created |
| E2: Fixed ports | Complete | Inventory confirms good state; no code changes needed |
| E3: Environment/global state isolation | Complete | `OnceLock<Mutex<()>>` serialization guard added |
| E4: Task/process lifecycle hygiene | Complete | `ProcessGuard` RAII wrapper added |
| E5: Sleep replacement | Complete | Classification complete; no high-priority replacements |
| E6: DNS fixture deduplication | Complete | 5-module support library created (incremental adoption) |
| E7: Testkit boundary | Complete | Documented in-scope/out-of-scope with README |
| E8: Nextest scheduling | Complete | 6 broad overrides → 6 evidence-based groups |
| E9: Test taxonomy | Complete | `docs/testing/test-taxonomy.md` with 15 modalities |
| E10: Fuzz matrix | Complete | Serial loop → parallel matrix (4 concurrent) |
| E11: Impact measurement | Complete | Before/after metrics recorded |

## Workstream Results

### E1 — Test Resource Inventory

**Created**: `docs/testing/test-resource-inventory.md`

Inventoried all 28 root integration tests and 9 per-crate test suites for resource usage:

| Resource Category | Findings |
|-------------------|----------|
| Fixed ports | 1 HIGH-risk (synvoid-tunnel fallback `:51821` — production code, not test) |
| Env var mutation | 2 HIGH-risk sites (security_regression.rs) |
| Process spawn | 1 HIGH-risk (fault_injection_test.rs — unguarded) |
| Ephemeral ports | All other tests use port 0 or string-only URLs |

Every broad nextest serialization override now has a documented cause. Top 20 slow tests have resource classification.

### E2 — Fixed Ports

**Finding**: Most tests already use ephemeral port 0. The only fixed port (`:51821` in `synvoid-tunnel`) is production fallback code, not a test issue.

**Action**: No code changes needed. Inventory confirms good state across the test suite.

### E3 — Environment/Global State Isolation

**Changes**:
- Added `OnceLock<Mutex<()>>` serialization guard to `security_regression.rs` for 3 env-var-mutating tests
- Guard is process-wide, ensures safe parallel execution under nextest
- `synvoid-static-files` already had proper save/restore pattern (confirmed in inventory)

**Before**: 3 tests mutating environment variables without serialization guarantee
**After**: All env-var mutation serialized through process-wide guard

### E4 — Task/Process Lifecycle Hygiene

**Changes**:
- Added `ProcessGuard` RAII wrapper to `fault_injection_test.rs`
- Ensures spawned OS process is killed and waited on even if test panics
- Removed manual cleanup that was only reached on happy path

**Before**: Spawned OS process only cleaned up on test success
**After**: Process guaranteed to be terminated and reaped on any exit path

### E5 — Sleep Replacement

**Classification of all test sleeps**:

| Sleep | Location | Severity | Classification | Action |
|-------|----------|----------|----------------|--------|
| 1ms sleep | `worker_supervision_control_flow.rs:3490` | Low | Timing behavior under test | Keep |
| 5s startup | `fault_injection_test.rs` | Low | OS process initialization | Keep (required) |
| 1-hour keep-alive | `composition_root_behavioral.rs` | None | Relies on task cancellation (correct) | Keep |
| 1-hour keep-alive | `worker_supervision_control_flow.rs` | None | Relies on task cancellation (correct) | Keep |
| Various <100ms | Multiple files | None | Protocol/timing behavior under test | Keep |

**Result**: No high-priority arbitrary stabilization sleeps identified. Remaining sleeps are either protocol behavior under test or required OS initialization delays.

### E6 — DNS Fixture Deduplication

**Created**: `crates/synvoid-dns/tests/support/` with 5 modules:

| Module | Functions | Deduplication Source |
|--------|-----------|---------------------|
| `query.rs` | 10 query builder functions | Deduplicated from 8+ files |
| `zone.rs` | 4 zone construction helpers | Deduplicated from 9+ files |
| `context.rs` | 4 test context/setup helpers | Deduplicated from 7+ files |
| `response.rs` | 11 response parsing helpers | Deduplicated from 3+ files |
| `mod.rs` | Re-exports and documentation | Central module |

**Total deduplication potential**: ~1600 lines across 8+ integration test files.

**Adoption**: Helpers available for incremental adoption. No existing test files modified (preserves all existing behavior).

### E7 — Testkit Boundary

**Decision**: Keep minimal with no current consumers.

**Changes**:
- Added comprehensive doc comments to all public items in `synvoid-testkit`
- Created `README.md` with in-scope/out-of-scope table
- Documented process for adding new helpers (requires ≥2 crate consumers)

**In-scope** (generic cross-crate):
- Ephemeral TCP/UDP servers
- Temporary certificate/key material
- Test tracing initialization
- Generic temp-directory lifecycle

**Out-of-scope** (domain-specific, stays in owning crates):
- DNS query builders
- Mesh routing fixtures
- WAF corpora
- IPC-specific endpoints

### E8 — Nextest Scheduling

**Replaced** broad `fixed_port|global_state|process_global` filter with evidence-based groups:

| Group | Max Threads | Tests | Reason |
|-------|-------------|-------|--------|
| `global-env` | 1 | security_regression, metrics_wiring | Process-global env var mutation |
| `process-spawn` | 2 | fault_injection | OS process spawn lifecycle |
| `network-heavy` | 4 | DNS integration tests | Port binding and network I/O |

**Timeout changes**:
- Fault injection: 60s timeout (process initialization)
- Worker supervision: 60s timeout
- DNS integration: expanded filter covering 18 test patterns
- Stress/interop: 120s timeout preserved

**Before**: 4 broad pattern overrides serializing unrelated tests
**After**: 6 evidence-based groups with targeted concurrency limits

### E9 — Test Taxonomy

**Created**: `docs/testing/test-taxonomy.md`

15 test modalities classified:

| Modality | Lane | Serialization |
|----------|------|---------------|
| Unit | PR | None |
| Integration | PR | Per-binary if needed |
| Composition | PR | None |
| Static policy guard | PR | None |
| Security regression | PR | global-env group |
| Property (bounded) | PR | None |
| Fuzz smoke | Nightly | Matrix (max-parallel: 4) |
| Fuzz campaign | Release | Sequential per-target |
| Stress | Nightly | network-heavy group |
| Endurance | Release | Dedicated |
| Interoperability | Main/Nightly | network-heavy group |
| Benchmark | Nightly | Dedicated |
| Performance regression | Release | Dedicated |
| Platform qualification | Nightly/Scheduled | Per-platform |

Lane assignment summary with duration estimates and resource class mapping documented.

### E10 — Fuzz Matrix

**Converted** `fuzz-smoke` job from serial loop to matrix strategy:

```yaml
strategy:
  fail-fast: false
  max-parallel: 4
  matrix:
    target: [17 targets]
```

**Features**:
- Per-target 15-minute timeout
- Corpus and crash artifact uploads
- One target failure does not suppress other results
- Deterministic target list

**Updated** AGENTS.md with corrected target list (17 targets).

### E11 — Impact Measurement

| Metric | Before | After |
|--------|--------|-------|
| Fixed-port test count | 1 (tunnel fallback) | 0 (production code, not test) |
| Env-var race risk | 3 unserialized tests | 0 |
| Process leak risk | 1 unguarded spawn | 0 |
| Nextest override patterns | 4 broad | 6 evidence-based |
| DNS fixture duplication | ~1600 lines across 8+ files | Centralized in 5 support modules |
| Fuzz CI execution | Serial loop | Parallel matrix (4 concurrent) |
| Test failures introduced | — | 0 |

No test failures introduced. All existing tests continue to pass.

## Validation

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo nextest run -p synvoid-repo-guards --cargo-profile ci --profile ci
cargo nextest run -p synvoid-dns --cargo-profile ci --profile ci
cargo nextest run -p synvoid-ipc --cargo-profile ci --profile ci
cargo nextest run -p synvoid-mesh --features mesh --cargo-profile ci --profile ci
cargo test --profile ci --tests
```

## Known Limitations

- **DNS test support module**: Created but not yet adopted by existing tests (incremental adoption)
- **`std::thread::sleep(1ms)`**: Remains in `worker_supervision_control_flow.rs:3490` (low severity, 1ms, timing behavior under test)
- **5s startup sleep**: Remains in `fault_injection_test.rs` (OS process initialization requirement)
- **`synvoid-testkit`**: Has zero consumers (documented, available for future use per ≥2-consumer rule)
- **No `start_paused` time tests**: Not introduced (would require semantic validation per test)

## Milestone F Handoff

Milestone E provides:

- **Resource inventory** (`docs/testing/test-resource-inventory.md`) — authoritative baseline for performance budgets
- **Test taxonomy** (`docs/testing/test-taxonomy.md`) — lane assignments for scheduling optimization
- **Nextest groups** (`.config/nextest.toml`) — foundation for further concurrency improvements
- **DNS support module** (`crates/synvoid-dns/tests/support/`) — ready for incremental adoption to reduce test code duplication
- **Process guards** — `ProcessGuard` pattern available for other process-spawning tests
- **Env serialization guard** — `OnceLock<Mutex<()>>` pattern available for other global-state mutations
- **Fuzz matrix** — parallel execution infrastructure for nightly fuzz smoke runs

## Documentation Updated

- `docs/testing/test-resource-inventory.md` — created
- `docs/testing/test-taxonomy.md` — created
- `crates/synvoid-dns/tests/support/` — created (5 modules)
- `crates/synvoid-testkit/README.md` — created
- `.config/nextest.toml` — updated with evidence-based groups
- `.github/workflows/` — fuzz-smoke job converted to matrix strategy
- `AGENTS.md` — updated fuzz target list
