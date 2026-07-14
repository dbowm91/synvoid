# Runtime Operations Drill

Phase 16 deliverable: reproducible operator drill steps for validating hardened architecture under realistic workflows.

## Environment

| Item | Value | Notes |
|------|-------|-------|
| OS | Linux (any recent kernel) | macOS acceptable for most drills |
| Privileges | Unprivileged user | No root required for localhost binds |
| Mesh | Optional single-node | Enabled for Drill 5 only |
| DNS | Feature-gated | Disabled for minimal drills |
| HTTP/3 | Feature-gated | Disabled for minimal drills |
| TLS/ACME | Disabled | No real certificates needed |
| Admin API | localhost:18081 | Test-only token |
| Plugins | Test fixtures only | Intentional failure fixtures |

### Preferred Local Drill Profile

- localhost-only bind addresses
- Temporary config directory under `/tmp/synvoid-ops-test/`
- Admin token generated for test only: `test-only-token-not-for-production`
- Mesh disabled unless Drill 5
- No real ACME external dependency
- Test plugin fixtures with intentional failure

## Test Fixtures

Config fixtures for drills are in `tests/fixtures/ops/`:

| Fixture | Purpose |
|---------|---------|
| `ops_minimal.toml` | Minimal localhost config for basic drills |
| `ops_mesh_single_node.toml` | Mesh-enabled single-node config |
| `ops_plugin_failure.toml` | Config referencing nonexistent plugin for failure drill |
| `ops_dns_disabled.toml` | Config with DNS explicitly disabled |
| `sites/test.localhost.toml` | Minimal site config for test domain |

**Warning**: All fixtures use test-only tokens and temporary paths. Never deploy these to production.

## Drill 1: Config Validation and Startup

### Steps

```bash
# Validate config
cargo run -- --config tests/fixtures/ops/ops_minimal.toml --configtest

# Start runtime (foreground, Ctrl-C to stop)
cargo run -- --config tests/fixtures/ops/ops_minimal.toml --foreground
```

### Expected Results

- Config validation succeeds (exit 0)
- Runtime starts with task registration logs
- Admin diagnostics endpoint available at `http://127.0.0.1:18081/`
- Logs include startup profile and task names
- No panics or missing-dependency errors

### Observability Signals

- Structured log line with `level=info` and startup profile
- Admin `/health` or `/diagnostics` returns 200
- Task registration messages in logs

## Drill 2: Status, Reload, Stop

### Steps

```bash
# Start in background (using the supervisor mode or foreground with PID tracking)
cargo run -- --config tests/fixtures/ops/ops_minimal.toml --foreground &
SYNVOID_PID=$!

# Check status (requires running instance and control socket)
cargo run -- --status

# Reload configuration
cargo run -- --rehash

# Graceful stop
cargo run -- --stop

# Verify no orphaned processes
kill -0 $SYNVOID_PID 2>/dev/null && echo "STILL RUNNING" || echo "STOPPED"
```

### Expected Results

- Status returns typed runtime/supervisor state
- Reload produces typed outcome (acknowledged or no-op if not running)
- Stop triggers graceful shutdown with typed `StopOutcome`
- Shutdown report includes joined/aborted task counts
- No orphaned processes remain

### Note

If no running instance is found, `--status` and `--stop` return `ConnectionUnavailable` error. This is expected behavior and should be documented.

## Drill 3: Admin Block/Unblock and Audit

### Steps

Exercise admin block/unblock via the test in the test suite:

```bash
cargo test --test admin_mutation_blocklist
```

Or via direct API calls to the admin endpoint:

```bash
# Block an IP
curl -X POST http://127.0.0.1:18081/api/admin/block \
  -H "Authorization: Bearer test-only-token-not-for-production" \
  -H "Content-Type: application/json" \
  -d '{"ip": "203.0.113.10", "reason": "drill-test"}'

# Verify block applied (typed AdminMutationResult with status=Applied)
# Block again (expect NoOpAlreadyPresent or DuplicateIgnored)
# Unblock (expect Applied)
# Unblock again (expect NoOpAlreadyAbsent)
```

### Expected Results

- Block returns `AdminMutationResult` with `status: "Applied"` and `local_store_mutated: true`
- Duplicate block returns `DuplicateIgnored` or refresh behavior
- Unblock returns `Applied`
- Double unblock returns `NoOpAlreadyAbsent`
- Audit events emitted with no raw session tokens
- Propagation status says `QueuedBestEffort` or local-only

### JSON Example

```json
{
  "status": "Applied",
  "target": "203.0.113.10",
  "message": "IP blocked",
  "local_store_mutated": true,
  "event_id": "evt-abc123",
  "audit_id": "aud-def456",
  "propagation": {
    "status": "QueuedBestEffort"
  }
}
```

### Observability Signals

- Admin audit log entry with `AdminMutationAuthority::AdminManual`
- BlockStore write event in metrics
- No raw token in audit event

## Drill 4: Plugin Failure and Capability Denial

### Steps

```bash
cargo test -p synvoid-plugin-runtime --test plugin_failure_does_not_poison_manager
cargo test --test plugin_capability_boundary_guard
cargo test --test plugin_signature_policy_guard
```

### Expected Results

- Manifest parsing failures are isolated per-manifest
- Capability violations disable only the violating guard
- Manager remains usable after individual plugin failures
- Repeated timeouts do not poison other plugins
- Concurrency exhaustion is per-plugin
- All guards share no state

### Observability Signals

- Plugin failure logged with plugin name (no high-cardinality labels)
- `PluginRuntimeState::DisabledByRuntimeFailure` for failed guards
- Manager operational metrics unchanged

## Drill 5: Mesh / Blocklist Convergence Smoke

### Steps (Single-Node)

```bash
cargo test -p synvoid-mesh --test mesh_forced_cleanup --features mesh
cargo test --test mesh_task_ownership_guard --features mesh,dns
cargo test --test mesh_admin_edge_cases --features mesh,dns
```

### Steps (Two-Node, if feasible)

```bash
# Start node A with config mesh_single_node on port 19000
# Start node B on port 19001 with separate data dir
# Block IP on node A
# Verify node B receives event or catchup/snapshot repair path
# Disconnect node B, reconnect, verify cursor/catchup status
# Unblock and ensure stale old block does not resurrect
```

### Expected Results

- Mesh tasks register and shut down cleanly
- Blocklist cursor persistence verified
- Snapshot/catchup helper functions work via tests
- Convergence health visible via admin diagnostics
- Request path remains local-only
- Mesh propagation described as best-effort

### Observability Signals

- Mesh peer connection/disconnection logs
- Blocklist event log entries
- DHT record updates (if applicable)

## Drill 6: Degraded Feature/Profile Behavior

### Steps

```bash
# Core only (no features)
cargo check --no-default-features

# Mesh only
cargo check --no-default-features --features mesh

# DNS only
cargo check --no-default-features --features dns

# Full mesh+dns
cargo check --no-default-features --features mesh,dns

# Default features
cargo check
```

### Expected Results

- All profile combinations compile successfully
- Disabled features fail closed or no-op explicitly
- Logs do not imply enabled protection when disabled
- Admin diagnostics show capability/profile state
- No linker errors or missing feature gates

### Observability Signals

- Feature gate compilation flags visible in build output
- Runtime startup logs show enabled/disabled subsystems

## Observability Checklist

| Drill | Logs | Metrics | Admin Diagnostic | Audit Event | Notes |
|-------|------|---------|------------------|-------------|-------|
| 1: Config/Startup | ✓ | ✓ | ✓ | — | Task registration visible |
| 2: Status/Reload/Stop | ✓ | ✓ | ✓ | — | Shutdown report typed |
| 3: Block/Unblock | ✓ | ✓ | ✓ | ✓ | AdminMutationResult typed |
| 4: Plugin Failure | ✓ | ✓ | — | — | Manager isolation verified |
| 5: Mesh Convergence | ✓ | ✓ | ✓ | — | Best-effort propagation |
| 6: Degraded Features | ✓ | — | ✓ | — | Profile state visible |

## Verification Commands

```bash
# Format check
cargo fmt --all -- --check

# Profile matrix
cargo check --no-default-features
cargo check --no-default-features --features mesh
cargo check --no-default-features --features dns
cargo check --no-default-features --features mesh,dns
cargo check

# Architecture verification script
./scripts/verify_architecture.sh

# Drill-specific tests
cargo test --test failure_injection
cargo test --test admin_mutation_blocklist
cargo test -p synvoid-plugin-runtime --test plugin_failure_does_not_poison_manager
cargo test --test security_observability_guard
cargo test --test plugin_capability_boundary_guard
cargo test --test plugin_signature_policy_guard

# Mesh drills (require mesh features)
cargo test -p synvoid-mesh --test mesh_forced_cleanup --features mesh
cargo test --test mesh_task_ownership_guard --features mesh,dns
```

## Corrective Patch Priority

If drill reveals blocking issues, fix in this order:

1. Dangerous false-success reports
2. Token/secret leakage
3. Runtime shutdown hangs/leaks
4. Plugin sandbox bypass
5. Admin mutation/audit inconsistency
6. Missing docs for intentional no-op/degraded behavior
7. Observability gaps

Do not patch around runtime failures by weakening guards or changing expectations without code evidence.
