# MaluWAF Deferred Work

**Status**: Implementation plan completed. Only deferred items remain.
**Last Updated**: 2026-05-04

---

## Deferred Items

### Testing Infrastructure

| Item | Priority | Status | Notes |
|------|----------|--------|-------|
| Sandbox Leak Test | Low | DEFERRED | Test infrastructure incomplete |
| Socket Hijack Test | Low | DEFERRED | Test infrastructure incomplete |

### Plugin Isolation

| Item | Priority | Status | Notes |
|------|----------|--------|-------|
| Wire `GlobalWasmMemoryBudget::try_allocate()` into `WasmRuntime::load()` | High | DEFERRED | Requires significant refactoring |
| Plugin lifecycle leak (`std::mem::forget`) | Low | DEFERRED | Intentional design decision |

### Health & Observability

| Item | Priority | Status | Notes |
|------|----------|--------|-------|
| Health API (`/health/extensions`) | Medium | DEFERRED | ExtensionRegistry not integrated |

### Config Reload

| Item | Priority | Status | Notes |
|------|----------|--------|-------|
| Accurate reload status reporting | Medium | DEFERRED | |
| Incremental rebuild for site config changes | Medium | DEFERRED | |
| Fix mesh blocking reload behavior | Medium | DEFERRED | |

### Runtime Ownership

| Item | Priority | Status | Notes |
|------|----------|--------|-------|
| Track all spawned tasks in `task_handles` | Medium | DEFERRED | |
| Await DHT routing initialization | Medium | DEFERRED | |

### Performance Optimizations (Low Priority)

| Item | Priority | Status | Notes |
|------|----------|--------|-------|
| DHT routing optimization | Low | DEFERRED | Current implementation adequate for <10k nodes |
| HTTP/3 response header filtering | Medium | DEFERRED | Low traffic path |
| PowerShell → native Windows APIs | Low | DEFERRED | PowerShell resolver works |
| IPC framing copy optimization | Low | DEFERRED | Not on request hot path |

### Documentation

| Item | Priority | Status | Notes |
|------|----------|--------|-------|
| Threat Feed Export Documentation (P3.2) | Low | DEFERRED | |

---

## Future Recommendations

1. **DHT Routing Optimization**: For 100k+ node scale, current Kademlia bucket iteration becomes bottleneck
2. **HTTP/QUIC Stream Pooling**: Could be combined with W2.4 for better mesh latency
3. **Advanced DHT Routing**: Current implementation adequate for <10k nodes

---

## Verification Commands

```bash
# Core profile (minimal)
cargo check --no-default-features

# Mesh profile
cargo check --no-default-features --features mesh

# DNS profile
cargo check --no-default-features --features dns

# Full profile
cargo check --no-default-features --features mesh,dns

# Security regression tests
cargo test --test security_regression
```

(End of file - 420 lines)