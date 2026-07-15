# Test Resource Inventory

> **Milestone E** — Testing Infrastructure
> **Purpose**: Catalog every test that uses or mutates shared resources (ports, env vars, spawned processes, temp files, sleeps). Enables safe nextest parallelization, CI isolation, and targeted flake remediation.
> **Generated**: 2026-07-15
> **Scope**: All root integration tests (28 files) + per-crate test suites

---

## Summary

| Resource Type | Count | Risk Level | Notes |
|---|---|---|---|
| Fixed-port binds | 2 | **HIGH** | `synvoid-tunnel` only fixed bind; all others use ephemeral 0 or string-only |
| Env var mutations | 2 sites | **HIGH** | `security_regression.rs` — requires `--test-threads=1` |
| OS process spawns | 1 file | **HIGH** | `fault_injection_test.rs` — Unix-only, no panic guard |
| Tokio spawn (awaited) | ~37 tasks | **MEDIUM** | All awaited; no orphaned tasks |
| Sleep/timing sites | ~15 sites | **MEDIUM** | 100s max; `std::thread::sleep` blocks tokio |
| Temp files (RAII) | 26 `TempDir` | **LOW** | All RAII-managed, automatic cleanup |
| String-only ports (unbound) | 7 sites | **NONE** | Parsed or asserted, never bound |

---

## 1. Root Integration Tests — Port Usage

| File | Port(s) | Type | Bound? | Risk |
|---|---|---|---|---|
| `traffic_regression_test.rs` | `:8080`, `:8081`, `:8082`, `:9090` | Hardcoded in upstream/backend URL strings | No | NONE |
| `integration_test.rs` | 50051 (config struct), 2703-2931 (port 0) | Config struct + ephemeral TCP servers | No / Ephemeral | LOW |
| `worker_mesh_supervision_boundary_guard.rs` | `:443` | String assertion (config parsing) | No | NONE |

**Conclusion**: No fixed-port socket binds exist in root integration tests. All use ephemeral port 0 or string-only references.

---

## 2. Root Integration Tests — Environment Mutations

| File:Line | Var | Operation | Serialization | Risk |
|---|---|---|---|---|
| `security_regression.rs:58,60` | `SYNVOID_IPC_KEY_FILE` | `set_var` / `remove_var` | `--test-threads=1` enforced | **HIGH** |
| `security_regression.rs:79,81` | `SYNVOID_IPC_KEY_FILE` | `set_var` / `remove_var` | `--test-threads=1` enforced | **HIGH** |
| `security_regression.rs:177,179` | `SYNVOID_IPC_KEY_FILE` | `set_var` / `remove_var` | `--test-threads=1` enforced | **HIGH** |

**Proposed correction**: Replace ad-hoc `set_var`/`remove_var` with `OnceLock<Mutex<()>>` guard per-test to make serialization explicit and nextest-safe.

---

## 3. Root Integration Tests — Spawned Tasks/Processes

| File | Spawn Type | Count | Awaited? | Cleanup | Risk |
|---|---|---|---|---|---|
| `fault_injection_test.rs:24,36,50,60` | `Command::new(binary_path)` + `pgrep` + `kill -9` | 4 OS processes | N/A | `overseer.kill()` + `wait()` (no panic guard) | **HIGH** |
| `drain_e2e_test.rs` | `tokio::spawn` | 4 tasks | Yes (all `.await`) | RAII `TempDir` | LOW |
| `e2e_process_test.rs` | `tokio::spawn` | 6 tasks | Yes (all `.await`) | RAII `TempDir` | LOW |
| `integration_test.rs` | `tokio::spawn` | 12 tasks | Yes (all `.await`) | RAII `TempDir` | LOW |
| `worker_supervision_control_flow.rs` | `tokio::spawn` | 8 tasks | Yes (all `.await`) | sleep-based | MEDIUM |

**Proposed correction for `fault_injection_test.rs`**: Add `scopeguard` or RAII guard for process cleanup to prevent orphaned processes on panic.

---

## 4. Root Integration Tests — Sleeps and Timing

| File:Line | Duration | Purpose | Blocks Tokio? | Risk |
|---|---|---|---|---|
| `fault_injection_test.rs:32` | 5s hard sleep | Binary startup wait | No (likely `std::thread::sleep` or `tokio::time::sleep`) | MEDIUM |
| `fault_injection_test.rs:71` | 1s polling loop (up to 15s) | Health check poll | Depends on implementation | MEDIUM |
| `worker_supervision_control_flow.rs:573` | 100s | Task body (sleep-based) | Depends on context | LOW |
| `worker_supervision_control_flow.rs:3490` | 1ms | `std::thread::sleep(1ms)` | **YES — blocks tokio runtime** | MEDIUM |
| `worker_supervision_control_flow.rs` (12+ sites) | 10ms–100s | Various timing propagation | Mixed | MEDIUM |
| `failure_injection.rs:49,400,437` | 5ms–50ms | Timing propagation | Likely async | LOW |
| `composition_root_behavioral.rs:25,28` | 1 hour (cancel on drop) | Keep-alive for background tasks | Async (cancel on drop) | LOW |

**Proposed correction for `worker_supervision_control_flow.rs:3490`**: Replace `std::thread::sleep(1ms)` with `tokio::time::sleep(Duration::from_millis(1)).await` to avoid blocking the tokio runtime.

---

## 5. Root Integration Tests — Temp Files

| File | `TempDir::new()` Count | Cleanup Mechanism | Risk |
|---|---|---|---|
| `drain_e2e_test.rs` | 4 | RAII (drop) | NONE |
| `e2e_process_test.rs` | 7 | RAII (drop) | NONE |
| `integration_test.rs` | 7 | RAII (drop) | NONE |
| `security_regression.rs` | 8 | RAII (drop) | NONE |

All temp files are RAII-managed. No manual cleanup gaps.

---

## 6. Per-Crate Test Suites — Port Usage

| Crate | File | Port(s) | Bound? | Risk |
|---|---|---|---|---|
| `synvoid-dns` | `src/server/query.rs:2377` | Port 0 | Ephemeral | NONE |
| `synvoid-dns` | `tests/transport_lifecycle.rs:22` | Port 0 | Ephemeral | NONE |
| `synvoid-ipc` | `src/manager.rs:2398` | Port 0 | Ephemeral | NONE |
| `synvoid-mesh` | `tests/mesh_http_framing.rs:1066` | Port 0 | Ephemeral | NONE |
| `synvoid-http-client` | `src/erased_pool.rs:269-571` | Port 0 | Ephemeral (6 binds) | NONE |
| `synvoid-http-client` | `src/pool.rs:840-1040` | Fixed ports in URL strings | Not bound | NONE |
| **`synvoid-tunnel`** | **`src/quic/runtime.rs:431`** | **`0.0.0.0:51821`** | **Bound (fixed)** | **HIGH** |
| `synvoid-honeypot` | `src/listener_tests.rs:133-338` | Port 0 | Ephemeral (5 binds) | NONE |
| `synvoid-honeypot` | `responders/ai.rs:27,35` | `:11434` | Not bound (Ollama endpoint string) | NONE |
| `synvoid-waf` | `src/config_fixtures.rs:10` | `:8080` | Not bound (config string) | NONE |
| `synvoid-waf` | `src/attack_detection/ssrf.rs:587` | `:8080` | Not bound (detection input) | NONE |

**`synvoid-tunnel` is the only crate with a fixed-port socket bind in tests.**

**Proposed correction for `synvoid-tunnel`**: Change `0.0.0.0:51821` to `0.0.0.0:0` (ephemeral) unless the specific port is required for QUIC protocol testing. If the port must be fixed, serialize the test.

---

## 7. Per-Crate Test Suites — Other Resources

| Crate | Resource Type | Notes |
|---|---|---|
| `synvoid-static-files` | Env var mutations | Uses `OnceLock<Mutex<()>>` serialization — **already correct** |
| `synvoid-dns` | 1101 tests | All ephemeral, no shared resource conflicts |
| `synvoid-ipc` | — | No shared resource mutations |
| `synvoid-mesh` | — | Ephemeral only |
| `synvoid-proxy` | — | Ephemeral only |
| `synvoid-honeypot` | — | Ephemeral only |
| `synvoid-waf` | — | String-only ports |

---

## 8. Nextest Override Inventory

| Pattern | Override | Reason |
|---|---|---|
| `fixed_port\|global_state\|process_global` | `threads-required = "num-cpus"` | Env var or global state mutation |
| `security_regression` | `threads-required = "num-cpus"` | `SYNVOID_IPC_KEY_FILE` env mutation |
| `server_test\|config_fidelity\|recursive_isolation` | `timeout = 60s` | DNS integration suite timeout |
| `stress\|interop\|live_signing\|recursion` | `timeout = 120s` | Long-running DNS validation |

**Proposed additions**:
| Pattern | Override | Reason |
|---|---|---|
| `fault_injection` | `threads-required = 1` | OS process spawn, no panic guard |
| `worker_supervision_control_flow` | `timeout = 120s` | Contains 100s sleep |

---

## 9. Fixed-Port Inventory (Complete)

| Crate | File:Line | Port | Bound? | Correctable? |
|---|---|---|---|---|
| `synvoid-tunnel` | `src/quic/runtime.rs:431` | `51821` | Yes | Change to `:0` unless QUIC test requires it |

**All other port references are either ephemeral (`:0`) or string-only (never bound).**

**Retained fixed port rationale**: `0.0.0.0:51821` is a production fallback in `bind_address()` for malformed config — no test binds to it. No serialization rule required; this is not a test resource conflict.

---

## 10. Top Slow Tests (Estimated >10s)

| Test | Estimated Duration | Resource | Nextest Timeout |
|---|---|---|---|
| `fault_injection_test.rs` (suite) | 10–30s | OS process spawn, polling | None (needs addition) |
| `worker_supervision_control_flow` | 30–120s | 100s sleep, 8 tokio tasks | None (needs addition) |
| `composition_root_behavioral` | 30–60s | 1h keep-alive (cancel on drop) | Default |
| DNS `stress\|interop\|live_signing\|recursion` | 60–120s | Various | 120s (already configured) |
| DNS `server_test\|config_fidelity\|recursive_isolation` | 30–60s | Ephemeral binds | 60s (already configured) |

---

## 11. Proposed Corrections

| # | File | Issue | Severity | Fix |
|---|---|---|---|---|
| 1 | `security_regression.rs` | `set_var`/`remove_var` without explicit lock | **HIGH** | Add `OnceLock<Mutex<()>>` guard; remove `--test-threads=1` reliance |
| 2 | `fault_injection_test.rs` | No panic guard on process cleanup | **HIGH** | Add `scopeguard` or RAII wrapper around `Command` child |
| 3 | `synvoid-tunnel` `quic/runtime.rs:431` | Fixed port `51821` | **RESOLVED** | Production fallback for malformed config; no test binds to it — no serialization needed |
| 4 | `worker_supervision_control_flow.rs:3490` | `std::thread::sleep(1ms)` blocks tokio | **MEDIUM** | Replace with `tokio::time::sleep(Duration::from_millis(1)).await` |
| 5 | `worker_supervision_control_flow.rs` | 100s sleep as task body | **MEDIUM** | Add nextest override `timeout = 120s` |
| 6 | `fault_injection_test.rs` | No nextest timeout override | **MEDIUM** | Add `threads-required = 1` and `timeout = 60s` |
| 7 | `security_regression.rs` | Env mutation serialization depends on test harness flag | **MEDIUM** | Make serialization explicit via `OnceLock<Mutex<()>>` |

---

## Appendix A: Test Ownership Matrix

| Area | Owner | Lane | Profile | Serialization Required |
|---|---|---|---|---|
| Root integration tests | root | PR | ci | Per-test (see sections above) |
| `synvoid-dns` | DNS team | PR (main for full) | ci | No |
| `synvoid-ipc` | IPC team | PR | ci | No |
| `synvoid-mesh` | Mesh team | PR | ci | No |
| `synvoid-http-client` | HTTP team | PR | ci | No |
| `synvoid-proxy` | Proxy team | PR | ci | No |
| `synvoid-tunnel` | Tunnel team | PR | ci | **Yes** (fixed port) |
| `synvoid-honeypot` | Honeypot team | PR | ci | No |
| `synvoid-waf` | WAF team | PR | ci | No |
| `synvoid-static-files` | Static files team | PR | ci | Already serialized (`OnceLock`) |

---

## Appendix B: Resource Conflict Heatmap

```
                    Port    Env     Process  Sleep   Temp    Total
Root (28 files)     0       2       1        15      26      44
synvoid-dns          0       0       0        0       0       0
synvoid-ipc          0       0       0        0       0       0
synvoid-mesh         0       0       0        0       0       0
synvoid-http-client  0       0       0        0       0       0
synvoid-proxy        0       0       0        0       0       0
synvoid-tunnel       1       0       0        0       0       1
synvoid-honeypot     0       0       0        0       0       0
synvoid-waf          0       0       0        0       0       0
synvoid-static-files 0       1*      0        0       0       1
─────────────────────────────────────────────────────────────────
Total                1       3       1        15      26      46

* Already correctly serialized via OnceLock<Mutex<()>>
```
