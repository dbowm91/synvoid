# Process Lifecycle Architecture Review Plan

## Verified Correct
- **Default mode is Supervisor**: `run_supervisor_mode()` is called in the default `else` branch at `src/main.rs:541-546`
- **Legacy mode via --master flag**: `run_master_mode()` is called when `--master` flag is set at `src/main.rs:529-531`
- **Process hierarchy structure**: Overseer (src/overseer/) -> Master (src/startup/master.rs, src/master/) -> Supervisor (src/supervisor/) consolidated mode
- **UnifiedServerWorker**: Handles HTTP/HTTPS/HTTP3 + WAF + proxy, uses single Tokio async event loop (src/worker/unified_server.rs)
- **StaticWorker**: CSS/JS minification and compression (src/worker/)
- **BaseWorkerProcess**: Legacy raw TCP/UDP proxy, deprecated and not used for HTTP traffic
- **SO_REUSEPORT mechanism**: spawn_upgrade_worker() at src/process/manager.rs:558-612 handles reuse_port parameter for kernel load balancing during upgrades
- **Initial workers use reuse_port: false**: Confirmed at src/startup/worker.rs:42 in build_unified_server_worker_args
- **CPU pinning**: Implemented in spawn_unified_server_worker_with_id() at src/process/manager.rs:667-668
- **IPC over Unix domain sockets**: Confirmed in src/process/ipc.rs and src/process/ipc_transport.rs
- **gRPC control API**: Supervisor starts gRPC server on control_api_addr at src/supervisor/process.rs:114-134
- **Worker types and flags**: --worker (BaseWorkerProcess), --static-worker (StaticWorker), --unified-server-worker (UnifiedServerWorker), --mesh-agent

## Discrepancies Found
- **run_supervisor_mode() line numbers**: Document says "src/main.rs:538-547" but actual call is at lines 541-546 (the else block spans 538-547, the actual function call is at 541)
- **run_master_mode() line number**: Document says "src/main.rs:529" but actual call is at line 531 (line 529 is `} else if args.master {`)
- **Supervisor lacks DrainManager**: The Overseer has sophisticated drain coordination via DrainManager (src/overseer/drain_manager.rs), but Supervisor's graceful_shutdown() at src/supervisor/process.rs:1605 only sends SIGTERM to workers without connection draining
- **Drain coordination not documented**: The architecture mentions "Zero-Downtime Upgrades" but doesn't clarify that proper drain coordination (DrainManager) only exists in Overseer/Legacy mode, NOT in Supervisor/Consolidated mode
- **run_overseer_mode() exists but undocumented**: run_overseer_mode() exists at src/startup/master.rs:89-203 but is NOT exposed via CLI flags and not documented in the architecture

## Bugs Identified
- **Missing drain coordination in Supervisor (Medium)**: When Supervisor (consolidated mode) performs graceful shutdown or upgrades, it does NOT properly drain active connections before terminating workers. It only sends SIGTERM and waits. The Overseer has proper DrainManager that coordinates connection draining with workers, but this is NOT available in Supervisor mode. This could cause connection drops during upgrades in consolidated mode.

## Suggested Improvements
1. **Document drain coordination limitation**: Architecture should clarify that Supervisor mode lacks the DrainManager available in Overseer mode
2. **Fix line number references**: Update documentation to reflect actual line numbers (541 for run_supervisor_mode, 531 for run_master_mode)
3. **Add Overseer to process hierarchy diagram**: run_overseer_mode() exists and should be documented or removed if deprecated
4. **Clarify upgrade path**: Document that SO_REUSEPORT upgrades only work properly via Overseer, not directly via Supervisor
5. **Consider porting DrainManager to Supervisor**: For true zero-downtime upgrades in consolidated mode, Supervisor should have equivalent drain coordination

