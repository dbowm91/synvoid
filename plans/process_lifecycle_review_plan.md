# Process Lifecycle Module Review Plan

## Verified Correct Items

- **Supervisor is default mode**: `src/main.rs:539-547` confirms that when no mode flags are specified, `run_supervisor_mode()` is called - the document is accurate here.
- **UnifiedServerWorker handles HTTP/HTTPS/HTTP3**: `src/worker/unified_server.rs:174` confirms `run_unified_server_worker` handles all three protocols.
- **StaticWorker for background tasks**: `src/worker/mod.rs:96` confirms `run_static_worker` handles CSS/JS minification and compression.
- **CPU affinity via sched_setaffinity**: `src/worker/unified_server.rs:183-203` confirms CPU affinity is set via `nix::sched::sched_setaffinity` on Linux. Warning is logged on non-Linux Unix platforms.
- **SO_REUSEPORT for kernel load balancing**: Multiple files confirm reuse_port is used - `src/overseer/spawn.rs:126-127`, `src/process/manager.rs:583`.
- **Shared-nothing architecture**: Workers operate independently with separate IPC channels.
- **gRPC control API**: Supervisor hosts gRPC control API per `src/supervisor/process.rs:114-134`.
- **ProcessManager spawns workers**: Both Supervisor and Master use `ProcessManager` to spawn workers.

## Stale/Incorrect Items

1. **Line 50 - `src/overseer/spawn.rs:43` reference is partially correct but context wrong**:
   - Document says "Initial workers use `reuse_port: false` (default). See `src/overseer/spawn.rs:43`"
   - Actual: `SpawnConfig::for_current_binary` (line 30-48) sets `reuse_port: false` by default - this is correct.
   - However, the reference to "see `src/overseer/spawn.rs:43`" points to middle of file (line 43 is within the struct initialization). A better reference would be line 30-48.

2. **Line 15 - Overseer key logic path `src/overseer/` is correct**, but the description is outdated:
   - Overseer code still exists in `src/overseer/` and is still invoked via `run_overseer_mode()` in `src/startup/master.rs:89`
   - **However**, Overseer mode CAN be invoked via `--master` flag (line 529-531 in main.rs), not via a dedicated overseer flag.

3. **Line 32 - "Legacy Mode (code only, not selectable)" is INCORRECT**:
   - The document claims Legacy Mode "cannot be invoked - there's no CLI flag to enable it"
   - **This is wrong**: Running `synvoid --master` actually invokes `run_master_mode()` in `src/startup/master.rs:23`, not `run_overseer_mode()`.
   - However, `run_overseer_mode()` exists at line 89 of `src/startup/master.rs` and IS callable via the process hierarchy (Overseer spawns Master, which spawns Workers).
   - The actual CLI flow is: No flag -> Supervisor. `--master` -> Master. `--mesh-agent` -> MeshAgent.

4. **Worker process terminology inconsistency**:
   - Document says "BaseWorkerProcess" at line 47
   - Actual CLI flag is `--worker` (line 43 in main.rs)
   - The spawn code uses `ProcessMode::Worker { worker_id, port }` in `src/overseer/spawn.rs:95-100`
   - There's no explicit "BaseWorkerProcess" struct name visible in main.rs or worker/mod.rs

## Bugs Found

1. **No bugs identified** - The architecture document accurately describes the process hierarchy as implemented.

## Security Concerns

1. **Overseer spawns Master with implicit trust**: In legacy Overseer->Master->Worker flow, there's no authentication shown between Overseer and Master processes. The document doesn't mention any IPC signing requirement for this hierarchy.

2. **Windows command pipe allows unsigned read-only commands**: `src/startup/master.rs:949-955` shows that Status and HealthCheck commands are accepted unsigned with a note that "Future releases should require signing for all commands when a signing key is configured."

## Document Update Recommendations

1. **Line 15**: Add clarification that Overseer is invoked via `--master` flag which spawns the Master process, and Overseer manages the Master process lifecycle.

2. **Line 25**: Update "Key Logic" reference from `src/startup/master.rs` to include the actual entry point `run_master_mode()`.

3. **Line 32**: Clarify the Legacy Mode invocation path. When `--master` flag is used:
   - If mesh feature is enabled and `run_master_mode()` is called directly (line 531 in main.rs)
   - The full Overseer->Master->Worker hierarchy is still used by `run_overseer_mode()` which spawns Master process

4. **Line 43**: Consider adding the actual CLI flag `--worker` for the Legacy Worker (BaseWorkerProcess) since this is what appears in `main.rs:43-44`.

5. **Line 47**: Consider clarifying what "requires further investigation" means - the code exists but is not invoked by any CLI flag in main.rs.

6. **Lines 33-38**: Add explicit note about gRPC API (`proto/control.proto`) being located in `proto/` directory rather than just saying "hosts the formal Control Plane API".

7. **CPU Pinning section**: The document correctly states CPU affinity is Linux-only and logs warning on other platforms. This is accurate based on `src/worker/unified_server.rs:205-212`.
