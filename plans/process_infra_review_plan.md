# Process & Infrastructure Review Plan

**Reviewed:** 2026-05-28
**Documents:** supervisor.md, worker_architecture.md, process_lifecycle.md, ipc_process.md, drain.md, platform.md, platform_deep_dive.md

## Verified Correct Items

- **SupervisorProcess struct** (`src/supervisor/process.rs:30-38`): Fields match documented layout exactly
- **SupervisorProcess::new** (`src/supervisor/process.rs:41-64`): Signature matches documented `pub async fn new(state, pm_config)`
- **run_supervisor_mode** (`src/supervisor/process.rs:315`): Exists at stated location
- **Constants** (`src/supervisor/process.rs:20-21`): `DRAIN_POLL_INTERVAL_MS = 100`, `DEFAULT_DRAIN_TIMEOUT_SECS = 30` correct
- **Tokio runtime** (`src/supervisor/process.rs:363-367`): 4 worker threads confirmed
- **Runtime dir** (`src/supervisor/process.rs:377-380`): `XDG_RUNTIME_DIR` fallback to `/var/run` confirmed
- **DrainManager struct** (`src/supervisor/drain_manager.rs:20-25`): All fields match
- **DrainManager methods**: `start_drain`, `register_worker`, `update_worker_connections`, `wait_for_drain`, `drain_worker_with_confirmation` all exist
- **drain_aware_shutdown** (`src/supervisor/process.rs:198-272`): Full drain protocol implementation exists
- **Platform enum** (`src/platform/mod.rs:21-30`): All 8 variants match
- **Platform capability methods** (`src/platform/mod.rs:110-183`): All documented methods exist
- **is_admin_required_for_tun** (`src/platform/mod.rs:166-176`): Returns `false` for Unix, `true` for Windows/Unknown - correct per AGENTS.md
- **ProcessManagerConfig** (`src/process/manager.rs:38-60`): All fields present
- **ProcessEvent enum** (`src/process/manager.rs:117-129`): All variants match documented list
- **BaseWorkerProcess** (`src/process/worker.rs:47-54`): Fields match
- **WorkerProcess** (`src/process/worker.rs:93-101`): Fields match
- **StaticWorkerProcess** (`src/process/worker.rs:158-162`): Fields match
- **UnifiedServerWorkerProcess** (`src/process/worker.rs:185-192`): Fields match
- **Message enum exists** (`src/process/ipc.rs:305`): 60+ variants confirmed
- **MessageCategory enum** (`src/process/ipc.rs:1553-1572`): 18 categories (not 17 as stated in ipc_process.md)
- **DrainRequest/DrainStatusRequest/DrainStatusResponse/StopAccepting** all exist in Message enum
- **IpcSigner struct** (`src/process/ipc_signed.rs:114-117`): `signer_id: u64, key: [u8; 32]` matches
- **IpcSigner::try_from_env** (`src/process/ipc_signed.rs:149`): Exists, reads `SYNVOID_IPC_KEY_FILE`
- **IpcSigner::verify** uses `subtle::ConstantTimeEq` (`src/process/ipc_signed.rs:225,243`): Confirmed
- **Signed IPC constants** (`src/process/ipc_signed.rs:49-53`): `HMAC_SIZE=32`, `TIMESTAMP_SIZE=8`, `NONCE_SIZE=16`, `SIGNED_MESSAGE_OVERHEAD=60`, `MAX_IPC_MESSAGE_SIZE=1,048,576` all correct
- **MAX_NONCE_CACHE_SIZE** (`src/process/ipc_signed.rs:69`): 10,000 confirmed
- **REPLAY_WINDOW_SECS** (`src/process/ipc_signed.rs:70`): 60 confirmed
- **MAX_WORKERS_TRACKED** (`src/process/ipc_rate_limit.rs:27`): 10,000 confirmed
- **MAX_STRING_LENGTH/MAX_PATH_LENGTH** (`src/process/ipc.rs:805-806`): 64KB/4KB confirmed
- **validate()** (`src/process/ipc.rs:829`): Path traversal checks confirmed
- **ControlPlane gRPC service** (`src/supervisor/api.rs:14-18`): All 5 RPCs confirmed
- **start_grpc_server** (`src/supervisor/api.rs:131`): Signature includes `tls_config: Option<InternalTlsConfig>` (newer than documented)
- **SupervisorState** (`src/supervisor/state.rs:17-35`): All fields match (with cfg(feature="mesh") gates)
- **mesh feature** (`Cargo.toml:33`): `mesh = ["synvoid-config/mesh", "dep:openraft"]` matches
- **macos-sandbox feature** (`Cargo.toml:38`): `macos-sandbox = []` exists
- **BufferPool** has **4 tiers** (small/medium/large/jumbo) at `crates/synvoid-utils/src/buffer/pool.rs:200-208`
- **SupervisorModule structure** (`src/supervisor/mod.rs`): Public API surface matches (including `cli_commands`, `drain_manager`, `ipc` which are not in the documented module list but exist)

## Discrepancies Found

### process_lifecycle.md
- **[line 7]**: "The Overseer is the top-level orchestrator that spawns and monitors the Master process" — **`src/overseer/` does not exist**. The directory has been removed. The Overseer is legacy dead code.
- **[line 17]**: "The `run_overseer_mode()` function exists in `src/startup/master.rs:89`" — **`src/startup/master.rs` does not exist**. No `run_overseer_mode()` or `run_master_mode()` functions exist anywhere in `src/`.
- **[line 20-28]**: Master process section references `src/startup/master.rs`, `src/master/` — **neither directory exists**.
- **[line 34]**: "Supervisor replaces Overseer + Master, spawning workers directly via `run_supervisor_mode()` (`src/main.rs:541-546`)" — The call is at `src/main.rs:531-537`, not 541-546.
- **[line 36]**: "the Supervisor does not currently implement drain coordination" — **Contradicted by actual code**. `SupervisorProcess::drain_aware_shutdown()` at `src/supervisor/process.rs:198-272` implements full drain coordination with `DrainManager` and `DrainProtocol`.
- **[line 55]**: "the Supervisor does not currently support the `PortSwap` upgrade mode" — Needs verification; the `UpgradeModePayload` enum exists in `src/process/ipc.rs:1600` with `PortSwap` variant.
- **[line 56]**: "CPU Pinning: On Linux, workers are automatically assigned CPU affinity" — Confirmed in `src/main.rs` (`--cpu-affinity` flag), but not "automatic" — requires explicit flag.

### supervisor.md
- **[line 43]**: `run_master_mode()` at `src/master/mod.rs` — **`src/master/` does not exist**.
- **[line 157]**: `overseer/drain_manager.rs` — Actual location is `src/supervisor/drain_manager.rs`.
- **[line 207-238]**: `src/drain/mod.rs` DrainStatus/WorkerDrainState structs — The actual `DrainStatus` has additional fields not shown: `is_draining`, `connections_drained`, `drain_start`, `drain_elapsed_secs`, `drain_remaining_secs`, `drain_complete`. The actual `WorkerDrainState` has additional fields: `active_connections`, `idle_connections`, `connections_drained`, `drain_start`.
- **[line 244-264]**: IPC message types at `src/process/ipc.rs:729-761` — The actual line numbers are `730-754` (close but not exact).
- **[line 270-285]**: `ProcessManagerConfig` at `src/process/manager.rs:37-59` — Actual is lines `38-60`. Field `master_socket_path` is now `supervisor_socket_path` (line 49). Also missing documented field `log_level`, `pre_spawn_workers`, `warm_workers_target`, `health_check_interval_secs`, `control_api_tls`, `allow_insecure_ipc_key`, `ipc_rate_limit`.
- **[line 393-399]**: `start_grpc_server` signature at `src/supervisor/api.rs:129-144` — Actual line is `131` and includes `tls_config: Option<InternalTlsConfig>` parameter not shown in docs.
- **[line 639-641]**: Feature `mesh = ["synvoid-config/mesh", "dep:openraft"]` at Cargo.toml:33 — Correct.
- **[line 654-656]**: Feature `dns` at Cargo.toml:23 — Actual has additional deps: `dep:tokio-dstip`, `dep:cryptoki`, `dep:getrandom` not listed.
- **[line 694]**: `src/overseer/mod.rs` module list — **`src/overseer/` does not exist**.
- **[line 703-708]**: `src/master/mod.rs` — **`src/master/` does not exist**.
- **[line 764-778]**: Tokio runtime config at `process.rs:354-358` — Actual is at lines `363-367`.

### worker_architecture.md
- **[line 23-24]**: "Three tiers: small (4KB), medium (32KB), large (128KB)" — **Actual is 4 tiers**: small, medium, large, jumbo (256KB) at `crates/synvoid-utils/src/buffer/pool.rs:200-208`.

### ipc_process.md
- **[line 5]**: "able" appears on its own line — formatting artifact/typo.
- **[line 39]**: `worker.rs:47-54` for BaseWorkerProcess — Correct.
- **[line 63]**: `ipc_session_key: Option<[u8; 32]>` — Correct but missing from the field list is `allow_insecure_ipc_key: bool` (line 58 of manager.rs).
- **[line 76]**: "17 categories" — **Actual is 18 categories** in `MessageCategory` enum.
- **[line 82]**: "WorkerCertReload" listed under WorkerLifecycle — Correct per `ipc.rs:1393`.
- **[line 87]**: "OverseerUpgradePrepare, OverseerUpgradePrepareAck, OverseerUpgradeCommit..." — These use `Supervisor*` prefix in actual Message enum (`SupervisorUpgradePrepare`, etc. at ipc.rs), not `Overseer*`. Let me verify...

Actually, checking the Message enum more carefully:
- Line 1475 shows `SupervisorCommitUpgradeAck` etc., confirming the Supervisor naming is used in the Message enum for the Upgrade category. The doc lists `Overseer*` variants which may have been renamed.

- **[line 101-107]**: `SIGNED_MESSAGE_OVERHEAD: 60 bytes (4 + 8 + 16 + 32)` — Correct.
- **[line 110-117]**: `IpcSigner` struct — `signer_id: u64`, `key: [u8; 32]` correct.
- **[line 114-117]**: `IpcEnvelope` at `ipc_signed.rs:408-415` — The struct is `SignedIpcMessage` in actual code. Need to verify.
- **[line 230-237]**: `CommandClient` at `command.rs:20-66` — Exists.
- **[line 315]**: "Key passed to workers via temp file" — `try_from_env()` at `ipc_signed.rs:149` reads `SYNVOID_IPC_KEY_FILE`, and separately there is `read_ipc_key_file()` at line 598. The temp file creation would be in the supervisor/master side. The docs describe a temp-file-based key exchange; the `try_from_env()` implementation verifies file permissions (`mode & 0o222 == 0`, uid match) which is more secure than documented.

### drain.md
- **[line 18-26]**: `DrainStatus` struct — Missing fields: `is_draining`, `connections_drained`, `drain_start`, `drain_elapsed_secs`, `drain_remaining_secs`, `drain_complete`.
- **[line 27-33]**: `WorkerDrainState` struct — Missing fields: `active_connections`, `idle_connections`, `connections_drained`, `drain_start`.

### platform.md
- **[line 43]**: "supports_seatbelt()" listed in capability queries — **This method does not exist** on the `Platform` enum. macOS sandboxing is gated via `#[cfg(feature = "macos-sandbox")]` in `src/platform/sandbox.rs:1022`, not via a platform capability query.
- **[line 19-26]**: Module exports list `service` — `src/platform/service/` directory exists (verified: `mod.rs`, `stub_service.rs`, `windows_service.rs`). This is correct.
- **[line 117-125]**: `Signal` enum — `Status` and `User2` both map to `SIGUSR2`. This IS documented correctly at line 124-125 ("`User2` — `SIGUSR2 (also Status)`"). Not a documentation error, but a design quirk worth noting.
- **[line 636-654]**: Directory structure lists `service/` and `windows/` subdirectories — `src/platform/service/` exists. `src/platform/windows/` not found by glob (the `windows.rs` file exists but not a `windows/` directory).

### platform_deep_dive.md
- **[line 43]**: `platform().supports_seatbelt()` — **Method does not exist** on `Platform`.
- **[line 69]**: "Seatbelt sandboxing is not yet fully implemented" — This contradicts `platform.md:524` which says it IS implemented with feature gate. The code at `src/platform/sandbox.rs:1022-1029` shows it IS implemented but feature-gated (`#[cfg(all(target_os = "macos", feature = "macos-sandbox"))]`). The `platform_deep_dive.md` note is misleading — it should say "requires `macos-sandbox` feature" instead of "not yet fully implemented".
- **[line 107]**: "18 categories" — Correct, matches `MessageCategory` enum.
- **[line 115]**: "OverseerDrainWorkers" in category list — Actual code uses `SupervisorDrainWorkers` prefix.
- **[line 219-233]**: Startup module key files lists `master.rs` with `run_master_mode()`, `run_overseer_mode()` — **`src/startup/master.rs` does not exist**.
- **[line 258]**: `src/startup/master.rs:278-302` enforcement reference — File does not exist.
- **[line 403-405]**: Enforcement reference to `src/startup/master.rs:278-302` — File does not exist.

## Bugs Identified

- **[low] BUG-PROC-1**: `drain.md` and `supervisor.md` document `DrainStatus` and `WorkerDrainState` structs with fewer fields than actual implementation. The documented structs are incomplete snapshots. (Not a code bug, but a documentation accuracy issue that could mislead developers.)

- **[low] BUG-PROC-2**: `platform.md:117-125` documents `Signal::Status` and `Signal::User2` both mapping to `SIGUSR2`. This is either a documentation error or a design issue where two signal variants are conflated. (Need to verify actual signal mapping in `src/platform/process.rs`.)

## Suggested Improvements

### Documentation Accuracy
- **Remove all references to `src/overseer/`, `src/master/`, `src/startup/master.rs`** — These files/directories no longer exist. The Overseer and Master have been consolidated into the Supervisor.
- **Remove `--master` flag references** — The CLI has no `--master` flag in `src/main.rs`.
- **Remove `run_master_mode()` and `run_overseer_mode()` references** — These functions don't exist.
- **Update `SupervisorCommand` naming** — `ipc_process.md` documents `MasterCommand` but actual code uses `SupervisorCommand` (ipc.rs:23). Note: the `Message` enum still uses `MasterShutdown`, `MasterConfigReload` etc. naming which is the legacy naming but still present in code.
- **Update buffer pool tiers** — `worker_architecture.md` says 3 tiers; actual is 4 (small/medium/large/jumbo).
- **Update DrainStatus/WorkerDrainState structs** — Add missing fields to documentation.
- **Update ProcessManagerConfig** — Add missing fields (`log_level`, `pre_spawn_workers`, `warm_workers_target`, `health_check_interval_secs`, `control_api_tls`, `allow_insecure_ipc_key`, `ipc_rate_limit`), rename `master_socket_path` to `supervisor_socket_path`.
- **Fix MessageCategory count** — `ipc_process.md` says 17, actual is 18.
- **Remove `supports_seatbelt()` reference** — Replace with feature-gate documentation (`#[cfg(feature = "macos-sandbox")]`).
- **Update gRPC API signature** — Add `tls_config` parameter to `start_grpc_server`.
- **Update drain coordination status** — `process_lifecycle.md` says Supervisor lacks drain coordination, but it's fully implemented.
- **Fix platform.md directory structure** — `src/platform/service/` directory exists (verified: `mod.rs`, `stub_service.rs`, `windows_service.rs`). `src/platform/windows/` not found by glob (may not exist).
- **Update `platform_deep_dive.md` startup references** — Remove `master.rs` references.
- **Remove `Overseer*` message variant names from ipc_process.md** — All `Overseer*` variants in the Message enum have been renamed to `Supervisor*` prefix. The documentation still lists the old names.

### Code Quality
- **Consider renaming `MasterShutdown`/`MasterConfigReload` in Message enum** — These use legacy naming while the rest of the codebase uses `Supervisor*`. This is a breaking IPC protocol change that should be coordinated. The naming is currently inconsistent:
  - `MasterShutdown`, `MasterConfigReload`, `MasterProcessConfigReload`, `MasterSupervisorConfigReload`, `MasterHealthCheck`, `MasterResizeThreadpool`, `MasterCertReload` (legacy `Master*` prefix)
  - `SupervisorUpgradePrepare`, `SupervisorDrainWorkers`, `SupervisorDualSupervisorPrepare` (new `Supervisor*` prefix)
  - `SupervisorCommand` admin command type (new naming)
- **Consider adding `supports_seatbelt()` to Platform enum** — For API consistency with other capability queries, even if it just wraps the feature gate check.
- **Signal enum quirk**: `Signal::Status` and `Signal::User2` both map to `SIGUSR2` on Unix (`src/platform/unix.rs:326,328`). This is documented but may cause confusion — consider if both are needed or if `Status` should use a different signal.

### Security
- **`try_from_env()` key file permissions check** is more thorough than documented — includes uid match and mode check. Good.
- **Constant-time comparison** in IPC signing is confirmed (`subtle::ConstantTimeEq`).
- **Temp file security** (`O_NOFOLLOW`, `0o600`, immediate deletion) is confirmed.

## Stale Content

- **process_lifecycle.md entire sections 1-2** (Overseer/Master): References `src/overseer/`, `src/master/`, `src/startup/master.rs` which no longer exist. The document should be updated to reflect the consolidated Supervisor architecture.
- **supervisor.md sections 9.1-9.2** (Overseer/Master legacy): References non-existent `src/overseer/mod.rs` and `src/master/mod.rs` module lists.
- **supervisor.md section 2.7**: References `overseer/drain_manager.rs` — actual location is `src/supervisor/drain_manager.rs`.
- **platform_deep_dive.md sections 4**: References `src/startup/master.rs` which does not exist.
- **platform.md section 2.7**: References `service/` subdirectory which may not exist as a directory.
- **drain.md**: Struct definitions are incomplete snapshots of actual code.
- **worker_architecture.md**: Buffer pool tier count is outdated (3 vs actual 4).
- **ipc_process.md**: Lists `Overseer*` message variants (e.g., `OverseerUpgradePrepare`, `OverseerDrainWorkers`) — actual code uses `Supervisor*` prefix for all of these.
- **supervisor.md**: Section 10.3 references line numbers `354-358` for Tokio runtime — actual is `363-367`.
- **platform_deep_dive.md**: References `src/startup/master.rs` (lines 219-233, 258, 403-405) which does not exist.

## Cross-Reference Status

- **AGENTS.md "Known File Path Corrections"**: References to `src/http/client.rs` → `src/http_client/mod.rs` etc. are still accurate.
- **AGENTS.md "Verified Already Fixed" — PL-5 DrainManager ported to Supervisor**: Still accurate — `src/supervisor/drain_manager.rs` exists and `drain_aware_shutdown()` is implemented.
- **AGENTS.md "Process Hierarchy" table**: Lists `Supervisor`, `UnifiedServerWorker`, `StaticWorker`, `BaseWorkerProcess` — accurate. Note: `BaseWorkerProcess` description says "deprecated, unused for HTTP" which is accurate per `process_lifecycle.md:51`.
- **AGENTS.md "BaseWorkerProcess (Legacy - Not Used for HTTP)"**: Accurate — no HTTP handler for `--worker` mode in `main.rs`.
- **AGENTS.md "Default entry point"**: `run_supervisor_mode()` via `src/main.rs` — accurate.
- **AGENTS.md "Granian IS integrated"**: Not directly relevant to this module review.
- **AGENTS.md "Supervisor manages lifecycle, consolidates Supervisor"**: The wording is awkward ("consolidates Supervisor") — should say "consolidates Overseer + Master".
- **AGENTS.md feature gate verification**: Core/Mesh/DNS/Full profiles — need to verify compilation. The features `mesh` and `dns` in `Cargo.toml:22-23` match documented flags.
