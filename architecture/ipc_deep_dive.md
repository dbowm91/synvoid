# IPC & Process Deep Dive

SynVoid's inter-process communication layer handles Supervisor ↔ Worker communication via Unix domain sockets (Windows named pipes) with signed messages. File descriptor passing for socket handoff is a separate path owned by `synvoid-platform`, not by `synvoid-ipc`.

## Architecture

### Transport Layer (`synvoid-ipc`)

- **Unix domain sockets** (Windows named pipes via `ipc_windows.rs`)
- **HMAC-SHA3-256 signed messages** for authentication and integrity (constant-time verification)
- **Message framing**: Length-prefixed Postcard-encoded messages
- **Non-blocking I/O** with `tokio::net::UnixStream`
- **FD passing (`SCM_RIGHTS`)** lives in `crates/synvoid-platform/src/unix.rs`
  behind the root `socket-handoff` default feature — not in `synvoid-ipc`

### Message Protocol

All IPC messages use the `Message` enum (125 variants) serialized with Postcard:

```rust
enum Message {
    // Worker lifecycle
    WorkerStarted { worker_id, pid, socket_path },
    WorkerReady { worker_id },
    WorkerHeartbeat { worker_id, metrics },
    
    // Drain protocol
    DrainRequest { timeout_secs, drain_id },
    StopAccepting { drain_id },
    StopAcceptingAck { drain_id, accepted, active_connections },
    DrainStatusRequest { drain_id },
    DrainStatusResponse { drain_id, is_draining, active_connections },
    
    // Blocklist sync
    BlocklistRequest { worker_id, from_version },
    BlocklistResponse { blocks, mesh_blocks, version },
    BlocklistUpdate { blocks, mesh_blocks, version },
    BlocklistEventUpdate { event_json, source_node, event_id },
    
    // Configuration
    MasterConfigReload { config_path },
    MasterCertReload,
    UnifiedServerWorkerResize { worker_threads },
    
    // Mesh/Trust
    CanonicalTrustSnapshotUpdate { snapshot, generated_at_unix },
    RulePatternsUpdate { version, patterns },
    ThreatFeedUpdate { indicators, version, timestamp },
    // ... 50+ more variants
}
```

### Message Signing

Every IPC message is signed with HMAC-SHA3-256:
- **Session key**: one 32-byte random key per supervisor process, generated in
  `ProcessManagerConfig::default()` and handed to **every** worker it spawns (it is
  a shared supervisor/worker key, not a per-worker key). It reaches a worker through
  a `0600` temp file whose path is passed in `SYNVOID_IPC_KEY_FILE`; `SYNVOID_IPC_KEY`
  (raw key in the environment) is only a warned fallback gated on
  `allow_insecure_ipc_key`.
- **Signature**: 4-byte length prefix + 8-byte timestamp + 16-byte nonce + `[u8; 32]`
  HMAC, prepended to the serialized message (`SIGNED_MESSAGE_OVERHEAD = 60`, `ipc_signed.rs:50`)
- **Verification**: Supervisor validates worker signatures; workers validate supervisor signatures, using constant-time comparison (`ct_eq`)
- **Replay protection**: Nonce cache with 60-second timestamp window (`ipc_signed.rs`)

### File Descriptor Passing

Used for zero-copy socket handoff between processes (on Unix via SCM_RIGHTS):

```rust
// Supervisor → Worker: socket handoff request
SocketHandoffRequest {
    socket_path: String,  // Path to the listening socket
}

// Worker → Supervisor: handoff ready
SocketHandoffReady {
    ports: Vec<u16>,
}

// Worker → Supervisor: handoff complete
SocketHandoffComplete {
    success: bool,
    fd_count: usize,
}
```

### Connection Lifecycle

```
Worker Start
    │
    ▼
Connect to Supervisor Socket
    │
    ▼
Send WorkerStarted { worker_id, pid }
    │
    ▼
Receive SessionKey (via env var or IPC)
    │
    ▼
Send WorkerReady { worker_id }
    │
    ▼
Main IPC Loop
    ├── Send UnifiedServerWorkerHeartbeat (every 5s, `unified_server/lifecycle.rs:144`)
    ├── Receive BlocklistUpdate
    ├── Receive MasterConfigReload
    ├── Receive DrainRequest
    └── Send metrics/status updates
    │
    ▼
Worker Shutdown
    │
    ▼
Send WorkerShutdownComplete
    │
    ▼
Close Socket
```

## Key Types

| Type | Location | Purpose |
|------|----------|---------|
| `Message` | `synvoid-ipc/src/ipc.rs` | 125-variant IPC message enum |
| `IpcSigner` | `synvoid-ipc/src/ipc_signed.rs` | HMAC-SHA3-256 signing/verification |
| `IpcListener` | `synvoid-ipc/src/ipc_transport.rs` | Unix socket listener |
| `IpcStream` | `synvoid-ipc/src/ipc_transport.rs` | Unix socket stream |
| `SignedWriter` | `synvoid-ipc/src/ipc_signed.rs` | Signed write adapter |

## Security Considerations

- **Path permissions**: the IPC socket and its parent directory are created with `0o700` (owner-only, `socket_path.rs:200` and `:12`/`:44`). The `0o600` mode belongs to the **session-key temp files**, not the socket (`manager.rs:625`, `:653`).
- **Session isolation**: each supervisor instance has its own key, shared with all of its workers; workers of different supervisors cannot forge each other's messages (`signer_id` is the first 8 key bytes)
- **Message authentication**: All messages are HMAC-SHA3-256 signed with constant-time verification
- **Replay protection**: Nonce cache with timestamp window prevents replay attacks
- **FD validation**: Received FDs are validated before use
- **Socket cleanup**: `IpcListener::bind` **unconditionally** unlinks any pre-existing file at the socket path before binding (`ipc_transport.rs:176-181`) — there is no liveness/staleness probe, so a live peer's socket would also be removed
