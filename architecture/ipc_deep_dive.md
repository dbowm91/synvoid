# IPC & Process Deep Dive

SynVoid's inter-process communication layer handles all Supervisor ↔ Worker and Worker ↔ Worker communication via Unix domain sockets with signed messages and file descriptor passing.

## Architecture

### Transport Layer (`synvoid-ipc`)

- **Unix domain sockets** with `SCM_RIGHTS` for FD passing
- **HMAC-SHA3-256 signed messages** for authentication and integrity (constant-time verification)
- **Message framing**: Length-prefixed Postcard-encoded messages
- **Non-blocking I/O** with `tokio::net::UnixStream`

### Message Protocol

All IPC messages use the `Message` enum (~118 variants) serialized with Postcard:

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
- **Session key**: 32-byte random key exchanged via `SYNVOID_IPC_KEY_FILE` env var or file-based key exchange at startup
- **Signature**: `[u8; 32]` (HMAC) + 8-byte timestamp + 16-byte nonce appended to serialized message
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
    ├── Send WorkerHeartbeat (every 5s)
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
| `Message` | `synvoid-ipc/src/ipc.rs` | ~118 variant IPC message enum |
| `IpcSigner` | `synvoid-ipc/src/ipc_signed.rs` | HMAC-SHA3-256 signing/verification |
| `IpcListener` | `synvoid-ipc/src/ipc_transport.rs` | Unix socket listener |
| `IpcStream` | `synvoid-ipc/src/ipc_transport.rs` | Unix socket stream |
| `SignedWriter` | `synvoid-ipc/src/ipc_signed.rs` | Signed write adapter |

## Security Considerations

- **Path permissions**: IPC socket created with `0o600` (owner-only access)
- **Session isolation**: Each worker gets a unique session key
- **Message authentication**: All messages are HMAC-SHA3-256 signed with constant-time verification
- **Replay protection**: Nonce cache with timestamp window prevents replay attacks
- **FD validation**: Received FDs are validated before use
- **Socket cleanup**: Stale sockets are detected and cleaned up on startup
