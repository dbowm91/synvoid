# IPC & Process Deep Dive

SynVoid's inter-process communication layer handles all Supervisor ↔ Worker and Worker ↔ Worker communication via Unix domain sockets with signed messages and file descriptor passing.

## Architecture

### Transport Layer (`synvoid-ipc`)

- **Unix domain sockets** with `SCM_RIGHTS` for FD passing
- **Ed25519 signed messages** for authentication and integrity
- **Message framing**: Length-prefixed Postcard-encoded messages
- **Non-blocking I/O** with `tokio::net::UnixStream`

### Message Protocol

All IPC messages use the `Message` enum (60+ variants) serialized with Postcard:

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

Every IPC message is signed with Ed25519:
- **Session key**: Generated per-worker at startup, exchanged during handshake
- **Signature**: `[u8; 64]` appended to serialized message
- **Verification**: Supervisor validates worker signatures; workers validate supervisor signatures
- **Replay protection**: Monotonic sequence numbers per session

### File Descriptor Passing

Used for zero-copy socket handoff between processes:

```rust
// Supervisor → Worker: socket handoff
SocketHandoff {
    listener_fd: RawFd,  // Passed via SCM_RIGHTS
    port: u16,
    socket_type: SocketType,  // Tcp, TcpReusePort
}

// Worker → Supervisor: socket release
SocketRelease {
    listener_fd: RawFd,
    port: u16,
}
```

- Up to 254 FDs per message
- FDs are duplicated (not transferred) — sender retains original
- Receiver gets a new file descriptor pointing to the same kernel object

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
| `Message` | `synvoid-ipc/src/message.rs` | 60+ variant IPC message enum |
| `IpcSession` | `synvoid-ipc/src/session.rs` | Session state with signing keys |
| `IpcListener` | `synvoid-ipc/src/listener.rs` | Unix socket listener |
| `IpcStream` | `synvoid-ipc/src/stream.rs` | Unix socket stream |
| `SignedMessage` | `synvoid-ipc/src/signing.rs` | Message + Ed25519 signature |

## Security Considerations

- **Path permissions**: IPC socket created with `0o600` (owner-only access)
- **Session isolation**: Each worker gets a unique session key
- **Message authentication**: All messages are Ed25519-signed
- **Sequence numbers**: Prevent replay attacks
- **FD validation**: Received FDs are validated before use
- **Socket cleanup**: Stale sockets are detected and cleaned up on startup
