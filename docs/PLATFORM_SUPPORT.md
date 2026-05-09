# Platform Support

SynVoid is designed for consistent performance across modern operating systems, leveraging platform-specific primitives for its Shared-Nothing Architecture.

## Support Matrix

| Platform | Support Level | CI Tested | Notes |
|----------|--------------|-----------|-------|
| Linux (glibc) | Production | Yes | Primary target, full `SO_REUSEPORT` & core pinning |
| Alpine Linux (musl) | Production | Yes | Full feature support |
| macOS | Production | Yes | Full `SO_REUSEPORT` support |
| Windows (10+) | Production | Yes | `SO_REUSEPORT` support via modern Windows API |
| FreeBSD | Production | Yes | Full feature support |

## Feature Availability by Platform

### Shared-Nothing Architecture

| Feature | Linux | macOS | FreeBSD | Windows |
|---------|-------|-------|---------|---------|
| `SO_REUSEPORT` | ✅ | ✅ | ✅ | ✅ |
| CPU Core Pinning | ✅ (native) | ❌ | ✅ | ❌ |
| Shared-Nothing Mode| ✅ | ✅ | ✅ | ✅ |

### Control Plane (gRPC)

| Feature | Linux | macOS | FreeBSD | Windows |
|---------|-------|-------|---------|---------|
| gRPC API (TLS) | ✅ | ✅ | ✅ | ✅ |
| Raft Consensus | ✅ | ✅ | ✅ | ✅ |
| Mesh (QUIC) | ✅ | ✅ | ✅ | ✅ |

## Platform-Specific Details

### Linux (glibc/musl)

Linux is the premier platform for SynVoid, offering the most granular performance controls.

**Features:**
- **Deterministic Core Pinning:** Uses `sched_setaffinity` to bind workers to physical CPU cores, eliminating jitter.
- **Advanced Sandboxing:** Workers are strictly confined using Landlock or Seccomp.
- **Efficient I/O:** Leverages `io_uring` (via Tokio) for high-throughput packet processing.

### Windows (10, 11, Server 2019+)

Modern Windows versions support `SO_REUSEPORT` semantics (via `SO_REUSEADDR` behavior changes and specific socket flags), enabling SynVoid's shared-nothing model.

**Differences:**
- **IPC:** Uses Named Pipes (`\\.\pipe\synvoid-*`) instead of Unix Domain Sockets.
- **Service Management:** Recommended to run as a Windows Service (`sc.exe`).
- **CPU Pinning:** Currently uses the OS scheduler for worker distribution rather than strict affinity.

### macOS & BSD

Full shared-nothing support using `kqueue` and `SO_REUSEPORT`.

**Notes:**
- **macOS:** `SO_REUSEPORT` is fully supported, allowing multiple workers to bind to the same port.
- **FreeBSD:** Leverages native `SO_REUSEPORT_LB` for kernel-level distribution.

## Zero-Downtime Upgrades

Across all platforms, SynVoid achieves zero-downtime upgrades via:
1. **New Supervisor Start:** The new Supervisor takes over the gRPC management port.
2. **Worker Rotation:** The new Supervisor spawns new workers that bind to the service ports via `SO_REUSEPORT`.
3. **Graceful Drain:** Old workers are signaled via IPC to finish processing and exit.

## Feature Flags

| Feature | Default | Description |
|---------|---------|-------------|
| `landlock` | Yes | Linux-specific sandboxing |
| `grpc-tls` | Yes | Mandatory TLS for the gRPC control plane |

## Performance Considerations

### Linux
- Ensure `worker_processes` matches physical cores.
- Check `dmesg` to verify Landlock and Core Pinning are active.

### Windows
- Use Windows Server 2019 or later for optimal socket performance.
- Named pipe latency is slightly higher than Unix sockets; adjust IPC timeouts if needed.

## Testing

Each platform is verified in CI:
- **Unit Tests:** All core logic.
- **Integration Tests:** Supervisor-Worker IPC and gRPC command handling.
- **Load Tests:** Verified shared-nothing throughput on Linux and macOS.
