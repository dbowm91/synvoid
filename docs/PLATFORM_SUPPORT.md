# Platform Support

MaluWAF is designed to run on multiple platforms with consistent functionality where possible. This document outlines the support matrix and platform-specific considerations.

## Support Matrix

| Platform | Support Level | CI Tested | Notes |
|----------|--------------|-----------|-------|
| Linux (glibc) | Production | Yes | Primary target, full feature support |
| Alpine Linux (musl) | Production | Yes | Uses musl libc, all features supported |
| macOS (Intel & Apple Silicon) | Production | Yes | Full feature support |
| FreeBSD | Production | Yes | Full feature support |
| OpenBSD | Best Effort | No | Compiles, community testing needed |
| NetBSD | Best Effort | No | Compiles, community testing needed |
| Windows | Production* | Yes | Named pipes for IPC, port-swap for upgrades |
| Windows Server | Production* | Yes | Windows Service support recommended |

*Windows has feature limitations due to platform differences (see below).

## Feature Availability by Platform

### Core Features

| Feature | Linux | macOS | FreeBSD | Windows |
|---------|-------|-------|---------|---------|
| HTTP/HTTPS Proxy | ✅ | ✅ | ✅ | ✅ |
| WAF Engine | ✅ | ✅ | ✅ | ✅ |
| Rate Limiting | ✅ | ✅ | ✅ | ✅ |
| Bot Detection | ✅ | ✅ | ✅ | ✅ |
| GeoIP | ✅ | ✅ | ✅ | ✅ |
| TLS Termination | ✅ | ✅ | ✅ | ✅ |
| HTTP/3 (QUIC) | ✅ | ✅ | ✅ | ✅ |
| WebSocket Proxy | ✅ | ✅ | ✅ | ✅ |
| FastCGI | ✅ | ✅ | ✅ | ✅ |

### Process Management

| Feature | Linux | macOS | FreeBSD | Windows |
|---------|-------|-------|---------|---------|
| Multi-worker | ✅ | ✅ | ✅ | ✅ |
| Hot Reload | ✅ | ✅ | ✅ | ✅ |
| Graceful Shutdown | ✅ | ✅ | ✅ | ✅ |
| Daemonization | ✅ | ✅ | ✅ | ❌ (use Service) |
| Unix Signals | ✅ | ✅ | ✅ | ❌ (use IPC) |

### Zero-Downtime Upgrades

| Mode | Linux | macOS | FreeBSD | Windows |
|------|-------|-------|---------|---------|
| Socket FD Passing | ✅ | ✅ | ✅ | ❌ |
| SO_REUSEPORT | ✅ | ✅ | ✅ | ❌ |
| Port Swap | ✅ | ✅ | ✅ | ✅ |
| Load Balancer | ✅ | ✅ | ✅ | ✅ |

## Platform-Specific Details

### Linux (glibc)

Standard Linux distributions (Ubuntu, Debian, CentOS, RHEL, Fedora) using glibc.

**Default paths:**
- Data: `/var/lib/maluwaf`
- Config: `/etc/maluwaf`
- Logs: `/var/log/maluwaf`
- Runtime: `/run/maluwaf`

**Features:**
- Full `SO_REUSEPORT` support for zero-downtime upgrades
- Socket FD passing via SCM_RIGHTS
- All signal handling (SIGTERM, SIGHUP, SIGUSR1, SIGUSR2)
- TCP_QUICKACK for improved latency

### Alpine Linux (musl)

Alpine Linux uses musl libc instead of glibc. All features are supported.

**Build:**
```bash
# Native build on Alpine
apk add cargo
cargo build --release

# Cross-compile from other Linux
rustup target add x86_64-unknown-linux-musl
cargo build --target x86_64-unknown-linux-musl --release
```

**Docker:**
```dockerfile
FROM alpine:latest
RUN apk add --no-cache maluwaf
# or build from source
```

### macOS

Full support on both Intel (x86_64) and Apple Silicon (aarch64).

**Default paths:**
- Data: `~/.local/share/maluwaf`
- Config: `~/.config/maluwaf`
- Logs: `~/.local/log/maluwaf`
- Runtime: `$TMPDIR/maluwaf-runtime`

**Notes:**
- Uses launchd for service management instead of systemd
- File descriptors limits may need adjustment (`ulimit -n`)

### FreeBSD

Full support with native FreeBSD paths.

**Default paths:**
- Data: `/var/db/maluwaf`
- Config: `/usr/local/etc/maluwaf`
- Logs: `/var/log/maluwaf`
- Runtime: `/var/run/maluwaf`

**Installation:**
```bash
pkg install rust
cargo build --release
```

**Service management:**
Create `/usr/local/etc/rc.d/maluwaf` for rc.d integration.

### Windows

Windows support uses named pipes instead of Unix sockets for IPC.

**Default paths:**
- Data: `%PROGRAMDATA%\maluwaf`
- Config: `%PROGRAMDATA%\maluwaf\config`
- Logs: `%PROGRAMDATA%\maluwaf\logs`
- Named Pipes: `\\.\pipe\maluwaf-*`

**IPC Differences:**
- Master IPC: `\\.\pipe\maluwaf-master`
- Worker IPC: `\\.\pipe\maluwaf-worker-*`
- Commands: `\\.\pipe\maluwaf-commands`

**Upgrade Mode:**
Windows uses "port swap" mode for upgrades:
1. New master starts on temporary port (base_port + offset)
2. Old master drains connections
3. External load balancer switches to new port
4. Old master exits

For true zero-downtime without a load balancer, Windows socket duplication (WSADuplicateSocket) is available but requires parent-child process relationship.

**Windows Service:**
```powershell
# Register as Windows Service (recommended for production)
sc.exe create MaluWAF binPath="C:\Program Files\MaluWAF\maluwaf.exe --service"
sc.exe start MaluWAF
```

## Feature Flags

Control compile-time features via Cargo features:

```toml
[dependencies]
maluwaf = { version = "0.1", features = ["socket-handoff", "daemonize"] }
```

| Feature | Default | Description |
|---------|---------|-------------|
| `socket-handoff` | Yes | Socket FD passing for zero-downtime upgrades (Unix only) |
| `daemonize` | No | Unix daemonization support |

## Building for Specific Platforms

### Cross-Compilation

```bash
# Linux musl (Alpine)
rustup target add x86_64-unknown-linux-musl
cargo build --target x86_64-unknown-linux-musl --release

# Windows from Linux
rustup target add x86_64-pc-windows-gnu
cargo build --target x86_64-pc-windows-gnu --release

# FreeBSD from Linux (requires cross toolchain)
cargo install cross
cross build --target x86_64-unknown-freebsd --release
```

### Docker Multi-Platform

```dockerfile
# Build for multiple platforms
FROM --platform=$TARGETPLATFORM rust:latest AS builder
RUN cargo build --release

FROM --platform=$TARGETPLATFORM debian:bookworm-slim
COPY --from=builder /app/target/release/maluwaf /usr/local/bin/
```

## Performance Considerations

### Linux
- Use `SO_REUSEPORT` for best multi-core performance
- Enable `TCP_QUICKACK` (automatic on Linux)
- Consider increasing file descriptor limits

### macOS
- Lower default file descriptor limits
- Consider `kqueue` vs `epoll` differences (handled by tokio)

### Windows
- Named pipes have higher overhead than Unix sockets
- Consider increasing named pipe buffer sizes
- Use I/O completion ports (handled by tokio)

### BSD
- Similar performance to Linux
- `kqueue` provides excellent scalability

## Testing

Each platform is tested in CI:

| Platform | Test Type |
|----------|-----------|
| Linux (glibc) | Full test suite |
| Linux (musl) | Build + basic tests |
| macOS | Full test suite |
| Windows | Full test suite |
| FreeBSD | Build + basic tests (via VM) |

## Reporting Issues

When reporting platform-specific issues, please include:

1. Platform and version (e.g., `Ubuntu 22.04`, `Alpine 3.19`, `FreeBSD 14.0`)
2. Rust version (`rustc --version`)
3. Target triple (`rustup show`)
4. Build output with `RUST_LOG=debug`
5. Any relevant system logs

## Contributing Platform Support

To add support for a new platform:

1. Add target to `Cargo.toml` if needed
2. Create platform-specific module in `src/platform/`
3. Add CI job in `.github/workflows/ci.yml`
4. Update this documentation
5. Test thoroughly on actual hardware or VM
