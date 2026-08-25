# Windows Support Testing Notes

## Status: EXPERIMENTAL - Testing Required

This document outlines the Windows support implementation and what needs to be tested.

## Implemented Features

### 1. IPC Layer
- **Client-side**: Workers can connect to the Supervisor via named pipes
- **Server-side**: Supervisor can accept worker connections via named pipes
- **Protocol**: Same 4-byte length prefix + JSON framing as Unix

### 2. Named Pipe Paths
- Supervisor IPC: `\\.\pipe\synvoid-supervisor`
- CPU (static) worker IPC: `\\.\pipe\synvoid-static-worker`
- CLI commands: `\\.\pipe\synvoid-commands`

### 3. Signal Handling
- Ctrl+C handler works on Windows (via tokio)
- SIGTERM not available on Windows (uses IPC-based fallback)
- SIGUSR1/SIGUSR2 not available on Windows
- CLI operations use flags (`--status`, `--stop`, `--rehash`) instead of signals

### 4. Process Management
- Worker spawn works via standard process spawning (Supervisor → UnifiedServerWorker + CPU worker)
- Process health monitoring via heartbeat messages
- Graceful shutdown via IPC messages

### 5. CPU Worker (Offload)
- Implemented on Windows using named pipes (`--cpu-worker`; `--static-worker` is an alias)
- Mirrors Unix behavior (synchronous, thread-per-connection)

## Known Limitations

1. **Performance**: Named pipes are slower than Unix sockets

## Testing Checklist

### Phase 1: Basic Functionality
- [ ] Build on Windows (`cargo build --target x86_64-pc-windows-msvc`)
- [ ] Supervisor process starts successfully
- [ ] Supervisor IPC pipe is created
- [ ] Ctrl+C triggers graceful shutdown

### Phase 2: Worker Communication  
- [ ] Workers connect to the Supervisor via named pipes
- [ ] Worker heartbeats are received by the Supervisor
- [ ] Worker health monitoring detects failures

### Phase 3: Request Processing
- [ ] UnifiedServerWorker handles HTTP requests
- [ ] Configuration propagation to workers works

### Phase 4: Offload
- [ ] CPU worker starts and creates named pipe
- [ ] Data-plane worker can connect to the CPU worker for offload tasks
- [ ] Offload requests work correctly

### Phase 5: CLI Operations
- [ ] CLI can reach the control API / command pipe
- [ ] `synvoid --stop` works
- [ ] `synvoid --rehash` works (config reload)
- [ ] `synvoid --status` works

### Phase 6: Advanced Features
- [ ] Config hot reload via IPC
- [ ] Graceful shutdown of workers

## Building on Windows

```powershell
# Install MSVC toolchain
rustup default stable-x86_64-pc-windows-msvc

# Build
cargo build --release

# Run
cargo run --release
```

## Troubleshooting

### Issue: Named pipe connection fails
**Solution**: Ensure the pipe name matches exactly (case-sensitive)

### Issue: Workers cannot connect
**Solution**: Check Windows Firewall settings

### Issue: High memory usage
**Solution**: This is expected on Windows due to named pipe overhead

## Reporting Issues

If you encounter bugs on Windows, please report:
1. Windows version (e.g., Windows 11 22H2)
2. Rust version (`rustc --version`)
3. Build output with `RUST_LOG=debug`
4. Steps to reproduce
