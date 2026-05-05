# Windows Support Testing Notes

## Status: EXPERIMENTAL - Testing Required

This document outlines the Windows support implementation and what needs to be tested.

## Implemented Features

### 1. IPC Layer
- **Client-side**: Workers can connect to master via named pipes
- **Server-side**: Master can accept worker connections via named pipes
- **Protocol**: Same 4-byte length prefix + JSON framing as Unix

### 2. Named Pipe Paths
- Master IPC: `\\.\pipe\synvoid-master`
- Static worker IPC: `\\.\pipe\synvoid-static-worker`
- CLI commands: `\\.\pipe\synvoid-commands`

### 3. Signal Handling
- Ctrl+C handler works on Windows (via tokio)
- SIGTERM not available on Windows (uses IPC-based fallback)
- SIGUSR1/SIGUSR2 not available on Windows
- CLI commands now use named pipe instead of signals

### 4. Process Management
- Worker spawn works via standard process spawning
- Process health monitoring via heartbeat messages
- Graceful shutdown via IPC messages

### 5. Static Worker (Minification)
- Implemented on Windows using named pipes
- Mirrors Unix behavior (synchronous, thread-per-connection)

## Known Limitations

1. **Performance**: Named pipes are slower than Unix sockets

## Testing Checklist

### Phase 1: Basic Functionality
- [ ] Build on Windows (`cargo build --target x86_64-pc-windows-msvc`)
- [ ] Master process starts successfully
- [ ] Master IPC pipe is created
- [ ] Ctrl+C triggers graceful shutdown

### Phase 2: Worker Communication  
- [ ] Workers connect to master via named pipes
- [ ] Worker heartbeats are received by master
- [ ] Worker health monitoring detects failures

### Phase 3: Request Processing
- [ ] Request workers handle HTTP requests
- [ ] Load balancing across workers

### Phase 4: Minification
- [ ] Static worker starts and creates named pipe
- [ ] Request workers can connect to static worker for minification
- [ ] Minification requests work correctly

### Phase 5: CLI Commands
- [ ] CLI can connect to command pipe
- [ ] `stop` command works
- [ ] `reload` command works
- [ ] `status` command works
- [ ] `health` command works

### Phase 6: Advanced Features
- [ ] Config hot reload via IPC
- [ ] Threadpool resize
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
