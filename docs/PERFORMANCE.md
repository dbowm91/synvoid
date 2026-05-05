# Performance & Latency Guide

This guide covers performance tuning and latency optimization for SynVoid deployments.

## Architecture Overview

SynVoid uses a multi-process architecture:
- **Overseer**: Optional parent process for orchestration
- **Master**: Administrative API, process management, IPC hub
- **Workers**: Handle HTTP requests, apply WAF rules

## Latency Considerations

### IPC Communication

The master communicates with workers via Unix domain sockets (Unix) or named pipes (Windows). By default, SynVoid uses exponential backoff for IPC polling:

- Initial poll interval: 1ms
- Maximum poll interval: 50ms
- This approach balances responsiveness with CPU efficiency

### Worker Configuration

```toml
[defaults.worker_pool]
workers = 4           # Number of worker processes
worker_port_base = 9000
auto_scale = true     # Automatically adjust workers based on load
```

### HTTP Settings

```toml
[http]
header_read_timeout_secs = 10
keep_alive_timeout_secs = 60
max_headers = 128
max_request_size = 1048576  # 1MB - adjust based on use case
```

### Connection Handling

- **Keep-alive**: Enabled by default (60s). Adjust based on client behavior
- **Pipeline limit**: Default 32 concurrent requests per connection

## Performance Tuning

### 1. Worker Count

Rule of thumb: 2-4 workers per CPU core for I/O-bound workloads.

```toml
[defaults.worker_pool]
workers = 8  # For 4-core machine with I/O workload
```

### 2. Rate Limiting Mode

```toml
[defaults.ratelimit]
mode = "shared"  # "shared" or "isolated"
```

- **shared**: Global rate limit state across all workers (more accurate, slight overhead)
- **isolated**: Per-worker rate limits (lower overhead, slightly less accurate)

### 3. Threat Level Scaling

Enable auto-scaling for threat levels to reduce load during attacks:

```toml
[threat_level]
auto_scale = true
scale_up_attacks_per_min = 50
scale_down_attacks_per_min = 10
```

### 4. Blocking Optimization

For high-throughput deployments, consider:

- **Enable IP feeds sparingly**: Each feed adds lookup overhead
- **Tune block duration**: Longer bans reduce repeated lookups
- **Use regex carefully**: Complex regex patterns in blocking rules increase latency

### 5. Challenge Settings

PoW challenges are CPU-intensive. Adjust difficulty:

```toml
[defaults.pow_challenge]
difficulty = 6    # Lower = easier, Higher = more CPU work
timeout_secs = 60
prefer_wasm = true  # Use WebAssembly for PoW (faster)
```

## Monitoring

Key metrics to watch:

- **Request latency**: `p95`, `p99` response times
- **Worker CPU**: Should stay below 70% under normal load
- **IPC queue depth**: High values indicate worker starvation
- **Block rate**: Sudden spikes may indicate attack

Access metrics at `/api/v1/metrics` on the admin port (default 8081).

## Known Latency Pitfalls

1. **Synchronous file I/O**: Static file serving uses async I/O; ensure disks are fast
2. **Large request bodies**: Increase `max_request_size` only if needed
3. **Complex WAF rules**: Each rule adds inspection overhead
4. **Mesh networking**: Threat intel sharing adds network latency; tune sync intervals

## Benchmarking

Use tools like `wrk` or `oha` to benchmark:

```bash
# Basic throughput test
wrk -t4 -c100 -d30s http://localhost:8080/

# With keep-alive
wrk -t4 -c100 -d30s -H "Connection: keep-alive" http://localhost:8080/
```

Target latency should be <10ms for simple proxied requests under normal load.


## See Also

- [ARCHITECTURE.md](./ARCHITECTURE.md) - System architecture overview
- [PROCESS_MANAGEMENT.md](./PROCESS_MANAGEMENT.md) - Process and worker management
- [TROUBLESHOOTING.md](./TROUBLESHOOTING.md) - Performance issues troubleshooting
- [CONFIGURATION.md](./CONFIGURATION.md) - Configuration options for tuning

