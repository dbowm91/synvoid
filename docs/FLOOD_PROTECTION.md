# Flood Protection

MaluWAF provides multi-layer flood protection against various types of volumetric attacks. This document explains how each protection mechanism works and when to use different configurations.

## Understanding Flood Attacks

Before configuring protection, it's helpful to understand the types of floods:

| Attack Type | What It Targets | How It Works |
|-------------|-----------------|--------------|
| **SYN Flood** | TCP handshake | Sends SYN packets without completing handshake, exhausting connection slots |
| **Connection Flood** | Open connections | Opens many connections without sending requests |
| **UDP Flood** | Bandwidth | Sends high-volume UDP packets (common: DNS amplification) |
| **Request Flood** | Application layer | Sends legitimate-looking requests faster than server can handle |

## SYN Flood Protection

Tracks half-open connections to detect and mitigate SYN floods:

```toml
[defaults.flood]
syn_rate_per_ip = 50         # SYN packets per second per IP
syn_rate_global = 10000     # Global SYN rate limit
half_open_max = 1000        # Max half-open connections
half_open_per_ip_max = 10   # Max half-open per IP
```

### How It Works

When a client initiates a TCP connection, it sends a SYN packet. The server responds with SYN-ACK and waits for the final ACK. A SYN flood attacks this three-way handshake:

1. **Per-IP Rate Limiting**: Each IP can only send a limited number of SYN packets per second
2. **Global Rate Limiting**: Protects against distributed attacks from many IPs
3. **Half-Open Tracking**: Monitors connections that haven't completed the handshake
4. **Automatic Cleanup**: Removes stale half-open entries to free resources

### When to Tune These Settings

- **Low traffic sites**: Reduce `syn_rate_per_ip` to 10-20, `half_open_max` to 100-500
- **High traffic sites**: Increase to 100+ SYN/sec per IP, `half_open_max` to 5000+
- **Under attack**: Use blackhole mode (see below) to drop traffic early

### Configuration Options

| Parameter | Default | Description |
|-----------|---------|-------------|
| `syn_rate_per_ip` | 50 | SYN packets/second per IP |
| `syn_rate_global` | 10000 | Global SYN packets/second |
| `half_open_max` | 1000 | Max half-open connections |
| `half_open_per_ip_max` | 10 | Max half-open per IP |

## Connection Rate Limiting

Prevents connection exhaustion:

```toml
[defaults.flood]
connection_rate_per_ip = 100    # Connections per second per IP
connection_rate_global = 20000  # Global connection rate
```

### Features

- Per-IP connection rate tracking
- Global connection limits
- Active connection monitoring
- Automatic window rotation

### Practical Guidance

Connection rate limiting is most effective against:
- Single IP opening too many connections
- Slowloris-style attacks holding connections open
- Botnets attempting connection exhaustion

Start with defaults and adjust based on your legitimate traffic patterns.

## UDP Flood Protection

Rate limits UDP traffic with per-port granularity:

```toml
[defaults.flood]
udp_rate_per_ip = 1000      # UDP packets per second per IP
udp_rate_global = 100000    # Global UDP rate
```

### When to Use UDP Protection

UDP flood protection is essential if you:
- Run a DNS server behind the WAF
- Use UDP-based services
- Are target of UDP amplification attacks

**Common scenario**: DNS servers are frequent targets because attackers can spoof the source IP and use your DNS server to amplify traffic toward victims.

### Features

- Per-IP packet rate limiting
- Per-port rate limiting (prevents DNS amplification)
- Global packet rate limiting
- Slotted counter design for O(1) lookups

## Blackhole Mode

Automatic traffic filtering during sustained attacks:

```toml
[defaults.flood]
blackhole_threshold = 0.9      # Enter blackhole at 90% capacity
blackhole_duration_secs = 60   # Blackhole duration
```

### When to Use Blackhole Mode

Blackhole mode is a **last resort** when under heavy attack:
- Use when capacity is consistently above 80-90%
- Accepts that some legitimate traffic will be dropped
- Buys time for upstream defenses to activate

**Recommended settings**:
- Lower threshold (0.5-0.7) for critical services
- Higher threshold (0.8-0.9) for non-critical services

### Behavior

When capacity exceeds threshold:
1. New connections are silently dropped
2. Existing connections continue normally
3. After duration expires, gradual restoration
4. Automatic reactivation if attack resumes

## Rate Limiting

Per-IP and global rate limiting with sliding windows:

```toml
[defaults.ratelimit]
mode = "shared"  # "shared" or "isolated" per site

[defaults.ratelimit.ip]
per_second = 10
per_minute = 60
per_5min = 200
per_hour = 500
per_day = 1000
burst = 20

[defaults.ratelimit.global]
per_second = 500
per_minute = 5000
max_connections = 10000
```

### Configuration Options

| Parameter | Default | Description |
|-----------|---------|-------------|
| `mode` | "shared" | "shared" or "isolated" per site |
| `per_second` | 10 | Requests per second per IP |
| `per_minute` | 60 | Requests per minute per IP |
| `per_5min` | 200 | Requests per 5 minutes per IP |
| `per_hour` | 500 | Requests per hour per IP |
| `per_day` | 1000 | Requests per day per IP |
| `burst` | 20 | Burst allowance |

### Memory Configuration

```toml
[defaults.rate_limit_memory]
max_ips = 1000000
cleanup_interval_secs = 60
```

## Metrics

All flood protection is tracked via Prometheus metrics:

```
maluwaf.flood.syn_limited                    # SYN flood limited
maluwaf.flood.connection_limited             # Connection rate limited
maluwaf.flood.udp_limited                   # UDP flood limited
maluwaf.syn_flood.half_open_count           # Current half-open connections
maluwaf.connection_limiter.active          # Active connections
maluwaf.connection_limiter.global_limited  # Global connection limit
maluwaf.connection_limiter.ip_limited       # Per-IP connection limit
maluwaf.ratelimit.blackhole_drop            # Blackholed requests
maluwaf.ratelimit.blackhole_active          # Blackhole mode active
maluwaf.ratelimit.global_limited            # Global rate limited
maluwaf.ratelimit.ip_limited                # Per-IP rate limited
```

## Tuning Guidelines

### High Traffic Sites

```toml
[defaults.flood]
syn_rate_global = 50000
connection_rate_global = 100000
half_open_max = 5000

[defaults.ratelimit.global]
per_second = 5000
max_connections = 50000
```

### Low Traffic Sites

```toml
[defaults.flood]
syn_rate_global = 5000
connection_rate_global = 5000
half_open_max = 500

[defaults.ratelimit.global]
per_second = 100
max_connections = 1000
```

### DDoS Protection

For sites requiring DDoS protection:

```toml
[defaults.flood]
syn_rate_per_ip = 10
syn_rate_global = 5000
connection_rate_per_ip = 10
connection_rate_global = 5000
half_open_max = 100
half_open_per_ip_max = 2
blackhole_threshold = 0.5
blackhole_duration_secs = 300
```


## See Also

- [ATTACK_DETECTION.md](./ATTACK_DETECTION.md) - Payload-based attack detection (SQLi, XSS, etc.)
- [THREAT_LEVEL.md](./THREAT_LEVEL.md) - Adaptive threat level system for automatic escalation
- [CONFIGURATION.md](./CONFIGURATION.md) - Flood protection configuration options
- [WAF_MESH.md](./WAF_MESH.md) - Distributed mesh network for DDoS mitigation

