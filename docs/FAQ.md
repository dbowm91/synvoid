# Frequently Asked Questions

Common questions about SynVoid.

## General

### What is SynVoid?

SynVoid is a high-performance Web Application Firewall (WAF) and reverse proxy written in Rust. It provides attack detection, bot mitigation, flood protection, and can operate as a distributed mesh network for DDoS mitigation.

### How does SynVoid compare to NGINX with ModSecurity?

| Feature | SynVoid | NGINX + ModSecurity |
|---------|---------|---------------------|
| **Language** | Rust (memory safe) | C |
| **HTTP/3 Support** | Native | Via module |
| **Mesh Networking** | Built-in | Requires additional setup |
| **Bot Mitigation** | Built-in | Requires extra modules |
| **Configuration** | TOML | NGINX config |

### What's the difference between Stall, Block, and Tarpit?

- **Block**: Returns 403 Forbidden. Users know they've been blocked.
- **Stall**: Holds connection open indefinitely. Attacker can't tell if server exists.
- **Tarpit**: Sends fake responses to waste attacker time.

See [ATTACK_DETECTION.md](./ATTACK_DETECTION.md#when-to-use-each-decision-type) for detailed guidance.

## Configuration

### How do I whitelist my monitoring service?

Add the service's IP range to trusted proxies:

```toml
[server]
trusted_proxies = ["127.0.0.1", "::1", "10.0.0.0/8"]  # Add your monitoring IPs
```

Or disable bot protection for specific IPs:

```toml
[defaults.bot]
enabled = true

[defaults.bot.whitelist]
ip_ranges = ["203.0.113.0/24"]  # Your monitoring service
```

### How do I allow Googlebot?

Googlebot is allowlisted by default. If it's being blocked:

```toml
[defaults.bot]
known_bots_allow = ["googlebot", "googleother"]
```

### How do I test my WAF configuration?

```bash
# Test SQL injection (should be blocked)
curl -H "Host: example.com" "http://localhost/search?term=1'%20OR%20'1'='1"

# Test XSS (should be blocked)
curl -H "Host: example.com" "http://localhost/xss?<script>alert(1)</script>"

# Test with Googlebot (should pass)
curl -H "Host: example.com" -H "User-Agent: Mozilla/5.0 (compatible; Googlebot/2.1)" http://localhost/
```

### What's the difference between paranoia levels?

- **Level 1**: Minimal false positives, basic detection only
- **Level 2** (recommended): Balanced detection with moderate false positive rate
- **Level 3**: Aggressive detection, higher false positive rate

Start at Level 2 and adjust based on your observations.

## Performance

### How many requests can SynVoid handle?

Performance depends on your hardware, but SynVoid is designed for high throughput:
- Single instance: 10,000+ req/s on modern hardware
- With worker scaling: Scales to available CPU cores

See [PERFORMANCE.md](./PERFORMANCE.md) for tuning tips.

### Does SynVoid support HTTP/3?

Yes. Enable HTTP/3 in your configuration:

```toml
[http3]
enabled = true
port = 443
```

## Networking

### When should I use WAF Mesh vs clustering?

- **Master-Worker Clustering**: Use when you need to scale horizontally within one location
- **WAF Mesh**: Use for geographic distribution, threat intelligence sharing, or building a private CDN

See [WAF_MESH.md](./WAF_MESH.md#when-to-use-mesh-vs-clustering) for detailed guidance.

### Can UDP services be proxied through the mesh?

No. UDP services (DNS, VoIP, gaming) cannot be proxied through the mesh due to port conflicts and connectionless nature. Each WAF node can still protect local UDP services directly.

## Security

### How do I secure the admin API?

1. Use a strong token (generate with `--generatetoken`)
2. Bind to localhost or internal network only
3. Enable TLS for remote admin access
4. Consider using the admin token env var:

```toml
[admin]
enabled = true
port = 8081
token_env_var = "SYNVOID_ADMIN_TOKEN"  # Use env var instead of config
```

### Is IPC between processes secure?

Enable IPC signing in production:

```toml
[security]
ipc_enforce_signing = true
ipc_session_key_env = "SYNVOID_IPC_KEY"
```

Generate a key with: `xxd -l 32 -p /dev/urandom`

## Troubleshooting

### Requests are being blocked but they're legitimate

1. Lower paranoia level:
```toml
[defaults.attack_detection]
paranoia_level = 1
```

2. Check logs for what's being blocked:
```bash
tail -f /var/log/synvoid/access.log | grep WAF
```

3. Add exceptions for specific paths:
```toml
[site.attack_detection]
enabled = true

[site.attack_detection.whitelist]
paths = ["/api/webhook", "/admin/search"]
```

### WAF won't start - address already in use

```bash
# Find what's using the port
lsof -i :8080

# Stop the conflicting service or change port in config
```

### Upstream connection errors

1. Verify upstream is running
2. Check firewall rules
3. Ensure `trusted_proxies` includes WAF IP
4. Check health check configuration

See [TROUBLESHOOTING.md](./TROUBLESHOOTING.md) for more issues.

## Getting Help

- GitHub Issues: https://github.com/synvoid/synvoid/issues
- Documentation: Check the docs/ folder
- Configuration Examples: See examples/ directory
