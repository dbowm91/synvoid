# Request Sanitization

MaluWAF sanitizes incoming requests to protect your upstream servers from malformed, malicious, or potentially problematic input. This document explains what sanitization happens and how to configure it.

## Overview

Request sanitization in MaluWAF operates at multiple levels:

1. **Header Sanitization** - Cleaning HTTP headers
2. **Path Sanitization** - Normalizing request paths
3. **Trusted Proxy Handling** - Properly handling X-Forwarded-* headers

## Header Sanitization

### Hop-by-Hop Headers

MaluWAF automatically removes hop-by-hop headers that should not be forwarded to upstream servers:

| Header | Why It's Removed |
|--------|------------------|
| `Connection` | Connection-specific headers shouldn't be forwarded |
| `Keep-Alive` | Connection state |
| `Proxy-Authenticate` | Proxy authentication |
| `Proxy-Authorization` | Proxy credentials |
| `TE` | Transfer encoding related |
| `Trailers` | Trailer headers |
| `Transfer-Encoding` | Already handled by proxy |
| `Upgrade` | Protocol upgrade handled separately |

### Response Headers

Outgoing responses are also sanitized to prevent information leakage:

```toml
[defaults.security]
remove_server_header = true      # Remove Server header
remove_powered_by_header = true   # Remove X-Powered-By header
```

### Headers Removed by Default

- `Server` - Reveals server type/version
- `X-Powered-By` - Reveals application framework
- `X-AspNet-Version` - Reveals ASP.NET version
- `X-AspNetMvc-Version` - Reveals MVC version

## Path Sanitization

### URL Normalization

MaluWAF normalizes request paths before processing:

1. **Double encoding** - `%252e` → `%2e` → `.`
2. **Null bytes** - `/etc/passwd%00.txt` → `/etc/passwd`
3. **Unicode normalization** - Various Unicode representations normalized
4. **Path traversal** - `../../etc/passwd` detected and blocked

### Configuration

```toml
[defaults.security]
normalize_path = true
block_path_traversal = true

[defaults.security.path_traversal]
enabled = true
custom_patterns = []
```

## Trusted Proxy Handling

When MaluWAF sits behind a load balancer or CDN, it needs to correctly identify the original client IP and protocol.

### Configuration

```toml
[server]
trusted_proxies = [
    "10.0.0.0/8",      # Private network
    "172.16.0.0/12",   # Docker network
    "192.168.0.0/16",  # Local network
    "127.0.0.1",       # Localhost
]

[defaults.security]
sanitize_forwarded_headers = true
```

### How It Works

1. **Trusted proxy detected** - Request comes from an IP in `trusted_proxies`
2. **Parse X-Forwarded-*** - Extract original client IP and protocol
3. **Validate** - Ensure forwarded values aren't spoofed
4. **Use for WAF decisions** - Rate limiting, blocking uses real client IP

### Example

```
Client → CDN (1.2.3.4) → MaluWAF (10.0.0.1) → Upstream

Request received by MaluWAF:
  X-Forwarded-For: 203.0.113.50
  X-Forwarded-Proto: https

MaluWAF detects:
  - Request from trusted proxy (1.2.3.4)
  - Original client: 203.0.113.50
  - Original protocol: https
```

## Forwarded Header Sanitization

### Attack Prevention

Without proper sanitization, attackers can spoof X-Forwarded-* headers to:
- Bypass IP-based rate limits
- Appear as trusted internal IPs
- Inject malicious values

### How MaluWAF Protects

When `sanitize_forwarded_headers = true`:

1. **Untrusted sources** - Headers are stripped entirely
2. **Trusted proxies** - Headers are parsed and validated
3. **Validation** - Only the first (original) client IP is used

```toml
[defaults.security]
sanitize_forwarded_headers = true
```

## Request Body Handling

### Size Limits

```toml
[http]
max_request_size = 1048576  # 1MB default
```

### Content-Type Validation

MaluWAF can validate Content-Type headers:

```toml
[defaults.security]
strict_content_type = true
allowed_content_types = [
    "application/json",
    "application/x-www-form-urlencoded",
    "multipart/form-data",
]
```

### Request Smuggling Prevention

MaluWAF detects HTTP request smuggling attacks:

```toml
[defaults.attack_detection.request_smuggling]
enabled = true
```

This detects:
- Content-Length vs Transfer-Encoding conflicts
- HTTP/2 pseudo-header conflicts
- Response queue poisoning attempts

## Configuration Options

### Security Defaults

```toml
[defaults.security]
# Header sanitization
remove_server_header = true
remove_powered_by_header = true

# Path sanitization
normalize_path = true
block_path_traversal = true

# Proxy sanitization
sanitize_forwarded_headers = true

# Request limits
max_request_size = 1048576
max_header_size = 4096
```

### Server-Level

```toml
[server]
trusted_proxies = ["10.0.0.0/8", "172.16.0.0/12"]
```

## Troubleshooting

### Legitimate Traffic Blocked

If sanitization is blocking legitimate requests:

1. **Check path encoding** - Ensure URLs are properly encoded
2. **Verify trusted proxies** - Add your CDN/load balancer to trusted_proxies
3. **Disable specific checks** - If needed, disable path_traversal for specific paths

### Incorrect Client IP Detection

If client IPs appear as proxy IPs:

1. Verify proxy is in `trusted_proxies`
2. Check `sanitize_forwarded_headers` is enabled
3. Ensure proxy sends correct X-Forwarded-For headers

### Request Smuggling False Positives

Some legitimate proxies may trigger smuggling detection:

```toml
[defaults.attack_detection.request_smuggling]
enabled = false  # Disable if causing issues
```

## Best Practices

1. **Always use trusted_proxies** - Add your CDN, load balancer, or reverse proxy
2. **Enable sanitize_forwarded_headers** - Prevents header injection
3. **Remove information headers** - Set `remove_server_header = true`
4. **Configure size limits** - Prevent resource exhaustion
5. **Monitor blocked requests** - Watch for false positives

## See Also

- [ATTACK_DETECTION.md](./ATTACK_DETECTION.md) - Attack detection details
- [CONFIGURATION.md](./CONFIGURATION.md) - Sanitization configuration options
- [TROUBLESHOOTING.md](./TROUBLESHOOTING.md) - Debugging request issues
