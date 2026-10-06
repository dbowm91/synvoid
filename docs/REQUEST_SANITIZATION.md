# Request Sanitization

SynVoid sanitizes incoming requests to protect your upstream servers from malformed, malicious, or potentially problematic input. This document explains what sanitization happens and how to configure it.

## Overview

Request sanitization in SynVoid operates at multiple levels:

1. **Header Sanitization** - Cleaning HTTP headers
2. **Path Sanitization** - Normalizing request paths
3. **Trusted Proxy Handling** - Properly handling X-Forwarded-* headers

## Header Sanitization

### Hop-by-Hop Headers

SynVoid automatically removes hop-by-hop headers that should not be forwarded to upstream servers:

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

Outgoing responses are sanitized to prevent information leakage. The main config's
`[security]` section controls this (`MainSecurityConfig`); there is no
`remove_server_header` or `remove_powered_by_header` key:

```toml
[security]
global_security_headers = true   # Add the standard hardening response headers

# Optional: additional response headers to clear
more_clear_headers = ["Server", "X-Powered-By", "X-AspNet-Version", "X-AspNetMvc-Version"]
```

### Headers Removed by Default

`Server`, `X-Powered-By`, `X-AspNet-Version`, and `X-AspNetMvc-Version` are not stripped
automatically. List them in `more_clear_headers` (see above) to have them cleared.
Per-site response hardening is configured under `[security_headers]`.

## Path Sanitization

### URL Normalization

SynVoid normalizes request paths before processing:

1. **Double encoding** - `%252e` → `%2e` → `.`
2. **Null bytes** - `/etc/passwd%00.txt` → `/etc/passwd`
3. **Unicode normalization** - Various Unicode representations normalized
4. **Path traversal** - `../../etc/passwd` detected and blocked

### Configuration

```toml
[attack_detection.path_traversal]
enabled = true
custom_patterns = []
```

Path normalization is not a `[security]` toggle — detection runs through the site's
`[attack_detection]` section, and detection runs inline on the borrowed request
(`check_request_sync`), not as per-request spawned tasks.

## Trusted Proxy Handling

When SynVoid sits behind a load balancer or CDN, it needs to correctly identify the original client IP and protocol.

### Configuration

```toml
[server]
trusted_proxies = [
    "10.0.0.0/8",      # Private network
    "172.16.0.0/12",   # Docker network
    "192.168.0.0/16",  # Local network
    "127.0.0.1",       # Localhost
]

[security]
sanitize_forwarded_headers = true
```

### How It Works

1. **Trusted proxy detected** - Request comes from an IP in `trusted_proxies`
2. **Parse X-Forwarded-*** - Extract original client IP and protocol
3. **Validate** - Ensure forwarded values aren't spoofed
4. **Use for WAF decisions** - Rate limiting, blocking uses real client IP

### Example

```
Client → CDN (1.2.3.4) → SynVoid (10.0.0.1) → Upstream

Request received by SynVoid:
  X-Forwarded-For: 203.0.113.50
  X-Forwarded-Proto: https

SynVoid detects:
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

### How SynVoid Protects

When `sanitize_forwarded_headers = true`:

1. **Untrusted sources** - Headers are stripped entirely
2. **Trusted proxies** - Headers are parsed and validated
3. **Validation** - Only the first (original) client IP is used

```toml
[security]
sanitize_forwarded_headers = true
```

## Request Body Handling

### Size Limits

```toml
[http]
max_request_size = 1048576
```

### Content-Type Validation

There is no `strict_content_type` / `allowed_content_types` configuration in SynVoid;
content-type checks are performed by the protocol parsing layer and are not
operator-tunable today. Header and body volume are bounded by the `[http]` limits:

```toml
[http]
max_request_size = 1048576
max_header_size_ingress = 8192
max_header_size_egress = 8192
max_request_line_size = 8192
max_headers = 100
```

### Request Smuggling Prevention

SynVoid detects HTTP request smuggling attacks (CL/TE conflicts, H2 pseudo-header
conflicts, response queue poisoning). The detector has **no per-site configuration
key** — it is not wired to a `[attack_detection.request_smuggling]` table, and adding
one will not change behavior:

```toml
# There is no request_smuggling table under [attack_detection]; the only
# per-detector tables are sqli, xss, path_traversal, rfi, and ssrf.
[attack_detection]
enabled = true
```

## Configuration Options

### Security Defaults

```toml
[security]
# Response hardening
global_security_headers = true
more_clear_headers = ["Server", "X-Powered-By"]

# Proxy sanitization
sanitize_forwarded_headers = true

# Request limits (main [http] section)
# max_request_size, max_header_size_ingress, max_header_size_egress
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
3. **Disable specific checks** - If needed, disable path_traversal for a site

### Incorrect Client IP Detection

If client IPs appear as proxy IPs:

1. Verify proxy is in `trusted_proxies`
2. Check `sanitize_forwarded_headers` is enabled
3. Ensure proxy sends correct X-Forwarded-For headers

### Request Smuggling False Positives

Some legitimate proxies may trigger smuggling detection. Because the request-smuggling
detector has no per-site toggle, it cannot be disabled from config — reduce false
positives at the proxy instead (for example, avoid emitting both `Content-Length` and
`Transfer-Encoding`, and use the comma-separated `TE` form SynVoid expects):

```toml
# No [attack_detection.request_smuggling] table exists; this block has no effect.
# [attack_detection.path_traversal]
# enabled = false
```

## Best Practices

1. **Always use trusted_proxies** - Add your CDN, load balancer, or reverse proxy
2. **Enable sanitize_forwarded_headers** - Prevents header injection
3. **Remove information headers** - Add `Server` / `X-Powered-By` to `security.more_clear_headers`
4. **Configure size limits** - Prevent resource exhaustion
5. **Monitor blocked requests** - Watch for false positives

## See Also

- [ATTACK_DETECTION.md](./ATTACK_DETECTION.md) - Attack detection details
- [CONFIGURATION.md](./CONFIGURATION.md) - Sanitization configuration options
- [TROUBLESHOOTING.md](./TROUBLESHOOTING.md) - Debugging request issues
