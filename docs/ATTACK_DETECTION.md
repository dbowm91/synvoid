# Attack Detection

SynVoid provides comprehensive attack detection across multiple vulnerability categories. This document explains how the detection pipeline works, how to interpret results, and how to debug detection issues.

## Detection Pipeline Overview

When a request enters SynVoid, it passes through multiple detection layers. Understanding this flow helps you configure protection effectively and debug false positives/negatives.

```
Client Request
     │
     ▼
┌─────────────────────────┐
│   1. Rate Limiting      │ ◄── First line of defense
│   • Per-IP limits       │     Controls request volume
│   • Global limits       │     before expensive parsing
└─────────────────────────┘
     │
     ▼
┌─────────────────────────┐
│   2. Connection Limit   │ ◄── Connection-level protection
│   • Connection count    │     Enforces connection limits
│   • Connection rate     │
└─────────────────────────┘
     │
     ▼
┌─────────────────────────┐
│   3. Protocol Parsing  │ ◄── Valid HTTP structure
│   • Header validation  │     Rejects malformed requests
│   • Method filtering    │     early
└─────────────────────────┘
     │
     ▼
┌─────────────────────────┐
│   4. Bot Detection     │ ◄── Automated traffic
│   • User-agent analysis │     Identifies scanners
│   • Behavioral analysis │     and crawlers
│   • Honeypot endpoints  │
└─────────────────────────┘
     │
     ▼
┌─────────────────────────┐
│   5. Attack Detection   │ ◄── Payload inspection
│   • SQLi, XSS, etc.      │     Core WAF functionality
│   • Pattern matching    │
└─────────────────────────┘
     │
     ▼
┌─────────────────────────┐
│   6. Challenge (opt)    │ ◄── JavaScript/CSS challenges
│   • PoW challenge       │     Browser verification
│   • JS challenge        │
└─────────────────────────┘
     │
     ▼
   Allow / Block / Challenge / Tarpit
```

Each layer can independently block, challenge, or allow a request. The request is rejected at the first layer that decides to block.

## WAF Decision Types

When SynVoid makes a protection decision, it returns one of these:

| Decision | HTTP Code | Description |
|----------|-----------|-------------|
| **Pass** | 200 (or upstream response) | Request allowed through |
| **Block** | 403 (configurable) | Request denied |
| **Drop** | - | Connection silently closed |
| **Challenge** | 200 (HTML challenge page) | Browser verification required |
| **Stall** | - | Connection held indefinitely |
| **Tarpit** | 200 (fake response) | Fake content to waste attacker time |

### Understanding Each Decision

**Pass**: The request passed all checks and was forwarded to the upstream server.

**Block**: The request was identified as malicious and denied. The client receives an error page (default 403 Forbidden).

**Drop**: The connection is silently terminated without response. Attackers cannot distinguish between "server not responding" and "you've been blocked."

**Challenge**: The client must solve a proof-of-work or JavaScript challenge. Legitimate browsers complete this automatically.

**Stall**: The connection is held open indefinitely. This consumes attacker resources while appearing as a slow server.

**Tarpit**: The client receives fake but convincing responses. This wastes attacker time and can reveal their tools/scanning patterns.

### When to Use Each Decision Type

Use this guide to choose the appropriate action for your scenario:

| Decision | Best For | Avoid When |
|----------|----------|------------|
| **Block** | Most production sites; clear attack signatures | Legitimate users might send suspicious-looking but safe requests |
| **Stall** | High-security environments; honeypots | Users expect fast responses; aggressive attackers might cause resource exhaustion |
| **Tarpit** | Baiting attackers; gathering intelligence | Performance is critical; high-volume legitimate traffic |
| **Drop** | Extreme cases; confirmed malicious actors | You need to inform users why they were denied |
| **Challenge** | General bot mitigation | Users have JavaScript disabled; API-only access |

#### Recommended Configurations by Use Case

**Standard Website:**
```toml
[defaults.attack_detection]
action = "block"  # Clear feedback, easy to debug
```

**High-Security / Honeypot:**
```toml
[defaults.attack_detection]
action = "stall"  # Don't reveal anything
```

**Anti-Scraping:**
```toml
[defaults.attack_detection]
action = "tarpit"  # Waste scraper time
```

## Detection Methods

### SQL Injection (SQLi)

Uses libinjection for detection with fingerprinting:
- Tests query strings, POST bodies, headers, and cookies
- Handles URL-encoded and double-encoded payloads
- Returns fingerprint for logging and analysis

**Example detections:**
```
1' OR '1'='1
1 UNION SELECT * FROM users
'; DROP TABLE users;--
```

**How it works:**
1. Input is normalized (URL decode, case normalization)
2. libinjection analyzes for SQL syntax patterns
3. Fingerprint identifies the specific attack type
4. Decision made based on paranoia level

### Cross-Site Scripting (XSS)

Context-aware detection testing multiple HTML parsing contexts:
- Data state
- Unquoted attributes
- Single/double quoted attributes
- Backtick quoted values

**Example detections:**
```
<script>alert('xss')</script>
<img src=x onerror=alert(1)>
<svg onload=alert(1)>
```

**How it works:**
1. Input parsed as HTML document
2. Each parsing context checked for injection
3. Context determines which payloads are dangerous
4. Tags, attributes, and event handlers analyzed

### Path Traversal

Pattern-based detection using Aho-Corasick automaton:
- Basic traversal: `../`, `..\`
- URL-encoded: `%2e%2e%2f`, `%252e%252e`
- Double-encoded variants
- Sensitive file access: `/etc/passwd`, `/windows/system32`
- Protocol handlers: `file://`, `php://`, `expect://`

### Server-Side Request Forgery (SSRF)

- Internal IP detection (127.0.0.1, 10.x.x.x, 172.16-31.x.x, 192.168.x.x)
- Cloud metadata endpoints (169.254.169.254, metadata.google, metadata.azure)
- Alternative localhost representations (0.0.0.0, localhost, [::1])
- IPv6 zone IDs (`%eth0`)
- Dangerous protocols (gopher://, dict://)

### Command Injection

Pattern-based detection for shell command injection:
- Command separators (`;`, `|`, `&&`, `||`, `&`)
- Command substitution (`` ` ` ``, `$( )`)
- Common command names (`ls`, `cat`, `wget`, `curl`, `bash`, `sh`)
- Environment variable access (`$VAR`, `${VAR}`)

**Example detections:**
```
; ls -la
| cat /etc/passwd
$(whoami)
`id`
```

### JWT Validation

Analyzes JWT tokens for security issues:
- Algorithm confusion attacks (changing `alg` to `none`)
- Weak secret detection
- Expiration validation
- Key confusion prevention

### LDAP Injection

Detects LDAP injection attempts:
- Filter manipulation (`*)(uid=*))(|(uid=*)
- DN manipulation
- Comment injection

### Open Redirect

Validates redirect URLs:
- Blocked protocols (javascript:, data:, vbscript:)
- External domain redirects (configurable allowlist)
- IP-based redirects
- Newline injection protection
- Homograph attack protection

### Server-Side Template Injection (SSTI)

- Jinja2 patterns (`{{7*7}}`, `{% %}`)
- Template syntax in user input
- Common template engine payloads

### XML External Entity (XXE)

XML External Entity detection:
- Entity declaration detection (`<!ENTITY`)
- DTD inclusion detection
- External entity reference (`SYSTEM`, `PUBLIC`)

### XPath Injection

XPath injection attack detection:
- XPath expression injection
- Predicate manipulation
- Function injection

### Request Smuggling

HTTP Request Smuggling detection:
- Content-Length vs Transfer-Encoding conflicts
- H2 CL/TE smuggling
- Response queue poisoning
- Proper comma-separated TE header parsing

### Remote File Inclusion (RFI)

- URL parameter injection detection
- IP address in URL parameters
- PHP-specific RFI vectors
- Protocol handlers in parameters

### Header Validation

Validates incoming HTTP headers:
- Maximum header length enforcement
- Invalid characters detection
- Known malicious header patterns

## Configuration

### Paranoia Levels

Configure detection sensitivity:

```toml
[defaults.attack_detection]
paranoia_level = 2  # 1=low, 2=medium, 3=high
```

- **Level 1 (Low)**: Minimal false positives, basic detection
- **Level 2 (Medium)**: Balanced detection, moderate false positives (recommended)
- **Level 3 (High)**: Aggressive detection, higher false positive rate

**What changes between levels:**

| Detection Type | Level 1 | Level 2 | Level 3 |
|----------------|---------|---------|---------|
| SQL Injection | Only obvious patterns | + Encoded variants | + Aggressive matching |
| XSS | Tag-based | + Attribute-based | + Context-aware |
| Path Traversal | Basic `../` | + Encoded | + All variants |

### Actions

Configure response to detected attacks:

```toml
[defaults.attack_detection]
action = "stall"  # "stall", "block", or "log"
```

- **stall**: Hold connection indefinitely (stealth mode)
- **block**: Return error response
- **log**: Log but allow request

### Custom Patterns

Add site-specific detection patterns:

```toml
[defaults.attack_detection]
custom_sqli_patterns = ["union.*select", "sleep\\("]
custom_xss_patterns = ["<script", "javascript:"]
custom_rce_patterns = ["nmap", "nc "]
```

### Domain Allowlists

For SSRF and open redirect detection:

```toml
[defaults.attack_detection.ssrf]
allowed_domains = ["api.stripe.com", "api.github.com"]

[defaults.attack_detection.open_redirect]
allowed_domains = ["example.com", "trusted-site.com"]
```

## Debugging Detection Issues

### Viewing Detection Logs

Enable detailed logging to understand what SynVoid is detecting:

```bash
# Set log level to debug
curl -X PUT -H "Authorization: Bearer <token>" \
  -H "Content-Type: application/json" \
  -d '{"level": "debug"}' \
  http://127.0.0.1:8081/api/config/log-level
```

### Testing Detection

Use curl to test specific payloads:

```bash
# Test SQL injection
curl -v -H "Host: example.com" \
  "http://localhost/search?term=1'%20OR%20'1'='1"

# Test XSS
curl -v -H "Host: example.com" \
  "http://localhost/comment?text=<script>alert(1)</script>"

# Test path traversal
curl -v -H "Host: example.com" \
  "http://localhost/file?path=../../etc/passwd"
```

### Common False Positive Scenarios

**1. URL Parameters with SQL-Like Content**

Some legitimate URLs contain SQL-like patterns:
- Search: `/search?q=order+by+1`
- API: `/api/items?filter=status=active`

**Solution:** Add to allowlist or use relaxed detection for specific paths.

**2. Rich Text Editors**

Content management systems often contain XSS-like patterns in stored content:
- `<img src="...">` in blog posts
- JavaScript in HTML emails

**Solution:** Disable XSS detection for admin paths or specific user roles.

**3. Internal API Calls**

Services calling your API may trigger bot detection:
- Monitoring services
- Webhooks from trusted services

**Solution:** Add IP ranges to trusted list.

### Debugging Steps

**Step 1: Identify the Detection**

Check logs to see which detection type triggered:

```bash
# Filter logs for WAF events
tail -f /var/log/synvoid/access.log | grep WAF
```

**Step 2: Understand the Payload**

Look at the actual request that triggered detection:

```bash
# Enable debug logging and reproduce
RUST_LOG=debug ./synvoid -f

# Make the request again
curl -H "Host: example.com" "http://localhost/path?param=value"
```

**Step 3: Determine the Fix**

| Issue | Solution |
|-------|----------|
| False positive | Add pattern to allowlist, lower paranoia, disable specific check |
| False negative | Raise paranoia level, enable detection type, add custom patterns |
| Detection not working | Check that attack_detection is enabled globally and per-site |

## Tuning for Your Application Stack

### PHP Applications

PHP applications often use:
- Query parameters with SQL-like syntax (`?order=asc`, `?filter=status`)
- File upload functionality
- Dynamic includes

**Recommended settings:**
```toml
[site.attack_detection]
paranoia_level = 2
```

### REST APIs

REST APIs frequently use:
- JSON in request bodies
- Path parameters that look like traversal (`/users/1`)
- Complex query filters

**Recommended settings:**
```toml
[site.attack_detection]
paranoia_level = 2
action = "log"  # Start with logging, then switch to block
```

### Single Page Applications (SPAs)

SPAs typically have:
- Client-side routing
- Less server-side input validation
- API-only backend

**Recommended settings:**
```toml
[site.attack_detection]
paranoia_level = 2

# API-only, so focus on SQLi and XSS
[site.attack_detection.xss]
enabled = true

[site.attack_detection.sqli]
enabled = true
```

### Content Management Systems (CMS)

CMS platforms like WordPress use:
- URL parameters for content queries
- Rich text content that may contain XSS-like patterns
- Plugin ecosystems with varied security

**Recommended settings:**
```toml
[site.attack_detection]
paranoia_level = 2
action = "stall"  # Silent blocking for CMS
```

## Metrics

Attack detection is tracked via Prometheus metrics:

```
synvoid_attack_detected{type="sqli"}
synvoid_attack_detected{type="xss"}
synvoid_attack_detected{type="ssrf"}
# ... etc
```

### Key Metrics

| Metric | Description |
|--------|-------------|
| `synvoid_attack_detected_total` | Counter of all detected attacks by type |
| `synvoid_waf_decision_total` | Decisions made (pass/block/challenge) |
| `synvoid_blocklist_size` | Number of blocked IPs |
| `synvoid_rate_limit_exceeded` | Rate limit violations |

### Query Examples

```promql
# Attack rate over time
rate(synvoid_attack_detected_total[5m])

# Top attack types
topk(10, synvoid_attack_detected_total)

# Blocked request percentage
sum(rate(synvoid_waf_decision_total{decision="block"}[5m]))
/ sum(rate(synvoid_waf_decision_total[5m])) * 100
```

## See Also

- [FLOOD_PROTECTION.md](./FLOOD_PROTECTION.md) - Connection-level flood and DDoS protection
- [REQUEST_SANITIZATION.md](./REQUEST_SANITIZATION.md) - Request sanitization and header handling
- [CONFIGURATION.md](./CONFIGURATION.md) - Attack detection configuration options
- [TROUBLESHOOTING.md](./TROUBLESHOOTING.md) - Debugging false positives/negatives
