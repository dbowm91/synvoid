# WAF Bot Detection Skill

## Overview

The MaluWAF bot detection system identifies and blocks automated clients (bots, crawlers, scrapers) using multiple detection methods including User-Agent analysis, JA3/JA4 fingerprinting, and configurable bot policies.

## Architecture

### Detection Methods

| Method | Source | Implementation |
|--------|--------|----------------|
| User-Agent analysis | Request header | `check_user_agent()` in `bot.rs` |
| JA3 fingerprint | TLS client hello | `check_ja3()` in `bot.rs` |
| JA4 fingerprint | TLS client hello | `check_ja4()` in `bot.rs` |
| Combined fingerprints | UA + JA3 + JA4 | `check_with_fingerprints()` in `bot.rs` |

### Entry Point

Bot detection is called from `check_bot_protection()` in `waf/mod.rs`:

```rust
// src/waf/mod.rs:check_bot_protection()
fn check_bot_protection(
    &self,
    client_ip: IpAddr,
    path: &str,
    user_agent: Option<&str>,
    ja4_hash: Option<&str>,  // W3.1: Now passed through
) -> Option<WafDecision>
```

### Call Chain

```
HTTP/TLS Request
    │
    ▼
WafCore::check_request_full()
    │
    ▼
check_bot_protection(client_ip, path, user_agent, ja4_hash)
    │
    ▼
bot_detector.check_with_fingerprints(user_agent, site_block_ai_crawlers, None, ja4_hash)
    │
    ├──► check_fingerprints(ja3_hash, ja4_hash)
    │       │
    │       ├──► check_ja3() → checks known_bot_ja3_hashes set
    │       │
    │       └──► check_ja4() → checks known_bot_ja4_hashes set
    │
    └──► check_user_agent() → blocks AI crawlers if configured
```

## JA4 Fingerprint Wiring (W3.1)

JA4 is computed during TLS handshake in `HttpsConnection`:

```rust
// src/tls/server.rs:56-63
impl HttpsConnection {
    fn new(stream: TlsStream<TcpStream>) -> Self {
        let client_hello_bytes = extract_client_hello_bytes_from_stream(&stream);
        let ja4_hash = client_hello_bytes.and_then(|bytes| compute_ja4(&bytes));
        Self {
            ja4_hash: Mutex::new(ja4_hash),
            // ...
        }
    }

    fn get_ja4(&self) -> Option<String> {
        self.ja4_hash.lock().clone()
    }
}
```

The JA4 is passed through `check_request_full()`:

```rust
// src/waf/mod.rs:872-881
pub async fn check_request_full(
    &self,
    client_ip: IpAddr,
    method: &str,
    path: &str,
    query_string: Option<&str>,
    headers: &http::HeaderMap,
    body: Option<&[u8]>,
    user_agent: Option<&str>,
    ja4_hash: Option<&str>,  // NEW: W3.1
) -> WafDecision
```

## Bot Detection Result

```rust
// src/waf/bot.rs
pub enum BotDetectionResult {
    Allowed,
    Blocked { reason: String, bot_type: String },
    Tarpit { reason: String, bot_type: String },
}
```

## Configuration

### Site-Level Bot Protection

In site TOML config:

```toml
[site.security]
# Block AI crawlers (ChatGPT, Claude, etc.)
block_ai_crawlers = true

# Known bot JA4 hashes (add custom known bots)
known_bot_ja4_hashes = [
    "t13d19192020...",  # Custom known bot
]
```

### BotDetector Structure

```rust
// src/waf/bot.rs
pub struct BotDetector {
    known_bot_ja3_hashes: HashSet<String>,
    known_bot_ja4_hashes: HashSet<String>,
    ai_crawler_patterns: Vec<Regex>,
    site_block_ai_crawlers: bool,
}
```

## Key Files

| File | Purpose |
|------|---------|
| `src/waf/bot.rs` | BotDetector implementation |
| `src/tls/server.rs:56-84` | JA4 computation in HttpsConnection |
| `src/waf/mod.rs:1181-1215` | check_bot_protection() |
| `src/http/server.rs` | Plain HTTP (no JA4 available) |
| `src/proxy.rs` | Proxy path (no JA4 available) |

## JA4 vs JA3

| Aspect | JA3 | JA4 |
|--------|-----|-----|
| Introduced | Earlier | TLS 1.3 support |
| Format | 32-char MD5 hash | Truncated SHA256 + components |
| Information | TLS version, ciphers, extensions | QUIC + TLS fingerprints |
| Coverage | All TLS clients | QUIC-aware clients |

## Working with Bot Detection

### Adding a New Known Bot

1. Obtain JA4 hash from logs:
   ```rust
   tracing::debug!("JA4: {:?}", ja4_hash);
   ```

2. Add to site config or global config

3. Hash must be lowercase (JA4 is case-sensitive)

### Testing Bot Detection

```rust
#[test]
fn test_ja4_detection() {
    let detector = BotDetector::new(config);
    let result = detector.check_ja4("t13d19192020...");
    assert!(matches!(result, Some(BotDetectionResult::Blocked { .. })));
}
```

## Common Issues

### JA4 Not Available

- Plain HTTP connections don't have JA4 (only TLS)
- Some TLS clients don't expose client hello in the right way
- JA4 computation can fail silently - always use `Option<String>`

### Bot Detection Not Triggering

- Check that `check_bot_protection` is called in `check_request_full()`
- Verify `ja4_hash` is being passed through the call chain
- Ensure known bot hashes are in lowercase (JA4 comparison is case-sensitive)
