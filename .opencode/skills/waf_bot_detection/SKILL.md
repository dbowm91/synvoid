---
name: waf_bot_detection
description: WAF bot detection — User-Agent matching (live) and JA3/JA4 TLS fingerprint matching (plumbed, hash sets empty in production). Use when touching bot policy, site `[bot]` overrides, or JA4 threading.
---

# WAF Bot Detection Skill

## Overview

The SynVoid bot detection system identifies and blocks automated clients (bots, crawlers, scrapers) using multiple detection methods including User-Agent analysis, JA3/JA4 fingerprinting, and configurable bot policies.

## Architecture

### Detection Methods

| Method | Source | Implementation |
|--------|--------|----------------|
| User-Agent analysis | Request header | `BotDetector::check_user_agent()` (private) in `crates/synvoid-waf/src/bot.rs` |
| JA3 fingerprint | TLS client hello | `BotDetector::check_ja3()` in `crates/synvoid-waf/src/bot.rs` |
| JA4 fingerprint | TLS client hello | `BotDetector::check_ja4()` in `crates/synvoid-waf/src/bot.rs` |
| Combined fingerprints | UA + JA3 + JA4 | `BotDetector::check_with_fingerprints()` in `crates/synvoid-waf/src/bot.rs` |

### JA3/JA4 wiring reality (corrected)

`BotDetector::with_ja4(...)` is **never called outside its own constructor
chain**. `BotDetector::new(...)` → `with_ja3(..., Vec::new())` →
`with_ja4(..., true, Vec::new(), Vec::new())`, so both `known_bot_ja3_hashes`
and `known_bot_ja4_hashes` are always **empty `HashSet`s** in production, and
the only construction site (`assemble_detectors` in `src/waf/assembly.rs`,
using `BotDetector::new`) cannot populate them. There is no config field or
`[bot]` TOML key for known-bot JA3/JA4 hashes anywhere in
`crates/synvoid-config` (`BotDefaults` in `crates/synvoid-config/src/defaults.rs`
carries only `block_ai_crawlers`, `enable_css_honeypot`, `enable_js_challenge`,
`known_bots_allow`, `ai_crawlers_block`, `scraper_patterns`, challenge
cookies/difficulty). Consequently `check_ja3()`/`check_ja4()` always return
`None`, `check_fingerprints()` always returns `None`, and JA4 threading through
the request path currently **gates nothing** — detection is effectively
User-Agent-only. The plumbing is present and correct; the hash sets are the
missing input.

### Entry Point

Bot detection runs in stage 2 (challenge/bot/rate/flood candidates) of the
`WafCore::check_request_full()` staged pipeline in `src/waf/mod.rs` (see
`architecture/enforcement_decision_contract.md` for the stage policy and
precedence). `check_bot_protection()` returns `Option<StagedOutcome>` (a
`WafDecision` directive plus its canonical `EnforcementCandidate`), not a
bare decision — outcomes fold through the deterministic reducer instead of
early-returning:

```rust
// src/waf/mod.rs — WafCore::check_bot_protection()
fn check_bot_protection(
    &self,
    client_ip: IpAddr,
    path: &str,
    user_agent: Option<&str>,
    ja4_hash: Option<&str>,
    site_bot_config: Option<&crate::config::site::SiteBotConfig>,
) -> Option<StagedOutcome>
```

`BotDetectionResult` maps to the canonical contract via
`synvoid_waf::enforcement::bot_candidate` (`Blocked`→`Block`,
`Tarpit`→`Tarpit`, `Allowed`→no claim); the automated-tool challenge path
maps to `EnforcementClass::Challenge` / `EnforcementSource::BotPolicy` /
`EnforcementReason::ChallengeRequired`. Keep the mapping single-sourced
there — do not duplicate class/source/reason literals.

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
    │       ├──► check_ja3() → checks known_bot_ja3_hashes set (ALWAYS EMPTY)
    │       │
    │       └──► check_ja4() → checks known_bot_ja4_hashes set (ALWAYS EMPTY)
    │
    └──► check_user_agent() → blocks AI crawlers if configured
```

## JA4 Fingerprint Wiring (W3.1)

JA4 is computed during TLS handshake in `HttpsConnection::new`
(`src/tls/server.rs`):

```rust
// src/tls/server.rs — HttpsConnection::new / get_ja4
use synvoid_tls::sni_peek::compute_ja4;

struct HttpsConnection {
    io: Mutex<Option<TokioIo<tokio_rustls::server::TlsStream<tokio::net::TcpStream>>>>,
    drop_requested: RunningFlag,
    ja4_hash: Mutex<Option<String>>,
}

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
// src/waf/mod.rs — WafCore::check_request_full
pub async fn check_request_full(
    &self,
    site_id: Option<&str>,
    ip: IpAddr,
    method: &str,
    path: &str,
    query: Option<&str>,
    headers: &http::HeaderMap,
    body: Option<&[u8]>,
    ua: Option<&str>,
    ja4_hash: Option<&str>,
    site_bot_config: Option<&crate::config::site::SiteBotConfig>,
    _ctx: Option<&RequestServices>,
) -> WafDecision
```

## Bot Detection Result

```rust
// crates/synvoid-waf/src/bot.rs
pub enum BotDetectionResult {
    Allowed { reason: String },
    Blocked { reason: String, bot_type: String },
    Tarpit { reason: String, bot_type: String },
}
```

## Configuration

### Site-Level Bot Protection

The site-level override section is `[bot]` (see
`config/sites/example.com.toml`), holding `SiteBotConfig`
(`crates/synvoid-config/src/site/defensive.rs`: `inherit`,
`block_ai_crawlers`, `enable_css_honeypot`, `enable_js_challenge`,
`challenge_type`):

```toml
[bot]
inherit = true
block_ai_crawlers = true
enable_css_honeypot = true
enable_js_challenge = false
```

There is **no** `known_bot_ja4_hashes` (or `known_bot_ja3_hashes`) config key
— see "JA3/JA4 wiring reality" above.

### BotDetector Structure

```rust
// crates/synvoid-waf/src/bot.rs
pub struct BotDetector {
    known_bots_allow: Arc<HashSet<String>>,
    ai_crawlers_block: Arc<HashSet<String>>,
    scraper_patterns: Arc<HashSet<String>>,
    known_bot_ja3_hashes: Arc<HashSet<String>>,  // empty in production
    known_bot_ja4_hashes: Arc<HashSet<String>>,  // empty in production
    block_ai_crawlers: bool,
    block_scrapers: bool,
}
```

Matching is delegated to the `isbot` crate (`static DEFAULT_BOTS: LazyLock<Bots>`)
plus the configured substring sets — there is no `ai_crawler_patterns: Vec<Regex>`
field.

## Key Files

| File | Purpose |
|------|---------|
| `crates/synvoid-waf/src/bot.rs` | BotDetector implementation (re-exported via `src/waf/mod.rs`) |
| `src/tls/server.rs` (`HttpsConnection::new` / `get_ja4`) | JA4 computation at TLS accept |
| `src/waf/mod.rs` (`WafCore::check_request_full` / `check_bot_protection`) | Staged pipeline + bot stage |
| `src/waf/assembly.rs` (`assemble_detectors`) | The only `BotDetector::new` construction site |
| `crates/synvoid-config/src/site/defensive.rs` | `SiteBotConfig` |
| `crates/synvoid-config/src/defaults.rs` (`BotDefaults`) | Global bot defaults |
| `src/http/server.rs` | Plain HTTP (no JA4 available) |
| `crates/synvoid-proxy/src/` (canonical; `src/proxy/` is a re-export shim) | Proxy path (no JA4 available) |

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

2. **There is no config key for it today.** Populating
   `known_bot_ja4_hashes` requires either a new `BotDefaults`/site config field
   wired through `assemble_detectors` to `BotDetector::with_ja4`, or calling
   `with_ja4` directly. Until then a new known bot only affects behavior if it
   matches `known_bots_allow` / `ai_crawlers_block` / `scraper_patterns`.

3. Hashes are matched case-insensitively: `check_ja3`/`check_ja4` test the raw
   input first, then `input.to_lowercase()` when the input contains any ASCII
   uppercase. Known hashes are lowercased once at construction.

### Testing Bot Detection

```rust
// A populated JA4 set is required — `BotDetector::new` leaves both hash sets
// empty, so use `with_ja4` in a test to exercise JA4 matching at all.
let detector = BotDetector::with_ja4(
    vec![],
    vec![],
    vec![],
    true,      // block_ai_crawlers
    false,     // block_scrapers
    vec![],    // known_bot_ja3_hashes
    vec!["t13d19192020...".to_string()],
);
let result = detector.check_ja4("t13d19192020...");
assert!(matches!(result, Some(BotDetectionResult::Blocked { .. })));
```

## Common Issues

### JA4 Not Available

- Plain HTTP connections don't have JA4 (only TLS)
- Some TLS clients don't expose client hello in the right way
- JA4 computation can fail silently - always use `Option<String>`

### Bot Detection Not Triggering

- Check that `check_bot_protection` is called in `check_request_full()`
- Verify `ja4_hash` is being passed through the call chain
- Remember both known-hash sets are empty in production: JA3/JA4 matching
  cannot fire regardless of the input hash
- Site `block_ai_crawlers` is an `Option<bool>` override; `None` falls back to
  the global `BotDefaults.block_ai_crawlers` (default `true`)
