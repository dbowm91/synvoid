# Bot Protection

SynVoid provides comprehensive bot detection and mitigation to protect your applications from automated traffic, scrapers, and AI crawlers.

## Overview

Bot protection is integrated into the WAF pipeline and operates at multiple levels:

```
Request → IP Reputation → User-Agent Analysis → Behavioral Analysis → Challenge → Decision
```

## How Bot Detection Works

### 1. IP Reputation

Checks against known malicious IP databases and tracks:
- Previously flagged attack sources
- Datacenter IPs (often used for scraping)
- Proxy/VPN detection
- Geographic anomalies

### 2. User-Agent Analysis

Analyzes the User-Agent header to identify:
- Known search engine crawlers (allowlisted)
- Known malicious bots
- AI crawler signatures
- Anomalous or missing User-Agents

### 3. Behavioral Analysis

Monitors request patterns for:
- Unusual request rates
- Crawling patterns (sequential URLs)
- Headless browser indicators
- Automation tool signatures

### 4. Challenge System

Challenges suspicious clients with:
- JavaScript challenges
- CSS honeypot traps
- Proof-of-work challenges (12 second timeout)

## Configuration

### Basic Setup

```toml
[defaults.bot]
block_ai_crawlers = true
```

`[defaults.bot]` has no `enabled` key — `block_ai_crawlers` (default `true`) and
`enable_css_honeypot` (default `true`) are the individual switches.

### Known Bots Allowlist

Allow legitimate crawlers:

```toml
[defaults.bot]
known_bots_allow = [
    "googlebot",
    "googleother", 
    "bingbot",
    "yandex",
    "duckduckbot",
    "slurp",
    "applebot",
    "facebookexternalhit",
    "twitterbot"
]
```

The shipped default is `["googlebot", "bingbot", "yandex", "duckduckbot"]`; the wider list
above is opt-in.

### AI Crawler Blocking

Block AI training crawlers. `ai_crawlers_block` is a flat list of User-Agent substrings
(there is no `[defaults.bot.ai_crawlers]` sub-table):

```toml
[defaults.bot]
block_ai_crawlers = true

ai_crawlers_block = [
    "GPTBot",
    "ChatGPT-User",
    "ClaudeBot",
    "Google-Extended",
    "Amazonbot",
    "anthropic-ai",
    "cohere-ai",
    "PerplexityBot",
    "YouBot"
]
```

### JavaScript Challenge

Challenge suspicious clients with JavaScript. There is no `[defaults.bot.js_challenge]`
sub-table and no `secret` key — the JS challenge is a boolean plus a difficulty:

```toml
[defaults.bot]
enable_js_challenge = true
js_difficulty = 1        # integer 1..=; default 1
challenge_cookie_name = "synvoid_challenge"
challenge_window_secs = 300
```

### CSS Honeypot

Add invisible trap links that only bots follow. The honeypot is a single boolean under
`[defaults.bot]`; trap paths are not configurable here:

```toml
[defaults.bot]
enable_css_honeypot = true
```

### Proof-of-Work Challenge

Challenge suspicious clients with computational PoW. PoW defaults live at
`[defaults.pow_challenge]` (**not** under `[defaults.bot]`), and `difficulty` is an integer
work factor, not a `easy`/`medium`/`hard` string:

```toml
[defaults.pow_challenge]
enabled = true
difficulty = 6            # integer work factor; default 6
adaptive_difficulty = true
max_difficulty = 12
timeout_secs = 60         # default 60 seconds
window_secs = 300
prefer_wasm = true

[defaults.pow_challenge.block]
enabled = false
ban_duration = "1h"
```

| Key | Default | Description |
|-----|---------|-------------|
| `difficulty` | `6` | Integer work factor (higher = slower to solve) |
| `adaptive_difficulty` | `true` | Scale difficulty to measured throughput |
| `max_difficulty` | `12` | Ceiling when adaptive difficulty is on |
| `timeout_secs` | `60` | How long a client has to submit a solution |
| `window_secs` | `300` | Rate-limit window for PoW attempts |

### IP Whitelist

Whitelist specific IPs or ranges. There is no `[defaults.bot.whitelist]` section; bot
exemptions use the site whitelist:

```toml
[site.whitelist]
networks = [
    "10.0.0.0/8",
    "192.168.0.0/16"
]
```

## Bot Categories

| Category | Description | Default Action |
|----------|-------------|----------------|
| **Search Engine** | Google, Bing, etc. | Allow |
| **Social Media** | Facebook, Twitter bots | Allow |
| **AI Crawler** | GPTBot, ClaudeBot, etc. | Block (configurable) |
| **Security Scanner** | sqlmap, nikto, etc. | Block |
| **Scraper** | Generic scraping tools | Block |
| **Headless Browser** | Puppeteer, Selenium | Challenge (PoW: 60s timeout) |
| **Unknown** | No recognized signature | Challenge (PoW: 60s timeout) |

## Testing Bot Protection

```bash
# Test with a scraper user agent (should be blocked)
curl -H "Host: example.com" \
  -H "User-Agent: sqlmap/1.4" \
  http://localhost/

# Test with Google bot (should be allowed)
curl -H "Host: example.com" \
  -H "User-Agent: Mozilla/5.0 (compatible; Googlebot/2.1)" \
  http://localhost/

# Test with AI crawler (depends on config)
curl -H "Host: example.com" \
  -H "User-Agent: CCBot/2.0" \
  http://localhost/
```

## Troubleshooting

### Legitimate Traffic Being Blocked

1. Check which bot category is blocking:
```bash
tail -f /var/log/synvoid/access.log | grep -i bot
```

2. Add to allowlist:
```toml
[site.whitelist]
ips = ["YOUR_IP"]
networks = ["YOUR_IP/32"]
```

3. Lower challenge strictness:
```toml
[defaults.bot]
enable_js_challenge = false  # Disable the JS challenge
js_difficulty = 1            # Or lower the work factor
```

### Googlebot Being Blocked

Verify the User-Agent is actually Googlebot (attackers may spoof it):

```toml
[defaults.bot]
# Googlebot performs reverse DNS lookup to verify
# Add extra allowlist just in case
known_bots_allow = ["googlebot", "googleother"]
```

### Too Many Challenges

If too many legitimate users are being challenged:

```toml
[defaults.bot]
block_ai_crawlers = false  # Disable AI crawler blocking
enable_js_challenge = false  # Disable JS challenge

[defaults.pow_challenge]
difficulty = 4             # Lower the PoW work factor (default 6)
```

## Metrics

Bot detection does not export its own metrics series. Bot, challenge and PoW decisions
appear in the standard WAF blocking counters — per-attack-type blocks are available on the
admin API at `GET /api/stats` under `blocked_by_type`, and there is no
`synvoid_bot_detected` / `synvoid_bot_challenged` / `synvoid_bot_blocked` series.

## See Also

- [ATTACK_DETECTION.md](./ATTACK_DETECTION.md) - Attack detection details
- [FLOOD_PROTECTION.md](./FLOOD_PROTECTION.md) - Connection-level protection
- [CONFIGURATION.md](./CONFIGURATION.md) - Bot configuration options
- [TROUBLESHOOTING.md](./TROUBLESHOOTING.md) - Debugging bot issues
- [FAQ.md](./FAQ.md) - Common bot protection questions
