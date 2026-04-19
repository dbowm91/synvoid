# Bot Protection

MaluWAF provides comprehensive bot detection and mitigation to protect your applications from automated traffic, scrapers, and AI crawlers.

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
enabled = true
block_ai_crawlers = true
```

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

### AI Crawler Blocking

Block AI training crawlers:

```toml
[defaults.bot.ai_crawlers]
enabled = true

[defaults.bot.ai_crawlers.block]
names = [
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

Challenge suspicious clients with JavaScript:

```toml
[defaults.bot.js_challenge]
enabled = true
secret = "your-challenge-secret"
```

### CSS Honeypot

Add invisible trap links that only bots follow:

```toml
[defaults.bot.css_honeypot]
enabled = true
hidden_link_class = "w3css"
follow_redirect = false

[defaults.bot.css_honeypot.traps]
paths = [
    "/hidden-admin-link",
    "/secret-crawler-only", 
    "/google-sitemap.xml"
]
```

### Proof-of-Work Challenge

Challenge suspicious clients with computational PoW:

```toml
[defaults.bot.pow_challenge]
enabled = true
difficulty = "medium"  # easy, medium, hard
timeout_seconds = 12  # Default is 12 seconds
```

| Difficulty | Target Bits | Typical Solve Time |
|------------|-------------|-------------------|
| easy       | 16 bits     | 1-2 seconds       |
| medium     | 24 bits     | 4-8 seconds       |
| hard       | 32 bits     | 15-30 seconds    |

### IP Whitelist

Whitelist specific IPs or ranges:

```toml
[defaults.bot.whitelist]
ip_ranges = [
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
| **Headless Browser** | Puppeteer, Selenium | Challenge (PoW: 12s timeout) |
| **Unknown** | No recognized signature | Challenge (PoW: 12s timeout) |

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
tail -f /var/log/maluwaf/access.log | grep -i bot
```

2. Add to allowlist:
```toml
[defaults.bot.whitelist]
ip_ranges = ["YOUR_IP/32"]
```

3. Lower challenge strictness:
```toml
[defaults.bot.js_challenge]
enabled = false  # Or set to lower mode
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

[defaults.bot.js_challenge]
enabled = false  # Disable JS challenge
```

## Metrics

Track bot detection via Prometheus:

```
maluwaf_bot_detected{type="scraper"}
maluwaf_bot_detected{type="ai_crawler"}
maluwaf_bot_challenged
maluwaf_bot_blocked
```

## See Also

- [ATTACK_DETECTION.md](./ATTACK_DETECTION.md) - Attack detection details
- [FLOOD_PROTECTION.md](./FLOOD_PROTECTION.md) - Connection-level protection
- [CONFIGURATION.md](./CONFIGURATION.md) - Bot configuration options
- [TROUBLESHOOTING.md](./TROUBLESHOOTING.md) - Debugging bot issues
- [FAQ.md](./FAQ.md) - Common bot protection questions
