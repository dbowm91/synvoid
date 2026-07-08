# Tarpit Operator Guide

SynVoid's anti-scraping tarpit traps automated crawlers and scanners by generating infinite, realistic-looking HTML pages using Markov chain text generation. Designed to waste attacker resources and slow automated attacks.

## 1. Overview

The tarpit intercepts requests from known scraper user agents and returns HTML pages that appear legitimate but contain links to other generated pages, creating an infinite crawl trap. The system has two modes:

- **Streaming mode** — sends HTML chunks with random delays to maximize resource waste
- **Single-shot mode** — returns a complete page with a configurable initial delay

The tarpit integrates with the HTTP server as a middleware handler and is triggered by WAF bot detection or direct user-agent matching.

**Key capabilities:**

- Markov chain text generation with 10 built-in technology corpora
- Configurable link density and depth limiting
- Global and per-IP admission control with RAII cleanup
- Per-session resource budgets (chunks, bytes, duration, idle)
- Input escaping for all attacker-controlled values
- Fingerprint-resistant content variation

## 2. How It Works

1. An incoming request is evaluated against configured scraper user-agent patterns
2. If the user agent matches (case-insensitive), the request enters the tarpit
3. The tarpit generates an HTML page containing:
   - Markov-generated title, paragraphs, and link text
   - Navigation links to other generated pages
   - A links section with `links_per_page` depth-aware links
   - Footer with related article links
4. Generated links follow the pattern `{seed}-{adjective}-{noun}-{4digit}[-{index}]`
5. In streaming mode, chunks are sent with configurable random delays (5–30ms by default)
6. The session terminates when any budget limit is reached

## 3. Enabling the Tarpit

The tarpit is **enabled by default** (`enabled = true`). Disable it by setting `enabled = false` in the `[tarpit]` config section or via the admin API at `PUT /config/defaults/tarpit`.

### User-Agent Matching

Pattern matching is case-insensitive. The default patterns include:

| Pattern | Covers |
|---------|--------|
| `scrapy` | Scrapy framework |
| `curl` | cURL CLI |
| `wget` | wget CLI |
| `python-requests` | Python requests library |
| `python-urllib` | Python urllib |
| `aiohttp` | Python async HTTP |
| `httpx` | Python httpx |
| `go-http` | Go HTTP client |
| `node-fetch` | Node.js fetch |
| `axios` | Axios HTTP client |
| `rubygems` | RubyGems fetcher |
| `java` / `okhttp` | Java HTTP clients |
| `feedparser` / `UniversalFeedParser` | RSS/Atom parsers |
| `libwww-perl` | Perl LWP |
| `PySpider` / `scrapeloader` | Python scrapers |
| `SiteAnalyzer` / `Screaming Frog` | SEO tools |

Custom patterns can be added via `scraper_user_agents` in the config. Additional bot detection (e.g., from WAF bot-fingerprinting) can also trigger tarpit routing independently of user-agent matching.

## 4. Content Generation

### Markov Chain Model

The tarpit uses a bigram (order-2) Markov chain trained on 10 built-in technology corpora covering web development, cloud computing, security, APIs, databases, containers, and DevOps topics.

- `generate_sentence(min_words, max_words)` — produces a single sentence
- `generate_sentences(count)` — produces multiple sentences (first sentence: 8–15 words, subsequent: 5–12)
- `generate_html_page(depth, max_depth, links_per_page, path_seed)` — produces a complete HTML page

Custom corpora are supported via `MarkovChain::with_custom_corpus(corpus, order)` or `TarpitHandler::with_custom_corpus(config, corpus)`.

### HTML Structure

Each generated page contains:

- `<!DOCTYPE html>` declaration with viewport meta tag
- `<header>` with Markov-generated title
- `<nav>` with 5 navigation links
- `<main>` with 3–6 paragraphs of generated content
- `<section>` with `links_per_page` crawl-trap links
- `<footer>` with 10 related article links

### Edge Cases

- **Empty model**: Falls back to `"The system is processing your request."`
- **`max_depth == 0`**: Clamped to 1 to prevent infinite zero-depth generation
- **Empty corpus**: Handled gracefully with degenerate fallback text
- **Empty path seed**: Defaults to `"page"` with a random suffix

## 5. Escaping and Safety

All attacker-controlled values are escaped before HTML interpolation:

| Function | Context | Characters Escaped |
|----------|---------|-------------------|
| `html_escape()` | HTML text content | `&` → `&amp;`, `<` → `&lt;`, `>` → `&gt;`, `"` → `&quot;`, `'` → `&#x27;` |
| `html_attr_escape()` | HTML attributes | Same as `html_escape` (documented for attribute context) |
| `js_string_escape()` | JavaScript string literals | `\` → `\\`, `'` → `\'`, `"` → `\"`, newlines → `\n`/`\r`/`\t`, `<` → `\x3c`, `>` → `\x3e`, `&` → `\x26` |
| `url_path_encode()` | URL path segments | Non-unreserved characters → percent-encoded (RFC 3986) |
| `sanitize_redirect_target()` | Redirect destinations | CRLF blocked, control chars rejected, absolute URLs only if host in allow list |

### Redirect Safety

`sanitize_redirect_target(target, allowed_hosts)` returns `Result<String, RedirectRejection>`:

| Rejection | Condition |
|-----------|-----------|
| `CrlfInjection` | Target contains `\r` or `\n` |
| `ControlCharacter` | Target contains ASCII 0–31 or 127 |
| `HostNotAllowed(host)` | Absolute URL whose host is not in the allow list |
| `InvalidRelativePath` | Relative path doesn't start with `/` or starts with `//` |

### Redirect Page Generation

`generate_redirect_page(target_path)` creates an HTML page with:

- `<meta http-equiv="refresh">` with a random 1–3 second delay
- A clickable link to the target as a fallback
- `<script>setTimeout(...)</script>` JavaScript fallback redirect
- All values escaped via `html_escape`, `html_attr_escape`, and `js_string_escape`

## 6. Admission Control

Admission control prevents resource exhaustion using tokio `Semaphore` primitives.

### Limits

| Setting | Default | Description |
|---------|---------|-------------|
| `max_concurrent` | 256 | Maximum concurrent tarpit sessions globally |
| `max_per_ip` | 4 | Maximum concurrent sessions per source IP |

### Behavior

- `TarpitAdmission::try_admit(ip)` attempts non-blocking acquisition of both global and per-IP permits
- Returns `Some(AdmissionGuard)` if admitted, `None` if either limit is reached
- `AdmissionGuard` is an RAII guard — permits are released automatically when dropped
- Per-IP semaphores are created lazily on first admission for each IP
- `active_count()` returns the approximate number of active sessions
- `active_count_for_ip(ip)` returns sessions for a specific IP

### Limitations

- Admission control is **not enforced** in single-shot `handle_request` mode — only the streaming `stream_request` path uses it
- The `TarpitRejection::AdmissionLimit` enum variant is defined but currently unused

## 7. Session Budgets

Each streaming session is tracked by `SessionBudget`, which enforces four resource limits:

| Budget | Default | Description |
|--------|---------|-------------|
| `max_duration_secs` | 600 (10 min) | Maximum total session lifetime |
| `max_chunks` | 500 | Maximum HTML segments sent per session |
| `max_bytes` | 50 MB (52,428,800) | Maximum total bytes sent per session |
| `max_idle_secs` | 30 | Maximum idle time before session close |
| `write_timeout_ms` | 5,000 | Per-chunk write timeout |

### Budget Enforcement

- `record_chunk(len)` increments counters and returns `false` when any limit is exceeded
- `is_expired()` checks if `max_duration_secs` has elapsed
- `is_idle()` checks if `max_idle_secs` has elapsed since last activity
- `state()` returns a snapshot of current consumption
- On session end, the handler yields `</body></html>` as the closing chunk

## 8. Fingerprint Resistance

The tarpit varies output across sessions to resist fingerprinting:

| Setting | Default | Description |
|---------|---------|-------------|
| `min_chunk_delay_ms` | 5 | Minimum delay between chunks |
| `max_chunk_delay_ms` | 30 | Maximum delay between chunks |
| `vary_content_type` | true | Randomly varies `Content-Type` header (`text/html; charset=utf-8` or `text/html`) |
| `vary_status_code` | true | Randomly varies HTTP status codes (configured but may not be fully applied in all code paths) |

Each session uses a per-session seeded RNG to vary:

- Content type selection
- Chunk delay timing (random within configured range)
- Generated text content
- Link paths and destinations

## 9. Redirect Handling

### Redirect Policies

| Policy | Description |
|--------|-------------|
| `RelativeOnly` (default) | Only relative paths allowed (must start with `/`, not `//`) |
| `AllowList(hosts)` | Specific absolute hosts permitted |
| `AllowAll` | Any URL allowed (not recommended for production) |

All modes block CRLF injection and control characters in redirect targets.

## 10. Metrics Reference

| Metric | Type | Description |
|--------|------|-------------|
| `synvoid.tarpit.requests` | counter | Total tarpit requests received |
| `synvoid.tarpit.admitted` | counter | Sessions admitted (always equals requests in single-shot mode) |
| `synvoid.tarpit.timed_out` | counter | Sessions terminated by budget/idle/timeout |
| `synvoid.tarpit.completed` | counter | Sessions finished naturally |
| `synvoid.tarpit.bytes_sent` | counter | Total bytes sent across all streaming sessions |
| `synvoid.tarpit.response_time` | histogram | Single-shot response time |

The `synvoid.requests.tarpitted` counter (in the worker pool) tracks total requests routed to the tarpit from the HTTP pipeline.

## 11. Configuration Reference

```toml
[tarpit]
# Enable/disable the tarpit (default: true)
enabled = true

# Maximum crawl depth before wrapping (default: 10)
max_depth = 10

# Number of links per page (default: 50)
links_per_page = 50

# Initial response delay in milliseconds (default: 100)
response_delay_ms = 100

# User-agent patterns to match (case-insensitive)
scraper_user_agents = [
    "scrapy", "curl", "wget", "python-requests",
    "python-urllib", "aiohttp", "httpx",
]

# Redirect policy: "relative_only" | "allow_list" | "allow_all"
redirect_policy = "relative_only"

# [tarpit.admission]
# Maximum concurrent sessions globally (default: 256)
max_concurrent = 256
# Maximum concurrent sessions per IP (default: 4)
max_per_ip = 4

# [tarpit.budget]
# Maximum session duration in seconds (default: 600)
max_duration_secs = 600
# Maximum chunks per session (default: 500)
max_chunks = 500
# Maximum bytes per session (default: 52428800 = 50MB)
max_bytes = 52428800
# Maximum idle time in seconds (default: 30)
max_idle_secs = 30
# Per-chunk write timeout in ms (default: 5000)
write_timeout_ms = 5000

# [tarpit.fingerprint]
# Minimum delay between chunks in ms (default: 5)
min_chunk_delay_ms = 5
# Maximum delay between chunks in ms (default: 30)
max_chunk_delay_ms = 30
# Randomly vary Content-Type header (default: true)
vary_content_type = true
# Randomly vary HTTP status codes (default: true)
vary_status_code = true
```

## 12. Known Limitations

- **Single-shot admission bypass**: `handle_request` (single-shot mode) does not enforce admission control limits — only `stream_request` (streaming mode) uses the `TarpitAdmission` semaphore
- **Status code variation**: `vary_status_code` is configured but may not be applied in all code paths
- **Unused rejection variant**: `TarpitRejection::AdmissionLimit` is defined but never returned
- **Unused manager**: `TarpitManager` exists but is not used by the handler — `TarpitHandler` manages its own `MarkovChain` instance directly
- **No integration tests**: The `synvoid-tarpit` crate has unit tests only; the handler integration is not covered by integration tests
- **Idle tracking**: `is_idle()` checks `last_activity` but activity is only updated on `record_chunk()` calls — if the client stalls between chunks, idle detection may be delayed
