# Tarpit Architecture

## 1. Purpose and Responsibility

The Tarpit module (`crates/synvoid-tarpit/`) provides an **anti-scraping tarpit** that generates infinite, slowly-expanding HTML pages using Markov chain text generation with configurable link density. Designed to waste scraper resources. Hardened in Milestone C Phase 4 with input escaping, admission control, session budgets, fingerprint resistance, and redirect safety.

**Core Responsibilities:**
- Generate infinite, slowly-expanding HTML pages
- Markov chain text generation with configurable link density
- Scraper user-agent detection and tarpit decision logic
- Input escaping for all attacker-controlled values before HTML interpolation
- Concurrent session admission control (global + per-IP)
- Per-session resource budgets (chunks, bytes, duration, idle)
- Fingerprint-resistant content variation (delay ranges, status codes, content types)
- Safe redirect generation with CRLF/injection prevention

---

## 2. Key Data Structures

```rust
// Escaping module: synvoid-tarpit::escaping
pub fn html_escape(input: &str) -> String;
pub fn html_attr_escape(input: &str) -> String;
pub fn js_string_escape(input: &str) -> String;
pub fn url_path_encode(input: &str) -> String;
pub fn sanitize_redirect_target(target: &str) -> Result<String, RedirectRejection>;

pub enum RedirectRejection {
    CrlfInjection,
    ControlCharacter,
    AbsoluteUrlNotAllowed { host: String },
}

// Admission control: synvoid-tarpit::admission
pub struct TarpitAdmission {
    global_semaphore: Arc<Semaphore>,
    per_ip_semaphores: DashMap<IpAddr, Arc<Semaphore>>,
}

pub struct AdmissionGuard {
    _global: OwnedSemaphorePermit,
    _per_ip: OwnedSemaphorePermit,
}

// Budget tracking: synvoid-tarpit::budget
pub struct SessionBudget {
    chunks_sent: AtomicU64,
    bytes_sent: AtomicU64,
    start_time: Instant,
    last_activity: AtomicU64,
}

// Redirect policy: synvoid-tarpit::redirect
pub enum RedirectPolicy {
    RelativeOnly,
    AllowList(Vec<String>),
    AllowAll,
}

pub struct TarpitManager {
    chain: Arc<RwLock<MarkovChain>>,
    config: TarpitConfig,
}

pub struct TarpitConfig {
    pub enabled: bool,
    pub max_depth: u32,
    pub links_per_page: u32,
    pub min_chunk_delay_ms: u64,
    pub max_chunk_delay_ms: u64,
    pub max_concurrent: usize,
    pub max_per_ip: usize,
    pub max_duration_secs: u64,
    pub max_chunks: u64,
    pub max_bytes: u64,
    pub max_idle_secs: u64,
    pub scraper_patterns: Vec<String>,
    pub redirect_policy: RedirectPolicy,
}

pub struct MarkovChain {
    // Text/HTML generation state
}
```

---

## 3. Public API

| Method | Module | Description |
|--------|--------|-------------|
| `html_escape(input)` | `escaping` | Escape HTML special characters (`<`, `>`, `&`, `"`, `'`) |
| `html_attr_escape(input)` | `escaping` | Escape for use inside HTML attributes |
| `js_string_escape(input)` | `escaping` | Escape for safe JS string interpolation |
| `url_path_encode(input)` | `escaping` | Encode for URL path segments |
| `sanitize_redirect_target(target)` | `escaping` | Validate and sanitize redirect target; rejects CRLF, control chars, absolute URLs not in allow list |
| `TarpitAdmission::try_acquire(ip)` | `admission` | Attempt to acquire global + per-IP permit; returns `AdmissionGuard` RAII on success |
| `TarpitAdmission::new(max_concurrent, max_per_ip)` | `admission` | Constructor with configurable limits |
| `SessionBudget::new(config)` | `budget` | Create budget with configured limits |
| `SessionBudget::record_chunk(bytes)` | `budget` | Record chunk sent; returns `false` when any budget is exceeded |
| `SessionBudget::is_expired()` | `budget` | Check if duration or idle budget is exceeded |
| `TarpitManager::new(config)` | root | Constructor |
| `generate_page(current_depth, path_seed)` | root | Generate tarpit page |
| `generate_redirect_page(path, user_agent, config)` | root | Generate redirect page; returns `Result<String, RedirectRejection>` |
| `handle_request(request, config)` | root | Handle incoming request with admission control and budget tracking |
| `stream_request(request, config)` | root | Stream tarpit response with budget enforcement |
| `is_scraper_user_agent(ua)` | root | Detect known scrapers |
| `should_tarpit(is_bot, user_agent)` | root | Decision logic |

---

## 4. Integration Points

- **HTTP Server**: `handle_request` and `stream_request` are called from the tarpit handler; both use `TarpitAdmission` for concurrency gating and `SessionBudget` for per-session resource limits
- **WAF**: Bot detection triggers tarpit via `should_tarpit`
- **Redirects**: `generate_redirect_page` returns `Result<String, RedirectRejection>` — callers must handle rejection

---

## 5. Key Implementation Details

### 5.1 Escaping Module

All attacker-controlled values are escaped before interpolation into HTML:
- `html_escape` / `html_attr_escape` / `js_string_escape` — applied to path, query parameters, headers, and user-agent before embedding in tarpit HTML
- `url_path_encode` — applied to generated link targets
- `sanitize_redirect_target` — validates redirect destinations: blocks CRLF injection (`\r\n`), rejects control characters (bytes 0x00–0x1F, 0x7F), and blocks absolute URLs unless the host matches an allow list

### 5.2 Admission Control

- Global semaphore (default 256 concurrent sessions) prevents total resource exhaustion
- Per-IP semaphore (default 4 concurrent sessions) prevents single-source flooding
- Uses `OwnedSemaphorePermit` for RAII-based automatic cleanup when sessions end
- Per-IP entries are cleaned up when the count drops to zero

### 5.3 Budget Tracking

`SessionBudget` enforces four limits per session:
- `max_duration_secs` (default 600s) — total session lifetime
- `max_chunks` (default 500) — maximum number of chunks sent
- `max_bytes` (default 50MB) — maximum total bytes sent
- `max_idle_secs` (default 30s) — maximum idle time between chunks

`record_chunk()` returns `false` when any limit is exceeded, signaling the handler to terminate the session. `is_expired()` checks duration and idle budgets independently.

### 5.4 Fingerprint Resistance

- Per-session seeded RNG (scoped via `rand::rng()` to avoid Send/Sync issues) varies content across sessions
- Configurable chunk delay range (`min_chunk_delay_ms` / `max_chunk_delay_ms`) creates varied timing signatures
- Varied HTTP status codes across sessions
- Content type variation per session prevents fingerprinting

### 5.5 Redirect Safety

`RedirectPolicy` controls redirect target validation:
- `RelativeOnly` (default) — only relative paths are allowed
- `AllowList(hosts)` — specific absolute hosts are permitted
- `AllowAll` — any absolute URL is permitted (not recommended for production)

All modes block CRLF injection and control characters in redirect targets.

### 5.6 Edge-Case Guards

- `max_depth == 0` is clamped to 1 to prevent infinite zero-depth generation
- Empty Markov model returns a fallback sentence instead of panicking
- Empty corpus is handled gracefully with degenerate fallback text

### 5.7 Metrics

| Counter | Description |
|---------|-------------|
| `synvoid.tarpit.admitted` | Sessions accepted through admission control |
| `synvoid.tarpit.timed_out` | Sessions terminated by budget exhaustion |
| `synvoid.tarpit.completed` | Sessions that finished naturally |
| `synvoid.tarpit.bytes_sent` | Total bytes sent across all tarpit sessions |

### 5.8 Markov Chain Generation

- Generates realistic-looking text that expands infinitely
- Each page contains links to deeper pages (configurable density via `links_per_page`)
- Depth limiting via configurable `max_depth` prevents runaway recursion
- User-agent pattern matching identifies known scrapers (scrapy, curl, wget, python-requests)
