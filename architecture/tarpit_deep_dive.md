# Tarpit Deep Dive

SynVoid's tarpit system traps automated scrapers and bots in infinite HTML page generation loops, consuming attacker resources without affecting legitimate users.

## Architecture

### Core Components

```
TarpitService
├── MarkovChain (text generation)
├── TarpitAdmission (concurrency control)
├── SessionBudget (resource tracking)
└── TarpitConfig (configuration)
```

### Markov Chain Generator

Order-2 Markov chain trained on technology/web corpora:

```rust
pub struct MarkovChain {
    model: HashMap<String, Vec<String>>,
    order: usize,  // 2 (bigram)
}
```

Generates realistic HTML pages with paragraphs, navigation links, and footer links. Supports custom corpus injection for domain-specific content.

### Admission Control

Semaphore-based concurrency limiting:

```rust
pub struct TarpitAdmission {
    global: Arc<Semaphore>,   // Default 256
    ip_map: Arc<Mutex<HashMap<IpAddr, Arc<Semaphore>>>>,  // Default 4 per IP
    max_per_ip: usize,
    active_count: Arc<AtomicUsize>,
}

// RAII guard automatically releases on drop
let _guard = admission.try_admit(ip)?;
```

### Session Budget

Per-session resource tracking:

```rust
pub struct SessionBudget {
    config: BudgetConfig,
    start: Instant,
    last_activity: Mutex<Instant>,
    chunks_sent: AtomicU64,
    bytes_sent: AtomicU64,
}
```

### Response Generation

```rust
pub fn generate_infinite_streaming_response(
    chain: &MarkovChain,
    max_depth: u32,
    links_per_page: u32,
) -> String {
    // Generates a single HTML page with Markov-generated content,
    // navigation links, content paragraphs, and footer links.
    // Called per-chunk inside the streaming handler loop.
}
```

## Fingerprint Resistance

To avoid tarpit detection:

- **Chunk delays**: 5-30ms configurable delay between chunks
- **Content-type variation**: Randomize between `text/html` variants
- **Status-code variation**: Occasionally return 200, mostly 200 with slow delivery
- **Header variation**: Randomize `Server`, `X-Powered-By` headers

## Redirect Safety

```rust
pub fn sanitize_redirect_target(
    target: &str,
    allowed_hosts: &[String],
) -> Result<String, RedirectRejection> {
    // 1. Reject CRLF injection
    if target.contains('\r') || target.contains('\n') {
        return Err(RedirectRejection::CrlfInjection);
    }
    
    // 2. Reject control characters
    if target.chars().any(|c| (c as u32) < 32 || c as u32 == 127) {
        return Err(RedirectRejection::ControlCharacter);
    }
    
    // 3. Absolute URLs: check host against allowed_hosts
    // 4. Relative paths: must start with / and not //
}
```

## Output Escaping

- `html_escape()` — Escape `<`, `>`, `&`, `"`, `'`
- `html_attr_escape()` — Escape for HTML attributes
- `js_string_escape()` — Escape for JavaScript strings
- `url_path_encode()` — Percent-encode for URL paths

## Integration Points

Triggered by scraper pattern detection in the WAF request path:
- User-agent matching for "scrapy", "curl", "wget", "python-requests", etc.
- Configurable per-site via `TarpitConfig`
- Admission control prevents resource exhaustion on the tarpit itself

## Key Types

| Type | Location | Purpose |
|------|----------|---------|
| `MarkovChain` | `crates/synvoid-tarpit/src/generator.rs` | Text generation engine |
| `TarpitAdmission` | `crates/synvoid-tarpit/src/admission.rs` | Concurrency control |
| `SessionBudget` | `crates/synvoid-tarpit/src/budget.rs` | Per-session resource tracking |
| `TarpitConfig` | `crates/synvoid-tarpit/src/config.rs` | Configuration |
| `TarpitHandler` | `src/tarpit/handler.rs` | Root-owned service entry point |
