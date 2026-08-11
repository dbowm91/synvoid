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
    order: usize,  // 2 (bigram)
    transitions: HashMap<Vec<char>, HashMap<char, usize>>,
    corpus: Vec<String>,
}
```

Generates realistic HTML pages with paragraphs, navigation links, and footer links. Supports custom corpus injection for domain-specific content.

### Admission Control

Semaphore-based concurrency limiting:

```rust
pub struct TarpitAdmission {
    global_semaphore: Arc<Semaphore>,   // Default 256
    per_ip: DashMap<IpAddr, Arc<Semaphore>>,  // Default 4 per IP
}

// RAII guard automatically releases on drop
let _guard = admission.try_acquire(ip)?;
```

### Session Budget

Per-session resource tracking:

```rust
pub struct SessionBudget {
    chunks_sent: AtomicU64,   // Default max: 500
    bytes_sent: AtomicU64,    // Default max: 50MB
    start_time: Instant,
    last_chunk: Instant,      // Idle timeout: 30s
    max_duration: Duration,   // Default: 600s
}
```

### Response Generation

```rust
pub fn generate_infinite_streaming_response(
    chain: &MarkovChain,
    config: &TarpitConfig,
) -> impl Stream<Item = Result<Bytes>> {
    async_stream::stream! {
        loop {
            // Generate HTML page with links
            let html = chain.generate_html_page(config);
            
            // Apply fingerprint resistance
            let html = apply_delays(html, config.chunk_delay);
            
            yield Ok(Bytes::from(html));
            
            // Budget check
            if budget.exceeded() {
                break;
            }
        }
    }
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
pub fn sanitize_redirect_target(target: &str) -> Result<String> {
    // 1. Reject CRLF injection
    if target.contains('\r') || target.contains('\n') {
        return Err(Error::CrlfInjection);
    }
    
    // 2. Reject control characters
    if target.chars().any(|c| c.is_control()) {
        return Err(Error::ControlCharacter);
    }
    
    // 3. Reject open redirect
    if target.starts_with("//") || target.starts_with("http://") || target.starts_with("https://") {
        return Err(Error::OpenRedirect);
    }
    
    // 4. Validate against host allowlist
    Ok(target.to_string())
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
| `MarkovChain` | `crates/synvoid-tarpit/src/markov.rs` | Text generation engine |
| `TarpitAdmission` | `crates/synvoid-tarpit/src/admission.rs` | Concurrency control |
| `SessionBudget` | `crates/synvoid-tarpit/src/budget.rs` | Per-session resource tracking |
| `TarpitConfig` | `crates/synvoid-tarpit/src/config.rs` | Configuration |
| `TarpitService` | `crates/synvoid-tarpit/src/service.rs` | Service entry point |
