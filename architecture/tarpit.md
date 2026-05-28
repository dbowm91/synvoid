# Tarpit Architecture

## 1. Purpose and Responsibility

The Tarpit module (`src/tarpit/`) provides an **anti-scraping tarpit** that generates infinite, slowly-expanding HTML pages using Markov chain text generation with configurable link density. Designed to waste scraper resources.

**Core Responsibilities:**
- Generate infinite, slowly-expanding HTML pages
- Markov chain text generation
- Configurable link density per page
- Scraper user-agent detection
- Tarpit decision logic

---

## 2. Key Data Structures

```rust
pub struct TarpitManager {
    chain: MarkovChain,
    config: TarpitConfig,
}

pub struct TarpitConfig {
    pub max_depth: usize,
    pub links_per_page: usize,
    pub response_delay_ms: u64,
    pub scraper_patterns: Vec<String>,
}

pub struct MarkovChain {
    // Text/HTML generation state
}
```

---

## 3. Public API

| Method | Description |
|--------|-------------|
| `TarpitManager::new(config)` | Constructor |
| `generate_page(current_depth, path_seed) -> String` | Generate tarpit page |
| `is_scraper_user_agent(ua) -> bool` | Detect known scrapers |
| `should_tarpit(is_bot, user_agent) -> bool` | Decision logic |

---

## 4. Integration Points

- **HTTP Server**: Tarpit response generation
- **WAF**: Bot detection triggers tarpit
- **Challenge**: Tarpit as alternative to challenges

---

## 5. Key Implementation Details

- **Markov Chains**: Generates realistic-looking text that expands infinitely
- **Link Density**: Each page contains links to deeper pages
- **Depth Limiting**: Configurable maximum depth to prevent infinite recursion
- **Delay**: Response delay to consume scraper time
- **Pattern Matching**: Known scraper User-Agent patterns (scrapy, curl, wget, python-requests)
