# AI Bot Blocking Enhancement Plan

## Overview

Enhance the WAF's AI bot blocking to be more robust, configurable, and network-aware. Allow origin servers to enable/disable protection, and enable global nodes to push updates to the DHT network.

---

## 1. Current Implementation

### Existing Structure

| Component | Location | Purpose |
|-----------|----------|---------|
| `BotDetector` | `src/waf/bot.rs` | Core detection logic |
| `BotProtectionConfig` | `src/waf/mod.rs:1150` | Runtime config |
| `BotDefaults` | `src/config/defaults.rs:247` | Default config |
| `SiteBotConfig` | `src/config/site.rs:944` | Per-site override |
| Global node blocklist | `src/mesh/dht/network_policy.rs` | Existing IP blocklist |

### Current Detection Logic (`src/waf/bot.rs:47-96`)

```
1. Missing UA → Allowed
2. Empty UA → Tarpit
3. Allowed bot (whitelist) → Allowed
4. Scraper pattern → Tarpit
5. isbot library detection → Blocked
6. AI crawler pattern → Blocked
7. Legitimate → Allowed
```

### Current Default Patterns

```rust
// AI crawlers (defaults.rs:285-292)
"GPTBot", "ChatGPT-User", "ClaudeBot", "Claude-Web", "CCBot", "Google-Extended"

// Known allowed bots (defaults.rs:279-284)
"googlebot", "bingbot", "yandex", "duckduckbot"

// Scrapers (defaults.rs:293-314)
"scrapy", "curl", "wget", "python-requests", "python-urllib", "aiohttp", "httpx", etc.
```

---

## 2. Enhancement Goals

1. **Expand AI bot patterns** - Include more AI providers
2. **Per-site control** - Origin can enable/disable AI bot blocking (requires fixing existing but unused SiteBotConfig)
3. **DHT integration** - Global nodes push updates to network
4. **New bot detection** - Log unknown AI patterns for admin awareness (NOT blocking, just alerting)

---

## 3. Implementation Phases

### Phase 1: Enhanced Default Patterns

**File:** `src/config/defaults.rs`

Expand the default `ai_crawlers_block` list and add new config fields:

```rust
ai_crawlers_block: vec![
    // OpenAI
    "GPTBot",
    "ChatGPT-User",
    "ChatGPT-Plugin",
    "OpenAI",
    "OAI-SearchBot",
    // Anthropic
    "ClaudeBot",
    "Claude-Web",
    "anthropic-ai",
    // Google
    "Google-Extended",
    "GoogleOther",
    // Common Crawl
    "CCBot",
    // TikTok
    "Bytespider",
    // Perplexity
    "PerplexityBot",
    // Apple
    "Applebot",
    // Amazon
    "Amazonbot",
    // Meta
    "Meta-ExternalBot",
    "FacebookBot",
    // xAI
    "Grok",
    // Mistral
    "MistralAI",
    // Cohere
    "CohereBot",
    // AI21
    "ai21",
],

// NEW: Enable logging of unknown AI patterns
detect_new_ai_bots: true,
```
    "PerplexityBot",
    // Apple
    "Applebot",
    // Amazon
    "Amazonbot",
    // Meta
    "Meta-ExternalBot",
    "FacebookBot",
    // xAI
    "Grok",
    // Mistral
    "MistralAI",
    // Cohere
    "CohereBot",
    // AI21
    "ai21",
],
```

---

### Phase 2: Per-Site Override Support

**Files:** `src/config/site.rs`, `src/waf/mod.rs`, `src/waf/bot.rs`

> **ARCHITECTURE NOTE:** The current WAF implementation uses a single global `WafCore` instance.
> Per-site override requires passing site config at request time, similar to how `target.site_config`
> is used in HTTP handlers. The `BotDetector.check()` method should accept optional site-specific
> overrides to merge with global config.

#### 2.1 Extend SiteBotConfig

```rust
// src/config/site.rs:944
pub struct SiteBotConfig {
    pub inherit: Option<bool>,
    pub block_ai_crawlers: Option<bool>,
    pub ai_crawlers_block: Option<Vec<String>>,  // NEW: custom patterns
    pub enable_css_honeypot: Option<bool>,
    pub enable_js_challenge: Option<bool>,
    pub challenge_type: Option<String>,
    // NEW: DHT integration
    pub dht_ai_bot_updates_enabled: Option<bool>,  // default: true
    pub dht_ai_bot_override_local: Option<bool>,   // default: true (DHT supersedes local in mesh)
}
```

#### 2.2 Add Runtime DHT State to WafCore

```rust
// src/waf/mod.rs - new fields in WafCore
pub struct WafCore {
    // ... existing fields
    ai_bot_list: RwLock<GlobalAiBotList>,  // NEW: DHT-sourced list
    dht_updates_enabled: bool,
    dht_override_local: bool,
}
```

#### 2.3 Merge Logic

Create a merge function that combines:
1. Default patterns
2. Site-specific patterns (if not inheriting)
3. DHT patterns (if enabled and override is true)

```rust
fn merge_ai_bot_patterns(
    defaults: &[String],
    site_override: Option<&Vec<String>>,
    dht_list: &GlobalAiBotList,
    dht_enabled: bool,
    dht_override: bool,
) -> Vec<String> {
    let mut patterns = defaults.to_vec();
    
    // Add site-specific patterns
    if let Some(site_patterns) = site_override {
        patterns.extend(site_patterns.iter().cloned());
    }
    
    // Add DHT patterns if enabled and override is true
    if dht_enabled && dht_override {
        for entry in &dht_list.bots {
            if matches!(entry.action, BotAction::Block) {
                patterns.extend(entry.patterns.iter().cloned());
            }
        }
    }
    
    // Dedupe
    patterns.sort();
    patterns.dedup();
    
    patterns
}
```

---

### Phase 3: DHT Network Integration

#### 3.1 New DHT Record Types

**File:** `src/mesh/dht/network_policy.rs`

```rust
#[derive(Debug, Clone, Serialize, Deserialize, Archive, RkyvSerialize, RkyvDeserialize)]
pub struct GlobalAiBotList {
    pub version: u64,
    pub bots: Vec<AiBotEntry>,
    pub last_updated: u64,
    pub updated_by: String,
    pub min_reputation: i64,
    pub signature: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Archive, RkyvSerialize, RkyvDeserialize)]
pub struct AiBotEntry {
    pub name: String,
    pub patterns: Vec<String>,
    pub action: BotAction,
    pub added_at: u64,
    pub added_by: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Archive, RkyvSerialize, RkyvDeserialize)]
pub enum BotAction {
    Block,
    Allow,
    Tarpit,
}

// Constants
pub const AI_BOT_LIST_RATE_LIMIT_SECS: u64 = 300;  // 5 minutes
```

#### 3.2 Add DHT Key

**File:** `src/mesh/dht/keys.rs`

```rust
pub enum DhtKey {
    // ... existing
    GlobalAiBotList,  // NEW
}

// Add to all existing match arms
DhtKey::GlobalAiBotList => "global_ai_bot_list",
"global_ai_bot_list" => DhtKey::GlobalAiBotList,
```

#### 3.3 Add MeshMessage Variants

**File:** `src/mesh/protocol.rs`

```rust
pub enum MeshMessage {
    // ... existing
    AiBotListQuery {
        request_id: ArcStr,
        source_node_id: ArcStr,
        timestamp: u64,
    },
    AiBotListResponse {
        request_id: ArcStr,
        list: GlobalAiBotList,
        timestamp: u64,
    },
    AiBotListUpdate {
        request_id: ArcStr,
        source_node_id: ArcStr,
        list: GlobalAiBotList,
        timestamp: u64,
    },
    AiBotListUpdateAck {
        request_id: ArcStr,
        accepted: bool,
        timestamp: u64,
    },
}
```

#### 3.4 Implement DHT Publishing (Global Nodes)

**File:** `src/mesh/dht/record_store_crud.rs`

Add methods for AI bot list:

```rust
impl RecordStoreManager {
    pub fn store_ai_bot_list(&self, list: GlobalAiBotList) -> bool {
        // Rate limit check
        if let Some(last) = self.last_ai_bot_update.read().as_ref() {
            let now = crate::mesh::safe_unix_timestamp();
            if now.saturating_sub(*last) < AI_BOT_LIST_RATE_LIMIT_SECS {
                tracing::warn!("AI bot list update rate limited");
                return false;
            }
        }
        
        // Verify global node permission
        if !self.is_global_node() {
            tracing::error!("Non-global node attempted to publish AI bot list");
            return false;
        }
        
        // Sign the list
        let mut signed_list = list;
        if let Some(signer) = self.mesh_signer.as_ref() {
            signed_list.sign(signer);
        }
        
        // Store
        let record = DhtRecord {
            key: "global_ai_bot_list".to_string(),
            value: serde_json::to_string(&signed_list).unwrap(),
            source_node_id: self.node_id.clone(),
            version: signed_list.version,
            timestamp: signed_list.last_updated,
        };
        
        self.store_record(record, MAX_REPUTATION_THRESHOLD)
    }
    
    pub fn get_ai_bot_list(&self) -> Option<GlobalAiBotList> {
        let record = self.get_record("global_ai_bot_list")?;
        serde_json::from_str(&record.value).ok()
    }
}
```

#### 3.5 Implement DHT Subscription (Edge Nodes)

**File:** `src/mesh/dht/record_store_message.rs`

Add handler for `AiBotListUpdate`:

```rust
fn handle_ai_bot_list_update(&self, msg: MeshMessage::AiBotListUpdate) {
    // Verify signature against known global node keys
    if !self.verify_global_node_signature(&msg.list) {
        tracing::warn!("Invalid signature on AI bot list update");
        return;
    }
    
    // Update local cache
    if let Some(waf_core) = self.waf_core.as_ref() {
        waf_core.update_ai_bot_list(msg.list);
    }
    
    // Acknowledge
    MeshMessage::AiBotListUpdateAck {
        request_id: msg.request_id,
        accepted: true,
    }
}
```

#### 3.6 Global Node Periodic Publishing

**File:** `src/mesh/transport_global.rs` or new module

```rust
async fn start_ai_bot_list_broadcaster(&self) {
    let mut interval = tokio::time::interval(
        Duration::from_secs(AI_BOT_LIST_RATE_LIMIT_SECS)
    );
    
    loop {
        interval.tick().await;
        
        if !self.is_global_node() {
            continue;
        }
        
        // Check if list has updates
        if let Some(list) = self.get_pending_ai_bot_updates() {
            // Publish to DHT
            self.record_store.store_ai_bot_list(list);
            
            // Broadcast to connected peers
            self.broadcast_ai_bot_list_update(list).await;
        }
    }
}
```

---

### Phase 4: New Bot Detection

**File:** `src/waf/bot.rs`

> **NOTE:** New bot detection is for ALERTING ONLY - it logs warnings when unknown AI company patterns are detected.
> This does NOT block the request. The purpose is to alert admins so they can manually update blocklists if needed.
> This is distinct from the AI crawler blocking which actively blocks requests.

Add detection for unknown AI patterns:

```rust
// Known AI company name patterns (for detection, not blocking)
const AI_COMPANY_PATTERNS: &[&str] = &[
    "openai",
    "anthropic",
    "google",
    "meta",
    "facebook",
    "microsoft",
    "amazon",
    "apple",
    "perplexity",
    "mistral",
    "cohere",
    "ai21",
    "xai",
    "grok",
    "bytedance",
    "tiktok",
];

impl BotDetector {
    /// Check with optional site config for per-site overrides
    pub fn check(&self, user_agent: Option<&str>, site_config: Option<&SiteBotConfigOverride>) -> BotDetectionResult {
        // ... existing logic ...
        
        // Site-specific override: check if AI blocking disabled for this site
        if let Some(site) = site_config {
            if let Some(block_ai) = site.block_ai_crawlers {
                if !block_ai {
                    // Site has explicitly disabled AI bot blocking
                    return BotDetectionResult::Allowed {
                        reason: "site_ai_blocking_disabled".to_string(),
                    };
                }
            }
        }
        
        // ... rest of existing logic ...
        
        // NEW: Log unknown AI patterns if detection enabled (ALERTING ONLY)
        if self.detect_new && self.is_unknown_ai_pattern(ua) {
            tracing::warn!(
                "New AI bot pattern detected: {} - consider adding to blocklist",
                ua
            );
        }
        
        BotDetectionResult::Allowed { reason: "legitimate".to_string() }
    }
    
    fn is_unknown_ai_pattern(&self, ua: &str) -> bool {
        let ua_lower = ua.to_lowercase();
        
        // Check if UA contains any AI company name
        let contains_ai_company = AI_COMPANY_PATTERNS.iter()
            .any(|company| ua_lower.contains(company));
        
        if !contains_ai_company {
            return false;
        }
        
        // Check if it's already in our blocklist
        let already_blocked = self.ai_crawlers_block.iter()
            .any(|pattern| ua_lower.contains(&pattern.to_lowercase()));
        
        !already_blocked
    }
}

/// Lightweight override struct passed at request time
pub struct SiteBotConfigOverride {
    pub block_ai_crawlers: Option<bool>,
    pub ai_crawlers_block: Option<Vec<String>>,
    pub dht_ai_bot_updates_enabled: Option<bool>,
    pub dht_ai_bot_override_local: Option<bool>,
}
```

---

### Phase 5: Admin API

**Files:** `src/admin/handlers/`

Add endpoints for managing AI bot list:

```rust
// GET /api/v1/admin/ai-bot-list - View current list
// POST /api/v1/admin/ai-bot-list - Add bot to list (global node only)
// DELETE /api/v1/admin/ai-bot-list/:name - Remove bot from list (global node only)
// POST /api/v1/admin/ai-bot-list/push - Push to DHT (global node only)
```

---

## 4. Configuration Options

### Defaults Level (`config.toml`)

```toml
[defaults.bot]
# Enable AI crawler blocking (default: true)
block_ai_crawlers = true

# Patterns to block (default: expanded list)
ai_crawlers_block = [
    "GPTBot",
    "ClaudeBot",
    # ... etc
]

# Allow known search bots
known_bots_allow = [
    "googlebot",
    "bingbot",
    "yandex",
    "duckduckbot",
]

# Log new AI bot patterns
detect_new_ai_bots = true
```

### Site Level (`sites/*.toml`)

```toml
[site.bot]
# Inherit from defaults or override
inherit = true

# Override blocking setting
block_ai_crawlers = false  # Allow AI bots for this site

# Custom patterns for this site only
ai_crawlers_block = ["GPTBot", "ClaudeBot"]

# DHT integration
dht_ai_bot_updates_enabled = true   # Receive DHT updates
dht_ai_bot_override_local = true   # DHT supersedes local config
```

### Global Node Level

```toml
[mesh]
# Rate limit for AI bot list updates (default: 300)
ai_bot_update_rate_limit_secs = 300
```

---

## 5. Data Flow

### DHT Update Flow

```
┌─────────────┐     ┌──────────────┐     ┌─────────────┐
│ Global Node │────>│   DHT Store  │<────│  Edge Node  │
│  (Publisher)│     │ (Key: global │     │ (Subscriber)│
└─────────────┘     │  _ai_bot_list)│     └─────────────┘
        │           └──────────────┘            │
        │                  │                    │
        │     ┌────────────┴────────────┐       │
        │     │ Verify signature        │       │
        │     │ Check rate limit        │       │
        │     └─────────────────────────┘       │
        │                                        │
        └─────────── Broadcast to peers <───────┘
```

### Per-Site Request Flow

```
Request ──> Lookup SiteConfig ──> Check bot.block_ai_crawlers
                                      │
                    ┌─────────────────┼─────────────────┐
                    │                 │                 │
              inherit=true      inherit=false    Not set
                    │                 │                 │
                    v                 v                 v
           Use defaults    Use site config    Use defaults
                    │                 │                 │
                    └─────────────────┼─────────────────┘
                                      │
                                      v
                              Merge with DHT if enabled
                                      │
                                      v
                           BotDetector.check(UA)
```

---

## 6. Constants

```rust
// In src/mesh/dht/network_policy.rs
pub const AI_BOT_LIST_RATE_LIMIT_SECS: u64 = 300;  // 5 minutes

// In src/config/defaults.rs  
const DEFAULT_DETECT_NEW_AI_BOTS: bool = true;
const DEFAULT_DHT_AI_BOT_UPDATES_ENABLED: bool = true;
const DEFAULT_DHT_AI_BOT_OVERRIDE_LOCAL: bool = true;
```

---

## 7. Test Plan

### Unit Tests

1. **BotDetector tests** - Existing in `src/waf/bot.rs`
2. **New bot detection** - Test unknown AI pattern logging
3. **Pattern merge logic** - Test merging defaults + site + DHT

### Integration Tests

1. **DHT round-trip** - Publish and retrieve AI bot list
2. **Rate limiting** - Verify 5-minute limit enforced
3. **Signature verification** - Invalid signatures rejected
4. **Per-site override** - Site config overrides defaults

---

## 8. Files to Modify

| File | Changes |
|------|---------|
| `src/config/defaults.rs` | Expand default patterns, add new config fields |
| `src/config/site.rs` | Extend SiteBotConfig with DHT fields |
| `src/waf/bot.rs` | Add new bot detection, enhance check() signature |
| `src/waf/mod.rs` | Add DHT state to WafCore, merge logic |
| `src/mesh/dht/network_policy.rs` | Add GlobalAiBotList, AiBotEntry, BotAction |
| `src/mesh/dht/keys.rs` | Add GlobalAiBotList DHT key |
| `src/mesh/protocol.rs` | Add AiBotList* message variants |
| `src/mesh/dht/record_store_crud.rs` | Add store/get methods for AI bot list |
| `src/mesh/dht/record_store_message.rs` | Add message handlers |
| `src/server/mod.rs` | Pass new config to WafCore |
| `src/worker/connection.rs` | Pass new config to WafCore |
| `admin-ui/src/config_docs.rs` | Document new fields |

---

## 9. Backward Compatibility

- All new fields have sensible defaults
- Existing configs continue to work unchanged
- DHT updates are opt-in per-site (`dht_ai_bot_updates_enabled`)

---

## 10. Security Considerations

1. **Signature verification** - All DHT updates must be signed by known global nodes
2. **Rate limiting** - Prevents abuse of DHT update mechanism
3. **Reputation check** - Global nodes only accept updates from high-reputation nodes
4. **Override warning** - Log when DHT overrides local site config
