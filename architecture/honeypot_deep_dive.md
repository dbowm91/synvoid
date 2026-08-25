# Honeypot Deep Dive

SynVoid's honeypot system lures attackers with realistic service emulations, captures connection payloads, extracts threat intelligence indicators, and optionally deploys AI-powered interactive responders.

## Architecture

### Core Components

```
PortHoneypotController
├── PortManager (port rotation)
├── ProtocolDetector (banner analysis)
├── HoneypotStorage (SQLite persistence)
├── AiResponders (LLM backends)
├── IntelExtractor (pattern matching)
└── SignalScorer (risk scoring)
```

### Port Rotation

`PortManager` with stable port assignments and configurable rotation:

```rust
pub struct PortManager {
    // Manages service-to-port assignments with rotation
    // Services identified by protocol string (ssh, http, mysql, etc.)
}
```

Supported protocols: SSH, HTTP, MySQL, Redis, FTP, SMTP, PostgreSQL, Elasticsearch, and more.

### Protocol Detection

`ProtocolDetector` with confidence scoring via binary and text pattern matching:

```rust
pub struct ProtocolDetector;

impl ProtocolDetector {
    pub fn detect(&self, payload: &[u8]) -> Option<ProtocolMatch>;
    pub fn get_banner_for_service(&self, service: &str, port: u16) -> Option<ServiceBanner>;
}

pub struct ProtocolMatch {
    pub protocol: String,   // Normalized: http, ssh, tls, mysql, redis, postgres, smb, etc.
    pub service: String,    // Display label: HTTP, SSH, PostgreSQL, etc.
    pub confidence: Confidence,  // High, Medium, Low
    pub evidence: String,   // Detection reason
}
```

### AI Responders

Multiple LLM backends with budget enforcement:

```rust
pub enum AiProvider {
    Ollama(OllamaConfig),
    OpenAI(OpenAIConfig),
    Anthropic(AnthropicConfig),
}

// Budget enforcement components
pub struct AiCircuitBreaker;   // Failure-based cooldown
pub struct AiConcurrencyLimiter;  // Semaphore-based concurrency limit
pub struct AiTurnCounter;      // Per-connection turn budget
pub enum BudgetExceeded { ... }  // Rejection reason
```

### Threat Intel Extraction

13 regex patterns for attack detection:

| Pattern | Category |
|---------|----------|
| `\bselect\s+[\w\s*.,-]+\s+from\b` | SQL injection |
| `<\s*script[^>]*>\|javascript\s*:` | XSS |
| `\.\./\|\.\.\\` | Path traversal |
| `/etc/(passwd\|shadow\|hosts)` | LFI |
| `\b(wget\|curl\|nc\|ncat)\s+['"]?https?://` | RCE |
| `\b(bash\|sh)\s+-[ic]` | Shell injection |
| `<\?php\|phpinfo\s*\(` | PHP exploitation |
| `/wp-admin/\|/wp-login.php` | WordPress probe |
| `/\.git/\|/\.svn/HEAD` | VCS/config leak |
| `(aws_access_key\|aws_secret\|access_key_id\|secret_access_key)` | AWS credential theft |
| `\bredis.*config\s+set\b` | Redis attack |
| `\bmongo(?:db)?\s*\.\s*` | MongoDB attack |
| `/admin(?:/login)?\|/administrator` | Admin panel probe |

### Signal Scoring

```rust
pub struct HoneypotSignalScore {
    pub confidence: Confidence,
    pub severity: SeverityLevel,
    pub signal_class: SignalClass,
    pub event_count: u32,
    pub distinct_ports: u32,
    pub attack_patterns: u32,
    pub first_seen: i64,
    pub last_seen: i64,
    pub score: f64,
    pub action_class: IndicatorActionClass,
    pub payload_truncated: bool,
}

pub enum IndicatorActionClass {
    Observe,
    LocalRateLimitCandidate,
    LocalBlockCandidate,
    MeshShareCandidate,
    MeshBlockCandidate,
}
```

Scoring factors:
- Base score per signal class
- Confidence multipliers
- Repeat offender bonuses
- Port-based bonuses (SSH probes higher risk)
- Pattern complexity bonuses
- Time-based decay

## Integration Points

- Controller managed by supervisor
- Mesh control commands for coordinated response
- Threat intel indicators feed into BlockStore via mesh propagation
- AI responders powered by external LLMs (optional)

## Key Types

| Type | Location | Purpose |
|------|----------|---------|
| `PortHoneypotController` | `crates/synvoid-honeypot/src/controller.rs` | Lifecycle management |
| `HoneypotStorage` | `crates/synvoid-honeypot/src/storage.rs` | SQLite persistence |
| `ProtocolDetector` | `crates/synvoid-honeypot/src/protocol.rs` | Protocol identification |
| `HoneypotIntelExtractor` | `crates/synvoid-honeypot/src/threat_intel.rs` | Threat extraction |
| `HoneypotSignalScore` | `crates/synvoid-honeypot/src/threat_intel.rs` | Risk scoring |
| `AiCircuitBreaker` | `crates/synvoid-honeypot/src/ai_budget.rs` | AI budget enforcement |
