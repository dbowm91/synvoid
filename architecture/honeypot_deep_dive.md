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
    services: HashMap<ServiceType, PortAssignment>,
    rotation_config: RotationConfig,
}

pub enum ServiceType {
    Ssh, Http, Mysql, Redis, Ftp, Smtp, Postgres, Elasticsearch,
}
```

### Protocol Detection

`ProtocolDetector` with confidence scoring:

```rust
pub struct ProtocolDetector {
    patterns: Vec<ProtocolPattern>,
}

pub struct ProtocolPattern {
    service: ServiceType,
    banner_pattern: Regex,
    confidence: Confidence,  // High, Medium, Low
}
```

### AI Responders

Multiple LLM backends with budget enforcement:

```rust
pub enum AiBackend {
    Anthropic { api_key: String },
    OpenAI { api_key: String },
    Ollama { endpoint: String },
}

// Budget enforcement
struct AiBudgetManager {
    circuit_breaker: AiCircuitBreaker,   // Failure-based cooldown
    concurrency_limiter: AiConcurrencyLimiter,  // Semaphore
    turn_counter: AiTurnCounter,         // Per-connection budget
}
```

### Threat Intel Extraction

13 regex patterns for attack detection:

| Pattern | Category |
|---------|----------|
| `SELECT.*FROM` | SQL injection |
| `<script>` | XSS |
| `\.\./\.\.` | Path traversal |
| `/etc/passwd` | LFI |
| `;.*ls` | RCE |
| `\|.*sh` | Shell injection |
| `\$_\[(GET\|POST)\]` | PHP injection |
| `wp-admin\|wp-login` | WordPress probe |
| `\.git\|\.env` | VCS/config leak |
| `AKIA[0-9A-Z]{16}` | AWS credentials |

### Signal Scoring

```rust
pub struct HoneypotSignalScore {
    base_scores: HashMap<SignalClass, f64>,
    config: ScoringConfig,
}

pub enum RiskLevel {
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
| `ProtocolDetector` | `crates/synvoid-honeypot/src/detector.rs` | Protocol identification |
| `HoneypotIntelExtractor` | `crates/synvoid-honeypot/src/intel.rs` | Threat extraction |
| `HoneypotSignalScore` | `crates/synvoid-honeypot/src/scoring.rs` | Risk scoring |
| `AiCircuitBreaker` | `crates/synvoid-honeypot/src/ai.rs` | AI budget enforcement |
