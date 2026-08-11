---
name: honeypot
description: Deception layer with AI-powered responders, protocol detection, port rotation, and threat intelligence extraction.
---

# Skill: Honeypot (Deception Layer)

## Context
The honeypot subsystem provides active deception: configurable listeners impersonate vulnerable services, detect attacker protocols, and optionally respond via AI. Extracted threat indicators feed the mesh intelligence pipeline.

## When to Use
- Modifying honeypot responder behavior or adding new responders
- Adjusting AI budget controls (circuit breaker, concurrency limits)
- Tuning protocol detection confidence thresholds
- Changing port rotation strategy (Random/Stable/Hybrid)
- Working on threat indicator extraction or mesh propagation

## Key Files
- `crates/synvoid-honeypot/src/lib.rs` — re-exports
- `crates/synvoid-honeypot/src/ai_budget.rs` — `AiCircuitBreaker`, `AiConcurrencyLimiter`, `AiTurnCounter`
- `crates/synvoid-honeypot/src/config.rs` — all config types (`PortHoneypotConfig`, `AiConfig`, etc.)
- `crates/synvoid-honeypot/src/controller.rs` — `PortHoneypotController`
- `crates/synvoid-honeypot/src/listener.rs` — TCP listener with admission control
- `crates/synvoid-honeypot/src/mesh_control.rs` — `HoneypotMeshController`, `HoneypotControlCommand`
- `crates/synvoid-honeypot/src/protocol.rs` — `ProtocolDetector` (15+ protocol detectors)
- `crates/synvoid-honeypot/src/responders/` — `AiHoneypotResponder`, `AnthropicResponder`, `OllamaResponder`, `OpenAIResponder`, `StaticResponder`, `TemplateResponder`, `VulnerableAppResponder`
- `crates/synvoid-honeypot/src/responses.rs` — `HoneypotResponder` trait, `HoneypotResponderRegistry`
- `crates/synvoid-honeypot/src/rotation.rs` — `PortManager` (Random/Stable/Hybrid modes)
- `crates/synvoid-honeypot/src/runner.rs` — `PortHoneypotRunner`
- `crates/synvoid-honeypot/src/storage.rs` — `HoneypotStorage` (SQLite)
- `crates/synvoid-honeypot/src/storage_writer.rs` — async bounded channel → SQLite batch writer
- `crates/synvoid-honeypot/src/threat_intel.rs` — `HoneypotIndicator`, `HoneypotIntelExtractor`

## Architecture

### Responder Hierarchy
```
HoneypotResponderRegistry
  ├── AiHoneypotResponder (Ollama/OpenAI/Anthropic)
  │     ├── AiCircuitBreaker (3 failures → 60s cooldown)
  │     └── AiConcurrencyLimiter (max 2 concurrent AI calls)
  ├── StaticResponder (canned responses)
  ├── TemplateResponder (template-based)
  └── VulnerableAppResponder (interactive vulnerable app)
```

### Protocol Detection Flow
```
Incoming bytes → ProtocolDetector::detect()
  → Vec<ProtocolMatch> (SSH, HTTP, MySQL, Redis, etc.)
  → Confidence::High/Medium/Low
  → Select responder + service banner
```

### Port Rotation
- `Random` — random available port per session
- `Stable` — fixed port mapping
- `Hybrid` — stable primary + random secondary

### Threat Intelligence Pipeline
```
Honeypot session → HoneypotIntelExtractor
  → HoneypotIndicator (IP, protocol, behavior)
  → Confidence scoring → Mesh propagation (if ≥ Medium + 3 events)
```

## Critical Invariants
- **AI responder Disabled by default** — must be explicitly opted in
- **Raw payload storage NOT default** — `Truncated` mode (256 bytes + SHA-256)
- **Mesh propagation disabled by default** — requires Medium confidence + 3+ events
- **Sync `respond()` never calls `block_on`** — async only via `respond_async()`
- **AI system prompts enforce containment** — `[SYSTEM — HONEYPOT SIMULATION]` header
- **Circuit breaker**: 3 failures → 60s cooldown (prevents AI cost runaway)

## Configuration Defaults
```toml
[honeypot]
enabled = false  # Opt-in required

[honeypot.ai]
mode = "disabled"
model = "llama3"

[honeypot.admission]
max_concurrent = 256
max_per_ip = 10

[honeypot.storage]
queue_capacity = 4096
batch_size = 64
payload_retention = "truncated"  # 256 bytes + SHA-256
```

## Testing
```bash
cargo test -p synvoid-honeypot --all-targets
```
182 tests covering responders, protocol detection, AI budget, storage, and threat intel extraction.
