# AGENTS.override.md — synvoid-honeypot

## Quick Commands

```bash
# All tests (182 tests)
cargo test -p synvoid-honeypot --all-targets

# All features
cargo test -p synvoid-honeypot --all-features --all-targets

# Clippy
cargo clippy -p synvoid-honeypot --all-targets -- -D warnings

# Specific test groups
cargo test -p synvoid-honeypot -- listener_tests
cargo test -p synvoid-honeypot -- all_targets storage_writer
cargo test -p synvoid-honeypot -- all_targets threat_intel
cargo test -p synvoid-honeypot -- ai_responder_containment_tests
```

## Architecture

Honeypot crate: deception layer deploying fake service endpoints to detect attackers.

### Key Modules
- `listener.rs` — TCP listener with global/per-IP admission control, RAII guards
- `storage_writer.rs` — Async bounded channel to SQLite batch writer
- `threat_intel.rs` — Signal scoring, action classification, mesh propagation guardrails
- `ai_budget.rs` — Circuit breaker, concurrency limiter, turn counter, prompt/response truncation
- `responders/ai.rs` — Ollama/OpenAI/Anthropic providers with hardened system prompts
- `responders/mod.rs` — TemplateResponder, AiHoneypotResponder, StaticResponder, VulnerableAppResponder
- `protocol.rs` — 15+ protocol detectors with confidence levels
- `rotation.rs` — Port rotation (Random/Stable/Hybrid modes)
- `config.rs` — All configuration structs with serde defaults

### Critical Invariants
1. **AI responder is Disabled by default** — must explicitly enable via `ai.mode`
2. **Raw payload storage is NOT default** — default retention is Truncated (256 bytes + SHA-256 hash)
3. **Mesh propagation is disabled by default** — requires `mesh_enabled = true` + Medium confidence + 3+ events
4. **Low-confidence single events are telemetry, not blocks** — scoring threshold for rate-limit is 0.3
5. **`try_write_record` is non-blocking** — queue-full drops are counted, not blocked
6. **AI `respond()` (sync) never calls `block_on`** — returns static fallback; only `respond_async()` calls providers
7. **AI system prompts enforce containment** — `[SYSTEM — HONEYPOT SIMULATION]` header, no real access

### Metrics
12 counters: connections_accepted, connections_rejected_global_limit, connections_rejected_per_ip_limit, connections_timed_out_initial, connections_timed_out_read, handler_errors, payload_truncated, storage_drops, storage_write_errors, ai_turns_exceeded, ai_responses_success, ai_responses_fallback

### Config Defaults
- Queue capacity: 4096
- Batch size: 64
- Max concurrent connections: 256
- Max per-IP connections: 10
- Payload retention: Truncated (256 bytes)
- AI mode: Disabled
- Circuit breaker: 3 failures, 60s cooldown

### Dependencies
- `synvoid-storage` (SQLite)
- `synvoid-config` (PortHoneypotConfig)
- `tokio` (async runtime, channels, semaphores)
- `rand` (port selection, content variation)
- `sha2` (payload hashing)
- `regex` (attack pattern detection)
