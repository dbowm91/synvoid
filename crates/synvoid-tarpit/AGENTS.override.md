# AGENTS.override.md — synvoid-tarpit

## Quick Commands

```bash
# All tests (54 tests)
cargo test -p synvoid-tarpit --all-targets

# Clippy
cargo clippy -p synvoid-tarpit --all-targets -- -D warnings
```

## Architecture

Anti-scraping tarpit generating infinite HTML pages via Markov chain text generation.

### Key Modules
- `escaping.rs` — HTML/JS/URL escaping, redirect safety validation
- `admission.rs` — Global + per-IP semaphore admission control with RAII guards
- `budget.rs` — Session budgets (duration, chunks, bytes, idle) with atomic counters
- `generator.rs` — Markov chain (bigram model) with 10 built-in corpora
- `config.rs` — TarpitConfig, AdmissionConfig, BudgetConfig, FingerprintConfig, RedirectPolicy

### Critical Invariants
1. **All attacker-controlled values are escaped** — html_escape, js_string_escape, url_path_encode before HTML interpolation
2. **Redirect safety is default-deny** — RelativeOnly policy blocks absolute URLs, CRLF injection, control characters
3. **Admission is non-blocking** — `try_admit()` returns None if limits reached, never blocks
4. **RAII guards for cleanup** — AdmissionGuard drops release permits automatically
5. **Session budgets are enforced** — `record_chunk()` returns false when any budget exceeded
6. **Max depth clamped to 1** — even if 0 is configured
7. **Fallback sentence exists** — "The system is processing your request." if Markov model empty

### Metrics
6 counters/histograms: tarpit.requests, tarpit.admitted, tarpit.timed_out, tarpit.completed, tarpit.bytes_sent, tarpit.response_time

### Config Defaults
- Enabled: true
- Max concurrent: 256
- Max per-IP: 4
- Max duration: 600s
- Max chunks: 500
- Max bytes: 50MB
- Max idle: 30s
- Chunk delay: 5-30ms
- Redirect policy: RelativeOnly

### Known Limitations
- Admission not enforced in single-shot `handle_request` mode
- `vary_status_code` configured but not applied in all code paths
- `TarpitManager` defined but unused by handler
- `TarpitRejection::AdmissionLimit` defined but never constructed

### Dependencies
- `rand` (Markov chain, content variation)
- `tokio` (async streaming, sleep)
- `parking_lot` (Mutex for per-IP semaphores)
- `serde` (config serialization)
