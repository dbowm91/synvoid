---
name: tarpit
description: Anti-scraping tarpit with Markov chain text generation, session budgets, and admission control for trapping malicious clients.
---

# Skill: Tarpit (Anti-Scraping)

## Context
The tarpit wastes attacker resources by serving dynamically generated, plausible-looking content that consumes time and bandwidth without revealing real application data.

## When to Use
- Modifying tarpit response generation or Markov chain corpora
- Adjusting admission control (global/per-IP semaphores)
- Tuning session budgets (duration, chunks, bytes, idle timeout)
- Changing redirect policy or escaping logic
- Debugging tarpit performance under load

## Key Files
- `crates/synvoid-tarpit/src/lib.rs` — re-exports
- `crates/synvoid-tarpit/src/admission.rs` — `AdmissionGuard`, `TarpitAdmission` (RAII semaphore)
- `crates/synvoid-tarpit/src/budget.rs` — `BudgetState`, `SessionBudget` (atomic counters)
- `crates/synvoid-tarpit/src/config.rs` — `TarpitConfig`, `AdmissionConfig`, `BudgetConfig`
- `crates/synvoid-tarpit/src/escaping.rs` — `html_escape`, `js_string_escape`, `url_path_encode`, `sanitize_redirect_target`
- `crates/synvoid-tarpit/src/generator.rs` — `MarkovChain` (bigram model, 10 built-in corpora)

## Architecture

### Admission Control
```
Request → try_admit() → Some(AdmissionGuard) → process → Guard dropped → permit released
                      → None → 429 or queue
```
- Global semaphore: `max_concurrent` (default 256)
- Per-IP semaphore: `max_per_ip` (default 4)
- Non-blocking: `try_admit()` never waits

### Session Budgets
Atomic counters enforce limits per session:
- `max_duration` (600s) — wall-clock timeout
- `max_chunks` (500) — response chunks sent
- `max_bytes` (50MB) — total bytes sent
- `max_idle` (30s) — inactivity timeout

### Markov Chain Generator
- Bigram model trained on 10 built-in corpora (HTML, JS, JSON, etc.)
- Fallback sentence when model is empty
- Chunk delay: 5-30ms between chunks (configurable)

### Redirect Policy
- `RelativeOnly` (default) — blocks absolute URLs and CRLF injection
- `AllowAbsolute` — permits external redirects (use with caution)

## Configuration Defaults
```toml
[tarpit]
enabled = true
chunk_delay_ms = [5, 30]

[tarpit.admission]
max_concurrent = 256
max_per_ip = 4

[tarpit.budget]
max_duration_secs = 600
max_chunks = 500
max_bytes = 52428800  # 50MB
max_idle_secs = 30
```

## Critical Invariants
- All attacker-controlled values MUST pass through `escaping.rs` before HTML output
- `try_admit()` is non-blocking — never call `.unwrap()` or `.await` on admission
- `AdmissionGuard` is RAII — dropping it releases the permit
- Redirect targets pass through `sanitize_redirect_target()` (default-deny CRLF)

## Testing
```bash
cargo test -p synvoid-tarpit --all-targets
```
54 tests covering admission, budget, escaping, generator, and integration.

## Common Issues
1. **Too many 429s** — increase `max_concurrent` or `max_per_ip`
2. **Markov output is gibberish** — check corpus selection; fallback sentence activates when model is empty
3. **Redirect loops** — ensure redirect target passes `sanitize_redirect_target()`
