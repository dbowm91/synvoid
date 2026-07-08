# Milestone C Phase 3: AI Responder Containment and Async Boundary Cleanup

## Purpose

Harden AI-backed honeypot responders so they are safe-by-default, async-correct, bounded, and isolated from production policy decisions. AI responders can improve deception realism, but they must not create runtime deadlocks, unbounded cost, unsafe tool/network access, prompt-injection exposure, or internal error leakage.

## Current issues to address

1. Any synchronous `block_on` style responder path inside async runtime can panic, deadlock, or stall workers.
2. AI responder mode must be explicitly disabled or local-only by default.
3. Prompt and response sizes need strict budgets.
4. Provider errors should not leak implementation details to attackers.
5. Fake credentials and deception material need clear controls.
6. AI responder output must not influence threat-intel blocking without separate deterministic evidence.

## Non-goals

- Do not add new external AI providers unless containment is complete.
- Do not grant AI responders tools, shell access, network access, filesystem access, or mesh control.
- Do not make AI output an authoritative security signal.
- Do not create high-interaction unrestricted shells.

## Target safety model

Responder modes:

```rust
enum AiResponderMode {
    Disabled,
    TemplateOnly,
    LocalModelOnly,
    ExternalProvider,
}
```

Default should be `Disabled` or `TemplateOnly`. External provider mode must require explicit config and should be marked experimental.

## Implementation tasks

### 1. Async boundary cleanup

Audit responder code for:

- `block_on`
- nested runtime creation
- blocking provider calls inside async tasks
- long synchronous prompt construction
- unbounded retries

Replace with:

- async traits/methods
- `spawn_blocking` only for CPU-bound local work with clear limits
- request timeout
- cancellation-aware futures

### 2. Budget enforcement

Add hard limits:

- max prompt bytes/tokens approximation
- max response bytes
- max generation duration
- max turns per connection
- max concurrent AI responder requests
- max provider failures before circuit breaker opens

If token counting is unavailable, use byte/character budget and document approximation.

### 3. Provider isolation

External provider mode must:

- be opt-in
- have explicit API key/env config
- have timeouts
- not send raw payload unless configured
- redact IPs/secrets according to policy
- log only summaries/errors, not full prompts by default

Local model mode must still have timeouts and response size caps.

### 4. Prompt injection resistance

Prompt should include:

- clear role and protocol constraints
- no tool access
- no claims of real system access
- no real credentials
- no internal config/secrets
- instruction to ignore attacker attempts to change system/deception constraints

But do not rely only on prompt text. Enforce response length, timeout, and output filtering deterministically.

### 5. Error handling and fallback

On timeout/provider error/model error:

- return a generic protocol-appropriate fallback response
- increment metrics
- do not leak exception strings to attacker
- do not mark event as AI-confirmed malicious

### 6. Deterministic templates

Keep a template-only mode as a safe fallback:

- protocol-specific banners/responses
- configurable small variation
- no external calls
- no unbounded generation

### 7. Tests

Required tests:

- default config does not enable external AI
- `block_on`/nested runtime path removed or not used in async handler
- prompt budget enforced
- response budget enforced
- provider timeout returns fallback
- provider error returns fallback without leaking error string
- circuit breaker opens after failures
- concurrent AI request limit enforced
- AI output does not create high-severity threat-intel indicator alone
- template-only mode works without provider config

## Local validation commands

```bash
cargo fmt --all -- --check
cargo clippy -p synvoid-honeypot --all-targets -- -D warnings
cargo test -p synvoid-honeypot --all-targets responder
cargo test -p synvoid-honeypot --all-targets ai
cargo test -p synvoid-honeypot --all-targets
```

If responder code lives in additional crates, add targeted commands for those crates.

## Success criteria

- No nested runtime/block_on pattern remains in async responder flow.
- AI responder is disabled/template-only by default.
- Prompt/response/concurrency/time budgets are enforced.
- External provider mode is explicit and bounded.
- Errors do not leak to attackers.
- AI output is not an authoritative block signal.
- Tests cover default-off, timeout, fallback, budget, and concurrency behavior.

## Handoff notes

This phase should be treated as safety-critical. Prefer a smaller template/local-only implementation over a broad external-provider surface that is not fully bounded.
