# Milestone C Phase 4: Tarpit Safety, Escaping, Admission, and Fingerprint Resistance

## Purpose

Harden the tarpit system so it is safe to expose in production-like deployments. The tarpit should waste attacker time without creating XSS/open-redirect behavior, unbounded connection/resource use, easy fingerprinting, or deterministic crash paths.

## Current issues to address

1. Redirect/HTML responses may interpolate attacker-controlled paths without sufficient escaping.
2. Long-lived streaming responses need admission and duration budgets.
3. Generated output may be deterministic/fingerprintable.
4. Edge cases such as `max_depth == 0` must not panic.
5. Extension/path handling should not ignore available context.
6. Tarpit metrics should distinguish admitted, rejected, timed out, and completed sessions.

## Non-goals

- Do not build a general web application framework.
- Do not make tarpit streams unbounded by default.
- Do not add external network calls.
- Do not depend on AI generation for tarpit content.

## Implementation tasks

### 1. Escaping and redirect safety

Audit all tarpit response generators for attacker-controlled interpolation:

- request path
- query string
- host/header values
- user-agent
- generated redirect target

Apply context-appropriate escaping:

- HTML text escaping
- HTML attribute escaping
- JavaScript string escaping if JS is emitted
- URL/path encoding where needed

Redirect behavior:

- do not generate open redirects to attacker-controlled absolute URLs by default
- only emit relative redirects or configured safe hostnames
- reject/control CRLF and control characters

Tests:

- path containing `<script>` is escaped
- path containing quotes does not break attribute context
- absolute URL input does not become open redirect
- CRLF injection blocked/escaped

### 2. Edge-case guards

Fix deterministic crash paths:

- `max_depth == 0`
- empty template list
- empty corpus/token list
- zero stream chunk interval
- duration lower than one chunk interval
- invalid content type/config

Tests should cover each guard.

### 3. Admission control

Add tarpit admission limits:

- max concurrent tarpit sessions
- max sessions per IP
- max streams per site/scope
- optional global byte-rate budget
- queue/drop behavior for over-limit sessions

Use semaphores/RAII guards similar to honeypot listener where applicable.

### 4. Duration and output budgets

Bound long-lived streams:

- max connection duration
- max chunks
- max bytes per response
- max idle time
- write timeout per chunk
- cancellation on shutdown

Default should protect server resources over indefinite deception.

### 5. Fingerprint resistance

Reduce deterministic patterns:

- seeded per-session variation
- configurable content families
- varied delays within safe bounds
- varied status codes/content types where appropriate
- avoid obvious repeating fixed chunks

Do not use cryptographic randomness unless already available and necessary. Predictability reduction is enough; this is not a cryptographic protocol.

### 6. Metrics and logs

Add counters/gauges:

- admitted sessions
- rejected global limit
- rejected per-IP limit
- timed-out sessions
- completed sessions
- bytes sent
- active sessions
- escaping/redirect policy rejections

Logs should not include raw unescaped attacker input without sanitization.

### 7. Tests

Required tests:

- HTML escaping for path/query/header-derived values
- redirect target sanitization
- `max_depth == 0` no panic
- empty corpus no panic
- concurrent admission limit enforced
- per-IP limit enforced
- duration budget stops stream
- byte budget stops stream
- write timeout path releases permits
- seeded variation changes output across sessions while preserving bounds

## Local validation commands

```bash
cargo fmt --all -- --check
cargo clippy -p synvoid-tarpit --all-targets -- -D warnings
cargo test -p synvoid-tarpit --all-targets
```

If tarpit is integrated in HTTP/WAF crates:

```bash
cargo clippy -p synvoid-http --all-targets -- -D warnings
cargo test -p synvoid-http --all-targets tarpit
cargo test -p synvoid-waf --all-targets tarpit
```

## Success criteria

- Attacker-controlled values are escaped in correct context.
- Redirect generation cannot become an open redirect by default.
- Edge cases do not panic.
- Tarpit streams have admission, duration, and byte budgets.
- Permit/session state releases on all exits.
- Output is less deterministic within documented bounds.
- Tests cover escaping, admission, budgets, and edge cases.

## Handoff notes

This phase is operational safety work. Keep it deterministic and testable; do not add model-generated tarpit content or external dependencies unless separately justified.
