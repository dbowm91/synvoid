# synvoid-testkit

Shared test utilities for cross-crate use in the SynVoid workspace.

## Purpose

This crate exists to eliminate test-boilerplate duplication across the
workspace. It depends only on `synvoid-core` and `synvoid-config`, keeping
the dependency footprint small enough that any workspace crate can pull it
in as a `[dev-dependency]` without dragging in the server binary or
networking layers.

## Boundary policy (Milestone E)

**In scope** — helpers with demonstrated cross-crate value:

| Category | Examples |
|----------|----------|
| Ephemeral servers | Generic TCP/UDP listeners for integration tests |
| Certificate material | Temp CA + leaf certs used by TLS, proxy, and HTTP/3 tests |
| Tracing init | `tracing_subscriber` setup for test output capture |
| Temp directories | RAII directory lifecycle for config/zone/persistence tests |
| Clocks / readiness | Deterministic time sources, health-check waiters |
| Process cleanup | Drop-based child-process reapers |
| Assertion macros | `assert_contains!`, `assert_not_contains!` (used in ≥2 crates) |

**Out of scope** — belongs in the owning crate's own tests:

- DNS query builders → `synvoid-dns`
- Mesh routing fixtures → `synvoid-mesh`
- WAF rule corpora → `synvoid-waf`
- IPC endpoint fixtures → `synvoid-ipc`
- Anything that depends on more than `synvoid-core` or `synvoid-config`

## Adding a new helper

1. Confirm it will be consumed by **two or more** workspace crates.
2. Add it to the appropriate module (or create a new one).
3. Include a doc comment with a usage example.
4. Add at least one unit test.
5. Update this README's "In scope" table.

## Current status

As of Milestone E this crate has **no active consumers**. The helpers
below are retained for potential future use. If no consumer materialises
by the next milestone review they should be removed to reduce maintenance
surface.

| Module | Public items |
|--------|-------------|
| `assertions` | `assert_contains!`, `assert_not_contains!` |
| `config_fixtures` | `temp_config_dir()`, `minimal_config()` |
| `request_fixtures` | `test_request_context()`, `test_request_context_with_site()` |
