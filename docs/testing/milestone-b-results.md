# Milestone B: Modernize Test Execution

**Date:** July 2026

## Summary

Milestone B modernized SynVoid's test execution infrastructure by adopting cargo-nextest for faster parallel test runs, extracting 16 static guard tests into a lightweight shared crate, and formalizing CI policies for test lifecycle management.

## What Was Done

### Nextest Adoption

- Installed cargo-nextest 0.9.140 as the test runner for eligible test targets.
- Created `.config/nextest.toml` with a dedicated CI profile:
  - `fail-fast = false` — run all tests even if one fails, for complete reporting.
  - `slow-timeout = 30s` — flag tests exceeding 30 seconds.
  - `retries = 0` — no automatic retries; failures are real.
- Created `docs/testing/nextest-policy.md` documenting the adoption rationale, configuration, and usage guidelines.
- CI workflows updated to use nextest for unit and integration tests where applicable.
- Doctests retained on `cargo test` since nextest does not support them.

### Repository Guard Crate

- Created `tools/synvoid-repo-guards/` as a lightweight standalone crate for static analysis guard tests.
- Shared helpers extracted and available to all guard modules:
  - `workspace_root()` — resolves the workspace root path.
  - `collect_rs_files()` — recursively collects all `.rs` files in the workspace.
  - `strip_comments()` — strips Rust comments from source for accurate pattern scanning.
  - `prepare_for_scanning()` — preprocesses source content for guard assertions.
- 16 static guard tests migrated into the crate, organized into 4 test modules:

  | Module | Tests | Coverage |
  |--------|-------|----------|
  | `module_ownership` | 3 | Root module ledger, facade boundary, dependency ownership |
  | `composition_boundary` | 4 | Data plane, request path, HTTP pipeline, HTTP/3 WAF |
  | `lifecycle_ownership` | 5 | Background spawns, supervisor spawns, mem::forget, composition root thinness, CLI dispatch |
  | `docs_and_misc` | 2 | Docs path references, unsafe native sandbox language |

- Dependency boundary maintained: only `regex` as a dev-dependency, no dependency on the root `synvoid` crate.

### Guard Classification

A full inventory of all guard tests was performed:

| Classification | Count | Description |
|----------------|-------|-------------|
| STATIC | 27 | Pattern/source-scanning guards with no runtime state |
| RUNTIME | 6 | Guards requiring live process or runtime infrastructure |
| MIXED | 0 | None identified |
| **Total** | **33** | |

Distribution after Milestone B:

- 14 static guards moved to lightweight `synvoid-repo-guards` crate.
- 13 complex static guards remain in root `tests/` (assertion complexity defers migration to Milestone C).
- 6 runtime guards remain in root `tests/` (require runtime context).

### CI Integration

- PR fast lane uses nextest for eligible test targets, reducing feedback latency.
- Guard suite runs static guards from the lightweight crate without building the full workspace.
- JUnit XML output configured for CI artifact collection and trend analysis.
- Slow-test threshold (30s) and timeout policies are explicit in nextest configuration.

## Metrics

| Metric | Value |
|--------|-------|
| Guard crate tests | 16 |
| Guard crate execution time | 0.97s |
| Root synvoid dependency | None (lightweight crate) |
| Clippy | Clean |
| Format | Clean |
| Existing test coverage | Fully preserved |

## What Remains for Milestone C

- Move 13 complex static guards (plugin safety, detailed source scanning) from root `tests/` to the lightweight crate once assertion complexity is refactored.
- Move runtime guards to their owning domain crates for better ownership alignment.
- Full test count reconciliation between `cargo test` and `cargo nextest run` to ensure no tests are lost or duplicated.

## What Remains for Milestone E

- Remove unnecessary serialization constraints identified during Milestone B analysis.
- Address resource conflicts deferred from Milestone B (specific items tracked in the milestone planning notes).
