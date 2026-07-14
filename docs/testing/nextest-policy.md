# Nextest Policy

## Pinned Version

cargo-nextest 0.9.x (latest stable as of Milestone B).

### Installation

```bash
cargo install cargo-nextest
```

### CI Installation

Use `taiki-e/install-action` with pinned version:

```yaml
- uses: taiki-e/install-action@nextest
```

## Profiles

### default (local development)
- fail-fast = false
- Standard timeouts

### ci (CI pipeline)
- fail-fast = false
- status-level = "pass"
- final-status-level = "slow"
- slow-timeout: 30s period, terminate after 2 periods
- retries: 0 (disabled by default)

## Retry Policy

Retries are disabled by default. A retry may be added only when:
- The nondeterminism source is external and documented
- The first failure remains visible in reports
- A tracking issue exists to remove the retry
- Security-critical deterministic tests are not masked

No retries are configured for any suite at this time.

## Serialization Policy

Tests are serialized only when they have documented conflicts:
- Fixed ports or network globals: `threads-required = "num-cpus"`
- Stress/interop/live tests: extended slow-timeout (120s)

All other tests run at full nextest concurrency.

## Doctests

Doctests are NOT run by nextest. Use:
```bash
cargo test --workspace --doc --profile ci
```

## JUnit Output

CI profiles produce JUnit XML at:
```
target/nextest/ci/junit.xml
```

## Cargo Profile vs Nextest Profile

- **Cargo profile** (`--cargo-profile ci`): Controls compilation settings (opt-level, debug, incremental)
- **Nextest profile** (`--profile ci`): Controls test execution (timeouts, retries, JUnit output)

These are separate concepts. Use both:
```bash
cargo nextest run --cargo-profile ci --profile ci
```
