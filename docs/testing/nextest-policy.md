# Nextest Policy

## Pinned Version

cargo-nextest **0.9.140** (pinned as of Milestone B).

### Local Installation

```bash
cargo install cargo-nextest@0.9.140
```

### CI Installation

Use `taiki-e/install-action` (installs the pinned latest stable by default):

```yaml
- uses: taiki-e/install-action@nextest
```

### Version Verification

```bash
cargo nextest --version
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

Tests are serialized only when they have documented conflicts. All other tests run at full nextest concurrency.

### Current Overrides

| Override | Filter | Reason | Action |
|----------|--------|--------|--------|
| Global state | `test(/fixed_port\|global_state\|process_global/)` | Tests use process-global resources | `threads-required = "num-cpus"` |
| Stress/interop | `test(/stress\|interop\|live_signing\|recursion/)` | Long-running tests need extended timeout | `slow-timeout = 120s × 1` |
| Security regression | `test(security_regression)` | Uses process-global blockstore and IPC mocks | `threads-required = "num-cpus"` |
| DNS integration | `package(synvoid-dns) and test(/server_test\|config_fidelity\|recursive_isolation/)` | Bind to fixed ports | `slow-timeout = 60s × 2` |

### How to Add a Serialization Exception

1. Identify the test and its conflict (fixed port, global state, etc.)
2. Add a `[[profile.ci.overrides]]` entry in `.config/nextest.toml`
3. Document the reason in this file under "Current Overrides"
4. File a Milestone E issue to remove the constraint if possible

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
