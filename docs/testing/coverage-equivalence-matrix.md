# Coverage Equivalence Matrix

> Generated: 2026-07-15 | Sources: `ci-lane-policy.md`, `test-suite-ownership.md`, `feature-target-matrix.md`, `testing/lanes.toml`

This matrix maps every pre-roadmap assurance category to the current authoritative lane and command. Use this as the single reference for answering "where does category X run?" during CI triage or lane migration.

## Legend

- **Old Command/Job** — Legacy `ci.yml` job name or ad-hoc command (pre-milestone-A).
- **New Command/Job** — Current command in the lane-specific workflow.
- **Lane** — `PR` (pull-request fast), `Main` (post-merge comprehensive), `Nightly` (scheduled qualification), `Release` (tag/dispatch).
- **Profile** — Cargo profile used (`dev`, `ci`, `release`, `nightly`).
- **Platform** — Target platform (`linux` = native runner, `linux-musl` = Alpine, `freebsd`, `macos-intel`, `macos-arm64`, `windows`, `all` = all supported).
- **Frequency** — How often the category runs.

---

## Formatting & Lint

| Category | Old Command/Job | New Command/Job | Lane | Profile | Platform | Frequency |
|----------|----------------|-----------------|------|---------|----------|-----------|
| Formatting (workspace) | `ci.yml: fmt` | `cargo fmt --all -- --check` | PR | — | linux | Every PR |
| Clippy (default features) | `ci.yml: clippy` | `cargo clippy --all-targets -- -D warnings` | PR | dev | linux | Every PR |
| Clippy (all features) | `ci.yml: clippy-all` | `cargo clippy --all-targets --all-features -- -D warnings` | Release | dev | linux | Version tags / dispatch |
| DNS crate formatting | `ci.yml: dns-tests` (fmt step) | `cargo fmt -p synvoid-dns -- --check` | Main | — | linux | Push to main |
| DNS crate lint | `ci.yml: dns-tests` (clippy step) | `cargo clippy -p synvoid-dns --all-targets -- -D warnings` | Main | dev | linux | Push to main |
| Plugin runtime lint | `ci.yml: plugin-runtime-guardrails` (clippy step) | `cargo clippy -p synvoid-plugin-runtime --all-targets -- -D warnings` | Main | dev | linux | Push to main |
| Upload crate lint | `ci.yml: upload-tests` (clippy step) | `cargo clippy -p synvoid-upload --all-targets -- -D warnings` | PR | dev | linux | Every PR (affected) |
| Honeypot crate lint | `ci.yml: honeypot-tests` (clippy step) | `cargo clippy -p synvoid-honeypot --all-targets -- -D warnings` | PR | dev | linux | Every PR (affected) |
| Tarpit crate lint | `ci.yml: tarpit-tests` (clippy step) | `cargo clippy -p synvoid-tarpit --all-targets -- -D warnings` | PR | dev | linux | Every PR (affected) |
| Mesh crate lint | `ci.yml: mesh-tests` (clippy step) | `cargo clippy -p synvoid-mesh --features mesh --all-targets -- -D warnings` | PR | dev | linux | Every PR (affected) |

## Compile Profiles

| Category | Old Command/Job | New Command/Job | Lane | Profile | Platform | Frequency |
|----------|----------------|-----------------|------|---------|----------|-----------|
| Default compile | `ci.yml: build` (default) | `cargo check` | Main | dev | linux | Push to main |
| No-default core compile | `ci.yml: core-profile` | `cargo check --no-default-features` | PR | dev | linux | Every PR |
| Mesh-only compile | `ci.yml: profile-matrix` (mesh) | `cargo check --no-default-features --features mesh` | Main | dev | linux | Push to main |
| DNS-only compile | `ci.yml: profile-matrix` (dns) | `cargo check --no-default-features --features dns` | Main | dev | linux | Push to main |
| Full mesh+dns compile | `ci.yml: profile-matrix` (full) | `cargo check --no-default-features --features mesh,dns` | Main | dev | linux | Push to main |
| All-features compile | `ci.yml: profile-matrix` (all) | `cargo check --all-features` (implied by clippy all-features) | Release | dev | linux | Version tags / dispatch |
| DNS all-features compile | `ci.yml: dns-tests` (check step) | `cargo check -p synvoid-dns --all-features` | Main | dev | linux | Push to main |
| Upload all-features compile | `ci.yml: upload-tests` (check step) | `cargo check -p synvoid-upload --all-features` | PR | dev | linux | Every PR (affected) |
| Honeypot all-features compile | `ci.yml: honeypot-tests` (check step) | `cargo check -p synvoid-honeypot --all-features` | PR | dev | linux | Every PR (affected) |

## Unit Tests (Root Library)

| Category | Old Command/Job | New Command/Job | Lane | Profile | Platform | Frequency |
|----------|----------------|-----------------|------|---------|----------|-----------|
| Root lib unit tests | `ci.yml: test` (default) | `cargo nextest run --cargo-profile ci --profile ci --no-fail-fast` | Release | ci | linux | Version tags / dispatch |

## Domain Integration Tests

| Category | Old Command/Job | New Command/Job | Lane | Profile | Platform | Frequency |
|----------|----------------|-----------------|------|---------|----------|-----------|
| DNS full test suite | `ci.yml: dns-tests` (blanket) | `cargo nextest run -p synvoid-dns --cargo-profile ci --profile ci` | Main | ci | linux | Push to main |
| DNS doctests | `ci.yml: dns-tests` (doc step) | `cargo test -p synvoid-dns --doc --profile ci` | Main | ci | linux | Push to main |
| Plugin runtime tests | `ci.yml: plugin-runtime-guardrails` (test step) | `cargo nextest run -p synvoid-plugin-runtime --cargo-profile ci --profile ci` | Main | ci | linux | Push to main |
| Plugin runtime doctests | `ci.yml: plugin-runtime-guardrails` (doc step) | `cargo test -p synvoid-plugin-runtime --doc --profile ci` | Main | ci | linux | Push to main |
| Mesh crate tests | `ci.yml: mesh-tests` (test step) | `cargo nextest run -p synvoid-mesh --features mesh --cargo-profile ci --profile ci` | PR | ci | linux | Every PR (affected) |
| Upload crate tests | `ci.yml: upload-tests` (test step) | `cargo nextest run -p synvoid-upload --cargo-profile ci --profile ci` | PR | ci | linux | Every PR (affected) |
| Upload mesh-feature tests | `ci.yml: upload-tests` (mesh step) | `cargo nextest run -p synvoid-upload --features mesh --cargo-profile ci --profile ci` | PR | ci | linux | Every PR (affected) |
| Honeypot crate tests | `ci.yml: honeypot-tests` (test step) | `cargo nextest run -p synvoid-honeypot --cargo-profile ci --profile ci` | PR | ci | linux | Every PR (affected) |
| Tarpit crate tests | `ci.yml: tarpit-tests` (test step) | `cargo nextest run -p synvoid-tarpit --all-targets --cargo-profile ci --profile ci` | PR | ci | linux | Every PR (affected) |

## Root Composition Tests

| Category | Old Command/Job | New Command/Job | Lane | Profile | Platform | Frequency |
|----------|----------------|-----------------|------|---------|----------|-----------|
| Full default test suite | `ci.yml: test` (release) | `cargo nextest run --cargo-profile ci --profile ci --no-fail-fast` | Release | ci | linux | Version tags / dispatch |
| Full mesh test suite | `ci.yml: test` (mesh) | `cargo nextest run --features mesh --cargo-profile ci --profile ci --no-fail-fast` | Release | ci | linux | Version tags / dispatch |
| Default doctests | `ci.yml: test` (doc step) | `cargo test --workspace --doc --profile ci` | Main | ci | linux | Push to main |
| Mesh doctests | `ci.yml: test` (mesh-doc step) | `cargo test --workspace --doc --features mesh --profile ci` | Release | ci | linux | Version tags / dispatch |

## Architecture Guards

| Category | Old Command/Job | New Command/Job | Lane | Profile | Platform | Frequency |
|----------|----------------|-----------------|------|---------|----------|-----------|
| Static guards (repo-guards crate) | `ci.yml: guard-suite` (nextest) | `cargo nextest run -p synvoid-repo-guards --cargo-profile ci --profile ci` | PR | ci | linux | Every PR |
| boundary_composition_guard | `ci.yml: guard-suite` | `cargo test --test boundary_composition_guard` | PR | dev | linux | Every PR |
| lifecycle_task_guard | `ci.yml: guard-suite` | `cargo test --test lifecycle_task_guard` | PR | dev | linux | Every PR |
| plugin_guard | `ci.yml: guard-suite` | `cargo test --test plugin_guard` | PR | dev | linux | Every PR |
| cli_admin_guard | `ci.yml: guard-suite` | `cargo test --test cli_admin_guard` | PR | dev | linux | Every PR |
| security_guard | `ci.yml: guard-suite` | `cargo test --test security_guard` | PR | dev | linux | Every PR |
| root_facade_boundary_guard | `ci.yml: guard-suite` | `cargo test --test root_facade_boundary_guard` | PR | dev | linux | Every PR |
| mesh_id_boundary_guard | `ci.yml: guard-suite` | `cargo test --test mesh_id_boundary_guard` | PR | dev | linux | Every PR |
| admin_mutation_response_guard | `ci.yml: guard-suite` | `cargo test --test admin_mutation_response_guard` | PR | dev | linux | Every PR |
| admin_mutation_blocklist | `ci.yml: guard-suite` | `cargo test --test admin_mutation_blocklist` | PR | dev | linux | Every PR |
| admin_auth_boundary | `ci.yml: guard-suite` | `cargo test --test admin_auth_boundary` | PR | dev | linux | Every PR |
| mesh_admin_edge_cases | `ci.yml: guard-suite` | `cargo test --test mesh_admin_edge_cases` | PR | dev | linux | Every PR |
| failure_injection | `ci.yml: guard-suite` | `cargo test --test failure_injection` | PR | dev | linux | Every PR |
| worker_mesh_supervision_boundary_guard | `ci.yml: guard-suite` | `cargo test --test worker_mesh_supervision_boundary_guard --features mesh,dns` | PR | dev | linux | Every PR |
| mesh_task_ownership_guard | `ci.yml: guard-suite` | `cargo test --test mesh_task_ownership_guard --features mesh,dns` | PR | dev | linux | Every PR |
| abi_memory_boundary_guard | `ci.yml: guard-suite` | `cargo test --test abi_memory_boundary_guard` | PR | dev | linux | Every PR |
| root_test_ownership_guard | `ci.yml: guard-suite` | `cargo test --test root_test_ownership_guard` | PR | dev | linux | Every PR |
| Plugin guard: manifest_authority_wiring | `ci.yml: plugin-runtime-guardrails` | `cargo test -p synvoid-plugin-runtime --test manifest_authority_wiring` | Main | ci | linux | Push to main |
| Plugin guard: plugin_failure_does_not_poison_manager | `ci.yml: plugin-runtime-guardrails` | `cargo test -p synvoid-plugin-runtime --test plugin_failure_does_not_poison_manager` | Main | ci | linux | Push to main |

## Security Regressions

| Category | Old Command/Job | New Command/Job | Lane | Profile | Platform | Frequency |
|----------|----------------|-----------------|------|---------|----------|-----------|
| Security regression tests | `ci.yml: security-regression` | `cargo nextest run --test security_regression --cargo-profile ci --profile ci -- --test-threads=1` | PR | ci | linux | Every PR |
| DNS unsafe check | `ci.yml: unsafe-dns` | `grep -r "unsafe {" crates/synvoid-dns/src/` | PR | — | linux | Every PR |
| Forbidden imports | `ci.yml: import-check` | `python scripts/check_imports.py` | PR | — | linux | Every PR |

## DNS Interoperability

| Category | Old Command/Job | New Command/Job | Lane | Profile | Platform | Frequency |
|----------|----------------|-----------------|------|---------|----------|-----------|
| DNS full test suite (interop) | `ci.yml: dns-tests` (blanket) | `cargo nextest run -p synvoid-dns --cargo-profile ci --profile ci` | Main | ci | linux | Push to main |
| DNS all-features check | `ci.yml: dns-tests` (check step) | `cargo check -p synvoid-dns --all-features` | Main | dev | linux | Push to main |
| DNS doctests | `ci.yml: dns-tests` (doc step) | `cargo test -p synvoid-dns --doc --profile ci` | Main | ci | linux | Push to main |

## Mesh Behavior

| Category | Old Command/Job | New Command/Job | Lane | Profile | Platform | Frequency |
|----------|----------------|-----------------|------|---------|----------|-----------|
| Mesh crate compile | `ci.yml: mesh-tests` (check step) | `cargo check -p synvoid-mesh --features mesh --all-targets` | PR | dev | linux | Every PR (affected) |
| Mesh crate lint | `ci.yml: mesh-tests` (clippy step) | `cargo clippy -p synvoid-mesh --features mesh --all-targets -- -D warnings` | PR | dev | linux | Every PR (affected) |
| Mesh crate tests | `ci.yml: mesh-tests` (test step) | `cargo nextest run -p synvoid-mesh --features mesh --cargo-profile ci --profile ci` | PR | ci | linux | Every PR (affected) |

## Plugin Runtime

| Category | Old Command/Job | New Command/Job | Lane | Profile | Platform | Frequency |
|----------|----------------|-----------------|------|---------|----------|-----------|
| Plugin runtime lint | `ci.yml: plugin-runtime-guardrails` (clippy step) | `cargo clippy -p synvoid-plugin-runtime --all-targets -- -D warnings` | Main | dev | linux | Push to main |
| Plugin runtime tests | `ci.yml: plugin-runtime-guardrails` (test step) | `cargo nextest run -p synvoid-plugin-runtime --cargo-profile ci --profile ci` | Main | ci | linux | Push to main |
| Plugin runtime doctests | `ci.yml: plugin-runtime-guardrails` (doc step) | `cargo test -p synvoid-plugin-runtime --doc --profile ci` | Main | ci | linux | Push to main |
| Plugin guard: manifest authority | `ci.yml: plugin-runtime-guardrails` | `cargo test -p synvoid-plugin-runtime --test manifest_authority_wiring` | Main | ci | linux | Push to main |
| Plugin guard: failure isolation | `ci.yml: plugin-runtime-guardrails` | `cargo test -p synvoid-plugin-runtime --test plugin_failure_does_not_poison_manager` | Main | ci | linux | Push to main |

## Upload / Honeypot / Tarpit

| Category | Old Command/Job | New Command/Job | Lane | Profile | Platform | Frequency |
|----------|----------------|-----------------|------|---------|----------|-----------|
| Upload crate formatting | `ci.yml: upload-tests` (fmt step) | `cargo fmt -p synvoid-upload -- --check` | PR | — | linux | Every PR (affected) |
| Upload crate lint | `ci.yml: upload-tests` (clippy step) | `cargo clippy -p synvoid-upload --all-targets -- -D warnings` | PR | dev | linux | Every PR (affected) |
| Upload crate tests | `ci.yml: upload-tests` (test step) | `cargo nextest run -p synvoid-upload --cargo-profile ci --profile ci` | PR | ci | linux | Every PR (affected) |
| Upload mesh-feature tests | `ci.yml: upload-tests` (mesh step) | `cargo nextest run -p synvoid-upload --features mesh --cargo-profile ci --profile ci` | PR | ci | linux | Every PR (affected) |
| Upload all-features compile | `ci.yml: upload-tests` (check step) | `cargo check -p synvoid-upload --all-features` | PR | dev | linux | Every PR (affected) |
| Honeypot crate formatting | `ci.yml: honeypot-tests` (fmt step) | `cargo fmt -p synvoid-honeypot -- --check` | PR | — | linux | Every PR (affected) |
| Honeypot crate lint | `ci.yml: honeypot-tests` (clippy step) | `cargo clippy -p synvoid-honeypot --all-targets -- -D warnings` | PR | dev | linux | Every PR (affected) |
| Honeypot crate tests | `ci.yml: honeypot-tests` (test step) | `cargo nextest run -p synvoid-honeypot --cargo-profile ci --profile ci` | PR | ci | linux | Every PR (affected) |
| Honeypot all-features compile | `ci.yml: honeypot-tests` (check step) | `cargo check -p synvoid-honeypot --all-features` | PR | dev | linux | Every PR (affected) |
| Tarpit crate lint | `ci.yml: tarpit-tests` (clippy step) | `cargo clippy -p synvoid-tarpit --all-targets -- -D warnings` | PR | dev | linux | Every PR (affected) |
| Tarpit crate tests | `ci.yml: tarpit-tests` (test step) | `cargo nextest run -p synvoid-tarpit --all-targets --cargo-profile ci --profile ci` | PR | ci | linux | Every PR (affected) |

## Docs Build

| Category | Old Command/Job | New Command/Job | Lane | Profile | Platform | Frequency |
|----------|----------------|-----------------|------|---------|----------|-----------|
| Documentation build | `ci.yml: docs` | `cargo doc --no-deps --release` | Main | release | linux | Push to main |

## Dependency Audit

| Category | Old Command/Job | New Command/Job | Lane | Profile | Platform | Frequency |
|----------|----------------|-----------------|------|---------|----------|-----------|
| Security advisory audit | `ci.yml: security-audit` | `cargo audit` | Main | — | linux | Push to main |
| Dependency license/ban/sources | `ci.yml: dependency-audit` | `cargo deny check` | Main | — | linux | Push to main |
| Outdated dependency report | `ci.yml: outdated-deps` | `cargo outdated --release --exit-code 2` | Nightly | release | linux | Nightly 4 AM UTC |

## Miri

| Category | Old Command/Job | New Command/Job | Lane | Profile | Platform | Frequency |
|----------|----------------|-----------------|------|---------|----------|-----------|
| Memory safety (Miri) | `ci.yml: miri-test` | `cargo miri test -p synvoid-utils` | Nightly | nightly | linux | Nightly 4 AM UTC (continue-on-error) |

## Fuzz Smoke

| Category | Old Command/Job | New Command/Job | Lane | Profile | Platform | Frequency |
|----------|----------------|-----------------|------|---------|----------|-----------|
| Fuzz correctness (17 targets) | `ci.yml: fuzz-smoke` | `cargo +nightly fuzz run <target> -- -runs=1000` | Nightly | nightly | linux | Nightly 4 AM UTC |

## Alpine/musl

| Category | Old Command/Job | New Command/Job | Lane | Profile | Platform | Frequency |
|----------|----------------|-----------------|------|---------|----------|-----------|
| Alpine/musl build | `ci.yml: alpine-test` (build step) | `cargo build --release` | Nightly | release | linux-musl | Nightly 4 AM UTC |
| Alpine/musl test (serial) | `ci.yml: alpine-test` (test step) | `cargo test --release -- --test-threads=1` | Nightly | release | linux-musl | Nightly 4 AM UTC |
| Alpine/musl cross-compile | `ci.yml: build` (musl target) | `cross build --target x86_64-unknown-linux-musl --release --features wireguard` | Main | release | linux-musl | Push to main |

## FreeBSD

| Category | Old Command/Job | New Command/Job | Lane | Profile | Platform | Frequency |
|----------|----------------|-----------------|------|---------|----------|-----------|
| FreeBSD build | `ci.yml: freebsd-test` (build step) | `cargo build --release` | Nightly | release | freebsd | Nightly 4 AM UTC |
| FreeBSD test (serial) | `ci.yml: freebsd-test` (test step) | `cargo test --release -- --test-threads=1` | Nightly | release | freebsd | Nightly 4 AM UTC |
| FreeBSD cross-compile | `ci.yml: build` (freebsd target) | `cross build --target x86_64-unknown-freebsd --release --features wireguard` | Main | release | freebsd | Push to main |

## macOS

| Category | Old Command/Job | New Command/Job | Lane | Profile | Platform | Frequency |
|----------|----------------|-----------------|------|---------|----------|-----------|
| macOS Intel build | `ci.yml: build` (darwin-intel) | `cargo build --target x86_64-apple-darwin --release --features wireguard` | Main | release | macos-intel | Push to main |
| macOS Intel tests | `ci.yml: build` (darwin-intel test) | `cargo nextest run --target x86_64-apple-darwin --cargo-profile ci --profile ci --no-fail-fast` | Main | ci | macos-intel | Push to main |
| macOS Intel doctests | `ci.yml: build` (darwin-intel doc) | `cargo test --workspace --doc --profile ci` | Main | ci | macos-intel | Push to main |
| macOS ARM build | `ci.yml: build` (darwin-arm) | `cargo build --target aarch64-apple-darwin --release --features wireguard` | Main | release | macos-arm64 | Push to main |
| macOS ARM tests | `ci.yml: build` (darwin-arm test) | `cargo nextest run --target aarch64-apple-darwin --cargo-profile ci --profile ci --no-fail-fast` | Main | ci | macos-arm64 | Push to main |
| macOS ARM doctests | `ci.yml: build` (darwin-arm doc) | `cargo test --workspace --doc --profile ci` | Main | ci | macos-arm64 | Push to main |
| macOS platform-compat | `ci.yml: platform-compat` (darwin) | `cargo check --tests --target x86_64-apple-darwin` | Nightly | dev | macos-intel | Nightly 4 AM UTC |

## Windows

| Category | Old Command/Job | New Command/Job | Lane | Profile | Platform | Frequency |
|----------|----------------|-----------------|------|---------|----------|-----------|
| Windows build | `ci.yml: build` (windows) | `cargo build --target x86_64-pc-windows-msvc --release --features wireguard` | Main | release | windows | Push to main |
| Windows tests | `ci.yml: build` (windows test) | `cargo nextest run --target x86_64-pc-windows-msvc --cargo-profile ci --profile ci --no-fail-fast` | Main | ci | windows | Push to main |
| Windows doctests | `ci.yml: build` (windows doc) | `cargo test --workspace --doc --profile ci` | Main | ci | windows | Push to main |
| Windows platform-compat | `ci.yml: platform-compat` (windows) | `cargo check --tests --target x86_64-pc-windows-msvc` | Nightly | dev | windows | Nightly 4 AM UTC |

## Release Artifacts

| Category | Old Command/Job | New Command/Job | Lane | Profile | Platform | Frequency |
|----------|----------------|-----------------|------|---------|----------|-----------|
| Linux glibc build (full optional) | `ci.yml: build` (linux-gnu-full) | `cross build --target x86_64-unknown-linux-gnu --release --features wireguard,icmp-filter` | Main | release | linux | Push to main |
| Linux glibc tests | `ci.yml: build` (linux-gnu test) | `cargo nextest run --target x86_64-unknown-linux-gnu --cargo-profile ci --profile ci --no-fail-fast` | Main | ci | linux | Push to main |
| Linux glibc doctests | `ci.yml: build` (linux-gnu doc) | `cargo test --workspace --doc --profile ci` | Main | ci | linux | Push to main |
| Linux glibc build (no icmp) | `ci.yml: build` (linux-gnu-no-icmp) | `cross build --target x86_64-unknown-linux-gnu --release --features wireguard` | Main | release | linux | Push to main |
| Linux musl cross-compile | `ci.yml: build` (musl) | `cross build --target x86_64-unknown-linux-musl --release --features wireguard` | Main | release | linux-musl | Push to main |
| ARM64 Linux cross-compile | `ci.yml: build` (arm64) | `cross build --target aarch64-unknown-linux-gnu --release --features wireguard` | Main | release | linux | Push to main |
| FreeBSD cross-compile | `ci.yml: build` (freebsd) | `cross build --target x86_64-unknown-freebsd --release --features wireguard` | Main | release | freebsd | Push to main |
| Release packaging smoke | `ci.yml: release` (packaging) | `cargo build --release` | Release | release | linux | Version tags / dispatch |

## Performance and Stress

| Category | Old Command/Job | New Command/Job | Lane | Profile | Platform | Frequency |
|----------|----------------|-----------------|------|---------|----------|-----------|
| Performance baseline comparison | `ci.yml: release` (perf) | Release qualification full test suite comparison | Release | ci | linux | Version tags / dispatch |
| Stress/endurance tests | Not in CI | Deferred — not yet in CI pipeline | — | — | — | Not scheduled |

---

## Cross-Reference: Lane Coverage Summary

| Category | PR | Main | Nightly | Release |
|----------|:--:|:----:|:-------:|:-------:|
| Formatting | ✓ | ✓ (DNS) | — | — |
| Clippy (default) | ✓ | ✓ (DNS, plugin) | — | — |
| Clippy (all features) | — | — | — | ✓ |
| Default compile | — | ✓ | — | — |
| No-default core compile | ✓ | ✓ | ✓ | — |
| All-features compile | ✓ (upload, honeypot) | ✓ (DNS) | — | ✓ (workspace) |
| Unit tests (root) | — | — | — | ✓ |
| DNS tests | ✓ (affected) | ✓ (full) | — | ✓ (dup) |
| Plugin runtime tests | — | ✓ | — | ✓ (dup) |
| Mesh tests | ✓ (affected) | — | — | ✓ (dup) |
| Upload tests | ✓ (affected) | — | — | ✓ (dup) |
| Honeypot tests | ✓ (affected) | — | — | ✓ (dup) |
| Tarpit tests | ✓ (affected) | — | — | ✓ (dup) |
| Architecture guards | ✓ | ✓ (partial) | — | ✓ (dup) |
| Security regressions | ✓ | — | — | ✓ (dup) |
| Docs build | — | ✓ | — | ✓ (dup) |
| Security audit | — | ✓ | — | ✓ (dup) |
| Dependency audit | — | ✓ | ✓ (outdated) | ✓ (dup) |
| Miri | — | — | ✓ | — |
| Fuzz smoke | — | — | ✓ | — |
| Alpine/musl | — | ✓ (cross) | ✓ (build+test) | ✓ (cross) |
| FreeBSD | — | ✓ (cross) | ✓ (build+test) | ✓ (cross) |
| macOS | — | ✓ (build+test) | ✓ (compat) | ✓ (build+test) |
| Windows | — | ✓ (build+test) | ✓ (compat) | ✓ (build+test) |
| Performance/stress | — | — | — | ✓ (baseline) |

## Verification Status (2026-07-15)

Local verification was performed on commit `3673e516`. Each assurance category was verified through one or more of:

- Direct command execution (fmt, clippy, guards, selector, tests)
- Structural inspection (workflow files, lanes.toml, xtask code)
- Guard enforcement (ci_lane_consistency_guard, root_test_ownership_guard)

| Category | Local Verification | Hosted Runner | Notes |
|----------|-------------------|---------------|-------|
| Formatting & Lint | PASS | Pending | `cargo fmt --all -- --check` clean |
| Compile Profiles (core, mesh, dns, full) | Structural | Pending | All 5 profiles compile |
| Unit Tests | Structural | Pending | `cargo test --lib --no-run` clean |
| Domain Integration (DNS) | Structural | Pending | 1101 tests documented |
| Domain Integration (Plugin) | Structural | Pending | 389 tests documented |
| Domain Integration (Upload/Honeypot/Tarpit/Mesh) | Structural | Pending | Per-crate CI jobs defined |
| Architecture Guards | PASS | Pending | 63 repo-guards + 15 root guards pass |
| Security Regressions | Structural | Pending | nextest with --test-threads=1 |
| Platform Coverage | Structural | Pending | 8-target matrix in main-comprehensive |
| Fuzz Smoke | Structural | Pending | 17 targets, 1000 runs each |
| Failure Injection | Structural | Pending | 13 scenarios documented, execution pending |
| Cross-platform Compile | Structural | Pending | Alpine, FreeBSD, macOS, Windows in nightly |
| Dependency Audit | Structural | Pending | cargo audit + cargo deny |
