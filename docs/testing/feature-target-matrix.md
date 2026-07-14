# CI Feature / Target / Command Matrix

> Generated: 2026-07-14 | Source: `.github/workflows/{pr-fast,main-comprehensive,nightly-qualification,release-qualification}.yml`

This document enumerates every feature combination, target triple, and cargo command used across all four CI lanes, analyses overlap, and recommends consolidation.

---

## 1. Root Feature Definitions

From `Cargo.toml`:

| Feature | Default | Category |
|---------|---------|----------|
| `socket-handoff` | Yes | Core |
| `mesh` | Yes | Core |
| `dns` | Yes | Core |
| `erased_pool` | Yes | Core |
| `swagger-ui` | Yes | Core |
| `wireguard` | No | Optional |
| `icmp-filter` | No | Optional (Supported) |
| `icmp-ebpf` | No | Beta (eBPF, Linux-only) |
| `flood-ebpf` | No | Beta (eBPF, Linux-only) |
| `origin_key_exchange` | No | Optional |
| `audit` | No | Optional |
| `post-quantum` | No | Beta |
| `verify-pq` | No | Beta |
| `tun-rs` | No | Optional |
| `buffer` | No | Optional |
| `rkyv` | No | Optional |
| `macos-sandbox` | No | Optional |
| `test-utils` | No | Optional |
| `fastcgi_streaming` | No | Optional |

---

## 2. Complete Matrix: Every CI Entry

### PR Fast Lane (`pr-fast.yml`)

| # | Job | Command | Target | Features | Profile | Tests? | Assurance Property |
|---|-----|---------|--------|----------|---------|--------|-------------------|
| P1 | fmt | `cargo fmt --all -- --check` | native | — | — | N/A | Formatting conformance |
| P2 | clippy | `cargo clippy --all-targets -- -D warnings` | native | default | dev | N/A | Lint correctness |
| P3 | unsafe-dns | `grep -r "unsafe {" crates/synvoid-dns/src/` | native | — | — | N/A | No unsafe in DNS source |
| P4 | core-profile | `cargo check --no-default-features` | native | none | dev | Compile-only | Core-only compiles |
| P5 | import-check | `python scripts/check_imports.py` | native | — | — | N/A | Forbidden import boundary |
| P6 | security-regression | `cargo nextest run --test security_regression --cargo-profile ci --profile ci -- --test-threads=1` | native | default | ci | Tests | Security regression detection |
| P7 | guard-suite | `cargo nextest run -p synvoid-repo-guards --cargo-profile ci --profile ci` | native | — | ci | Tests | Architecture static guards |
| P8 | guard-suite | `cargo test --test boundary_composition_guard` | native | default | dev | Tests | Request-path vs composition boundary |
| P9 | guard-suite | `cargo test --test lifecycle_task_guard` | native | default | dev | Tests | Background task ownership |
| P10 | guard-suite | `cargo test --test plugin_guard` | native | default | dev | Tests | Plugin capability boundary |
| P11 | guard-suite | `cargo test --test cli_admin_guard` | native | default | dev | Tests | CLI dispatch boundary |
| P12 | guard-suite | `cargo test --test security_guard` | native | default | dev | Tests | Threat-intel boundary |
| P13 | guard-suite | `cargo test --test root_facade_boundary_guard` | native | default | dev | Tests | Domain crates can't import root |
| P14 | guard-suite | `cargo test --test mesh_id_boundary_guard` | native | default | dev | Tests | Mesh-ID admin-only boundary |
| P15 | guard-suite | `cargo test --test admin_mutation_response_guard` | native | default | dev | Tests | Mutation response typing |
| P16 | guard-suite | `cargo test --test admin_mutation_blocklist` | native | default | dev | Tests | Blocklist mutation behavior |
| P17 | guard-suite | `cargo test --test admin_auth_boundary` | native | default | dev | Tests | Auth authority boundary |
| P18 | guard-suite | `cargo test --test mesh_admin_edge_cases` | native | default | dev | Tests | Mesh admin edge cases |
| P19 | guard-suite | `cargo test --test failure_injection` | native | default | dev | Tests | Failure-injection resilience |
| P20 | guard-suite | `cargo test --test worker_mesh_supervision_boundary_guard --features mesh,dns` | native | mesh,dns | dev | Tests | Mesh supervision boundary |
| P21 | guard-suite | `cargo test --test mesh_task_ownership_guard --features mesh,dns` | native | mesh,dns | dev | Tests | Mesh task ownership |
| P22 | guard-suite | `cargo test --test abi_memory_boundary_guard` | native | default | dev | Tests | ABI memory boundary hardening |
| P23 | upload-tests | `cargo fmt -p synvoid-upload -- --check` | native | — | — | N/A | Upload crate formatting |
| P24 | upload-tests | `cargo clippy -p synvoid-upload --all-targets -- -D warnings` | native | default | dev | N/A | Upload crate lint |
| P25 | upload-tests | `cargo nextest run -p synvoid-upload --cargo-profile ci --profile ci` | native | default | ci | Tests | Upload crate unit tests |
| P26 | upload-tests | `cargo nextest run -p synvoid-upload --features mesh --cargo-profile ci --profile ci` | native | mesh | ci | Tests | Upload crate mesh-feature tests |
| P27 | upload-tests | `cargo check -p synvoid-upload --all-features` | native | all | dev | Compile-only | Upload all-features compiles |
| P28 | honeypot-tests | `cargo fmt -p synvoid-honeypot -- --check` | native | — | — | N/A | Honeypot crate formatting |
| P29 | honeypot-tests | `cargo clippy -p synvoid-honeypot --all-targets -- -D warnings` | native | default | dev | N/A | Honeypot crate lint |
| P30 | honeypot-tests | `cargo nextest run -p synvoid-honeypot --cargo-profile ci --profile ci` | native | default | ci | Tests | Honeypot unit tests |
| P31 | honeypot-tests | `cargo check -p synvoid-honeypot --all-features` | native | all | dev | Compile-only | Honeypot all-features compiles |
| P32 | tarpit-tests | `cargo clippy -p synvoid-tarpit --all-targets -- -D warnings` | native | default | dev | N/A | Tarpit crate lint |
| P33 | tarpit-tests | `cargo nextest run -p synvoid-tarpit --all-targets --cargo-profile ci --profile ci` | native | default | ci | Tests | Tarpit unit tests |
| P34 | mesh-tests | `cargo check -p synvoid-mesh --features mesh --all-targets` | native | mesh | dev | Compile-only | Mesh crate compiles |
| P35 | mesh-tests | `cargo clippy -p synvoid-mesh --features mesh --all-targets -- -D warnings` | native | mesh | dev | N/A | Mesh crate lint |
| P36 | mesh-tests | `cargo nextest run -p synvoid-mesh --features mesh --all-targets --cargo-profile ci --profile ci` | native | mesh | ci | Tests | Mesh crate tests |

### Main Comprehensive Lane (`main-comprehensive.yml`)

| # | Job | Command | Target | Features | Profile | Tests? | Assurance Property |
|---|-----|---------|--------|----------|---------|--------|-------------------|
| M1 | build | `cross build --target x86_64-unknown-linux-gnu --release --features wireguard,icmp-filter` | x86_64-linux-gnu | wireguard,icmp-filter | release | Compile-only | Linux glibc + full optional |
| M2 | build | `cargo nextest run --target x86_64-unknown-linux-gnu --cargo-profile ci --profile ci --no-fail-fast` | x86_64-linux-gnu | wireguard,icmp-filter | ci | Tests | Linux glibc test suite |
| M3 | build | `cargo test --workspace --doc --profile ci` | x86_64-linux-gnu | wireguard,icmp-filter | ci | Doctests | Linux glibc doctests |
| M4 | build | `cross build --target x86_64-unknown-linux-gnu --release --features wireguard` | x86_64-linux-gnu | wireguard | release | Compile-only | Linux glibc compile (no icmp) |
| M5 | build | `cross build --target x86_64-unknown-linux-musl --release --features wireguard` | x86_64-linux-musl | wireguard | release | Compile-only | Linux musl cross-compile |
| M6 | build | `cross build --target aarch64-unknown-linux-gnu --release --features wireguard` | aarch64-linux-gnu | wireguard | release | Compile-only | ARM64 Linux cross-compile |
| M7 | build | `cargo build --target x86_64-apple-darwin --release --features wireguard` | x86_64-apple-darwin | wireguard | release | Compile-only | macOS Intel build |
| M8 | build | `cargo nextest run --target x86_64-apple-darwin --cargo-profile ci --profile ci --no-fail-fast` | x86_64-apple-darwin | wireguard | ci | Tests | macOS Intel tests |
| M9 | build | `cargo test --workspace --doc --profile ci` | x86_64-apple-darwin | wireguard | ci | Doctests | macOS Intel doctests |
| M10 | build | `cargo build --target aarch64-apple-darwin --release --features wireguard` | aarch64-apple-darwin | wireguard | release | Compile-only | macOS ARM build |
| M11 | build | `cargo nextest run --target aarch64-apple-darwin --cargo-profile ci --profile ci --no-fail-fast` | aarch64-apple-darwin | wireguard | ci | Tests | macOS ARM tests |
| M12 | build | `cargo test --workspace --doc --profile ci` | aarch64-apple-darwin | wireguard | ci | Doctests | macOS ARM doctests |
| M13 | build | `cargo build --target x86_64-pc-windows-msvc --release --features wireguard` | x86_64-pc-windows-msvc | wireguard | release | Compile-only | Windows build |
| M14 | build | `cargo nextest run --target x86_64-pc-windows-msvc --cargo-profile ci --profile ci --no-fail-fast` | x86_64-pc-windows-msvc | wireguard | ci | Tests | Windows tests |
| M15 | build | `cargo test --workspace --doc --profile ci` | x86_64-pc-windows-msvc | wireguard | ci | Doctests | Windows doctests |
| M16 | build | `cross build --target x86_64-unknown-freebsd --release --features wireguard` | x86_64-freebsd | wireguard | release | Compile-only | FreeBSD cross-compile |
| M17 | dns-tests | `cargo fmt -p synvoid-dns -- --check` | native | — | — | N/A | DNS crate formatting |
| M18 | dns-tests | `cargo clippy -p synvoid-dns --all-targets -- -D warnings` | native | default | dev | N/A | DNS crate lint |
| M19 | dns-tests | `cargo nextest run -p synvoid-dns --cargo-profile ci --profile ci` | native | default | ci | Tests | DNS full test suite |
| M20 | dns-tests | `cargo test -p synvoid-dns --doc --profile ci` | native | default | ci | Doctests | DNS doctests |
| M21 | dns-tests | `cargo check -p synvoid-dns --all-features` | native | all | dev | Compile-only | DNS all-features compiles |
| M22 | plugin-runtime-guardrails | `cargo fmt --all -- --check` | native | — | — | N/A | Full workspace formatting |
| M23 | plugin-runtime-guardrails | `cargo clippy -p synvoid-plugin-runtime --all-targets -- -D warnings` | native | default | dev | N/A | Plugin runtime lint |
| M24 | plugin-runtime-guardrails | `cargo nextest run -p synvoid-plugin-runtime --cargo-profile ci --profile ci` | native | default | ci | Tests | Plugin runtime unit tests |
| M25 | plugin-runtime-guardrails | `cargo nextest run -p synvoid-repo-guards --cargo-profile ci --profile ci` | native | — | ci | Tests | Static guards (dup of P7) |
| M26 | plugin-runtime-guardrails | `cargo test --test plugin_guard` | native | default | dev | Tests | Plugin guard (dup of P10) |
| M27 | plugin-runtime-guardrails | `cargo test --test boundary_composition_guard` | native | default | dev | Tests | Composition guard (dup of P8) |
| M28 | plugin-runtime-guardrails | `cargo test --test abi_memory_boundary_guard` | native | default | dev | Tests | ABI guard (dup of P22) |
| M29 | plugin-runtime-guardrails | `cargo test -p synvoid-plugin-runtime --test manifest_authority_wiring` | native | default | ci | Tests | Manifest authority wiring |
| M30 | plugin-runtime-guardrails | `cargo test -p synvoid-plugin-runtime --test plugin_failure_does_not_poison_manager` | native | default | ci | Tests | Plugin failure isolation |
| M31 | profile-matrix | `cargo check` | native | default | dev | Compile-only | Default profile compiles |
| M32 | profile-matrix | `cargo check --no-default-features` | native | none | dev | Compile-only | Core profile compiles |
| M33 | profile-matrix | `cargo check --no-default-features --features mesh` | native | mesh | dev | Compile-only | Mesh profile compiles |
| M34 | profile-matrix | `cargo check --no-default-features --features dns` | native | dns | dev | Compile-only | DNS profile compiles |
| M35 | profile-matrix | `cargo check --no-default-features --features mesh,dns` | native | mesh,dns | dev | Compile-only | Full profile compiles |
| M36 | docs | `cargo doc --no-deps --release` | native | default | release | N/A | Documentation builds clean |
| M37 | security-audit | `cargo audit` | native | — | — | N/A | Advisory check |
| M38 | dependency-audit | `cargo deny check` | native | — | — | N/A | License/ban/sources check |

### Nightly Qualification Lane (`nightly-qualification.yml`)

| # | Job | Command | Target | Features | Profile | Tests? | Assurance Property |
|---|-----|---------|--------|----------|---------|--------|-------------------|
| N1 | alpine-test | `cargo build --release` | x86_64-linux-musl | default | release | Compile-only | Alpine/musl build |
| N2 | alpine-test | `cargo test --release -- --test-threads=1` | x86_64-linux-musl | default | release | Tests | Alpine/musl test (serial) |
| N3 | freebsd-test | `cargo build --release` | x86_64-freebsd | default | release | Compile-only | FreeBSD build |
| N4 | freebsd-test | `cargo test --release -- --test-threads=1` | x86_64-freebsd | default | release | Tests | FreeBSD test (serial) |
| N5 | platform-compat | `cargo check --target x86_64-unknown-linux-gnu` | x86_64-linux-gnu | default | dev | Compile-only | Linux glibc compat |
| N6 | platform-compat | `cargo check --target x86_64-unknown-linux-musl` | x86_64-linux-musl | default | dev | Compile-only | Linux musl compat |
| N7 | platform-compat | `cargo check --target x86_64-apple-darwin` | x86_64-apple-darwin | default | dev | Compile-only | macOS Intel compat |
| N8 | platform-compat | `cargo check --target x86_64-pc-windows-msvc` | x86_64-pc-windows-msvc | default | dev | Compile-only | Windows compat |
| N9 | platform-compat | `cargo check --target x86_64-unknown-freebsd` | x86_64-freebsd | default | dev | Compile-only | FreeBSD compat |
| N10 | miri-test | `cargo miri test -p synvoid-utils` | native | default | nightly | Tests | Memory safety (Miri) |
| N11 | fuzz-smoke | `cargo +nightly fuzz run <target> -- -runs=1000` (16 targets) | native | default | nightly | Tests | Fuzz correctness (16 targets) |
| N12 | outdated-deps | `cargo outdated --release --exit-code 2` | native | — | — | N/A | Dependency freshness |
| N13 | profile-matrix | `cargo check` | native | default | dev | Compile-only | Default (dup of M31) |
| N14 | profile-matrix | `cargo check --no-default-features` | native | none | dev | Compile-only | Core (dup of P4, M32) |
| N15 | profile-matrix | `cargo check --no-default-features --features mesh` | native | mesh | dev | Compile-only | Mesh (dup of M33) |
| N16 | profile-matrix | `cargo check --no-default-features --features dns` | native | dns | dev | Compile-only | DNS (dup of M34) |
| N17 | profile-matrix | `cargo check --no-default-features --features mesh,dns` | native | mesh,dns | dev | Compile-only | Full (dup of M35) |

### Release Qualification Lane (`release-qualification.yml`)

| # | Job | Command | Target | Features | Profile | Tests? | Assurance Property |
|---|-----|---------|--------|----------|---------|--------|-------------------|
| R1 | build | `cross build --target x86_64-unknown-linux-gnu --release --features wireguard,icmp-filter` | x86_64-linux-gnu | wireguard,icmp-filter | release | Compile-only | Release Linux glibc build (dup of M1) |
| R2 | build | `cargo nextest run --target x86_64-unknown-linux-gnu --cargo-profile ci --profile ci --no-fail-fast` | x86_64-linux-gnu | wireguard,icmp-filter | ci | Tests | Release Linux glibc tests (dup of M2) |
| R3 | build | `cargo test --workspace --doc --profile ci` | x86_64-linux-gnu | wireguard,icmp-filter | ci | Doctests | Release Linux doctests (dup of M3) |
| R4 | build | `cross build --target x86_64-unknown-linux-gnu --release --features wireguard` | x86_64-linux-gnu | wireguard | release | Compile-only | Release Linux no-icmp build (dup of M4) |
| R5 | build | `cross build --target x86_64-unknown-linux-musl --release --features wireguard` | x86_64-linux-musl | wireguard | release | Compile-only | Release musl build (dup of M5) |
| R6 | build | `cross build --target aarch64-unknown-linux-gnu --release --features wireguard` | aarch64-linux-gnu | wireguard | release | Compile-only | Release ARM64 build (dup of M6) |
| R7 | build | `cargo build --target x86_64-apple-darwin --release --features wireguard` | x86_64-apple-darwin | wireguard | release | Compile-only | Release macOS Intel build (dup of M7) |
| R8 | build | `cargo nextest run --target x86_64-apple-darwin --cargo-profile ci --profile ci --no-fail-fast` | x86_64-apple-darwin | wireguard | ci | Tests | Release macOS Intel tests (dup of M8) |
| R9 | build | `cargo test --workspace --doc --profile ci` | x86_64-apple-darwin | wireguard | ci | Doctests | Release macOS doctests (dup of M9) |
| R10 | build | `cargo build --target aarch64-apple-darwin --release --features wireguard` | aarch64-apple-darwin | wireguard | release | Compile-only | Release macOS ARM build (dup of M10) |
| R11 | build | `cargo nextest run --target aarch64-apple-darwin --cargo-profile ci --profile ci --no-fail-fast` | aarch64-apple-darwin | wireguard | ci | Tests | Release macOS ARM tests (dup of M11) |
| R12 | build | `cargo test --workspace --doc --profile ci` | aarch64-apple-darwin | wireguard | ci | Doctests | Release macOS ARM doctests (dup of M12) |
| R13 | build | `cargo build --target x86_64-pc-windows-msvc --release --features wireguard` | x86_64-pc-windows-msvc | wireguard | release | Compile-only | Release Windows build (dup of M13) |
| R14 | build | `cargo nextest run --target x86_64-pc-windows-msvc --cargo-profile ci --profile ci --no-fail-fast` | x86_64-pc-windows-msvc | wireguard | ci | Tests | Release Windows tests (dup of M14) |
| R15 | build | `cargo test --workspace --doc --profile ci` | x86_64-pc-windows-msvc | wireguard | ci | Doctests | Release Windows doctests (dup of M15) |
| R16 | build | `cross build --target x86_64-unknown-freebsd --release --features wireguard` | x86_64-freebsd | wireguard | release | Compile-only | Release FreeBSD build (dup of M16) |
| R17 | full-test-suite | `cargo nextest run --cargo-profile ci --profile ci --no-fail-fast` | native | default | ci | Tests | Full default test suite |
| R18 | full-test-suite | `cargo test --workspace --doc --profile ci` | native | default | ci | Doctests | Full default doctests |
| R19 | full-test-suite | `cargo nextest run --features mesh --cargo-profile ci --profile ci --no-fail-fast` | native | mesh | ci | Tests | Mesh test suite |
| R20 | full-test-suite | `cargo test --workspace --doc --features mesh --profile ci` | native | mesh | ci | Doctests | Mesh doctests |
| R21 | full-test-suite | `cargo nextest run -p synvoid-dns --cargo-profile ci --profile ci --no-fail-fast` | native | default | ci | Tests | DNS test suite (dup of M19) |
| R22 | full-test-suite | `cargo test -p synvoid-dns --doc --profile ci` | native | default | ci | Doctests | DNS doctests (dup of M20) |
| R23 | full-test-suite | `cargo nextest run -p synvoid-plugin-runtime --cargo-profile ci --profile ci --no-fail-fast` | native | default | ci | Tests | Plugin runtime tests (dup of M24) |
| R24 | full-test-suite | `cargo test -p synvoid-plugin-runtime --doc --profile ci` | native | default | ci | Doctests | Plugin runtime doctests |
| R25 | full-test-suite | `cargo nextest run -p synvoid-honeypot --cargo-profile ci --profile ci --no-fail-fast` | native | default | ci | Tests | Honeypot tests (dup of P30) |
| R26 | full-test-suite | `cargo test -p synvoid-honeypot --doc --profile ci` | native | default | ci | Doctests | Honeypot doctests |
| R27 | full-test-suite | `cargo nextest run -p synvoid-tarpit --cargo-profile ci --profile ci --no-fail-fast` | native | default | ci | Tests | Tarpit tests (dup of P33) |
| R28 | full-test-suite | `cargo test -p synvoid-tarpit --doc --profile ci` | native | default | ci | Doctests | Tarpit doctests |
| R29 | full-test-suite | `cargo nextest run -p synvoid-mesh --features mesh --cargo-profile ci --profile ci --no-fail-fast` | native | mesh | ci | Tests | Mesh crate tests (dup of P36) |
| R30 | full-test-suite | `cargo test -p synvoid-mesh --features mesh --doc --profile ci` | native | mesh | ci | Doctests | Mesh crate doctests |
| R31 | security-regression | `cargo nextest run --test security_regression --cargo-profile ci --profile ci -- --test-threads=1` | native | default | ci | Tests | Security regression (dup of P6) |
| R32 | guard-suite | `cargo nextest run -p synvoid-repo-guards --cargo-profile ci --profile ci` | native | — | ci | Tests | Static guards (dup of P7, M25) |
| R33 | guard-suite | `cargo test --test boundary_composition_guard` (15 root guards) | native | default | dev | Tests | Root guard tests (dup of P8-P22) |
| R34 | guard-suite | `cargo test -p synvoid-plugin-runtime --test manifest_authority_wiring` | native | default | ci | Tests | Manifest authority (dup of M29) |
| R35 | guard-suite | `cargo test -p synvoid-plugin-runtime --test plugin_failure_does_not_poison_manager` | native | default | ci | Tests | Failure isolation (dup of M30) |
| R36 | clippy | `cargo clippy --all-targets --all-features -- -D warnings` | native | all | dev | N/A | All-features lint |
| R37 | docs | `cargo doc --no-deps --release` | native | default | release | N/A | Documentation (dup of M36) |
| R38 | security-audit | `cargo audit` | native | — | — | N/A | Advisory check (dup of M37) |
| R39 | dependency-audit | `cargo deny check` | native | — | — | N/A | License check (dup of M38) |

---

## 3. Target Triple Summary

| Target Triple | PR Fast | Main Comprehensive | Nightly | Release |
|---------------|---------|-------------------|---------|---------|
| `native` (runner arch) | All jobs | Profile matrix, DNS, plugin, guard | Miri, fuzz | Full test suite, guards, lint |
| `x86_64-unknown-linux-gnu` | — | Build + Test + Doctests | platform-compat | Build + Test + Doctests |
| `x86_64-unknown-linux-musl` | — | Cross-compile only | platform-compat, alpine-test | Cross-compile only |
| `aarch64-unknown-linux-gnu` | — | Cross-compile only | platform-compat | Cross-compile only |
| `x86_64-apple-darwin` | — | Build + Test + Doctests | platform-compat | Build + Test + Doctests |
| `aarch64-apple-darwin` | — | Build + Test + Doctests | platform-compat | Build + Test + Doctests |
| `x86_64-pc-windows-msvc` | — | Build + Test + Doctests | platform-compat | Build + Test + Doctests |
| `x86_64-unknown-freebsd` | — | Cross-compile only | platform-compat, freebsd-test | Cross-compile only |

---

## 4. Feature Combination Summary

| Feature Set | PR Fast | Main Comprehensive | Nightly | Release |
|-------------|---------|-------------------|---------|---------|
| none (`--no-default-features`) | core-profile check | profile-matrix check | profile-matrix check | — |
| default | clippy, all guard tests, all crate tests | profile-matrix check, build matrix | profile-matrix check, platform-compat, alpine, freebsd | full-test-suite default |
| mesh only | mesh-tests crate | profile-matrix check, build matrix | profile-matrix check | full-test-suite mesh |
| dns only | — | profile-matrix check | profile-matrix check | — |
| mesh,dns | guard tests (worker_mesh, mesh_task) | profile-matrix check | profile-matrix check | — |
| wireguard | — | Build matrix (all targets) | — | Build matrix (all targets) |
| wireguard,icmp-filter | — | Linux glibc only | — | Linux glibc only |
| all features | upload/honeypot check | DNS check | — | clippy all-features |

---

## 5. Overlap Analysis

### Tier 1: Identical Duplicates (same command, same lane semantics)

| Entry Set | Commands | Verdict |
|-----------|----------|---------|
| P4 (core-profile) ↔ N14 (nightly no-default) ↔ M32 (main no-default) | `cargo check --no-default-features` | **3-way overlap.** P4 is the PR-gate version. M32/N14 are redundant with P4. |
| P7 (repo-guards nextest) ↔ M25 ↔ R32 | `cargo nextest run -p synvoid-repo-guards --cargo-profile ci --profile ci` | **3-way overlap.** Identical command in 3 lanes. |
| P8 (boundary_composition_guard) ↔ M27 ↔ R33 | `cargo test --test boundary_composition_guard` | **3-way overlap.** Guard runs in every lane. |
| P10 (plugin_guard) ↔ M26 ↔ R33 | `cargo test --test plugin_guard` | **3-way overlap.** |
| P22 (abi_memory_boundary_guard) ↔ M28 ↔ R33 | `cargo test --test abi_memory_boundary_guard` | **3-way overlap.** |
| M31 ↔ N13 | `cargo check` (default) | **2-way overlap.** Main and nightly both run default profile check. |
| M33 ↔ N15 | `cargo check --no-default-features --features mesh` | **2-way overlap.** |
| M34 ↔ N16 | `cargo check --no-default-features --features dns` | **2-way overlap.** |
| M35 ↔ N17 | `cargo check --no-default-features --features mesh,dns` | **2-way overlap.** |
| P6 ↔ R31 | security regression tests | **2-way overlap.** Identical command. |
| M19 ↔ R21 | `cargo nextest run -p synvoid-dns --cargo-profile ci --profile ci` | **2-way overlap.** |
| M20 ↔ R22 | `cargo test -p synvoid-dns --doc --profile ci` | **2-way overlap.** |
| M24 ↔ R23 | `cargo nextest run -p synvoid-plugin-runtime --cargo-profile ci --profile ci` | **2-way overlap.** |
| M36 ↔ R37 | `cargo doc --no-deps --release` | **2-way overlap.** |
| M37 ↔ R38 | `cargo audit` | **2-way overlap.** |
| M38 ↔ R39 | `cargo deny check` | **2-way overlap.** |
| P30 ↔ R25 | `cargo nextest run -p synvoid-honeypot --cargo-profile ci --profile ci` | **2-way overlap.** |
| P33 ↔ R27 | `cargo nextest run -p synvoid-tarpit --cargo-profile ci --profile ci` | **2-way overlap.** |
| P36 ↔ R29 | `cargo nextest run -p synvoid-mesh --features mesh --cargo-profile ci --profile ci` | **2-way overlap.** |

### Tier 2: Same Property, Different Profile (intentional overlap)

| Entry Set | Property Proven | Verdict |
|-----------|-----------------|---------|
| M1 (release build) ↔ N1 (alpine release build) | Compiles on Linux glibc/musl with wireguard,icmp-filter | **Intentional.** Different environments (ubuntu vs alpine container). |
| M1-M16 (build matrix, release) ↔ R1-R16 (build matrix, release) | Cross-platform release compilation | **Intentional for release lane.** Main comprehensive and release qualification are intentionally separate triggers. |
| M2-M3 (test on linux glibc, ci profile) ↔ R2-R3 | Test suite on linux glibc | **Intentional.** Different trigger points (post-merge vs release tag). |

### Tier 3: Partial Overlap (overlapping but not identical)

| Entry Set | Overlap | Gap |
|-----------|---------|-----|
| P2 (clippy default) ↔ R36 (clippy all-features) | Lint correctness | Different feature sets: default vs all-features |
| P4 (core-profile) ↔ M4 (linux glibc no-icmp) | No-default-features compilation | P4 is check only; M4 is release build + tests |
| P25 (upload default) ↔ P26 (upload mesh) | Upload crate correctness | Different features: default vs mesh |
| M8/M11/M14 (platform tests) ↔ N5-N9 (platform compat) | Cross-platform compilation | M* tests on native, N* check compilation only |

---

## 6. Redundancy Removal Recommendations

### High-Value Removals (reduce CI cost without losing coverage)

| Recommendation | Estimated Savings | Risk |
|----------------|-------------------|------|
| **Remove profile-matrix from nightly-qualification** (N13-N17). The 5 `cargo check` variants are identical to M31-M35 in main-comprehensive. Nightly already runs platform-compat which covers the same property. | 5 invocations per nightly run | Low. Property is already proven by main-comprehensive. |
| **Remove DNS crate tests from release-qualification** (R21-R22). The blanket `cargo nextest run -p synvoid-dns` in R21 is identical to M19 in main-comprehensive. DNS crate has no platform-specific code. | 2 invocations per release | Low. DNS crate is platform-agnostic; main-comprehensive already proves correctness. |
| **Remove plugin-runtime tests from release-qualification** (R23-R24). Identical to M24 in main-comprehensive. Plugin runtime has no platform-specific code. | 2 invocations per release | Low. Same rationale as DNS. |
| **Remove honeypot/tarpit/mesh crate tests from release-qualification** (R25-R30). Identical to P30/P33/P36 in PR fast lane. These crates are platform-agnostic. | 6 invocations per release | Low. Already proven in PR fast lane on every PR. |
| **Remove guard-suite from release-qualification** (R32-R35). Identical to P7-P22 and M25-M30. Already proven on every PR and every push to main. | 4 invocations per release | Low. Architecture invariants are invariant across profiles. |
| **Remove security-regression from release-qualification** (R31). Identical to P6. Already proven on every PR. | 1 invocation per release | Low. Security regressions are caught before merge. |
| **Remove docs/security-audit/dependency-audit from release-qualification** (R37-R39). Identical to M36-M38 in main-comprehensive. | 3 invocations per release | Low. Already proven post-merge. |

**Total recommended removals from release-qualification:** 23 invocations. Release lane would retain: build matrix (R1-R16), full-test-suite default+mesh (R17-R20), and clippy all-features (R36) — the only unique entries.

### Medium-Value Removals

| Recommendation | Estimated Savings | Risk |
|----------------|-------------------|------|
| **Remove plugin guard duplicates from main-comprehensive plugin-runtime-guardrails** (M25-M28, M33-M35). These 6 entries (repo-guards nextest, plugin_guard, boundary_composition_guard, abi_memory_boundary_guard + 3 profile checks) duplicate PR fast lane. | 6 invocations per main-comprehensive run | Low-Medium. PR fast lane already proves these on every merge candidate. Main-comprehensive adds no new property. |

### Not Recommended (Intentional Overlap)

| Entry Set | Rationale |
|-----------|-----------|
| PR fast lane guards (P8-P22) | Required for merge; must run on every PR |
| Main comprehensive build matrix (M1-M16) | Different trigger (post-merge); proves compilation on real targets |
| Nightly platform-compat (N5-N9) | Different environment; catches portability issues PR lane misses |
| Nightly alpine/freebsd (N1-N4) | Expensive; intentionally deferred from PR lane |

---

## 7. Canonical Matrix Per Lane

### PR Fast Lane (target: <10 min)

```
Format:    cargo fmt --all -- --check
Lint:      cargo clippy --all-targets -- -D warnings
Safety:    grep for unsafe in DNS source
Profiles:  cargo check --no-default-features
Imports:   python scripts/check_imports.py
Security:  cargo nextest run --test security_regression --test-threads=1
Guards:    cargo nextest run -p synvoid-repo-guards
           + 15 standalone cargo test --test <guard> invocations
Crate:     synvoid-upload (fmt, clippy, nextest, mesh-feature nextest, all-features check)
           synvoid-honeypot (fmt, clippy, nextest, all-features check)
           synvoid-tarpit (clippy, nextest)
           synvoid-mesh (check, clippy, nextest --features mesh)
```

### Main Comprehensive Lane (target: <30 min)

```
Build:     8-target matrix (x86_64-linux-gnu ×2, musl, aarch64-linux, x86_64-darwin,
           aarch64-darwin, windows, freebsd) — release profile, wireguard (+icmp-filter on linux glibc)
DNS:       fmt, clippy, nextest blanket, doctests, all-features check
Plugin:    fmt, clippy, nextest, repo-guards, 5 standalone guard tests
Profiles:  5 cargo check variants (default, core, mesh, dns, mesh+dns)
Docs:      cargo doc --no-deps --release
Audit:     cargo audit + cargo deny check
```

### Nightly Qualification Lane (target: <60 min)

```
Alpine:    cargo build --release + cargo test --release --test-threads=1 (musl container)
FreeBSD:   cargo build --release + cargo test --release --test-threads=1 (VM)
Compat:    cargo check × 5 targets (linux-gnu, musl, darwin, windows, freebsd)
Miri:      cargo miri test -p synvoid-utils (continue-on-error)
Fuzz:      cargo +nightly fuzz run × 16 targets (--runs=1000)
Deps:      cargo outdated --release (continue-on-error)
```

### Release Qualification Lane (target: <60 min)

```
Build:     8-target matrix (identical to main comprehensive)
Tests:     Full default test suite + mesh test suite (native)
Clippy:    cargo clippy --all-targets --all-features -- -D warnings
(DNS, plugin, honeypot, tarpit, mesh crate tests, guards, security-regression,
 docs, audit — all deferred from main-comprehensive; NOT unique to release)
```

---

## 8. Summary Statistics

| Metric | PR Fast | Main Comp. | Nightly | Release |
|--------|---------|------------|---------|---------|
| Total cargo invocations | ~45 | ~38 | ~12 | ~35 |
| Unique properties proven | 8 | 7 | 6 | 2 (build + all-features lint) |
| Duplicate invocations (cross-lane) | 0 | 6 (guards) | 5 (profile matrix) | 23 (nearly all test/guard/audit) |
| Targets tested | 1 (native) | 8 | 5 (compat) + 2 (alpine/freebsd) | 8 |
| Feature combos tested | 4 (none, default, mesh, mesh+dns) | 6 (none, default, mesh, dns, mesh+dns, all) | 6 (same as main) | 3 (default, wireguard, all) |

**Key insight:** Release qualification is the most redundant lane. Its build matrix (R1-R16) is identical to main comprehensive. Its test/guard/audit entries (R17-R39) are all duplicates of entries already proven in PR fast or main comprehensive lanes. The only unique value is the `clippy --all-features` lint (R36), which could be moved to main comprehensive.
