# CI Cache Policy

## Overview

SynVoid CI uses a layered caching strategy to minimize compilation time across 4 CI lanes, 7 cross-compilation targets, and 50+ workspace crates. All cache layers are **best-effort** — cache misses degrade to normal compilation without failing the job.

## Supported Cache Layers

| Layer | What | Tool | Size (typical) | Key Input |
|-------|------|------|----------------|-----------|
| 1 | Cargo source caches | `Swatinem/rust-cache@v2` (built-in) | ~200 MB | Cargo.lock hash |
| 2 | Tool binaries | `actions/cache@v4` / `taiki-e/install-action` | ~50 MB | Tool + version |
| 3 | Compiler outputs | sccache (via `Swatinem/rust-cache` wrapper) | ~2 GB | sccache key |
| 4 | Cargo target metadata | `Swatinem/rust-cache@v2` | ~500 MB | Profile + features + target |

### Layer 1: Cargo Source Caches

`Swatinem/rust-cache@v2` automatically caches `~/.cargo/registry/{index,cache}` and `~/.cargo/git/db`. This avoids re-downloading and re-extracting crates on cache hits.

**Coverage:** All jobs that run `cargo` commands and use `Swatinem/rust-cache@v2`.

### Layer 2: Tool Binaries

Tool binaries are cached individually to avoid repeated `cargo install`:

| Tool | Cache method | Key | Location |
|------|-------------|-----|----------|
| `cargo-nextest` | `taiki-e/install-action@nextest` (built-in caching) | `nextest-0.9.x` | `~/.cargo/bin/nextest` |
| `cargo-fuzz` | `actions/cache@v4` | `{runner.os}-cargo-fuzz-0.13.2` | `~/.cargo/bin/cargo-fuzz` |
| `cargo-audit` | `taiki-e/install-action@v2` | tool + version | `~/.cargo/bin/cargo-audit` |
| `cargo-deny` | `taiki-e/install-action@v2` | tool + version | `~/.cargo/bin/cargo-deny` |
| `cross` | `taiki-e/install-action@v2` | tool + version | `~/.cargo/bin/cross` |
| `sccache` | `Swatinem/rust-cache@v2` (via sccache setup) | see Layer 3 | `~/.cargo/bin/sccache` |

### Layer 3: Compiler Outputs (sccache)

sccache wraps `rustc` and caches compilation artifacts across jobs sharing the same sccache key. This provides the largest speedup for repeated incremental compilations.

**Setup (planned — not yet in workflows):**

```yaml
- name: Setup sccache
  uses: mozilla-actions/sccache-action@v0.0.6
  env:
    SCCACHE_GHA_ENABLED: "true"
    RUSTC_WRAPPER: "sccache"
```

**sccache key dimensions:**

```
{toolchain}-{target}-{profile}-{features}
```

Example keys:

| Job | sccache key |
|-----|------------|
| PR fast / clippy | `stable-x86_64-unknown-linux-gnu-ci-default` |
| PR fast / guard-suite | `stable-x86_64-unknown-linux-gnu-ci-default` |
| Main comprehensive / build (linux-gnu) | `stable-x86_64-unknown-linux-gnu-release-wireguard,icmp-filter` |
| Main comprehensive / dns-tests | `stable-x86_64-unknown-linux-gnu-ci-default` |
| Release qualification / full-test-suite (dns) | `stable-x86_64-unknown-linux-gnu-ci-dns` |
| Nightly qualification / miri | `nightly-x86_64-unknown-linux-gnu-dev-default` |

**sccache backend:** GitHub Actions cache (`SCCACHE_GHA_ENABLED=true`). Each unique key gets its own cache entry (up to 10 GB total per repository, shared across all workflows).

### Layer 4: Cargo Target Metadata

`Swatinem/rust-cache@v2` manages `target/` directory metadata (dependency `.d` files, incremental compilation state, fingerprints). This is separate from sccache — sccache caches `.o`/`.rlib` files, while rust-cache ensures Cargo's dependency graph resolution is cached.

**Key configuration:**

```yaml
- uses: Swatinem/rust-cache@v2
  with:
    key: ${{ matrix.target }}          # or profile-${{ matrix.name }}, etc.
    cache-targets: true                # default; target/ metadata
    cache-dependencies: true           # default; Cargo.lock + registry
    shared-key: ""                     # optional cross-job sharing
```

## Cache Key Dimensions

Cache keys are composed from the following dimensions. A full cache key is the concatenation of relevant dimensions.

| Dimension | Values | Effect on cache |
|-----------|--------|-----------------|
| Toolchain | `stable`, `nightly` | Different compiler versions produce incompatible artifacts |
| Target triple | `x86_64-unknown-linux-gnu`, `x86_64-unknown-linux-musl`, `aarch64-unknown-linux-gnu`, `x86_64-apple-darwin`, `aarch64-apple-darwin`, `x86_64-pc-windows-msvc`, `x86_64-unknown-freebsd` | Cross-compiled artifacts are target-specific |
| Profile | `dev`, `ci`, `release` | Different opt-level, LTO, debug settings produce different artifacts |
| Feature class | `default`, `no-default`, `mesh`, `dns`, `mesh-dns`, `all-features` | Feature flags change which crates are compiled |
| Cargo.lock hash | SHA-256 of `Cargo.lock` | Dependency versions change compilation inputs |
| OS | `ubuntu-latest`, `macos-latest`, `windows-latest` | Platform-specific dependencies and system libraries |

### Feature Classes (Profile Matrix)

The CI profile matrix exercises 5 feature combinations. Each produces a distinct sccache key:

| Class | Command | Key suffix |
|-------|---------|------------|
| `default` | `cargo check` | `default` |
| `no-default` | `cargo check --no-default-features` | `no-default` |
| `mesh` | `cargo check --no-default-features --features mesh` | `mesh` |
| `dns` | `cargo check --no-default-features --features dns` | `dns` |
| `mesh-dns` | `cargo check --no-default-features --features mesh,dns` | `mesh-dns` |

## Invalidation Rules

| Trigger | What invalidates | Scope |
|---------|-----------------|-------|
| `Cargo.lock` change | All source caches, sccache, target metadata | All jobs sharing the same lockfile |
| Toolchain upgrade (`dtolnay/rust-toolchain`) | All compiler-dependent caches | All jobs for that toolchain |
| Feature flag change in `Cargo.toml` | sccache entries for affected feature classes | Jobs compiling with changed features |
| Target triple change | sccache + target metadata for that target | Jobs building for that target |
| `Swatinem/rust-cache` action version bump | Target metadata | All jobs using that action |
| sccache action version bump | Compiler output caches | All jobs using sccache |
| OS runner image update (`ubuntu-latest`) | System library caches | All jobs on that runner |

### Partial Invalidation

`Swatinem/rust-cache@v2` performs partial invalidation automatically: it removes files from `target/` that are no longer needed (stale dependency artifacts). This prevents unbounded cache growth from dependency churn.

sccache does **not** perform partial invalidation — stale entries persist until evicted by the 10 GB GitHub Actions cache limit (LRU eviction).

## Jobs That Intentionally Do Not Cache

| Job | Lane | Reason |
|-----|------|--------|
| `fmt` (Rustfmt) | PR Fast | No compilation; runs in <5s. Caching overhead > benefit. |
| `docs` (Documentation) | Main Comprehensive, Release | One-off `cargo doc --release`. No incremental benefit. |
| `import-check` (Python) | PR Fast | Python script, no Rust compilation. Uses `actions/setup-python`. |
| `unsafe-dns` (grep) | PR Fast | Static analysis only; no compilation. |
| `alpine-test` | Nightly | Container-based build; cache not shared with host runner. |
| `freebsd-test` | Nightly | VM-based build; cache not shared with host runner. |
| `platform-compat` | Nightly | Iterates 5 targets with `cargo check` only; cache overhead exceeds benefit for check-only. |
| `outdated-deps` | Nightly | Queries crate metadata; no compilation. |

## Release and Security Considerations

### Release Build Determinism

Release qualification builds (`release-qualification.yml`) use `Swatinem/rust-cache@v2` with a `release-` prefix to isolate from CI-profile caches. However:

- **sccache is NOT used for release builds.** Release artifacts must be compiled from scratch to ensure reproducibility. LTO (`lto = true`) and `codegen-units = 1` interact poorly with sccache's shared compilation cache.
- **Cargo source caches ARE used** for release builds (registry downloads). This is safe — source code is content-addressed.

### Cache Isolation

| Concern | Mitigation |
|---------|------------|
| Secrets in cache keys | Cache keys must never contain secrets, tokens, or repository-specific paths. GitHub Actions cache keys are scoped to the repository and branch (with cross-branch sharing for the default branch). |
| Cross-tenant cache poisoning | GitHub Actions cache is repository-scoped. Fork PRs cannot read caches from the base repository (default behavior). |
| Stale malicious artifacts | `Swatinem/rust-cache` removes stale files on save. sccache entries are evicted by LRU at 10 GB. |
| Cache for security-sensitive jobs | Security regression tests and guard tests use standard caches. These jobs validate behavior, not artifact integrity. |

### Branch Cache Access

| Branch type | Can read caches from | Can write caches to |
|-------------|---------------------|---------------------|
| Default branch (main) | main, all PRs | main |
| PR branch |自己的 branch, main (read-only) | 自己的 branch |
| Fork PR | Fork's own caches only | Fork's own caches only |

## Fallback Behavior

All cache layers are **best-effort**. Cache failures never block CI.

| Failure mode | Effect | User impact |
|-------------|--------|-------------|
| Cache restore miss | Full compilation from source | Slower job (no failure) |
| Cache restore error | Continues without cache | Slower job (no failure) |
| Cache save error | Continues; next run starts cold | Next run is slower |
| sccache unavailable | Falls back to direct `rustc` | Slower compilation (no failure) |
| GitHub Actions cache quota exceeded | LRU eviction of oldest entries | Occasional cold starts for old keys |

**No job should `continue-on-error` for cache operations.** Cache is an optimization, not a requirement.

## Measurement Requirements

### sccache Stats

After each job using sccache, emit compilation statistics:

```yaml
- name: sccache stats
  if: always()
  run: sccache --show-stats
```

Key metrics to track:

| Metric | Meaning | Target |
|--------|---------|--------|
| `Compile requests` | Total rustc invocations | — |
| `Compile cache hits` | Artifacts served from cache | >80% for incremental |
| `Compile cache misses` | Artifacts compiled from source | Minimize |
| `Compile failures` | Failed compilations (not cache-related) | 0 |
| `Cache size` | Current sccache cache size | <2 GB per key |

### Cache Restore/Save Duration

`Swatinem/rust-cache@v2` and `actions/cache@v4` emit step outputs with timing. Track:

| Measurement | Where | Purpose |
|-------------|-------|---------|
| Cache restore duration | `Swatinem/rust-cache` step output | Detect slow restores (network-bound) |
| Cache save duration | `Swatinem/rust-cache` step output (post-job) | Detect oversized caches |
| Net time saved | `restore_duration - (cold_compile_time - cached_compile_time)` | Validate cache ROI |

### Reporting

Cache performance should be reported monthly in the CI performance baseline (`docs/testing/ci-performance-baseline.md`):

- Average sccache hit rate per lane
- Total cache size per lane
- Net time saved per lane (estimate)
- Cache miss rate after `Cargo.lock` changes (expected: 100% for affected crates)

## Per-Lane Cache Configuration

### PR Fast Lane

| Job | Layers used | Expected cache benefit |
|-----|-------------|----------------------|
| clippy | 1, 3, 4 | High (incremental clippy on 50 crates) |
| security-regression | 1, 3, 4 | Medium (test compilation) |
| guard-suite | 1, 3, 4 | Medium (test compilation) |
| upload-tests | 1, 3, 4 | High (per-crate tests) |
| honeypot-tests | 1, 3, 4 | High (per-crate tests) |
| tarpit-tests | 1, 3, 4 | High (per-crate tests) |
| mesh-tests | 1, 3, 4 | High (per-crate tests) |
| core-profile | 1, 3, 4 | Low (check-only, fast) |

### Main Comprehensive Lane

| Job | Layers used | Expected cache benefit |
|-----|-------------|----------------------|
| build (8 targets) | 1, 2, 3, 4 | High (release builds across targets) |
| dns-tests | 1, 3, 4 | High (1100+ tests) |
| plugin-runtime-guardrails | 1, 3, 4 | High (plugin tests + guards) |
| profile-matrix (5 jobs) | 1, 3, 4 | Medium (check-only, fast) |

### Nightly Qualification Lane

| Job | Layers used | Expected cache benefit |
|-----|-------------|----------------------|
| profile-matrix | 1, 3, 4 | Medium |
| fuzz-smoke | 1, 2 (cargo-fuzz only) | Low (nightly toolchain, different key) |
| miri-test | None (nightly + miri) | None (unique toolchain) |

### Release Qualification Lane

| Job | Layers used | Expected cache benefit |
|-----|-------------|----------------------|
| build (8 targets) | 1, 2, 4 (no sccache) | Medium (source + metadata only) |
| full-test-suite (7 suites) | 1, 3, 4 | High |
| security-regression | 1, 3, 4 | Medium |
| guard-suite | 1, 3, 4 | Medium |

## Maximum Expected Cache Size

| Layer | Per job class | Total (all jobs) |
|-------|--------------|-------------------|
| Cargo source (registry) | ~200 MB | ~200 MB (shared) |
| Tool binaries | ~50 MB | ~100 MB (nextest + fuzz + audit + deny) |
| sccache outputs | ~2 GB per key | ~10 GB (GitHub Actions limit) |
| Cargo target metadata | ~500 MB per key | ~3 GB (multiple profiles × targets) |
| **Total** | **~2.7 GB** | **~13 GB** |

GitHub Actions provides 10 GB of cache storage per repository. The sccache and target metadata layers are the primary consumers. LRU eviction ensures the most-recently-used keys are retained.

## Future Considerations

- **sccache integration** (current milestone): Adding `mozilla-actions/sccache-action@v0.0.6` to compilation jobs. This is the highest-impact cache improvement.
- **Cache partitioning by feature class**: Currently, `Swatinem/rust-cache` keys include profile/feature suffixes to avoid cross-contamination. With sccache, this becomes automatic (sccache keys include features).
- **Persistent cache for nightly**: Nightly toolchain changes frequently, invalidating all caches. Consider `Swatinem/rust-cache` with `shared-key: nightly` to at least share source caches across nightly runs.
- **Cache monitoring**: Add a weekly CI job that reports cache sizes and hit rates to track degradation.
