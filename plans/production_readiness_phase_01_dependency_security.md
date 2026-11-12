# Phase 01 Plan: Dependency Security Refresh

Status: **COMPLETE** (implemented 2026-11-11; evidence below).
Campaign: `plans/production_readiness_remediation_roadmap.md`.
Predecessor: none. This is the first phase because it already blocks release.

## The finding

At `d507fefa`, `cargo audit` reports **53 advisories** plus 18 warnings and
exits non-zero; `cargo deny check` reports `advisories FAILED`. The repository
still records a clean audit in
`architecture/dependency_advisory_remediation.md`, so the evidence is stale.
The release checklist requires both commands to pass.

Not all advisories are reachable in the default runtime, but several are on
request-path crates:

| Crate | Current | Advisory minimum | Reachability |
|---|---|---|---|
| `rustls` | 0.23.45 | >=0.23.46 | inbound TLS and egress |
| `rustls-webpki` | 0.103.15 | >=0.103.16 | certificate verification |
| `webpki-roots` | 1.0.7 / 0.26.11 | >=1.0.10 for 1.x | egress trust store |
| `webpki-root-certs` | 1.0.7 | >=1.0.10 | egress trust store |
| `quinn-proto` | 0.11.16 | >=0.11.17, >=0.11.18 for two advisories | HTTP/3, DoQ, tunnels |
| `libsqlite3-sys` | 0.30.1 | >=0.39.0 | block store, threat history, honeypot, DNS/mesh |
| `wasmtime` (plugin runtime) | 36.0.16 | >=36.0.20 in the 36 LTS line | WASM plugins |
| `wasmtime` (YARA compat fork) | 48.0.5 | >=48.0.8 in the 48 line | YARA scanning |
| `zip` | 2.4.2 / 3.0.0 / 8.6.0 | 9.x for the extract advisories | upload archive inspection, Windows Wintun, YARA |
| `pulldown-cmark` | 0.13.4 | >=0.13.6 | build-time only via `prost-build` |
| `crypto-bigint` / `ctutils` | 0.5.5 / 0.4.2 | 0.7.6 / 0.4.4 | transitive via `p256`/`ecdsa`/YARA |

`quinn` itself is 0.11.9; the patched `quinn-proto` is compatible with the
0.11 line. `rusqlite` 0.32.1 is the only `libsqlite3-sys` consumer; the latest
published `rusqlite` is 0.41.1, and the exact release that resolves
`libsqlite3-sys >=0.39.0` must be verified from the lockfile after the bump.
`zip` is a direct dependency of `synvoid-upload` and `synvoid-platform`
(Windows-only) and a transitive dependency of the YARA compatibility fork.

## Work items

### 01.1 Patch-level security updates

- Update `rustls` to >=0.23.46 and `rustls-webpki` to >=0.103.16.
- Update `webpki-roots` / `webpki-root-certs` to >=1.0.10.
- Update `quinn`/`quinn-proto` to the patched 0.11 line; verify `quinn`,
  `h3-quinn` and the root `quinn` edge resolve one compatible version.
- Keep the single `aws-lc-rs` `CryptoProvider` invariant; do not introduce
  `ring` through a dev-dependency graph.
- Run the TLS/H2/H3/DoQ interop tests and `prefer_post_quantum_does_not_gate_the_hybrid_key_exchange`.

### 01.2 SQLite

- Bump `rusqlite` in the root and in `synvoid-honeypot`, `synvoid-mesh`,
  `synvoid-dns` to a release whose `libsqlite3-sys` is >=0.39.0. The latest
  published `rusqlite` is 0.41.1; verify the resolved `libsqlite3-sys` version
  before choosing the exact pin.
- Adapt any changed API in the block store, threat-history persistence,
  honeypot SQLite, mesh and DNS paths.
- Run the block-store persistence/reload tests, threat-history tests, honeypot
  persistence benchmarks/tests, and the DNS/mesh SQLite suites.

### 01.3 Wasmtime lines

- Move `synvoid-plugin-runtime` from `wasmtime 36.0.16` to the current patched
  36 LTS release (>=36.0.20), and update the root dev-dependency pin to match.
- Move the YARA compatibility fork's `wasmtime` from 48.0.5 to >=48.0.8 and
  refresh the Phase 40/103/123 marker comments in
  `third-party/yara-x-compat/Cargo.toml`.
- Re-run plugin sandbox tests, instance-pool/fuel/epoch tests, YARA engine and
  jail tests, upload scanning tests, and `cargo test -p synvoid-yara`.
- The compatibility fork remains the only YARA path until an upstream
  `yara-x` release resolves a patched Wasmtime line; do not remove the patch
  without re-running `yara_fork_is_temporary_guard`.

### 01.4 ZIP

- Move `synvoid-upload` and `synvoid-platform` to `zip 9.x` and adapt
  `ZipArchive`/`ZipWriter`/`SimpleFileOptions` usage.
- Keep archive inspection default-off; if it is enabled, run the traversal,
  absolute-path, entry-count, compression-ratio and nested-archive tests.
- The YARA compatibility fork's `zip 8.6.0` dependency must either move to a
  patched line or be recorded as a capability-assessed exception if its only
  use is non-extract parsing. Do not add a broad advisory ignore.

### 01.5 Build-time and transitive advisories

- Bump `prost-build` / `tonic-prost-build` to a release whose
  `pulldown-cmark` is >=0.13.6. If no release exists, record the build-time-only
  scope (codegen, not runtime input) in the advisory metadata rather than
  ignoring it silently.
- Track `crypto-bigint`/`ctutils` through the `p256`/`ecdsa`/YARA line. If the
  patched line is not compatible with the YARA compatibility fork, record the
  timing-side-channel exposure and the capability boundary; do not call it
  patched.

### 01.6 Evidence and documentation

- Re-run `cargo audit` and `cargo deny check`; update `deny.toml` only with
  per-advisory metadata (path, affected capability, exposure, review date).
- Update `SECURITY.md`, `architecture/dependency_security_baseline_phase25.md`,
  `architecture/dependency_advisory_remediation.md` and
  `architecture/dependency_advisory_remediation.md` with the new versions,
  dates and any remaining exceptions.
- Keep the daily dependency-security CI job; do not replace it with a manual
  check.

## Verification

```bash
cargo tree -i rustls
cargo tree -i quinn-proto
cargo tree -i libsqlite3-sys
cargo tree -i wasmtime
cargo tree -i zip
cargo audit
cargo deny check
cargo test -p synvoid-waf --profile ci
cargo test -p synvoid-dns --profile ci
cargo test -p synvoid-yara --profile ci
cargo test -p synvoid-plugin-runtime --profile ci
cargo test -p synvoid-upload --profile ci
cargo nextest run --workspace --cargo-profile ci --profile ci --exclude synvoid-fuzz
cargo xtask verify
cargo xtask verify-full   # before release
```

## Risks and decisions

- **No published patch for a transitive crate** is possible. Do not invent a
  fix: disable the capability, record the exposure, or hold the release. A
  capability-unreachable advisory is not a patched advisory.
- **Wasmtime LTS support** ends in 2027-08-20 for the 36 line; plan the next
  LTS move separately.
- **ZIP 9 is a major API change**; archive inspection is default-off, so the
  blast radius is bounded, but the tests above are mandatory.
- **SQLite API changes** can touch backup/persistence code; run the operations
  backup and threat-history suites, not only a workspace compile.

## Exit criteria

- `cargo audit` exits 0 and `cargo deny check` passes, or every remaining
  advisory is named in `deny.toml` with capability evidence and a review date.
- The release checklist can run `verify-release` without failing on
  dependency security.
- The version/evidence documents above no longer claim a stale clean state.

## Completion evidence

Implemented 2026-11-11. `cargo audit` exits 0 and `cargo deny check` reports
`advisories ok, bans ok, licenses ok, sources ok`. Landed rustls 0.23.46,
rustls-webpki 0.103.16, quinn-proto 0.11.19, rusqlite 0.41.1 /
libsqlite3-sys 0.39.1, wasmtime 36.0.20 and 48.0.8 (official yara-x 1.23.0),
zip 9.5.0, tokio 1.54.1, prost-build 0.14.4 and pulldown-cmark 0.13.6. Remaining
exceptions are named in `deny.toml`/`.cargo/audit.toml` with capability and
review metadata (rsa decrypt, rkyv 0.7 via minify, build-only zip 3.0.0, and
unmaintained build/optional chains).

