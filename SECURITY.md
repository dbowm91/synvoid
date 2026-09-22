# Security Policy

> Operator hardening guidance lives in `docs/SECURITY.md` — this file is the
> vulnerability-reporting policy and supported-version statement.

## Supported Versions

We release security patches for the latest released version. We recommend users to always use the latest release.

| Version | Supported          |
| ------- | ------------------ |
| latest  | :white_check_mark: |

## Reporting a Vulnerability

If you discover a security vulnerability within SynVoid, please send an email to the maintainers. All security vulnerabilities will be promptly addressed.

Please include the following information:

- Type of vulnerability
- Full paths of source file(s) related to the vulnerability
- Location of the affected source code (tag/branch/commit or direct URL)
- Any special configuration required to reproduce the issue
- Step-by-step instructions to reproduce the issue
- Proof-of-concept or exploit code (if possible)
- Impact of the issue, including how an attacker might exploit it

## Security Features

SynVoid includes several security features:

### Attack Detection
- SQL Injection (via libinjection)
- Cross-Site Scripting (XSS)
- Command Injection
- Path Traversal
- Remote/Local File Inclusion (RFI/LFI)
- Server-Side Request Forgery (SSRF)
- Server-Side Template Injection (SSTI)
- XML External Entity (XXE)
- LDAP/XPath Injection
- Open Redirect
- HTTP Request Smuggling

### Rate Limiting
- Per-IP rate limiting with configurable windows
- Global rate limiting
- Connection limiting

### Bot Protection
- Known search bot allowlisting
- AI crawler blocking (configurable)
- Scraper detection (configurable)
- Proof-of-Work challenges
- CSS honeypot challenges

### Process Security
- HMAC-signed IPC messages
- Socket FD passing for zero-downtime upgrades
- Graceful connection draining

### Deception Layer

**Port Honeypot**: Deploys fake service endpoints (SSH, HTTP, MySQL, Redis, FTP, PostgreSQL, SMB, RDP, VNC, SMTP) to detect and study attacker behavior. Disabled by default. AI responder disabled by default. Raw payload storage disabled by default. Threat-intel mesh propagation disabled by default, requires Medium+ confidence and 3+ events. See [`docs/HONEYPOT.md`](docs/HONEYPOT.md).

**Tarpit**: Anti-scraping trap that generates infinite HTML pages via Markov chains. Escapes all attacker-controlled values before HTML interpolation. Redirect safety blocks CRLF injection and absolute URL redirects. Admission control limits concurrent sessions (256 global, 4 per-IP). Session budgets enforce duration (600s), chunks (500), bytes (50MB), and idle (30s) limits. See [`docs/TARPIT.md`](docs/TARPIT.md).

## Configuration Recommendations

For production deployments:

1. **Use strong admin tokens**: Generate tokens using `--generatetoken` or set `admin.token_env_var`
2. **Enable HTTPS**: Configure TLS in your site configuration
3. **Restrict trusted proxies**: Don't trust `0.0.0.0` in production
4. **Configure rate limits**: Adjust based on your traffic patterns
5. **Enable logging**: Monitor for attack patterns
6. **Keep updated**: Use the latest version for security patches
7. **Enable IPC signing**: Set `security.ipc_enforce_signing = true` and configure `security.ipc_session_key_env`
8. **Configure CORS carefully**: Avoid wildcard origins in production

## IPC Security

SynVoid supports HMAC-signed IPC communication between the master process and workers. This prevents unauthorized workers from connecting to the master.

### Configuration

```toml
[security]
# Require signed IPC messages (recommended for production)
ipc_enforce_signing = true

# Environment variable containing 64-character hex session key
# Generate with: xxd -l 32 -p /dev/urandom
ipc_session_key_env = "SYNVOID_IPC_KEY"
```

### Setup

1. Generate a secure key: `xxd -l 32 -p /dev/urandom`
2. Set the environment variable: `export SYNVOID_IPC_KEY="<your-key>"`
3. Enable enforcement: Set `ipc_enforce_signing = true`

Without IPC signing enabled, any process on the same machine can connect to the master IPC socket.

---

## Known Dependency Vulnerabilities

The following vulnerabilities exist in transitive dependencies and are documented for awareness. Fixes are monitored via [RustSec Advisory Database](https://rustsec.org/).

### High Severity

| Vulnerability | Crate | ID | Status | Notes |
|---------------|-------|-----|--------|-------|
| ~~KyberSlash~~ | ~~`pqc_kyber` / `pqc_kyber_edit`~~ | ~~RUSTSEC-2023-0079~~ | **Remediated (Phase 44)** | Migrated wasm-pow to maintained final ML-KEM (`ml-kem` 0.3); draft-Kyber packages absent from lockfile (guard `pqc_backend_is_maintained_ml_kem`) |
| ~~Denial of Service~~ | ~~`quinn-proto`~~ | ~~RUSTSEC-2026-0037~~ | **Patched** | Fixed via git patch to 0.11.14 |
| ~~Winch compiler backend sandbox escape~~ | ~~`wasmtime` 40.0.4 (via yara-x)~~ | ~~RUSTSEC-2026-0095~~ | **Remediated (Phase 40)** | YARA line moved to wasmtime 47.0.4 (patched); ignore removed 2026-09-18 |
| ~~Cranelift aarch64 sandbox escape~~ | ~~`wasmtime` 40.0.4 (via yara-x)~~ | ~~RUSTSEC-2026-0096~~ | **Remediated (Phase 40)** | YARA line moved to wasmtime 47.0.4 (patched); ignore removed 2026-09-18 |
| ~~Filesystem sandbox escape (trailing-slash paths/symlinks)~~ | ~~`wasmtime` 40.0.4 (via yara-x); direct 36.0.15 LTS patched~~ | ~~RUSTSEC-2026-0269~~ | **Remediated (Phase 40)** | Both lines version-patched (direct 36.0.15 LTS >=36.0.14; transitive 47.0.4 >=47.0.4); ignore removed 2026-09-18. See `architecture/dependency_security_baseline_phase25.md` §11. |

### Medium Severity

| Vulnerability | Crate | ID | Status | Notes |
|---------------|-------|-----|--------|-------|
| Marvin Attack | `rsa` | RUSTSEC-2023-0071 | **Low exposure** | Direct + transitive (yara-x); assessed low exposure — not actively invoked in current code paths |

### Unmaintained Dependencies (Warnings)

Transitive unmaintained/unsound notices stay visible via `cargo audit` warnings
and are triaged here. `cargo deny check` gates unmaintained/unsound for
workspace crates (`unmaintained = "workspace"`, `unsound = "workspace"`) — our
own crates must never go unmaintained without failing the gate — while
transitive notices are accepted below rather than silenced with broader ignores
(see `architecture/dependency_security_baseline_phase25.md` §5).

| Crate | Alternative | Status | Notes |
|-------|-------------|--------|-------|
| `bincode` | `postcard` | **Partial** | Transitive only (admin-ui yew chain: `bincode` 1.3.3; `yara-x`: `bincode` 2.0.1); no direct root/workspace edge since Phase 31 cleanup; postcard handles primary serialization |
| `paste` | None | Acceptable | Transitive via utoipa |
| `proc-macro-error` | None | Acceptable | Transitive via yew |
| `atomic-polyfill` | None | Acceptable | Transitive via postcard/heapless |
| ~~`rustls-pemfile`~~ | ~~`rustls-pki-types`~~ | **Removed** | Migrated to rustls-pki-types PEM iterator |
| `once_cell` | `std::sync::LazyLock` | **Removed** | Replaced with std library equivalent |
| `unicode-segmentation` 1.13.1 | 1.13.2 | **Yanked** | Transitive dep; 1.13.1 yanked, 1.13.2 available |
| `gimli` 0.33.1 | None | **Yanked** | Transitive via wasmtime; build warning only |

### Cryptographic Dependencies

| Crate | Version | Language | Purpose |
|-------|---------|----------|---------|
| `aws-lc-rs` | 1.16.2 | C (compiled) | TLS 1.3, ML-KEM, ML-DSA |
| `ring` | 0.17.14 | Rust | DNS/QUIC (transitive via hickory/quinn) |
| `libcrux-ml-dsa` | 0.0.8 | Pure Rust | ML-DSA signatures |
| `ml-kem` | 0.3.2 | Pure Rust | Final ML-KEM-768 (wasm-pow client; Phase 44) |
| `ed25519-dalek` | 2.1.0 | Pure Rust | Ed25519 signatures |
| `x25519-dalek` | 2.0.0 | Pure Rust | X25519 key exchange |
| `sha2`, `sha3` | 0.10 | Pure Rust | Hashing |
| `hmac` | 0.12 | Pure Rust | HMAC |
| `aes-gcm` | 0.10 | Pure Rust | AES-GCM |
| `zeroize` | 1.8 | Pure Rust | Secret destruction |
| `subtle` | 2.12 | Pure Rust | Constant-time ops |

### Post-Quantum Crates

| Crate | Algorithm | Location | Vulnerability |
|-------|-----------|----------|----------------|
| `ml-kem` | ML-KEM-768 (FIPS 203 final) | crates/synvoid-wasm-pow | ✅ Secure (Phase 44 migration; KAT-verified, interop with aws-lc-rs) |
| `libcrux-ml-dsa` | ML-DSA-65/87 | pqc/workspace | ✅ Secure |
| `aws-lc-rs` | ML-KEM + ML-DSA | Cargo.toml | ✅ Secure |

### NASM Not Used

- **Status**: Confirmed - NASM assembler is NOT used
- `ml-kem` uses pure Rust implementation (no `nasm` feature; pre-Phase-44 `pqc_kyber_edit` also avoided it)
- No C/asm additions at build time

---

## YARA Rule Provenance & Trust (Phase 4)

Active YARA rules carry provenance metadata tracking their source, verification state, and identity.

### Rule Source Types

| Source | Trust Level | Description |
|--------|------------|-------------|
| `Bundled` | Low | Default malware rules shipped with the binary |
| `Directory` | Operator-controlled | Rules loaded from a local filesystem directory |
| `DirectoryWithFallback` | Operator-controlled | Directory rules with bundled fallback on failure |
| `Inline` | High | Rules provided directly via config or admin API |
| `Mesh` | Network-trusted | Rules received from mesh peers, Ed25519-verified |

Phase 36 source-only trust: signed/approved source text is the canonical
executable input; compilation happens locally in `synvoid-yara`. Wire
compiled bytes are opaque/non-executable metadata (never stored, never
deserialized). There is no `CompiledBundle` source type: a mesh version bump
with no acceptable source retains the previous generation, and upload reloads
recompile via `reload_with_rules`. See `crates/synvoid-yara/src/artifact.rs`.

### Directory Loading Hardening

Directory-based rule loading enforces:
- **Sorted file order**: Rules loaded alphabetically for deterministic compilation
- **Symlink rejection**: Symlinks are rejected by default (`yara_allow_rule_symlinks = false`)
- **File count limit**: Maximum rule files per directory (`yara_max_rule_files = 256`)
- **Aggregate size limit**: Maximum total source bytes (`yara_max_rule_source_bytes = 8MB`)
- **Canonical path enforcement**: Directory is canonicalized to prevent traversal

### Signed Bundle Format

YARA rule bundles can be signed with Ed25519 keys via `YaraRuleManifest`:
- Content SHA-256 hashes for source and compiled rules
- Ed25519 signature over `source_hash:compiled_hash`
- Base64-encoded signature in TOML manifest
- Verification via `manifest.verify()` and `manifest.verify_content()`

### Mesh Rule Trust

Mesh-delivered rules are verified against trusted signers (`require_signature = true` by default). Unsigned mesh updates are rejected in production mode. The mesh trust model uses Ed25519 signatures, not RSA.

### Operator Inspection

```rust
// Get active rule provenance
let provenance = scanner.get_rule_provenance();
// provenance.source_type, .version, .content_sha256, .verified, .loaded_at

// Get last reload error (None if last reload succeeded)
let error = scanner.get_last_reload_error();
```

### Dependency Policy (Phase 25 baseline)

`deny.toml` enforces (blocking in CI via `cargo deny check`):
- Yanked crate denial (`yanked = "deny"`)
- Unknown registries denied; unknown Git sources denied with NO exceptions
  (Phase 37 removed the wasmtime 42.0.2 git patch; re-adding any git source
  requires an `allow-git` entry plus baseline evidence)
- Wildcard version requirements denied (`wildcards = "deny"`)
- Unmaintained/unsound gating for workspace crates (see triage note above)
- Documented rationale, exposure, owner, Reviewed/Re-audit dates, and remove
  conditions for all ignored advisories (guard-enforced by `deny_ignore_metadata_guard`)
- Duplicate-version allowlist narrowed to the documented wasmtime split
  (transitive 47.0.4 via the yara-x compat fork + direct 36.0.15 LTS)

`cargo audit` runs as a blocking gate with the same narrow exceptions mirrored
in `.cargo/audit.toml` (cargo-audit does not read `deny.toml`).

---

## Dependency Patches

### quinn-proto (RUSTSEC-2026-0037)
- **Issue**: DoS via malformed QUIC transport parameters (CVE-2026-31812)
- **Severity**: High (CVSS 8.7)
- **Fix**: Patched in `quinn-proto 0.11.14`
- **Patch**: Applied via `[patch.crates-io]` in Cargo.toml
- **TODO**: Remove patch when quinn 0.11.10+ is released on crates.io
- **Tracking**: https://github.com/quinn-rs/quinn/releases

### wasmtime (RUSTSEC-2026-0095 and related 2026-04 advisories — remediated Phase 40)
- **Issue**: Winch compiler backend sandbox escape (CVE-2026-34987) + Cranelift/Winch/component-model advisories 0085-0096, 0114, 0222
- **Severity**: High (0095/0096 critical-class sandbox escapes)
- **Fix**: Direct runtime at `wasmtime 36.0.15` LTS (unaffected by every advisory in this group — proven by a clean `cargo audit` on an isolated 36.0.15 resolve with no ignores, 2026-09-17); YARA transitive line moved 40.0.4 → 47.0.4 in Phase 40 (patched; ignores removed 2026-09-18)
- **Status**: Not affected (direct) / version-patched (YARA transitive) — no ignores remain for this group

### wasmtime (RUSTSEC-2026-0269 — patched on both lines, Phase 40)
- **Issue**: Filesystem sandbox escape when paths/symlinks contain trailing slashes (GHSA-vqjp-4c8c-hfgg)
- **Severity**: High (8.8). Affected: 37.0.0–46.0.2 except backported LTS lines; patched ranges include >=36.0.14,<37.0.0 and >=47.0.4. Direct 36.0.15 is PATCHED; transitive 47.0.4 is PATCHED.
- **Exposure**: Capability-absent on top of version remediation — `wasmtime-wasi` is not resolved, linked, or reachable from either consumer (proven from the lockfile/feature graph, not from absence of a PoC).
- **Upgrade**: Phase 40 moved the YARA line off wasmtime 40.x (temporary `third-party/yara-x-compat` fork of official yara-x 1.20.0 with the PR #769 wasmtime-47.0.4 delta); the per-advisory ignore is removed. Removal condition for the fork: an official fixed yara-x release (see `architecture/dependency_security_baseline_phase25.md` §11). Re-audit: 2026-10-01.
- **Status**: Patched (both lines) + documented decision + guard-enforced (`wasmtime_baseline_guard`, `wasmtime_transitive_matches_baseline`)
- **Reference**: `architecture/dependency_security_baseline_phase25.md`

### rustls-pemfile Removal
- **Issue**: Unmaintained (RUSTSEC-2025-0134)
- **Fix**: Replaced with `rustls_pki_types::CertificateDer::pem_slice_iter()`
- **Status**: `rustls-pemfile` removed from Cargo.toml

### bincode → postcard Migration
- **Issue**: bincode unmaintained (RUSTSEC-2025-0141)
- **Fix**: Migrated primary serialization to `postcard`; `bincode` is transitive-only (admin-ui yew chain + `yara-x`); no direct root/workspace edge since Phase 31 cleanup
- **Benefits**: 
  - Actively maintained
  - 30% smaller serialized output
  - No dependency conflicts
- **Status**: Partial — primary paths migrated, legacy paths retained

### rkyv for High-Performance Paths
- **Purpose**: Zero-copy serialization for DNS and DHT operations
- **Implementation**:
  - Added `rkyv` dependency (renamed to avoid lightningcss conflict)
  - Created `src/serialization_rkyv.rs` module re-exporting rkyv
  - Added rkyv derives to DNS message types (`crates/synvoid-dns/src/messages.rs`)
  - Added rkyv derives to DHT types (keys, signed, stake, network_policy, merkle, store, routing)
  - Added rkyv derives to `MeshNodeRole` in `src/mesh/config.rs`
- **Default Serialization**: rkyv is now the default for:
  - `SignedDhtRecord::serialize()` / `deserialize()` - DHT record storage
  - `PersistedRoutingTable::to_bytes()` / `from_bytes()` - routing table persistence
  - `RoutingTable::to_persisted_bytes()` / `from_persisted_bytes()` - routing table
  - `DhtRoutingManager::get_persisted_bytes()` / `init_with_persisted_bytes()` - manager API
- **Fallback Methods**: 
  - `serialize_json()` / `deserialize_json()` - for wire format compatibility
  - `to_bytes_postcard()` / `from_bytes_postcard()` - for postcard compatibility
- **Error Handling**: Methods return `Result` types with proper error propagation
- **Completed**: 2025-03-12

### yara-x/rsa Exposure Assessment (RUSTSEC-2023-0071)
- **Vulnerability**: Marvin Attack - potential key recovery through timing side-channels
- **Exposure**: LOW
- **Analysis**:
  - The `rsa` crate is a transitive dependency via yara-x
  - yara-x uses RSA only for optional YARA rule signature verification
  - SynVoid uses **ed25519-dalek** for YARA rule feed signature verification (not RSA)
  - The RSA functionality is loaded but never invoked in the current code path
- **Recommendation**: No action required unless you enable RSA-based YARA rule signing

### yara-x/wasmtime Transitive Line (remediated Phase 40)
- **Prior issue**: yara-x 1.15 pulled wasmtime 40.0.4 which had multiple vulnerabilities
- **Your direct version**: wasmtime 36.0.15 LTS from crates.io (patched for RUSTSEC-2026-0269 and unaffected by the 2026-04 advisories — see above; no git patch)
- **Current path**: yara-x 1.20.0 (temporary manifest-only compat fork) → wasmtime 47.0.4 (patched; transitive)
- **Mitigation**: single `synvoid-yara` owner for yara-x; version-patched transitive line with guard-enforced fork removal metadata (Reviewed: 2026-09-18; Re-audit: 2026-10-01)
- **Recommendation**: Replace the fork with an official fixed yara-x release when available (see `third-party/yara-x-compat/README.SYNVOID.md`)

### yara-x Serialized-Rule Deserialization (GHSA-2jx3-ff3v-j7jj, Phase 36; version-remediated Phase 40)
- **Issue**: YARA-X <=1.18 `Rules::deserialize` on malformed serialized bytes can cause memory corruption. Fixed upstream in 1.19.0+. SynVoid is now on yara-x 1.20.0 (no RUSTSEC ID mapped — `cargo audit`/`cargo deny` do not fire; tracked here instead).
- **Exposure after Phase 36**: NO remote/mesh/wire bytes reach any deserializer. `YaraScanner::reload_with_compiled_rules`, `CompiledArtifact::deserialize_verified`, `from_bytes_with_binding`, mesh `local_compiled_rules`/`apply_compiled_rules`/`get_current_compiled_rules`, and the `CompiledBundle` source type were removed; upload/mesh/jail paths recompile approved source text locally. Residual risk is local-only (malformed bytes from a local operator artifact), fail-closed with previous-generation retention.
- **Upgrade status**: LANDED in Phase 40 (temporary manifest-only compat fork of official 1.20.0 with the PR #769 wasmtime-47.0.4 delta; `YARA_ENGINE_VERSION` is `yara-x/1.20`). No advisory ignore exists for this GHSA (nothing to ignore — unmapped; documented instead of silenced). Remove the fork (not this section) when an official fixed yara-x release replaces it.

### Post-Quantum Architecture
- **Hybrid Key Exchange**: X25519 + final ML-KEM-768 provides defense-in-depth (wasm-pow client via `ml-kem` 0.3, server via `aws-lc-rs`; Phase 44)
- **ML-DSA**: Uses libcrux-ml-dsa (pure Rust) in pqc workspace
- **TLS Post-Quantum**: Via aws-lc-rs feature in rustls
- **Reference**: See `skills/crypto_dependencies.md` for full documentation

---

### Monitoring

Dependency checks are blocking gates, not manual chores:
```bash
cargo deny check   # routine `cargo xtask verify` step (pinned cargo-deny)
cargo audit        # blocking `dependency-security` CI job (every PR + daily) and `verify-release` (pinned cargo-audit)
```

Exceptions are mirrored in `deny.toml` + `.cargo/audit.toml` with owner,
Reviewed/Re-audit dates, and remove conditions; `deny_ignore_metadata_guard`
fails expired or undocumented ignores (deadlines are evaluated against the
current UTC date, so an exception expires automatically).

---

## Security Posture for Release 1.1.0

### Production Security Defaults

The following security measures are enabled by default in production builds:

- **Constant-time comparison** for all secrets, keys, MACs, and auth tokens via `subtle::ConstantTimeEq`
- **HMAC-signed IPC** with replay protection between supervisor and workers
- **Plugin sandbox (WASM)** with capability-based access control and default-deny policy
- **TLS enforcement** on all external listeners (HTTP/1, HTTP/2, HTTP/3, DNS-over-TLS)
- **Block store with provenance tracking** — every block write is attributed to a `BlockProvenanceKind`
- **Admin auth boundary** — mutating admin endpoints require authenticated sessions and return typed `AdminMutationResult`
- **Plugin ABI memory boundary** — `write_to_guest_memory` requires `guest_alloc`/`guest_free`; fixed-offset fallback removed
- **Plugin lifecycle hardening** — prepare-then-commit reload with generation-aware atomic swaps; failed reloads never replace a working plugin
- **Unsafe native extensions disabled by default** — production loading requires explicit risk acknowledgement, path allowlist, and optional SHA-256 verification

### Feature Gate Security Classification

| Feature Gate | Status | Security Implication |
|-------------|--------|---------------------|
| `mesh` | Supported | Ed25519 peer auth, TLS transport, DHT record signing |
| `dns` | Supported | DNSSEC validation, TSIG authentication, zone signing |
| `socket-handoff` | Supported | Graceful connection migration via FD passing |
| `erased_pool` | Supported | Type-erased HTTP/2 connection pooling |
| `swagger-ui` | Supported | API documentation UI (dev only, disable in production) |
| `wireguard` | Supported | WireGuard VPN tunnel for mesh transport |
| `icmp-filter` | Supported | ICMP flood filtering (nftables/pf/winfw) |
| `origin_key_exchange` | Supported | Signed HTTP integrity verification |
| `audit` | Supported | Audit logging for admin mutations |
| `tun-rs` | Supported | TUN device support |
| `buffer` | Supported | Sharded buffer pool with ABA-safe design |
| `rkyv` | Supported | Zero-copy serialization for DNS/DHT types |
| `macos-sandbox` | Experimental | macOS Seatbelt via deprecated `sandbox_init` (opt-in; not App Sandbox; Linux is the production strict-isolation target) |
| `test-utils` | Supported | Test utilities (not for production) |
| `fastcgi_streaming` | Supported | Streaming FastCGI proxy |
| `flood-ebpf` | Beta | Requires root, kernel BTF; eBPF XDP/TC ICMP filtering (Linux only) |
| `post-quantum` | Beta | Hybrid ML-KEM-768 + Ed25519 key exchange (experimental) |
| `verify-pq` | Beta | Post-quantum signature verification (experimental) |

### Known Security Limitations

- **eBPF features require root** and Linux kernel 5.8+ with BTF support; falls back to nftables when unavailable
- **Post-quantum features are experimental** — functional but limited real-world validation
- **YARA compilation uses wasmtime** (47.0.4 via the temporary yara-x 1.20 compat fork, version-patched; direct runtime is 36.0.15 LTS, patched; `wasmtime-wasi` unreachable) with guard-enforced fork removal metadata (Reviewed: 2026-09-18; Re-audit: 2026-10-01; remove the fork when an official fixed yara-x release replaces it)
- **External DNSSEC tooling deferred** — zone signing is internal but external key management tooling is not yet shipped
- **KyberSlash closed (Phase 44)** — wasm-pow migrated from draft-Kyber `pqc_kyber_edit` to maintained final ML-KEM (`ml-kem` 0.3); RUSTSEC-2023-0079 no longer applies to the graph (guard `pqc_backend_is_maintained_ml_kem`)
- **Archive inspection is ZIP-only and non-recursive** — TAR/GZIP/BZIP2/7z are detected by MIME but not opened; nested archives are counted but not recursively scanned

### Security Verification Commands

Operators can verify the security posture of a deployment with:

```bash
# Dependency audit — checks for known vulnerabilities
cargo deny check

# Lint — catches unsafe patterns, unwrap abuse, and common mistakes
cargo clippy --all-targets --all-features -- -D warnings

# Security regression tests — validates cryptographic and auth invariants
cargo test --test security_regression -- --test-threads=1

# Security observability guard — validates metric labels, doc coverage, registry signals
cargo test --test security_observability_guard

# Plugin capability boundary — validates plugin isolation and sandbox enforcement
cargo test --test plugin_capability_boundary_guard

# Plugin failure isolation — one plugin failure does not poison others
cargo test --test plugin_failure_does_not_poison_manager

# Plugin signature policy — strict verification enforcement
cargo test --test plugin_signature_policy_guard

# ABI memory boundary — guest allocation and checked arithmetic
cargo test --test abi_memory_boundary_guard

# Admin mutation response guard — typed mutation results
cargo test --test admin_mutation_response_guard

# Full test suite (release mode, no fail-fast)
cargo test --release --no-fail-fast
```
