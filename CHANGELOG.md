# Changelog

All notable changes to SynVoid will be documented in this file.

Format based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.1.0] - 2026-07-12 (Release Candidate)

### Summary

The 1.1.0 release adds a production-grade DNS authoritative server with DNSSEC signing and validation, a WASM plugin runtime with capability-based sandboxing, a deception layer comprising honeypot listeners and anti-scraping tarpits, and a workspace-wide release validation pass covering 2,760+ tests across 43 workspace members. This release transforms SynVoid from a WAF and reverse proxy into a multi-protocol security platform with extensibility, deception, and verifiable release hygiene.

### Added

**DNS Authoritative Server (synvoid-dns)**
- Typed wire-format response encoder supporting A, AAAA, CNAME, NS, SOA, MX, TXT, PTR, CAA, TLSA, SVCB, HTTPS, NAPTR, SSHFP, DNSKEY, DS, RRSIG, NSEC, and NSEC3 RR types
- Canonical single-parse query parser replacing ad hoc per-path parsers across cache, firewall, RRL, coalescing, transfer, update, and notify modules
- Authoritative negative responses (NODATA, NXDOMAIN) with SOA authority section and DNSSEC-authenticated denial (NSEC/NSEC3)
- SOA validation and serial management with RFC 1982 arithmetic, IXFR history tracking, and AXFR TCP-only enforcement
- Dynamic UPDATE with post-mutation re-validation, prerequisite checking, cache invalidation, and atomic rollback on SOA invariant violation
- NOTIFY rate limiting, source allowlist, and stale-serial suppression
- Query coalescing with broadcast response to concurrent identical queries
- Cache redesign with qclass, DO bit, transport class, and namespace key dimensions; SOA-derived negative TTL; serve-stale with configurable max_stale_count
- DNSSEC live signing with KSK/ZSK rotation, RRSIG generation, and NSEC/NSEC3 denial proofs
- TSIG authentication for transfer and update paths with HMAC-SHA256 sign-verify roundtrips
- Encrypted transports: DNS-over-TLS (DoT), DNS-over-HTTPS (DoH), DNS-over-QUIC (DoQ) as thin adapters over canonical parser
- Recursive resolver isolation with ACL, circuit breaker, CD/AD flag handling, bailiwick checks, ECS support, and depth limits
- 8 production profiles (4 production-supported, 2 beta, 1 experimental) with hardened example configs
- 5 criterion benchmark suites (cache, wire, zone, coalescer, limits) and 28 stress/resource-limit tests
- Health checker providing liveness/readiness status (Healthy/Degraded/NotReady) with zone, cache, DNSSEC, encrypted transport, and transfer health state
- Structured metrics for transport queries/errors, operation counts, zone reload, recursive circuit breaker, DNSSEC signing failures, and control-plane authorization
- Interoperability and conformance test suites (7 internal suites)
- Operator diagnostics guide with smoke tests, alerting matrix, and troubleshooting flowchart

**Plugin Runtime (synvoid-plugin-runtime)**
- WASM sandbox with capability-based trust model: SignedSandboxed, LocalSandboxed, and UnsafeNative tiers
- Manifest authority wiring with per-plugin capabilities, limits, and signing state enforced independently at runtime
- Signed byte loading with TOCTOU closure: file-based plugin loading reads WASM bytes once and instantiates from verified bytes
- Mandatory invocation guard with failure/quarantine semantics for traps, fuel exhaustion, and timeouts
- ABI memory boundary hardening with guest_alloc/guest_free requirement, single-frame allocation, and checked arithmetic
- ABI frame serialization via canonical `serialize_headers_canonical` and `build_request_frame` (no ad-hoc header encoding)
- Request/response serialization with explicit size, status, and mutation bounds
- Execution containment with fuel mandatory for sandboxed tiers, wall-clock and host-call timeouts, and instance pooling with per-plugin isolation
- Host API sub-capabilities for mesh (DHT prefixes, event topics, threat-check permissions), persistence, filesystem, network, and metrics with default-deny allowlist
- Unsafe native extension production gate with risk acknowledgement, path allowlist, and optional SHA-256 hash verification
- Hot-reload with prepare-then-commit pipeline, generation-aware atomic swaps, stable file detection, and debounce
- Plugin lifecycle state machine with explicit transitions, generation tracking, and structured audit events
- 44+ unit and integration tests across manifest validation, ABI boundary, execution containment, lifecycle, and guard state

**Honeypot Deception Layer (synvoid-honeypot)**
- Async bounded storage writer pipeline with tokio::mpsc channel and background SQLite batch writer
- Payload retention modes (None, HashOnly, Truncated, Full) with SHA-256 hashing and configurable truncation limits
- Backpressure policy with queue-full drops counted via metrics, batch insertion with transaction-level flush
- Signal class classification (ProtocolProbe, KnownAttackPattern, RepeatedHit, ExploitPayload, CredentialAttempt, ScannerFingerprint, MalwareCorrelation)
- Bounded scoring model (0.0-1.0) with confidence weighting, diminishing-returns repeat bonus, and time decay
- 5 action classes (Observe, LocalRateLimitCandidate, LocalBlockCandidate, MeshShareCandidate, MeshBlockCandidate) with configurable thresholds
- Mesh propagation guardrails: minimum confidence, minimum event count, dedupe keys, TTL
- AI honeypot responder with Disabled/TemplateOnly/LocalModelOnly/ExternalProvider modes (default Disabled)
- AI budget controls: circuit breaker (opens after N consecutive failures, 60s cooldown), concurrency limiter, turn counter, prompt/response truncation
- Template responder with 7 service-specific deterministic factories (SSH, HTTP, MySQL, Redis, PostgreSQL, FTP, SMTP)
- 9 hardened system prompts with prompt injection resistance and containment disclaimers
- Listener concurrency via tokio::Semaphore with per-IP RAII guard and automatic cleanup
- Protocol detection rewritten for binary safety across TLS, MySQL, SMB, PostgreSQL, Redis, HTTP, SSH, and unknown fixtures
- 182 total tests covering admission, accounting, storage, scoring, AI containment, and protocol detection

**Tarpit Anti-Scraping (synvoid-tarpit)**
- HTML escaping (`html_escape`, `html_attr_escape`), JavaScript string escaping (`js_string_escape`), and URL path encoding (`url_path_encode`)
- Redirect safety with RedirectPolicy (RelativeOnly, AllowList, AllowAll), CRLF injection blocking, control character rejection, and absolute URL host allowlist
- Admission control via global semaphore (default 256) and per-IP semaphore (default 4) with OwnedSemaphorePermit RAII guard
- Session budget tracking with atomic counters for chunks sent, bytes sent, duration, and idle time; checks max_duration_secs (600s), max_chunks (500), max_bytes (50MB), max_idle_secs (30s)
- Fingerprint resistance via seeded per-session RNG, configurable chunk delay range, and varied status codes
- 54 total tests covering escaping, admission, budgets, and edge cases

**WAF and Streaming WAF (synvoid-waf, synvoid-core)**
- Streaming WAF engine for incremental body scanning and real-time attack detection
- WAF hardening with improved rule evaluation and attack detection accuracy

**Post-Quantum Cryptography**
- Hybrid Ed25519 + ML-DSA-44 post-quantum mesh signature implementation
- Post-quantum TLS key exchange support (Beta feature gate)

**Mesh and Trust Domains (synvoid-mesh)**
- 7 trust domains with CanonicalTrustReader and trust domain invariants
- Mesh trust domain boundary enforcement and policy cleanup iterations
- Threat-intel consumer actionability classification (46 consumers by enforcement capability)
- BlockStore architecture with persistence, snapshot export, peer cursors, and source-scoped ordering
- Blocklist reconciliation for offline-peer catchup, event log, and snapshot fallback

**Architecture Hardening**
- 22 guard tests enforcing architectural boundaries (composition root, data plane, root facade, module ledger, dependency ownership, mesh-ID, threat-intel, HTTP pipeline, plugin capability, ABI memory, lifecycle, unsafe native sandbox)
- Final public surface audit and release hardening (Phase 10-16)
- Root module burn-down with reclassification of platform, utils, and tarpit modules
- Typed CLI/supervisor command dispatch with plan/execute/runtime-launch boundary
- Admin legacy mutation audit with AdminMutationResult and AdminAuditEvent
- 16 fuzz targets (parser boundary, plugin manifest, HTTP path normalization, attack detection, IPC, blocklist, admin mutation, mesh protocol)
- 5 compilation profiles verified in CI (Default, Core, Mesh, DNS, Full)

### Changed

**DNS Server**
- Replaced ad hoc byte-appending response construction with typed wire-format encoder
- Replaced per-path query parsing with single canonical parsed-query structure
- Cache key redesigned with qclass, DO bit, transport class, and namespace dimensions
- AXFR now TCP-only and disabled by default
- NOTIFY source validation with allowlist and rate limiting
- Zone activation gated by `validate_zone_for_activation()` with SOA field, label, and origin checks

**Plugin Runtime**
- WASM sandbox uses canonical ABI frame serialization instead of ad-hoc header encoding
- File-based plugin loading verifies exact bytes before instantiation (TOCTOU closure)
- Native `.so`/`.dylib`/`.dll` plugins reclassified as `unsafe_native_plugins`, disabled by default
- Hot reload is prepare-then-commit with generation-aware atomic swaps

**Worker Architecture**
- UnifiedServerWorker decomposed into typed modules (startup_plan, resources, runtime_handles, plugin_runtime)
- CPU offload moved from `src/worker/mod.rs` to `src/worker/cpu_task/`
- Supervisor consolidated from `src/overseer/` and `src/master/` into `src/supervisor/`

**Workspace**
- 43 workspace members (34 dedicated synvoid-* library crates plus root, pqc, admin-ui, examples, and fuzz)
- Root crate facade reduction with 34 crates extracted from monolithic root
- 32 unwired DNS metrics methods removed (metrics.rs reduced from 1128 to 504 lines)
- 36 ignored tests cleaned up (34 dead stubs deleted, 2 deadlock tests rewritten and unignored)
- CI expanded to 26 jobs including dedicated tarpit-tests, mesh-tests, and profile-matrix jobs

### Fixed

**DNS Server**
- Response flag semantics: RA=false for authoritative responses, RD echoed from query
- Byte-size truncation preserving query ID and setting TC correctly
- Parser propagation: single-parse canonical query replaces redundant per-path parsers
- Authoritative NODATA/NXDOMAIN with SOA in authority section
- Encoder strictness: MX/CAA/TLSA validation with EncodeReport for skip tracking
- Query coalescing broadcast for concurrent identical queries
- Runtime correctness: bind address honor, DNS64 pass-through, TCP connection limit guards
- Cache invalidation on dynamic update and AXFR
- UPDATE `parse_rr_with_rdata()` including TTL+RDLENGTH bytes in rdata
- UPDATE `skip_rr_with_rdata()` not skipping full RR
- UPDATE `check_prerequisite()` inverted logic for Exists/ExistsRRset
- Zone `validate_zone_for_activation()` rejecting control chars, NUL, whitespace, backslash, and slash in origin
- Server `replace_zone_with_validation()` atomic swap-or-preserve with cache invalidation

**Plugin Runtime**
- ABI memory boundary: removed fixed-offset 1024 fallback; all guest pointer/length operations use checked_guest_range
- Manifest-to-runtime authority differentiation (PreparedPluginLoad vs raw default_limits)
- Plugin failure isolation: one plugin's failure no longer poisons others
- Epoch interrupt handling and body chunk timeout enforcement

**Workspace**
- 9 test failures fixed in workspace-wide validation (WAF fast-path SQLi/XXE, status text, duration parsing, sandbox stub, panic counter, pidfile, security observability, mesh attachment)
- 2 clippy issues fixed (lint name correction, pidfile allow attribute)
- `ipc_signed::deserialize_signed` missing 4-byte length prefix handling
- Tarpit `generate_sentence_normal` non-deterministic failure (Markov chain dead-end continues instead of breaking)
- Mesh test key generation: Ed25519 keys via `rcgen::PKCS_ED25519` instead of default ECDSA P-256
- `extract_public_key_from_cert` returning `subject_public_key` for consistency with `verify_certificate_chain`
- CI summary job dynamic expression fix preventing all jobs from running

### Security

- Constant-time comparison enforced via `subtle::ConstantTimeEq` for secrets, keys, MACs, and auth tokens
- File permissions set to `0o600` on private key files
- Plugin ABI memory boundary: guest_alloc/guest_free required; fixed-offset fallback removed
- Plugin signed byte loading: TOCTOU closure with verified bytes owned by `PreparedPluginLoad`
- Unsafe native extensions: disabled by default, production loading requires risk acknowledgement, path allowlist, and optional SHA-256 hash verification
- Honeypot AI responders: no real secrets, mesh state, admin credentials, or environment data leaked; prompt injection resistance
- Tarpit CRLF injection blocking and control character rejection in redirect targets
- Honeypot mesh propagation guardrails: minimum confidence, minimum event count, dedupe keys, TTL
- Threat-intel enforcement paths use policy-strict lookups, never raw diagnostic lookups
- Mesh-ID blocks restricted to admin/control-plane only (not WAF/request/proxy/HTTP-3 code)
- cargo-deny passes; 12 advisory ignores documented with re-audit dates (2026-10-01)

### Known Limitations

- `synvoid-icmp-filter` eBPF (`icmp-ebpf` feature): compiles cleanly, returns explicit error at runtime when eBPF unavailable, falls back to nftables. Not in default profile.
- `--all-features` full workspace check fails on `synvoid-icmp-filter` eBPF dependency resolution. Individual crate checks pass.
- wasmtime 40.0.4 (via yara-x) has known CVEs but is used only for YARA compilation, not the WASM sandbox. 11 advisory ignores in deny.toml with re-audit date 2026-10-01.
- Email alerting is a stub (`src/admin/alerting/mod.rs:349`).
- `spin` idle instance eviction never cleans up old UUID entries.
- DNS: DoQ is experimental. Persistent TCP pipelining, EDNS keepalive, NSEC3 closest-encloser proofs, external DNSSEC tooling, and bailiwick enforcement are deferred.
- DNS: `--all-features` profile fails on `synvoid-icmp-filter` eBPF dependency.

## [1.1.0-rc.1] - 2026-07-12

Pre-release candidate. See [1.1.0] entry above for full details.

## [Unreleased]

No pending changes. All planned work for 1.1.0 is complete.

## [1.0.0] - 2026-02-23

### Initial Release

- Complete WAF and reverse proxy implementation
- Multi-layer attack detection (SQLi, XSS, XXE, path traversal, command injection)
- Comprehensive flood protection (SYN, UDP, ICMP, connection rate limiting)
- High-performance reverse proxying with connection pooling and upstream health checks
- HTTP/3 (QUIC) support
- Admin API with WebSocket support and Prometheus metrics
- Traffic shaping with token bucket algorithm
- Proxy cache for upstream performance
- FastCGI protocol proxying
- TCP/UDP protocol filtering
- Multi-site management from single instance
- Structured JSON logging
- Custom error pages support
- Production-ready deployment guide

## [0.9.0] - 2026-01-15

### Beta Release

- Core WAF functionality
- Basic reverse proxy capabilities
- Initial attack detection rules
- Basic configuration system
- Early documentation

## [0.1.0] - 2025-12-01

### Initial Development

- Project initialization
- Basic structure setup
- Initial feature planning
- Early proof of concept

[Unreleased]: https://github.com/synvoid/synvoid/compare/v1.1.0...HEAD
[1.1.0]: https://github.com/synvoid/synvoid/releases/tag/v1.1.0
[1.0.0]: https://github.com/synvoid/synvoid/releases/tag/v1.0.0
[0.9.0]: https://github.com/synvoid/synvoid/releases/tag/v0.9.0
[0.1.0]: https://github.com/synvoid/synvoid/releases/tag/v0.1.0
