# Overview & Methodology Review Plan

**Reviewed:** 2026-05-28
**Documents:** `architecture/overview.md`, `architecture/deep_dive_review.md`

## Verified Correct Items

- **Feature gates**: All 12 feature gates in overview.md match Cargo.toml (`dns`, `mesh`, `socket-handoff`, `erased_pool`, `swagger-ui`, `post-quantum`, `wireguard`, `icmp-filter`, `flood-ebpf`, `macos-sandbox`, `pqc-mesh`, `fastcgi_streaming`)
- **Default features**: All 5 default features correctly identified (`socket-handoff`, `mesh`, `dns`, `erased_pool`, `swagger-ui`)
- **Attack detectors**: 13 attack types confirmed (SQLi, XSS, PathTraversal, RFI, SSRF, SSTI, CmdInjection, XXE, JWT, RequestSmuggling, LdapInjection, XPathInjection, OpenRedirect)
- **Load balancing**: 6 algorithms confirmed (RoundRobin, Random, LeastConnections, PeakEwma, WeightedRoundRobin, IpHash)
- **BackendType**: 11 variants confirmed (Upstream, FastCgi, Php, Cgi, AxumDynamic, AppServer, Static, QuicTunnel, Serverless, Mesh, Spin)
- **IPC security**: HMAC session key signing verified in `src/process/ipc_signed.rs`, SO_PEERCRED in `src/process/ipc_transport.rs:54`
- **SO_REUSEPORT**: Used for zero-downtime upgrades in HTTP, HTTPS, and HTTP/3 listeners
- **CPU pinning**: `sched_setaffinity` implemented in `src/worker/unified_server.rs:186`
- **Sandbox backends**: All 5 verified — Landlock (`linux`), Pledge (`openbsd`), Capsicum (`freebsd`), Seatbelt (`macos`), Windows Job Objects
- **ThreatLevelManager**: Exists at `src/waf/threat_level/mod.rs:116`, used across WAF, supervisor, admin modules
- **rkyv zero-copy**: Extensively used in mesh module (123+ references across DHT, protocol, config, behavioral types)
- **BufferPool**: Confirmed 4-tier sharded design in `crates/synvoid-utils/src/buffer/pool.rs:211`
- **LocationMatcher**: Exists at `src/location_matcher.rs:119`
- **ReDoS prevention**: `check_regex_complexity()` in `src/utils.rs:758`, used in location_matcher, waf endpoints, RFI detection
- **Path traversal prevention**: `canonicalize()` + prefix check in `src/static_files/mod.rs:355`
- **JA3/JA4 fingerprinting**: JA4 computation in `src/tls/sni_peek.rs:180`, bot detection in `src/waf/bot.rs`
- **Tarpit Markov chain**: `MarkovChain` in `src/tarpit/generator.rs:20`, `TarpitHandler` in `src/tarpit/handler.rs:8`
- **Architecture files**: All 55+ referenced architecture docs verified to exist (except 2 noted below)
- **External docs**: `SECURITY.md`, `docs/adr/`, `plans/plan.md`, `skills/` all verified present
- **Project structure**: All top-level directories exist as documented

## Discrepancies Found

| # | Location | Claim | Actual | Severity |
|---|----------|-------|--------|----------|
| D1 | overview.md:269 | `src/proxy/mod.rs` ~400 lines | 1,450 lines | Medium — line count 3.6x understated |
| D2 | overview.md:272 | `src/supervisor/mod.rs` ~800 lines | 17 lines | High — file is just re-exports; real logic in `supervisor/process.rs` |
| D3 | overview.md:273 | `src/admin/mod.rs` ~2000+ lines | 972 lines | Medium — line count ~2x overstated |
| D4 | overview.md:274 | `src/tls/server.rs` ~1700 lines | 2,281 lines | Low — 34% understated |
| D5 | overview.md:275 | `src/http_client/mod.rs` ~900 lines | 1,307 lines | Low — 45% understated |
| D6 | overview.md:276 | `src/upstream/pool.rs` ~800 lines | 1,540 lines | Low — 93% understated |
| D7 | overview.md:277 | `src/plugin/mod.rs` ~700 lines | 424 lines | Low — 39% overstated |
| D8 | overview.md:278 | `crates/synvoid-config/src/lib.rs` ~500 lines | 447 lines | Low — close |
| D9 | overview.md:271 | `src/mesh/` ~15000+ lines | ~48,190 lines | Medium — 3x understated |
| D10 | deep_dive_review.md:48 | Claims `io_uring` used via Tokio | No io_uring references found in source | High — unverifiable claim |

## Bugs Identified

| # | Location | Issue | Severity |
|---|----------|-------|----------|
| B1 | overview.md:174 | References `architecture/tunnel.md` — file does not exist | Medium — broken link in module index |
| B2 | overview.md:210 | References `architecture/admin.md` — file does not exist (only `admin_deep_dive.md`) | Medium — broken link in module index |
| B3 | overview.md:224 | References `architecture/serder.md` — filename is a typo ("serder" not "serde") | Low — file exists with misspelled name |
| B4 | overview.md feature gates | 7 feature gates in Cargo.toml undocumented: `origin_key_exchange`, `audit`, `verify-pq`, `tun-rs`, `buffer`, `rkyv`, `test-utils` | Medium — incomplete feature documentation |
| B5 | `src/honeypot_unified/mod.rs` | Directory exists (215 lines) but NOT declared in `src/lib.rs` — dead code, never compiled | Medium — stale module |
| B6 | deep_dive_review.md:49 | Claims Windows supports `SO_REUSEPORT` — code uses platform-specific socket2 configuration, not literally SO_REUSEPORT | Low — misleading description |

## Suggested Improvements

1. **Update line counts**: Revise the Key Source Files table in overview.md to match actual line counts
2. **Fix broken links**: Either create `architecture/tunnel.md` and `architecture/admin.md`, or remove references from the module index
3. **Fix filename typo**: Rename `architecture/serder.md` to `architecture/serde.md` or acknowledge the typo
4. **Document all feature gates**: Add the 7 undocumented feature gates to the Feature Gates table
5. **Remove dead code**: Either add `pub mod honeypot_unified;` to `src/lib.rs` or delete `src/honeypot_unified/`
6. **Verify io_uring claim**: The deep_dive_review.md io_uring reference cannot be verified — either cite specific Tokio internals or remove the claim
7. **Clarify Windows socket options**: deep_dive_review.md should describe Windows IPC as using named pipes and platform-specific socket options, not literally `SO_REUSEPORT`

## Stale Content

| Item | Location | Issue |
|------|----------|-------|
| `src/honeypot_unified/` | Source tree | Dead module not compiled — never declared in lib.rs |
| `architecture/tunnel.md` | overview.md:174 | Referenced but does not exist |
| `architecture/admin.md` | overview.md:210 | Referenced but does not exist |
| Line count estimates | overview.md:266-278 | All significantly outdated |
| io_uring reference | deep_dive_review.md:48 | Cannot be verified in source code |

## Cross-Reference Status

| Reference | Status | Notes |
|-----------|--------|-------|
| AGENTS.md → mesh module path | ✅ Verified | `src/mesh/` exists, ~48k lines |
| AGENTS.md → ConfigManager location | ✅ Verified | `crates/synvoid-config/src/lib.rs` |
| AGENTS.md → BufferPool 4 tiers | ✅ Verified | small/medium/large/jumbo in `pool.rs` |
| AGENTS.md → ThreatLevelManager | ✅ Verified | `src/waf/threat_level/mod.rs:116` |
| AGENTS.md → MeshProxy | ✅ Verified | `src/mesh/proxy.rs:63` |
| AGENTS.md → BackendType 11 variants | ✅ Verified | `src/router.rs:66-78` |
| overview.md → architecture/ docs | ⚠️ 2 broken links | tunnel.md, admin.md missing |
| overview.md → external docs | ✅ All verified | SECURITY.md, ADRs, plans, skills all exist |
| overview.md → feature gates | ⚠️ 7 undocumented | origin_key_exchange, audit, verify-pq, tun-rs, buffer, rkyv, test-utils |
| deep_dive_review → IPC HMAC | ✅ Verified | `ipc_signed.rs` with HMAC-SHA3-256 |
| deep_dive_review → SO_PEERCRED | ✅ Verified | `ipc_transport.rs:54` |
| deep_dive_review → SO_REUSEPORT | ✅ Verified | Used in HTTP, HTTPS, HTTP/3 listeners |
| deep_dive_review → CPU pinning | ✅ Verified | `sched_setaffinity` in unified_server.rs |
| deep_dive_review → io_uring | ❌ Unverified | No io_uring references in source |
