# Networking Deep Dives Review Plan

**Reviewed:** 2026-05-28
**Documents:** `architecture/networking_deep_dive.md`, `architecture/listener.md`

## Verified Correct Items

| Claim | Source | Status |
|-------|--------|--------|
| QUIC `MAX_DATAGRAM_PAYLOAD` is 1200 bytes | `src/tunnel/quic/messages.rs:4` | ✅ Correct |
| TLS ALPN detection at `tls/server.rs:410-411` | Lines 410-411 extract ALPN and check `ALPN_HTTP2` | ✅ Correct |
| `ALPN_HTTP2` constant is `b"h2"` | `src/tls/server.rs:54` | ✅ Correct |
| `AcmeDnsChallenge` exists in `src/tls/acme_dns.rs` with DashMap | Lines 11-64 | ✅ Correct |
| ACME DNS-01 challenge served via `_acme-challenge.<domain>` TXT | `src/dns/server/query.rs:698-721` | ✅ Correct |
| `build_acme_txt_response()` at `src/dns/server/response.rs:782` | Line 782 | ✅ Correct |
| DNS-01 feature-gated with `#[cfg(feature = "dns")]` | `src/dns/server/query.rs:698` | ✅ Correct |
| `Http2PooledConnection` exists (empty stub) | `src/http_client/erased_pool.rs:125` | ✅ Correct |
| `SiteConnectionLimiter` dead code claim | Confirmed per AGENTS.md (removed 2026-05-27) | ✅ Correct |
| `BufferPool` with 4 tiers (small/medium/large/jumbo) | `crates/synvoid-utils/src/buffer/pool.rs:23-27` | ✅ Correct |
| `post-quantum` feature flag exists | `Cargo.toml:30` | ✅ Correct |
| `pqc-mesh` feature flag exists | `Cargo.toml:37` | ✅ Correct |
| `verify-pq` feature flag exists | `Cargo.toml:31` | ✅ Correct |
| ML-KEM config with variant, rotation, session TTL, max sessions | `src/mesh/config.rs:1130-1141` | ✅ Correct |
| ML-DSA config at `global_node.ml_dsa_private_key_base64` | `src/mesh/config.rs:787` | ✅ Correct |
| QUIC 0-RTT disabled by default | `src/mesh/config.rs:1390-1394` | ✅ Correct |
| `SocketOptionsBase` defaults: 262KB send/recv | `src/listener/common.rs:13-14` | ✅ Correct |
| `ListenerConfigBase` defaults: port 0, 0.0.0.0 | `src/listener/common.rs:36-37` | ✅ Correct |
| TCP listener at `src/tcp/listener.rs` | File exists, 869 lines | ✅ Correct |
| `verify-pq` feature used in QUIC transport | `src/mesh/transports/quic.rs:31` | ✅ Correct |

## Discrepancies Found

### networking_deep_dive.md

| # | Document Claim | Actual | Severity |
|---|---------------|--------|----------|
| D1 | `src/http_client/mod.rs:893` has `is_http2 = true` | Line 893 is `.unwrap_or_default()`. The `is_http2` parameter is at line 878. No hardcoded `true` exists there. | Low |
| D2 | `mesh.config.quic.enable_0rtt = false` and `mesh.quic.enable_0rtt` (default: false) | Actual config path is `tls.quic_enable_0rtt` (`src/mesh/config.rs:1369`). The document uses incorrect config paths. | Medium |
| D3 | `SiteConnectionLimiter` at `src/waf/traffic_shaper/limiter.rs:306-346` | File is only 304 lines. This struct was removed (per AGENTS.md 2026-05-27). The claim is stale. | Medium |
| D4 | `AcmeDnsChallenge` at `src/tls/acme_dns.rs:11-64` | Actual lines are 11-64 but `AcmeDnsChallenge` struct is at lines 11-14, impl at 16-64. The range is acceptable but imprecise. | Low |
| D5 | ACME DNS TXT served at `src/dns/server/query.rs:679-698` | ACME handling is at lines 698-721 (`#[cfg(feature = "dns")]` block). Lines 679-698 are qname parsing code. | Medium |
| D6 | `mesh.ml_kem` section in `MeshConfig` | Actual field name is `mlkem` (`src/mesh/config.rs:704`), not `ml_kem`. | Low |
| D7 | Feature description says `pqc-mesh` enables ML-DSA-44 for inter-node communication | Feature flag exists in `Cargo.toml` but has **zero** `#[cfg(feature = "pqc-mesh")]` usages in any `.rs` file. The flag is defined but completely unwired. | High |

### listener.md

| # | Document Claim | Actual | Severity |
|---|---------------|--------|----------|
| D8 | `ListenerConfigBase` has `bind_addresses: Vec<String>` | Actual field is `bind_address: String` (singular) with separate `bind_address_v6: Option<String>` (`src/listener/common.rs:23-24`) | High |
| D9 | `ListenerConfigBase` has `expected_protocol: ProtocolType` | Actual field is `expected_protocol: String` (`src/listener/common.rs:27`), not `ProtocolType` enum | High |
| D10 | `ListenerConfigBase` has `upstream_address: Option<String>` | Actual field is `upstream_address: String` (not Optional) with separate `upstream_address_v6: Option<String>` (`src/listener/common.rs:26-27`) | High |
| D11 | `ListenerConfigBase` has `filter_config: Option<FilterConfig>` | Actual fields are `filter_enabled: bool` and `strict_mode: bool` (`src/listener/common.rs:28-29`). No `FilterConfig` type. | High |
| D12 | `ConnectionContext` has `server_name: Option<String>` | Actual field is `server_name: String` (not Optional) (`src/listener/common.rs:65`) | Medium |
| D13 | `ConnectionContext` has `expected_protocol: ProtocolType` | Actual field is `expected_protocol: String` (`src/listener/common.rs:67`) | High |
| D14 | `ListenerConfigBase::default()` documented as "Port 0, 0.0.0.0, unknown protocol" | Default also includes `upstream_address: "127.0.0.1:0"`, `filter_enabled: true`, `strict_mode: true` - these are omitted | Low |
| D15 | Integration points: HTTP Server, HTTP/3, ICMP Filter, Platform | `ListenerConfigBase` is defined and exported but **never instantiated or imported** by any other module. `ListenerInstance<C>` is also never used. | Critical |
| D16 | `ListenerInstance::new(config, listen_addr)` documented as public API | `ListenerInstance::new()` is never called anywhere in the codebase | Medium |

## Bugs Identified

| # | Bug | Location | Severity |
|---|-----|----------|----------|
| B1 | **`pqc-mesh` feature flag is dead**: Defined in `Cargo.toml:37` but no Rust source file uses `cfg(feature = "pqc-mesh")`. ML-DSA signing works without this flag (always compiled). The flag is a no-op. | `Cargo.toml`, all `src/**/*.rs` | High |
| B2 | **`listener/common.rs` module is entirely dead code**: `SocketOptionsBase`, `ListenerConfigBase`, `ListenerInstance<C>`, and `ConnectionContext` are defined and exported but never instantiated or used by any module. TCP/UDP listeners define their own `TcpSocketOptions`, `TcpListenerInstance`, `UdpListenerInstance`. | `src/listener/common.rs` | Medium |
| B3 | **Documentation mismatch on ListenerConfigBase fields**: The listener.md document describes a completely different struct than what exists. Fields don't match types, optionality, or naming. | `architecture/listener.md` vs `src/listener/common.rs` | High |

## Suggested Improvements

### networking_deep_dive.md

1. **Fix 0-RTT config path**: Change `mesh.config.quic.enable_0rtt` and `mesh.quic.enable_0rtt` to `tls.quic_enable_0rtt` to match actual config.
2. **Fix line number for ACME DNS TXT**: Change `src/dns/server/query.rs:679-98` to `src/dns/server/query.rs:698-721`.
3. **Update SiteConnectionLimiter claim**: The dead code was already removed (AGENTS.md 2026-05-27). Update the claim to reflect current state or remove.
4. **Fix `mesh.ml_kem` to `mesh.mlkem`**: Match actual field name.
5. **Add warning about `pqc-mesh` feature**: Document that the feature flag exists but is unwired, or remove mention until it's actually implemented.
6. **Fix `src/http_client/mod.rs:893` reference**: The `is_http2` parameter is at line 878, not 893.

### listener.md

1. **Rewrite struct definitions to match actual code**: The documented structs don't match the source. Either update docs or remove if the module is confirmed dead.
2. **Add dead code note**: If `listener/common.rs` is intentionally dead (perhaps future refactor), document it as such. Otherwise, consider removing the module.
3. **Fix `ConnectionContext.server_name` type**: Should be `String`, not `Option<String>`.
4. **Remove `ProtocolType` references**: `expected_protocol` is `String`, not `ProtocolType` enum.
5. **Remove integration points claim**: None of the listed modules actually use `ListenerConfigBase`.

### Source Code

1. **Evaluate `listener/common.rs` for removal**: All types are dead code. TCP/UDP listeners have their own types. Consider deleting the module or actually integrating it.
2. **Wire or remove `pqc-mesh` feature**: Either add `#[cfg(feature = "pqc-mesh")]` guards around ML-DSA code, or remove the feature flag from `Cargo.toml`.

## Stale Content

| Item | Location | Issue |
|------|----------|-------|
| `SiteConnectionLimiter` at `limiter.rs:306-346` | networking_deep_dive.md:82 | Struct was removed (2026-05-27). File is 304 lines. |
| `mesh.config.quic.enable_0rtt` config path | networking_deep_dive.md:16 | Wrong path. Actual: `tls.quic_enable_0rtt`. |
| `mesh.quic.enable_0rtt` config path | networking_deep_dive.md:16 | Wrong path. Actual: `tls.quic_enable_0rtt`. |
| `mesh.ml_kem` config section | networking_deep_dive.md:60 | Wrong field name. Actual: `mesh.mlkem`. |
| Integration points in listener.md | listener.md:59-62 | `ListenerConfigBase` is not used by any listed module. |

## Cross-Reference Status

| AGENTS.md Entry | Document Coverage | Notes |
|----------------|-------------------|-------|
| `Http2PooledConnection` is empty stub | networking_deep_dive.md:10 | ✅ Covered |
| `SiteConnectionLimiter` dead code | networking_deep_dive.md:82 | ⚠️ Stale - code was removed, doc still references line numbers |
| BufferPool 4 tiers | networking_deep_dive.md:77,86 | ✅ Covered |
| `post-quantum` feature flag | networking_deep_dive.md:59,68 | ✅ Covered |
| `pqc-mesh` feature flag | networking_deep_dive.md:69 | ⚠️ Documented but flag is unwired (no cfg usage) |
| `verify-pq` feature flag | networking_deep_dive.md:70 | ✅ Covered, used in `quic.rs:31` |
| ML-KEM key exchange | networking_deep_dive.md:58 | ✅ Covered, config field is `mlkem` not `ml_kem` |
| ML-DSA signatures | networking_deep_dive.md:63-64 | ✅ Covered |
| ACME DNS-01 challenge | networking_deep_dive.md:36-52 | ✅ Covered |
| QUIC 0-RTT disabled by default | networking_deep_dive.md:16 | ✅ Behavior correct, config path wrong |
