# Networking Architecture Review Plan

## Verified Correct
- **HTTP/3 via Quinn**: Confirmed in `src/http3/server.rs:111-131` and `Cargo.toml:170-172` (quinn 0.11, h3 0.0.8, h3-quinn 0.0.10)
- **QUIC MAX_DATAGRAM_PAYLOAD = 1200**: `src/tunnel/quic/messages.rs:4` - correct
- **ListenerInstance & ConnectionContext**: `src/listener/common.rs:48-84` - structures match documentation
- **TCP Listener**: Actual implementation in `src/tcp/listener.rs` - documentation correct
- **TLS via rustls**: Confirmed throughout codebase (not OpenSSL) - matches documentation
- **AcmeDnsChallenge**: `src/tls/acme_dns.rs:11-64` manages pending challenges with DashMap
- **DNS-01 Challenge Flow**: `src/dns/server/query.rs:677-698` serves TXT records for `_acme-challenge.{domain}`
- **build_acme_txt_response**: `src/dns/server/response.rs:782` - correct function location
- **BufferPool**: `crates/synvoid-utils/src/buffer/pool.rs` - proper ownership-based buffer reuse
- **ConnectionLimiter**: `src/waf/traffic_shaper/limiter.rs` - exists for global/per-IP limiting
- **X25519MLKEM768**: `src/startup/master.rs:211,221` enables post-quantum TLS
- **ML-DSA mesh signatures**: Config field `ml_dsa_private_key_base64` in `src/mesh/config.rs:787`
- **HTTP/2 infrastructure**: `src/http_client/typed_pool.rs:169` uses `http2_only(is_http2)` - documented correctly as "available but not fully enforced"
- **handle_request (H1)**: `src/http/server.rs:661`
- **handle_request_with_cache (H2/TLS)**: `src/tls/server.rs:606` - different signature than H1 handler
- **CertResolver for dynamic certificate selection**: `src/tls/cert_resolver.rs:22`

## Discrepancies Found
- **SiteConnectionLimiter dead code**: `src/waf/traffic_shaper/limiter.rs:306-346` - documentation says this "limits the impact of a surge in traffic" but AGENTS.md confirms it is dead code (struct never instantiated). All HTTP traffic goes through `try_acquire_with_limits()` directly. **This is documented as "Known - not blocking" in AGENTS.md**
- **Shared Handler description imprecision**: Documentation says H1 uses `handle_request in http/server.rs` and H2 uses `handle_request_with_cache in tls/server.rs:606` - this is technically correct but H2/TLS handler has a **different signature** than H1 handler (they are separate implementations with different parameter sets, not just different method names)

## Bugs Identified

### High Severity
**None identified** - No critical networking bugs found in verified code paths

### Medium Severity
**SiteConnectionLimiter parameters ignored**: `src/waf/traffic_shaper/limiter.rs:312-323`
- `_max_connections`, `_max_connections_per_ip`, `_acquisitions_per_mil_lisecond` are never used
- The struct wraps a global `ConnectionLimiter` and doesn't track per-site limits independently
- Not blocking since HTTP path uses `try_acquire_with_limits()` directly, but documentation is misleading
- See `plans/plan.md` for tracking

### Low Severity
**HTTP/2 available but not enforced**: `src/http_client/mod.rs:893`
- `is_http2 = true` hardcoded; infrastructure exists but pooled connections don't fully utilize HTTP/2
- Documented as known limitation - correctly noted in both AGENTS.md and networking document

## Suggested Improvements
- **Clarify SiteConnectionLimiter documentation**: Either remove the per-site limit claim or implement actual per-site tracking
- **Add HTTP/2 connection pooling milestone**: Document when full HTTP/2 pooled connections will be available
- **Protocol detection section**: The docs mention HTTP/1.1, HTTP/2, HTTP/3 but don't describe the automatic protocol detection mechanism at the TLS.handshake layer
- **Connection migration docs**: Mention how QUIC connection migration works (connection IDs allow mobile clients to switch networks)
- **0-RTT documentation**: The networking doc mentions 0-RTT but doesn't explain the security tradeoffs or configuration requirements
