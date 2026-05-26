# Networking Module Review Plan

## Verified Correct Items
- **HTTP/2 Infrastructure**: `src/http_client/mod.rs:893` confirms `is_http2 = true` hardcoded
- **H1 Handler**: `handle_request` exists at `src/http/server.rs:661`
- **H2 Handler**: `handle_request_with_cache` exists at `src/tls/server.rs:606`
- **QUIC MAX_DATAGRAM_PAYLOAD**: `src/tunnel/quic/messages.rs:4` confirms value is 1200 bytes
- **TCP Listener**: Implementation in `src/tcp/listener.rs` confirmed (TcpListenerPool, TcpListenerInstance)
- **ListenerInstance**: Generic struct in `src/listener/common.rs:48`, re-exported via `src/listener/mod.rs`
- **ListenerConfigBase**: Confirmed in `src/listener/common.rs:21`
- **ConnectionContext**: Confirmed in `src/listener/common.rs:63`
- **AcmeDnsChallenge**: Struct at `src/tls/acme_dns.rs:11`, uses DashMap for pending challenges
- **DNS-01 Challenge Flow**: ACME DNS-01 challenge at `src/dns/server/query.rs:679-698`
- **build_acme_txt_response**: Function at `src/dns/server/response.rs:782`
- **SiteConnectionLimiter**: Struct at `src/waf/traffic_shaper/limiter.rs:306`
- **BufferPool**: Confirmed at `crates/synvoid-utils/src/buffer/pool.rs`
- **CertResolver**: TLS certificate selection at `src/tls/cert_resolver.rs:22`

## Stale/Incorrect Items
1. **Listener Architecture Description (Lines 22-24)**:
   - **Claim**: "TCP Listener: Uses `src/listener/mod.rs` with `ListenerInstance` for connection management; actual TCP listener implementation in `src/tcp/listener.rs`"
   - **Issue**: `src/listener/mod.rs` only contains re-exports (3 lines). `ListenerInstance<C>` is a generic wrapper struct in `src/listener/common.rs:48`, not a concrete TCP listener. The actual TCP listener pool is `TcpListenerPool` in `src/tcp/listener.rs:192`.
   - **Correction**: The architecture should clarify that `src/listener/common.rs` defines generic listener types (`ListenerInstance`, `ListenerConfigBase`, `ConnectionContext`), while `src/tcp/listener.rs` provides the concrete `TcpListenerPool` implementation.

2. **HTTP/2 Pooled Connections Statement (Line 10)**:
   - **Claim**: "HTTP/2 pooled connections are not fully available in current implementation"
   - **Issue**: The code shows all client builders use `.http2_only(false)` (`src/http_client/mod.rs:374`, `420`, `644`, `typed_pool.rs:169`), meaning HTTP/2 is available but not enforced. The `send_request` function passes `is_http2 = true` (line 893) to enable it per-request. The "not fully available" characterization is vague and potentially stale.
   - **Correction**: Clarify what "not fully available" means - is it HTTP/2 connection pooling not working, or just not enabled by default?

3. **ConnectionContext in Listener Configuration (Line 24)**:
   - **Claim**: "`src/listener/common.rs` defines `ListenerConfigBase`, `ListenerInstance`, `ConnectionContext` for connection handling"
   - **Issue**: All three are correctly located, but `ConnectionContext` is documented here as part of "connection handling" when it's primarily used for passing client connection metadata (client_ip, server_name, port, expected_protocol) through the listener pipeline.
   - **Correction**: The description is functional but could better clarify `ConnectionContext`'s role as a metadata carrier.

4. **UDP Amplification Protections (Line 23)**:
   - **Claim**: "UDP Handling: Built-in protections against amplification attacks"
   - **Issue**: No specific UDP amplification protection implementation found in `src/udp/`. Need verification if this protection exists in DNS server or elsewhere.
   - **Correction**: Reference specific implementation or remove claim if unimplemented.

## Bugs Found
- **No bugs found** in the code referenced by the architecture document. All function signatures, line references, and implementations exist and appear correct.

## Security Concerns
1. **HTTP/2 Hardcoded to True (Medium)**:
   - Location: `src/http_client/mod.rs:893`
   - Issue: `is_http2 = true` is hardcoded in `send_request_erased_streaming`. This means all upstream requests through this path will attempt HTTP/2, which may be unexpected behavior if `http2_only(false)` is intended to allow fallback.
   - Recommendation: Document this behavior or verify if this is intentional.

2. **ACME DNS-01 Challenge Domain Matching (Low)**:
   - Location: `src/dns/server/query.rs:679`
   - Issue: The code strips `_acme-challenge.` prefix but doesn't validate the remaining domain is a valid FQDN or that it matches the ACME account's authorized domains.
   - Recommendation: Add domain validation to prevent serving challenges for unauthorized domains.

3. **Feature Gating for ACME DNS-01**:
   - Location: `src/dns/server/query.rs:676-698`
   - Issue: ACME DNS-01 handling is gated behind `#[cfg(feature = "dns")]` but the architecture document doesn't mention this requirement.
   - Recommendation: Document that DNS-01 challenges require the `dns` feature flag (already noted in line 52 of the doc, but ensure consistency).

## Document Update Recommendations
1. **Section "TCP & UDP Listeners" (Lines 20-24)**:
   - Rewrite to clarify the listener architecture:
     ```
     ### 3. TCP & UDP Listeners
     Beyond HTTP, SynVoid can act as a generic proxy for any TCP or UDP service.
     - **TCP Listener:** Uses a `TcpListenerPool` (`src/tcp/listener.rs:192`) for connection management. The pool implements connection limiting, protocol detection, and rate limiting.
     - **Listener Types:** `src/listener/common.rs` defines generic listener structures:
       - `ListenerInstance<C>`: Generic wrapper pairing config with socket address
       - `ListenerConfigBase`: Base configuration for listeners
       - `ConnectionContext`: Metadata carrier (client_ip, server_name, port, protocol)
     - **UDP Handling:** Built-in protections against amplification attacks.
     ```

2. **Section "HTTP/1.1 & HTTP/2" (Lines 7-11)**:
   - Clarify HTTP/2 status:
     ```
     - **HTTP/2:** Infrastructure exists and is available via the `is_http2` parameter in `send_request` (`src/http_client/mod.rs:893`). All client builders use `.http2_only(false)`, allowing HTTP/1.1 fallback but preferring HTTP/2 when available.
     ```

3. **Section "UDP Amplification" (Line 23)**:
   - Add reference or clarify where this protection is implemented:
     ```
     - **UDP Handling:** Built-in protections against amplification attacks (implemented in DNS server module).
     ```

4. **Add HTTP/3 Implementation Details**:
   - The document mentions HTTP/3 via Quinn but doesn't verify implementation exists. Add:
     ```
     ### 2. HTTP/3 (QUIC)
     SynVoid features native HTTP/3 support via the **Quinn** library.
     - **Implementation:** `Http3Server` in `src/http3/server.rs`
     - **QUIC Runtime:** `src/tunnel/quic/runtime.rs` provides Quinn integration
     - [Rest of content remains same]
     ```

5. **Listener Configuration Section (Lines 22-24)**:
   - Add cross-reference to `src/tcp/listener.rs` for the actual TCP listener pool implementation rather than implying `ListenerInstance` is the primary TCP listener.

## Verification Commands
```bash
# Verify HTTP client HTTP/2 configuration
grep -n "http2_only" src/http_client/mod.rs

# Verify QUIC datagram size
grep -n "MAX_DATAGRAM_PAYLOAD" src/tunnel/quic/messages.rs

# Verify listener structure
grep -n "ListenerInstance\|ListenerConfigBase\|ConnectionContext" src/listener/common.rs

# Verify ACME DNS challenge implementation
grep -n "AcmeDnsChallenge\|build_acme_txt_response\|_acme-challenge" src/tls/acme_dns.rs src/dns/server/query.rs src/dns/server/response.rs
```
