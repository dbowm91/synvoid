# Wave 1
- [x] Traffic Layer: Fix Proxy Cache Key, Purge, and Revalidation Semantics (Cache lookup/storage lives in ProxyServer, Stale-while-revalidate URL rebuild, Request-header policy for revalidation, build_cached_response() overwrites Cache-Control).
- [x] WAF/Security Layer: Anomaly Scoring - Duplicated detector runs (scoring re-runs many detectors already run by direct detection).
- [x] WAF/Security Layer: Body Inspection - Multipart boundary parsing for targeted field inspection, Payload-split-across-chunks edge cases in streaming WAF).

# Wave 3 (Systems Layer Deferred)
- [ ] Deep WireGuard/TUN backend work, except where platform compile checks require gating.

# Wave 4 (Distributed Layer Deferred)
- [ ] Performance tuning of DHT routing and regional quorum selection.
- [ ] Major Raft storage schema changes unrelated to auth metadata.
- [ ] New mesh admin APIs for manual quorum or Raft management.
- [ ] Changing the public wire protocol beyond the minimum needed for signed context and auth.

# Note: Wave 2 removed (admin UI/API redesign, config schema, performance rewrites - not aligned with 100k node target)

# Completed Items (Zero-Copy Validation)
- [x] Zero-copy streaming for HTTP proxy is correctly implemented using BufferPool
- [x] HTTP server uses 1MB threshold for zero-copy streaming
- [x] Static files use 4KB threshold but uses Buffered variant (not true sendfile)
- **Note**: Static file `into_bytes()` reads entire file into memory - would require deeper refactoring of HTTP response handling to properly use sendfile syscall