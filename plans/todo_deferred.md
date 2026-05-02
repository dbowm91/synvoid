# Wave 1
- [x] Traffic Layer: Fix Proxy Cache Key, Purge, and Revalidation Semantics (Cache lookup/storage lives in ProxyServer, Stale-while-revalidate URL rebuild, Request-header policy for revalidation, build_cached_response() overwrites Cache-Control).
- [x] WAF/Security Layer: Anomaly Scoring - Duplicated detector runs (scoring re-runs many detectors already run by direct detection).
- [x] WAF/Security Layer: Body Inspection - Multipart boundary parsing for targeted field inspection, Payload-split-across-chunks edge cases in streaming WAF.

# Wave 2 (Architecture Deferred)
- [ ] Full multi-crate workspace decomposition.
  - **Attempted 2026-05-02**: WAF module extraction failed due to extensive cross-dependencies on main crate modules (config, auth, challenge, block_store, geoip, mesh, tarpit, metrics, utils, theme, upload, http_client). WAF module is too tightly coupled at the type level.
  - **Recommendation**: Only extract truly self-contained parts (attack_detection patterns, ratelimit core) while keeping WafCore in main crate.
- [ ] Moving mesh control-plane into a separate process.
- [ ] Moving plugin/serverless execution into a separate process.
- [ ] Replacing the admin UI/API architecture.
- [ ] A full config schema redesign.
- [ ] Replacing Tokio/Hyper/Quinn foundations.
- [ ] Large performance rewrites beyond routing/location hot-path cleanup.

# Wave 3 (Systems Layer Deferred)
- [ ] Full service-manager polish for systemd/launchd/Windows SCM beyond compile and basic behavior.
- [ ] Large-scale performance tuning outside IPC framing and buffer pool safety.
- [ ] Replacing all shell-outs across the repository.
- [ ] Deep WireGuard/TUN backend work, except where platform compile checks require gating.
- [ ] New admin APIs for platform capability reporting.

# Wave 4 (Distributed Layer Deferred)
- [ ] Performance tuning of DHT routing and regional quorum selection.
- [ ] Major Raft storage schema changes unrelated to auth metadata.
- [ ] New mesh admin APIs for manual quorum or Raft management.
- [ ] Changing the public wire protocol beyond the minimum needed for signed context and auth.

# Completed Items (Zero-Copy Validation)
- [x] Zero-copy streaming for HTTP proxy is correctly implemented using BufferPool
- [x] HTTP server uses 1MB threshold for zero-copy streaming
- [x] Static files use 4KB threshold but uses Buffered variant (not true sendfile)
- **Note**: Static file `into_bytes()` reads entire file into memory - would require deeper refactoring of HTTP response handling to properly use sendfile syscall