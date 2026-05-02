# Wave 1
- [x] Traffic Layer: Fix Proxy Cache Key, Purge, and Revalidation Semantics (Cache lookup/storage lives in ProxyServer, Stale-while-revalidate URL rebuild, Request-header policy for revalidation, build_cached_response() overwrites Cache-Control).
- [x] WAF/Security Layer: Anomaly Scoring - Duplicated detector runs (scoring re-runs many detectors already run by direct detection).
- [x] WAF/Security Layer: Body Inspection - Multipart boundary parsing for targeted field inspection, Payload-split-across-chunks edge cases in streaming WAF.

# Wave 2 (Architecture Deferred)
- [ ] Full multi-crate workspace decomposition.
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
