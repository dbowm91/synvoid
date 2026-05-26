# Worker Architecture Review Plan

## Verified Correct

- **UnifiedServer struct**: Correctly defined at `src/server/mod.rs:47` with all documented components (TCP/UDP pools, WAF, TLS config, etc.)
- **HTTP/1.1 Support**: Full support via HttpServer in `src/server/mod.rs`
- **HTTP/2 ALPN Negotiation**: Correctly implemented at `src/tls/server.rs:410-487` with ALPN protocol detection
- **HTTP/3 via Quinn**: Implemented via `run_http3_server_inner` at `src/server/mod.rs:1264-1298`
- **TCP & UDP Proxying**: `TcpListenerPool` and `UdpListenerPool` exist at `src/server/mod.rs:55-56`
- **Listener Pools**: Both TcpListenerPool and UdpListenerPool are properly configured and started
- **WAF Pipeline Order (verified)**: `src/waf/mod.rs:442-516` shows correct order:
  1. Block Store Check (line 456)
  2. Rate Limits (line 460)
  3. Endpoint Block (line 464)
  4. Honeypot Detection (line 468)
  5. Bot Protection (line 472) - challenges issued inline via `challenge_manager`
  6. Flood Protection (line 476-484)
  7. Attack Detection (line 486-514)
- **Buffer Pooling**: `BufferPool` is used throughout codebase (`src/buffer/pool.rs`, referenced in 49 locations)
- **Granian Integration**: App servers (Granian supervisors) are initialized in UnifiedServerWorker at `src/worker/unified_server.rs:459-496`
- **UnifiedServerWorker Process**: Defined in `src/process/mod.rs:76` and implemented in `src/worker/unified_server.rs`
- **Worker Pool Management**: `src/worker_pool/mod.rs` correctly implements WorkerPool with load balancing algorithms (RoundRobin, LeastConnections)
- **Process Architecture**: Matches AGENTS.md description - Supervisor manages Master which spawns UnifiedServerWorker processes
- **Single Tokio Event Loop**: UnifiedServerWorker uses single Tokio async runtime as documented

## Discrepancies Found

- **WAF Pipeline Stage 5 Wording**: Document says "Challenges are issued inline within bot protection via `challenge_manager.generate_challenge_page()` within `check_bot_protection()`" - this is CORRECT but the implementation detail is at `src/waf/mod.rs:634-695` where `check_bot_protection()` returns `WafDecision::Challenge` or `WafDecision::ChallengeWithCookie`

- **Upstream Health Monitoring Wording**: Document says "Primarily passive - monitors backend responses for failures/successes. Active health checks (periodic HTTP GET/TCP connect) are configurable but not the primary mechanism." - Code at `src/upstream/pool.rs:765-782` shows `enable_health_check()` and `start_health_check()` exist but must be explicitly called. This confirms active checks are not default, supporting the "primarily passive" characterization.

## Bugs Identified

### Medium - HTTP/2 Upstream Hardcoded
- **Location**: `src/http_client/mod.rs:893`
- **Issue**: `is_http2 = true` is hardcoded, forcing HTTP/2 for all upstream connections
- **Impact**: Cannot use HTTP/1.1 for upstream when needed (e.g., for older backends that don't support h2)
- **Status**: Known issue documented in `plans/plan.md:147`

## Suggested Improvements

- **Add health check status to admin API**: Currently no endpoint to view if active health checks are enabled/disabled for upstream pools
- **Document the `worker_pool` module purpose**: The `src/worker_pool/` directory appears to be a separate worker pool implementation (for managing Worker processes) distinct from the UnifiedServerWorker - this distinction should be clarified in architecture docs
- **Clarify scaling guidance**: The architecture doc mentions "tune `tcp.worker_pool_size`" but this parameter is for the TCP listener pool threads, not the overall worker scaling. Consider adding more explicit guidance on the relationship between `tcp.worker_pool_size`, `unified_server_workers`, and actual scaling needs
- **Document Buffer Pool implementation**: The architecture mentions "Buffer Pooling" but doesn't specify the implementation location - it would help to note that `synvoid_utils::buffer::pool::BufferPool` is the implementation
- **Add sequence diagram for worker startup**: The architecture describes the flow but a sequence diagram showing UnifiedServerWorker initialization would clarify the process hierarchy
