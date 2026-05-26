# Routing Architecture Review Plan

## Verified Correct
- **Matching Hierarchy**: Document correctly describes the routing flow: listener default -> exact domain match -> wildcard/suffix match -> default server fallback -> path-based location matching (lines 1126-1221 in router.rs)
- **Reverse-Domain Radix Tree**: Correctly described. The router uses `matchit::MatchRouter` with reversed domain names for wildcard/suffix matching (router.rs:34, 179, 274-277, 1377-1381)
- **BackendType enum**: Has 11 variants as documented (Upstream, FastCgi, Php, Cgi, AxumDynamic, AppServer, Static, QuicTunnel, Serverless, Mesh, Spin) - src/router.rs:65-78
- **Load Balancing Algorithms**: All 6 documented algorithms exist and are implemented:
  - RoundRobin (default) - pool.rs:51
  - Random - pool.rs:52
  - LeastConnections - pool.rs:53
  - PeakEwma - pool.rs:54
  - WeightedRoundRobin - pool.rs:55
  - IpHash - pool.rs:56
- **PeakEwma Formula**: The document correctly states the cost formula `(conn + 1) * (latency + 1)` which is implemented at pool.rs:520-521
- **Health Monitoring**: 
  - Active health checks via periodic HTTP GET/HEAD/TCP connect exist (health.rs:71-97, 176-240)
  - Passive health checks via `record_success()` and `record_failure()` exist (pool.rs:307-335)
- **Connection Limits**: Backend enforces max_connections with `increment_connections()`/`decrement_connections()` (pool.rs:157, 283, 287-301)
- **Backup Servers**: `is_backup` flag and `new_backup()` constructor exist (pool.rs:163, 242, 256-257)
- **Connection Lifecycle**: increment/decrement connection flow correctly implemented (pool.rs:287-301)

## Discrepancies Found
- **Line Reference Error**: Document references `parse_quictunnel_url()` at lines 513-532 but actual function is at lines 512-532 (off by one)
- **PeakEwma Line Reference**: Document references pool.rs:48-57 for the PeakEwma formula, but lines 48-57 only contain the LoadBalanceAlgorithm enum definition. The actual cost formula implementation is at lines 520-521 in the `apply_algorithm` method

## Bugs Identified
- **None identified** - The routing and upstream pool implementation appears to correctly match the documented architecture

## Suggested Improvements
- **Update Line References**: Fix the `parse_quictunnel_url()` line reference from 513-532 to 512-532 in the architecture document
- **Fix PeakEwma Reference**: Update the line reference from 48-57 to 520-528 where the actual PeakEwma cost calculation formula `(conn + 1) * (latency + 1)` is implemented
- **Consider Adding Metric Labels**: The architecture document mentions connection limits but could document the `max_load_percent` health check threshold (health.rs:26, 45) which is an additional resilience mechanism
- **Document IP-Based Routing**: The architecture describes listener-level defaults but does not mention the IP-specific domain maps (`ip_domain_map`, `ip_wildcard_routers`) which enable per-IP virtual host routing (router.rs:40-43, 349-394)
