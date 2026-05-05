# WAF Module - AGENTS.override.md

Specialized guidance for WAF engine and attack detection.

## Hot Path

`src/waf/attack_detection/` — WAF rule matching runs per-request on all inputs. Critical hot path:
- Every allocation compounds at 1000K rps
- Avoid O(n) operations; prefer O(1) lookups
- Use thread-local buffers and object pools

## Module-Specific Patterns

### Rule Matching

- Rule matching executes on every input for every request
- Use `HashMap`/`HashSet` for rule lookups
- Lazy evaluation for rule parsing

### Attack Detection Action Semantics

`check_attack_patterns()` reads action from config:
- `stall` (default): returns `WafDecision::Stall`
- `block`: returns `WafDecision::Block(403, "Forbidden")`
- `log`: records metrics but returns `None` (request passes)

### Trusted Proxy XFF Handling

`get_real_ip()` and `find_client_ip_in_xff()` must scan XFF right-to-left:
- First trusted proxy marks the trusted suffix boundary
- Client is the first untrusted public IP immediately before the trusted suffix
- Never return `ips[0]` - standard XFF order is `client, proxy1, proxy2`

### Body Inspection UTF-8 Hardening

When inspecting request body, use `String::from_utf8_lossy()` instead of `unwrap_or("")`:
```rust
// WRONG - invalid UTF-8 becomes empty string, evading detection
let body_str = std::str::from_utf8(body).unwrap_or("");

// CORRECT - invalid bytes replaced with U+FFFD
let body_str = String::from_utf8_lossy(body);
```

### Serverless Mode

Use `ServerlessWafMode` enum (`enforce|log|off`) instead of boolean `serverless_only`:
- `enforce`: WAF always active
- `log`: WAF runs but doesn't block
- `off`: WAF disabled

### Stall/Tarpit Concurrency Safety

Stall actions can exhaust worker resources at high traffic. Use bounded stall with metrics:
- `max_stalled_requests` config limits concurrent stalls (default 100)
- Metrics: `ACTIVE_STALLED_REQUESTS`, `STALL_REJECTED_CONCURRENCY_CAP`, `STALL_TIMEOUTS`
- When cap reached, return 429 instead of stalling

See `skills/performance_patterns.md` for implementation details.

## Skills Reference

- `skills/streaming_waf.md` — Streaming WAF engine patterns
- `skills/security_patterns.md` — Constant-time comparison, path traversal, XSS prevention