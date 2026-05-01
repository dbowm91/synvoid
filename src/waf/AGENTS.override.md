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

## Skills Reference

- `skills/streaming_waf.md` — Streaming WAF engine patterns
- `skills/security_patterns.md` — Constant-time comparison, path traversal, XSS prevention