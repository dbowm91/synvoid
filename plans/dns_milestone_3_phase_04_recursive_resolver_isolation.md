# DNS Milestone 3 Phase 4: Recursive Resolver Isolation and Safety

## Objective

Harden recursive DNS behavior so it remains explicitly opt-in, isolated from authoritative serving, resistant to open-resolver misconfiguration, and clear about DNSSEC validation status. This phase focuses on recursive policy boundaries, cache separation, upstream resolution behavior, trust anchors, AD/CD semantics, bailiwick, and safe defaults.

## Context

Milestone 2 verified that recursive defaults are safe and that cache namespaces separate authoritative and recursive data. Milestone 3 should now make recursive behavior trustworthy enough for controlled deployment profiles without accidentally turning Synvoid into an open resolver.

## Non-goals

Do not implement a full resolver comparable to Unbound/BIND unless already close. Do not claim production recursive validation unless proven. Do not conflate authoritative DNSSEC signing with recursive DNSSEC validation.

## Primary files

- `crates/synvoid-dns/src/recursive.rs`
- `crates/synvoid-dns/src/recursive_cache.rs`
- `crates/synvoid-dns/src/resolver.rs`
- `crates/synvoid-dns/src/resolver_global.rs`
- `crates/synvoid-dns/src/dnssec_validation.rs`
- `crates/synvoid-dns/src/trust_anchor.rs`
- `crates/synvoid-dns/src/cache.rs`
- `crates/synvoid-dns/src/server/query.rs`
- `crates/synvoid-config/src/dns/dns_recursive.rs`
- recursive isolation tests and docs

## Workstream 1: Recursive deployment profile and defaults

Tasks:

- Confirm recursive mode is disabled by default.
- Confirm recursive listener bind address defaults to loopback or otherwise safe local binding.
- Confirm allowlist policy is required before serving non-local clients.
- Add validation that refuses unsafe recursive exposure unless explicitly acknowledged.
- Document safe local-recursive and internal-network-recursive profiles.

Tests:

- default config recursive disabled.
- recursive enabled without allowlist refuses external clients.
- unsafe bind/allow-all config fails validation unless explicit override exists.
- authoritative no-zone path remains REFUSED when recursion disabled.

Acceptance criteria:

- default config cannot become an open resolver.

## Workstream 2: Authoritative/recursive routing boundary

Tasks:

- Define exact routing order when both authoritative and recursive modes are enabled.
- Ensure served authoritative zones never leak into upstream recursion incorrectly.
- Ensure no-zone authoritative queries recurse only when recursion is enabled and client is allowed.
- Ensure REFUSED/NODATA/NXDOMAIN semantics are clear when recursion is disabled.
- Add metrics for authoritative versus recursive path selection.

Tests:

- served-zone query uses authoritative path.
- no-zone query with recursion disabled returns REFUSED.
- no-zone query with recursion enabled and allowed uses recursive path.
- no-zone query with recursion enabled but disallowed returns REFUSED.

Acceptance criteria:

- path selection is deterministic and documented.

## Workstream 3: Recursive cache semantics

Tasks:

- Ensure recursive cache namespace cannot collide with authoritative cache.
- Store validation state where applicable: secure, insecure, bogus, unchecked.
- Store upstream source metadata safely.
- Implement or document negative caching policy for recursive responses.
- Avoid caching SERVFAIL/REFUSED unless explicitly configured.
- Ensure DNSSEC DO/CD/AD response shape does not collide across cache keys.

Tests:

- recursive and authoritative cache entries cannot collide.
- recursive negative cache respects configured policy.
- recursive SERVFAIL not cached by default.
- DO/CD/AD dimensions are safe or explicitly excluded.

Acceptance criteria:

- recursive cache cannot serve unsafe or wrong-context data.

## Workstream 4: Upstream resolver behavior

Tasks:

- Audit upstream selection policy.
- Enforce per-upstream timeout, retry count, and concurrency limit.
- Implement circuit breaker or backoff for unhealthy upstreams if not present.
- Avoid query amplification through excessive retries.
- Enforce max CNAME chain and recursion depth.
- Ensure client query IDs are not blindly reused upstream if privacy/security policy says otherwise.

Tests:

- upstream timeout returns deterministic response.
- retry count bounded.
- unhealthy upstream backed off or marked degraded.
- CNAME loop/depth limited.
- malformed upstream response rejected.

Acceptance criteria:

- recursive path is bounded and cannot amplify failures indefinitely.

## Workstream 5: Bailiwick and response validation

Tasks:

- Audit bailiwick rules for authority and additional records.
- Reject unrelated glue/additional data unless policy allows.
- Validate CNAME chains and delegation responses.
- Avoid cache poisoning through out-of-bailiwick additional records.
- Add metrics/logging for rejected upstream data.

Tests:

- out-of-bailiwick additional A/AAAA not cached.
- in-bailiwick glue accepted where appropriate.
- unrelated authority data rejected.
- CNAME chain validation works.

Acceptance criteria:

- recursive cache resists basic poisoning through additional/authority sections.

## Workstream 6: DNSSEC validation boundary

Tasks:

- Define DNSSEC validation states and when AD can be set.
- Ensure AD is set only for validated recursive data and only when client did not disable validation in a way that forbids AD.
- Ensure CD handling is standards-aware or explicitly limited.
- Audit trust-anchor loading and root anchor policy.
- If validation is partial, mark recursive AD support as disabled/deferred by default.

Tests:

- authoritative signed answer does not set AD.
- recursive unchecked answer does not set AD.
- validated secure answer sets AD only if validation is enabled and succeeds.
- bogus answer returns SERVFAIL or configured validation failure policy.
- CD behavior tested or documented as deferred.

Acceptance criteria:

- AD/CD behavior is correct or safely disabled.

## Workstream 7: Privacy and minimization

Tasks:

- Decide support status for QNAME minimization.
- Decide ECS forwarding policy; default should avoid leaking client subnet unless explicitly configured.
- Ensure logs honor qname privacy config.
- Consider upstream query ID/randomization and source port policy.

Tests:

- ECS not forwarded by default.
- qname privacy redacts logs where testable.
- QNAME minimization enabled/disabled behavior tested if implemented.

Acceptance criteria:

- recursive mode does not leak client details unintentionally.

## Workstream 8: Rate limiting and abuse controls

Tasks:

- Apply per-client rate limits to recursive queries.
- Apply outstanding recursive query limits.
- Add max recursion depth, max CNAME chain, max response size, and max upstream concurrency.
- Add metrics for refused due to limits.

Tests:

- client rate limit enforced.
- outstanding query cap enforced.
- recursion depth cap enforced.
- response-size cap enforced.

Acceptance criteria:

- recursive path has anti-abuse controls sufficient for controlled deployment.

## Workstream 9: Documentation

Update:

- `architecture/dns.md`
- `architecture/dns_config_runtime_matrix.md`
- recursive DNS docs if present
- DNSSEC ADRs for validation boundary

Document:

- safe recursive profiles;
- open resolver prevention;
- cache separation;
- upstream policy;
- bailiwick policy;
- DNSSEC validation status;
- privacy defaults;
- deferred limitations.

## Verification commands

```bash
cargo fmt --all --check
cargo test -p synvoid-dns recursive
cargo test -p synvoid-dns recursive_cache
cargo test -p synvoid-dns dns_recursive_isolation
cargo test -p synvoid-dns dnssec_validation
cargo check -p synvoid-dns --all-features
cargo check --workspace
```

## Completion criteria

Phase 4 is complete when recursive mode remains safe by default, authoritative/recursive routing is deterministic, recursive cache is isolated, upstream behavior is bounded, bailiwick and poisoning controls are tested, AD/CD semantics are safe, and docs accurately state what recursive deployment profile is supported.
