# Changelog — synvoid-rate-limit

All notable changes to this crate are recorded here. The format follows
"Keep a Changelog" conventions; versioning follows the repository's
pre-1.0 semver policy (see `architecture/public_crate_release_policy.md`).

## [0.1.0] — 2026-09-19

Initial externally supported release (first SynVoid library crate promoted
to class 3 in Phase 47).

- `AtomicSlidingWindow`: lock-free bucketed sliding-window counter over
  explicit monotonic millisecond ticks, with saturating/checked duration
  math, clamped degenerate configuration, single-CAS-winner rotation, and a
  saturating running sum that can never underflow.
- `WindowClock`: monotonic millisecond tick source (`Instant`-based).
- `WindowStats`: policy-neutral count/limit/remaining snapshot; exactly N
  against a limit of N is allowed.
- Neutral admission vocabulary: `RateLimitResult`, `IpRateLimiter`,
  `KeyedRateLimiter`, `RateLimitStats`, `RateLimitStatsProvider`.
- `ip_to_slot`: pure deterministic IP-to-slot hash (IPv4/IPv6); documented
  as an implementation detail, not a stable cross-version hash.
- Zero dependencies (std only); no application/HTTP/metrics/config edges.
- MSRV 1.81 with packaged-tarball build/test evidence outside the workspace.
