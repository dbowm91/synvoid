# synvoid-rate-limit

Lock-free, policy-neutral rate-limit mechanism primitives: monotonic
sliding-window counters, an explicit monotonic tick source, neutral admission
vocabulary, and a tiny pure IP-to-slot hash.

This crate answers only mechanism questions — "how many events fall inside
this window, how much quota remains" — and never domain-policy questions
(blocklists, threat levels, HTTP responses, metrics, logging, config).
Domain crates map the neutral outcome onto their own decisions.

## Quickstart

```rust
use synvoid_rate_limit::{AtomicSlidingWindow, WindowClock, WindowStats};

let clock = WindowClock::new();
let window = AtomicSlidingWindow::new(60, 60); // 60s window, 60 buckets
let limit = 100u64;

window.increment_now(&clock);
let count = window.count_now(&clock);
let stats: WindowStats = window.stats_at(clock.now_ms(), limit);
assert!(stats.is_within_limit());
assert_eq!(stats.remaining, limit - count);
```

Deterministic testing uses explicit ticks (no sleeps):

```rust
use synvoid_rate_limit::AtomicSlidingWindow;

let window = AtomicSlidingWindow::new(1, 10); // 1s window, 10 buckets
assert_eq!(window.increment_at(100), 1);
assert_eq!(window.increment_at(150), 2);
assert_eq!(window.count_at(150), 2);
assert_eq!(window.count_at(1_100), 0); // one full window later: expired
```

## Time model and overflow semantics

- All window methods take an explicit millisecond tick (`u64`). Production
  callers use [`WindowClock`] (monotonic `Instant`-based) or their own
  monotonic baseline. **Never pass wall-clock milliseconds**: NTP steps or
  epoch skew corrupt rotation.
- Exactly N events against a limit of N is allowed; N+1 exceeds it.
  `remaining` saturates at zero past the limit.
- Duration math saturates: `window_duration_secs * 1000` cannot overflow,
  degenerate configuration is clamped (`bucket_count >= 1`,
  `bucket_duration_ms >= 1`) instead of panicking on the request path.
- A time jump larger than the whole window clears every bucket; concurrent
  rotation is resolved by a single compare-exchange winner and the running
  sum is decremented with saturating subtraction, so it can never underflow.
- `reset()` clears every bucket and the running sum; the window stays usable.

## Slot hashing

`ip_to_slot(ip, num_slots)` maps an IP to `[0, num_slots)` (`None` when
`num_slots == 0`). It is deterministic within a crate version and covers
both IPv4 and IPv6, with a power-of-two fast path.

**Stability contract**: the slot mapping is an implementation detail, not a
semver-guaranteed stable hash. Do not persist slot numbers across crate
upgrades or expect identical mappings from other implementations. The only
guarantees are determinism within one version, range containment, and
`None` for zero slots. This function intentionally duplicates a few dozen
lines of pure hashing so the crate stays dependency-free (std only).

## Non-goals

- No blocklist/threat/auth policy, no HTTP/Axum/Hyper types, no metrics,
  logging, or config types.
- No persistence, no cross-process shared memory, no async runtime use.
- No wall-clock handling; time is always caller-supplied monotonic ticks.

## Dependency budget

Zero dependencies (std only). In particular this crate never depends on
application, HTTP, async-runtime, metrics, or serialization crates, so it
can be adopted without pulling in unrelated stacks.

## MSRV and support

- MSRV: Rust 1.81 (declared as `rust-version`, verified by building and
  testing the packaged tarball outside the workspace on that toolchain).
- Pre-1.0 semver: within `0.x`, minor bumps may extend the API in
  backwards-compatible ways; patch bumps are compatible fixes only. The
  `ip_to_slot` mapping, internal bucket layout, and timing performance are
  explicitly **not** semver-guaranteed (see the shared policy in
  `architecture/public_crate_release_policy.md`).
- Support: this is the first externally supported SynVoid library crate
  (class 3). Security issues: see the repository `SECURITY.md`.
