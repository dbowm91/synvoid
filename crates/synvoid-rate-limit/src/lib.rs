//! Shared rate-limit mechanism primitives.
//!
//! This crate owns the reusable, policy-neutral limiting machinery that is
//! consumed by at least two production subsystems (WAF request-path accounting
//! and mesh peer/global admission). It answers only mechanism questions —
//! "how many events fall inside this window, how much quota remains, when
//! does the window reset" — and never domain-policy questions.
//!
//! # Mechanism vs policy
//!
//! Belongs here:
//!
//! - monotonic sliding-window counters ([`AtomicSlidingWindow`]);
//! - an explicit monotonic tick source ([`WindowClock`]);
//! - neutral admission vocabulary ([`RateLimitResult`], [`IpRateLimiter`],
//!   [`KeyedRateLimiter`], [`RateLimitStats`], [`RateLimitStatsProvider`]);
//! - policy-neutral snapshots ([`WindowStats`]);
//! - a tiny pure IP-to-slot hash ([`ip_to_slot`]).
//!
//! Stays in the owning domain crate:
//!
//! - WAF `Blackholed` state and adaptive probe/backoff behavior;
//! - auth brute-force lockout semantics;
//! - admin middleware/Axum extraction and HTTP responses;
//! - upload-specific response policy;
//! - IPC connection rejection and error types;
//! - mesh peer reputation/trust policy;
//! - DNS response/RRL behavior;
//! - SynVoid metric names, logging, and config types.
//!
//! Domain crates adapt the generic result into their existing decision types
//! (e.g. WAF maps counts onto `RateLimitDecision`, mesh maps them onto its
//! peer/global admission checks).
//!
//! # Time model
//!
//! Window methods take an explicit millisecond tick
//! ([`AtomicSlidingWindow::increment_at`], [`AtomicSlidingWindow::count_at`])
//! so tests advance time deterministically without sleeps. Production callers
//! use monotonic time via [`WindowClock`] (or their own monotonic baseline);
//! wall-clock ticks must never be passed because clock skew would corrupt
//! rotation. Duration/tick arithmetic is saturating or checked, large time
//! jumps clear stale buckets, concurrent rotation never underflows the
//! running sum, and degenerate configuration is clamped by contract.
//!
//! # Dependency budget
//!
//! This crate is intentionally dependency-free (std only). In particular it
//! must never gain an edge on the root `synvoid` crate, `synvoid-config`,
//! `synvoid-waf`, `synvoid-mesh`, `synvoid-ipc`, `synvoid-admin`, any
//! HTTP/Axum/Hyper stack, or `synvoid-metrics`. [`ip_to_slot`] is a small
//! deliberate duplication of the canonical helper in `synvoid-utils` so this
//! crate stays a leaf; `synvoid-utils` remains the general-purpose owner.

pub mod contracts;
pub mod slot;
pub mod window;

pub use contracts::{
    IpRateLimiter, KeyedRateLimiter, RateLimitResult, RateLimitStats, RateLimitStatsProvider,
};
pub use slot::ip_to_slot;
pub use window::{AtomicSlidingWindow, WindowClock, WindowStats};
