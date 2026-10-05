//! DNS lifecycle state (Phase 129 Workstream D).
//!
//! Replaces `synvoid_utils::flags::{RunningFlag, DrainFlag}`. The two flags
//! only ever held `ConnectionLimits` state — graceful degradation and
//! graceful shutdown — so they are modelled here as the DNS concepts they
//! actually are rather than as generic reusable flag wrappers.
//!
//! # Why this is not just a copy
//!
//! `RunningFlag` started `true` and `DrainFlag` started `false`, and the
//! names described neither. Here the initial value is part of the type's
//! name (`DegradationState::Normal` / `Draining::No`), so a future caller
//! cannot construct the inverse by accident.
//!
//! # Ordering contract (unchanged)
//!
//! Loads are `Acquire`, stores are `Release`, exactly as the predecessors.
//! This matters: `initiate_graceful_shutdown` is called from the supervisor
//! while request-path threads read `is_in_graceful_shutdown`, and a weaker
//! ordering could let a reader observe the drain flag before the state it
//! guards. Do not change these orderings.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

/// Whether the DNS server is shedding load under pressure.
///
/// Starts `Normal` so a freshly constructed `ConnectionLimits` never rejects
/// traffic before an operator or the supervisor opts in.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DegradationState {
    /// Serving normally.
    Normal,
    /// Shedding a `reject_ratio` fraction of requests.
    Degraded,
}

impl DegradationState {
    /// Shared handle. `ConnectionLimits` is cloned into listeners and task
    /// guards, so the state is reference-counted rather than moved.
    fn handle() -> Arc<AtomicBool> {
        Arc::new(AtomicBool::new(false))
    }
}

/// Whether graceful shutdown is in progress.
///
/// Starts `No`; `initiate_graceful_shutdown` is one-way in practice, and the
/// release path calls it more than once, so it must stay idempotent.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Draining {
    /// Normal operation.
    No,
    /// Refusing new work; in-flight queries drain at the query boundary.
    Yes,
}

impl Draining {
    fn handle() -> Arc<AtomicBool> {
        Arc::new(AtomicBool::new(false))
    }
}

/// Shared, cloneable lifecycle state for one `ConnectionLimits` instance.
#[derive(Debug, Clone)]
pub struct LifecycleState {
    degraded: Arc<AtomicBool>,
    draining: Arc<AtomicBool>,
}

impl LifecycleState {
    /// A server that is neither degraded nor draining.
    pub fn new() -> Self {
        Self {
            degraded: DegradationState::handle(),
            draining: Draining::handle(),
        }
    }

    /// Current degradation state.
    pub fn degradation(&self) -> DegradationState {
        if self.degraded.load(Ordering::Acquire) {
            DegradationState::Degraded
        } else {
            DegradationState::Normal
        }
    }

    /// Enter or leave degraded mode.
    pub fn set_degradation(&self, state: DegradationState) {
        self.degraded.store(
            matches!(state, DegradationState::Degraded),
            Ordering::Release,
        );
    }

    /// True when the server is shedding load.
    pub fn is_degraded(&self) -> bool {
        self.degraded.load(Ordering::Acquire)
    }

    /// Current drain state.
    pub fn draining(&self) -> Draining {
        if self.draining.load(Ordering::Acquire) {
            Draining::Yes
        } else {
            Draining::No
        }
    }

    /// Enter or leave draining.
    pub fn set_draining(&self, state: Draining) {
        self.draining
            .store(matches!(state, Draining::Yes), Ordering::Release);
    }

    /// True when graceful shutdown is in progress.
    pub fn is_draining(&self) -> bool {
        self.draining.load(Ordering::Acquire)
    }
}

impl Default for LifecycleState {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fresh_state_is_normal_and_not_draining() {
        let state = LifecycleState::new();
        assert_eq!(state.degradation(), DegradationState::Normal);
        assert_eq!(state.draining(), Draining::No);
        assert!(!state.is_degraded());
        assert!(!state.is_draining());
    }

    /// Clones share state. `ConnectionLimits` is cloned into every listener,
    /// so a value-copied flag would silently let one listener drain while
    /// another keeps serving.
    #[test]
    fn clones_share_state() {
        let a = LifecycleState::new();
        let b = a.clone();
        b.set_draining(Draining::Yes);
        assert!(a.is_draining(), "drain must be visible through the clone");
        b.set_degradation(DegradationState::Degraded);
        assert!(a.is_degraded());
    }

    /// The release path calls `initiate_graceful_shutdown` from more than one
    /// place, so repeated entry must not change the outcome.
    #[test]
    fn drain_is_idempotent() {
        let state = LifecycleState::new();
        for _ in 0..5 {
            state.set_draining(Draining::Yes);
            assert!(state.is_draining());
        }
        assert_eq!(state.draining(), Draining::Yes);
    }

    /// Degradation and draining are independent axes: a server can be draining
    /// without being degraded, and vice versa.
    #[test]
    fn degradation_and_draining_are_independent() {
        let state = LifecycleState::new();
        state.set_degradation(DegradationState::Degraded);
        assert!(state.is_degraded());
        assert!(!state.is_draining());

        state.set_draining(Draining::Yes);
        assert!(state.is_degraded());
        assert!(state.is_draining());

        state.set_degradation(DegradationState::Normal);
        assert!(!state.is_degraded());
        assert!(
            state.is_draining(),
            "clearing degradation must not end a drain"
        );
    }

    /// Round-tripping through the enums must preserve the boolean state in
    /// both directions.
    #[test]
    fn enum_round_trip_is_lossless() {
        let state = LifecycleState::new();
        for degradation in [DegradationState::Normal, DegradationState::Degraded] {
            state.set_degradation(degradation.clone());
            assert_eq!(state.degradation(), degradation);
        }
        for draining in [Draining::No, Draining::Yes] {
            state.set_draining(draining.clone());
            assert_eq!(state.draining(), draining);
        }
    }
}
