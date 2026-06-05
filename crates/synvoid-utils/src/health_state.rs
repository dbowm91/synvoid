use std::sync::atomic::{AtomicU8, Ordering};

/// System health state for proxy caching decisions.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HealthState {
    Normal = 0,
    Warning = 1,
    Critical = 2,
}

impl From<u8> for HealthState {
    fn from(v: u8) -> Self {
        match v {
            1 => HealthState::Warning,
            2 => HealthState::Critical,
            _ => HealthState::Normal,
        }
    }
}

static CURRENT_HEALTH: AtomicU8 = AtomicU8::new(0);

/// Global health state reader/writer. The monitoring loop that updates this
/// lives in root synvoid; extracted crates only read via `get()`.
pub struct GlobalHealthState;

impl GlobalHealthState {
    pub fn get() -> HealthState {
        HealthState::from(CURRENT_HEALTH.load(Ordering::Relaxed))
    }

    pub fn set(state: HealthState) {
        CURRENT_HEALTH.store(state as u8, Ordering::Relaxed);
    }
}
