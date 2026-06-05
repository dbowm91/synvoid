use std::time::{Duration, Instant};
use tokio::time::interval;

pub use synvoid_utils::{GlobalHealthState, HealthState};

/// Monitor for system-wide health and resource pressure.
pub struct SystemHealthMonitor;

impl SystemHealthMonitor {
    /// Start the health monitoring loop.
    pub fn start() {
        tokio::spawn(async move {
            let mut interval = interval(Duration::from_millis(500));
            loop {
                let start = Instant::now();
                interval.tick().await;

                // Measure tokio schedule delay
                let delay = start.elapsed().saturating_sub(Duration::from_millis(500));

                let state = if delay > Duration::from_millis(200) {
                    HealthState::Critical
                } else if delay > Duration::from_millis(50) {
                    HealthState::Warning
                } else {
                    HealthState::Normal
                };

                GlobalHealthState::set(state);

                if state != HealthState::Normal {
                    tracing::warn!(
                        "System under pressure: state={:?}, delay={:?}ms",
                        state,
                        delay.as_millis()
                    );
                }
            }
        });
    }

    /// Get the current global health state.
    pub fn get_state() -> HealthState {
        GlobalHealthState::get()
    }
}
