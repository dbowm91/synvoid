use std::sync::atomic::{AtomicU8, Ordering};
use std::time::{Duration, Instant};
use tokio::time::interval;

/// System health state.
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

                CURRENT_HEALTH.store(state as u8, Ordering::Relaxed);

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
        HealthState::from(CURRENT_HEALTH.load(Ordering::Relaxed))
    }
}
