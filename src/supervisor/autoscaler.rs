use crate::config::SupervisorConfig;

#[derive(Clone, Debug)]
pub enum ScaleDecision {
    ScaleUp(usize),
    ScaleDown(usize),
    NoChange,
}

pub struct AutoScaler {
    config: SupervisorConfig,
    last_scale_up: parking_lot::Mutex<Option<std::time::Instant>>,
    last_scale_down: parking_lot::Mutex<Option<std::time::Instant>>,
}

impl AutoScaler {
    pub fn new(config: SupervisorConfig) -> Self {
        Self {
            config,
            last_scale_up: parking_lot::Mutex::new(None),
            last_scale_down: parking_lot::Mutex::new(None),
        }
    }

    pub fn evaluate(&self, current_workers: usize, avg_load: f64) -> ScaleDecision {
        let now = std::time::Instant::now();

        if avg_load > self.config.scale_up_threshold {
            if let Some(last) = *self.last_scale_up.lock() {
                if now.duration_since(last).as_secs() < self.config.scale_up_cooldown_secs {
                    return ScaleDecision::NoChange;
                }
            }

            if current_workers < self.config.max_workers {
                *self.last_scale_up.lock() = Some(now);
                let to_add = ((avg_load * current_workers as f64) as usize).max(1);
                let scale_by = to_add.min(self.config.max_workers - current_workers);
                return ScaleDecision::ScaleUp(scale_by);
            }
        }

        if avg_load < self.config.scale_down_threshold {
            if let Some(last) = *self.last_scale_down.lock() {
                if now.duration_since(last).as_secs() < self.config.scale_down_cooldown_secs {
                    return ScaleDecision::NoChange;
                }
            }

            if current_workers > self.config.min_workers {
                *self.last_scale_down.lock() = Some(now);
                let to_remove = ((self.config.scale_down_threshold - avg_load)
                    * current_workers as f64) as usize;
                let scale_by = to_remove
                    .max(1)
                    .min(current_workers - self.config.min_workers);
                return ScaleDecision::ScaleDown(scale_by);
            }
        }

        ScaleDecision::NoChange
    }

    pub fn get_recommended_workers(&self, avg_load: f64, target_per_worker: f64) -> usize {
        let needed = (avg_load / target_per_worker).ceil() as usize;
        needed.clamp(self.config.min_workers, self.config.max_workers)
    }
}
