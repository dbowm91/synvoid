use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct BaselineStats {
    pub metric_name: String,
    pub mean: f64,
    pub std_dev: f64,
    pub min_value: f64,
    pub max_value: f64,
    pub samples: u64,
    pub computed_at: i64,
}

impl BaselineStats {
    pub fn z_score(&self, value: f64) -> f64 {
        if self.std_dev == 0.0 {
            return 0.0;
        }
        (value - self.mean) / self.std_dev
    }

    pub fn is_anomalous(&self, value: f64, sigma_threshold: f64) -> bool {
        self.z_score(value).abs() > sigma_threshold
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        serde_json::to_vec(self).unwrap_or_default()
    }
}

pub struct RunningStatistics {
    count: u64,
    mean: f64,
    m2: f64,
    min_value: f64,
    max_value: f64,
}

impl RunningStatistics {
    pub fn new() -> Self {
        Self {
            count: 0,
            mean: 0.0,
            m2: 0.0,
            min_value: f64::INFINITY,
            max_value: f64::NEG_INFINITY,
        }
    }

    pub fn update(&mut self, value: f64) {
        self.count += 1;
        let delta = value - self.mean;
        self.mean += delta / self.count as f64;
        let delta2 = value - self.mean;
        self.m2 += delta * delta2;

        if value < self.min_value {
            self.min_value = value;
        }
        if value > self.max_value {
            self.max_value = value;
        }
    }

    pub fn variance(&self) -> f64 {
        if self.count < 2 {
            return 0.0;
        }
        self.m2 / (self.count - 1) as f64
    }

    pub fn std_dev(&self) -> f64 {
        self.variance().sqrt()
    }

    pub fn count(&self) -> u64 {
        self.count
    }

    pub fn z_score(&self, value: f64) -> f64 {
        if self.std_dev() == 0.0 {
            return 0.0;
        }
        (value - self.mean) / self.std_dev()
    }

    pub fn finalize(&self, metric_name: &str) -> BaselineStats {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64;

        BaselineStats {
            metric_name: metric_name.to_string(),
            mean: self.mean,
            std_dev: self.std_dev(),
            min_value: if self.min_value.is_infinite() {
                0.0
            } else {
                self.min_value
            },
            max_value: if self.max_value.is_infinite() {
                0.0
            } else {
                self.max_value
            },
            samples: self.count,
            computed_at: now,
        }
    }

    pub fn reset(&mut self) {
        *self = Self::new();
    }
}

impl Default for RunningStatistics {
    fn default() -> Self {
        Self::new()
    }
}

pub struct BaselineLearner {
    statistics: RwLock<HashMap<String, RunningStatistics>>,
    learning_enabled: RwLock<bool>,
    learning_complete: RwLock<bool>,
    learning_duration_secs: u32,
    learning_start_time: RwLock<Option<i64>>,
    collected_samples: RwLock<HashMap<String, u64>>,
}

impl BaselineLearner {
    pub fn new(learning_duration_secs: u32) -> Arc<Self> {
        Arc::new(Self {
            statistics: RwLock::new(HashMap::new()),
            learning_enabled: RwLock::new(true),
            learning_complete: RwLock::new(false),
            learning_duration_secs,
            learning_start_time: RwLock::new(None),
            collected_samples: RwLock::new(HashMap::new()),
        })
    }

    pub fn start_learning(&self) {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64;

        *self.learning_start_time.write() = Some(now);
        *self.learning_enabled.write() = true;
        *self.learning_complete.write() = false;
        self.statistics.write().clear();
        self.collected_samples.write().clear();
    }

    pub fn stop_learning(&self) {
        *self.learning_enabled.write() = false;
    }

    pub fn complete_learning(&self) {
        *self.learning_enabled.write() = false;
        *self.learning_complete.write() = true;
    }

    pub fn is_learning(&self) -> bool {
        *self.learning_enabled.read()
    }

    pub fn is_learning_complete(&self) -> bool {
        *self.learning_complete.read()
    }

    pub fn learning_progress(&self) -> f64 {
        let start = match *self.learning_start_time.read() {
            Some(t) => t,
            None => return 0.0,
        };

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64;

        let elapsed = now - start;
        let duration = self.learning_duration_secs as i64;

        if duration <= 0 {
            return 1.0;
        }

        (elapsed as f64 / duration as f64).min(1.0)
    }

    pub fn record_sample(&self, metric_name: &str, value: f64) {
        if !*self.learning_enabled.read() {
            return;
        }

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64;

        if self.learning_start_time.read().is_none() {
            *self.learning_start_time.write() = Some(now);
        }

        let mut stats = self.statistics.write();
        let stats_entry = stats
            .entry(metric_name.to_string())
            .or_insert_with(RunningStatistics::new);
        stats_entry.update(value);

        let mut collected = self.collected_samples.write();
        *collected.entry(metric_name.to_string()).or_insert(0) += 1;

        if let Some(start) = *self.learning_start_time.read() {
            if now - start >= self.learning_duration_secs as i64 {
                *self.learning_complete.write() = true;
                *self.learning_enabled.write() = false;
            }
        }
    }

    pub fn get_baseline(&self, metric_name: &str) -> Option<BaselineStats> {
        let stats = self.statistics.read();
        stats.get(metric_name).map(|s| s.finalize(metric_name))
    }

    pub fn get_all_baselines(&self) -> Vec<BaselineStats> {
        let stats = self.statistics.read();
        stats
            .iter()
            .filter(|(_, s)| s.count() > 10)
            .map(|(name, s)| s.finalize(name))
            .collect()
    }

    pub fn get_z_score(&self, metric_name: &str, value: f64) -> Option<f64> {
        let stats = self.statistics.read();
        stats.get(metric_name).map(|s| s.z_score(value))
    }

    pub fn compute_composite_z_score(
        &self,
        metrics: &super::collector::ThreatMetrics,
    ) -> Option<f64> {
        let stats = self.statistics.read();

        let mut scores = Vec::new();

        if let Some(s) = stats.get("requests_per_minute") {
            if s.std_dev() > 0.0 {
                scores.push(s.z_score(metrics.requests_per_minute as f64));
            }
        }

        if let Some(s) = stats.get("attacks_per_minute") {
            if s.std_dev() > 0.0 {
                scores.push(s.z_score(metrics.attacks_per_minute as f64) * 2.0);
            }
        }

        if let Some(s) = stats.get("rate_limit_hits_per_minute") {
            if s.std_dev() > 0.0 {
                scores.push(s.z_score(metrics.rate_limit_hits_per_minute as f64) * 1.5);
            }
        }

        if scores.is_empty() {
            return None;
        }

        let sum: f64 = scores.iter().map(|s| s * s).sum();
        Some(sum.sqrt())
    }

    pub fn reset(&self) {
        *self.learning_enabled.write() = true;
        *self.learning_complete.write() = false;
        *self.learning_start_time.write() = None;
        self.statistics.write().clear();
        self.collected_samples.write().clear();
    }

    pub fn get_sample_counts(&self) -> HashMap<String, u64> {
        self.collected_samples.read().clone()
    }

    pub fn get_learning_stats(&self) -> LearningStats {
        let progress = self.learning_progress();
        let samples = self.get_sample_counts();
        let min_samples = samples.values().cloned().min().unwrap_or(0);

        LearningStats {
            is_learning: self.is_learning(),
            is_complete: self.is_learning_complete(),
            progress,
            total_samples: min_samples,
            samples_per_metric: samples,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LearningStats {
    pub is_learning: bool,
    pub is_complete: bool,
    pub progress: f64,
    pub total_samples: u64,
    pub samples_per_metric: HashMap<String, u64>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_running_statistics() {
        let mut stats = RunningStatistics::new();

        stats.update(10.0);
        stats.update(20.0);
        stats.update(30.0);

        assert_eq!(stats.mean, 20.0);
        assert!(stats.std_dev() > 0.0);
    }

    #[test]
    fn test_welford_algorithm() {
        let mut stats = RunningStatistics::new();

        for i in 1..=100 {
            stats.update(i as f64);
        }

        let baseline = stats.finalize("test");

        assert!((baseline.mean - 50.5).abs() < 0.1);
        assert!(baseline.std_dev > 28.0);
    }

    #[test]
    fn test_baseline_z_score() {
        let stats = BaselineStats {
            metric_name: "test".to_string(),
            mean: 100.0,
            std_dev: 10.0,
            min_value: 0.0,
            max_value: 0.0,
            samples: 100,
            computed_at: 0,
        };

        assert_eq!(stats.z_score(100.0), 0.0);
        assert_eq!(stats.z_score(110.0), 1.0);
        assert_eq!(stats.z_score(90.0), -1.0);
    }

    #[test]
    fn test_baseline_learner() {
        let learner = BaselineLearner::new(60);

        for _ in 0..50 {
            learner.record_sample("requests_per_minute", 100.0);
        }

        assert!(learner.is_learning());
        assert!(learner.get_baseline("requests_per_minute").is_some());
    }
}
