pub mod sqlite;

pub use self::persistence::{
    BaselinePersistence, ThreatHistory, ThreatHistoryAll, ThreatHistorySample,
};

mod persistence {
    use crate::waf::threat_level::baseline::BaselineStats;
    use serde::{Deserialize, Serialize};
    use std::collections::VecDeque;
    use std::fs;
    use std::io;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::Arc;

    const CURRENT_VERSION: u32 = 1;

    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct PersistedBaseline {
        pub version: u32,
        pub site_id: Option<String>,
        pub computed_at: i64,
        pub learning_duration_secs: u32,
        pub statistics: Vec<BaselineStats>,
    }

    pub struct BaselinePersistence {
        persist_path: PathBuf,
        global_persist_path: PathBuf,
    }

    impl BaselinePersistence {
        pub fn new(data_dir: Option<PathBuf>, site_id: Option<String>) -> Self {
            let (persist_path, global_persist_path) = if let Some(dir) = data_dir {
                let base = dir.join("threat_level");
                let site_path = site_id
                    .as_ref()
                    .map(|id| base.join(format!("baseline_{}.json", id)));
                let global_path = base.join("baseline_global.json");
                (site_path.unwrap_or(global_path.clone()), global_path)
            } else {
                (
                    PathBuf::from("/var/lib/maluwaf/threat_level/baseline_global.json"),
                    PathBuf::from("/var/lib/maluwaf/threat_level/baseline_global.json"),
                )
            };

            Self {
                persist_path,
                global_persist_path,
            }
        }

        pub fn save(
            &self,
            baselines: &[BaselineStats],
            learning_duration_secs: u32,
            site_id: Option<&str>,
        ) -> io::Result<()> {
            let path = if site_id.is_some() {
                &self.persist_path
            } else {
                &self.global_persist_path
            };

            if let Some(parent) = path.parent() {
                fs::create_dir_all(parent)?;
            }

            let now = crate::utils::safe_unix_timestamp() as i64;

            let persisted = PersistedBaseline {
                version: CURRENT_VERSION,
                site_id: site_id.map(String::from),
                computed_at: now,
                learning_duration_secs,
                statistics: baselines.to_vec(),
            };

            let json = serde_json::to_string_pretty(&persisted)?;
            fs::write(path, json)?;

            tracing::info!(
                "Saved baseline to {:?} with {} metrics",
                path,
                baselines.len()
            );
            Ok(())
        }

        pub fn load(&self, site_id: Option<&str>) -> io::Result<Option<Vec<BaselineStats>>> {
            let path = if site_id.is_some() {
                &self.persist_path
            } else {
                &self.global_persist_path
            };

            if !path.exists() {
                return Ok(None);
            }

            let content = fs::read_to_string(path)?;
            let persisted: PersistedBaseline = serde_json::from_str(&content)
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;

            if persisted.version != CURRENT_VERSION {
                tracing::warn!(
                    "Baseline version mismatch: expected {}, got {}",
                    CURRENT_VERSION,
                    persisted.version
                );
            }

            tracing::info!(
                "Loaded baseline from {:?} with {} metrics",
                path,
                persisted.statistics.len()
            );
            Ok(Some(persisted.statistics))
        }

        pub fn exists(&self, site_id: Option<&str>) -> bool {
            let path = if site_id.is_some() {
                &self.persist_path
            } else {
                &self.global_persist_path
            };
            path.exists()
        }
    }

    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct ThreatHistorySample {
        pub timestamp: i64,
        pub level: u8,
        pub score: f64,
        pub requests_per_second: u32,
        pub requests_per_minute: u32,
        pub attacks_per_minute: u32,
        pub rate_limit_hits: u32,
        pub blocked: u32,
    }

    pub struct ThreatHistory {
        minute: Arc<RwLock<VecDeque<ThreatHistorySample>>>,
        hour: Arc<RwLock<VecDeque<ThreatHistorySample>>>,
        day: Arc<RwLock<VecDeque<ThreatHistorySample>>>,
        week: Arc<RwLock<VecDeque<ThreatHistorySample>>>,
        month: Arc<RwLock<VecDeque<ThreatHistorySample>>>,
        max_minute_samples: usize,
        max_hour_samples: usize,
        max_day_samples: usize,
        max_week_samples: usize,
        max_month_samples: usize,
        last_aggregated_minute: AtomicU64,
        last_aggregated_hour: AtomicU64,
        last_aggregated_day: AtomicU64,
    }

    impl ThreatHistory {
        pub fn new() -> Self {
            Self {
                minute: Arc::new(RwLock::new(VecDeque::with_capacity(3600))),
                hour: Arc::new(RwLock::new(VecDeque::with_capacity(168))),
                day: Arc::new(RwLock::new(VecDeque::with_capacity(365))),
                week: Arc::new(RwLock::new(VecDeque::with_capacity(52))),
                month: Arc::new(RwLock::new(VecDeque::with_capacity(36))),
                max_minute_samples: 3600,
                max_hour_samples: 168,
                max_day_samples: 365,
                max_week_samples: 52,
                max_month_samples: 36,
                last_aggregated_minute: AtomicU64::new(0),
                last_aggregated_hour: AtomicU64::new(0),
                last_aggregated_day: AtomicU64::new(0),
            }
        }

        pub fn with_limits(
            max_minutes: usize,
            max_hours: usize,
            max_days: usize,
            max_weeks: usize,
            max_months: usize,
        ) -> Self {
            Self {
                minute: Arc::new(RwLock::new(VecDeque::with_capacity(max_minutes))),
                hour: Arc::new(RwLock::new(VecDeque::with_capacity(max_hours))),
                day: Arc::new(RwLock::new(VecDeque::with_capacity(max_days))),
                week: Arc::new(RwLock::new(VecDeque::with_capacity(max_weeks))),
                month: Arc::new(RwLock::new(VecDeque::with_capacity(max_months))),
                max_minute_samples: max_minutes,
                max_hour_samples: max_hours,
                max_day_samples: max_days,
                max_week_samples: max_weeks,
                max_month_samples: max_months,
                last_aggregated_minute: AtomicU64::new(0),
                last_aggregated_hour: AtomicU64::new(0),
                last_aggregated_day: AtomicU64::new(0),
            }
        }

        pub fn add_sample(&self, sample: ThreatHistorySample) {
            let timestamp = sample.timestamp as u64;

            {
                let mut queue = self.minute.write();
                if queue.len() >= self.max_minute_samples {
                    queue.pop_front();
                }
                queue.push_back(sample.clone());
            }

            if timestamp / 60 > self.last_aggregated_minute.load(Ordering::Relaxed) {
                self.last_aggregated_minute
                    .store(timestamp / 60, Ordering::Relaxed);
                self.aggregate_upwards(60, &self.minute, &self.hour, self.max_hour_samples);
            }

            if timestamp / 3600 > self.last_aggregated_hour.load(Ordering::Relaxed) {
                self.last_aggregated_hour
                    .store(timestamp / 3600, Ordering::Relaxed);
                self.aggregate_upwards(3600, &self.hour, &self.day, self.max_day_samples);
            }

            if timestamp / 86400 > self.last_aggregated_day.load(Ordering::Relaxed) {
                self.last_aggregated_day
                    .store(timestamp / 86400, Ordering::Relaxed);
                self.aggregate_upwards(86400, &self.day, &self.week, self.max_week_samples);
                self.aggregate_upwards(86400 * 7, &self.week, &self.month, self.max_month_samples);
            }
        }

        fn aggregate_upwards(
            &self,
            _bucket_secs: u64,
            from: &Arc<RwLock<VecDeque<ThreatHistorySample>>>,
            to: &Arc<RwLock<VecDeque<ThreatHistorySample>>>,
            max_to: usize,
        ) {
            let from_queue = from.read();
            if from_queue.is_empty() {
                return;
            }

            let bucket_count = from_queue.len();
            if bucket_count < 60 {
                return;
            }

            let avg_requests: f64 = from_queue
                .iter()
                .map(|s| s.requests_per_minute as f64)
                .sum::<f64>()
                / bucket_count as f64;
            let avg_attacks: f64 = from_queue
                .iter()
                .map(|s| s.attacks_per_minute as f64)
                .sum::<f64>()
                / bucket_count as f64;
            let avg_rl_hits: f64 = from_queue
                .iter()
                .map(|s| s.rate_limit_hits as f64)
                .sum::<f64>()
                / bucket_count as f64;
            let avg_blocked: f64 =
                from_queue.iter().map(|s| s.blocked as f64).sum::<f64>() / bucket_count as f64;

            let max_level = from_queue.iter().map(|s| s.level).max().unwrap_or(1);
            let max_score = from_queue
                .iter()
                .map(|s| s.score)
                .fold(0.0_f64, |a, b| a.max(b));

            let last_sample = from_queue.back().unwrap();

            let aggregated = ThreatHistorySample {
                timestamp: last_sample.timestamp,
                level: max_level,
                score: max_score,
                requests_per_second: (avg_requests / 60.0) as u32,
                requests_per_minute: avg_requests as u32,
                attacks_per_minute: avg_attacks as u32,
                rate_limit_hits: avg_rl_hits as u32,
                blocked: avg_blocked as u32,
            };

            drop(from_queue);

            let mut to_queue = to.write();
            if to_queue.len() >= max_to {
                to_queue.pop_front();
            }
            to_queue.push_back(aggregated);
        }

        pub fn get_minute_history(&self, limit: usize) -> Vec<ThreatHistorySample> {
            let queue = self.minute.read();
            queue.iter().rev().take(limit).cloned().collect()
        }

        pub fn get_hour_history(&self, limit: usize) -> Vec<ThreatHistorySample> {
            let queue = self.hour.read();
            queue.iter().rev().take(limit).cloned().collect()
        }

        pub fn get_day_history(&self, limit: usize) -> Vec<ThreatHistorySample> {
            let queue = self.day.read();
            queue.iter().rev().take(limit).cloned().collect()
        }

        pub fn get_week_history(&self, limit: usize) -> Vec<ThreatHistorySample> {
            let queue = self.week.read();
            queue.iter().rev().take(limit).cloned().collect()
        }

        pub fn get_month_history(&self, limit: usize) -> Vec<ThreatHistorySample> {
            let queue = self.month.read();
            queue.iter().rev().take(limit).cloned().collect()
        }

        pub fn get_all_history(&self) -> ThreatHistoryAll {
            ThreatHistoryAll {
                minute: self.get_minute_history(60),
                hour: self.get_hour_history(24),
                day: self.get_day_history(7),
                week: self.get_week_history(4),
                month: self.get_month_history(12),
            }
        }

        pub fn clear(&self) {
            self.minute.write().clear();
            self.hour.write().clear();
            self.day.write().clear();
            self.week.write().clear();
            self.month.write().clear();
        }
    }

    impl Default for ThreatHistory {
        fn default() -> Self {
            Self::new()
        }
    }

    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct ThreatHistoryAll {
        pub minute: Vec<ThreatHistorySample>,
        pub hour: Vec<ThreatHistorySample>,
        pub day: Vec<ThreatHistorySample>,
        pub week: Vec<ThreatHistorySample>,
        pub month: Vec<ThreatHistorySample>,
    }

    use parking_lot::RwLock;

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn test_persistence_roundtrip() {
            let temp_dir = std::env::temp_dir().join("maluwaf_test_baseline");
            let persistence = BaselinePersistence::new(Some(temp_dir.clone()), None);

            let baselines = vec![BaselineStats {
                metric_name: "requests_per_minute".to_string(),
                mean: 100.0,
                std_dev: 25.0,
                min_value: 10.0,
                max_value: 200.0,
                samples: 100,
                computed_at: 1234567890,
            }];

            persistence.save(&baselines, 600, None).unwrap();
            let loaded = persistence.load(None).unwrap().unwrap();

            assert_eq!(loaded.len(), 1);
            assert!((loaded[0].mean - 100.0).abs() < 0.001);
        }

        #[test]
        fn test_history_aggregation() {
            let history = ThreatHistory::new();

            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs() as i64;

            for i in 0..120 {
                let sample = ThreatHistorySample {
                    timestamp: now + i as i64 * 60,
                    level: 2,
                    score: 1.5,
                    requests_per_second: 10,
                    requests_per_minute: 600,
                    attacks_per_minute: 5,
                    rate_limit_hits: 10,
                    blocked: 2,
                };
                history.add_sample(sample);
            }

            let minute_history = history.get_minute_history(10);
            assert!(!minute_history.is_empty());
        }
    }
}
