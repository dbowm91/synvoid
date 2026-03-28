pub mod baseline;
pub mod collector;
pub mod persistence;
pub mod scorer;

pub use baseline::{BaselineLearner, BaselineStats, LearningStats};
pub use collector::{ThreatMetrics, ThreatMetricsCollector};
pub use persistence::sqlite::{BackupInfo, SqliteBackup, SqliteHistory};
pub use persistence::{BaselinePersistence, ThreatHistory, ThreatHistoryAll, ThreatHistorySample};
pub use scorer::{ThreatLevel, ThreatScore, ThreatScorer, ThreatStatus};

use crate::config::ThreatLevelConfig;

use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::broadcast;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatLevelConfigExtended {
    pub learning_enabled: bool,
    pub learning_duration_secs: u32,
    pub sigma_scale_up: f64,
    pub sigma_scale_down: f64,
    pub attack_weight: f64,
    pub rate_limit_weight: f64,
    pub baseline_persist_path: Option<String>,
    pub history_retention_days: u32,
    pub history_flush_interval_secs: u32,
    pub use_sqlite_history: bool,
}

impl Default for ThreatLevelConfigExtended {
    fn default() -> Self {
        Self {
            learning_enabled: true,
            learning_duration_secs: 600,
            sigma_scale_up: 2.0,
            sigma_scale_down: 0.5,
            attack_weight: 2.0,
            rate_limit_weight: 1.5,
            baseline_persist_path: None,
            history_retention_days: 365,
            history_flush_interval_secs: 60,
            use_sqlite_history: true,
        }
    }
}

#[derive(Debug, Clone)]
pub struct LegacyThreatLevelConfig {
    pub escalation: LegacyEscalationConfig,
    pub auto_scale: bool,
    pub initial: u8,
    pub cooldown_secs: u32,
    pub scale_up_window_secs: u32,
    pub scale_up_attacks_per_min: u32,
    pub scale_down_window_secs: u32,
    pub scale_down_attacks_per_min: u32,
    pub persist_interval_normal_secs: u32,
    pub persist_interval_attack_secs: u32,
}

#[derive(Debug, Clone)]
pub struct LegacyEscalationConfig {
    pub enabled: bool,
    pub violations_before_block: u32,
    pub violation_window_secs: u32,
    pub excluded_ips: Vec<String>,
}

impl From<&ThreatLevelConfig> for ThreatLevelConfigExtended {
    fn from(_config: &ThreatLevelConfig) -> Self {
        Self {
            learning_enabled: true,
            learning_duration_secs: 600,
            sigma_scale_up: 2.0,
            sigma_scale_down: 0.5,
            attack_weight: 2.0,
            rate_limit_weight: 1.5,
            baseline_persist_path: None,
            history_retention_days: 365,
            history_flush_interval_secs: 60,
            use_sqlite_history: true,
        }
    }
}

pub struct ThreatLevelManager {
    collector: Arc<ThreatMetricsCollector>,
    learner: Arc<BaselineLearner>,
    scorer: Arc<ThreatScorer>,
    history: Arc<ThreatHistory>,
    sql_history: Option<Arc<SqliteHistory>>,
    persistence: Arc<BaselinePersistence>,

    current_level: AtomicU8,
    manual_override: AtomicU8,
    is_manual: AtomicU8,

    config: ThreatLevelConfigExtended,

    last_evaluation: RwLock<Instant>,
    evaluation_interval: Duration,

    cooldown_until: RwLock<Instant>,
    cooldown_duration: Duration,

    scale_tx: broadcast::Sender<ThreatLevel>,
}

impl ThreatLevelManager {
    pub fn new(
        config: ThreatLevelConfig,
        data_dir: Option<PathBuf>,
        site_id: Option<String>,
    ) -> Arc<Self> {
        let extended_config = ThreatLevelConfigExtended::from(&config);
        let (scale_tx, _) = broadcast::channel(100);

        let collector = Arc::new(ThreatMetricsCollector::new());
        let learner = BaselineLearner::new(extended_config.learning_duration_secs);
        let scorer = Arc::new(ThreatScorer::new(
            extended_config.sigma_scale_up,
            extended_config.sigma_scale_down,
            extended_config.attack_weight,
            extended_config.rate_limit_weight,
        ));
        let history = Arc::new(ThreatHistory::new());

        let sql_history = if extended_config.use_sqlite_history {
            let sid = site_id.clone().unwrap_or_else(|| "global".to_string());
            match SqliteHistory::new(
                data_dir.clone(),
                sid,
                extended_config.history_flush_interval_secs,
            ) {
                Ok(h) => {
                    tracing::info!("Using SQLite-backed history storage");
                    Some(h)
                }
                Err(e) => {
                    tracing::warn!(
                        "Failed to initialize SQLite history, falling back to in-memory: {}",
                        e
                    );
                    None
                }
            }
        } else {
            None
        };

        let persistence = Arc::new(BaselinePersistence::new(data_dir, site_id.clone()));

        let config_clone = extended_config.clone();

        let manager = Arc::new(Self {
            collector,
            learner,
            scorer,
            history,
            sql_history,
            persistence,
            current_level: AtomicU8::new(config.initial),
            manual_override: AtomicU8::new(0),
            is_manual: AtomicU8::new(0),
            config: config_clone,
            last_evaluation: RwLock::new(Instant::now()),
            evaluation_interval: Duration::from_secs(config.scale_up_window_secs as u64),
            cooldown_until: RwLock::new(Instant::now()),
            cooldown_duration: Duration::from_secs(config.cooldown_secs as u64),
            scale_tx,
        });

        if extended_config.learning_enabled {
            manager.load_or_start_learning(site_id.as_deref());
        }

        manager
    }

    fn load_or_start_learning(&self, site_id: Option<&str>) {
        if let Ok(Some(baselines)) = self.persistence.load(site_id) {
            if !baselines.is_empty() {
                tracing::info!("Loaded existing baseline with {} metrics", baselines.len());
                for baseline in &baselines {
                    for _ in 0..baseline.samples {
                        let metric_name = &baseline.metric_name;
                        let value = match metric_name.as_str() {
                            "requests_per_minute" => baseline.mean,
                            "attacks_per_minute" => baseline.mean,
                            "rate_limit_hits_per_minute" => baseline.mean,
                            _ => baseline.mean,
                        };
                        self.learner.record_sample(metric_name, value);
                    }
                }
                return;
            }
        }

        tracing::info!(
            "Starting new baseline learning period ({}s)",
            self.config.learning_duration_secs
        );
        self.learner.start_learning();
    }

    pub fn record_request(&self) {
        self.collector.record_request();
    }

    pub fn record_attack(&self) {
        self.collector.record_attack();
    }

    pub fn record_rate_limit_hit(&self) {
        self.collector.record_rate_limit_hit();
    }

    pub fn record_blocked(&self) {
        self.collector.record_blocked();
    }

    pub fn get_level(&self) -> ThreatLevel {
        if self.is_manual.load(Ordering::Relaxed) == 1 {
            return ThreatLevel(self.manual_override.load(Ordering::Relaxed));
        }
        ThreatLevel(self.current_level.load(Ordering::Relaxed))
    }

    pub fn set_level(&self, level: u8) {
        let new_level = ThreatLevel::new(level);
        self.manual_override.store(new_level.0, Ordering::Relaxed);
        self.is_manual.store(1, Ordering::Relaxed);
        self.current_level.store(new_level.0, Ordering::Relaxed);
        let _ = self.scale_tx.send(new_level);
        tracing::info!("ThreatLevel manually set to {}", new_level);
    }

    pub fn reset_to_auto(&self) {
        self.is_manual.store(0, Ordering::Relaxed);
        let auto_level = 1u8;
        self.current_level.store(auto_level, Ordering::Relaxed);
        let _ = self.scale_tx.send(ThreatLevel(auto_level));
        tracing::info!("ThreatLevel reset to auto mode (level {})", auto_level);
    }

    pub fn is_manual(&self) -> bool {
        self.is_manual.load(Ordering::Relaxed) == 1
    }

    pub fn check_and_scale(&self) -> Option<ThreatLevel> {
        if self.is_manual.load(Ordering::Relaxed) == 1 {
            return None;
        }

        let now = Instant::now();

        {
            let cooldown = *self.cooldown_until.read();
            if now < cooldown {
                return None;
            }
        }

        {
            let last_eval = *self.last_evaluation.read();
            if now.duration_since(last_eval) < self.evaluation_interval {
                return None;
            }
        }

        *self.last_evaluation.write() = now;

        let metrics = self.collector.get_current_metrics();

        if self.learner.is_learning() {
            self.learner
                .record_sample("requests_per_minute", metrics.requests_per_minute as f64);
            self.learner
                .record_sample("attacks_per_minute", metrics.attacks_per_minute as f64);
            self.learner.record_sample(
                "rate_limit_hits_per_minute",
                metrics.rate_limit_hits_per_minute as f64,
            );

            if self.learner.is_learning_complete() {
                self.save_baseline();
                tracing::info!("Baseline learning complete");
            }

            return None;
        }

        let baselines = self.learner.get_all_baselines();
        let score = self.scorer.calculate_score(&metrics, &baselines);
        let new_level = self.scorer.determine_level(&score);

        let current = self.current_level.load(Ordering::Relaxed);
        if new_level.as_u8() != current {
            self.current_level
                .store(new_level.as_u8(), Ordering::Relaxed);
            *self.cooldown_until.write() = now + self.cooldown_duration;
            let _ = self.scale_tx.send(new_level);

            tracing::info!(
                "ThreatLevel auto-scaled: {} -> {} (score: {:.2})",
                current,
                new_level.as_u8(),
                score.aggregate_score
            );

            return Some(new_level);
        }

        None
    }

    pub fn record_history_sample(&self) {
        let metrics = self.collector.get_current_metrics();
        let baselines = self.learner.get_all_baselines();
        let score = self.scorer.calculate_score(&metrics, &baselines);
        let level = self.scorer.determine_level(&score);

        let now = crate::utils::safe_unix_timestamp() as i64;

        let sample = ThreatHistorySample {
            timestamp: now,
            level: level.as_u8(),
            score: score.aggregate_score,
            requests_per_second: metrics.requests_per_second,
            requests_per_minute: metrics.requests_per_minute,
            attacks_per_minute: metrics.attacks_per_minute,
            rate_limit_hits: metrics.rate_limit_hits_per_minute,
            blocked: metrics.blocked_per_minute,
        };

        self.history.add_sample(sample.clone());

        if let Some(ref sql_history) = self.sql_history {
            sql_history.add_sample(sample);
        }
    }

    pub fn get_throttling_multiplier(&self) -> f64 {
        let level = self.get_level();
        self.scorer.get_throttling_multiplier(level)
    }

    pub fn get_rate_limit_multiplier(&self) -> f32 {
        self.get_throttling_multiplier() as f32
    }

    pub fn get_status(&self) -> ThreatStatus {
        let metrics = self.collector.get_current_metrics();
        let baselines = self.learner.get_all_baselines();
        let score = self.scorer.calculate_score(&metrics, &baselines);
        let level = self.scorer.determine_level(&score);

        ThreatStatus {
            level: level.as_u8(),
            score: score.aggregate_score,
            request_score: score.request_z_score,
            attack_score: score.attack_z_score,
            rate_limit_score: score.rate_limit_z_score,
            throttling_multiplier: self.scorer.get_throttling_multiplier(level),
            is_learning: self.learner.is_learning(),
            learning_progress: self.learner.learning_progress(),
            has_baseline: !baselines.is_empty(),
        }
    }

    pub fn get_metrics(&self) -> ThreatMetrics {
        self.collector.get_current_metrics()
    }

    pub fn get_totals(&self) -> (u64, u64, u64, u64) {
        self.collector.get_total_counts()
    }

    pub fn get_baselines(&self) -> Vec<BaselineStats> {
        self.learner.get_all_baselines()
    }

    pub fn get_learning_stats(&self) -> LearningStats {
        self.learner.get_learning_stats()
    }

    pub fn get_history(&self) -> ThreatHistoryAll {
        if let Some(ref sql_history) = self.sql_history {
            return sql_history.get_all_history();
        }
        self.history.get_all_history()
    }

    pub fn prune_history(&self) -> std::io::Result<usize> {
        if let Some(ref sql_history) = self.sql_history {
            return sql_history.prune(self.config.history_retention_days);
        }
        Ok(0)
    }

    pub fn get_history_sample_count(&self) -> i64 {
        if let Some(ref sql_history) = self.sql_history {
            return sql_history.get_total_sample_count();
        }
        0
    }

    pub fn get_base_ban_duration(&self, violations_count: u32) -> u64 {
        let level = self.get_level().as_u8();

        let base_seconds = match level {
            1 => 3600,
            2 => 14400,
            3 => 86400,
            4 => 604800,
            5 => 0,
            _ => 3600,
        };

        if base_seconds == 0 {
            return 0;
        }

        let multiplier = 2u64.saturating_pow(violations_count.saturating_sub(1));
        base_seconds * multiplier
    }

    pub fn subscribe(&self) -> broadcast::Receiver<ThreatLevel> {
        self.scale_tx.subscribe()
    }

    pub fn get_legacy_config(&self) -> LegacyThreatLevelConfig {
        LegacyThreatLevelConfig {
            escalation: LegacyEscalationConfig {
                enabled: true,
                violations_before_block: 3,
                violation_window_secs: 300,
                excluded_ips: vec!["127.0.0.1".to_string()],
            },
            auto_scale: true,
            initial: 1,
            cooldown_secs: 60,
            scale_up_window_secs: 60,
            scale_up_attacks_per_min: 50,
            scale_down_window_secs: 300,
            scale_down_attacks_per_min: 10,
            persist_interval_normal_secs: 60,
            persist_interval_attack_secs: 15,
        }
    }

    pub fn save_baseline(&self) {
        let baselines = self.learner.get_all_baselines();
        if baselines.is_empty() {
            return;
        }

        if let Err(e) = self
            .persistence
            .save(&baselines, self.config.learning_duration_secs, None)
        {
            tracing::error!("Failed to save baseline: {}", e);
        }
    }

    pub fn reset_baseline(&self) {
        self.learner.reset();
        self.learner.start_learning();
        tracing::info!("Baseline reset and learning restarted");
    }

    pub fn force_baseline_complete(&self) {
        let baselines = self.learner.get_all_baselines();
        if !baselines.is_empty() {
            self.save_baseline();
        }
        self.learner.complete_learning();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_threat_level_manager_creation() {
        let config = ThreatLevelConfig::default();
        let manager = ThreatLevelManager::new(config, None, None);

        assert_eq!(manager.get_level().as_u8(), 1);
    }

    #[test]
    fn test_record_metrics() {
        let config = ThreatLevelConfig::default();
        let manager = ThreatLevelManager::new(config, None, None);

        manager.record_request();
        manager.record_request();
        manager.record_attack();
        manager.record_rate_limit_hit();

        let metrics = manager.get_metrics();
        assert_eq!(metrics.requests_per_minute, 2);
        assert_eq!(metrics.attacks_per_minute, 1);
    }

    #[test]
    fn test_manual_override() {
        let config = ThreatLevelConfig::default();
        let manager = ThreatLevelManager::new(config, None, None);

        manager.set_level(4);
        assert_eq!(manager.get_level().as_u8(), 4);
        assert!(manager.is_manual());

        manager.reset_to_auto();
        assert_eq!(manager.get_level().as_u8(), 1);
        assert!(!manager.is_manual());
    }

    #[test]
    fn test_threat_status() {
        let config = ThreatLevelConfig::default();
        let manager = ThreatLevelManager::new(config, None, None);

        manager.record_request();
        manager.record_request();

        let status = manager.get_status();
        assert!(status.level >= 1);
    }
}
