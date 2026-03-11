use crate::waf::threat_level::baseline::BaselineStats;
use crate::waf::threat_level::collector::ThreatMetrics;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ThreatLevel(pub u8);

impl ThreatLevel {
    pub const MIN: Self = Self(1);
    pub const MAX: Self = Self(5);

    pub fn new(level: u8) -> Self {
        Self(level.clamp(Self::MIN.0, Self::MAX.0))
    }

    pub fn as_u8(self) -> u8 {
        self.0
    }
}

impl Default for ThreatLevel {
    fn default() -> Self {
        Self(1)
    }
}

impl std::fmt::Display for ThreatLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct ThreatScore {
    pub request_z_score: f64,
    pub attack_z_score: f64,
    pub rate_limit_z_score: f64,
    pub aggregate_score: f64,
}

impl ThreatScore {
    pub fn new(request_z_score: f64, attack_z_score: f64, rate_limit_z_score: f64) -> Self {
        let attack_weight = 2.0;
        let rate_limit_weight = 1.5;

        let weighted_sum = request_z_score.powi(2)
            + (attack_z_score * attack_weight).powi(2)
            + (rate_limit_z_score * rate_limit_weight).powi(2);

        let aggregate_score = weighted_sum.sqrt();

        Self {
            request_z_score,
            attack_z_score,
            rate_limit_z_score,
            aggregate_score,
        }
    }

    pub fn from_no_baseline(metrics: &ThreatMetrics) -> Self {
        let request_score = Self::normalize_requests(metrics.requests_per_minute);
        let attack_score = Self::normalize_attacks(metrics.attacks_per_minute);
        let rate_limit_score = Self::normalize_rate_limits(metrics.rate_limit_hits_per_minute);

        Self::new(request_score, attack_score, rate_limit_score)
    }

    fn normalize_requests(rpm: u32) -> f64 {
        if rpm < 50 {
            0.0
        } else if rpm < 200 {
            ((rpm - 50) as f64 / 150.0).clamp(0.0, 1.0)
        } else if rpm < 1000 {
            1.0 + ((rpm - 200) as f64 / 800.0).clamp(0.0, 1.0)
        } else {
            2.0 + ((rpm - 1000) as f64 / 4000.0).clamp(0.0, 1.0)
        }
    }

    fn normalize_attacks(apm: u32) -> f64 {
        if apm == 0 {
            0.0
        } else if apm < 5 {
            0.5
        } else if apm < 20 {
            1.0 + ((apm - 5) as f64 / 15.0).clamp(0.0, 1.0)
        } else {
            2.0 + ((apm - 20) as f64 / 80.0).clamp(0.0, 1.0)
        }
    }

    fn normalize_rate_limits(rlh: u32) -> f64 {
        if rlh == 0 {
            0.0
        } else if rlh < 10 {
            ((rlh) as f64 / 10.0).clamp(0.0, 1.0)
        } else if rlh < 100 {
            1.0 + ((rlh - 10) as f64 / 90.0).clamp(0.0, 1.0)
        } else {
            2.0 + ((rlh - 100) as f64 / 400.0).clamp(0.0, 1.0)
        }
    }
}

pub struct ThreatScorer {
    sigma_scale_up: f64,
    sigma_scale_down: f64,
    attack_weight: f64,
    rate_limit_weight: f64,
}

impl ThreatScorer {
    pub fn new(
        sigma_scale_up: f64,
        sigma_scale_down: f64,
        attack_weight: f64,
        rate_limit_weight: f64,
    ) -> Self {
        Self {
            sigma_scale_up,
            sigma_scale_down,
            attack_weight,
            rate_limit_weight,
        }
    }

    pub fn calculate_score(
        &self,
        metrics: &ThreatMetrics,
        baselines: &[BaselineStats],
    ) -> ThreatScore {
        let get_baseline = |name: &str| -> Option<&BaselineStats> {
            baselines.iter().find(|b| b.metric_name == name)
        };

        let request_z = if let Some(baseline) = get_baseline("requests_per_minute") {
            baseline
                .z_score(metrics.requests_per_minute as f64)
                .max(0.0)
        } else {
            ThreatScore::normalize_requests(metrics.requests_per_minute)
        };

        let attack_z = if let Some(baseline) = get_baseline("attacks_per_minute") {
            baseline.z_score(metrics.attacks_per_minute as f64).max(0.0) * self.attack_weight
        } else {
            ThreatScore::normalize_attacks(metrics.attacks_per_minute)
        };

        let rate_limit_z = if let Some(baseline) = get_baseline("rate_limit_hits_per_minute") {
            baseline
                .z_score(metrics.rate_limit_hits_per_minute as f64)
                .max(0.0)
                * self.rate_limit_weight
        } else {
            ThreatScore::normalize_rate_limits(metrics.rate_limit_hits_per_minute)
        };

        ThreatScore::new(request_z, attack_z, rate_limit_z)
    }

    pub fn determine_level(&self, score: &ThreatScore) -> ThreatLevel {
        let aggregate = score.aggregate_score;

        if aggregate < 0.5 {
            ThreatLevel(1)
        } else if aggregate < 1.5 {
            ThreatLevel(2)
        } else if aggregate < 2.5 {
            ThreatLevel(3)
        } else if aggregate < 3.5 {
            ThreatLevel(4)
        } else {
            ThreatLevel(5)
        }
    }

    pub fn determine_level_with_baseline(
        &self,
        score: &ThreatScore,
        baselines: &[BaselineStats],
    ) -> ThreatLevel {
        if baselines.is_empty() {
            return self.determine_level(score);
        }

        let has_valid_baseline = baselines.iter().any(|b| b.samples > 10 && b.std_dev > 0.0);

        if !has_valid_baseline {
            return self.determine_level(score);
        }

        let mut sigma_levels = Vec::new();

        for baseline in baselines {
            if baseline.samples < 10 || baseline.std_dev == 0.0 {
                continue;
            }

            let z = baseline.z_score(0.0);

            let level = if z > self.sigma_scale_up * 2.0 {
                5
            } else if z > self.sigma_scale_up * 1.5 {
                4
            } else if z > self.sigma_scale_up {
                3
            } else if z > self.sigma_scale_down {
                2
            } else {
                1
            };

            sigma_levels.push(level as u8);
        }

        if sigma_levels.is_empty() {
            return self.determine_level(score);
        }

        let max_sigma_level = *sigma_levels.iter().max().unwrap_or(&1);
        let avg_score_level = self.determine_level(score).as_u8();

        ThreatLevel(std::cmp::max(max_sigma_level, avg_score_level))
    }

    pub fn get_throttling_multiplier(&self, level: ThreatLevel) -> f64 {
        match level.as_u8() {
            1 => 1.0,
            2 => 0.75,
            3 => 0.5,
            4 => 0.25,
            5 => 0.1,
            _ => 1.0,
        }
    }
}

impl Default for ThreatScorer {
    fn default() -> Self {
        Self::new(2.0, 0.5, 2.0, 1.5)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatStatus {
    pub level: u8,
    pub score: f64,
    pub request_score: f64,
    pub attack_score: f64,
    pub rate_limit_score: f64,
    pub throttling_multiplier: f64,
    pub is_learning: bool,
    pub learning_progress: f64,
    pub has_baseline: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_threat_level_bounds() {
        assert_eq!(ThreatLevel::new(0).0, 1);
        assert_eq!(ThreatLevel::new(3).0, 3);
        assert_eq!(ThreatLevel::new(6).0, 5);
    }

    #[test]
    fn test_threat_score_calculation() {
        let score = ThreatScore::new(1.0, 2.0, 0.5);
        assert!(score.aggregate_score > 0.0);
    }

    #[test]
    fn test_threat_scorer_level() {
        let scorer = ThreatScorer::default();

        let score_low = ThreatScore::new(0.1, 0.1, 0.0);
        assert_eq!(scorer.determine_level(&score_low).as_u8(), 1);

        let score_high = ThreatScore::new(5.0, 5.0, 5.0);
        assert_eq!(scorer.determine_level(&score_high).as_u8(), 5);
    }

    #[test]
    fn test_throttling_multiplier() {
        let scorer = ThreatScorer::default();

        assert!((scorer.get_throttling_multiplier(ThreatLevel(1)) - 1.0).abs() < 0.001);
        assert!((scorer.get_throttling_multiplier(ThreatLevel(5)) - 0.1).abs() < 0.001);
    }

    #[test]
    fn test_baseline_z_score() {
        let baseline = BaselineStats {
            metric_name: "test".to_string(),
            mean: 100.0,
            std_dev: 10.0,
            min_value: 50.0,
            max_value: 150.0,
            samples: 100,
            computed_at: 1234567890,
        };

        assert_eq!(baseline.z_score(100.0), 0.0);
        assert_eq!(baseline.z_score(110.0), 1.0);
        assert_eq!(baseline.z_score(90.0), -1.0);
    }
}
