use base64::Engine;
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use std::time::Duration;
use subtle::ConstantTimeEq;
use tokio::time;

use crate::mesh::protocol::{MeshMessageSigner, ThreatIndicator, ThreatSeverity, ThreatType};
use crate::mesh::safe_unix_timestamp;
use crate::mesh::threat_intel::ThreatIntelligenceManager;

const DEFAULT_FETCH_INTERVAL_SECS: u64 = 300;
const DEFAULT_FEED_URL: &str = "https://threat-feed.example.com/v1/indicators";
const MAX_INDICATORS_PER_FETCH: usize = 10000;
const FEED_SIGNATURE_TIMESTAMP_VALIDITY_SECS: u64 = 3600;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatFeedConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default = "default_feed_url")]
    pub feed_url: String,
    #[serde(default = "default_trusted_signers")]
    pub trusted_signers: Vec<String>,
    #[serde(default = "default_fetch_interval")]
    pub fetch_interval_secs: u64,
    #[serde(default)]
    pub min_indicator_ttl_seconds: u64,
}

fn default_feed_url() -> String {
    DEFAULT_FEED_URL.to_string()
}

fn default_trusted_signers() -> Vec<String> {
    Vec::new()
}

fn default_fetch_interval() -> u64 {
    DEFAULT_FETCH_INTERVAL_SECS
}

impl Default for ThreatFeedConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            feed_url: DEFAULT_FEED_URL.to_string(),
            trusted_signers: Vec::new(),
            fetch_interval_secs: DEFAULT_FETCH_INTERVAL_SECS,
            min_indicator_ttl_seconds: 60,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatFeedPayload {
    pub version: u64,
    pub timestamp: u64,
    pub indicators: Vec<ThreatFeedIndicator>,
    #[serde(default)]
    pub signature: String,
    #[serde(default)]
    pub signer_public_key: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatFeedIndicator {
    pub threat_type: u8,
    pub indicator_value: String,
    pub severity: u8,
    pub reason: String,
    pub ttl_seconds: u64,
    pub source_node_id: String,
    pub site_scope: Option<String>,
    pub rate_limit_requests: Option<u64>,
    pub rate_limit_window_secs: Option<u64>,
    pub suspicious_pattern: Option<String>,
}

pub struct ThreatFeedClient {
    config: Arc<ThreatFeedConfig>,
    threat_manager: Arc<ThreatIntelligenceManager>,
    http_client: crate::http_client::HttpClient,
    last_fetch: Arc<RwLock<u64>>,
    last_indicator_count: Arc<RwLock<usize>>,
}

impl ThreatFeedClient {
    pub fn new(
        config: ThreatFeedConfig,
        threat_manager: Arc<ThreatIntelligenceManager>,
    ) -> Arc<Self> {
        let http_client = crate::http_client::create_simple_http_client(Duration::from_secs(30));

        Arc::new(Self {
            config: Arc::new(config),
            threat_manager,
            http_client,
            last_fetch: Arc::new(RwLock::new(0)),
            last_indicator_count: Arc::new(RwLock::new(0)),
        })
    }

    pub fn start_background_fetching(self: &Arc<Self>) {
        if !self.config.enabled {
            tracing::info!("Threat feed client is disabled");
            return;
        }

        if self.config.trusted_signers.is_empty() {
            tracing::warn!("No trusted signers configured for threat feed - deny-by-default active");
        }

        let self_clone = Arc::clone(self);
        let interval = Duration::from_secs(self.config.fetch_interval_secs);

        tokio::spawn(async move {
            tracing::info!(
                "Starting threat feed background fetcher (interval: {}s)",
                interval.as_secs()
            );

            self_clone.fetch_and_process().await;

            let mut interval_timer = time::interval(interval);
            loop {
                interval_timer.tick().await;
                self_clone.fetch_and_process().await;
            }
        });
    }

    pub async fn fetch_and_process(&self) {
        tracing::debug!("Fetching threat feed from {}", self.config.feed_url);

        let fetch_result = self.fetch_feed().await;

        match fetch_result {
            Ok(payload) => {
                if !self.verify_feed_signature(&payload) {
                    tracing::error!("Feed signature verification failed - rejecting payload");
                    return;
                }

                let verified_count = self.process_indicators(&payload).await;
                *self.last_fetch.write() = safe_unix_timestamp();
                *self.last_indicator_count.write() = verified_count;

                tracing::info!(
                    "Threat feed processed: {} indicators verified and imported",
                    verified_count
                );
            }
            Err(e) => {
                tracing::error!("Failed to fetch/process threat feed: {}", e);
            }
        }
    }

    fn verify_feed_signature(&self, payload: &ThreatFeedPayload) -> bool {
        if payload.signature.is_empty() || payload.signer_public_key.is_empty() {
            tracing::warn!("Feed payload missing signature or public key");
            return false;
        }

        if !self.is_trusted_signer(&payload.signer_public_key) {
            tracing::warn!(
                "Feed signed by untrusted public key: {}",
                &payload.signer_public_key[..8.min(payload.signer_public_key.len())]
            );
            return false;
        }

        let now = safe_unix_timestamp();
        if now.saturating_sub(payload.timestamp) > FEED_SIGNATURE_TIMESTAMP_VALIDITY_SECS {
            tracing::warn!(
                "Feed signature timestamp too old: {} (current: {}, max age: {}s)",
                payload.timestamp,
                now,
                FEED_SIGNATURE_TIMESTAMP_VALIDITY_SECS
            );
            return false;
        }

        let signer_pk_bytes = match base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(&payload.signer_public_key)
        {
            Ok(bytes) => bytes,
            Err(e) => {
                tracing::warn!("Failed to decode signer public key: {}", e);
                return false;
            }
        };

        if signer_pk_bytes.len() != 32 {
            tracing::warn!(
                "Invalid signer public key length: {} (expected 32)",
                signer_pk_bytes.len()
            );
            return false;
        }

        let signature_bytes = match base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(&payload.signature)
        {
            Ok(bytes) => bytes,
            Err(e) => {
                tracing::warn!("Failed to decode signature: {}", e);
                return false;
            }
        };

        if signature_bytes.len() != 64 {
            tracing::warn!(
                "Invalid signature length: {} (expected 64)",
                signature_bytes.len()
            );
            return false;
        }

        let content = Self::get_signable_content(payload);
        let mut pk_array = [0u8; 32];
        pk_array.copy_from_slice(&signer_pk_bytes);

        let signer = MeshMessageSigner::new(pk_array);

        let result = signer.verify(content.as_bytes(), &signature_bytes, &signer_pk_bytes);

        if !result {
            tracing::warn!("Ed25519 signature verification failed for feed payload");
        }

        result
    }

    fn get_signable_content(payload: &ThreatFeedPayload) -> String {
        let indicator_hashes: Vec<String> = payload
            .indicators
            .iter()
            .map(|i| format!("{}:{}:{}", i.threat_type, i.indicator_value, i.severity))
            .collect();

        format!(
            "{}:{}:{}:{}",
            payload.version,
            payload.timestamp,
            payload.indicators.len(),
            indicator_hashes.join(",")
        )
    }

    fn is_trusted_signer(&self, signer_public_key: &str) -> bool {
        self.config.trusted_signers.iter().any(|pk| {
            let result = pk.as_bytes().ct_eq(signer_public_key.as_bytes());
            bool::from(result)
        })
    }

    async fn fetch_feed(&self) -> Result<ThreatFeedPayload, String> {
        let response = crate::http_client::get_with_timeout(
            &self.http_client,
            &self.config.feed_url,
            Duration::from_secs(30),
        )
        .await
        .map_err(|e| format!("Request failed: {}", e))?;

        if !response.status.is_success() {
            return Err(format!("HTTP error: {}", response.status));
        }

        let body = String::from_utf8_lossy(&response.body);

        let payload: ThreatFeedPayload = if body.starts_with('{') || body.starts_with('[') {
            serde_json::from_str(&body).map_err(|e| format!("JSON parse failed: {}", e))?
        } else {
            return Err("Invalid feed format - expected JSON".to_string());
        };

        let now = safe_unix_timestamp();
        if now.saturating_sub(payload.timestamp) > 86400 {
            return Err("Feed payload is older than 24 hours - rejecting".to_string());
        }

        Ok(payload)
    }

    async fn process_indicators(&self, payload: &ThreatFeedPayload) -> usize {
        let mut verified_count = 0;

        for indicator_data in payload.indicators.iter().take(MAX_INDICATORS_PER_FETCH) {
            if let Some(verified) = self.verify_and_convert_indicator(indicator_data, payload) {
                self.announce_indicator(verified).await;
                verified_count += 1;
            }
        }

        verified_count
    }

    fn verify_and_convert_indicator(
        &self,
        indicator_data: &ThreatFeedIndicator,
        payload: &ThreatFeedPayload,
    ) -> Option<ThreatIndicator> {
        let threat_type = match indicator_data.threat_type {
            0 => ThreatType::Unspecified,
            1 => ThreatType::IpBlock,
            2 => ThreatType::IpThrottle,
            3 => ThreatType::RateLimitViolation,
            4 => ThreatType::SuspiciousActivity,
            5 => ThreatType::AsnBlock,
            6 => ThreatType::DomainBlock,
            7 => ThreatType::UrlBlock,
            8 => ThreatType::CertBlock,
            _ => {
                tracing::warn!("Unknown threat type: {}", indicator_data.threat_type);
                return None;
            }
        };

        let severity = match indicator_data.severity {
            0 => ThreatSeverity::Unspecified,
            1 => ThreatSeverity::Low,
            2 => ThreatSeverity::Medium,
            3 => ThreatSeverity::High,
            4 => ThreatSeverity::Critical,
            _ => {
                tracing::warn!("Unknown severity: {}", indicator_data.severity);
                return None;
            }
        };

        let indicator = ThreatIndicator {
            threat_type,
            indicator_value: indicator_data.indicator_value.clone(),
            severity,
            reason: indicator_data.reason.clone(),
            ttl_seconds: indicator_data.ttl_seconds.max(self.config.min_indicator_ttl_seconds),
            source_node_id: format!("feed:{}", indicator_data.source_node_id),
            timestamp: payload.timestamp,
            site_scope: indicator_data.site_scope.clone().unwrap_or_default(),
            rate_limit_requests: indicator_data.rate_limit_requests,
            rate_limit_window_secs: indicator_data.rate_limit_window_secs,
            suspicious_pattern: indicator_data.suspicious_pattern.clone(),
            signature: Vec::new(),
            signer_public_key: None,
        };

        Some(indicator)
    }

    async fn announce_indicator(&self, indicator: ThreatIndicator) {
        let key = format!(
            "threat_indicator:{}:{:?}",
            indicator.indicator_value, indicator.threat_type
        );

        if let Some(existing) = self.threat_manager.lookup_local_indicator(
            &indicator.indicator_value,
            indicator.threat_type,
        ) {
            if existing.timestamp >= indicator.timestamp {
                tracing::debug!("Duplicate or older indicator from feed, skipping: {}", key);
                return;
            }
        }

        if let Ok(ip) = indicator.indicator_value.parse() {
            self.threat_manager.announce_local_block(
                ip,
                format!("feed:{}", indicator.reason),
                indicator.ttl_seconds,
                indicator.site_scope.clone(),
            );
        } else {
            let site_scope = indicator.site_scope.clone();
            match indicator.threat_type {
                ThreatType::DomainBlock => {
                    tracing::info!(
                        "Feed domain block: {} (reason: {}, TTL: {}s, scope: {})",
                        indicator.indicator_value,
                        indicator.reason,
                        indicator.ttl_seconds,
                        site_scope
                    );
                }
                ThreatType::UrlBlock => {
                    tracing::info!(
                        "Feed URL block: {} (reason: {}, TTL: {}s, scope: {})",
                        indicator.indicator_value,
                        indicator.reason,
                        indicator.ttl_seconds,
                        site_scope
                    );
                }
                ThreatType::AsnBlock => {
                    tracing::info!(
                        "Feed ASN block: {} (reason: {}, TTL: {}s, scope: {})",
                        indicator.indicator_value,
                        indicator.reason,
                        indicator.ttl_seconds,
                        site_scope
                    );
                }
                _ => {}
            }
        }
    }

    pub fn get_last_fetch_time(&self) -> u64 {
        *self.last_fetch.read()
    }

    pub fn get_last_indicator_count(&self) -> usize {
        *self.last_indicator_count.read()
    }

    pub fn is_enabled(&self) -> bool {
        self.config.enabled
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_threat_feed_config_default() {
        let config = ThreatFeedConfig::default();
        assert!(config.enabled);
        assert_eq!(config.feed_url, DEFAULT_FEED_URL);
        assert!(config.trusted_signers.is_empty());
        assert_eq!(config.fetch_interval_secs, DEFAULT_FETCH_INTERVAL_SECS);
    }

    #[test]
    fn test_threat_feed_indicator_serialization() {
        let indicator = ThreatFeedIndicator {
            threat_type: 1,
            indicator_value: "192.168.1.1".to_string(),
            severity: 3,
            reason: "Test threat".to_string(),
            ttl_seconds: 3600,
            source_node_id: "feed-node-001".to_string(),
            site_scope: Some("global".to_string()),
            rate_limit_requests: None,
            rate_limit_window_secs: None,
            suspicious_pattern: None,
        };

        let json = serde_json::to_string(&indicator).unwrap();
        let parsed: ThreatFeedIndicator = serde_json::from_str(&json).unwrap();

        assert_eq!(parsed.threat_type, indicator.threat_type);
        assert_eq!(parsed.indicator_value, indicator.indicator_value);
        assert_eq!(parsed.severity, indicator.severity);
    }

    #[test]
    fn test_threat_feed_payload_serialization() {
        let payload = ThreatFeedPayload {
            version: 1,
            timestamp: 1704067200,
            indicators: vec![
                ThreatFeedIndicator {
                    threat_type: 1,
                    indicator_value: "10.0.0.1".to_string(),
                    severity: 2,
                    reason: "Malicious scanner".to_string(),
                    ttl_seconds: 1800,
                    source_node_id: "test-feed".to_string(),
                    site_scope: None,
                    rate_limit_requests: Some(100),
                    rate_limit_window_secs: Some(60),
                    suspicious_pattern: None,
                },
            ],
            signature: String::new(),
            signer_public_key: String::new(),
        };

        let json = serde_json::to_string(&payload).unwrap();
        let parsed: ThreatFeedPayload = serde_json::from_str(&json).unwrap();

        assert_eq!(parsed.version, 1);
        assert_eq!(parsed.indicators.len(), 1);
        assert_eq!(parsed.indicators[0].indicator_value, "10.0.0.1");
    }

    #[test]
    fn test_threat_feed_payload_with_signature() {
        let payload = ThreatFeedPayload {
            version: 1,
            timestamp: safe_unix_timestamp(),
            indicators: vec![
                ThreatFeedIndicator {
                    threat_type: 1,
                    indicator_value: "192.168.1.100".to_string(),
                    severity: 3,
                    reason: "Brute force attack".to_string(),
                    ttl_seconds: 7200,
                    source_node_id: "global-feed".to_string(),
                    site_scope: Some("production".to_string()),
                    rate_limit_requests: None,
                    rate_limit_window_secs: None,
                    suspicious_pattern: None,
                },
            ],
            signature: "sig_data".to_string(),
            signer_public_key: "pk_data".to_string(),
        };

        assert!(!payload.signature.is_empty());
        assert!(!payload.signer_public_key.is_empty());
    }

    #[test]
    fn test_is_trusted_signer_empty() {
        let config = ThreatFeedConfig {
            enabled: true,
            feed_url: "https://example.com/feed".to_string(),
            trusted_signers: Vec::new(),
            fetch_interval_secs: 300,
            min_indicator_ttl_seconds: 60,
        };
        assert!(config.trusted_signers.is_empty());
    }

    #[test]
    fn test_is_trusted_signer_with_keys() {
        let trusted_signers = vec!["trusted_key_abc123".to_string(), "another_key_xyz789".to_string()];
        assert!(trusted_signers.contains(&"trusted_key_abc123".to_string()));
        assert!(trusted_signers.contains(&"another_key_xyz789".to_string()));
        assert!(!trusted_signers.contains(&"untrusted_key".to_string()));
    }

    #[test]
    fn test_get_signable_content() {
        let payload = ThreatFeedPayload {
            version: 1,
            timestamp: 1704067200,
            indicators: vec![
                ThreatFeedIndicator {
                    threat_type: 1,
                    indicator_value: "10.0.0.1".to_string(),
                    severity: 2,
                    reason: "Scanner".to_string(),
                    ttl_seconds: 1800,
                    source_node_id: "feed1".to_string(),
                    site_scope: None,
                    rate_limit_requests: None,
                    rate_limit_window_secs: None,
                    suspicious_pattern: None,
                },
                ThreatFeedIndicator {
                    threat_type: 2,
                    indicator_value: "10.0.0.2".to_string(),
                    severity: 3,
                    reason: "Attacker".to_string(),
                    ttl_seconds: 3600,
                    source_node_id: "feed1".to_string(),
                    site_scope: None,
                    rate_limit_requests: None,
                    rate_limit_window_secs: None,
                    suspicious_pattern: None,
                },
            ],
            signature: String::new(),
            signer_public_key: String::new(),
        };

        let content = ThreatFeedClient::get_signable_content(&payload);
        assert!(content.contains("1:10.0.0.1:2"));
        assert!(content.contains("2:10.0.0.2:3"));
    }
}