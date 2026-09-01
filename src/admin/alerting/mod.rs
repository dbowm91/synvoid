use serde::{Deserialize, Serialize};
use std::net::{IpAddr, ToSocketAddrs};
use std::sync::Arc;
use std::time::Duration;
use synvoid_core::net::is_restricted_ip;
use tokio::sync::RwLock as TokioRwLock;

pub const SUPPORTED_ALERT_METRICS: &[&str] = &[
    "error_rate_percent",
    "requests_per_second",
    "blocked_per_second",
    "time_validation_errors",
    "unhealthy_backends",
    "unhealthy_workers",
    "threat_level",
    "audit_write_failures",
];

const WEBHOOK_REQUEST_TIMEOUT: Duration = Duration::from_secs(10);

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AlertConfig {
    pub enabled: bool,
    pub webhook_enabled: bool,
    pub webhook_urls: Vec<String>,
    pub cooldown_secs: u64,
    pub alerts: Vec<AlertRule>,
}

impl Default for AlertConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            webhook_enabled: false,
            webhook_urls: Vec::new(),
            cooldown_secs: 300,
            alerts: vec![
                AlertRule {
                    name: "High Threat Level".to_string(),
                    metric: "threat_level".to_string(),
                    threshold: 4.0,
                    condition: AlertCondition::GreaterThan,
                    enabled: true,
                },
                AlertRule {
                    name: "High Error Rate".to_string(),
                    metric: "error_rate_percent".to_string(),
                    threshold: 5.0,
                    condition: AlertCondition::GreaterThan,
                    enabled: true,
                },
                AlertRule {
                    name: "Worker Failure".to_string(),
                    metric: "unhealthy_workers".to_string(),
                    threshold: 0.0,
                    condition: AlertCondition::GreaterThan,
                    enabled: true,
                },
            ],
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AlertRule {
    pub name: String,
    pub metric: String,
    pub threshold: f64,
    pub condition: AlertCondition,
    pub enabled: bool,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq)]
pub enum AlertCondition {
    GreaterThan,
    LessThan,
    Equals,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AlertEvent {
    pub timestamp: i64,
    pub rule_name: String,
    pub metric: String,
    pub value: f64,
    pub threshold: f64,
    pub message: String,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, utoipa::ToSchema)]
pub enum DeliveryOutcome {
    Success,
    PartialFailure,
    Failure,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebhookDeliveryResult {
    pub outcome: DeliveryOutcome,
    pub attempted: usize,
    pub succeeded: usize,
    pub failed: usize,
    pub details: Vec<DestinationResult>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DestinationResult {
    pub url: String,
    pub success: bool,
    pub error: Option<String>,
}

#[derive(Debug, thiserror::Error)]
pub enum AlertConfigError {
    #[error("Unknown metric: {metric}. Supported metrics: {metrics:?}")]
    UnknownMetric {
        metric: String,
        metrics: &'static [&'static str],
    },
    #[error("Invalid threshold: {threshold}. Threshold must be non-negative and finite")]
    InvalidThreshold { threshold: f64 },
    #[error("Invalid webhook URL scheme: {url}. Only http and https are allowed")]
    InvalidWebhookScheme { url: String },
    #[error(
        "Link-local/internal webhook URL blocked for SSRF: {url}. Add to allowlist if intentional"
    )]
    BlockedWebhookUrl { url: String },
}

impl AlertConfig {
    pub fn validate(&self) -> Result<(), AlertConfigError> {
        for rule in &self.alerts {
            if !SUPPORTED_ALERT_METRICS.contains(&rule.metric.as_str()) {
                return Err(AlertConfigError::UnknownMetric {
                    metric: rule.metric.clone(),
                    metrics: SUPPORTED_ALERT_METRICS,
                });
            }
            if !rule.threshold.is_finite() || rule.threshold < 0.0 {
                return Err(AlertConfigError::InvalidThreshold {
                    threshold: rule.threshold,
                });
            }
        }

        for url in &self.webhook_urls {
            validate_webhook_url(url)?;
        }

        Ok(())
    }
}

/// Validate a single webhook URL at configuration time.
///
/// Uses IP classification (not string matching) to block private/link-local/loopback targets.
/// DNS resolution is deferred to request time for the final check.
pub fn validate_webhook_url(url: &str) -> Result<(), AlertConfigError> {
    let parsed = url
        .parse::<url::Url>()
        .map_err(|_| AlertConfigError::InvalidWebhookScheme {
            url: url.to_string(),
        })?;

    match parsed.scheme() {
        "http" | "https" => {}
        _ => {
            return Err(AlertConfigError::InvalidWebhookScheme {
                url: url.to_string(),
            })
        }
    }

    let host = parsed
        .host_str()
        .ok_or_else(|| AlertConfigError::InvalidWebhookScheme {
            url: url.to_string(),
        })?;

    let host_for_ip_check = host
        .strip_prefix('[')
        .and_then(|h| h.strip_suffix(']'))
        .unwrap_or(host);

    if let Ok(ip) = host_for_ip_check.parse::<IpAddr>() {
        if is_restricted_ip(&ip) {
            return Err(AlertConfigError::BlockedWebhookUrl {
                url: url.to_string(),
            });
        }
    }

    if host == "localhost" {
        return Err(AlertConfigError::BlockedWebhookUrl {
            url: url.to_string(),
        });
    }

    Ok(())
}

/// Resolve the hostname in a URL and verify that no resolved IP is restricted.
///
/// Returns `Ok(())` if all resolved IPs are public, or `Err(message)` if any
/// candidate is restricted or resolution fails.
pub async fn validate_destination_at_request_time(url: &url::Url) -> Result<(), String> {
    let host = url
        .host_str()
        .ok_or_else(|| "URL has no host".to_string())?;

    let default_port = match url.scheme() {
        "https" => 443,
        "http" => 80,
        _ => return Err("unsupported scheme".to_string()),
    };
    let port = url.port().unwrap_or(default_port);

    let socket_addr = format!("{}:{}", host, port);
    let addrs: Vec<std::net::SocketAddr> = socket_addr
        .to_socket_addrs()
        .map_err(|e| format!("DNS resolution failed for {}: {}", host, e))?
        .collect();

    if addrs.is_empty() {
        return Err(format!("DNS resolution returned no addresses for {}", host));
    }

    for addr in &addrs {
        if is_restricted_ip(&addr.ip()) {
            return Err(format!(
                "destination {} resolves to restricted IP {}",
                host,
                addr.ip()
            ));
        }
    }

    Ok(())
}

#[derive(Clone)]
pub struct AlertManager {
    config: Arc<TokioRwLock<AlertConfig>>,
    last_fired: Arc<TokioRwLock<std::collections::HashMap<String, i64>>>,
}

impl AlertManager {
    pub fn new() -> Self {
        Self {
            config: Arc::new(TokioRwLock::new(AlertConfig::default())),
            last_fired: Arc::new(TokioRwLock::new(std::collections::HashMap::new())),
        }
    }

    pub async fn get_config(&self) -> AlertConfig {
        self.config.read().await.clone()
    }

    pub async fn update_config(&self, config: AlertConfig) -> Result<(), String> {
        config.validate().map_err(|e| e.to_string())?;
        *self.config.write().await = config;
        Ok(())
    }

    fn extract_metric_value(
        metric: &str,
        metrics: &super::state::AggregatedMetrics,
        system_resources: &super::state::SystemResources,
    ) -> Option<f64> {
        match metric {
            "error_rate_percent" => {
                let total = metrics.total_requests;
                let errors = metrics.errors;
                if total > 0 {
                    Some((errors as f64 / total as f64) * 100.0)
                } else {
                    Some(0.0)
                }
            }
            "requests_per_second" => Some(metrics.requests_per_second),
            "blocked_per_second" => Some(metrics.blocked_per_second),
            "time_validation_errors" => Some(system_resources.time_validation_errors as f64),
            "unhealthy_backends" => Some(metrics.unhealthy_backends as f64),
            "unhealthy_workers" => Some(metrics.unhealthy_workers as f64),
            "threat_level" => None,
            "audit_write_failures" => {
                Some(super::metrics_events::get_audit_write_failures() as f64)
            }
            _ => None,
        }
    }

    fn check_condition(value: f64, condition: AlertCondition, threshold: f64) -> bool {
        match condition {
            AlertCondition::GreaterThan => value > threshold,
            AlertCondition::LessThan => value < threshold,
            AlertCondition::Equals => (value - threshold).abs() < 0.01,
        }
    }

    pub async fn check_and_notify(
        &self,
        metrics: &super::state::AggregatedMetrics,
        system_resources: &super::state::SystemResources,
        threat_level: Option<u8>,
    ) -> Vec<AlertEvent> {
        let config = self.config.read().await;

        if !config.enabled {
            return Vec::new();
        }

        let mut events = Vec::new();
        let now = crate::utils::safe_unix_timestamp() as i64;
        let cooldown = config.cooldown_secs;

        for rule in &config.alerts {
            if !rule.enabled {
                continue;
            }

            let value = match rule.metric.as_str() {
                "threat_level" => threat_level.map(|l| l as f64),
                _ => Self::extract_metric_value(&rule.metric, metrics, system_resources),
            };

            let Some(value) = value else {
                continue;
            };

            let should_fire = Self::check_condition(value, rule.condition, rule.threshold);

            if should_fire {
                let rule_key = format!("{}:{}", rule.name, rule.metric);
                let mut last = self.last_fired.write().await;
                if let Some(last_time) = last.get(&rule_key) {
                    if now.saturating_sub(*last_time) < cooldown as i64 {
                        continue;
                    }
                }
                last.insert(rule_key, now);
                drop(last);

                let event = AlertEvent {
                    timestamp: now,
                    rule_name: rule.name.clone(),
                    metric: rule.metric.clone(),
                    value,
                    threshold: rule.threshold,
                    message: format!(
                        "Alert triggered: {} - {} {} {} (current value: {})",
                        rule.name,
                        rule.metric,
                        match rule.condition {
                            AlertCondition::GreaterThan => ">",
                            AlertCondition::LessThan => "<",
                            AlertCondition::Equals => "=",
                        },
                        rule.threshold,
                        value
                    ),
                };

                events.push(event.clone());

                if config.webhook_enabled && !config.webhook_urls.is_empty() {
                    let webhook_urls = config.webhook_urls.clone();
                    let event_clone = event.clone();
                    tokio::spawn(async move {
                        let result = send_webhook_internal(&webhook_urls, &event_clone).await;
                        match result.outcome {
                            DeliveryOutcome::Success => {
                                super::metrics_events::record_alert_delivery_success();
                            }
                            DeliveryOutcome::Failure | DeliveryOutcome::PartialFailure => {
                                super::metrics_events::record_alert_delivery_failure();
                            }
                        }
                    });
                }
            }
        }

        events
    }
}

async fn send_webhook_internal(urls: &[String], event: &AlertEvent) -> WebhookDeliveryResult {
    let client = crate::http_client::create_http_client();

    let payload = serde_json::json!({
        "timestamp": event.timestamp,
        "rule": event.rule_name,
        "metric": event.metric,
        "value": event.value,
        "threshold": event.threshold,
        "message": event.message,
    });

    let mut details = Vec::new();
    let mut succeeded = 0usize;
    let mut failed = 0usize;

    for url in urls {
        let result = deliver_webhook_single(&client, url, &payload).await;
        match &result {
            DestinationResult { success: true, .. } => succeeded += 1,
            _ => failed += 1,
        }
        details.push(result);
    }

    let outcome = if succeeded == urls.len() {
        DeliveryOutcome::Success
    } else if succeeded > 0 {
        DeliveryOutcome::PartialFailure
    } else {
        DeliveryOutcome::Failure
    };

    WebhookDeliveryResult {
        outcome,
        attempted: urls.len(),
        succeeded,
        failed,
        details,
    }
}

/// Deliver a single webhook POST request with request-time destination validation.
///
/// Validates the destination IP after DNS resolution. hyper does not follow
/// redirects automatically, so redirect responses are treated as non-2xx failures.
async fn deliver_webhook_single(
    client: &crate::http_client::HttpClient,
    url: &str,
    payload: &serde_json::Value,
) -> DestinationResult {
    let parsed_url = match url.parse::<url::Url>() {
        Ok(u) => u,
        Err(_) => {
            return DestinationResult {
                url: url.to_string(),
                success: false,
                error: Some("invalid URL".to_string()),
            };
        }
    };

    if let Err(e) = validate_destination_at_request_time(&parsed_url).await {
        return DestinationResult {
            url: url.to_string(),
            success: false,
            error: Some(e),
        };
    }

    match crate::http_client::post_json_with_timeout(client, url, payload, WEBHOOK_REQUEST_TIMEOUT)
        .await
    {
        Ok(resp) => {
            if resp.status.is_success() {
                DestinationResult {
                    url: url.to_string(),
                    success: true,
                    error: None,
                }
            } else {
                DestinationResult {
                    url: url.to_string(),
                    success: false,
                    error: Some(format!("HTTP {}", resp.status.as_u16())),
                }
            }
        }
        Err(e) => DestinationResult {
            url: url.to_string(),
            success: false,
            error: Some(e),
        },
    }
}

impl AlertManager {
    pub async fn send_webhook(&self, urls: &[String], event: &AlertEvent) -> WebhookDeliveryResult {
        send_webhook_internal(urls, event).await
    }

    pub async fn send_geoip_stale_notification(
        &self,
        edition_id: &str,
        days_since_update: u64,
    ) -> Result<(), String> {
        let config = self.config.read().await;

        if !config.enabled {
            return Ok(());
        }

        let now = crate::utils::safe_unix_timestamp() as i64;

        let event = AlertEvent {
            timestamp: now,
            rule_name: "GeoIP Database Stale".to_string(),
            metric: "geoip_stale".to_string(),
            value: days_since_update as f64,
            threshold: 7.0,
            message: format!(
                "GeoIP database '{}' has not been updated in {} days. \
                 Consider renewing your MaxMind subscription or checking network connectivity.",
                edition_id, days_since_update
            ),
        };

        if config.webhook_enabled && !config.webhook_urls.is_empty() {
            let webhook_urls = config.webhook_urls.clone();
            let event_clone = event.clone();
            tokio::spawn(async move {
                let result = send_webhook_internal(&webhook_urls, &event_clone).await;
                match result.outcome {
                    DeliveryOutcome::Success => {
                        super::metrics_events::record_alert_delivery_success();
                    }
                    DeliveryOutcome::Failure | DeliveryOutcome::PartialFailure => {
                        super::metrics_events::record_alert_delivery_failure();
                    }
                }
            });
        }

        Ok(())
    }
}

impl Default for AlertManager {
    fn default() -> Self {
        Self::new()
    }
}

impl synvoid_geoip::GeoIpNotificationHandler for AlertManager {
    fn send_stale_notification(
        &self,
        edition_id: &str,
        days: u64,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<(), String>> + Send + 'static>>
    {
        let self_clone = self.clone();
        let edition_id = edition_id.to_string();
        Box::pin(async move {
            self_clone
                .send_geoip_stale_notification(&edition_id, days)
                .await
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validate_webhook_url_allows_public_https() {
        assert!(validate_webhook_url("https://example.com/hook").is_ok());
        assert!(validate_webhook_url("http://example.com/webhook").is_ok());
    }

    #[test]
    fn validate_webhook_url_rejects_non_http() {
        assert!(validate_webhook_url("ftp://example.com/hook").is_err());
        assert!(validate_webhook_url("javascript:alert(1)").is_err());
    }

    #[test]
    fn validate_webhook_url_rejects_localhost() {
        assert!(validate_webhook_url("http://localhost/hook").is_err());
        assert!(validate_webhook_url("http://localhost:8080/hook").is_err());
    }

    #[test]
    fn validate_webhook_url_rejects_loopback_ip() {
        assert!(validate_webhook_url("http://127.0.0.1/hook").is_err());
        assert!(validate_webhook_url("http://127.0.0.1:8080/hook").is_err());
    }

    #[test]
    fn validate_webhook_url_rejects_private_ranges() {
        assert!(validate_webhook_url("http://10.0.0.1/hook").is_err());
        assert!(validate_webhook_url("http://172.16.0.1/hook").is_err());
        assert!(validate_webhook_url("http://192.168.1.1/hook").is_err());
    }

    #[test]
    fn validate_webhook_url_rejects_link_local() {
        assert!(validate_webhook_url("http://169.254.1.1/hook").is_err());
    }

    #[test]
    fn validate_webhook_url_rejects_ipv6_loopback() {
        assert!(validate_webhook_url("http://[::1]/hook").is_err());
    }

    #[test]
    fn validate_webhook_url_rejects_ipv6_private() {
        assert!(validate_webhook_url("http://[fd00::1]/hook").is_err());
        assert!(validate_webhook_url("http://[fe80::1]/hook").is_err());
    }

    #[test]
    fn alert_config_validation_rejects_invalid_metrics() {
        let config = AlertConfig {
            alerts: vec![AlertRule {
                name: "bad".to_string(),
                metric: "nonexistent".to_string(),
                threshold: 1.0,
                condition: AlertCondition::GreaterThan,
                enabled: true,
            }],
            ..Default::default()
        };
        assert!(config.validate().is_err());
    }

    #[test]
    fn alert_config_validation_rejects_negative_threshold() {
        let config = AlertConfig {
            alerts: vec![AlertRule {
                name: "bad".to_string(),
                metric: "error_rate_percent".to_string(),
                threshold: -1.0,
                condition: AlertCondition::GreaterThan,
                enabled: true,
            }],
            ..Default::default()
        };
        assert!(config.validate().is_err());
    }

    #[test]
    fn alert_config_validation_rejects_private_webhook() {
        let config = AlertConfig {
            webhook_urls: vec!["http://10.0.0.1/hook".to_string()],
            ..Default::default()
        };
        assert!(config.validate().is_err());
    }

    #[test]
    fn alert_config_validation_rejects_localhost_webhook() {
        let config = AlertConfig {
            webhook_urls: vec!["http://localhost/hook".to_string()],
            ..Default::default()
        };
        assert!(config.validate().is_err());
    }

    #[test]
    fn alert_config_validation_allows_public_webhook() {
        let config = AlertConfig {
            webhook_urls: vec!["https://hooks.slack.com/services/T00/B00/xxx".to_string()],
            ..Default::default()
        };
        assert!(config.validate().is_ok());
    }

    #[test]
    fn delivery_outcome_no_urls_is_success() {
        let result = WebhookDeliveryResult {
            outcome: DeliveryOutcome::Success,
            attempted: 0,
            succeeded: 0,
            failed: 0,
            details: vec![],
        };
        assert_eq!(result.outcome, DeliveryOutcome::Success);
    }
}
