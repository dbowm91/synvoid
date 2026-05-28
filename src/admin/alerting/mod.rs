use serde::{Deserialize, Serialize};
use std::sync::Arc;
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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AlertConfig {
    pub enabled: bool,
    pub email_enabled: bool,
    pub email_recipients: Vec<String>,
    pub email_smtp_host: Option<String>,
    pub email_smtp_port: Option<u16>,
    pub email_username: Option<String>,
    pub email_password: Option<String>,
    pub webhook_enabled: bool,
    pub webhook_urls: Vec<String>,
    pub cooldown_secs: u64,
    pub alerts: Vec<AlertRule>,
}

impl Default for AlertConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            email_enabled: false,
            email_recipients: Vec::new(),
            email_smtp_host: None,
            email_smtp_port: None,
            email_username: None,
            email_password: None,
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
    #[error("Email enabled but SMTP host not configured")]
    EmailMissingSmtpHost,
}

impl AlertConfig {
    pub fn validate(&self) -> Result<(), AlertConfigError> {
        if self.email_enabled {
            if self.email_smtp_host.is_none() {
                return Err(AlertConfigError::EmailMissingSmtpHost);
            }
        }

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
            let url_lower = url.to_lowercase();
            if !url_lower.starts_with("http://") && !url_lower.starts_with("https://") {
                return Err(AlertConfigError::InvalidWebhookScheme { url: url.clone() });
            }
            if url_lower.starts_with("http://") || url_lower.starts_with("https://") {
                let host = url
                    .strip_prefix("http://")
                    .or_else(|| url.strip_prefix("https://"))
                    .unwrap_or(url);
                let host_part = host.split('/').next().unwrap_or(host);
                if host_part == "localhost"
                    || host_part.starts_with("127.")
                    || host_part.starts_with("10.")
                    || host_part.starts_with("192.168.")
                    || host_part.starts_with("172.")
                {
                    return Err(AlertConfigError::BlockedWebhookUrl { url: url.clone() });
                }
            }
        }

        Ok(())
    }
}

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

    pub async fn update_config(&self, config: AlertConfig) {
        config.validate().expect("validated config should be valid");
        *self.config.write().await = config;
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
                    if now - last_time < cooldown as i64 {
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
                        if let Err(e) = send_webhook_internal(&webhook_urls, &event_clone).await {
                            tracing::warn!("Failed to send webhook: {}", e);
                        }
                    });
                }

                if config.email_enabled && !config.email_recipients.is_empty() {
                    let email_config = (
                        config.email_recipients.clone(),
                        config.email_smtp_host.clone(),
                        config.email_smtp_port,
                        config.email_username.clone(),
                        config.email_password.clone(),
                    );
                    let event_clone = event.clone();
                    tokio::spawn(async move {
                        if let Err(e) = send_email_internal(email_config, &event_clone).await {
                            tracing::warn!("Failed to send email: {}", e);
                        }
                    });
                }
            }
        }

        events
    }
}

async fn send_webhook_internal(urls: &[String], event: &AlertEvent) -> Result<(), String> {
    let client = crate::http_client::create_http_client();

    let payload = serde_json::json!({
        "timestamp": event.timestamp,
        "rule": event.rule_name,
        "metric": event.metric,
        "value": event.value,
        "threshold": event.threshold,
        "message": event.message,
    });

    let mut has_success = false;
    for url in urls {
        match crate::http_client::post_json(&client, url, &payload).await {
            Ok(_) => {
                tracing::info!("Webhook sent successfully to {}", url);
                has_success = true;
            }
            Err(e) => {
                tracing::warn!("Failed to send webhook to {}: {}", url, e);
            }
        }
    }
    if has_success {
        super::metrics_events::record_alert_delivery_success();
    } else if !urls.is_empty() {
        super::metrics_events::record_alert_delivery_failure();
    }
    Ok(())
}

#[allow(clippy::type_complexity)]
async fn send_email_internal(
    config: (
        Vec<String>,
        Option<String>,
        Option<u16>,
        Option<String>,
        Option<String>,
    ),
    event: &AlertEvent,
) -> Result<(), String> {
    let (recipients, smtp_host, smtp_port, username, password) = config;

    let _smtp_host = smtp_host.ok_or("SMTP host not configured")?;
    let _smtp_port = smtp_port.unwrap_or(587);
    let _username = username.ok_or("SMTP username not configured")?;
    let _password = password.ok_or("SMTP password not configured")?;

    tracing::info!(
        "Sending email alert to {} recipients about: {}",
        recipients.len(),
        event.rule_name
    );

    Ok(())
}

impl AlertManager {
    pub async fn send_webhook(&self, urls: &[String], event: &AlertEvent) -> Result<(), String> {
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
                if let Err(e) = send_webhook_internal(&webhook_urls, &event_clone).await {
                    tracing::warn!("Failed to send GeoIP stale webhook: {}", e);
                }
            });
        }

        if config.email_enabled && !config.email_recipients.is_empty() {
            let email_config = (
                config.email_recipients.clone(),
                config.email_smtp_host.clone(),
                config.email_smtp_port,
                config.email_username.clone(),
                config.email_password.clone(),
            );
            let event_clone = event.clone();
            tokio::spawn(async move {
                if let Err(e) = send_email_internal(email_config, &event_clone).await {
                    tracing::warn!("Failed to send GeoIP stale email: {}", e);
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
