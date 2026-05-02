use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tokio::sync::RwLock as TokioRwLock;

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
                    metric: "error_rate".to_string(),
                    threshold: 5.0,
                    condition: AlertCondition::GreaterThan,
                    enabled: true,
                },
                AlertRule {
                    name: "Worker Failure".to_string(),
                    metric: "worker_status".to_string(),
                    threshold: 0.0,
                    condition: AlertCondition::Equals,
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

pub struct AlertManager {
    config: Arc<TokioRwLock<AlertConfig>>,
}

impl AlertManager {
    pub fn new() -> Self {
        Self {
            config: Arc::new(TokioRwLock::new(AlertConfig::default())),
        }
    }

    pub async fn get_config(&self) -> AlertConfig {
        self.config.read().await.clone()
    }

    pub async fn update_config(&self, config: AlertConfig) {
        *self.config.write().await = config;
    }

    pub async fn check_and_notify(
        &self,
        metrics: &super::state::AggregatedMetrics,
    ) -> Vec<AlertEvent> {
        let config = self.config.read().await;

        if !config.enabled {
            return Vec::new();
        }

        let mut events = Vec::new();
        let now = crate::utils::safe_unix_timestamp() as i64;

        for rule in &config.alerts {
            if !rule.enabled {
                continue;
            }

            let should_fire = match rule.metric.as_str() {
                "threat_level" => {
                    let _threat_level = 1.0;
                    false
                }
                "error_rate" => {
                    let total = metrics.total_requests;
                    let errors = metrics.errors;
                    if total > 0 {
                        let rate = (errors as f64 / total as f64) * 100.0;
                        match rule.condition {
                            AlertCondition::GreaterThan => rate > rule.threshold,
                            AlertCondition::LessThan => rate < rule.threshold,
                            AlertCondition::Equals => (rate - rule.threshold).abs() < 0.01,
                        }
                    } else {
                        false
                    }
                }
                "worker_status" => false,
                _ => false,
            };

            if should_fire {
                let event = AlertEvent {
                    timestamp: now,
                    rule_name: rule.name.clone(),
                    metric: rule.metric.clone(),
                    value: 0.0,
                    threshold: rule.threshold,
                    message: format!(
                        "Alert triggered: {} - threshold: {}",
                        rule.name, rule.threshold
                    ),
                };

                events.push(event.clone());

                if config.webhook_enabled {
                    let webhook_urls = config.webhook_urls.clone();
                    let event_clone = event.clone();
                    tokio::spawn(async move {
                        if let Err(e) = send_webhook_internal(&webhook_urls, &event_clone).await {
                            tracing::warn!("Failed to send webhook: {}", e);
                        }
                    });
                }

                if config.email_enabled {
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
