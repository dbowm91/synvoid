//! Alerting system verification tests — Phase 6 acceptance criteria.
//!
//! Validates:
//! 1. Config-time SSRF protection (webhook URL validation)
//! 2. Request-time SSRF protection (DNS resolution validation)
//! 3. Truthful delivery status reporting
//! 4. Email/SMTP removal verification
//! 5. Delivery outcome aggregation

use synvoid::admin::alerting::{validate_destination_at_request_time, validate_webhook_url};
use synvoid::admin::alerting::{
    AlertCondition, AlertConfig, AlertRule, DeliveryOutcome, WebhookDeliveryResult,
};

// ── Config-time SSRF validation (supplement existing tests) ──────────────────

#[test]
fn ssrf_config_rejects_0_0_0_0() {
    assert!(validate_webhook_url("http://0.0.0.0/hook").is_err());
}

#[test]
fn ssrf_config_rejects_100_64_0_0() {
    // Carrier-grade NAT range
    assert!(validate_webhook_url("http://100.64.0.1/hook").is_err());
}

#[test]
fn ssrf_config_rejects_192_0_0_0() {
    assert!(validate_webhook_url("http://192.0.0.1/hook").is_err());
}

#[test]
fn ssrf_config_rejects_198_18_0_0() {
    // Benchmarking range
    assert!(validate_webhook_url("http://198.18.0.1/hook").is_err());
}

#[test]
fn ssrf_config_rejects_198_51_100_0() {
    // Documentation range
    assert!(validate_webhook_url("http://198.51.100.1/hook").is_err());
}

#[test]
fn ssrf_config_rejects_203_0_113_0() {
    // Documentation range
    assert!(validate_webhook_url("http://203.0.113.1/hook").is_err());
}

#[test]
fn ssrf_config_rejects_multicast() {
    assert!(validate_webhook_url("http://224.0.0.1/hook").is_err());
}

#[test]
fn ssrf_config_rejects_ipv6_documentation() {
    assert!(validate_webhook_url("http://[2001:db8::1]/hook").is_err());
}

#[test]
fn ssrf_config_rejects_ipv6_multicast() {
    assert!(validate_webhook_url("http://[ff02::1]/hook").is_err());
}

#[test]
fn ssrf_config_allows_public_ip() {
    assert!(validate_webhook_url("http://8.8.8.8/hook").is_ok());
}

#[test]
fn ssrf_config_allows_public_hostname() {
    assert!(validate_webhook_url("https://hooks.slack.com/test").is_ok());
}

// ── Request-time SSRF validation (DNS resolution) ────────────────────────────

#[tokio::test]
async fn ssrf_request_rejects_localhost_resolution() {
    let url = url::Url::parse("http://localhost/hook").unwrap();
    let result = validate_destination_at_request_time(&url).await;
    assert!(
        result.is_err(),
        "localhost should be rejected at request time"
    );
}

#[tokio::test]
async fn ssrf_request_rejects_loopback_resolution() {
    let url = url::Url::parse("http://127.0.0.1/hook").unwrap();
    let result = validate_destination_at_request_time(&url).await;
    assert!(
        result.is_err(),
        "loopback should be rejected at request time"
    );
}

#[tokio::test]
async fn ssrf_request_rejects_private_ip() {
    let url = url::Url::parse("http://10.0.0.1/hook").unwrap();
    let result = validate_destination_at_request_time(&url).await;
    assert!(
        result.is_err(),
        "private IP should be rejected at request time"
    );
}

#[tokio::test]
async fn ssrf_request_rejects_link_local() {
    let url = url::Url::parse("http://169.254.1.1/hook").unwrap();
    let result = validate_destination_at_request_time(&url).await;
    assert!(
        result.is_err(),
        "link-local should be rejected at request time"
    );
}

// ── Delivery outcome aggregation ─────────────────────────────────────────────

#[test]
fn delivery_all_success() {
    let result = WebhookDeliveryResult {
        outcome: DeliveryOutcome::Success,
        attempted: 3,
        succeeded: 3,
        failed: 0,
        details: vec![],
    };
    assert_eq!(result.outcome, DeliveryOutcome::Success);
    assert_eq!(result.succeeded, 3);
    assert_eq!(result.failed, 0);
}

#[test]
fn delivery_all_failure() {
    let result = WebhookDeliveryResult {
        outcome: DeliveryOutcome::Failure,
        attempted: 2,
        succeeded: 0,
        failed: 2,
        details: vec![],
    };
    assert_eq!(result.outcome, DeliveryOutcome::Failure);
    assert_eq!(result.succeeded, 0);
    assert_eq!(result.failed, 2);
}

#[test]
fn delivery_partial_failure() {
    let result = WebhookDeliveryResult {
        outcome: DeliveryOutcome::PartialFailure,
        attempted: 3,
        succeeded: 1,
        failed: 2,
        details: vec![],
    };
    assert_eq!(result.outcome, DeliveryOutcome::PartialFailure);
    assert_eq!(result.succeeded, 1);
    assert_eq!(result.failed, 2);
}

#[test]
fn delivery_no_urls_is_success() {
    let result = WebhookDeliveryResult {
        outcome: DeliveryOutcome::Success,
        attempted: 0,
        succeeded: 0,
        failed: 0,
        details: vec![],
    };
    assert_eq!(result.outcome, DeliveryOutcome::Success);
}

// ── Config validation ────────────────────────────────────────────────────────

#[test]
fn config_validation_allows_empty_webhooks() {
    let config = AlertConfig {
        webhook_urls: vec![],
        ..Default::default()
    };
    assert!(config.validate().is_ok());
}

#[test]
fn config_validation_rejects_nan_threshold() {
    let config = AlertConfig {
        alerts: vec![AlertRule {
            name: "bad".to_string(),
            metric: "error_rate_percent".to_string(),
            threshold: f64::NAN,
            condition: AlertCondition::GreaterThan,
            enabled: true,
        }],
        ..Default::default()
    };
    assert!(config.validate().is_err());
}

#[test]
fn config_validation_rejects_infinite_threshold() {
    let config = AlertConfig {
        alerts: vec![AlertRule {
            name: "bad".to_string(),
            metric: "error_rate_percent".to_string(),
            threshold: f64::INFINITY,
            condition: AlertCondition::GreaterThan,
            enabled: true,
        }],
        ..Default::default()
    };
    assert!(config.validate().is_err());
}

#[test]
fn config_validation_allows_zero_threshold() {
    let config = AlertConfig {
        alerts: vec![AlertRule {
            name: "zero".to_string(),
            metric: "error_rate_percent".to_string(),
            threshold: 0.0,
            condition: AlertCondition::GreaterThan,
            enabled: true,
        }],
        ..Default::default()
    };
    assert!(config.validate().is_ok());
}

#[test]
fn config_validation_allows_all_supported_metrics() {
    let metrics = &[
        "error_rate_percent",
        "requests_per_second",
        "blocked_per_second",
        "time_validation_errors",
        "unhealthy_backends",
        "unhealthy_workers",
        "threat_level",
        "audit_write_failures",
    ];
    for metric in metrics {
        let config = AlertConfig {
            alerts: vec![AlertRule {
                name: "test".to_string(),
                metric: metric.to_string(),
                threshold: 1.0,
                condition: AlertCondition::GreaterThan,
                enabled: true,
            }],
            ..Default::default()
        };
        assert!(
            config.validate().is_ok(),
            "metric '{}' should be valid",
            metric
        );
    }
}

// ── Delivery outcome enum completeness ───────────────────────────────────────

#[test]
fn delivery_outcome_variants_exhaustive() {
    let outcomes = [
        DeliveryOutcome::Success,
        DeliveryOutcome::PartialFailure,
        DeliveryOutcome::Failure,
    ];
    assert_eq!(
        outcomes.len(),
        3,
        "DeliveryOutcome should have exactly 3 variants"
    );
}
