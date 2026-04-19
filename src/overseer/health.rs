use crate::http_client::{create_simple_http_client, get_with_timeout, HttpClient};
use std::future::Future;
use std::time::{Duration, Instant};

#[derive(Debug, Clone)]
pub struct HealthChecker {
    client: HttpClient,
    health_path: String,
    timeout_secs: u64,
}

#[derive(Debug, Clone, PartialEq)]
pub enum HealthStatus {
    Healthy,
    Draining { active_connections: u64 },
    Unhealthy { status: u16, message: String },
    Error(String),
}

#[derive(Debug, Clone)]
pub struct WorkerReadinessStatus {
    pub port: u16,
    pub ready: bool,
    pub is_draining: bool,
    pub active_connections: u64,
}

#[derive(Debug, Clone)]
pub struct EnhancedHealthConfig {
    pub sample_requests: usize,
    pub latency_threshold_ms: u64,
    pub error_rate_threshold: f64,
    pub compare_with_baseline: bool,
    pub shadow_traffic_path: Option<String>,
}

impl Default for EnhancedHealthConfig {
    fn default() -> Self {
        Self {
            sample_requests: 5,
            latency_threshold_ms: 1000,
            error_rate_threshold: 0.1,
            compare_with_baseline: true,
            shadow_traffic_path: Some("/__internal__/health".to_string()),
        }
    }
}

#[derive(Debug, Clone)]
pub struct EnhancedHealthResult {
    pub port: u16,
    pub healthy: bool,
    pub avg_latency_ms: u64,
    pub p95_latency_ms: u64,
    pub error_rate: f64,
    pub success_count: usize,
    pub total_requests: usize,
    pub baseline_comparison: Option<BaselineComparison>,
}

#[derive(Debug, Clone)]
pub struct BaselineComparison {
    pub baseline_avg_latency_ms: u64,
    pub latency_degradation_percent: f64,
    pub is_degraded: bool,
}

#[derive(Debug, Clone)]
pub struct ShadowTrafficResult {
    pub port: u16,
    pub requests_sent: usize,
    pub old_version_successes: usize,
    pub new_version_successes: usize,
    pub old_version_avg_latency_ms: u64,
    pub new_version_avg_latency_ms: u64,
    pub latency_diff_percent: f64,
    pub healthy: bool,
}

pub async fn retry_with_timeout<T, E, F, Fut, Pred>(
    retries: u32,
    interval_secs: u64,
    mut operation: F,
    is_success: Pred,
) -> Result<T, E>
where
    F: FnMut() -> Fut,
    Fut: Future<Output = Result<T, E>>,
    Pred: Fn(&T) -> bool,
    E: std::fmt::Debug + Default,
{
    let mut last_error: Option<E> = None;

    for attempt in 1..=retries {
        match operation().await {
            Ok(result) => {
                if is_success(&result) {
                    return Ok(result);
                }
                tracing::debug!("Attempt {}: condition not met", attempt);
            }
            Err(e) => {
                tracing::debug!("Attempt {} failed: {:?}", attempt, e);
                last_error = Some(e);
            }
        }

        if attempt < retries {
            tokio::time::sleep(Duration::from_secs(interval_secs)).await;
        }
    }

    Err(last_error.unwrap_or_default())
}

pub async fn wait_for_condition<C, Fut>(
    timeout: Duration,
    poll_interval: Duration,
    mut condition: C,
) -> bool
where
    C: FnMut() -> Fut,
    Fut: Future<Output = bool>,
{
    let start = Instant::now();
    while start.elapsed() < timeout {
        if condition().await {
            return true;
        }
        tokio::time::sleep(poll_interval).await;
    }
    false
}

pub struct PollResult<T> {
    pub attempt: u32,
    pub results: Vec<T>,
    pub failures: Vec<T>,
}

pub async fn poll_until_success<T, F, Fut>(
    retries: u32,
    interval_secs: u64,
    mut operation: F,
    is_success: impl Fn(&[T]) -> bool,
    format_failure: impl Fn(&[T]) -> String,
) -> Result<PollResult<T>, Vec<T>>
where
    F: FnMut() -> Fut,
    Fut: Future<Output = Vec<T>>,
    T: Clone,
{
    for attempt in 1..=retries {
        let results = operation().await;

        if is_success(&results) {
            return Ok(PollResult {
                attempt,
                results,
                failures: Vec::new(),
            });
        }

        let failures: Vec<_> = results.to_vec();
        tracing::debug!(
            "Poll attempt {}/{} failed: {}",
            attempt,
            retries,
            format_failure(&failures)
        );

        if attempt < retries {
            tokio::time::sleep(Duration::from_secs(interval_secs)).await;
        }
    }

    let results = operation().await;
    let failures: Vec<_> = results.to_vec();
    Err(failures)
}

impl HealthChecker {
    pub fn new(health_path: Option<String>, timeout_secs: Option<u64>) -> Self {
        let timeout = Duration::from_secs(timeout_secs.unwrap_or(5));
        let client = create_simple_http_client(timeout);

        Self {
            client,
            health_path: health_path.unwrap_or_else(|| "/health".to_string()),
            timeout_secs: timeout_secs.unwrap_or(5),
        }
    }

    /// Builds a URL with the given host, port, and path.
    fn build_url(&self, host: &str, port: u16, path: &str) -> String {
        format!("http://{}:{}{}", host, port, path)
    }

    /// Builds the health check URL for a worker.
    fn build_health_url(&self, host: &str, port: u16) -> String {
        self.build_url(host, port, &self.health_path)
    }

    /// Builds an internal API URL for a worker (e.g., /__internal__/ready).
    fn build_internal_url(&self, host: &str, port: u16, endpoint: &str) -> String {
        self.build_url(host, port, &format!("/__internal__/{}", endpoint))
    }

    pub async fn check_worker(&self, host: &str, port: u16) -> HealthStatus {
        let url = self.build_health_url(host, port);

        match get_with_timeout(&self.client, &url, Duration::from_secs(self.timeout_secs)).await {
            Ok(response) => {
                if response.status.is_success() {
                    HealthStatus::Healthy
                } else {
                    HealthStatus::Unhealthy {
                        status: response.status.as_u16(),
                        message: format!("HTTP {}", response.status),
                    }
                }
            }
            Err(e) => HealthStatus::Error(e),
        }
    }

    pub async fn check_worker_readiness(&self, host: &str, port: u16) -> WorkerReadinessStatus {
        let url = self.build_internal_url(host, port, "ready");

        match get_with_timeout(&self.client, &url, Duration::from_secs(2)).await {
            Ok(response) => {
                let status = response.status;
                if let Ok(json) = serde_json::from_slice::<serde_json::Value>(&response.body) {
                    let ready = json["ready"].as_bool().unwrap_or(status.is_success());
                    let is_draining = json["reason"].as_str() == Some("draining");
                    let active_connections = json["active_connections"].as_u64().unwrap_or(0);

                    return WorkerReadinessStatus {
                        port,
                        ready,
                        is_draining,
                        active_connections,
                    };
                }

                WorkerReadinessStatus {
                    port,
                    ready: status.is_success(),
                    is_draining: false,
                    active_connections: 0,
                }
            }
            Err(e) => {
                tracing::debug!("Worker readiness check failed for port {}: {}", port, e);
                WorkerReadinessStatus {
                    port,
                    ready: false,
                    is_draining: false,
                    active_connections: 0,
                }
            }
        }
    }

    pub async fn check_worker_health_with_drain(&self, host: &str, port: u16) -> HealthStatus {
        let url = self.build_internal_url(host, port, "health");

        match get_with_timeout(&self.client, &url, Duration::from_secs(2)).await {
            Ok(response) => {
                let status = response.status;
                if let Ok(json) = serde_json::from_slice::<serde_json::Value>(&response.body) {
                    if let Some(status_str) = json["status"].as_str() {
                        if status_str == "draining" {
                            let active = json["active_connections"].as_u64().unwrap_or(0);
                            return HealthStatus::Draining {
                                active_connections: active,
                            };
                        }
                    }
                }

                if status.is_success() {
                    HealthStatus::Healthy
                } else if status.as_u16() == 503 {
                    HealthStatus::Draining {
                        active_connections: 0,
                    }
                } else {
                    HealthStatus::Unhealthy {
                        status: status.as_u16(),
                        message: format!("HTTP {}", status),
                    }
                }
            }
            Err(e) => HealthStatus::Error(e),
        }
    }

    pub async fn check_workers(&self, ports: &[u16], host: &str) -> Vec<(u16, HealthStatus)> {
        let mut results = Vec::new();

        for &port in ports {
            let status = self.check_worker(host, port).await;
            results.push((port, status));
        }

        results
    }

    pub async fn check_all_workers_readiness(
        &self,
        ports: &[u16],
        host: &str,
    ) -> Vec<WorkerReadinessStatus> {
        let mut results = Vec::new();

        for &port in ports {
            let status = self.check_worker_readiness(host, port).await;
            results.push(status);
        }

        results
    }

    pub async fn for_each_port<F, R, Fut>(
        &self,
        ports: &[u16],
        host: &str,
        mut check_fn: F,
    ) -> Vec<R>
    where
        F: FnMut(&Self, &str, u16) -> Fut,
        Fut: std::future::Future<Output = R>,
    {
        let mut results = Vec::with_capacity(ports.len());
        for &port in ports {
            results.push(check_fn(self, host, port).await);
        }
        results
    }

    pub async fn validate_all(
        &self,
        ports: &[u16],
        host: &str,
        retries: u32,
        interval_secs: u64,
    ) -> Result<(), Vec<(u16, HealthStatus)>> {
        let host = host.to_string();
        let this = self;

        poll_until_success(
            retries,
            interval_secs,
            || {
                let host = host.clone();
                async move { this.check_workers(ports, &host).await }
            },
            |results| {
                results
                    .iter()
                    .all(|(_, s)| matches!(s, HealthStatus::Healthy))
            },
            |failures| format!("{}/{} unhealthy", failures.len(), ports.len()),
        )
        .await
        .map(|_| ())
        .map_err(|failures| failures.into_iter().collect())
    }

    pub async fn validate_readiness(
        &self,
        ports: &[u16],
        host: &str,
        retries: u32,
        interval_secs: u64,
        warmup_secs: u64,
    ) -> Result<Vec<WorkerReadinessStatus>, Vec<WorkerReadinessStatus>> {
        if warmup_secs > 0 {
            tracing::info!("Waiting {}s for workers to warm up", warmup_secs);
            tokio::time::sleep(Duration::from_secs(warmup_secs)).await;
        }

        for attempt in 1..=retries {
            let results = self.check_all_workers_readiness(ports, host).await;
            let all_ready = results.iter().all(|r| r.ready && !r.is_draining);

            if all_ready {
                tracing::info!(
                    "All {} workers ready after {} attempts",
                    ports.len(),
                    attempt
                );
                return Ok(results);
            }

            let not_ready: Vec<_> = results.iter().filter(|r| !r.ready).collect();
            tracing::debug!(
                "Attempt {}/{}: {}/{} workers ready, waiting {}s",
                attempt,
                retries,
                ports.len() - not_ready.len(),
                ports.len(),
                interval_secs
            );

            if attempt < retries {
                tokio::time::sleep(Duration::from_secs(interval_secs)).await;
            }
        }

        let results = self.check_all_workers_readiness(ports, host).await;
        let failures: Vec<_> = results.iter().filter(|r| !r.ready).cloned().collect();

        tracing::warn!(
            "Readiness validation failed: {}/{} workers not ready",
            failures.len(),
            ports.len()
        );

        Err(failures)
    }

    pub async fn validate_with_metrics(
        &self,
        ports: &[u16],
        host: &str,
        retries: u32,
        interval_secs: u64,
    ) -> Result<ValidationMetrics, Vec<(u16, HealthStatus)>> {
        let mut total_checks = 0;
        let mut successful_checks = 0;

        for attempt in 1..=retries {
            let results = self.check_workers(ports, host).await;
            total_checks += ports.len();

            let all_healthy = results.iter().all(|(_, status)| {
                let healthy = matches!(status, HealthStatus::Healthy);
                if healthy {
                    successful_checks += 1;
                }
                healthy
            });

            if all_healthy {
                return Ok(ValidationMetrics {
                    total_checks,
                    successful_checks,
                    success_rate: if total_checks > 0 {
                        successful_checks as f64 / total_checks as f64
                    } else {
                        0.0
                    },
                });
            }

            if attempt < retries {
                tokio::time::sleep(Duration::from_secs(interval_secs)).await;
            }
        }

        let results = self.check_workers(ports, host).await;
        let failures: Vec<_> = results
            .into_iter()
            .filter(|(_, status)| !matches!(status, HealthStatus::Healthy))
            .collect();

        Err(failures)
    }

    pub async fn enhanced_health_check(
        &self,
        host: &str,
        port: u16,
        config: &EnhancedHealthConfig,
    ) -> EnhancedHealthResult {
        let url = format!("http://{}:{}{}", host, port, self.health_path);
        let mut latencies = Vec::new();
        let mut success_count = 0;
        let mut error_count = 0;

        for _ in 0..config.sample_requests {
            let start = Instant::now();

            match get_with_timeout(
                &self.client,
                &url,
                Duration::from_millis(config.latency_threshold_ms * 2),
            )
            .await
            {
                Ok(response) => {
                    let latency = start.elapsed().as_millis() as u64;
                    latencies.push(latency);

                    if response.status.is_success() {
                        success_count += 1;
                    } else {
                        error_count += 1;
                    }
                }
                Err(_) => {
                    error_count += 1;
                    latencies.push(config.latency_threshold_ms * 2);
                }
            }

            tokio::time::sleep(Duration::from_millis(50)).await;
        }

        latencies.sort();
        let total_requests = config.sample_requests;
        let error_rate = error_count as f64 / total_requests as f64;
        let avg_latency_ms = if !latencies.is_empty() {
            latencies.iter().sum::<u64>() / latencies.len() as u64
        } else {
            0
        };
        let p95_index = ((latencies.len() as f64) * 0.95).floor() as usize;
        let p95_latency_ms = latencies
            .get(p95_index.saturating_sub(1))
            .copied()
            .unwrap_or(0);

        let healthy = error_rate <= config.error_rate_threshold
            && avg_latency_ms <= config.latency_threshold_ms;

        EnhancedHealthResult {
            port,
            healthy,
            avg_latency_ms,
            p95_latency_ms,
            error_rate,
            success_count,
            total_requests,
            baseline_comparison: None,
        }
    }

    pub async fn enhanced_health_check_with_baseline(
        &self,
        host: &str,
        new_port: u16,
        baseline_port: u16,
        config: &EnhancedHealthConfig,
    ) -> EnhancedHealthResult {
        let baseline_result = self
            .enhanced_health_check(host, baseline_port, config)
            .await;
        let mut new_result = self.enhanced_health_check(host, new_port, config).await;

        if baseline_result.healthy {
            let latency_diff = if baseline_result.avg_latency_ms > 0 {
                ((new_result.avg_latency_ms as f64 - baseline_result.avg_latency_ms as f64)
                    / baseline_result.avg_latency_ms as f64)
                    * 100.0
            } else {
                0.0
            };

            let degradation_threshold = 50.0;
            let is_degraded = latency_diff > degradation_threshold;

            new_result.baseline_comparison = Some(BaselineComparison {
                baseline_avg_latency_ms: baseline_result.avg_latency_ms,
                latency_degradation_percent: latency_diff,
                is_degraded,
            });

            if is_degraded && new_result.healthy {
                tracing::warn!(
                    "New version on port {} has {:.1}% higher latency than baseline ({}ms vs {}ms)",
                    new_port,
                    latency_diff,
                    new_result.avg_latency_ms,
                    baseline_result.avg_latency_ms
                );
            }
        }

        new_result
    }

    pub async fn validate_enhanced(
        &self,
        ports: &[u16],
        host: &str,
        config: &EnhancedHealthConfig,
        retries: u32,
        interval_secs: u64,
    ) -> Result<Vec<EnhancedHealthResult>, Vec<EnhancedHealthResult>> {
        for attempt in 1..=retries {
            let mut results = Vec::new();

            for &port in ports {
                let result = self.enhanced_health_check(host, port, config).await;
                results.push(result);
            }

            let all_healthy = results.iter().all(|r| r.healthy);

            if all_healthy {
                tracing::info!(
                    "Enhanced health check passed on attempt {} for all {} ports",
                    attempt,
                    ports.len()
                );
                return Ok(results);
            }

            let unhealthy_count = results.iter().filter(|r| !r.healthy).count();
            tracing::debug!(
                "Enhanced health check attempt {}/{}: {}/{} ports healthy",
                attempt,
                retries,
                ports.len() - unhealthy_count,
                ports.len()
            );

            if attempt < retries {
                tokio::time::sleep(Duration::from_secs(interval_secs)).await;
            }
        }

        let results: Vec<_> = futures::future::join_all(
            ports
                .iter()
                .map(|&port| self.enhanced_health_check(host, port, config)),
        )
        .await;

        let failures: Vec<_> = results.into_iter().filter(|r| !r.healthy).collect();

        Err(failures)
    }

    pub async fn shadow_traffic_test(
        &self,
        host: &str,
        old_port: u16,
        new_port: u16,
        config: &EnhancedHealthConfig,
    ) -> ShadowTrafficResult {
        let path = config
            .shadow_traffic_path
            .as_deref()
            .unwrap_or("/__internal__/health");

        let mut old_latencies = Vec::new();
        let mut new_latencies = Vec::new();
        let mut old_successes: usize = 0;
        let mut new_successes: usize = 0;

        for _ in 0..config.sample_requests {
            let old_url = format!("http://{}:{}{}", host, old_port, path);
            let new_url = format!("http://{}:{}{}", host, new_port, path);

            let (old_result, new_result) = tokio::join!(
                self.make_shadow_request(&old_url, config.latency_threshold_ms * 2),
                self.make_shadow_request(&new_url, config.latency_threshold_ms * 2)
            );

            if let Some(latency) = old_result.0 {
                old_latencies.push(latency);
                if old_result.1 {
                    old_successes += 1;
                }
            }

            if let Some(latency) = new_result.0 {
                new_latencies.push(latency);
                if new_result.1 {
                    new_successes += 1;
                }
            }

            tokio::time::sleep(Duration::from_millis(10)).await;
        }

        let old_avg = if !old_latencies.is_empty() {
            old_latencies.iter().sum::<u64>() / old_latencies.len() as u64
        } else {
            0
        };

        let new_avg = if !new_latencies.is_empty() {
            new_latencies.iter().sum::<u64>() / new_latencies.len() as u64
        } else {
            0
        };

        let latency_diff = if old_avg > 0 {
            ((new_avg as f64 - old_avg as f64) / old_avg as f64) * 100.0
        } else {
            0.0
        };

        let healthy = new_successes >= old_successes.saturating_sub(1) && latency_diff < 100.0;

        ShadowTrafficResult {
            port: new_port,
            requests_sent: config.sample_requests,
            old_version_successes: old_successes,
            new_version_successes: new_successes,
            old_version_avg_latency_ms: old_avg,
            new_version_avg_latency_ms: new_avg,
            latency_diff_percent: latency_diff,
            healthy,
        }
    }

    async fn make_shadow_request(&self, url: &str, timeout_ms: u64) -> (Option<u64>, bool) {
        let start = Instant::now();

        match get_with_timeout(&self.client, url, Duration::from_millis(timeout_ms)).await {
            Ok(response) => {
                let latency = start.elapsed().as_millis() as u64;
                (Some(latency), response.status.is_success())
            }
            Err(_) => (None, false),
        }
    }

    pub async fn comprehensive_validation(
        &self,
        old_ports: &[u16],
        new_ports: &[u16],
        host: &str,
        config: &EnhancedHealthConfig,
    ) -> Result<Vec<EnhancedHealthResult>, String> {
        if old_ports.len() != new_ports.len() {
            return Err("Port count mismatch between old and new versions".to_string());
        }

        let mut results = Vec::new();

        for (old_port, new_port) in old_ports.iter().zip(new_ports.iter()) {
            let result = self
                .enhanced_health_check_with_baseline(host, *new_port, *old_port, config)
                .await;

            if !result.healthy {
                return Err(format!(
                    "Port {} failed health check: error_rate={:.1}%, avg_latency={}ms",
                    new_port,
                    result.error_rate * 100.0,
                    result.avg_latency_ms
                ));
            }

            if let Some(ref comparison) = result.baseline_comparison {
                if comparison.is_degraded {
                    tracing::warn!(
                        "Port {} shows latency degradation of {:.1}% (baseline: {}ms, new: {}ms)",
                        new_port,
                        comparison.latency_degradation_percent,
                        comparison.baseline_avg_latency_ms,
                        result.avg_latency_ms
                    );
                }
            }

            results.push(result);
        }

        Ok(results)
    }
}

#[derive(Debug, Clone)]
pub struct ValidationMetrics {
    pub total_checks: usize,
    pub successful_checks: usize,
    pub success_rate: f64,
}

impl std::fmt::Display for HealthStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            HealthStatus::Healthy => write!(f, "healthy"),
            HealthStatus::Draining { active_connections } => {
                write!(f, "draining ({} active)", active_connections)
            }
            HealthStatus::Unhealthy { status, message } => {
                write!(f, "unhealthy (HTTP {}: {})", status, message)
            }
            HealthStatus::Error(e) => write!(f, "error: {}", e),
        }
    }
}

#[derive(Debug, Clone)]
pub struct HealthCheckBuilder {
    host: String,
    health_path: Option<String>,
    timeout_secs: Option<u64>,
    retries: u32,
    interval_secs: u64,
    warmup_secs: u64,
}

impl HealthCheckBuilder {
    pub fn new(host: impl Into<String>) -> Self {
        Self {
            host: host.into(),
            health_path: None,
            timeout_secs: None,
            retries: 3,
            interval_secs: 5,
            warmup_secs: 0,
        }
    }

    pub fn with_health_path(mut self, path: impl Into<String>) -> Self {
        self.health_path = Some(path.into());
        self
    }

    pub fn with_timeout(mut self, secs: u64) -> Self {
        self.timeout_secs = Some(secs);
        self
    }

    pub fn with_retries(mut self, retries: u32) -> Self {
        self.retries = retries;
        self
    }

    pub fn with_interval(mut self, secs: u64) -> Self {
        self.interval_secs = secs;
        self
    }

    pub fn with_warmup(mut self, secs: u64) -> Self {
        self.warmup_secs = secs;
        self
    }

    pub fn build(&self) -> HealthChecker {
        HealthChecker::new(self.health_path.clone(), self.timeout_secs)
    }

    pub async fn validate(&self, ports: &[u16]) -> Result<(), Vec<(u16, HealthStatus)>> {
        let checker = self.build();
        checker
            .validate_all(ports, &self.host, self.retries, self.interval_secs)
            .await
    }

    pub async fn validate_with_readiness(
        &self,
        ports: &[u16],
    ) -> Result<Vec<WorkerReadinessStatus>, Vec<WorkerReadinessStatus>> {
        let checker = self.build();
        checker
            .validate_readiness(
                ports,
                &self.host,
                self.retries,
                self.interval_secs,
                self.warmup_secs,
            )
            .await
    }

    pub async fn enhanced_validate(
        &self,
        ports: &[u16],
        config: &EnhancedHealthConfig,
    ) -> Result<Vec<EnhancedHealthResult>, Vec<EnhancedHealthResult>> {
        let checker = self.build();
        checker
            .validate_enhanced(ports, &self.host, config, self.retries, self.interval_secs)
            .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_health_status_enum_variants() {
        let healthy = HealthStatus::Healthy;
        assert_eq!(healthy, HealthStatus::Healthy);

        let draining = HealthStatus::Draining {
            active_connections: 5,
        };
        assert_eq!(
            draining,
            HealthStatus::Draining {
                active_connections: 5,
            }
        );

        let unhealthy = HealthStatus::Unhealthy {
            status: 503,
            message: "Service unavailable".to_string(),
        };
        assert_eq!(
            unhealthy,
            HealthStatus::Unhealthy {
                status: 503,
                message: "Service unavailable".to_string(),
            }
        );

        let error = HealthStatus::Error("connection refused".to_string());
        assert_eq!(error, HealthStatus::Error("connection refused".to_string()));

        assert_eq!(healthy.clone(), HealthStatus::Healthy);
        assert_eq!(
            draining.clone(),
            HealthStatus::Draining {
                active_connections: 5
            }
        );
        assert_eq!(
            unhealthy.clone(),
            HealthStatus::Unhealthy {
                status: 503,
                message: "Service unavailable".to_string(),
            }
        );
        assert_eq!(
            error.clone(),
            HealthStatus::Error("connection refused".to_string())
        );
    }

    #[test]
    fn test_worker_readiness_status_default() {
        let status = WorkerReadinessStatus {
            port: 8080,
            ready: true,
            is_draining: false,
            active_connections: 0,
        };
        assert_eq!(status.port, 8080);
        assert!(status.ready);
        assert!(!status.is_draining);
        assert_eq!(status.active_connections, 0);
    }

    #[test]
    fn test_enhanced_health_config_defaults() {
        let config = EnhancedHealthConfig::default();
        assert_eq!(config.sample_requests, 5);
        assert_eq!(config.latency_threshold_ms, 1000);
        assert_eq!(config.error_rate_threshold, 0.1);
        assert!(config.compare_with_baseline);
        assert_eq!(
            config.shadow_traffic_path,
            Some("/__internal__/health".to_string())
        );
    }

    #[test]
    fn test_baseline_comparison_calculation() {
        let comparison = BaselineComparison {
            baseline_avg_latency_ms: 100,
            latency_degradation_percent: 25.5,
            is_degraded: true,
        };
        assert_eq!(comparison.baseline_avg_latency_ms, 100);
        assert_eq!(comparison.latency_degradation_percent, 25.5);
        assert!(comparison.is_degraded);

        let comparison2 = BaselineComparison {
            baseline_avg_latency_ms: 200,
            latency_degradation_percent: -10.0,
            is_degraded: false,
        };
        assert_eq!(comparison2.baseline_avg_latency_ms, 200);
        assert_eq!(comparison2.latency_degradation_percent, -10.0);
        assert!(!comparison2.is_degraded);
    }

    #[test]
    fn test_shadow_traffic_result_fields() {
        let result = ShadowTrafficResult {
            port: 9000,
            requests_sent: 10,
            old_version_successes: 9,
            new_version_successes: 10,
            old_version_avg_latency_ms: 150,
            new_version_avg_latency_ms: 140,
            latency_diff_percent: -6.67,
            healthy: true,
        };
        assert_eq!(result.port, 9000);
        assert_eq!(result.requests_sent, 10);
        assert_eq!(result.old_version_successes, 9);
        assert_eq!(result.new_version_successes, 10);
        assert_eq!(result.old_version_avg_latency_ms, 150);
        assert_eq!(result.new_version_avg_latency_ms, 140);
        assert_eq!(result.latency_diff_percent, -6.67);
        assert!(result.healthy);
    }

    #[test]
    fn test_worker_readiness_status_creation() {
        let status = WorkerReadinessStatus {
            port: 3000,
            ready: false,
            is_draining: true,
            active_connections: 42,
        };
        assert_eq!(status.port, 3000);
        assert!(!status.ready);
        assert!(status.is_draining);
        assert_eq!(status.active_connections, 42);
    }
}
