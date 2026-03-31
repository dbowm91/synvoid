use futures::future;
use metrics::counter;
use std::sync::Arc;
use std::time::Duration;
use tokio::time::interval;

use crate::http_client::{create_http_client_with_config, send_request_with_timeout};
use crate::upstream::pool::Backend;

pub struct HealthChecker {
    pools: Arc<tokio::sync::RwLock<Vec<Arc<crate::upstream::UpstreamPool>>>>,
    config: HealthCheckConfig,
    shutdown_tx: tokio::sync::broadcast::Sender<()>,
}

#[derive(Clone)]
pub struct HealthCheckConfig {
    pub interval_secs: u64,
    pub timeout_secs: u64,
    pub failure_threshold: u32,
    pub recovery_threshold: u32,
    pub health_check_path: String,
    pub health_check_method: HealthCheckMethod,
    pub max_load_percent: f32,
}

#[derive(Clone, Debug)]
pub enum HealthCheckMethod {
    Head,
    Get,
    Tcp,
}

impl Default for HealthCheckConfig {
    fn default() -> Self {
        Self {
            interval_secs: 10,
            timeout_secs: 5,
            failure_threshold: 3,
            recovery_threshold: 2,
            health_check_path: "/".to_string(),
            health_check_method: HealthCheckMethod::Head,
            max_load_percent: 80.0,
        }
    }
}

impl HealthChecker {
    pub fn new(config: HealthCheckConfig) -> Self {
        let (shutdown_tx, _) = tokio::sync::broadcast::channel(1);

        Self {
            pools: Arc::new(tokio::sync::RwLock::new(Vec::new())),
            config,
            shutdown_tx,
        }
    }

    pub async fn register_pool(&self, pool: Arc<crate::upstream::UpstreamPool>) {
        self.pools.write().await.push(pool);
    }

    pub async fn start(&self) {
        let pools = self.pools.clone();
        let config = self.config.clone();
        let mut shutdown_rx = self.shutdown_tx.subscribe();

        tokio::spawn(async move {
            let mut timer = interval(Duration::from_secs(config.interval_secs));

            loop {
                tokio::select! {
                    _ = timer.tick() => {
                        Self::check_all_pools(&pools, &config).await;
                    }
                    _ = shutdown_rx.recv() => {
                        tracing::info!("Health checker shutting down");
                        break;
                    }
                }
            }
        });

        tracing::info!(
            "Health checker started with interval {}s",
            self.config.interval_secs
        );
    }

    async fn check_all_pools(
        pools: &Arc<tokio::sync::RwLock<Vec<Arc<crate::upstream::UpstreamPool>>>>,
        config: &HealthCheckConfig,
    ) {
        let backends_to_check: Vec<Arc<Backend>> = {
            let pools_guard = pools.read().await;
            let mut backends = Vec::new();

            for pool in pools_guard.iter() {
                let pool_backends = pool.get_backends();
                backends.extend(pool_backends.iter().map(|b| Arc::new(b.clone())));
            }

            backends
        };

        if backends_to_check.is_empty() {
            return;
        }

        let health_checks: Vec<_> = backends_to_check
            .iter()
            .map(|backend| {
                let backend = backend.clone();
                let config = config.clone();
                async move {
                    let is_healthy = Self::check_backend(&backend, &config).await;
                    (backend, is_healthy)
                }
            })
            .collect();

        let results = future::join_all(health_checks).await;

        let _pools_guard = pools.read().await;
        for (backend, is_healthy) in results {
            if is_healthy {
                if !backend.is_healthy.is_running() {
                    backend
                        .consecutive_successes
                        .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    let successes = backend
                        .consecutive_successes
                        .load(std::sync::atomic::Ordering::Relaxed);

                    if successes >= config.recovery_threshold {
                        backend.is_healthy.set(true);
                        backend
                            .consecutive_failures
                            .store(0, std::sync::atomic::Ordering::Relaxed);
                        tracing::info!("Backend {} recovered", backend.url);
                        counter!("maluwaf.upstream.backend_recovered").increment(1);
                    }
                }
            } else {
                backend
                    .consecutive_failures
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                let failures = backend
                    .consecutive_failures
                    .load(std::sync::atomic::Ordering::Relaxed);

                if failures >= config.failure_threshold && backend.is_healthy.is_running() {
                    backend.is_healthy.set(false);
                    tracing::warn!(
                        "Backend {} marked unhealthy after {} failures",
                        backend.url,
                        failures
                    );
                    counter!("maluwaf.upstream.backend_unhealthy").increment(1);
                }
            }
        }
    }

    async fn check_backend(backend: &Backend, config: &HealthCheckConfig) -> bool {
        match config.health_check_method {
            HealthCheckMethod::Head | HealthCheckMethod::Get => {
                Self::http_health_check(backend, config).await
            }
            HealthCheckMethod::Tcp => Self::tcp_health_check(backend).await,
        }
    }

    async fn http_health_check(backend: &Backend, config: &HealthCheckConfig) -> bool {
        let client = create_http_client_with_config(
            Duration::from_secs(config.timeout_secs),
            10,
            Duration::from_secs(30),
        );

        let url = format!(
            "{}{}",
            backend.url.trim_end_matches('/'),
            config.health_check_path
        );

        let method = match config.health_check_method {
            HealthCheckMethod::Head => http::Method::HEAD,
            HealthCheckMethod::Get => http::Method::GET,
            _ => unreachable!(),
        };

        match send_request_with_timeout(
            &client,
            method,
            &url,
            Some(Duration::from_secs(config.timeout_secs)),
        )
        .await
        {
            Ok(resp) => {
                let status = resp.status_code();
                (200..400).contains(&status)
            }
            Err(e) => {
                tracing::debug!("Backend {} health check failed: {}", backend.url, e);
                false
            }
        }
    }

    async fn tcp_health_check(backend: &Backend) -> bool {
        let url = backend.url.as_ref();

        matches!(
            tokio::time::timeout(Duration::from_secs(5), tokio::net::TcpStream::connect(url))
                .await,
            Ok(Ok(_))
        )
    }

    pub fn shutdown(&self) {
        let _ = self.shutdown_tx.send(());
        tracing::info!("Health checker shutdown signal sent");
    }
}
