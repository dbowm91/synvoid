use super::shared_state::SharedWafState;
use crate::metrics::WorkerMetrics;
use crate::proxy::WafDecision;
use crate::http_client::{create_http_client, send_request_with_timeout, HttpClient};
use crate::process::{WorkerId, WorkerStatus};

use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::net::SocketAddr;
use std::time::Instant;
use tokio::task::JoinHandle;
use warp::Filter;
use parking_lot::RwLock as PLRwLock;
use metrics::{counter, histogram};
use http::Response;

pub use crate::process::WorkerStatus;

#[derive(Clone, Debug)]
pub struct Worker {
    pub id: WorkerId,
    pub port: u16,
    pub status: Arc<PLRwLock<WorkerStatus>>,
    pub metrics: WorkerMetrics,
    handle: Arc<PLRwLock<Option<JoinHandle<()>>>>,
    shared_state: Arc<SharedWafState>,
    upstream_url: Arc<String>,
}

impl Worker {
    pub fn new(
        id: WorkerId,
        port: u16,
        upstream_url: String,
        shared_state: Arc<SharedWafState>,
    ) -> Self {
        Worker {
            id,
            port,
            status: Arc::new(PLRwLock::new(WorkerStatus::Starting)),
            metrics: WorkerMetrics::default(),
            handle: Arc::new(PLRwLock::new(None)),
            shared_state,
            upstream_url: Arc::new(upstream_url),
        }
    }

    pub fn status(&self) -> WorkerStatus {
        *self.status.read()
    }

    pub fn current_load(&self) -> u64 {
        self.metrics.current_concurrent.load(Ordering::Relaxed)
    }

    pub fn metrics(&self) -> &WorkerMetrics {
        &self.metrics
    }

    pub async fn start(self: Arc<Self>) {
        let id = self.id;
        let port = self.port;
        let shared_state = self.shared_state.clone();
        let upstream_url = self.upstream_url.clone();
        let metrics = self.metrics.clone();
        let status = self.status.clone();

        *status.write() = WorkerStatus::Running;

        let handle = tokio::spawn(async move {
            let addr: SocketAddr = format!("127.0.0.1:{}", port)
                .parse()
                .expect("Hardcoded socket address should always parse");
            
            let client = create_http_client();

            let routes = warp::any()
                .and(warp::header::optional::<SocketAddr>("x-real-ip"))
                .and(warp::method())
                .and(warp::path::full())
                .and(warp::header::headers_cloned())
                .and(warp::addr::remote())
                .and_then(move |real_ip: Option<SocketAddr>, method: warp::http::Method, path: warp::path::FullPath, headers: warp::http::HeaderMap, remote_addr: Option<SocketAddr>| {
                    let shared_state = shared_state.clone();
                    let client = client.clone();
                    let upstream_url = upstream_url.clone();
                    let metrics = metrics.clone();
                    
                    metrics.total_requests.fetch_add(1, Ordering::Relaxed);
                    metrics.current_concurrent.fetch_add(1, Ordering::Relaxed);
                    
                    let current = metrics.current_concurrent.load(Ordering::Relaxed);
                    let peak = metrics.peak_concurrent.load(Ordering::Relaxed);
                    if current > peak {
                        metrics.peak_concurrent.store(current, Ordering::Relaxed);
                    }

                    let start = Instant::now();
                    
                    async move {
                        let client_ip = real_ip
                            .map(|ip| ip.ip())
                            .or(remote_addr.map(|ip| ip.ip()))
                            .unwrap_or_else(|| "127.0.0.1".parse().expect("Hardcoded IP should always parse"));
                        
                        let user_agent = headers.get("user-agent")
                            .and_then(|v| v.to_str().ok())
                            .map(|s| s.to_string());
                        
                        let path_str = path.as_str().to_string();
                        
                        let waf = match shared_state.get_waf().await {
                            Ok(waf) => waf,
                            Err(e) => {
                                tracing::error!("WAF not initialized: {}", e);
                                metrics.current_concurrent.fetch_update(Ordering::Relaxed, Ordering::Relaxed, |v| v.checked_sub(1));
                                return Ok(Response::builder()
                                    .status(503)
                                    .body("Service Unavailable".to_string())
                                    .unwrap_or_else(|_| Response::default()));
                            }
                        };

                        let http_method = http::Method::from_bytes(method.as_str().as_bytes())
                            .unwrap_or(http::Method::GET);
                        
                        match waf.check_request(client_ip, http_method.clone(), &path_str, user_agent.as_deref()).await {
                            WafDecision::Block(status, message) => {
                                metrics.blocked.fetch_add(1, Ordering::Relaxed);
                                counter!("maluwaf.requests.blocked").increment(1);
                                let elapsed = start.elapsed().as_millis() as u64;
                                metrics.total_latency_ms.fetch_add(elapsed, Ordering::Relaxed);
                                metrics.request_count_for_latency.fetch_add(1, Ordering::Relaxed);
                                histogram!("maluwaf.worker.request_duration").record(elapsed as f64);
                                metrics.current_concurrent.fetch_update(Ordering::Relaxed, Ordering::Relaxed, |v| v.checked_sub(1));
                                
                                let body = waf.error_page_manager.render_page(status, Some(&message));
                                Ok::<_, warp::Rejection>(Response::builder()
                                    .status(status)
                                    .header("Content-Type", "text/html")
                                    .body(body)
                                    .expect("Failed to build block response"))
                            }
                            WafDecision::Challenge(html) => {
                                metrics.challenged.fetch_add(1, Ordering::Relaxed);
                                counter!("maluwaf.requests.challenged").increment(1);
                                let elapsed = start.elapsed().as_millis() as u64;
                                metrics.total_latency_ms.fetch_add(elapsed, Ordering::Relaxed);
                                metrics.request_count_for_latency.fetch_add(1, Ordering::Relaxed);
                                histogram!("maluwaf.worker.request_duration").record(elapsed as f64);
                                metrics.current_concurrent.fetch_update(Ordering::Relaxed, Ordering::Relaxed, |v| v.checked_sub(1));
                                
                                Ok(Response::builder()
                                    .status(200)
                                    .header("Content-Type", "text/html")
                                    .header("Cache-Control", "no-store, no-cache, must-revalidate")
                                    .body(html)
                                    .expect("Failed to build challenge response"))
                            }
                            WafDecision::ChallengeWithCookie { html, session_cookie_name, session_cookie_value, session_cookie_max_age } => {
                                metrics.challenged.fetch_add(1, Ordering::Relaxed);
                                counter!("maluwaf.requests.challenged").increment(1);
                                let elapsed = start.elapsed().as_millis() as u64;
                                metrics.total_latency_ms.fetch_add(elapsed, Ordering::Relaxed);
                                metrics.request_count_for_latency.fetch_add(1, Ordering::Relaxed);
                                histogram!("maluwaf.worker.request_duration").record(elapsed as f64);
                                metrics.current_concurrent.fetch_update(Ordering::Relaxed, Ordering::Relaxed, |v| v.checked_sub(1));
                                
                                let cookie = format!("{}={}; path=/; max-age={}; Secure; SameSite=Strict", session_cookie_name, session_cookie_value, session_cookie_max_age);
                                Ok(Response::builder()
                                    .status(200)
                                    .header("Content-Type", "text/html")
                                    .header("Cache-Control", "no-store, no-cache, must-revalidate")
                                    .header("Set-Cookie", cookie)
                                    .body(html)
                                    .expect("Failed to build challenge-with-cookie response"))
                            }
                            WafDecision::Tarpit(_) => {
                                metrics.blocked.fetch_add(1, Ordering::Relaxed);
                                counter!("maluwaf.requests.tarpitted").increment(1);
                                let elapsed = start.elapsed().as_millis() as u64;
                                metrics.total_latency_ms.fetch_add(elapsed, Ordering::Relaxed);
                                metrics.request_count_for_latency.fetch_add(1, Ordering::Relaxed);
                                histogram!("maluwaf.worker.request_duration").record(elapsed as f64);
                                metrics.current_concurrent.fetch_update(Ordering::Relaxed, Ordering::Relaxed, |v| v.checked_sub(1));
                                
                                Ok(Response::builder()
                                    .status(200)
                                    .header("Content-Type", "text/html")
                                    .body("Please wait...".to_string())
                                    .expect("Failed to build tarpit response"))
                            }
                            WafDecision::Pass => {
                                let target_url = format!("{}{}", *upstream_url, path_str);
                                
                                match send_request_with_timeout(&client, http_method, &target_url, Some(std::time::Duration::from_secs(30))).await {
                                    Ok(response) => {
                                        let status = response.status_code();
                                        
                                        let resp_headers: Vec<(String, String)> = response
                                            .headers_iter()
                                            .filter_map(|(k, v)| v.to_str().ok().map(|vv| (k.to_string(), vv.to_string())))
                                            .collect();
                                        
                                        let body = response.body;
                                        
                                        let mut builder = Response::builder().status(status);
                                        for (key, value) in resp_headers {
                                            builder = builder.header(&key, &value);
                                        }
                                        
                                        metrics.proxied.fetch_add(1, Ordering::Relaxed);
                                        counter!("maluwaf.requests.proxied").increment(1);
                                        
                                        let elapsed = start.elapsed().as_millis() as u64;
                                        metrics.total_latency_ms.fetch_add(elapsed, Ordering::Relaxed);
                                        metrics.request_count_for_latency.fetch_add(1, Ordering::Relaxed);
                                        histogram!("maluwaf.worker.request_duration").record(elapsed as f64);
                                        metrics.current_concurrent.fetch_update(Ordering::Relaxed, Ordering::Relaxed, |v| v.checked_sub(1));
                                        
                                        Ok(builder.body(body).expect("Failed to build proxied response"))
                                    }
                                    Err(e) => {
                                        tracing::error!("Upstream error: {}", e);
                                        metrics.errors.fetch_add(1, Ordering::Relaxed);
                                        let elapsed = start.elapsed().as_millis() as u64;
                                        metrics.total_latency_ms.fetch_add(elapsed, Ordering::Relaxed);
                                        metrics.request_count_for_latency.fetch_add(1, Ordering::Relaxed);
                                        histogram!("maluwaf.worker.request_duration").record(elapsed as f64);
                                        metrics.current_concurrent.fetch_update(Ordering::Relaxed, Ordering::Relaxed, |v| v.checked_sub(1));
                                        
                                        Ok(Response::builder()
                                            .status(502)
                                            .body("Bad Gateway".to_string())
                                            .expect("Failed to build error response"))
                                    }
                                }
                            }
                        }
                    }
                });

            tracing::info!("Worker {} listening on {}", id.0, addr);
            
            warp::serve(routes).bind(addr).await;
        });

        *self.handle.write() = Some(handle);
    }

    pub async fn shutdown(&self) {
        *self.status.write() = WorkerStatus::Stopping;
        
        if let Some(handle) = self.handle.write().take() {
            handle.abort();
        }
        
        *self.status.write() = WorkerStatus::Stopped;
        tracing::info!("Worker {} stopped", self.id.0);
    }
}
