use super::shared_state::SharedWafState;
use crate::proxy::WafDecision;
use crate::http_client::{create_http_client, send_request_with_timeout, HttpClient};

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::net::SocketAddr;
use std::time::Instant;
use tokio::task::JoinHandle;
use warp::Filter;
use parking_lot::RwLock as PLRwLock;
use metrics::{counter, histogram};
use http::Response;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct WorkerId(pub usize);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WorkerStatus {
    Starting,
    Running,
    Stopping,
    Stopped,
}

pub struct WorkerMetrics {
    pub total_requests: AtomicU64,
    pub blocked: AtomicU64,
    pub challenged: AtomicU64,
    pub proxied: AtomicU64,
    pub errors: AtomicU64,
    pub current_concurrent: AtomicUsize,
    pub peak_concurrent: AtomicUsize,
    pub total_latency_ms: AtomicU64,
    pub request_count_for_latency: AtomicU64,
}

impl Clone for WorkerMetrics {
    fn clone(&self) -> Self {
        Self {
            total_requests: AtomicU64::new(self.total_requests.load(Ordering::Relaxed)),
            blocked: AtomicU64::new(self.blocked.load(Ordering::Relaxed)),
            challenged: AtomicU64::new(self.challenged.load(Ordering::Relaxed)),
            proxied: AtomicU64::new(self.proxied.load(Ordering::Relaxed)),
            errors: AtomicU64::new(self.errors.load(Ordering::Relaxed)),
            current_concurrent: AtomicUsize::new(self.current_concurrent.load(Ordering::Relaxed)),
            peak_concurrent: AtomicUsize::new(self.peak_concurrent.load(Ordering::Relaxed)),
            total_latency_ms: AtomicU64::new(self.total_latency_ms.load(Ordering::Relaxed)),
            request_count_for_latency: AtomicU64::new(self.request_count_for_latency.load(Ordering::Relaxed)),
        }
    }
}

impl Default for WorkerMetrics {
    fn default() -> Self {
        Self {
            total_requests: AtomicU64::new(0),
            blocked: AtomicU64::new(0),
            challenged: AtomicU64::new(0),
            proxied: AtomicU64::new(0),
            errors: AtomicU64::new(0),
            current_concurrent: AtomicUsize::new(0),
            peak_concurrent: AtomicUsize::new(0),
            total_latency_ms: AtomicU64::new(0),
            request_count_for_latency: AtomicU64::new(0),
        }
    }
}

impl std::fmt::Debug for WorkerMetrics {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WorkerMetrics")
            .field("total_requests", &self.total_requests.load(Ordering::Relaxed))
            .field("blocked", &self.blocked.load(Ordering::Relaxed))
            .field("challenged", &self.challenged.load(Ordering::Relaxed))
            .field("proxied", &self.proxied.load(Ordering::Relaxed))
            .field("errors", &self.errors.load(Ordering::Relaxed))
            .field("current_concurrent", &self.current_concurrent.load(Ordering::Relaxed))
            .field("peak_concurrent", &self.peak_concurrent.load(Ordering::Relaxed))
            .finish()
    }
}

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
        self.metrics.current_concurrent.load(Ordering::Relaxed) as u64
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
            let addr: SocketAddr = format!("127.0.0.1:{}", port).parse().unwrap();
            
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
                            .unwrap_or_else(|| "127.0.0.1".parse().unwrap());
                        
                        let user_agent = headers.get("user-agent")
                            .and_then(|v| v.to_str().ok())
                            .map(|s| s.to_string());
                        
                        let path_str = path.as_str().to_string();
                        
                        let waf = shared_state.get_waf().await;

                        let http_method = http::Method::from_bytes(method.as_str().as_bytes())
                            .unwrap_or(http::Method::GET);
                        
                        match waf.check_request(client_ip, http_method.clone(), &path_str, user_agent.as_deref()).await {
                            WafDecision::Block(status, message) => {
                                metrics.blocked.fetch_add(1, Ordering::Relaxed);
                                counter!("rustwaf.requests.blocked").increment(1);
                                let elapsed = start.elapsed().as_millis() as u64;
                                metrics.total_latency_ms.fetch_add(elapsed, Ordering::Relaxed);
                                metrics.request_count_for_latency.fetch_add(1, Ordering::Relaxed);
                                histogram!("rustwaf.worker.request_duration").record(elapsed as f64);
                                metrics.current_concurrent.fetch_sub(1, Ordering::Relaxed);
                                
                                let body = waf.error_page_manager.render_page(status, Some(&message));
                                Ok::<_, warp::Rejection>(Response::builder()
                                    .status(status)
                                    .header("Content-Type", "text/html")
                                    .body(body)
                                    .unwrap())
                            }
                            WafDecision::Challenge(html) => {
                                metrics.challenged.fetch_add(1, Ordering::Relaxed);
                                counter!("rustwaf.requests.challenged").increment(1);
                                let elapsed = start.elapsed().as_millis() as u64;
                                metrics.total_latency_ms.fetch_add(elapsed, Ordering::Relaxed);
                                metrics.request_count_for_latency.fetch_add(1, Ordering::Relaxed);
                                histogram!("rustwaf.worker.request_duration").record(elapsed as f64);
                                metrics.current_concurrent.fetch_sub(1, Ordering::Relaxed);
                                
                                Ok(Response::builder()
                                    .status(200)
                                    .header("Content-Type", "text/html")
                                    .header("Cache-Control", "no-store, no-cache, must-revalidate")
                                    .body(html)
                                    .unwrap())
                            }
                            WafDecision::Tarpit(_) => {
                                metrics.blocked.fetch_add(1, Ordering::Relaxed);
                                counter!("rustwaf.requests.tarpitted").increment(1);
                                let elapsed = start.elapsed().as_millis() as u64;
                                metrics.total_latency_ms.fetch_add(elapsed, Ordering::Relaxed);
                                metrics.request_count_for_latency.fetch_add(1, Ordering::Relaxed);
                                histogram!("rustwaf.worker.request_duration").record(elapsed as f64);
                                metrics.current_concurrent.fetch_sub(1, Ordering::Relaxed);
                                
                                Ok(Response::builder()
                                    .status(200)
                                    .header("Content-Type", "text/html")
                                    .body("Please wait...".to_string())
                                    .unwrap())
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
                                        counter!("rustwaf.requests.proxied").increment(1);
                                        
                                        let elapsed = start.elapsed().as_millis() as u64;
                                        metrics.total_latency_ms.fetch_add(elapsed, Ordering::Relaxed);
                                        metrics.request_count_for_latency.fetch_add(1, Ordering::Relaxed);
                                        histogram!("rustwaf.worker.request_duration").record(elapsed as f64);
                                        metrics.current_concurrent.fetch_sub(1, Ordering::Relaxed);
                                        
                                        Ok(builder.body(body).unwrap())
                                    }
                                    Err(e) => {
                                        tracing::error!("Upstream error: {}", e);
                                        metrics.errors.fetch_add(1, Ordering::Relaxed);
                                        let elapsed = start.elapsed().as_millis() as u64;
                                        metrics.total_latency_ms.fetch_add(elapsed, Ordering::Relaxed);
                                        metrics.request_count_for_latency.fetch_add(1, Ordering::Relaxed);
                                        histogram!("rustwaf.worker.request_duration").record(elapsed as f64);
                                        metrics.current_concurrent.fetch_sub(1, Ordering::Relaxed);
                                        
                                        Ok(Response::builder()
                                            .status(502)
                                            .body("Bad Gateway".to_string())
                                            .unwrap())
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
