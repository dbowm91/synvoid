use std::{
    collections::HashMap,
    sync::Arc,
    time::Instant,
};
use parking_lot::RwLock;
use axum::{
    body::Body,
    extract::Request,
    http::StatusCode,
    response::Response,
};
use tower::{Layer, Service, util::ServiceExt};
use std::future::Future;
use std::pin::Pin;

const CLEANUP_INTERVAL_SECS: u64 = 60;

pub struct AdminRateLimitConfig {
    pub requests_per_minute: u32,
    pub requests_per_second: u32,
}

impl Default for AdminRateLimitConfig {
    fn default() -> Self {
        Self {
            requests_per_minute: 60,
            requests_per_second: 10,
        }
    }
}

struct RateLimitEntry {
    requests_per_minute: u32,
    requests_per_second: u32,
    minute_window_start: Instant,
    second_window_start: Instant,
}

struct AdminRateLimiterInner {
    per_ip: RwLock<HashMap<String, RateLimitEntry>>,
    last_cleanup: RwLock<Instant>,
    config: AdminRateLimitConfig,
}

#[derive(Clone)]
pub struct AdminRateLimiter {
    inner: Arc<AdminRateLimiterInner>,
}

impl AdminRateLimiter {
    pub fn new(config: AdminRateLimitConfig) -> Self {
        Self {
            inner: Arc::new(AdminRateLimiterInner {
                per_ip: RwLock::new(HashMap::new()),
                last_cleanup: RwLock::new(Instant::now()),
                config,
            }),
        }
    }

    pub fn check_rate_limit(&self, ip: &str) -> bool {
        self.maybe_cleanup();

        let now = Instant::now();
        let mut per_ip = self.inner.per_ip.write();

        let entry = per_ip
            .entry(ip.to_string())
            .or_insert_with(|| RateLimitEntry {
                requests_per_minute: 0,
                requests_per_second: 0,
                minute_window_start: now,
                second_window_start: now,
            });

        if now.duration_since(entry.minute_window_start).as_secs() >= 60 {
            entry.requests_per_minute = 0;
            entry.minute_window_start = now;
        }

        if now.duration_since(entry.second_window_start).as_secs() >= 1 {
            entry.requests_per_second = 0;
            entry.second_window_start = now;
        }

        if entry.requests_per_minute >= self.inner.config.requests_per_minute {
            metrics::counter!("maluwaf.admin.rate_limited.minute").increment(1);
            return false;
        }

        if entry.requests_per_second >= self.inner.config.requests_per_second {
            metrics::counter!("maluwaf.admin.rate_limited.second").increment(1);
            return false;
        }

        entry.requests_per_minute += 1;
        entry.requests_per_second += 1;

        true
    }

    fn maybe_cleanup(&self) {
        let now = Instant::now();
        let last = *self.inner.last_cleanup.read();

        if now.duration_since(last).as_secs() >= CLEANUP_INTERVAL_SECS {
            let mut per_ip = self.inner.per_ip.write();
            per_ip.retain(|_, entry| {
                now.duration_since(entry.minute_window_start).as_secs() < 120
            });
            *self.inner.last_cleanup.write() = now;
        }
    }

    pub fn limited_response() -> Response<Body> {
        let body = r#"{"error":"Rate limit exceeded","message":"Too many requests. Please try again later.","retry_after_secs":60}"#;
        Response::builder()
            .status(StatusCode::TOO_MANY_REQUESTS)
            .header("content-type", "application/json")
            .body(Body::from(body))
            .unwrap()
    }
}

impl Default for AdminRateLimiter {
    fn default() -> Self {
        Self::new(AdminRateLimitConfig::default())
    }
}

#[derive(Clone)]
pub struct AdminRateLimitLayer {
    limiter: AdminRateLimiter,
}

impl AdminRateLimitLayer {
    pub fn new() -> Self {
        Self {
            limiter: AdminRateLimiter::new(AdminRateLimitConfig::default()),
        }
    }

    pub fn from_config(config: AdminRateLimitConfig) -> Self {
        Self {
            limiter: AdminRateLimiter::new(config),
        }
    }
}

impl Default for AdminRateLimitLayer {
    fn default() -> Self {
        Self::new()
    }
}

impl<S> Layer<S> for AdminRateLimitLayer {
    type Service = AdminRateLimitMiddleware<S>;

    fn layer(&self, inner: S) -> Self::Service {
        AdminRateLimitMiddleware {
            inner,
            limiter: self.limiter.clone(),
        }
    }
}

#[derive(Clone)]
pub struct AdminRateLimitMiddleware<S> {
    inner: S,
    limiter: AdminRateLimiter,
}

impl<S> Service<Request> for AdminRateLimitMiddleware<S>
where
    S: Service<Request, Response = Response<Body>> + Clone + Send + 'static,
    S::Error: std::fmt::Debug + Send + 'static,
    S::Future: Send + 'static,
{
    type Response = Response<Body>;
    type Error = S::Error;
    type Future = Pin<Box<dyn Send + Future<Output = Result<Self::Response, Self::Error>>>>;

    fn poll_ready(
        &mut self,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, request: Request) -> Self::Future {
        let client_ip = extract_client_ip(&request);

        if !self.limiter.check_rate_limit(&client_ip) {
            let response = AdminRateLimiter::limited_response();
            return Box::pin(async { Ok(response) });
        }

        let mut inner = self.inner.clone();
        Box::pin(async move {
            Ok(inner.ready().await?.call(request).await?)
        })
    }
}

fn extract_client_ip(request: &Request) -> String {
    if let Some(remote_addr) = request.extensions().get::<axum::extract::ConnectInfo<std::net::SocketAddr>>() {
        return remote_addr.ip().to_string();
    }
    
    "127.0.0.1".to_string()
}
