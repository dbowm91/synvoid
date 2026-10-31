//! Admin API rate limiting.

use axum::{
    body::Body,
    extract::Request,
    http::{Method, StatusCode},
    response::Response,
};
use parking_lot::RwLock;
use std::future::Future;
use std::pin::Pin;
use std::{collections::HashMap, sync::Arc, time::Instant};
use tower::{util::ServiceExt, Layer, Service};

const CLEANUP_INTERVAL_SECS: u64 = 60;

pub struct AdminRateLimitConfig {
    pub requests_per_minute: u32,
    pub requests_per_second: u32,
}

impl Default for AdminRateLimitConfig {
    fn default() -> Self {
        Self {
            requests_per_minute: 600,
            requests_per_second: 50,
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
        self.check_rate_limit_inner(ip, false)
    }

    /// Minute-budget-only check for the auth bootstrap paths (login,
    /// logout, CSRF refresh). The panel's own boot storm otherwise starves
    /// the session it is trying to establish on the per-second budget.
    /// Brute-force protection lives in the auth layer (login attempt
    /// lockout), not here.
    pub fn check_rate_limit_burst_exempt(&self, ip: &str) -> bool {
        self.check_rate_limit_inner(ip, true)
    }

    fn check_rate_limit_inner(&self, ip: &str, burst_exempt: bool) -> bool {
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
            metrics_024::counter!("synvoid.admin.rate_limited.minute").increment(1);
            return false;
        }

        if !burst_exempt && entry.requests_per_second >= self.inner.config.requests_per_second {
            metrics_024::counter!("synvoid.admin.rate_limited.second").increment(1);
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
            per_ip.retain(|_, entry| now.duration_since(entry.minute_window_start).as_secs() < 120);
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
        let burst_exempt = is_auth_bootstrap_request(&request);

        let allowed = if burst_exempt {
            self.limiter.check_rate_limit_burst_exempt(&client_ip)
        } else {
            self.limiter.check_rate_limit(&client_ip)
        };
        if !allowed {
            let response = AdminRateLimiter::limited_response();
            return Box::pin(async { Ok(response) });
        }

        let mut inner = self.inner.clone();
        Box::pin(async move { inner.ready().await?.call(request).await })
    }
}

/// Auth bootstrap paths bypass the per-second burst budget (the
/// per-minute budget still applies). The panel's boot storm otherwise
/// starves the very session it is trying to establish.
fn is_auth_bootstrap_request(request: &Request) -> bool {
    matches!(
        (request.method(), request.uri().path()),
        (&Method::POST, "/api/auth/session")
            | (&Method::DELETE, "/api/auth/session")
            | (&Method::GET, "/api/auth/csrf")
    )
}

fn extract_client_ip(request: &Request) -> String {
    // Check for forwarded IP from admin middleware
    if let Some(ip) = request.extensions().get::<ClientIp>() {
        return ip.0.clone();
    }

    if let Some(remote_addr) = request
        .extensions()
        .get::<axum::extract::ConnectInfo<std::net::SocketAddr>>()
    {
        return remote_addr.ip().to_string();
    }

    // Fallback: extract from X-Forwarded-For header
    if let Some(forwarded) = request.headers().get("x-forwarded-for") {
        if let Ok(val) = forwarded.to_str() {
            if let Some(first) = val.split(',').next() {
                return first.trim().to_string();
            }
        }
    }

    "127.0.0.1".to_string()
}

/// Client IP extracted from request headers/extensions.
///
/// This is set by the admin middleware's `extract_client_ip_middleware`.
#[derive(Clone, Debug)]
pub struct ClientIp(pub String);

#[cfg(test)]
mod tests {
    use super::*;

    fn test_limiter(per_minute: u32, per_second: u32) -> AdminRateLimiter {
        AdminRateLimiter::new(AdminRateLimitConfig {
            requests_per_minute: per_minute,
            requests_per_second: per_second,
        })
    }

    fn bootstrap_request(method: &str, path: &str) -> Request {
        Request::builder()
            .method(method)
            .uri(format!("http://localhost{path}"))
            .body(Body::empty())
            .expect("test request")
    }

    #[test]
    fn burst_exempt_paths_skip_per_second_but_keep_minute() {
        let limiter = test_limiter(3, 1);
        // Per-second budget is 1: the second immediate call would fail the
        // normal check but passes burst-exempt (minute budget still 3).
        assert!(limiter.check_rate_limit_burst_exempt("10.0.0.1"));
        assert!(limiter.check_rate_limit_burst_exempt("10.0.0.1"));
        assert!(limiter.check_rate_limit_burst_exempt("10.0.0.1"));
        // Minute budget exhausted: fourth call fails even when exempt.
        assert!(!limiter.check_rate_limit_burst_exempt("10.0.0.1"));
    }

    #[test]
    fn normal_check_still_enforces_burst() {
        let limiter = test_limiter(100, 1);
        assert!(limiter.check_rate_limit("10.0.0.2"));
        assert!(!limiter.check_rate_limit("10.0.0.2"));
    }

    #[test]
    fn bootstrap_paths_match_login_logout_csrf_only() {
        assert!(is_auth_bootstrap_request(&bootstrap_request(
            "POST",
            "/api/auth/session"
        )));
        assert!(is_auth_bootstrap_request(&bootstrap_request(
            "DELETE",
            "/api/auth/session"
        )));
        assert!(is_auth_bootstrap_request(&bootstrap_request(
            "GET",
            "/api/auth/csrf"
        )));
        assert!(!is_auth_bootstrap_request(&bootstrap_request(
            "GET",
            "/api/auth/session"
        )));
        assert!(!is_auth_bootstrap_request(&bootstrap_request(
            "GET",
            "/api/system/info"
        )));
        assert!(!is_auth_bootstrap_request(&bootstrap_request(
            "POST",
            "/api/config/reload"
        )));
    }
}
