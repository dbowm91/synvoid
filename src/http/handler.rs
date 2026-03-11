use std::net::IpAddr;
use std::sync::Arc;
use std::time::Instant;

use http::{Request, Response, Method, header::HeaderName, HeaderMap, HeaderValue};
use hyper::body::Incoming;
use http_body_util::Full;
use bytes::Bytes;
use tokio::sync::RwLock;
use metrics::{counter, histogram};

use crate::proxy::{WafDecision, HOP_BY_HOP_HEADERS, filter_response_headers, sanitize_request_path};
use crate::router::{Router, RouteTarget, RouteResult, BackendType};
use crate::waf::{WafCore, ConnectionToken};
use crate::upstream::UpstreamPool;
use crate::http_client::{create_http_client_with_config, send_request_with_timeout, HttpClient};
use crate::challenge::HONEYPOT_PREFIX;
use crate::auth::{AuthManager, BasicAuthManager, BasicAuthResult};
use crate::captcha::CaptchaManager;
use crate::config::{MainConfig, SiteSecurityHeadersConfig, SiteCorsConfig};
use crate::fastcgi::{FastCgiClient, FastCgiConfig};
use crate::cgi::{CgiHandler, CgiConfig};
use crate::http::range::serve_range;

pub type UpstreamPools = std::collections::HashMap<String, Arc<UpstreamPool>>;

static HEADERS_TO_REMOVE: &[&str] = &[
    "server",
    "x-powered-by",
    "x-aspnet-version",
    "x-aspnetmvc-version",
    "x-runtime",
    "x-generator",
    "x-drupal-cache",
    "x-varnish",
    "via",
    "x-served-by",
    "x-cache",
    "x-cache-hits",
];

pub struct RequestHandler {
    router: Arc<Router>,
    waf: Arc<WafCore>,
    main_config: Arc<MainConfig>,
    upstream_pools: Arc<RwLock<UpstreamPools>>,
    client: HttpClient,
    auth_manager: Option<Arc<AuthManager>>,
    captcha_manager: Option<Arc<CaptchaManager>>,
    fastcgi_clients: std::collections::HashMap<String, Arc<FastCgiClient>>,
    cgi_handlers: std::collections::HashMap<String, Arc<CgiHandler>>,
    basic_auth_managers: std::collections::HashMap<String, Arc<BasicAuthManager>>,
}

impl RequestHandler {
    pub fn new(
        router: Router,
        waf: Arc<WafCore>,
        main_config: MainConfig,
    ) -> Self {
        let client = create_http_client_with_config(
            std::time::Duration::from_secs(5),
            100,
            std::time::Duration::from_secs(30),
        );

        Self {
            router: Arc::new(router),
            waf,
            main_config: Arc::new(main_config),
            upstream_pools: Arc::new(RwLock::new(UpstreamPools::new())),
            client,
            auth_manager: None,
            captcha_manager: None,
            fastcgi_clients: std::collections::HashMap::new(),
            cgi_handlers: std::collections::HashMap::new(),
            basic_auth_managers: std::collections::HashMap::new(),
        }
    }

    pub fn with_config(mut self, main_config: MainConfig) -> Self {
        self.main_config = Arc::new(main_config);
        self
    }

    pub fn with_auth(mut self, auth_manager: Arc<AuthManager>) -> Self {
        self.auth_manager = Some(auth_manager);
        self
    }

    pub fn with_captcha(mut self, captcha_manager: Arc<CaptchaManager>) -> Self {
        self.captcha_manager = Some(captcha_manager);
        self
    }

    pub async fn register_upstream_pool(&self, site_id: String, pool: Arc<UpstreamPool>) {
        self.upstream_pools.write().await.insert(site_id, pool);
    }

    pub fn register_basic_auth(&mut self, site_id: String, config: &crate::config::SiteBasicAuthConfig) {
        if let Some(manager) = BasicAuthManager::new(config) {
            self.basic_auth_managers.insert(site_id, manager);
        }
    }

    fn check_basic_auth(&self, site_id: &str, headers: &http::HeaderMap) -> Option<Response<Full<Bytes>>> {
        let manager = self.basic_auth_managers.get(site_id)?;
        
        match manager.authenticate_request(headers) {
            BasicAuthResult::Authenticated => None,
            BasicAuthResult::CredentialsRequired | BasicAuthResult::Unauthorized => {
                Some(self.unauthorized_response(manager.realm()))
            }
        }
    }

    fn unauthorized_response(&self, realm: &str) -> Response<Full<Bytes>> {
        Response::builder()
            .status(401)
            .header("WWW-Authenticate", format!("Basic realm=\"{}\"", realm))
            .body(Full::new(Bytes::from("Authorization required")))
            .unwrap_or_else(|_| self.internal_error_response())
    }

    pub async fn handle_request(
        &self,
        req: Request<Incoming>,
        client_addr: std::net::SocketAddr,
    ) -> Response<Full<Bytes>> {
        let start = Instant::now();
        let client_ip = client_addr.ip();

        let connection_token = if let Some(ref conn_limiter) = self.waf.connection_limiter {
            match conn_limiter.try_acquire("_http_", client_ip).await {
                Ok(token) => Some(token),
                Err(e) => {
                    tracing::warn!("Connection limit exceeded for {}: {}", client_ip, e);
                    counter!("rustwaf.traffic.connection_limited").increment(1);
                    return self.rate_limit_response().await;
                }
            }
        } else {
            None
        };

        let _conn_token = connection_token;

        let (parts, body) = req.into_parts();
        let method = parts.method.clone();
        let path = parts.uri.path_and_query()
            .map(|pq| pq.to_string())
            .unwrap_or_else(|| "/".to_string());
        let host = parts.headers.get("host")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .to_string();

        let max_body_size = self.main_config.security.max_request_size;
        let content_length = parts.headers.get("content-length")
            .and_then(|v| v.to_str().ok())
            .and_then(|s| s.parse::<usize>().ok());

        if let Some(size) = content_length {
            if size > max_body_size {
                tracing::warn!(
                    "Request body too large: {} bytes (limit: {}) from {}",
                    size, max_body_size, client_ip
                );
                counter!("rustwaf.requests.body_too_large").increment(1);
                return self.build_response(
                    413,
                    "Request Entity Too Large".to_string(),
                    "text/plain",
                );
            }
        }

        let user_agent = parts.headers.get("user-agent")
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_string());
        
        let is_websocket_upgrade = Self::is_websocket_upgrade(&parts.headers);
        
        let query_string = parts.uri.query();
        
        let body_bytes = hyper::body::to_bytes(body).await.ok();
        let body_slice = body_bytes.as_ref().map(|b| b.as_ref());

        let is_grpc = Self::is_grpc_request(&parts.headers);
        let (effective_path, effective_body) = if is_grpc {
            if let Some(ref body) = body_slice {
                let grpc_path = Self::extract_grpc_method_path(body);
                if let Some(grpc_method) = grpc_path {
                    counter!("rustwaf.grpc.detected").increment(1);
                    tracing::debug!(grpc_method = %grpc_method, "gRPC method path extracted for WAF inspection");
                    (format!("/{}", grpc_method), body_slice)
                } else {
                    (path.clone(), body_slice)
                }
            } else {
                (path.clone(), body_slice)
            }
        } else {
            (path.clone(), body_slice)
        };

        let route = self.router.route(&host, &path);

        if path.starts_with("/_waf_pow") || path.starts_with("/_waf_css_challenge") || path.starts_with("/_waf_assets") || path.starts_with("/_waf_login") || path.starts_with("/_waf_logout") || path.starts_with("/_waf_captcha") {
            return self.handle_waf_internal_paths(&path, client_ip, &parts, body_bytes.as_deref()).await;
        }

        if path.starts_with(HONEYPOT_PREFIX) {
            counter!("rustwaf.honeypot.hit").increment(1);
            tracing::info!("IP-bound honeypot accessed: {} by {}", path, client_ip);
            return self.stall_response().await;
        }

        let route_target = match route {
            RouteResult::Found(target) => target,
            RouteResult::NotFound(msg) => {
                tracing::debug!("Route not found: {} for host: {}", msg, host);
                counter!("rustwaf.requests.not_found").increment(1);
                return self.stall_response().await;
            }
            RouteResult::Error(msg) => {
                tracing::error!("Router error: {}", msg);
                counter!("rustwaf.requests.router_error").increment(1);
                return self.stall_response().await;
            }
        };

        let waf_decision = self.waf.check_request_full(
            client_ip,
            method.clone(),
            &effective_path,
            query_string,
            &parts.headers,
            effective_body,
            user_agent.as_deref(),
        ).await;

        let response = match waf_decision {
            WafDecision::Stall => {
                counter!("rustwaf.requests.stalled").increment(1);
                return self.stall_response().await;
            }
            WafDecision::Block(status, message) => {
                counter!("rustwaf.requests.blocked").increment(1);
                return self.stall_response().await;
            }
            WafDecision::Challenge(html) => {
                counter!("rustwaf.requests.challenged").increment(1);
                self.build_response(200, html, "text/html")
            }
            WafDecision::Tarpit(tar_path) => {
                counter!("rustwaf.requests.tarpitted").increment(1);
                let html = self.waf.generate_tarpit_response(&tar_path);
                self.build_response(200, html, "text/html")
            }
            WafDecision::Pass => {
                if let Some(response) = self.check_basic_auth(&route_target.site_id, &parts.headers) {
                    return response;
                }

                if let Some(static_handler) = &route_target.static_handler {
                    self.serve_static(static_handler, &path, &parts.headers).await
                } else if is_websocket_upgrade {
                    counter!("rustwaf.websocket.upgrade").increment(1);
                    return self.websocket_upgrade_response(&route_target, &path, &parts.headers);
                } else {
                    self.proxy_request(
                        client_ip,
                        route_target,
                        method,
                        &path,
                        body_bytes.unwrap_or_default(),
                    ).await
                }
            }
        };

        histogram!("rustwaf.request.duration").record(start.elapsed());

        response
    }

    async fn stall_response(&self) -> Response<Full<Bytes>> {
        tokio::select! {
            _ = tokio::time::sleep(std::time::Duration::from_secs(10)) => {
                Response::builder()
                    .status(408)
                    .body(Full::new(Bytes::from_static(b"Request timeout")))
                    .unwrap()
            }
        }
    }

    async fn rate_limit_response(&self) -> Response<Full<Bytes>> {
        let body = "{\"error\":\"Too Many Connections\"}".to_string();
        Response::builder()
            .status(503)
            .header("Content-Type", "application/json")
            .header("Retry-After", "60")
            .body(Full::new(Bytes::from(body)))
            .unwrap_or_else(|_| self.build_response(500, "Internal Server Error".to_string(), "text/plain"))
    }

    async fn handle_waf_internal_paths(
        &self,
        path: &str,
        client_ip: IpAddr,
        parts: &http::request::Parts,
        body: Option<&[u8]>,
    ) -> Response<Full<Bytes>> {
        match path {
            "/_waf_pow_verify" => {
                if parts.method != Method::POST {
                    return self.build_response(405, "Method Not Allowed".to_string(), "text/plain");
                }
                self.handle_pow_verify(client_ip, parts).await
            }
            "/_waf_pow.js" => {
                self.serve_pow_js().await
            }
            "/_waf_pow_nojs.js" => {
                self.serve_pow_nojs_js().await
            }
            "/_waf_pow_fallback.js" => {
                self.serve_pow_fallback_js().await
            }
            "/_waf_pow.wasm" => {
                self.serve_pow_wasm().await
            }
            "/_waf_css_challenge" => {
                let html = self.waf.challenge_manager.generate_challenge_page(&client_ip);
                self.build_response(200, html, "text/html")
            }
            "/_waf_login" => {
                if parts.method == Method::POST {
                    self.handle_login(client_ip, parts.headers.get("user-agent").and_then(|v| v.to_str().ok()), body).await
                } else {
                    self.serve_login_page(None).await
                }
            }
            "/_waf_logout" => {
                self.handle_logout(parts.headers.get("cookie").and_then(|v| v.to_str().ok())).await
            }
            _ => {
                if path.starts_with("/_waf_pow") {
                    return self.build_response(404, "Not Found".to_string(), "text/plain");
                }
                if path.starts_with("/_waf_assets") {
                    return self.handle_css_asset(client_ip, path).await;
                }
                if path.starts_with("/_waf_captcha") {
                    return self.handle_captcha(path, parts, body).await;
                }
                self.build_response(404, "Not Found".to_string(), "text/plain")
            }
        }
    }

    async fn serve_login_page(&self, error: Option<&str>) -> Response<Full<Bytes>> {
        let error_html = error.map(|e| {
            format!(r#"<div style="color: red; margin-bottom: 1rem; padding: 0.5rem; background: #fee; border-radius: 4px;">{}</div>"#, e)
        }).unwrap_or_default();

        let html = format!(r#"<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Login Required</title>
    <style>
        body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); min-height: 100vh; display: flex; align-items: center; justify-content: center; margin: 0; }}
        .login-box {{ background: white; padding: 2rem; border-radius: 1rem; box-shadow: 0 10px 40px rgba(0,0,0,0.2); width: 100%; max-width: 400px; }}
        h1 {{ color: #333; margin-bottom: 1.5rem; text-align: center; }}
        .form-group {{ margin-bottom: 1rem; }}
        .form-group label {{ display: block; margin-bottom: 0.5rem; color: #555; font-weight: 500; }}
        .form-group input {{ width: 100%; padding: 0.75rem; border: 1px solid #ddd; border-radius: 0.5rem; font-size: 1rem; }}
        .form-group input:focus {{ outline: none; border-color: #667eea; }}
        .btn {{ width: 100%; padding: 0.75rem; background: #667eea; color: white; border: none; border-radius: 0.5rem; font-size: 1rem; cursor: pointer; }}
        .btn:hover {{ background: #5568d3; }}
    </style>
</head>
<body>
    <div class="login-box">
        <h1>Authentication Required</h1>
        {}
        <form method="POST" action="/_waf_login">
            <div class="form-group">
                <label>Username</label>
                <input type="text" name="username" required autocomplete="username">
            </div>
            <div class="form-group">
                <label>Password</label>
                <input type="password" name="password" required autocomplete="current-password">
            </div>
            <button type="submit" class="btn">Login</button>
        </form>
    </div>
</body>
</html>"#, error_html);

        self.build_response(200, html, "text/html")
    }

    async fn handle_login(&self, client_ip: IpAddr, user_agent: Option<&str>, body: Option<&[u8]>) -> Response<Full<Bytes>> {
        let auth = match self.auth_manager.as_ref() {
            Some(a) => a,
            None => {
                tracing::error!("Auth manager not configured");
                return self.build_response(503, "Auth not configured".to_string(), "text/plain");
            }
        };

        let (username, password) = match body {
            Some(body_bytes) => {
                let body_str = String::from_utf8_lossy(body_bytes);
                let mut username = String::new();
                let mut password = String::new();

                for pair in body_str.split('&') {
                    let mut parts = pair.splitn(2, '=');
                    match parts.next() {
                        Some("username") => username = urlencoding_decode(parts.next().unwrap_or("")),
                        Some("password") => password = urlencoding_decode(parts.next().unwrap_or("")),
                        _ => {}
                    }
                }
                (username, password)
            }
            None => return self.serve_login_page(Some("Invalid request")).await,
        };

        match auth.verify_login(&username, &password, Some(&client_ip.to_string()), user_agent).await {
            Ok(session) => {
                let cookie = format!(
                    "waf_session={}; path=/; max-age={}; HttpOnly; Secure; SameSite=Strict",
                    session.id,
                    86400
                );
                let html = r#"<!DOCTYPE html><html><head><meta http-equiv="refresh" content="0;url=/"></head><body>Login successful. Redirecting...</body></html>"#.to_string();
                
                let mut response = self.build_response(200, html, "text/html");
                response.headers_mut().insert(
                    http::header::SET_COOKIE,
                    cookie.parse().unwrap()
                );
                response
            }
            Err(e) => {
                self.serve_login_page(Some(&e.to_string())).await
            }
        }
    }

    async fn handle_logout(&self, cookie_header: Option<&str>) -> Response<Full<Bytes>> {
        if let Some(cookie_str) = cookie_header {
            if let Some(session_id) = extract_session_cookie(cookie_str) {
                if let Some(auth) = &self.auth_manager {
                    auth.destroy_session(&session_id).await;
                }
            }
        }

        let html = r#"<!DOCTYPE html><html><head><meta http-equiv="refresh" content="0;url=/"></head><body>Logged out. Redirecting...</body></html>"#.to_string();
        
        let mut response = self.build_response(200, html, "text/html");
        response.headers_mut().insert(
            http::header::SET_COOKIE,
            "waf_session=; path=/; max-age=0; HttpOnly; Secure; SameSite=Strict".parse().unwrap()
        );
        response
    }

    async fn handle_css_asset(&self, client_ip: IpAddr, path: &str) -> Response<Full<Bytes>> {
        let asset_name = path.trim_start_matches("/_waf_assets/rnd-").trim_end_matches(".png");
        
        if self.waf.challenge_manager.css_enabled() {
            let _ = self.waf.challenge_manager.record_css_asset_request(client_ip, asset_name).await;
        }

        let png_data = create_1x1_png();
        let mut response = Response::new(Full::new(Bytes::from(png_data)));
        response.headers_mut().insert(
            http::header::CONTENT_TYPE,
            "image/png".parse().unwrap()
        );
        response
    }

    async fn handle_captcha(&self, path: &str, parts: &http::request::Parts, body: Option<&[u8]>) -> Response<Full<Bytes>> {
        let captcha = match self.captcha_manager.as_ref() {
            Some(c) => c,
            None => {
                tracing::error!("Captcha manager not configured");
                return self.build_response(503, "Captcha not configured".to_string(), "text/plain");
            }
        };

        if path == "/_waf_captcha" {
            let (challenge_id, svg) = captcha.generate_challenge().await;
            let page = crate::captcha::generate_captcha_page(&challenge_id);
            return self.build_response(200, page, "text/html");
        }

        if path.starts_with("/_waf_captcha_img") {
            let challenge_id = parts.uri.query()
                .and_then(|q| {
                    q.split('&')
                        .find_map(|pair| {
                            let mut parts = pair.splitn(2, '=');
                            if parts.next() == Some("id") {
                                Some(urlencoding_decode(parts.next().unwrap_or("")))
                            } else {
                                None
                            }
                        })
                });

            if let Some(id) = challenge_id {
                let (_, svg) = captcha.generate_challenge().await;
                let mut response = Response::new(Full::new(Bytes::from(svg.into_bytes())));
                response.headers_mut().insert(
                    http::header::CONTENT_TYPE,
                    "image/svg+xml".parse().unwrap()
                );
                return response;
            }
            return self.build_response(400, "Missing challenge id".to_string(), "text/plain");
        }

        if path == "/_waf_captcha_verify" {
            if parts.method == Method::POST {
                let (challenge_id, answer) = match body {
                    Some(body_bytes) => {
                        let body_str = String::from_utf8_lossy(body_bytes);
                        let mut id = String::new();
                        let mut ans = String::new();

                        for pair in body_str.split('&') {
                            let mut parts = pair.splitn(2, '=');
                            match parts.next() {
                                Some("id") => id = urlencoding_decode(parts.next().unwrap_or("")),
                                Some("answer") => ans = urlencoding_decode(parts.next().unwrap_or("")),
                                _ => {}
                            }
                        }
                        (id, ans)
                    }
                    None => return self.build_response(400, "Invalid request".to_string(), "text/plain"),
                };

                let result = captcha.verify(&challenge_id, &answer).await;
                match result {
                    crate::captcha::CaptchaResult::Passed => {
                        let cookie = format!(
                            "waf_captcha=verified; path=/; max-age={}; SameSite=Strict",
                            3600
                        );
                        let html = r#"<!DOCTYPE html><html><head><meta http-equiv="refresh" content="0;url=/"></head><body>Verification passed. Redirecting...</body></html>"#.to_string();
                        
                        let mut response = self.build_response(200, html, "text/html");
                        response.headers_mut().insert(
                            http::header::SET_COOKIE,
                            cookie.parse().unwrap()
                        );
                        return response;
                    }
                    _ => {
                        let page = crate::captcha::generate_captcha_page(&challenge_id);
                        return self.build_response(200, page, "text/html");
                    }
                }
            }
        }

        self.build_response(404, "Not Found".to_string(), "text/plain")
    }

    async fn handle_pow_verify(
        &self,
        client_ip: IpAddr,
        parts: &http::request::Parts,
    ) -> Response<Full<Bytes>> {
        let content_type = parts.headers.get("content-type")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");

        if !content_type.starts_with("application/x-www-form-urlencoded") {
            return self.build_response(400, "Invalid content type".to_string(), "text/plain");
        }

        let challenge = parts.uri.query()
            .and_then(|q| {
                q.split('&')
                    .find_map(|pair| {
                        let mut parts = pair.splitn(2, '=');
                        if parts.next() == Some("c") {
                            parts.next().map(|s| urlencoding_decode(s))
                        } else {
                            None
                        }
                    })
            });

        self.build_response(200, 
            "<!DOCTYPE html><html><head><meta http-equiv=\"refresh\" content=\"0;url=/\"></head><body>Verification complete. Redirecting...</body></html>".to_string(),
            "text/html"
        )
    }

    async fn serve_pow_js(&self) -> Response<Full<Bytes>> {
        let js = include_str!("../../static/pow.js");
        self.build_response(200, js.to_string(), "application/javascript")
    }

    async fn serve_pow_nojs_js(&self) -> Response<Full<Bytes>> {
        let js = include_str!("../../static/pow_nojs.js");
        self.build_response(200, js.to_string(), "application/javascript")
    }

    async fn serve_pow_fallback_js(&self) -> Response<Full<Bytes>> {
        let js = include_str!("../../static/pow_fallback.js");
        self.build_response(200, js.to_string(), "application/javascript")
    }

    async fn serve_pow_wasm(&self) -> Response<Full<Bytes>> {
        self.build_response(404, "WASM module not built. Run wasm-pack build.".to_string(), "text/plain")
    }

    async fn serve_static(
        &self,
        handler: &crate::static_files::StaticFileHandler,
        path: &str,
        headers: &http::HeaderMap,
    ) -> Response<Full<Bytes>> {
        let accept_encoding = headers.get("accept-encoding")
            .and_then(|v| v.to_str().ok());

        let if_none_match = headers.get(http::header::IF_NONE_MATCH)
            .and_then(|v| v.to_str().ok());

        let if_modified_since = headers.get(http::header::IF_MODIFIED_SINCE)
            .and_then(|v| v.to_str().ok());

        let range_header = headers.get(http::header::RANGE)
            .and_then(|v| v.to_str().ok());

        let result = handler.serve(
            path,
            &Method::GET,
            accept_encoding,
            if_none_match,
            if_modified_since,
            range_header,
        );

        match result {
            Ok(response) => {
                if let Some(range) = range_header {
                    if !response.body.is_empty() {
                        let filename = std::path::Path::new(path)
                            .file_name()
                            .and_then(|n| n.to_str());
                        
                        let mime_type = response.headers.iter()
                            .find(|(k, _)| k.to_lowercase() == "content-type")
                            .map(|(_, v)| v.to_str().unwrap_or("application/octet-stream"))
                            .unwrap_or("application/octet-stream");
                        
                        let range_response = serve_range(
                            &response.body,
                            Some(range),
                            mime_type,
                            filename,
                        );
                        
                        let mut builder = Response::builder().status(range_response.status);
                        for (key, value) in range_response.headers.iter() {
                            if let Some(key) = key {
                                builder = builder.header(key, value);
                            }
                        }
                        return builder
                            .body(Full::new(Bytes::from(range_response.body)))
                            .unwrap_or_else(|_| self.internal_error_response());
                    }
                }
                
                handler.into_response(Ok(response))
            }
            Err(e) => handler.into_response(Err(e)),
        }
    }

    async fn proxy_request(
        &self,
        client_ip: std::net::IpAddr,
        target: RouteTarget,
        method: Method,
        path: &str,
        body: Bytes,
    ) -> Response<Full<Bytes>> {
        match target.backend_type {
            BackendType::FastCgi => {
                self.proxy_fastcgi_request(client_ip, target, method, path, body).await
            }
            BackendType::Php => {
                self.proxy_php_request(client_ip, target, method, path, body).await
            }
            BackendType::Cgi => {
                self.proxy_cgi_request(client_ip, target, method, path, body).await
            }
            _ => {
                self.proxy_http_request(client_ip, target, method, path).await
            }
        }
    }

    async fn proxy_fastcgi_request(
        &self,
        client_ip: std::net::IpAddr,
        target: RouteTarget,
        method: Method,
        path: &str,
        body: Bytes,
    ) -> Response<Full<Bytes>> {
        let socket = match &target.backend_socket {
            Some(s) => s.clone(),
            None => {
                tracing::error!("FastCGI socket not configured");
                return self.bad_gateway_response();
            }
        };

        let fcgi_client = self.fastcgi_clients
            .entry(socket.clone())
            .or_insert_with(|| Arc::new(FastCgiClient::new(socket.clone())))
            .clone();

        let fcgi_config = target.site_config.proxy.fastcgi.clone()
            .unwrap_or_else(|| FastCgiConfig::default());

        let uri = match http::Uri::try_from(path) {
            Ok(u) => u,
            Err(_) => {
                return self.internal_error_response();
            }
        };

        let mut headers = HeaderMap::new();
        if let Some(host) = target.site_config.site.domains.first() {
            if let Ok(val) = HeaderValue::from_str(host) {
                headers.insert(http::header::HOST, val);
            }
        }

        let timeout = fcgi_config.read_timeout.unwrap_or(60);
        
        match tokio::time::timeout(
            std::time::Duration::from_secs(timeout),
            fcgi_client.execute(&method, &uri, &headers, body, &fcgi_config)
        ).await {
            Ok(Ok(response)) => {
                counter!("rustwaf.requests.fastcgi").increment(1);
                response.into_http_response().map(|r| {
                    let (parts, body) = r.into_parts();
                    Response::from_parts(parts, Full::new(body))
                }).unwrap_or_else(|_| self.internal_error_response())
            }
            Ok(Err(e)) => {
                tracing::error!("FastCGI error: {}", e);
                counter!("rustwaf.requests.fastcgi_error").increment(1);
                self.bad_gateway_response()
            }
            Err(_) => {
                tracing::error!("FastCGI timeout after {}s", timeout);
                counter!("rustwaf.requests.fastcgi_timeout").increment(1);
                self.gateway_timeout_response()
            }
        }
    }

    async fn proxy_php_request(
        &self,
        client_ip: std::net::IpAddr,
        target: RouteTarget,
        method: Method,
        path: &str,
        body: Bytes,
    ) -> Response<Full<Bytes>> {
        let socket = match &target.backend_socket {
            Some(s) => s.clone(),
            None => {
                tracing::error!("PHP socket not configured");
                return self.bad_gateway_response();
            }
        };

        let fcgi_client = self.fastcgi_clients
            .entry(socket.clone())
            .or_insert_with(|| Arc::new(FastCgiClient::new(socket.clone())))
            .clone();

        let php_config = target.site_config.proxy.php.clone();
        
        let uri = match http::Uri::try_from(path) {
            Ok(u) => u,
            Err(_) => {
                return self.internal_error_response();
            }
        };

        let mut headers = HeaderMap::new();
        if let Some(host) = target.site_config.site.domains.first() {
            if let Ok(val) = HeaderValue::from_str(host) {
                headers.insert(http::header::HOST, val);
            }
        }

        let timeout = php_config.as_ref().and_then(|p| p.read_timeout).unwrap_or(60);
        
        let fcgi_config = crate::config::site::FastCgiConfig {
            socket: Some(socket),
            script_filename: php_config.as_ref().and_then(|p| p.root.clone()),
            index: php_config.as_ref().and_then(|p| p.index.clone()),
            params: None,
            split_path_info: None,
            try_files: None,
            connect_timeout: php_config.as_ref().and_then(|p| p.connect_timeout),
            send_timeout: php_config.as_ref().and_then(|p| p.send_timeout),
            read_timeout: php_config.as_ref().and_then(|p| p.read_timeout),
        };
        
        match tokio::time::timeout(
            std::time::Duration::from_secs(timeout),
            fcgi_client.execute(&method, &uri, &headers, body, &fcgi_config)
        ).await {
            Ok(Ok(response)) => {
                counter!("rustwaf.requests.php").increment(1);
                response.into_http_response().map(|r| {
                    let (parts, body) = r.into_parts();
                    Response::from_parts(parts, Full::new(body))
                }).unwrap_or_else(|_| self.internal_error_response())
            }
            Ok(Err(e)) => {
                tracing::error!("PHP error: {}", e);
                counter!("rustwaf.requests.php_error").increment(1);
                self.bad_gateway_response()
            }
            Err(_) => {
                tracing::error!("PHP timeout after {}s", timeout);
                counter!("rustwaf.requests.php_timeout").increment(1);
                self.gateway_timeout_response()
            }
        }
    }

    async fn proxy_cgi_request(
        &self,
        client_ip: std::net::IpAddr,
        target: RouteTarget,
        method: Method,
        path: &str,
        body: Bytes,
    ) -> Response<Full<Bytes>> {
        let root = match &target.backend_socket {
            Some(s) => s.clone(),
            None => {
                tracing::error!("CGI root not configured");
                return self.bad_gateway_response();
            }
        };

        let cgi_config = target.site_config.proxy.cgi.clone();
        
        let cgi_handler = match self.cgi_handlers.entry(root.clone()) {
            std::collections::hash_map::Entry::Occupied(e) => e.get().clone(),
            std::collections::hash_map::Entry::Vacant(e) => {
                let config = CgiConfig {
                    root: Some(root.clone()),
                    index: cgi_config.as_ref().and_then(|c| c.index.clone()).or(Some("index.cgi".to_string())),
                    pass_variables: cgi_config.as_ref().and_then(|c| c.pass_variables).or(Some(true)),
                    timeout: cgi_config.as_ref().and_then(|c| c.timeout).or(Some(30)),
                    stdout_stderr_merge: cgi_config.as_ref().and_then(|c| c.stdout_stderr_merge).or(Some(true)),
                };
                match CgiHandler::new(&config) {
                    Ok(handler) => {
                        let handler = Arc::new(handler);
                        e.insert(handler.clone());
                        handler
                    }
                    Err(e) => {
                        tracing::error!("Failed to create CGI handler: {}", e);
                        return self.internal_error_response();
                    }
                }
            }
        };

        let uri = match http::Uri::try_from(path) {
            Ok(u) => u,
            Err(_) => {
                return self.internal_error_response();
            }
        };

        let headers = HeaderMap::new();

        match cgi_handler.execute(&method, &uri, &headers, body, Some(client_ip)).await {
            Ok(response) => {
                counter!("rustwaf.requests.cgi").increment(1);
                response.into_http_response().map(|r| {
                    let (parts, body) = r.into_parts();
                    Response::from_parts(parts, Full::new(body))
                }).unwrap_or_else(|_| self.internal_error_response())
            }
            Err(e) => {
                tracing::error!("CGI error: {}", e);
                counter!("rustwaf.requests.cgi_error").increment(1);
                match e {
                    crate::cgi::CgiError::NotFound(_) => self.not_found_response(),
                    crate::cgi::CgiError::Forbidden(_) => self.forbidden_response(),
                    _ => self.bad_gateway_response(),
                }
            }
        }
    }

    async fn proxy_http_request(
        &self,
        client_ip: std::net::IpAddr,
        target: RouteTarget,
        method: Method,
        path: &str,
    ) -> Response<Full<Bytes>> {
        let safe_path = sanitize_request_path(path);
        let target_url = format!("{}{}", target.upstream.trim_end_matches('/'), safe_path);
        
        let global_headers_to_remove: Vec<String> = self.main_config.security.more_clear_headers.iter()
            .map(|s| s.to_lowercase())
            .collect();
        
        let site_headers_to_remove: Vec<String> = target.site_config.security.more_clear_headers.iter()
            .chain(target.site_config.security_headers.more_clear_headers.iter())
            .map(|s| s.to_lowercase())
            .collect();
        
        let mut headers_to_filter: Vec<String> = HOP_BY_HOP_HEADERS.iter()
            .map(|s| s.to_string())
            .collect();
        
        for h in global_headers_to_remove.iter() {
            if !headers_to_filter.contains(h) {
                headers_to_filter.push(h.clone());
            }
        }
        
        for h in site_headers_to_remove.iter() {
            if !headers_to_filter.contains(h) {
                headers_to_filter.push(h.clone());
            }
        }
        
        match send_request_with_timeout(&self.client, method.clone(), &target_url, Some(std::time::Duration::from_secs(30))).await {
            Ok(resp) => {
                let status = resp.status_code();
                
                if let Some(ref tracker) = self.waf.upstream_error_tracker {
                    if status >= 400 {
                        let result = tracker.record_error(client_ip, path, status);
                        
                        match result {
                            crate::waf::UpstreamErrorResult::ProbingDetected { unique_endpoints, error_count } => {
                                tracing::warn!(
                                    ip = %client_ip,
                                    endpoints = ?unique_endpoints,
                                    error_count = error_count,
                                    status_code = status,
                                    "Potential upstream vulnerability probe detected"
                                );
                                
                                if let Some(ref config) = tracker.get_config() {
                                    if config.auto_ban_elevated_threat {
                                        let threat_level = self.waf.threat_level.as_ref()
                                            .map(|tl| tl.get_level().as_u8())
                                            .unwrap_or(1);
                                        if threat_level >= config.elevated_threat_threshold {
                                            let ban_duration = config.elevated_ban_duration;
                                            tracing::warn!(
                                                ip = %client_ip,
                                                threat_level = threat_level,
                                                ban_duration_secs = ban_duration,
                                                "Auto-banning source of upstream error probing"
                                            );
                                            if let Some(ref store) = self.waf.block_store {
                                                store.block_ip(client_ip, "upstream_error_probe", ban_duration, "global");
                                            }
                                        }
                                    }
                                }
                            }
                            _ => {}
                        }
                    }
                }
                
                let headers = filter_response_headers(&resp.headers, &headers_to_filter);
                
                let body = resp.body;
                
                let mut builder = Response::builder().status(status);
                for (key, value) in headers {
                    builder = builder.header(&key, &value);
                }
                
                if target.site_config.security_headers.enabled.unwrap_or(false) || self.main_config.security.global_security_headers {
                    builder = self.inject_security_headers(builder, &target.site_config.security_headers);
                }
                
                counter!("rustwaf.requests.proxied").increment(1);
                
                builder
                    .body(Full::new(Bytes::from(body)))
                    .unwrap_or_else(|_| self.internal_error_response())
            }
            Err(e) => {
                tracing::error!("Upstream error: {}", e);
                counter!("rustwaf.requests.upstream_error").increment(1);
                self.bad_gateway_response()
            }
        }
    }

    fn inject_security_headers(
        &self,
        builder: http::response::Builder,
        config: &SiteSecurityHeadersConfig,
    ) -> http::response::Builder {
        let mut builder = builder;
        
        if let Some(ref hsts) = config.strict_transport_security {
            builder = builder.header("Strict-Transport-Security", hsts);
        }
        
        if let Some(ref csp) = config.content_security_policy {
            builder = builder.header("Content-Security-Policy", csp);
        }
        
        if let Some(ref xfo) = config.x_frame_options {
            builder = builder.header("X-Frame-Options", xfo);
        }
        
        if let Some(ref xcto) = config.x_content_type_options {
            builder = builder.header("X-Content-Type-Options", xcto);
        }
        
        if let Some(ref xxss) = config.x_xss_protection {
            builder = builder.header("X-XSS-Protection", xxss);
        }
        
        if let Some(ref rp) = config.referrer_policy {
            builder = builder.header("Referrer-Policy", rp);
        }
        
        if let Some(ref pp) = config.permissions_policy {
            builder = builder.header("Permissions-Policy", pp);
        }
        
        if let Some(ref cc) = config.cache_control {
            builder = builder.header("Cache-Control", cc);
        }
        
        if let Some(ref ect) = config.expect_ct {
            builder = builder.header("Expect-CT", ect);
        }
        
        if let Some(ref pcdp) = config.x_permitted_cross_domain_policies {
            builder = builder.header("X-Permitted-Cross-Domain-Policies", pcdp);
        }
        
        if let Some(ref xdo) = config.x_download_options {
            builder = builder.header("X-Download-Options", xdo);
        }
        
        if let Some(ref ct) = config.content_type {
            builder = builder.header("Content-Type", ct);
        }
        
        if config.cors.enabled.unwrap_or(false) {
            builder = self.inject_cors_headers(builder, &config.cors);
        }
        
        builder
    }

    fn inject_cors_headers(
        &self,
        builder: http::response::Builder,
        config: &SiteCorsConfig,
    ) -> http::response::Builder {
        let mut builder = builder;
        
        if let Some(ref origin) = config.allow_origin {
            builder = builder.header("Access-Control-Allow-Origin", origin);
        }
        
        if let Some(ref methods) = config.allow_methods {
            builder = builder.header("Access-Control-Allow-Methods", methods.join(", "));
        }
        
        if let Some(ref headers) = config.allow_headers {
            builder = builder.header("Access-Control-Allow-Headers", headers.join(", "));
        }
        
        if config.allow_credentials.unwrap_or(false) {
            builder = builder.header("Access-Control-Allow-Credentials", "true");
        }
        
        if let Some(max_age) = config.max_age {
            builder = builder.header("Access-Control-Max-Age", max_age.to_string());
        }
        
        if let Some(ref headers) = config.expose_headers {
            builder = builder.header("Access-Control-Expose-Headers", headers.join(", "));
        }
        
        builder
    }
    }

    fn build_response(&self, status: u16, body: String, content_type: &str) -> Response<Full<Bytes>> {
        Response::builder()
            .status(status)
            .header("Content-Type", content_type)
            .header("Content-Length", body.len())
            .body(Full::new(Bytes::from(body)))
            .unwrap_or_else(|_| self.internal_error_response())
    }

    fn not_found_response(&self) -> Response<Full<Bytes>> {
        self.build_response(404, "Not Found".to_string(), "text/plain")
    }

    fn internal_error_response(&self) -> Response<Full<Bytes>> {
        self.build_response(500, "Internal Server Error".to_string(), "text/plain")
    }

    fn bad_gateway_response(&self) -> Response<Full<Bytes>> {
        self.build_response(502, "Bad Gateway".to_string(), "text/plain")
    }

    fn gateway_timeout_response(&self) -> Response<Full<Bytes>> {
        self.build_response(504, "Gateway Timeout".to_string(), "text/plain")
    }

    fn is_websocket_upgrade(headers: &http::HeaderMap) -> bool {
        let upgrade = headers.get("upgrade")
            .and_then(|v| v.to_str().ok())
            .map(|v| v.to_lowercase());
        
        let connection = headers.get("connection")
            .and_then(|v| v.to_str().ok())
            .map(|v| v.to_lowercase());
        
        let has_upgrade = upgrade.as_ref().map(|u| u == "websocket").unwrap_or(false);
        let has_connection_upgrade = connection
            .as_ref()
            .map(|c| c.contains("upgrade"))
            .unwrap_or(false);
        
        has_upgrade && has_connection_upgrade
    }

    fn is_grpc_request(headers: &http::HeaderMap) -> bool {
        let content_type = headers.get("content-type")
            .and_then(|v| v.to_str().ok())
            .map(|v| v.to_lowercase());
        
        match content_type {
            Some(ct) => ct.starts_with("application/grpc") || ct.starts_with("application/grpc+"),
            None => false,
        }
    }

    fn extract_grpc_method_path(body: &[u8]) -> Option<String> {
        const GRPC_FRAME_HEADER_SIZE: usize = 5;
        
        if body.len() < GRPC_FRAME_HEADER_SIZE {
            return None;
        }

        let length = u32::from_be_bytes([body[1], body[2], body[3], body[4]]) as usize;
        if body.len() < GRPC_FRAME_HEADER_SIZE + length {
            return None;
        }

        let payload = &body[GRPC_FRAME_HEADER_SIZE..GRPC_FRAME_HEADER_SIZE + length];
        
        if payload.len() > 1 && payload[0] == 0x00 {
            if let Ok(text) = std::str::from_utf8(&payload[1..]) {
                if text.starts_with('/') {
                    return Some(text.to_string());
                }
            }
        }
        
        if payload.len() > 2 && payload[0] == 0x0a {
            let field_length = payload[1] as usize;
            if payload.len() >= 2 + field_length && field_length > 0 {
                if let Ok(text) = std::str::from_utf8(&payload[2..2 + field_length]) {
                    if text.starts_with('/') {
                        return Some(text.to_string());
                    }
                }
            }
        }

        None
    }

    fn websocket_upgrade_response(
        &self,
        target: &RouteTarget,
        path: &str,
        headers: &http::HeaderMap,
    ) -> Response<Full<Bytes>> {
        tracing::info!("WebSocket upgrade request for {}{}", target.upstream, path);
        
        let ws_key = headers.get("sec-websocket-key")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");
        
        let ws_version = headers.get("sec-websocket-version")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("13");
        
        let ws_protocols = headers.get("sec-websocket-protocol")
            .and_then(|v| v.to_str().ok());
        
        let accept_key = Self::compute_websocket_accept_key(ws_key);
        
        let mut builder = Response::builder()
            .status(101)
            .header("Upgrade", "websocket")
            .header("Connection", "Upgrade")
            .header("Sec-WebSocket-Accept", accept_key);
        
        if let Some(protocols) = ws_protocols {
            builder = builder.header("Sec-WebSocket-Protocol", protocols);
        }
        
        tracing::info!(
            "WebSocket tunnel established: {}{} -> {}",
            target.upstream, path,
            target.upstream
        );
        
        builder
            .body(Full::new(Bytes::new()))
            .unwrap_or_else(|_| self.internal_error_response())
    }

    fn compute_websocket_accept_key(key: &str) -> String {
        use sha2::{Sha256, Digest};
        
        const GUID: &str = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
        let combined = format!("{}{}", key, GUID);
        let mut hasher = Sha256::new();
        hasher.update(combined.as_bytes());
        let result = hasher.finalize();
        base64::encode(result)
    }
}

fn urlencoding_decode(s: &str) -> String {
    let mut result = String::new();
    let mut chars = s.chars().peekable();
    
    while let Some(c) = chars.next() {
        if c == '%' {
            let hex: String = chars.by_ref().take(2).collect();
            if hex.len() == 2 {
                if let Ok(byte) = u8::from_str_radix(&hex, 16) {
                    result.push(byte as char);
                    continue;
                }
            }
            result.push('%');
            result.push_str(&hex);
        } else if c == '+' {
            result.push(' ');
        } else {
            result.push(c);
        }
    }
    
    result
}

fn extract_session_cookie(cookie_header: &str) -> Option<String> {
    cookie_header
        .split(';')
        .find(|c| c.trim().starts_with("waf_session="))
        .and_then(|c| c.trim().strip_prefix("waf_session="))
        .map(|s| s.to_string())
}

fn create_1x1_png() -> Vec<u8> {
    vec![
        0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A,
        0x00, 0x00, 0x00, 0x0D, 0x49, 0x48, 0x44, 0x52,
        0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01,
        0x08, 0x02, 0x00, 0x00, 0x00, 0x90, 0x77, 0x53,
        0xDE, 0x00, 0x00, 0x00, 0x0C, 0x49, 0x44, 0x41,
        0x54, 0x08, 0xD7, 0x63, 0xF8, 0xCF, 0xC0, 0x00,
        0x00, 0x00, 0x03, 0x00, 0x01, 0x27, 0x73, 0x0D,
        0xB5, 0x00, 0x00, 0x00, 0x00, 0x49, 0x45, 0x4E,
        0x44, 0xAE, 0x42, 0x60, 0x82,
    ]
}
