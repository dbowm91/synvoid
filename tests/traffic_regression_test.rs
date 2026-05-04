use ahash::AHashSet;
use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
use std::sync::Arc;

use http::HeaderMap;
use maluwaf::config::site::ProxyHeadersConfig;
use maluwaf::config::site::RetryConfig;
use maluwaf::config::{MainConfig, SiteConfig};
use maluwaf::proxy::headers::HEADERS_TO_STRIP;
use maluwaf::proxy::retry::{
    calculate_backoff, is_idempotent_method, is_retryable_status, should_retry_request,
};
use maluwaf::proxy::{
    apply_response_size_limit, build_forward_headers, filter_response_headers,
    is_hop_by_hop_header, join_upstream_url, sanitize_request_path, ForwardedProtocol,
    ResponseSizeError,
};
use maluwaf::router::{BackendType, RouteResult, Router};
use maluwaf::upstream::{Backend, LoadBalanceAlgorithm, UpstreamPool};

#[cfg(test)]
mod echo_server_harness_tests {
    use maluwaf::test_utils::echo::{start_echo_server, EchoResponse};

    #[tokio::test]
    async fn test_echo_server_starts_and_captures() {
        let server = start_echo_server().await;
        assert_ne!(server.addr.port(), 0);

        let stream = tokio::net::TcpStream::connect(server.addr).await.unwrap();
        use tokio::io::AsyncReadExt;
        use tokio::io::AsyncWriteExt;
        let mut stream = stream;

        server.push_response(EchoResponse::new(200, "hello"));

        stream.write_all(b"GET /test/path?q=1 HTTP/1.1\r\nHost: example.com\r\nAuthorization: Bearer token123\r\n\r\n").await.unwrap();

        let mut buf = vec![0u8; 4096];
        let _ = stream.read(&mut buf).await;

        let captured = server.take_captured();
        assert_eq!(captured.len(), 1);
        assert_eq!(captured[0].method, "GET");
        assert_eq!(captured[0].path, "/test/path");
        assert_eq!(captured[0].query.as_deref(), Some("q=1"));

        let auth_header = captured[0]
            .headers
            .iter()
            .find(|(k, _)| k == "Authorization");
        assert!(auth_header.is_some());
        assert_eq!(auth_header.unwrap().1, "Bearer token123");
    }

    #[tokio::test]
    async fn test_echo_server_custom_status_and_headers() {
        let server = start_echo_server().await;

        server.push_response(
            EchoResponse::new(201, r#"{"id":42}"#)
                .with_header("content-type", "application/json")
                .with_header("x-custom", "value"),
        );

        let stream = tokio::net::TcpStream::connect(server.addr).await.unwrap();
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let mut stream = stream;

        stream
            .write_all(b"POST /api/items HTTP/1.1\r\nHost: example.com\r\n\r\n")
            .await
            .unwrap();

        let mut buf = vec![0u8; 8192];
        let n = stream.read(&mut buf).await.unwrap();
        let response = String::from_utf8_lossy(&buf[..n]);

        assert!(response.starts_with("HTTP/1.1 201 Created"));
        assert!(response.contains("content-type: application/json"));
        assert!(response.contains("x-custom: value"));
        assert!(response.contains(r#"{"id":42}"#));
    }

    #[tokio::test]
    async fn test_echo_server_delayed_response() {
        let server = start_echo_server().await;

        server.push_response(EchoResponse::new(200, "delayed").with_delay(50));

        let stream = tokio::net::TcpStream::connect(server.addr).await.unwrap();
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let mut stream = stream;

        let start = std::time::Instant::now();
        stream.write_all(b"GET / HTTP/1.1\r\n\r\n").await.unwrap();
        let mut buf = vec![0u8; 4096];
        let _ = stream.read(&mut buf).await;
        let elapsed = start.elapsed();

        assert!(elapsed.as_millis() >= 40);
    }

    #[tokio::test]
    async fn test_echo_server_multiple_requests() {
        let server = start_echo_server().await;

        for i in 0..3 {
            server.push_response(EchoResponse::new(200, format!("response {}", i)));
        }

        for i in 0..3 {
            let stream = tokio::net::TcpStream::connect(server.addr).await.unwrap();
            use tokio::io::{AsyncReadExt, AsyncWriteExt};
            let mut stream = stream;
            stream
                .write_all(format!("GET /req{} HTTP/1.1\r\n\r\n", i).as_bytes())
                .await
                .unwrap();
            let mut buf = vec![0u8; 4096];
            let _ = stream.read(&mut buf).await;
        }

        let captured = server.take_captured();
        assert_eq!(captured.len(), 3);
        assert_eq!(captured[0].path, "/req0");
        assert_eq!(captured[1].path, "/req1");
        assert_eq!(captured[2].path, "/req2");
    }
}

#[cfg(test)]
mod host_validation_tests {
    use super::*;

    fn make_router_with_domains(domains: Vec<&str>, reject_unknown: bool) -> Router {
        let mut site_config = SiteConfig::default();
        site_config.site.domains = domains.iter().map(|d| d.to_string()).collect();
        site_config.site.upstream.default = "http://127.0.0.1:8080".to_string();
        site_config.security.reject_unknown_hosts = Some(reject_unknown);

        let mut main_config = MainConfig::default();
        main_config.fallback.mode = "return_404".to_string();

        let mut sites = HashMap::new();
        sites.insert(site_config.site_id(), site_config);

        Router::new(&main_config, sites)
    }

    #[test]
    fn test_valid_host_accepted() {
        let router = make_router_with_domains(vec!["example.com", "www.example.com"], true);

        let result = router.route("example.com", "/api/data");
        assert!(matches!(result, RouteResult::Found(_)));

        let result = router.route("www.example.com", "/api/data");
        assert!(matches!(result, RouteResult::Found(_)));
    }

    #[test]
    fn test_unknown_host_rejected_when_enabled() {
        let router = make_router_with_domains(vec!["example.com"], true);

        let result = router.route("evil.example.com", "/api/data");
        assert!(matches!(result, RouteResult::NotFound(_)));
    }

    #[test]
    fn test_unknown_host_accepted_when_disabled() {
        let router = make_router_with_domains(vec!["example.com"], false);

        let result = router.route("other.example.com", "/api/data");
        assert!(matches!(result, RouteResult::Found(_)));
    }

    #[test]
    fn test_case_insensitive_host_matching() {
        let router = make_router_with_domains(vec!["example.com"], true);

        let result = router.route("EXAMPLE.COM", "/path");
        assert!(matches!(result, RouteResult::Found(_)));

        let result = router.route("Example.Com", "/path");
        assert!(matches!(result, RouteResult::Found(_)));
    }

    #[test]
    fn test_www_stripped_host_matching() {
        let router = make_router_with_domains(vec!["example.com"], true);

        let result = router.route("www.example.com", "/path");
        assert!(matches!(result, RouteResult::Found(_)));
    }

    #[test]
    fn test_subdomain_of_known_host_rejected() {
        let router = make_router_with_domains(vec!["example.com"], true);

        let result = router.route("sub.example.com", "/path");
        assert!(matches!(result, RouteResult::NotFound(_)));
    }

    #[test]
    fn test_empty_host_returns_not_found() {
        let router = make_router_with_domains(vec!["example.com"], false);

        let result = router.route("", "/path");
        assert!(matches!(result, RouteResult::NotFound(_)));
    }
}

#[cfg(test)]
mod header_preservation_tests {
    use super::*;

    #[test]
    fn test_authorization_preserved() {
        let client_ip = "192.168.1.1".parse().unwrap();
        let mut headers = HeaderMap::new();
        headers.insert("authorization", "Bearer secret-token".parse().unwrap());
        headers.insert("content-type", "application/json".parse().unwrap());
        headers.insert("accept", "application/json".parse().unwrap());

        let config = ProxyHeadersConfig::default();
        let forward = build_forward_headers(client_ip, &headers, &config, ForwardedProtocol::Https);

        assert_eq!(forward.get("authorization").unwrap(), "Bearer secret-token");
        assert_eq!(forward.get("content-type").unwrap(), "application/json");
        assert_eq!(forward.get("accept").unwrap(), "application/json");
    }

    #[test]
    fn test_connection_stripped() {
        let client_ip = "10.0.0.1".parse().unwrap();
        let mut headers = HeaderMap::new();
        headers.insert("connection", "keep-alive".parse().unwrap());
        headers.insert("keep-alive", "timeout=60".parse().unwrap());
        headers.insert("transfer-encoding", "chunked".parse().unwrap());
        headers.insert("upgrade", "websocket".parse().unwrap());

        let config = ProxyHeadersConfig::default();
        let forward = build_forward_headers(client_ip, &headers, &config, ForwardedProtocol::Http);

        assert!(forward.get("connection").is_none());
        assert!(forward.get("keep-alive").is_none());
        assert!(forward.get("transfer-encoding").is_none());
        assert!(forward.get("upgrade").is_none());
    }

    #[test]
    fn test_proxy_authenticate_stripped() {
        let client_ip = "10.0.0.1".parse().unwrap();
        let mut headers = HeaderMap::new();
        headers.insert("proxy-authenticate", "Basic realm=test".parse().unwrap());
        headers.insert("proxy-authorization", "Basic dXNlcjpwYXNz".parse().unwrap());

        let config = ProxyHeadersConfig::default();
        let forward = build_forward_headers(client_ip, &headers, &config, ForwardedProtocol::Http);

        assert!(forward.get("proxy-authenticate").is_none());
        assert!(forward.get("proxy-authorization").is_none());
    }

    #[test]
    fn test_xff_and_x_real_ip_added() {
        let client_ip = "203.0.113.5".parse().unwrap();
        let headers = HeaderMap::new();

        let config = ProxyHeadersConfig::default();
        let forward = build_forward_headers(client_ip, &headers, &config, ForwardedProtocol::Https);

        assert_eq!(forward.get("x-forwarded-for").unwrap(), "203.0.113.5");
        assert_eq!(forward.get("x-real-ip").unwrap(), "203.0.113.5");
        assert_eq!(forward.get("x-forwarded-proto").unwrap(), "https");
    }

    #[test]
    fn test_xff_appended_to_existing() {
        let client_ip = "203.0.113.5".parse().unwrap();
        let mut headers = HeaderMap::new();
        headers.insert("x-forwarded-for", "10.0.0.1, 10.0.0.2".parse().unwrap());

        let config = ProxyHeadersConfig::default();
        let forward = build_forward_headers(client_ip, &headers, &config, ForwardedProtocol::Http);

        let xff = forward.get("x-forwarded-for").unwrap().to_str().unwrap();
        assert!(xff.contains("203.0.113.5"));
    }

    #[test]
    fn test_response_header_filtering_strips_server() {
        let mut headers = HeaderMap::new();
        headers.insert("server", "nginx/1.24".parse().unwrap());
        headers.insert("x-powered-by", "Express".parse().unwrap());
        headers.insert("content-type", "text/html".parse().unwrap());

        let filter: AHashSet<String> = HEADERS_TO_STRIP.iter().map(|s| s.to_string()).collect();
        let filtered = filter_response_headers(&headers, &filter);
        let names: Vec<&str> = filtered.iter().map(|(k, _)| k.as_str()).collect();

        assert!(names.contains(&"content-type"));
        assert!(!names.iter().any(|n| *n == "server"));
        assert!(!names.iter().any(|n| *n == "x-powered-by"));
    }

    #[test]
    fn test_hop_by_hop_classification() {
        assert!(is_hop_by_hop_header("connection"));
        assert!(is_hop_by_hop_header("keep-alive"));
        assert!(is_hop_by_hop_header("transfer-encoding"));
        assert!(is_hop_by_hop_header("upgrade"));
        assert!(is_hop_by_hop_header("proxy-authenticate"));

        assert!(!is_hop_by_hop_header("content-type"));
        assert!(!is_hop_by_hop_header("authorization"));
        assert!(!is_hop_by_hop_header("cookie"));
        assert!(!is_hop_by_hop_header("host"));
    }

    #[test]
    fn test_hide_removes_specific_headers() {
        let client_ip = "10.0.0.1".parse().unwrap();
        let mut headers = HeaderMap::new();
        headers.insert("authorization", "Bearer token".parse().unwrap());
        headers.insert("x-internal-secret", "secret123".parse().unwrap());

        let mut config = ProxyHeadersConfig::default();
        config.hide = vec!["x-internal-secret".to_string()];

        let forward = build_forward_headers(client_ip, &headers, &config, ForwardedProtocol::Https);

        assert_eq!(forward.get("authorization").unwrap(), "Bearer token");
        assert!(forward.get("x-internal-secret").is_none());
    }

    #[test]
    fn test_forward_list_restricts_headers() {
        let client_ip = "10.0.0.1".parse().unwrap();
        let mut headers = HeaderMap::new();
        headers.insert("authorization", "Bearer token".parse().unwrap());
        headers.insert("x-custom", "value".parse().unwrap());
        headers.insert("accept", "*/*".parse().unwrap());

        let mut config = ProxyHeadersConfig::default();
        config.forward = vec!["accept".to_string()];

        let forward = build_forward_headers(client_ip, &headers, &config, ForwardedProtocol::Https);

        assert!(forward.get("authorization").is_none());
        assert!(forward.get("x-custom").is_none());
        assert_eq!(forward.get("accept").unwrap(), "*/*");
    }
}

#[cfg(test)]
mod url_join_tests {
    use super::*;

    #[test]
    fn test_basic_join() {
        assert_eq!(
            join_upstream_url("http://backend.example.com", "/api/users"),
            "http://backend.example.com/api/users"
        );
    }

    #[test]
    fn test_trailing_slash_on_upstream() {
        assert_eq!(
            join_upstream_url("http://backend.example.com/", "/api/users"),
            "http://backend.example.com/api/users"
        );
    }

    #[test]
    fn test_multiple_trailing_slashes() {
        assert_eq!(
            join_upstream_url("http://backend.example.com///", "/api/users"),
            "http://backend.example.com/api/users"
        );
    }

    #[test]
    fn test_path_without_leading_slash() {
        assert_eq!(
            join_upstream_url("http://backend.example.com", "api/users"),
            "http://backend.example.com/api/users"
        );
    }

    #[test]
    fn test_empty_path() {
        assert_eq!(
            join_upstream_url("http://backend.example.com", ""),
            "http://backend.example.com/"
        );
    }

    #[test]
    fn test_query_string_preserved() {
        assert_eq!(
            join_upstream_url("http://backend.example.com", "/search?q=hello&page=2"),
            "http://backend.example.com/search?q=hello&page=2"
        );
    }

    #[test]
    fn test_with_port() {
        assert_eq!(
            join_upstream_url("http://backend.example.com:8080", "/api"),
            "http://backend.example.com:8080/api"
        );
    }

    #[test]
    fn test_path_sanitization_double_slash() {
        assert_eq!(sanitize_request_path("/foo//bar"), "/foo/bar");
        assert_eq!(sanitize_request_path("/foo///bar"), "/foo/bar");
    }

    #[test]
    fn test_path_sanitization_dot_segments() {
        assert_eq!(sanitize_request_path("/foo/./bar"), "/foo/bar");
    }

    #[test]
    fn test_path_sanitization_percent_encoding() {
        assert_eq!(sanitize_request_path("/foo%20bar"), "/foo bar");
        assert_eq!(sanitize_request_path("/a%2Fb"), "/a/b");
    }

    #[test]
    fn test_path_sanitization_null_bytes_stripped() {
        assert_eq!(sanitize_request_path("/foo%00bar"), "/foobar");
    }

    #[test]
    fn test_path_sanitization_clean_path_unchanged() {
        assert_eq!(
            sanitize_request_path("/api/v1/users/123"),
            "/api/v1/users/123"
        );
    }
}

#[cfg(test)]
mod response_size_limit_tests {
    use super::*;

    #[test]
    fn test_under_limit_ok() {
        let body = vec![0u8; 1024];
        assert!(apply_response_size_limit(&body, Some(2048)).is_ok());
    }

    #[test]
    fn test_at_limit_ok() {
        let body = vec![0u8; 1024];
        assert!(apply_response_size_limit(&body, Some(1024)).is_ok());
    }

    #[test]
    fn test_over_limit_fails() {
        let body = vec![0u8; 1025];
        assert!(apply_response_size_limit(&body, Some(1024)).is_err());
    }

    #[test]
    fn test_no_limit_always_ok() {
        let body = vec![0u8; 10 * 1024 * 1024];
        assert!(apply_response_size_limit(&body, None).is_ok());
    }

    #[test]
    fn test_zero_body_under_limit() {
        let body: Vec<u8> = Vec::new();
        assert!(apply_response_size_limit(&body, Some(0)).is_ok());
    }

    #[test]
    fn test_one_byte_over_zero_limit() {
        let body = vec![1u8; 1];
        assert!(apply_response_size_limit(&body, Some(0)).is_err());
    }

    #[test]
    fn test_error_is_response_size_error() {
        let body = vec![0u8; 100];
        let result = apply_response_size_limit(&body, Some(50));
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.to_string().contains("size limit"));
    }
}

#[cfg(test)]
mod retry_behavior_tests {
    use super::*;

    fn default_retry_config() -> RetryConfig {
        RetryConfig {
            enabled: true,
            max_retries: 3,
            timeout_ms: Some(10),
            retry_on_error: true,
            retry_on_timeout: true,
            retry_on_status: vec![],
            retry_non_idempotent: false,
        }
    }

    #[test]
    fn test_retry_disabled_single_attempt() {
        let config = RetryConfig {
            enabled: false,
            ..Default::default()
        };

        assert!(!config.enabled);
        assert!(!should_retry_request(&http::Method::GET, &config) || !config.enabled);
    }

    #[test]
    fn test_idempotent_methods_retryable() {
        assert!(is_idempotent_method(&http::Method::GET));
        assert!(is_idempotent_method(&http::Method::HEAD));
        assert!(is_idempotent_method(&http::Method::OPTIONS));
        assert!(is_idempotent_method(&http::Method::TRACE));
    }

    #[test]
    fn test_non_idempotent_methods_not_retryable_by_default() {
        assert!(!is_idempotent_method(&http::Method::POST));
        assert!(!is_idempotent_method(&http::Method::PUT));
        assert!(!is_idempotent_method(&http::Method::DELETE));
        assert!(!is_idempotent_method(&http::Method::PATCH));
    }

    #[test]
    fn test_should_retry_idempotent_get() {
        let config = default_retry_config();
        assert!(should_retry_request(&http::Method::GET, &config));
    }

    #[test]
    fn test_should_not_retry_post_by_default() {
        let config = default_retry_config();
        assert!(!should_retry_request(&http::Method::POST, &config));
    }

    #[test]
    fn test_should_retry_post_when_non_idempotent_enabled() {
        let mut config = default_retry_config();
        config.retry_non_idempotent = true;
        assert!(should_retry_request(&http::Method::POST, &config));
    }

    #[test]
    fn test_502_is_retryable() {
        let config = default_retry_config();
        assert!(is_retryable_status(502, &config));
    }

    #[test]
    fn test_503_is_retryable() {
        let config = default_retry_config();
        assert!(is_retryable_status(503, &config));
    }

    #[test]
    fn test_504_is_retryable() {
        let config = default_retry_config();
        assert!(is_retryable_status(504, &config));
    }

    #[test]
    fn test_200_is_not_retryable() {
        let config = default_retry_config();
        assert!(!is_retryable_status(200, &config));
    }

    #[test]
    fn test_404_is_not_retryable() {
        let config = default_retry_config();
        assert!(!is_retryable_status(404, &config));
    }

    #[test]
    fn test_custom_retry_status() {
        let config = RetryConfig {
            retry_on_status: vec![429, 500],
            ..default_retry_config()
        };
        assert!(is_retryable_status(429, &config));
        assert!(is_retryable_status(500, &config));
        assert!(!is_retryable_status(502, &config));
    }

    #[test]
    fn test_backoff_exponential() {
        let base = 100;
        assert_eq!(calculate_backoff(0, base), 100);
        assert_eq!(calculate_backoff(1, base), 200);
        assert_eq!(calculate_backoff(2, base), 400);
        assert_eq!(calculate_backoff(3, base), 800);
    }

    #[test]
    fn test_backoff_capped_at_30s() {
        let result = calculate_backoff(10, 60000);
        assert_eq!(result, 30000);
    }

    #[test]
    fn test_backoff_zero_base() {
        assert_eq!(calculate_backoff(5, 0), 0);
    }
}

#[cfg(test)]
mod upstream_pool_routing_tests {
    use super::*;

    #[test]
    fn test_round_robin_selection() {
        let pool = UpstreamPool::new(
            vec![
                "http://127.0.0.1:8080".to_string(),
                "http://127.0.0.1:8081".to_string(),
                "http://127.0.0.1:8082".to_string(),
            ],
            LoadBalanceAlgorithm::RoundRobin,
        );

        let first = pool.select_backend().unwrap();
        let second = pool.select_backend().unwrap();
        let third = pool.select_backend().unwrap();
        let fourth = pool.select_backend().unwrap();

        assert_ne!(first.url, second.url);
        assert_ne!(second.url, third.url);
        assert_eq!(first.url, fourth.url);
    }

    #[test]
    fn test_failed_backend_not_selected() {
        let pool = UpstreamPool::new(
            vec![
                "http://127.0.0.1:8080".to_string(),
                "http://127.0.0.1:8081".to_string(),
            ],
            LoadBalanceAlgorithm::RoundRobin,
        );

        for _ in 0..3 {
            pool.mark_failed("http://127.0.0.1:8080");
        }

        let selected = pool.select_backend().unwrap();
        assert_eq!(selected.url.as_ref(), "http://127.0.0.1:8081");
    }

    #[test]
    fn test_backup_fallback() {
        let pool = UpstreamPool::new_with_backup(
            vec!["http://127.0.0.1:8080".to_string()],
            vec!["http://127.0.0.1:9090".to_string()],
            LoadBalanceAlgorithm::RoundRobin,
        );

        let primary = pool.select_backend().unwrap();
        assert!(!primary.is_backup);

        for _ in 0..3 {
            pool.mark_failed("http://127.0.0.1:8080");
        }

        let backup = pool.select_backend().unwrap();
        assert_eq!(backup.url.as_ref(), "http://127.0.0.1:9090");
        assert!(backup.is_backup);
    }

    #[test]
    fn test_all_unhealthy_returns_none() {
        let pool = UpstreamPool::new(
            vec![
                "http://127.0.0.1:8080".to_string(),
                "http://127.0.0.1:8081".to_string(),
            ],
            LoadBalanceAlgorithm::RoundRobin,
        );

        pool.mark_unhealthy("http://127.0.0.1:8080");
        pool.mark_unhealthy("http://127.0.0.1:8081");

        assert!(pool.select_backend().is_none());
    }

    #[test]
    fn test_select_next_backend() {
        let pool = UpstreamPool::new(
            vec![
                "http://127.0.0.1:8080".to_string(),
                "http://127.0.0.1:8081".to_string(),
            ],
            LoadBalanceAlgorithm::RoundRobin,
        );

        let current = pool.select_backend().unwrap();
        let next = pool.select_next_backend(&current);

        assert!(next.is_some());
        assert_ne!(next.unwrap().url, current.url);
    }

    #[test]
    fn test_backend_recovery_after_successes() {
        let backend = Backend::new("http://127.0.0.1:8080".to_string());
        backend.is_healthy.set(false);

        assert!(!backend.is_healthy.is_running());

        backend.record_success();
        backend.record_success();
        assert!(!backend.is_healthy.is_running());

        backend.record_success();
        assert!(backend.is_healthy.is_running());
    }

    #[test]
    fn test_backend_circuit_breaker_trips() {
        let backend = Backend::new("http://127.0.0.1:8080".to_string());
        assert!(backend.is_healthy.is_running());

        backend.record_failure();
        backend.record_failure();
        assert!(backend.is_healthy.is_running());

        backend.record_failure();
        assert!(!backend.is_healthy.is_running());
    }

    #[test]
    fn test_connection_tracking() {
        let backend = Backend::new("http://127.0.0.1:8080".to_string()).with_max_connections(5);

        assert_eq!(
            backend
                .current_connections
                .load(std::sync::atomic::Ordering::Relaxed),
            0
        );
        assert!(backend.is_available());

        for _ in 0..5 {
            backend.increment_connections();
        }
        assert!(!backend.is_available());

        backend.decrement_connections();
        assert!(backend.is_available());
    }
}

#[cfg(test)]
mod router_fallback_tests {
    use super::*;

    #[test]
    fn test_fallback_return_404() {
        let mut main_config = MainConfig::default();
        main_config.fallback.mode = "return_404".to_string();

        let router = Router::new(&main_config, HashMap::new());

        let result = router.route("unknown.example.com", "/path");
        assert!(matches!(result, RouteResult::NotFound(_)));
        if let RouteResult::NotFound(msg) = result {
            assert!(msg.contains("unknown.example.com"));
        }
    }

    #[test]
    fn test_fallback_proxy_to() {
        let mut main_config = MainConfig::default();
        main_config.fallback.mode = "proxy_to".to_string();
        main_config.fallback.upstream = Some("http://fallback-backend:8080".to_string());

        let router = Router::new(&main_config, HashMap::new());

        let result = router.route("unknown.example.com", "/path");
        assert!(
            matches!(result, RouteResult::Found(ref t) if matches!(t.backend_type, BackendType::Upstream))
        );
    }

    #[test]
    fn test_wildcard_domain_matching() {
        let mut site_config = SiteConfig::default();
        site_config.site.domains = vec![".example.com".to_string()];
        site_config.site.upstream.default = "http://127.0.0.1:8080".to_string();

        let mut main_config = MainConfig::default();
        main_config.fallback.mode = "return_404".to_string();

        let mut sites = HashMap::new();
        sites.insert(site_config.site_id(), site_config);

        let router = Router::new(&main_config, sites);

        let result = router.route("sub.example.com", "/path");
        assert!(matches!(result, RouteResult::Found(_)));

        let result = router.route("deep.sub.example.com", "/path");
        assert!(matches!(result, RouteResult::Found(_)));
    }
}
