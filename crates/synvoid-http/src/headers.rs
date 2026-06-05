use chrono::Utc;
use rand::Rng;
use synvoid_config::site::{SiteCorsConfig, SiteSecurityHeadersConfig};

pub fn inject_security_headers(
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
        builder = inject_cors_headers(builder, &config.cors);
    }

    builder
}

pub fn inject_cors_headers(
    builder: http::response::Builder,
    config: &SiteCorsConfig,
) -> http::response::Builder {
    let mut builder = builder;

    if let Some(ref origin) = config.allow_origin {
        if origin == "*" {
            if config.allow_wildcard_cors {
                tracing::warn!(
                    "Site CORS allow_origin='*' is insecure — only use for development. \
                     Specify exact origins."
                );
                builder = builder.header("Access-Control-Allow-Origin", origin);
            } else {
                tracing::error!(
                    "Site CORS allow_origin='*' is rejected for security. \
                     Set allow_wildcard_cors = true to permit (development only)."
                );
            }
        } else {
            builder = builder.header("Access-Control-Allow-Origin", origin);
        }
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

pub fn is_websocket_upgrade(headers: &http::HeaderMap) -> bool {
    let upgrade = headers
        .get("upgrade")
        .and_then(|v| v.to_str().ok())
        .map(|v| v.to_lowercase());

    let connection = headers
        .get("connection")
        .and_then(|v| v.to_str().ok())
        .map(|v| v.to_lowercase());

    let has_upgrade = upgrade.as_ref().map(|u| u == "websocket").unwrap_or(false);
    let has_connection_upgrade = connection
        .as_ref()
        .map(|c| c.contains("upgrade"))
        .unwrap_or(false);

    has_upgrade && has_connection_upgrade
}

pub fn compute_websocket_accept_key(key: &str) -> String {
    use sha1::{Digest, Sha1};

    const GUID: &str = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
    let combined = format!("{}{}", key, GUID);
    let mut hasher = Sha1::new();
    hasher.update(combined.as_bytes());
    let result = hasher.finalize();
    base64::Engine::encode(&base64::engine::general_purpose::STANDARD, result)
}

pub fn generate_stealth_timestamp(jitter_seconds: u32) -> String {
    let offset = if jitter_seconds > 0 {
        let mut rng = rand::rng();
        let secs = rng.random_range(-(jitter_seconds as i64)..=jitter_seconds as i64);
        Utc::now() + chrono::Duration::seconds(secs)
    } else {
        Utc::now()
    };
    offset.format("%a, %d %b %Y %H:%M:%S GMT").to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use synvoid_config::site::{SiteCookieConfig, SiteCorsConfig, SiteSecurityHeadersConfig};

    fn default_security_config() -> SiteSecurityHeadersConfig {
        SiteSecurityHeadersConfig {
            enabled: None,
            strict_transport_security: None,
            content_security_policy: None,
            x_frame_options: None,
            x_content_type_options: None,
            x_xss_protection: None,
            referrer_policy: None,
            permissions_policy: None,
            cache_control: None,
            expect_ct: None,
            x_permitted_cross_domain_policies: None,
            x_download_options: None,
            content_type: None,
            more_clear_headers: vec![],
            cors: SiteCorsConfig::default(),
            cookie: SiteCookieConfig::default(),
            date_header: None,
            date_jitter_seconds: None,
            server_token: None,
        }
    }

    #[test]
    fn test_inject_security_headers_hsts() {
        let config = SiteSecurityHeadersConfig {
            strict_transport_security: Some("max-age=31536000".to_string()),
            ..default_security_config()
        };
        let builder = http::Response::builder();
        let resp = inject_security_headers(builder, &config).body(()).unwrap();
        assert_eq!(
            resp.headers().get("strict-transport-security").unwrap(),
            "max-age=31536000"
        );
    }

    #[test]
    fn test_inject_security_headers_csp() {
        let config = SiteSecurityHeadersConfig {
            content_security_policy: Some("default-src 'self'".to_string()),
            ..default_security_config()
        };
        let builder = http::Response::builder();
        let resp = inject_security_headers(builder, &config).body(()).unwrap();
        assert_eq!(
            resp.headers().get("content-security-policy").unwrap(),
            "default-src 'self'"
        );
    }

    #[test]
    fn test_inject_security_headers_multiple() {
        let config = SiteSecurityHeadersConfig {
            x_frame_options: Some("DENY".to_string()),
            x_content_type_options: Some("nosniff".to_string()),
            referrer_policy: Some("no-referrer".to_string()),
            ..default_security_config()
        };
        let builder = http::Response::builder();
        let resp = inject_security_headers(builder, &config).body(()).unwrap();
        assert_eq!(resp.headers().get("x-frame-options").unwrap(), "DENY");
        assert_eq!(
            resp.headers().get("x-content-type-options").unwrap(),
            "nosniff"
        );
        assert_eq!(
            resp.headers().get("referrer-policy").unwrap(),
            "no-referrer"
        );
    }

    #[test]
    fn test_inject_security_headers_none_config() {
        let config = default_security_config();
        let builder = http::Response::builder();
        let resp = inject_security_headers(builder, &config).body(()).unwrap();
        assert!(resp.headers().is_empty());
    }

    #[test]
    fn test_is_websocket_upgrade_positive() {
        let mut headers = http::HeaderMap::new();
        headers.insert("upgrade", "websocket".parse().unwrap());
        headers.insert("connection", "Upgrade".parse().unwrap());
        assert!(is_websocket_upgrade(&headers));
    }

    #[test]
    fn test_is_websocket_upgrade_missing_upgrade() {
        let mut headers = http::HeaderMap::new();
        headers.insert("connection", "Upgrade".parse().unwrap());
        assert!(!is_websocket_upgrade(&headers));
    }

    #[test]
    fn test_is_websocket_upgrade_missing_connection() {
        let mut headers = http::HeaderMap::new();
        headers.insert("upgrade", "websocket".parse().unwrap());
        assert!(!is_websocket_upgrade(&headers));
    }

    #[test]
    fn test_is_websocket_upgrade_wrong_value() {
        let mut headers = http::HeaderMap::new();
        headers.insert("upgrade", "h2c".parse().unwrap());
        headers.insert("connection", "Upgrade".parse().unwrap());
        assert!(!is_websocket_upgrade(&headers));
    }

    #[test]
    fn test_is_websocket_upgrade_case_insensitive() {
        let mut headers = http::HeaderMap::new();
        headers.insert("upgrade", "WebSocket".parse().unwrap());
        headers.insert("connection", "keep-alive, Upgrade".parse().unwrap());
        assert!(is_websocket_upgrade(&headers));
    }

    #[test]
    fn test_compute_websocket_accept_key_known_value() {
        // RFC 6455 Section 4.2.2 test vector
        let key = "dGhlIHNhbXBsZSBub25jZQ==";
        let expected = "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=";
        assert_eq!(compute_websocket_accept_key(key), expected);
    }

    #[test]
    fn test_compute_websocket_accept_key_deterministic() {
        let key = "test-key-12345";
        let result1 = compute_websocket_accept_key(key);
        let result2 = compute_websocket_accept_key(key);
        assert_eq!(result1, result2);
    }

    #[test]
    fn test_generate_stealth_timestamp_format() {
        let ts = generate_stealth_timestamp(0);
        // Should match RFC 7231 date format
        assert!(ts.contains("GMT"));
        assert!(ts.len() > 20);
    }

    #[test]
    fn test_generate_stealth_timestamp_with_jitter() {
        let ts1 = generate_stealth_timestamp(10);
        let ts2 = generate_stealth_timestamp(10);
        // Both should be valid timestamps
        assert!(ts1.contains("GMT"));
        assert!(ts2.contains("GMT"));
    }
}
