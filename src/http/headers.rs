use crate::config::{SiteCorsConfig, SiteSecurityHeadersConfig};
use chrono::Utc;
use rand::Rng;

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
