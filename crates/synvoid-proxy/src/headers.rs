//! Header handling for proxy requests and responses.

use http::header::HeaderName;
use std::cell::RefCell;
use std::net::IpAddr;
use std::sync::LazyLock;
use unicode_normalization::UnicodeNormalization;

use ahash::AHashSet;
use synvoid_config::site::ProxyHeadersConfig;

pub const HOP_BY_HOP_HEADERS: &[&str] = &[
    "connection",
    "keep-alive",
    "close",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailers",
    "transfer-encoding",
    "upgrade",
];

pub const HEADERS_TO_STRIP: &[&str] = &[
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
    "x-backend",
    "x-server",
    "location",
];

pub const MAX_XFF_CHAIN_LENGTH: usize = 10;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ForwardedProtocol {
    Http,
    Https,
}

impl ForwardedProtocol {
    pub fn as_str(&self) -> &'static str {
        match self {
            ForwardedProtocol::Http => "http",
            ForwardedProtocol::Https => "https",
        }
    }
}

static HOP_BY_HOP_HEADERS_SET: LazyLock<AHashSet<&'static str>> =
    LazyLock::new(|| HOP_BY_HOP_HEADERS.iter().copied().collect());

static STATIC_HEADERS_TO_FILTER: LazyLock<AHashSet<&'static str>> = LazyLock::new(|| {
    HOP_BY_HOP_HEADERS
        .iter()
        .chain(HEADERS_TO_STRIP.iter())
        .copied()
        .collect()
});

static HOP_BY_HOP_HEADER_NAMES: LazyLock<AHashSet<http::header::HeaderName>> =
    LazyLock::new(|| {
        HOP_BY_HOP_HEADERS
            .iter()
            .filter_map(|s| s.parse().ok())
            .collect()
    });

#[inline]
pub fn is_hop_by_hop_header(name: &str) -> bool {
    HOP_BY_HOP_HEADERS
        .iter()
        .any(|h| h.eq_ignore_ascii_case(name))
}

#[inline]
pub fn is_hop_by_hop_header_name(name: &http::header::HeaderName) -> bool {
    HOP_BY_HOP_HEADER_NAMES.contains(name)
}

pub fn is_private_ip(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(ipv4) => {
            let octets = ipv4.octets();
            octets[0] == 10
                || (octets[0] == 172 && (16..=31).contains(&octets[1]))
                || (octets[0] == 192 && octets[1] == 168)
                || octets[0] == 127
                || (octets[0] == 169 && octets[1] == 254)
                || (octets[0] == 224 && octets[1] <= 239)
                || octets[0] == 0
        }
        IpAddr::V6(ipv6) => {
            let segments = ipv6.segments();
            segments[0] == 0xfc00
                || segments[0] == 0xfe80
                || segments[0] == 0xff00
                || (segments[0] == 0
                    && segments[1] == 0
                    && segments[2] == 0
                    && segments[3] == 0
                    && segments[4] == 0
                    && segments[5] == 0
                    && segments[6] == 0
                    && segments[7] == 1)
        }
    }
}

fn is_public_ip(s: &str) -> Option<bool> {
    s.parse::<IpAddr>().ok().map(|ip| !is_private_ip(&ip))
}

pub fn build_headers_to_filter(
    global_headers: &[String],
    site_headers: &[String],
) -> AHashSet<http::header::HeaderName> {
    let mut to_filter: AHashSet<http::header::HeaderName> = STATIC_HEADERS_TO_FILTER
        .iter()
        .filter_map(|s| s.parse().ok())
        .collect();

    for header in global_headers {
        if let Ok(name) = header.to_lowercase().parse() {
            to_filter.insert(name);
        }
    }

    for header in site_headers {
        if let Ok(name) = header.to_lowercase().parse() {
            to_filter.insert(name);
        }
    }

    to_filter
}

pub fn build_headers_to_filter_for_site(
    global_headers: &[String],
    site_security_headers: &[String],
    site_security_headers_legacy: &[String],
) -> AHashSet<http::header::HeaderName> {
    let mut to_filter = build_headers_to_filter(global_headers, site_security_headers);
    for header in site_security_headers_legacy {
        if let Ok(name) = header.to_lowercase().parse() {
            to_filter.insert(name);
        }
    }
    to_filter
}

pub fn sanitize_request_path(path: &str) -> std::borrow::Cow<'_, str> {
    if path.is_empty() {
        return std::borrow::Cow::Owned(String::new());
    }

    let path = path.nfkc().collect::<String>();

    let fast_path = {
        let bytes = path.as_bytes();
        !bytes.iter().any(|&b| b == b'%' || b == b'.' || b < 0x20) && !path.contains("//")
    };
    if fast_path {
        return std::borrow::Cow::Owned(path);
    }

    let mut result = Vec::<u8>::with_capacity(path.len());
    let mut bytes = path.bytes();
    let mut segments: Vec<Vec<u8>> = Vec::new();
    let mut current_segment: Vec<u8> = Vec::new();

    while let Some(b) = bytes.next() {
        match b {
            b'%' => {
                let h = bytes.next();
                let l = bytes.next();
                if let (Some(h), Some(l)) = (h, l) {
                    if let (Ok(h), Ok(l)) = (
                        u8::from_str_radix(std::str::from_utf8(&[h]).unwrap_or(""), 16),
                        u8::from_str_radix(std::str::from_utf8(&[l]).unwrap_or(""), 16),
                    ) {
                        let decoded = (h << 4) | l;
                        if decoded != 0 {
                            current_segment.push(decoded);
                        }
                    } else {
                        result.push(b'%');
                        result.push(h);
                        result.push(l);
                    }
                } else {
                    result.push(b'%');
                    if let Some(h) = h {
                        result.push(h);
                    }
                }
            }
            b'.' => {
                current_segment.push(b'.');
            }
            b'/' => {
                if !current_segment.is_empty() {
                    segments.push(std::mem::take(&mut current_segment));
                    current_segment = Vec::new();
                }
                while result.last() == Some(&b'/') {
                    result.pop();
                }
                result.push(b'/');
                continue;
            }
            b if b < 0x20 => {}
            _ => current_segment.push(b),
        }
    }

    if !current_segment.is_empty() {
        segments.push(current_segment);
    }

    for segment in segments.iter() {
        if segment.len() == 2 && segment[0] == b'.' && segment[1] == b'.' {
            if let Some(pos) = result.iter().rposition(|&b| b == b'/') {
                result.drain(pos..);
            }
        } else if segment.len() == 1 && segment[0] == b'.' {
            continue;
        } else if !segment.is_empty() {
            if result.is_empty() || result.last() != Some(&b'/') {
                result.push(b'/');
            }
            result.extend_from_slice(segment);
        }
    }

    if result.is_empty() {
        return std::borrow::Cow::Owned("/".to_string().nfkc().collect());
    }

    std::borrow::Cow::Owned(
        String::from_utf8(result)
            .unwrap_or_else(|e| {
                let valid_up_to = e.utf8_error().valid_up_to();
                let bytes = e.into_bytes();
                let (valid, _) = bytes.split_at(valid_up_to);
                String::from_utf8_lossy(valid).into_owned()
            })
            .nfkc()
            .collect(),
    )
}

#[inline]
pub fn filter_response_headers(
    headers: &http::HeaderMap,
    headers_to_filter: &AHashSet<String>,
) -> Vec<(String, String)> {
    headers
        .iter()
        .filter(|(k, _)| {
            let name_str = k.as_str();
            !HOP_BY_HOP_HEADERS_SET.contains(name_str) && !headers_to_filter.contains(name_str)
        })
        .filter_map(|(k, v)| v.to_str().ok().map(|vv| (k.to_string(), vv.to_string())))
        .collect()
}

#[inline]
pub fn filter_response_headers_buf(
    headers: &http::HeaderMap,
    headers_to_filter: &AHashSet<http::header::HeaderName>,
) -> http::HeaderMap {
    let mut result = http::HeaderMap::new();
    for (k, v) in headers.iter() {
        if HOP_BY_HOP_HEADER_NAMES.contains(k) || headers_to_filter.contains(k) {
            continue;
        }
        result.insert(k, v.clone());
    }
    result
}

#[inline]
pub fn filter_response_headers_buf_with_str_set(
    headers: &http::HeaderMap,
    headers_to_filter: &std::collections::HashSet<&str>,
) -> http::HeaderMap {
    let mut result = http::HeaderMap::new();
    for (k, v) in headers.iter() {
        if HOP_BY_HOP_HEADER_NAMES.contains(k) || headers_to_filter.contains(k.as_str()) {
            continue;
        }
        result.insert(k, v.clone());
    }
    result
}

pub fn apply_response_header_transforms(
    headers: &mut http::HeaderMap,
    config: &ProxyHeadersConfig,
) {
    if config.clear.is_empty() && config.set.is_empty() && config.hide.is_empty() {
        return;
    }

    let clear_patterns: Vec<String> = config.clear.to_vec();
    let hide_patterns: Vec<String> = config.hide.to_vec();

    let should_remove = |name: &http::header::HeaderName| -> bool {
        let name_str = name.as_str();

        for pattern in &clear_patterns {
            if pattern.contains('*') {
                let prefix = pattern.trim_end_matches('*');
                if name_str.starts_with(prefix) {
                    return true;
                }
            } else if name_str == pattern.to_lowercase() {
                return true;
            }
        }

        for pattern in &hide_patterns {
            if pattern.contains('*') {
                let prefix = pattern.trim_end_matches('*');
                if name_str.starts_with(prefix) {
                    return true;
                }
            } else if name_str == pattern.to_lowercase() {
                return true;
            }
        }

        false
    };

    let mut new_headers = http::HeaderMap::new();
    for (name, value) in headers.iter() {
        if !should_remove(name) {
            new_headers.insert(name, value.clone());
        }
    }

    for override_hdr in &config.set {
        if let (Ok(name), Ok(value)) = (
            HeaderName::from_bytes(override_hdr.name.as_bytes()),
            override_hdr.value.parse(),
        ) {
            new_headers.insert(name, value);
        }
    }

    *headers = new_headers;
}

static X_FORWARDED_FOR: LazyLock<http::header::HeaderName> =
    LazyLock::new(|| http::header::HeaderName::from_static("x-forwarded-for"));
static X_REAL_IP: LazyLock<http::header::HeaderName> =
    LazyLock::new(|| http::header::HeaderName::from_static("x-real-ip"));
static X_FORWARDED_PROTO: LazyLock<http::header::HeaderName> =
    LazyLock::new(|| http::header::HeaderName::from_static("x-forwarded-proto"));

thread_local! {
    static XFF_BUFFER: RefCell<String> = RefCell::new(String::with_capacity(256));
}

pub fn validate_and_truncate_xff(existing: &str, client_ip: &str) -> String {
    let mut entries: Vec<&str> = existing.split(',').map(|s| s.trim()).collect();
    entries.retain(|e| !e.is_empty() && is_public_ip(e) == Some(true));
    if entries.len() >= MAX_XFF_CHAIN_LENGTH {
        entries = entries.split_off(entries.len() - MAX_XFF_CHAIN_LENGTH + 1);
    }

    XFF_BUFFER.with(|buf| {
        let mut buf = buf.borrow_mut();
        buf.clear();
        if entries.is_empty() {
            buf.push_str(client_ip);
        } else {
            let joined = entries.join(", ");
            buf.push_str(&joined);
            buf.push_str(", ");
            buf.push_str(client_ip);
        }
        buf.to_string()
    })
}

pub fn build_forward_headers(
    client_ip: std::net::IpAddr,
    original_headers: &http::HeaderMap,
    config: &ProxyHeadersConfig,
    protocol: ForwardedProtocol,
) -> http::HeaderMap {
    let capacity = original_headers.len().min(32).max(8);
    let mut forward_headers = http::HeaderMap::with_capacity(capacity);

    let headers_to_forward: Vec<&str> = if config.forward.is_empty() {
        vec!["*"]
    } else {
        config.forward.iter().map(|s| s.as_str()).collect()
    };

    let forward_all = headers_to_forward.contains(&"*");

    for (name, value) in original_headers.iter() {
        let name_str = name.as_str();

        if is_hop_by_hop_header(name_str) {
            continue;
        }

        if name_str.eq_ignore_ascii_case("x-forwarded-for")
            || name_str.eq_ignore_ascii_case("x-real-ip")
            || name_str.eq_ignore_ascii_case("forwarded")
            || name_str.eq_ignore_ascii_case("x-forwarded-proto")
        {
            continue;
        }

        if config.hide.iter().any(|h| h.eq_ignore_ascii_case(name_str)) {
            continue;
        }

        if config
            .clear
            .iter()
            .any(|h| h.eq_ignore_ascii_case(name_str))
        {
            continue;
        }

        let should_forward = forward_all
            || headers_to_forward
                .iter()
                .any(|h| h.eq_ignore_ascii_case(name_str));
        if should_forward {
            forward_headers.insert(name, value.clone());
        }
    }

    let xff_value = {
        let existing = original_headers
            .get("x-forwarded-for")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");
        validate_and_truncate_xff(existing, &client_ip.to_string())
    };
    if let Ok(value) = xff_value.parse::<http::HeaderValue>() {
        forward_headers.insert(X_FORWARDED_FOR.clone(), value);
    }

    if let Ok(value) = client_ip.to_string().parse::<http::HeaderValue>() {
        forward_headers.insert(X_REAL_IP.clone(), value);
    }

    let proto = protocol.as_str();
    if let Ok(value) = proto.parse::<http::HeaderValue>() {
        forward_headers.insert(X_FORWARDED_PROTO.clone(), value);
    }

    for override_hdr in &config.set {
        if let (Ok(name), Ok(value)) = (
            HeaderName::from_bytes(override_hdr.name.as_bytes()),
            override_hdr.value.parse(),
        ) {
            forward_headers.insert(name, value);
        }
    }

    forward_headers
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sanitize_normal_path_unchanged() {
        assert_eq!(sanitize_request_path("/api/v1/users"), "/api/v1/users");
    }

    #[test]
    fn sanitize_root_path() {
        assert_eq!(sanitize_request_path("/"), "/");
    }

    #[test]
    fn sanitize_decodes_percent_encoding() {
        assert_eq!(sanitize_request_path("/foo%20bar"), "/foo bar");
        assert_eq!(sanitize_request_path("/a%2Fb"), "/a/b");
        assert_eq!(sanitize_request_path("/%7Euser"), "/~user");
    }

    #[test]
    fn sanitize_strips_null_bytes() {
        assert_eq!(sanitize_request_path("/foo%00bar"), "/foobar");
    }

    #[test]
    fn sanitize_strips_control_chars() {
        assert_eq!(sanitize_request_path("/foo\x01bar"), "/foobar");
        assert_eq!(sanitize_request_path("/foo\x1fbar"), "/foobar");
    }

    #[test]
    fn sanitize_collapses_duplicate_slashes() {
        assert_eq!(sanitize_request_path("/foo//bar"), "/foo/bar");
        assert_eq!(sanitize_request_path("/foo///bar"), "/foo/bar");
    }

    #[test]
    fn sanitize_collapses_dot_segments() {
        assert_eq!(sanitize_request_path("/foo/./bar"), "/foo/bar");
    }

    #[test]
    fn sanitize_preserves_valid_encoding() {
        assert_eq!(sanitize_request_path("/a%20b%20c"), "/a b c");
    }

    #[test]
    fn sanitize_malformed_percent_passes_through() {
        let result = sanitize_request_path("/foo%2");
        assert!(result.contains('%'));
    }

    #[test]
    fn filter_strips_hop_by_hop_headers() {
        let mut headers = http::HeaderMap::new();
        headers.insert("connection", "keep-alive".parse().unwrap());
        headers.insert("keep-alive", "timeout=5".parse().unwrap());
        headers.insert("transfer-encoding", "chunked".parse().unwrap());
        headers.insert("content-type", "text/html".parse().unwrap());

        let filtered = filter_response_headers(&headers, &AHashSet::new());
        let names: Vec<&str> = filtered.iter().map(|(k, _)| k.as_str()).collect();
        assert!(names.contains(&"content-type"));
        assert!(!names.iter().any(|n| *n == "connection"));
        assert!(!names.iter().any(|n| *n == "keep-alive"));
        assert!(!names.iter().any(|n| *n == "transfer-encoding"));
    }

    #[test]
    fn filter_strips_custom_headers() {
        let mut headers = http::HeaderMap::new();
        headers.insert("x-powered-by", "Express".parse().unwrap());
        headers.insert("server", "nginx".parse().unwrap());
        headers.insert("content-length", "1234".parse().unwrap());

        let static_filter: AHashSet<String> = STATIC_HEADERS_TO_FILTER
            .iter()
            .map(|s| s.to_string())
            .collect();
        let filtered = filter_response_headers(&headers, &static_filter);
        let names: Vec<&str> = filtered.iter().map(|(k, _)| k.as_str()).collect();
        assert!(names.contains(&"content-length"));
        assert!(!names.contains(&"x-powered-by"));
        assert!(!names.contains(&"server"));
    }

    #[test]
    fn filter_strips_site_specific_headers() {
        let mut headers = http::HeaderMap::new();
        headers.insert("x-custom", "secret".parse().unwrap());
        headers.insert("content-type", "text/plain".parse().unwrap());

        let mut filter_set = AHashSet::new();
        filter_set.insert("x-custom".to_string());

        let filtered = filter_response_headers(&headers, &filter_set);
        let names: Vec<&str> = filtered.iter().map(|(k, _)| k.as_str()).collect();
        assert!(names.contains(&"content-type"));
        assert!(!names.iter().any(|n| *n == "x-custom"));
    }

    #[test]
    fn hop_by_hop_known_headers() {
        for header in HOP_BY_HOP_HEADERS {
            assert!(
                is_hop_by_hop_header(header),
                "expected {header} to be hop-by-hop"
            );
            assert!(
                is_hop_by_hop_header(&header.to_uppercase()),
                "expected {} (uppercase) to be hop-by-hop",
                header.to_uppercase()
            );
        }
    }

    #[test]
    fn hop_by_hop_unknown_headers() {
        assert!(!is_hop_by_hop_header("content-type"));
        assert!(!is_hop_by_hop_header("content-length"));
        assert!(!is_hop_by_hop_header("x-custom"));
        assert!(!is_hop_by_hop_header("date"));
    }

    #[test]
    fn build_filter_empty_lists() {
        let filter = build_headers_to_filter(&[], &[]);
        assert!(!filter.is_empty());
        assert!(filter.contains(&http::header::HeaderName::from_static("server")));
        assert!(filter.contains(&http::header::HeaderName::from_static("x-powered-by")));
    }

    #[test]
    fn build_filter_global_headers_lowercase() {
        let filter = build_headers_to_filter(&["X-Custom-Header".to_string()], &[]);
        assert!(filter.contains(&http::header::HeaderName::from_static("x-custom-header")));
    }

    #[test]
    fn build_filter_site_headers_lowercase() {
        let filter = build_headers_to_filter(&[], &["X-Site-Secret".to_string()]);
        assert!(filter.contains(&http::header::HeaderName::from_static("x-site-secret")));
    }

    #[test]
    fn build_filter_combines_global_and_site() {
        let filter = build_headers_to_filter(&["X-Global".to_string()], &["X-Site".to_string()]);
        assert!(filter.contains(&http::header::HeaderName::from_static("x-global")));
        assert!(filter.contains(&http::header::HeaderName::from_static("x-site")));
    }

    #[test]
    fn build_filter_deduplicates() {
        let filter = build_headers_to_filter(&["x-dup".to_string()], &["x-dup".to_string()]);
        assert!(filter.contains(&http::header::HeaderName::from_static("x-dup")));
        let count = filter.iter().filter(|h| h.as_str() == "x-dup").count();
        assert_eq!(count, 1);
    }

    #[test]
    fn filter_headers_buf_returns_headers() {
        let mut headers1 = http::HeaderMap::new();
        headers1.insert("content-type", "text/html".parse().unwrap());
        headers1.insert("x-secret", "hidden".parse().unwrap());

        let mut filter_set = AHashSet::new();
        filter_set.insert("x-secret".parse().unwrap());

        let result = filter_response_headers_buf(&headers1, &filter_set);
        assert_eq!(result.len(), 1);
        assert!(result.get("content-type").is_some());

        let mut headers2 = http::HeaderMap::new();
        headers2.insert("x-custom", "value".parse().unwrap());

        let result2 = filter_response_headers_buf(&headers2, &AHashSet::new());
        assert_eq!(result2.len(), 1);
        assert!(result2.get("x-custom").is_some());
    }

    #[test]
    fn filter_headers_buf_empty_headers() {
        let result = filter_response_headers_buf(&http::HeaderMap::new(), &AHashSet::new());
        assert!(result.is_empty());
    }

    #[test]
    fn forward_headers_preserves_auth_by_default() {
        let client_ip = "192.168.1.1".parse().unwrap();
        let mut headers = http::HeaderMap::new();
        headers.insert("authorization", "Bearer token123".parse().unwrap());
        headers.insert("content-type", "application/json".parse().unwrap());
        headers.insert("accept", "application/json".parse().unwrap());
        headers.insert("cookie", "session=abc".parse().unwrap());

        let config = ProxyHeadersConfig::default();
        let result = build_forward_headers(client_ip, &headers, &config, ForwardedProtocol::Https);

        assert_eq!(result.get("authorization").unwrap(), "Bearer token123");
        assert_eq!(result.get("content-type").unwrap(), "application/json");
        assert_eq!(result.get("accept").unwrap(), "application/json");
        assert_eq!(result.get("cookie").unwrap(), "session=abc");
    }

    #[test]
    fn forward_headers_strips_hop_by_hop() {
        let client_ip = "192.168.1.1".parse().unwrap();
        let mut headers = http::HeaderMap::new();
        headers.insert("connection", "keep-alive".parse().unwrap());
        headers.insert("keep-alive", "timeout=5".parse().unwrap());
        headers.insert("transfer-encoding", "chunked".parse().unwrap());
        headers.insert("upgrade", "websocket".parse().unwrap());
        headers.insert("authorization", "Bearer token".parse().unwrap());

        let config = ProxyHeadersConfig::default();
        let result = build_forward_headers(client_ip, &headers, &config, ForwardedProtocol::Https);

        assert!(result.get("connection").is_none());
        assert!(result.get("keep-alive").is_none());
        assert!(result.get("transfer-encoding").is_none());
        assert!(result.get("upgrade").is_none());
        assert_eq!(result.get("authorization").unwrap(), "Bearer token");
    }

    #[test]
    fn forward_headers_sanitizes_xff() {
        let client_ip = "192.168.1.1".parse().unwrap();
        let mut headers = http::HeaderMap::new();
        headers.insert("x-forwarded-for", "10.0.0.1, 10.0.0.2".parse().unwrap());

        let config = ProxyHeadersConfig::default();
        let result = build_forward_headers(client_ip, &headers, &config, ForwardedProtocol::Https);

        let xff = result.get("x-forwarded-for").unwrap().to_str().unwrap();
        assert!(xff.contains("192.168.1.1"));
    }

    #[test]
    fn forward_headers_uses_explicit_forward_list() {
        let client_ip = "192.168.1.1".parse().unwrap();
        let mut headers = http::HeaderMap::new();
        headers.insert("authorization", "Bearer token".parse().unwrap());
        headers.insert("content-type", "application/json".parse().unwrap());
        headers.insert("x-custom", "value".parse().unwrap());

        let mut config = ProxyHeadersConfig::default();
        config.forward = vec!["content-type".to_string()];

        let result = build_forward_headers(client_ip, &headers, &config, ForwardedProtocol::Https);

        assert!(result.get("authorization").is_none());
        assert_eq!(result.get("content-type").unwrap(), "application/json");
        assert!(result.get("x-custom").is_none());
    }

    #[test]
    fn forward_headers_clear_removes_headers() {
        let client_ip = "192.168.1.1".parse().unwrap();
        let mut headers = http::HeaderMap::new();
        headers.insert("authorization", "Bearer token".parse().unwrap());
        headers.insert("x-custom", "value".parse().unwrap());

        let mut config = ProxyHeadersConfig::default();
        config.clear = vec!["x-custom".to_string()];

        let result = build_forward_headers(client_ip, &headers, &config, ForwardedProtocol::Https);

        assert_eq!(result.get("authorization").unwrap(), "Bearer token");
        assert!(result.get("x-custom").is_none());
    }

    #[test]
    fn forward_headers_hide_removes_headers() {
        let client_ip = "192.168.1.1".parse().unwrap();
        let mut headers = http::HeaderMap::new();
        headers.insert("authorization", "Bearer token".parse().unwrap());
        headers.insert("x-sensitive", "secret".parse().unwrap());

        let mut config = ProxyHeadersConfig::default();
        config.hide = vec!["x-sensitive".to_string()];

        let result = build_forward_headers(client_ip, &headers, &config, ForwardedProtocol::Https);

        assert_eq!(result.get("authorization").unwrap(), "Bearer token");
        assert!(result.get("x-sensitive").is_none());
    }

    #[test]
    fn forward_headers_sets_http_proto_for_plain_http() {
        let client_ip = "192.168.1.1".parse().unwrap();
        let headers = http::HeaderMap::new();
        let config = ProxyHeadersConfig::default();

        let result = build_forward_headers(client_ip, &headers, &config, ForwardedProtocol::Http);

        assert_eq!(result.get("x-forwarded-proto").unwrap(), "http");
    }

    #[test]
    fn forward_headers_sets_https_proto_for_https() {
        let client_ip = "192.168.1.1".parse().unwrap();
        let headers = http::HeaderMap::new();
        let config = ProxyHeadersConfig::default();

        let result = build_forward_headers(client_ip, &headers, &config, ForwardedProtocol::Https);

        assert_eq!(result.get("x-forwarded-proto").unwrap(), "https");
    }

    #[test]
    fn forward_headers_http3_uses_https() {
        let client_ip = "192.168.1.1".parse().unwrap();
        let headers = http::HeaderMap::new();
        let config = ProxyHeadersConfig::default();

        let result = build_forward_headers(client_ip, &headers, &config, ForwardedProtocol::Https);

        assert_eq!(result.get("x-forwarded-proto").unwrap(), "https");
    }
}
