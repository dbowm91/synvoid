//! Header handling for proxy requests and responses.

use http::header::HeaderName;
use std::net::IpAddr;
use std::sync::LazyLock;
use unicode_normalization::UnicodeNormalization;

use crate::config::site::ProxyHeadersConfig;
use ahash::AHashSet;

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
];

pub const MAX_XFF_CHAIN_LENGTH: usize = 10;

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

fn is_valid_ip(s: &str) -> bool {
    s.parse::<IpAddr>().is_ok()
}

pub fn validate_and_truncate_xff(existing: &str, client_ip: &str) -> String {
    let mut entries: Vec<&str> = existing.split(',').map(|s| s.trim()).collect();
    entries.retain(|e| !e.is_empty() && is_valid_ip(e));
    if entries.len() >= MAX_XFF_CHAIN_LENGTH {
        entries = entries.split_off(entries.len() - MAX_XFF_CHAIN_LENGTH + 1);
    }
    if entries.is_empty() {
        client_ip.to_string()
    } else {
        format!("{}, {}", entries.join(", "), client_ip)
    }
}

pub fn build_headers_to_filter(
    global_headers: &[String],
    site_headers: &[String],
) -> AHashSet<String> {
    let static_headers: AHashSet<String> = STATIC_HEADERS_TO_FILTER
        .iter()
        .map(|s| s.to_string())
        .collect();

    if global_headers.is_empty() && site_headers.is_empty() {
        return static_headers;
    }

    let mut to_filter = static_headers;

    for header in global_headers {
        let lower = header.to_lowercase();
        to_filter.insert(lower);
    }

    for header in site_headers {
        let lower = header.to_lowercase();
        to_filter.insert(lower);
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
        if segment.len() == 2 && segment.iter().all(|&b| b == b'.') {
            if let Some(pos) = result.iter().rposition(|&b| b == b'/') {
                let before_slash = result[..pos]
                    .iter()
                    .rposition(|&b| b == b'/')
                    .map(|p| p + 1)
                    .unwrap_or(0);
                result.drain(before_slash..);
            }
        } else if !segment.is_empty() {
            if !result.is_empty() && result.last() != Some(&b'/') {
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
    headers_to_filter: &AHashSet<String>,
    buf: &mut Vec<(String, String)>,
) {
    buf.clear();
    for (k, v) in headers.iter() {
        let name_str = k.as_str();
        if HOP_BY_HOP_HEADERS_SET.contains(name_str) || headers_to_filter.contains(name_str) {
            continue;
        }
        if let Ok(vv) = v.to_str() {
            buf.push((k.to_string(), vv.to_string()));
        }
    }
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

pub fn build_forward_headers(
    client_ip: std::net::IpAddr,
    original_headers: &http::HeaderMap,
    config: &ProxyHeadersConfig,
    is_tls: bool,
) -> Vec<(String, String)> {
    let mut forward_headers = Vec::with_capacity(8);

    let headers_to_forward: Vec<&str> = if config.forward.is_empty() {
        vec!["X-Real-IP", "X-Forwarded-For", "X-Forwarded-Proto", "Host"]
    } else {
        config.forward.iter().map(|s| s.as_str()).collect()
    };

    for header_name in headers_to_forward {
        match header_name {
            "X-Real-IP" => {
                forward_headers.push(("X-Real-IP".to_string(), client_ip.to_string()));
            }
            "X-Forwarded-For" => {
                let existing = original_headers
                    .get("x-forwarded-for")
                    .and_then(|v| v.to_str().ok())
                    .unwrap_or("");
                let new_value = validate_and_truncate_xff(existing, &client_ip.to_string());
                forward_headers.push(("X-Forwarded-For".to_string(), new_value));
            }
            "X-Forwarded-Proto" => {
                let proto = if is_tls { "https" } else { "http" };
                forward_headers.push(("X-Forwarded-Proto".to_string(), proto.to_string()));
            }
            "X-Forwarded-Host" => {
                if let Some(host) = original_headers.get("host") {
                    if let Ok(host_str) = host.to_str() {
                        forward_headers
                            .push(("X-Forwarded-Host".to_string(), host_str.to_string()));
                    }
                }
            }
            "Host" | "host" => {
                if let Some(host) = original_headers.get("host") {
                    if let Ok(host_str) = host.to_str() {
                        forward_headers.push(("Host".to_string(), host_str.to_string()));
                    }
                }
            }
            _ => {
                if let Some(value) = original_headers.get(header_name) {
                    if let Ok(value_str) = value.to_str() {
                        forward_headers.push((header_name.to_string(), value_str.to_string()));
                    }
                }
            }
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
        assert!(filter.contains("server"));
        assert!(filter.contains("x-powered-by"));
    }

    #[test]
    fn build_filter_global_headers_lowercase() {
        let filter = build_headers_to_filter(&["X-Custom-Header".to_string()], &[]);
        assert!(filter.contains("x-custom-header"));
    }

    #[test]
    fn build_filter_site_headers_lowercase() {
        let filter = build_headers_to_filter(&[], &["X-Site-Secret".to_string()]);
        assert!(filter.contains("x-site-secret"));
    }

    #[test]
    fn build_filter_combines_global_and_site() {
        let filter = build_headers_to_filter(&["X-Global".to_string()], &["X-Site".to_string()]);
        assert!(filter.contains("x-global"));
        assert!(filter.contains("x-site"));
    }

    #[test]
    fn build_filter_deduplicates() {
        let filter = build_headers_to_filter(&["x-dup".to_string()], &["x-dup".to_string()]);
        assert!(filter.contains("x-dup"));
        let count = filter.iter().filter(|h| *h == "x-dup").count();
        assert_eq!(count, 1);
    }

    #[test]
    fn filter_headers_buf_reuses_buffer() {
        let mut buf = Vec::new();

        let mut headers1 = http::HeaderMap::new();
        headers1.insert("content-type", "text/html".parse().unwrap());
        headers1.insert("x-secret", "hidden".parse().unwrap());

        let mut filter_set = AHashSet::new();
        filter_set.insert("x-secret".to_string());

        filter_response_headers_buf(&headers1, &filter_set, &mut buf);
        assert_eq!(buf.len(), 1);
        assert_eq!(buf[0].0, "content-type");

        let mut headers2 = http::HeaderMap::new();
        headers2.insert("x-custom", "value".parse().unwrap());

        filter_response_headers_buf(&headers2, &AHashSet::new(), &mut buf);
        assert_eq!(buf.len(), 1);
        assert_eq!(buf[0].0, "x-custom");
    }

    #[test]
    fn filter_headers_buf_empty_headers() {
        let mut buf = Vec::new();
        filter_response_headers_buf(&http::HeaderMap::new(), &AHashSet::new(), &mut buf);
        assert!(buf.is_empty());
    }
}
