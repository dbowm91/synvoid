//! Proxy caching logic.

use std::time::Duration;

use crate::proxy_cache::ProxyCacheEntry;

pub(super) fn get_cache_max_age_static(headers: &http::HeaderMap) -> Option<Duration> {
    if let Some(cc) = headers.get("cache-control") {
        if let Ok(cc_str) = cc.to_str() {
            let mut max_age: Option<u64> = None;
            let mut s_maxage: Option<u64> = None;
            let mut no_cache = false;

            for part in cc_str.split(',') {
                let part = part.trim().to_ascii_lowercase();
                if let Some(val) = part.strip_prefix("s-maxage=") {
                    if let Ok(age) = val.trim_matches('"').parse::<u64>() {
                        s_maxage = Some(age);
                    }
                } else if let Some(val) = part.strip_prefix("max-age=") {
                    if let Ok(age) = val.trim_matches('"').parse::<u64>() {
                        max_age = Some(age);
                    }
                } else if part == "no-cache" || part.starts_with("no-cache=") {
                    no_cache = true;
                }
            }

            if no_cache {
                return Some(Duration::from_secs(0));
            }

            if let Some(age) = s_maxage {
                return Some(Duration::from_secs(age));
            }
            if let Some(age) = max_age {
                return Some(Duration::from_secs(age));
            }
        }
    }
    None
}

pub(super) fn build_cached_response(entry: &ProxyCacheEntry) -> http::Response<bytes::Bytes> {
    let mut builder = http::Response::builder().status(entry.status);

    for (name, value) in entry.headers.iter() {
        if name != http::header::CACHE_CONTROL {
            builder = builder.header(name, value);
        }
    }

    // Preserve original Cache-Control if present, otherwise default to public
    let mut cache_directive = entry
        .headers
        .get(http::header::CACHE_CONTROL)
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string())
        .unwrap_or_else(|| {
            if entry.is_fresh {
                "public".to_string()
            } else {
                "public, stale-while-revalidate".to_string()
            }
        });

    // If stale, ensure stale-while-revalidate is present if not already
    if !entry.is_fresh && !cache_directive.contains("stale-while-revalidate") {
        if !cache_directive.is_empty() {
            cache_directive.push_str(", ");
        }
        cache_directive.push_str("stale-while-revalidate");
    }

    builder = builder.header("Cache-Control", cache_directive);

    // Add Age header representing seconds since the response was generated at origin
    let age = entry.created_at.elapsed().as_secs();
    builder = builder.header("Age", age.to_string());

    if entry.is_fresh {
        builder = builder.header("X-Cache", "HIT");
    } else {
        builder = builder.header("X-Cache", "STALE");
    }

    builder
        .body(entry.content.clone())
        .unwrap_or_else(|_| crate::http::fallback_error_bytes())
}

pub(super) fn filter_cacheable_headers(
    headers: &http::HeaderMap,
    allowed_custom_headers: &[String],
) -> http::HeaderMap {
    // Strict whitelist of safe headers that are generally okay to cache
    const SAFE_HEADERS: &[&str] = &[
        "cache-control",
        "content-type",
        "content-language",
        "content-encoding",
        "content-length",
        "content-location",
        "content-range",
        "etag",
        "last-modified",
        "vary",
        "expires",
        "age",
        "x-cache",
        "x-cache-hit",
        "x-frame-options",
        "x-content-type-options",
        "x-xss-protection",
        "strict-transport-security",
        "content-security-policy",
        "content-security-policy-report-only",
        "access-control-allow-origin",
        "access-control-allow-methods",
        "access-control-allow-headers",
        "access-control-expose-headers",
        "access-control-max-age",
        "access-control-allow-credentials",
        "timing-allow-origin",
        "link",
    ];

    let mut filtered = http::HeaderMap::new();
    for (name, value) in headers.iter() {
        let name_str = name.as_str();
        let is_safe = SAFE_HEADERS.iter().any(|&h| h.eq_ignore_ascii_case(name_str));
        let is_custom_allowed = allowed_custom_headers
            .iter()
            .any(|h| h.eq_ignore_ascii_case(name_str));

        if is_safe || is_custom_allowed {
            filtered.insert(name, value.clone());
        }
    }
    filtered
}
