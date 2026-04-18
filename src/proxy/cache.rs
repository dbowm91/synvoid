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
        builder = builder.header(name, value);
    }

    let mut cache_directive = if entry.is_fresh {
        "public".to_string()
    } else {
        "public, stale-while-revalidate".to_string()
    };

    if let Some(expires_at) = entry.expires_at {
        let max_age = expires_at.saturating_duration_since(std::time::Instant::now());
        if max_age.as_secs() > 0 {
            cache_directive.push_str(&format!(", max-age={}", max_age.as_secs()));
        }
    }

    if let Some(swr) = entry.stale_while_revalidate {
        let swr_age = swr.saturating_duration_since(std::time::Instant::now());
        if swr_age.as_secs() > 0 {
            cache_directive
                .push_str(&format!(", stale-while-revalidate={}", swr_age.as_secs()));
        }
    }

    if let Some(sie) = entry.stale_if_error {
        let sie_age = sie.saturating_duration_since(std::time::Instant::now());
        if sie_age.as_secs() > 0 {
            cache_directive.push_str(&format!(", stale-if-error={}", sie_age.as_secs()));
        }
    }

    builder = builder.header("Cache-Control", cache_directive);

    if entry.is_fresh {
        builder = builder.header("X-Cache", "HIT");
    } else {
        builder = builder.header("X-Cache", "STALE");
    }

    builder
        .body(entry.content.clone())
        .unwrap_or_else(|_| crate::http::fallback_error_bytes())
}

pub(super) fn filter_sensitive_headers(headers: &http::HeaderMap) -> http::HeaderMap {
    const SENSITIVE_HEADERS: &[&str] = &[
        "set-cookie",
        "authorization",
        "www-authenticate",
        "proxy-authenticate",
        "proxy-authorization",
        "cookie",
        "x-api-key",
        "x-auth-token",
    ];

    let mut filtered = http::HeaderMap::new();
    for (name, value) in headers.iter() {
        let name_str = name.as_str();
        if !SENSITIVE_HEADERS.contains(&name_str) {
            filtered.insert(name, value.clone());
        }
    }
    filtered
}
