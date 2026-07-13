//! Proxy caching logic.

use std::time::Duration;

use synvoid_proxy_cache::ProxyCacheEntry;

/// Return whether a Cache-Control header contains a directive, matching the
/// directive name case-insensitively and ignoring an optional value.
pub fn has_cache_control_directive(headers: &http::HeaderMap, directive: &str) -> bool {
    headers
        .get_all(http::header::CACHE_CONTROL)
        .iter()
        .any(|value| {
            value.to_str().ok().is_some_and(|value| {
                value.split(',').any(|part| {
                    let name = part.split_once('=').map_or(part, |(name, _)| name);
                    name.trim().eq_ignore_ascii_case(directive)
                })
            })
        })
}

/// Shared-cache request guard. Cookies and authorization headers are
/// deliberately bypassed because the cache key does not include their full
/// values. This prevents an authenticated or personalized response from
/// being served to another client.
pub fn should_bypass_shared_cache(headers: &http::HeaderMap) -> bool {
    headers.contains_key(http::header::AUTHORIZATION)
        || headers.contains_key(http::header::PROXY_AUTHORIZATION)
        || headers.contains_key(http::header::COOKIE)
        || has_cache_control_directive(headers, "no-cache")
        || has_cache_control_directive(headers, "no-store")
        || has_cache_control_directive(headers, "private")
}

/// Response-side shared-cache safety checks. `Vary: *` and unsupported Vary
/// fields cannot be represented by the configured cache key, and `Set-Cookie`
/// responses are private by definition for this shared cache.
pub fn is_safe_for_shared_cache(headers: &http::HeaderMap, vary_by: &[String]) -> bool {
    if headers.contains_key(http::header::SET_COOKIE)
        || has_cache_control_directive(headers, "no-store")
        || has_cache_control_directive(headers, "private")
    {
        return false;
    }

    headers.get_all(http::header::VARY).iter().all(|value| {
        let Ok(vary) = value.to_str() else {
            return false;
        };
        vary.split(',').all(|field| {
            let field = field.trim();
            field != "*"
                && vary_by
                    .iter()
                    .any(|configured| configured.eq_ignore_ascii_case(field))
        })
    })
}

pub fn get_cache_max_age_static(headers: &http::HeaderMap) -> Option<Duration> {
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

fn fallback_error_bytes() -> bytes::Bytes {
    bytes::Bytes::from("Internal Server Error")
}

pub fn build_cached_response(entry: &ProxyCacheEntry) -> http::Response<bytes::Bytes> {
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

    builder.body(entry.content.clone()).unwrap_or_else(|_| {
        http::Response::builder()
            .status(500)
            .body(fallback_error_bytes())
            .unwrap()
    })
}

pub fn filter_cacheable_headers(
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
        let is_safe = SAFE_HEADERS
            .iter()
            .any(|&h| h.eq_ignore_ascii_case(name_str));
        let is_custom_allowed = allowed_custom_headers
            .iter()
            .any(|h| h.eq_ignore_ascii_case(name_str));

        if is_safe || is_custom_allowed {
            filtered.insert(name, value.clone());
        }
    }
    filtered
}

#[inline]
pub fn join_upstream_url(upstream: impl AsRef<str>, path: impl AsRef<str>) -> String {
    let upstream = upstream.as_ref().trim_end_matches('/');
    let path = path.as_ref();
    if path.starts_with('/') {
        format!("{}{}", upstream, path)
    } else {
        format!("{}/{}", upstream, path)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shared_cache_bypasses_credentials_and_cookies() {
        let mut headers = http::HeaderMap::new();
        headers.insert(
            http::header::AUTHORIZATION,
            "Bearer secret".parse().unwrap(),
        );
        assert!(should_bypass_shared_cache(&headers));

        headers.remove(http::header::AUTHORIZATION);
        headers.insert(http::header::COOKIE, "session=secret".parse().unwrap());
        assert!(should_bypass_shared_cache(&headers));
    }

    #[test]
    fn shared_cache_rejects_private_and_unrepresented_vary_responses() {
        let mut headers = http::HeaderMap::new();
        headers.insert(http::header::SET_COOKIE, "session=secret".parse().unwrap());
        assert!(!is_safe_for_shared_cache(&headers, &[]));

        headers.remove(http::header::SET_COOKIE);
        headers.insert(http::header::VARY, "User-Agent".parse().unwrap());
        assert!(!is_safe_for_shared_cache(&headers, &[]));
        assert!(is_safe_for_shared_cache(
            &headers,
            &["user-agent".to_string()]
        ));
    }

    #[test]
    fn cache_control_directives_are_case_insensitive_and_tokenized() {
        let mut headers = http::HeaderMap::new();
        headers.insert(
            http::header::CACHE_CONTROL,
            "max-age=60, No-StOrE".parse().unwrap(),
        );
        assert!(has_cache_control_directive(&headers, "no-store"));
        assert!(!has_cache_control_directive(&headers, "no-store-extra"));
    }

    #[test]
    fn shared_cache_checks_duplicate_control_headers() {
        let mut request_headers = http::HeaderMap::new();
        request_headers.append(http::header::CACHE_CONTROL, "max-age=60".parse().unwrap());
        request_headers.append(http::header::CACHE_CONTROL, "no-store".parse().unwrap());
        assert!(should_bypass_shared_cache(&request_headers));

        let mut response_headers = http::HeaderMap::new();
        response_headers.append(http::header::VARY, "Accept-Encoding".parse().unwrap());
        response_headers.append(http::header::VARY, "*".parse().unwrap());
        assert!(!is_safe_for_shared_cache(
            &response_headers,
            &["accept-encoding".to_string()]
        ));
    }
}
