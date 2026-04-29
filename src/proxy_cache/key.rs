use ahash::AHasher;
use http::{HeaderMap, Method, Uri};

#[derive(Clone, Debug, Hash, PartialEq, Eq)]
pub struct CacheKey {
    pub scheme: String,
    pub method: String,
    pub host: String,
    pub uri: String,
    pub vary: String,
    pub site_id: String,
}

impl CacheKey {
    pub fn new(
        scheme: &str,
        method: &Method,
        host: &str,
        uri: &Uri,
        headers: &HeaderMap,
        key_pattern: &str,
        vary_by: &[String],
        site_id: &str,
    ) -> Self {
        let uri_str = uri
            .path_and_query()
            .map(|pq| pq.to_string())
            .unwrap_or_else(|| uri.path().to_string());

        let vary = Self::build_vary_key(headers, vary_by);

        let key = Self::replace_pattern_single_pass(
            key_pattern,
            &[
                ("$scheme", scheme),
                ("$request_method", method.as_str()),
                ("$host", host),
                ("$request_uri", &uri_str),
                ("$site_id", site_id),
            ],
        );

        let mut hasher = AHasher::default();
        std::hash::Hash::hash(&key, &mut hasher);
        std::hash::Hash::hash(&vary, &mut hasher);
        let hash = std::hash::Hasher::finish(&hasher);

        Self {
            scheme: scheme.to_string(),
            method: method.as_str().to_string(),
            host: host.to_string(),
            uri: format!("{}:{}", hash, uri_str),
            vary,
            site_id: site_id.to_string(),
        }
    }

    fn replace_pattern_single_pass<'a>(
        pattern: &'a str,
        replacements: &[(&str, &'a str)],
    ) -> String {
        let mut result = String::with_capacity(pattern.len());
        let bytes = pattern.as_bytes();
        let mut i = 0;

        while i < bytes.len() {
            let remaining = &bytes[i..];
            let mut matched_placeholder: Option<(&str, &str)> = None;

            for &(placeholder, replacement) in replacements {
                if remaining.starts_with(placeholder.as_bytes()) {
                    matched_placeholder = Some((placeholder, replacement));
                    break;
                }
            }

            if let Some((placeholder, replacement)) = matched_placeholder {
                result.push_str(replacement);
                i += placeholder.len();
            } else {
                result.push(bytes[i] as char);
                i += 1;
            }
        }

        result
    }

    fn build_vary_key(headers: &HeaderMap, vary_by: &[String]) -> String {
        if vary_by.is_empty() {
            return String::new();
        }

        let mut parts = Vec::new();
        for header_name in vary_by {
            if let Some(value) = headers.get(header_name.as_str()) {
                if let Ok(v) = value.to_str() {
                    parts.push(format!("{}:{}", header_name, v));
                }
            }
        }
        parts.join("|")
    }

    pub fn to_cache_string(&self) -> String {
        format!(
            "{}:{}:{}:{}:{}",
            self.scheme, self.method, self.host, self.uri, self.site_id
        )
    }

    pub fn from_cache_string(s: &str) -> Option<Self> {
        let mut parts = s.splitn(5, ':');
        Some(Self {
            scheme: parts.next()?.to_string(),
            method: parts.next()?.to_string(),
            host: parts.next()?.to_string(),
            uri: parts.next()?.to_string(),
            site_id: parts.next()?.to_string(),
            vary: String::new(),
        })
    }
}

#[derive(Clone)]
pub struct CacheKeyBuilder {
    pattern: String,
    vary_by: Vec<String>,
}

impl CacheKeyBuilder {
    pub fn new(pattern: String, vary_by: Vec<String>) -> Self {
        Self { pattern, vary_by }
    }

    pub fn build(
        &self,
        scheme: &str,
        method: &Method,
        host: &str,
        uri: &Uri,
        headers: &HeaderMap,
        site_id: &str,
    ) -> CacheKey {
        CacheKey::new(
            scheme,
            method,
            host,
            uri,
            headers,
            &self.pattern,
            &self.vary_by,
            site_id,
        )
    }
}
