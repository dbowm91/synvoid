use crate::attack_detection::config::{
    AttackDetectionConfig, AttackDetectionResult, AttackType, HeaderScanConfig, InputLocation,
};
use crate::attack_detection::normalizer::InputNormalizer;
use aho_corasick::AhoCorasick;
use std::sync::Arc;
use synvoid_core::url::urlencoding_decode_result;

#[macro_export]
macro_rules! pattern_detector {
    (
        $(#[$attr:meta])*
        $name:ident,
        $attack_type:expr,
        $attack_name:literal,
        $patterns_fn:path,
        $high_patterns_fn:path
    ) => {
        $(#[$attr])*
        pub struct $name {
            inner: $crate::attack_detection::detector_common::BasePatternDetector,
        }

        impl $name {
            pub fn new(paranoia_level: u8, custom_patterns: &[String]) -> Self {
                let inner = $crate::attack_detection::detector_common::BasePatternDetector::new(
                    $patterns_fn().as_slice(),
                    $high_patterns_fn().as_slice(),
                    custom_patterns,
                    paranoia_level,
                    $attack_type,
                    $attack_name,
                );
                Self { inner }
            }

            pub fn detect(&self, input: &str, location: InputLocation) -> Option<AttackDetectionResult> {
                self.inner.detect_internal(input, location)
            }
        }

        impl $crate::attack_detection::detector_common::PatternDetector for $name {
            fn patterns(&self) -> &Arc<AhoCorasick> {
                self.inner.patterns()
            }

            fn attack_type(&self) -> $crate::attack_detection::config::AttackType {
                $attack_type
            }

            fn detect(&self, input: &str, location: InputLocation) -> Option<AttackDetectionResult> {
                self.inner.detect_internal(input, location)
            }
        }
    };
}

#[macro_export]
macro_rules! url_decode_detector {
    (
        $(#[$attr:meta])*
        $name:ident,
        $attack_type:expr,
        $attack_name:literal,
        $patterns_fn:path,
        $high_patterns_fn:path
    ) => {
        $(#[$attr])*
        pub struct $name {
            inner: $crate::attack_detection::detector_common::BasePatternDetector,
        }

        impl $name {
            pub fn new(paranoia_level: u8, custom_patterns: &[String]) -> Self {
                let inner = $crate::attack_detection::detector_common::BasePatternDetector::new(
                    $patterns_fn().as_slice(),
                    $high_patterns_fn().as_slice(),
                    custom_patterns,
                    paranoia_level,
                    $attack_type,
                    $attack_name,
                );
                Self { inner }
            }

            fn detect_with_url_decode(&self, input: &str, location: InputLocation) -> Option<AttackDetectionResult> {
                use std::borrow::Cow;
                use synvoid_core::url::url_decode_all;

                let decoded: Cow<str> = if input.contains('%') || input.contains('+') {
                    Cow::Owned(url_decode_all(input))
                } else {
                    Cow::Borrowed(input)
                };

                if let Some(mat) = self.inner.patterns_ref().find(decoded.as_ref()) {
                    let matched = decoded[mat.start()..mat.end()].to_string();
                    tracing::warn!(
                        attack_type = $attack_name,
                        matched_pattern = %matched,
                        location = %location,
                        "{} detected", $attack_name
                    );
                    return Some(AttackDetectionResult {
                        attack_type: $attack_type,
                        fingerprint: None,
                        matched_pattern: Some(matched),
                        input_location: location,
                    });
                }

                if decoded != input {
                    if let Some(mat) = self.inner.patterns_ref().find(input) {
                        let matched = input[mat.start()..mat.end()].to_string();
                        tracing::warn!(
                            attack_type = $attack_name,
                            matched_pattern = %matched,
                            location = %location,
                            "{} detected (encoded)", $attack_name
                        );
                        return Some(AttackDetectionResult {
                            attack_type: $attack_type,
                            fingerprint: None,
                            matched_pattern: Some(matched),
                            input_location: location,
                        });
                    }
                }

                None
            }

            pub fn detect(&self, input: &str, location: InputLocation) -> Option<AttackDetectionResult> {
                self.detect_with_url_decode(input, location)
            }
        }

        impl $crate::attack_detection::detector_common::PatternDetector for $name {
            fn patterns(&self) -> &Arc<AhoCorasick> {
                self.inner.patterns()
            }

            fn attack_type(&self) -> $crate::attack_detection::config::AttackType {
                $attack_type
            }

            fn detect(&self, input: &str, location: InputLocation) -> Option<AttackDetectionResult> {
                self.detect_with_url_decode(input, location)
            }
        }
    };
}

const SECURITY_HEADERS: &[&str] = &[
    "cookie",
    "x-forwarded-for",
    "x-real-ip",
    "x-original-url",
    "x-rewrite-url",
    "x-host",
    "x-forwarded-proto",
    "referer",
    "origin",
    "authorization",
    "proxy-authorization",
];

/// `Referer`/`Origin` legitimately carry absolute same-site URLs. Detectors
/// skip their bare-URL heuristics there while keeping anchored/smuggled
/// pattern matching active.
pub(crate) fn is_referer_or_origin(location: &InputLocation) -> bool {
    location
        .header_name()
        .is_some_and(|n| n.eq_ignore_ascii_case("referer") || n.eq_ignore_ascii_case("origin"))
}

/// The `Host` header names the server the client already reached (and the
/// site router already matched); it is not a server-side fetch target, so
/// it carries no SSRF signal. IP-literal hosting would otherwise flag every
/// request.
pub(crate) fn is_host(location: &InputLocation) -> bool {
    location
        .header_name()
        .is_some_and(|n| n.eq_ignore_ascii_case("host"))
}

/// How a request header participates in payload (SQLi/XSS/etc.) detection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HeaderScanClass {
    /// Not a payload sink; skip value detectors.
    Skip,
    /// URL-bearing header (`Referer`, `Origin`); existing URL-aware detector
    /// exemptions still apply.
    Url,
    /// User-controlled value (`Cookie`, configured custom headers).
    UserValue,
    /// Credential (`Authorization`); handled by the JWT detector instead.
    Credential,
    /// Automated-client identification (`User-Agent`); handled by bot policy.
    UserAgent,
}

/// Central header scan policy.
///
/// The default is deliberately narrow: only `Cookie`, `Referer`, `Origin` and
/// explicitly configured custom headers are payload scanned. Content
/// negotiation, browser metadata, framing, cache validators and proxy
/// metadata are skipped. `HeaderValidator` is structural and still validates
/// every header independently of this policy.
#[derive(Debug, Clone, Default)]
pub struct HeaderScanPolicy {
    custom_scan: Vec<String>,
    custom_skip: Vec<String>,
}

impl HeaderScanPolicy {
    pub fn new(scan: &[String], skip: &[String]) -> Self {
        Self {
            custom_scan: normalize_header_names(scan),
            custom_skip: normalize_header_names(skip),
        }
    }

    pub fn from_config(config: &AttackDetectionConfig) -> Self {
        let HeaderScanConfig { scan, skip } = &config.header_scan;
        Self::new(scan, skip)
    }

    pub fn classify(&self, name: &str) -> HeaderScanClass {
        if contains_header(&self.custom_skip, name) {
            return HeaderScanClass::Skip;
        }
        if contains_header(&self.custom_scan, name) {
            return HeaderScanClass::UserValue;
        }
        if name.eq_ignore_ascii_case("cookie") {
            return HeaderScanClass::UserValue;
        }
        if name.eq_ignore_ascii_case("referer") || name.eq_ignore_ascii_case("origin") {
            return HeaderScanClass::Url;
        }
        if name.eq_ignore_ascii_case("authorization")
            || name.eq_ignore_ascii_case("proxy-authorization")
        {
            return HeaderScanClass::Credential;
        }
        if name.eq_ignore_ascii_case("user-agent") {
            return HeaderScanClass::UserAgent;
        }
        HeaderScanClass::Skip
    }

    /// Whether value detectors should run on this header at all.
    pub fn allows_payload_scan(&self, name: &str) -> bool {
        matches!(
            self.classify(name),
            HeaderScanClass::Url | HeaderScanClass::UserValue
        )
    }
}

fn normalize_header_names(names: &[String]) -> Vec<String> {
    names
        .iter()
        .map(|name| name.trim().to_ascii_lowercase())
        .filter(|name| !name.is_empty())
        .collect()
}

fn contains_header(names: &[String], name: &str) -> bool {
    names
        .iter()
        .any(|candidate| candidate.eq_ignore_ascii_case(name))
}

pub fn detect_in_headers<F>(
    headers: &http::HeaderMap,
    mut check_header: F,
    normalizer: Option<&InputNormalizer>,
    mut detect: impl FnMut(&[u8], InputLocation) -> Option<AttackDetectionResult>,
) -> Option<AttackDetectionResult>
where
    F: FnMut(&str) -> bool,
{
    let policy = HeaderScanPolicy::default();
    for header_name in SECURITY_HEADERS {
        if !policy.allows_payload_scan(header_name) || !check_header(header_name) {
            continue;
        }

        if let Some(value) = headers.get(*header_name) {
            if let Ok(value_str) = value.to_str() {
                let input = value_str.as_bytes();
                let location = InputLocation::Header((*header_name).into());

                if let Some(result) = detect(input, location.clone()) {
                    return Some(result);
                }

                if let Some(norm) = normalizer {
                    let normalized = norm.normalize(value_str);
                    if normalized.as_str() != value_str {
                        if let Some(result) = detect(normalized.as_bytes(), location) {
                            return Some(result);
                        }
                    }
                }
            }
        }
    }

    None
}

pub trait PatternDetector: Send + Sync {
    fn patterns(&self) -> &Arc<AhoCorasick>;

    fn attack_type(&self) -> AttackType {
        AttackType::Other
    }

    fn detect(&self, input: &str, location: InputLocation) -> Option<AttackDetectionResult>;

    #[inline]
    fn detect_in_security_headers(
        &self,
        headers: &http::HeaderMap,
        normalizer: Option<&InputNormalizer>,
    ) -> Option<AttackDetectionResult> {
        let policy = HeaderScanPolicy::default();
        for header_name in SECURITY_HEADERS {
            if !policy.allows_payload_scan(header_name) {
                continue;
            }
            if let Some(value) = headers.get(*header_name) {
                if let Ok(value_str) = value.to_str() {
                    let location = InputLocation::Header((*header_name).into());
                    if let Some(r) = self.detect(value_str, location.clone()) {
                        return Some(r);
                    }
                    if let Some(norm) = normalizer {
                        let normalized = norm.normalize(value_str);
                        if normalized.as_str() != value_str {
                            if let Some(result) = self.detect(normalized.as_str(), location.clone())
                            {
                                return Some(result);
                            }
                        }
                    } else if let Ok(decoded) = urlencoding_decode_result(value_str) {
                        if decoded != value_str {
                            if let Some(r) = self.detect(&decoded, location) {
                                return Some(r);
                            }
                        }
                    }
                }
            }
        }
        None
    }

    #[inline]
    fn detect_in_headers<F>(
        &self,
        headers: &http::HeaderMap,
        mut check_header: F,
        normalizer: Option<&InputNormalizer>,
    ) -> Option<AttackDetectionResult>
    where
        F: FnMut(&str) -> bool,
    {
        let policy = HeaderScanPolicy::default();
        for header_name in SECURITY_HEADERS {
            if !policy.allows_payload_scan(header_name) || !check_header(header_name) {
                continue;
            }
            if let Some(value) = headers.get(*header_name) {
                if let Ok(value_str) = value.to_str() {
                    let location = InputLocation::Header((*header_name).into());
                    if let Some(r) = self.detect(value_str, location.clone()) {
                        return Some(r);
                    }
                    if let Some(norm) = normalizer {
                        let normalized = norm.normalize(value_str);
                        if normalized.as_str() != value_str {
                            if let Some(result) = self.detect(normalized.as_str(), location.clone())
                            {
                                return Some(result);
                            }
                        }
                    } else if let Ok(decoded) = urlencoding_decode_result(value_str) {
                        if decoded != value_str {
                            if let Some(r) = self.detect(&decoded, location) {
                                return Some(r);
                            }
                        }
                    }
                }
            }
        }
        None
    }

    #[inline]
    fn detect_in_all_headers(
        &self,
        headers: &http::HeaderMap,
        normalizer: Option<&InputNormalizer>,
    ) -> Option<AttackDetectionResult> {
        let policy = HeaderScanPolicy::default();
        for (header_name, header_value) in headers.iter() {
            if !policy.allows_payload_scan(header_name.as_str()) {
                continue;
            }
            if let Ok(value) = header_value.to_str() {
                let location = InputLocation::Header(header_name.as_str().into());
                if let Some(r) = self.detect(value, location.clone()) {
                    return Some(r);
                }
                if let Some(norm) = normalizer {
                    let normalized = norm.normalize(value);
                    if normalized.as_str() != value {
                        if let Some(r) = self.detect(normalized.as_str(), location) {
                            return Some(r);
                        }
                    }
                }
            }
        }
        None
    }
}

pub struct BasePatternDetector {
    patterns: Arc<AhoCorasick>,
    attack_type: AttackType,
    attack_name: &'static str,
}

impl BasePatternDetector {
    pub fn new(
        base_patterns: &[&'static str],
        high_patterns: &[&'static str],
        custom_patterns: &[String],
        paranoia_level: u8,
        attack_type: AttackType,
        attack_name: &'static str,
    ) -> Self {
        let patterns = build_pattern_automaton(
            base_patterns,
            high_patterns,
            custom_patterns,
            paranoia_level,
        );
        Self {
            patterns,
            attack_type,
            attack_name,
        }
    }

    pub fn from_automaton(
        patterns: Arc<AhoCorasick>,
        attack_type: AttackType,
        attack_name: &'static str,
    ) -> Self {
        Self {
            patterns,
            attack_type,
            attack_name,
        }
    }

    pub fn detect_internal(
        &self,
        input: &str,
        location: InputLocation,
    ) -> Option<AttackDetectionResult> {
        if let Some(mat) = self.patterns.find(input) {
            let matched = input[mat.start()..mat.end()].to_string();

            tracing::warn!(
                attack_type = self.attack_name,
                matched_pattern = %matched,
                location = %location,
                "{} detected", self.attack_name
            );

            return Some(AttackDetectionResult {
                attack_type: self.attack_type,
                fingerprint: None,
                matched_pattern: Some(matched),
                input_location: location,
            });
        }

        None
    }

    pub fn detect_internal_normalized<F, S>(
        &self,
        input: &str,
        location: InputLocation,
        normalizer: F,
    ) -> Option<AttackDetectionResult>
    where
        F: Fn(&str) -> S,
        S: AsRef<str>,
    {
        let normalized = normalizer(input);
        let normalized_ref = normalized.as_ref();

        if let Some(mat) = self.patterns.find(normalized_ref) {
            let matched = normalized_ref[mat.start()..mat.end()].to_string();

            tracing::warn!(
                attack_type = self.attack_name,
                matched_pattern = %matched,
                location = %location,
                "{} detected", self.attack_name
            );

            return Some(AttackDetectionResult {
                attack_type: self.attack_type,
                fingerprint: None,
                matched_pattern: Some(matched),
                input_location: location,
            });
        }

        None
    }

    pub fn patterns_ref(&self) -> &Arc<AhoCorasick> {
        &self.patterns
    }
}

impl PatternDetector for BasePatternDetector {
    fn patterns(&self) -> &Arc<AhoCorasick> {
        &self.patterns
    }

    fn attack_type(&self) -> AttackType {
        self.attack_type
    }

    fn detect(&self, input: &str, location: InputLocation) -> Option<AttackDetectionResult> {
        self.detect_internal(input, location)
    }
}

pub fn build_pattern_automaton(
    base_patterns: &[&'static str],
    high_patterns: &[&'static str],
    custom_patterns: &[String],
    paranoia_level: u8,
) -> Arc<AhoCorasick> {
    let mut patterns: Vec<String> = base_patterns.iter().map(|s| s.to_string()).collect();

    if paranoia_level >= 3 {
        patterns.extend(high_patterns.iter().map(|s| s.to_string()));
    }

    let mut seen: std::collections::HashSet<String> = patterns.iter().cloned().collect();
    for pattern in custom_patterns.iter().cloned() {
        if seen.insert(pattern.clone()) {
            patterns.push(pattern);
        }
    }

    let patterns_str: Vec<&str> = patterns.iter().map(|s| s.as_str()).collect();
    match AhoCorasick::builder()
        .ascii_case_insensitive(true)
        .build(&patterns_str)
    {
        Ok(ac) => Arc::new(ac),
        Err(e) => {
            tracing::error!("AhoCorasick build failed for custom patterns: {}", e);
            // Fallback to base patterns only to keep data plane alive; static patterns are trusted.
            let base_str: Vec<&str> = base_patterns.to_vec();
            Arc::new(
                AhoCorasick::builder()
                    .ascii_case_insensitive(true)
                    .build(&base_str)
                    .unwrap_or_else(|_| {
                        AhoCorasick::builder()
                            .ascii_case_insensitive(true)
                            .build(Vec::<&str>::new())
                            .expect("empty pattern set always builds")
                    }),
            )
        }
    }
}

pub fn check_inputs<D>(
    detector: &D,
    normalizer: &InputNormalizer,
    path: Option<&str>,
    query_string: Option<&str>,
    headers: &http::HeaderMap,
    body: Option<&[u8]>,
) -> Option<AttackDetectionResult>
where
    D: PatternDetector,
{
    if let Some(p) = path {
        let normalized = normalizer.normalize(p);
        if let Some(result) =
            detect_with_pre_normalized(detector, normalized.as_str(), InputLocation::Path)
        {
            return Some(result);
        }
    }

    if let Some(qs) = query_string {
        let normalized = normalizer.normalize(qs);
        if let Some(result) =
            detect_with_pre_normalized(detector, normalized.as_str(), InputLocation::QueryString)
        {
            return Some(result);
        }
    }

    if let Some(result) = detector.detect_in_security_headers(headers, Some(normalizer)) {
        return Some(result);
    }

    if let Some(body_bytes) = body {
        let s = String::from_utf8_lossy(body_bytes);
        let s: &str = &s;
        let normalized = normalizer.normalize(s);
        if let Some(result) =
            detect_with_pre_normalized(detector, normalized.as_str(), InputLocation::PostBody)
        {
            return Some(result);
        }
    }

    None
}

fn detect_with_pre_normalized<D>(
    detector: &D,
    normalized: &str,
    location: InputLocation,
) -> Option<AttackDetectionResult>
where
    D: PatternDetector,
{
    if let Some(mat) = detector.patterns().find(normalized) {
        let matched = normalized[mat.start()..mat.end()].to_string();
        return Some(AttackDetectionResult {
            attack_type: detector.attack_type(),
            fingerprint: None,
            matched_pattern: Some(matched),
            input_location: location,
        });
    }
    None
}

#[cfg(test)]
mod header_scan_policy_tests {
    use super::*;

    #[test]
    fn cookie_referer_and_origin_are_scanned() {
        let policy = HeaderScanPolicy::default();
        assert_eq!(policy.classify("cookie"), HeaderScanClass::UserValue);
        assert_eq!(policy.classify("Referer"), HeaderScanClass::Url);
        assert_eq!(policy.classify("origin"), HeaderScanClass::Url);
        assert!(policy.allows_payload_scan("cookie"));
    }

    #[test]
    fn browser_and_framing_headers_are_skipped() {
        let policy = HeaderScanPolicy::default();
        for name in [
            "accept",
            "accept-language",
            "sec-fetch-dest",
            "priority",
            "upgrade-insecure-requests",
            "range",
            "if-none-match",
            "cache-control",
            "pragma",
            "dnt",
            "te",
            "connection",
            "host",
            "content-type",
            "content-length",
            "transfer-encoding",
        ] {
            assert!(
                !policy.allows_payload_scan(name),
                "{name} must be skipped by payload detectors"
            );
        }
    }

    #[test]
    fn authorization_and_user_agent_are_not_payload_scanned() {
        let policy = HeaderScanPolicy::default();
        assert_eq!(
            policy.classify("authorization"),
            HeaderScanClass::Credential
        );
        assert_eq!(policy.classify("user-agent"), HeaderScanClass::UserAgent);
        assert!(!policy.allows_payload_scan("authorization"));
        assert!(!policy.allows_payload_scan("user-agent"));
    }

    #[test]
    fn unknown_headers_are_skip_by_default() {
        let policy = HeaderScanPolicy::default();
        assert!(!policy.allows_payload_scan("x-custom"));
    }

    #[test]
    fn configured_scan_adds_and_skip_wins() {
        let policy = HeaderScanPolicy::new(
            &["X-App-User".to_string(), "x-blocked".to_string()],
            &["X-Blocked".to_string()],
        );
        assert!(policy.allows_payload_scan("x-app-user"));
        assert_eq!(policy.classify("x-blocked"), HeaderScanClass::Skip);
        assert!(!policy.allows_payload_scan("x-blocked"));
    }

    #[test]
    fn configured_scan_can_override_a_default_skip() {
        let policy = HeaderScanPolicy::new(&["x-forwarded-for".to_string()], &[]);
        assert!(policy.allows_payload_scan("X-Forwarded-For"));
    }
}
