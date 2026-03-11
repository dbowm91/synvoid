use crate::utils::urlencoding_decode_result;
use crate::waf::attack_detection::config::{AttackDetectionResult, AttackType, InputLocation};
use crate::waf::attack_detection::normalizer::InputNormalizer;
use aho_corasick::AhoCorasick;
use std::sync::Arc;

/// Creates a simple pattern-based attack detector.
///
/// This macro generates a detector that wraps `BasePatternDetector` and implements
/// the `PatternDetector` trait. Use this for detectors that only need pattern matching
/// without any custom preprocessing.
///
/// # Arguments
/// - `$name` - The detector struct name (e.g., `SstiDetector`)
/// - `$attack_type` - The `AttackType` enum variant (e.g., `AttackType::Ssti`)
/// - `$attack_name` - A string literal for logging (e.g., `"ssti"`)
/// - `$patterns_fn` - Function returning base patterns (e.g., `DefaultPatterns::ssti`)
/// - `$high_patterns_fn` - Function returning high-paranoia patterns (e.g., `DefaultPatterns::ssti_high`)
///
/// # Example
/// ```ignore
/// // Before: ~60 lines of boilerplate
/// // After:
/// pattern_detector!(
///     SstiDetector,
///     AttackType::Ssti,
///     "ssti",
///     DefaultPatterns::ssti,
///     DefaultPatterns::ssti_high
/// );
/// ```
///
/// # Detectors that can use this macro
/// - SstiDetector
/// - LdapInjectionDetector
/// - XPathInjectionDetector
/// - OpenRedirectDetector
/// - XxeDetector
///
/// # Detectors that cannot use this macro (need custom logic)
/// - CmdInjectionDetector (has input normalization)
/// - PathTraversalDetector (URL decoding)
/// - RfiDetector (IP pattern matching)
/// - SsrfDetector (private IP blocking)
/// - SqliDetector (uses libinjection)
/// - XssDetector (uses libinjection)
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
            inner: $crate::waf::attack_detection::detector_common::BasePatternDetector,
        }

        impl $name {
            pub fn new(paranoia_level: u8, custom_patterns: &[String]) -> Self {
                let inner = $crate::waf::attack_detection::detector_common::BasePatternDetector::new(
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

        impl $crate::waf::attack_detection::detector_common::PatternDetector for $name {
            fn patterns(&self) -> &Arc<AhoCorasick> {
                self.inner.patterns()
            }

            fn detect(&self, input: &str, location: InputLocation) -> Option<AttackDetectionResult> {
                self.detect(input, location)
            }
        }
    };
}

/// Creates a detector that performs URL decoding before pattern matching.
///
/// This macro generates a detector similar to `pattern_detector!`, but additionally
/// performs URL decoding on the input before pattern matching. This is useful for
/// detectors that need to detect attacks hidden in encoded URLs.
///
/// The detection logic:
/// 1. Lowercase and URL-decode the input
/// 2. Run pattern matching on decoded input
/// 3. If no match, try pattern matching on original lowercase input
///
/// # Arguments
/// Same as `pattern_detector!`
///
/// # Example
/// ```ignore
/// url_decode_detector!(
///     PathTraversalDetector,
///     AttackType::PathTraversal,
///     "path_traversal",
///     DefaultPatterns::path_traversal,
///     DefaultPatterns::path_traversal_high
/// );
/// ```
///
/// Note: PathTraversalDetector currently has custom logic beyond URL decoding,
/// so it cannot be fully replaced by this macro.
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
            inner: $crate::waf::attack_detection::detector_common::BasePatternDetector,
        }

        impl $name {
            pub fn new(paranoia_level: u8, custom_patterns: &[String]) -> Self {
                let inner = $crate::waf::attack_detection::detector_common::BasePatternDetector::new(
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
                use crate::utils::url_decode_all;
                let input_lower = input.to_lowercase();
                let decoded = url_decode_all(&input_lower);

                if let Some(mat) = self.inner.patterns_ref().find(&decoded) {
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

                if decoded != input_lower {
                    if let Some(mat) = self.inner.patterns_ref().find(&input_lower) {
                        let matched = input_lower[mat.start()..mat.end()].to_string();
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

        impl $crate::waf::attack_detection::detector_common::PatternDetector for $name {
            fn patterns(&self) -> &Arc<AhoCorasick> {
                self.inner.patterns()
            }

            fn detect(&self, input: &str, location: InputLocation) -> Option<AttackDetectionResult> {
                self.detect(input, location)
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

pub fn detect_in_headers<F>(
    headers: &http::HeaderMap,
    mut check_header: F,
    normalizer: Option<&InputNormalizer>,
    mut detect: impl FnMut(&[u8], InputLocation) -> Option<AttackDetectionResult>,
) -> Option<AttackDetectionResult>
where
    F: FnMut(&str) -> bool,
{
    for header_name in SECURITY_HEADERS {
        if !check_header(*header_name) {
            continue;
        }

        if let Some(value) = headers.get(*header_name) {
            if let Ok(value_str) = value.to_str() {
                let input = value_str.as_bytes();
                let location = InputLocation::Header(header_name.to_string());

                if let Some(result) = detect(input, location.clone()) {
                    return Some(result);
                }

                if let Some(norm) = normalizer {
                    let normalized = norm.normalize(value_str);
                    if normalized.normalized != value_str {
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

/// Trait for pattern-based attack detectors.
///
/// Implement this trait to create detectors that use Aho-Corasick
/// pattern matching to identify attacks.
///
/// # Implementing a Detector
///
/// For simple detectors, prefer using the [`pattern_detector!`] or
/// [`url_decode_detector!`] macros instead of implementing this trait manually.
///
/// # Example
/// ```ignore
/// impl PatternDetector for MyDetector {
///     fn patterns(&self) -> &Arc<AhoCorasick> {
///         self.inner.patterns()
///     }
///
///     fn detect(&self, input: &str, location: InputLocation) -> Option<AttackDetectionResult> {
///         self.inner.detect_internal(input, location)
///     }
/// }
/// ```
///
/// # Built-in Helper Methods
///
/// The trait provides default implementations for:
/// - `detect_in_security_headers` - Check security-sensitive headers
/// - `detect_in_headers` - Check headers matching a predicate
/// - `detect_in_all_headers` - Check all headers
/// - `detect_in_query` - Check URL query string
/// - `detect_in_body` - Check request body
pub trait PatternDetector: Send + Sync {
    fn patterns(&self) -> &Arc<AhoCorasick>;

    fn detect(&self, input: &str, location: InputLocation) -> Option<AttackDetectionResult>;

    #[inline]
    fn detect_in_security_headers(
        &self,
        headers: &http::HeaderMap,
        normalizer: Option<&InputNormalizer>,
    ) -> Option<AttackDetectionResult> {
        for header_name in SECURITY_HEADERS {
            if let Some(value) = headers.get(*header_name) {
                if let Ok(value_str) = value.to_str() {
                    let location = InputLocation::Header(header_name.to_string());
                    if let Some(r) = self.detect(value_str, location.clone()) {
                        return Some(r);
                    }
                    if let Some(norm) = normalizer {
                        let normalized = norm.normalize(value_str);
                        if normalized.normalized != value_str {
                            if let Some(r) = self.detect(&normalized.normalized, location) {
                                return Some(r);
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
        for header_name in SECURITY_HEADERS {
            if !check_header(*header_name) {
                continue;
            }
            if let Some(value) = headers.get(*header_name) {
                if let Ok(value_str) = value.to_str() {
                    let location = InputLocation::Header(header_name.to_string());
                    if let Some(r) = self.detect(value_str, location.clone()) {
                        return Some(r);
                    }
                    if let Some(norm) = normalizer {
                        let normalized = norm.normalize(value_str);
                        if normalized.normalized != value_str {
                            if let Some(r) = self.detect(&normalized.normalized, location) {
                                return Some(r);
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
        for (header_name, header_value) in headers.iter() {
            if let Ok(value) = header_value.to_str() {
                let location = InputLocation::Header(header_name.to_string());
                if let Some(r) = self.detect(value, location.clone()) {
                    return Some(r);
                }
                if let Some(norm) = normalizer {
                    let normalized = norm.normalize(value);
                    if normalized.normalized != value {
                        if let Some(r) = self.detect(&normalized.normalized, location) {
                            return Some(r);
                        }
                    }
                }
            }
        }
        None
    }
}

fn detect_header_value<D: PatternDetector>(
    detector: &D,
    header_name: &str,
    value: &str,
    normalizer: Option<&InputNormalizer>,
) -> Option<AttackDetectionResult> {
    let location = InputLocation::Header(header_name.to_string());

    if let Some(result) = detector.detect(value, location.clone()) {
        return Some(result);
    }

    if let Some(norm) = normalizer {
        let normalized = norm.normalize(value);
        if normalized.normalized != value {
            if let Some(result) = detector.detect(&normalized.normalized, location) {
                return Some(result);
            }
        }
    } else if let Ok(decoded) = urlencoding_decode_result(value) {
        if decoded != value {
            if let Some(result) = detector.detect(&decoded, location) {
                return Some(result);
            }
        }
    }

    None
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
        self.detect_internal_normalized(input, location, |s| s.to_lowercase())
    }

    pub fn detect_internal_normalized<F>(
        &self,
        input: &str,
        location: InputLocation,
        normalizer: F,
    ) -> Option<AttackDetectionResult>
    where
        F: Fn(&str) -> String,
    {
        let normalized = normalizer(input);

        if let Some(mat) = self.patterns.find(&normalized) {
            let matched = normalized[mat.start()..mat.end()].to_string();

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
    let mut patterns: Vec<String> = base_patterns.iter().map(|s| s.to_lowercase()).collect();

    if paranoia_level >= 3 {
        patterns.extend(high_patterns.iter().map(|s| s.to_lowercase()));
    }

    for pattern in custom_patterns {
        let pattern_lower = pattern.to_lowercase();
        if !patterns.contains(&pattern_lower) {
            patterns.push(pattern_lower);
        }
    }

    let patterns_str: Vec<&str> = patterns.iter().map(|s| s.as_str()).collect();
    Arc::new(AhoCorasick::new(&patterns_str).unwrap())
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
        if let Some(result) = detector.detect(normalized.as_str(), InputLocation::Path) {
            return Some(result);
        }
    }

    if let Some(qs) = query_string {
        let normalized = normalizer.normalize(qs);
        if let Some(result) = detector.detect(normalized.as_str(), InputLocation::QueryString) {
            return Some(result);
        }
    }

    if let Some(result) = detector.detect_in_security_headers(headers, Some(normalizer)) {
        return Some(result);
    }

    if let Some(body_bytes) = body {
        if let Ok(body_str) = std::str::from_utf8(body_bytes) {
            let normalized = normalizer.normalize(body_str);
            if let Some(result) = detector.detect(normalized.as_str(), InputLocation::PostBody) {
                return Some(result);
            }
        }
    }

    None
}
