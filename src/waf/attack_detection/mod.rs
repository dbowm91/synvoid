pub mod behavioral;
pub mod cmd_injection;
pub mod config;
pub mod detector_common;
pub mod header_validation;
pub mod jwt;
pub mod ldap_injection;
pub mod libinjection;
pub mod normalizer;
pub mod open_redirect;
pub mod path_traversal;
pub mod patterns;
pub mod request_smuggling;
pub mod rfi;
pub mod sqli;
pub mod ssrf;
pub mod ssti;
pub mod streaming;
pub mod xpath_injection;
pub mod xss;
pub mod xxe;

use std::collections::{HashMap, HashSet, VecDeque};
use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use arc_swap::ArcSwapOption;
use parking_lot::RwLock;

use crate::waf::attack_detection::behavioral::{BehavioralEngine, StandaloneRequestFeatures};
use crate::waf::attack_detection::normalizer::{
    InputNormalizer, NormalizationFlags, NormalizedData, NormalizedInput, NormalizedInputs,
};

pub use cmd_injection::CmdInjectionDetector;
pub use config::{
    AnomalyScoringConfig, AttackDetectionConfig, AttackDetectionResult, AttackType, DetectorConfig,
    InputLocation, SimpleDetectorConfig,
};
pub use detector_common::{BasePatternDetector, PatternDetector};
pub use header_validation::HeaderValidator;
pub use jwt::JwtDetector;
pub use ldap_injection::LdapInjectionDetector;
pub use libinjection::LibInjectionDetector;
pub use open_redirect::OpenRedirectDetector;
pub use path_traversal::PathTraversalDetector;
pub use request_smuggling::RequestSmugglingDetector;
pub use rfi::RfiDetector;
pub use sqli::SqliDetector;
pub use ssrf::SsrfDetector;
pub use ssti::SstiDetector;
pub use xpath_injection::XPathInjectionDetector;
pub use xss::XssDetector;
pub use xxe::XxeDetector;

pub use streaming::{StreamingWafCore, StreamingWafDecision};

pub struct AttackDetector {
    config: AttackDetectionConfig,
    normalizer: Arc<InputNormalizer>,
    sqli_detector: Arc<SqliDetector>,
    xss_detector: Arc<XssDetector>,
    path_traversal_detector: Arc<PathTraversalDetector>,
    rfi_detector: Arc<RfiDetector>,
    ssrf_detector: Arc<SsrfDetector>,
    ssti_detector: Arc<SstiDetector>,
    cmd_injection_detector: Arc<CmdInjectionDetector>,
    xxe_detector: Arc<XxeDetector>,
    jwt_detector: Arc<JwtDetector>,
    request_smuggling_detector: Arc<RequestSmugglingDetector>,
    header_validator: Arc<HeaderValidator>,
    ldap_injection_detector: Arc<LdapInjectionDetector>,
    xpath_injection_detector: Arc<XPathInjectionDetector>,
    open_redirect_detector: Arc<OpenRedirectDetector>,
    fast_path_detector: Option<regex::RegexSet>,
    #[cfg(feature = "mesh")]
    behavioral_intel: Option<Arc<crate::mesh::behavioral_intel::BehavioralIntelligenceManager>>,
    behavioral_engine: Arc<BehavioralEngine>,
}

impl AttackDetector {
    pub fn new(config: AttackDetectionConfig) -> Self {
        let sqli_detector = Arc::new(SqliDetector::new(
            config.paranoia_level,
            &config.sqli.custom_patterns,
        ));

        let xss_detector = Arc::new(XssDetector::new(
            config.paranoia_level,
            &config.xss.custom_patterns,
        ));

        let path_traversal_detector = Arc::new(PathTraversalDetector::new(
            config.paranoia_level,
            &config.path_traversal.custom_patterns,
        ));

        let rfi_detector = Arc::new(RfiDetector::new(
            config.paranoia_level,
            &config.rfi.custom_patterns,
        ));

        let ssrf_detector = Arc::new(SsrfDetector::new(
            config.paranoia_level,
            &config.ssrf.custom_patterns,
            config.ssrf.block_private_ips,
            config.ssrf.allowed_domains.clone(),
            config.ssrf.allowlist_only_mode,
        ));

        let ssti_detector = Arc::new(SstiDetector::new(
            config.paranoia_level,
            &config.ssti.custom_patterns,
        ));

        let cmd_injection_detector = Arc::new(CmdInjectionDetector::new(
            config.paranoia_level,
            &config.cmd_injection.custom_patterns,
        ));

        let xxe_detector = Arc::new(XxeDetector::new(
            config.paranoia_level,
            &config.xxe.custom_patterns,
        ));

        let jwt_detector = Arc::new(JwtDetector::new(
            config.paranoia_level,
            &config.jwt.custom_patterns,
        ));

        let request_smuggling_detector = Arc::new(RequestSmugglingDetector::new());

        let normalizer = Arc::new(InputNormalizer::new());

        let header_validator = Arc::new(HeaderValidator::new(
            config.max_header_size,
            config.max_headers,
        ));

        let ldap_injection_detector = Arc::new(LdapInjectionDetector::new(
            config.paranoia_level,
            &config.ldap_injection.custom_patterns,
        ));

        let xpath_injection_detector = Arc::new(XPathInjectionDetector::new(
            config.paranoia_level,
            &config.xpath_injection.custom_patterns,
        ));

        let open_redirect_detector = Arc::new(OpenRedirectDetector::new(
            config.paranoia_level,
            &config.open_redirect.custom_patterns,
        ));

        let fast_path_patterns = vec![
            r#"['";]--"#,                // SQL comment/injection
            r#"(?i)union\s+select"#,      // SQL union
            r#"(?i)select\s+.*\s+from"#, // SQL select
            r#"(?i)drop\s+(table|database|index)"#, // SQL drop
            r#"(?i)insert\s+into"#,       // SQL insert
            r#"(?i)update\s+.*\s+set"#,  // SQL update
            r#"(?i)alter\s+"#,           // SQL alter
            r#"<script"#,                // XSS
            r#"javascript:"#,             // XSS JS protocol
            r#"onload="#,                 // XSS event handler
            r#"onerror="#,                // XSS event handler
            r#"onclick="#,                // XSS event handler
            r#"\.\./\.\./"#,              // Path traversal
            r#"\.\./"#,                   // Path traversal
            r#"/etc/passwd"#,             // Path traversal
            r#"/windows/system32"#,       // Path traversal
            r#"/proc/self"#,              // Path traversal
            r#"<\?php"#,                  // PHP tags
            r#"<\?="#,                    // PHP short tag
            r#"\{\{"#,                    // Template injection
            r#"\$\{"#,                    // Expression injection
            r#"\{%\s"#,                   // Template injection (Jinja2)
            r#";\s*(rm|del|erase)"#,     // Command injection
            r#"\|\s*(cat|ls|curl|wget)"#, // Command injection pipe
            r#";\s*wget\s+"#,             // Wget download
            r#";\s*curl\s+"#,             // Curl download
            r#"`.*`"#,                    // Command injection backticks
            r#"\$\(.*\)"#,                // Command injection $()
            r#"%00"#,                     // Null byte injection
            r#"%2f"#,                     // Path encoding
            r#"%0a"#,                     // CRLF injection
            r#"%0d%0a"#,                  // CRLF injection
            r#"http://"#,                 // SSRF
            r#"https://"#,                // SSRF
            r#"file://"#,                 // SSRF/local file access
            r#"<!DOCTYPE"#,               // XXE
            r#"<!ENTITY"#,                 // XXE
            r#"<!\[CDATA\["#,              // XXE
            r#"transfer-encoding"#,       // Request smuggling
            r#"content-length"#,          // Request smuggling
        ];
        let fast_path_detector = regex::RegexSet::new(fast_path_patterns).ok();

        Self {
            config,
            normalizer,
            sqli_detector,
            xss_detector,
            path_traversal_detector,
            rfi_detector,
            ssrf_detector,
            ssti_detector,
            cmd_injection_detector,
            xxe_detector,
            jwt_detector,
            request_smuggling_detector,
            header_validator,
            ldap_injection_detector,
            xpath_injection_detector,
            open_redirect_detector,
            fast_path_detector,
            #[cfg(feature = "mesh")]
            behavioral_intel: None,
            behavioral_engine: Arc::new(BehavioralEngine::new()),
        }
    }

    #[cfg(feature = "mesh")]
    pub fn new_with_behavioral_intel(
        config: AttackDetectionConfig,
        behavioral_intel: Arc<crate::mesh::behavioral_intel::BehavioralIntelligenceManager>,
    ) -> Self {
        let detector = Self::new(config);
        Self {
            behavioral_intel: Some(behavioral_intel),
            ..detector
        }
    }

    pub fn is_fast_path_safe(&self, inputs: &NormalizedInputs) -> bool {
        if let Some(ref detector) = self.fast_path_detector {
            for value in inputs.all_values() {
                if detector.is_match(value) {
                    return false;
                }
            }
            // Dual-view check: also check raw values to detect payloads hidden in characters
            // that might be removed by aggressive normalization (null bytes, zero-width, etc.)
            for value in inputs.all_raw_values() {
                if detector.is_match(value) {
                    return false;
                }
            }
        }
        true
    }

    pub async fn check_request(
        &self,
        client_ip: IpAddr,
        method: &http::Method,
        path: &str,
        query_string: Option<&str>,
        headers: &http::HeaderMap,
        body: Option<&[u8]>,
    ) -> (Option<AttackDetectionResult>, u32) {
        if !self.config.enabled {
            return (None, 0);
        }

        let mut first_result = None;
        let mut total_score = 0;
        let anomaly_enabled = self.config.anomaly_scoring.enabled;

        // Standalone Behavioral Check
        let standalone_features =
            self.behavioral_engine
                .extract_features(client_ip, path, query_string, headers, body);

        if standalone_features.url_entropy > 5.0 || standalone_features.timing_variance_ms < 5 {
            total_score += 20;
            tracing::debug!(
                "Standalone behavioral anomaly detected for {}: entropy={}, variance={}ms",
                client_ip,
                standalone_features.url_entropy,
                standalone_features.timing_variance_ms
            );
        }

        #[cfg(feature = "mesh")]
        if let Some(ref behavioral_intel) = self.behavioral_intel {
            let mesh_features = crate::mesh::behavioral_intel::RequestFeatures {
                header_timing_variance_ms: standalone_features.timing_variance_ms,
                request_sequence_entropy: 0.5,
                byte_length_distribution: vec![
                    standalone_features.body_len / 1000,
                    (standalone_features.body_len % 1000) / 100,
                    (standalone_features.body_len % 100) / 10,
                    standalone_features.body_len % 10,
                ],
                inter_request_timing_ms: standalone_features.inter_request_timing_ms,
                suspicious_header_count: standalone_features.suspicious_header_count,
                url_entropy: standalone_features.url_entropy,
                body_to_header_ratio: standalone_features.body_to_header_ratio,
            };

            if let Some(fingerprint) = behavioral_intel.analyze_request(&mesh_features) {
                if fingerprint.severity_score >= 70 {
                    let result = AttackDetectionResult {
                        attack_type: AttackType::Other,
                        input_location: InputLocation::Path,
                        fingerprint: Some(format!(
                            "behavioral_fingerprint:{}",
                            fingerprint.fingerprint_id
                        )),
                        matched_pattern: Some(format!(
                            "Behavioral fingerprint match (severity: {}, confidence: {})",
                            fingerprint.severity_score, fingerprint.confidence
                        )),
                    };

                    if !anomaly_enabled {
                        return (Some(result), 0);
                    }

                    if first_result.is_none() {
                        first_result = Some(result);
                    }
                }
            }

            let adjusted_paranoia =
                behavioral_intel.adjust_paranoia_level(&mesh_features, self.config.paranoia_level);
            if adjusted_paranoia > self.config.paranoia_level {
                tracing::debug!(
                    "Behavioral intelligence elevated paranoia from {} to {}",
                    self.config.paranoia_level,
                    adjusted_paranoia
                );
            }
        }

        if let Some(max_size) = self.config.max_request_body_size {
            if let Some(body) = body {
                if body.len() > max_size {
                    let result = AttackDetectionResult {
                        attack_type: AttackType::Other,
                        input_location: InputLocation::PostBody,
                        fingerprint: Some(format!("body_size:{}", body.len())),
                        matched_pattern: Some(format!(
                            "Request body {} bytes exceeds limit {} bytes",
                            body.len(),
                            max_size
                        )),
                    };

                    if !anomaly_enabled {
                        return (Some(result), 0);
                    }

                    if first_result.is_none() {
                        first_result = Some(result);
                    }
                    total_score += 50;
                }
            }
        }

        if let Some(result) = self.header_validator.validate(headers) {
            if !anomaly_enabled {
                return (Some(result), 0);
            }

            if first_result.is_none() {
                first_result = Some(result.clone());
            }

            total_score += match result.attack_type {
                AttackType::Other => 30,
                _ => 50,
            };
        }

        // Independent heavy checks can run in parallel
        let mut join_set = tokio::task::JoinSet::new();

        if self.config.request_smuggling.enabled {
            let detector = self.request_smuggling_detector.clone();
            let headers = headers.clone();
            let body = body.map(|b| b.to_vec());
            join_set.spawn(async move {
                detector
                    .check_headers(&headers)
                    .or_else(|| detector.check_http2_smuggling(&headers, &[], body.as_deref()))
                    .or_else(|| body.as_deref().and_then(|b| detector.check_body(b)))
                    .map(|r| (r, 50))
            });
        }

        if self.config.jwt.enabled {
            let detector = self.jwt_detector.clone();
            let normalizer = self.normalizer.clone();
            let headers = headers.clone();
            let query_string = query_string.map(|s| s.to_string());
            let body = body.map(|b| b.to_vec());
            join_set.spawn(async move {
                if let Some(result) = detector.detect_in_headers(&headers) {
                    return Some((result, 40));
                }

                if let Some(qs) = query_string {
                    let normalized = normalizer.normalize(&qs);
                    if let Some(result) =
                        detector.detect(normalized.as_str(), InputLocation::QueryString)
                    {
                        return Some((result, 40));
                    }
                }

                if let Some(b) = body {
                    let s = String::from_utf8_lossy(&b);
                    let normalized = normalizer.normalize(&s);
                    if let Some(result) =
                        detector.detect(normalized.as_str(), InputLocation::PostBody)
                    {
                        return Some((result, 40));
                    }
                }
                None
            });
        }

        let needs_normalized_inputs = self.config.sqli.enabled
            || self.config.xss.enabled
            || self.config.ssti.enabled
            || self.config.cmd_injection.enabled
            || self.config.path_traversal.enabled
            || self.config.rfi.enabled
            || self.config.ssrf.enabled
            || self.config.xxe.enabled
            || self.config.ldap_injection.enabled
            || self.config.xpath_injection.enabled
            || self.config.open_redirect.enabled;

        if needs_normalized_inputs {
            let inputs = Arc::new(
                NormalizedInputs::normalize_all(
                    &self.normalizer,
                    Some(path),
                    query_string,
                    headers,
                    body,
                )
                .into_owned(),
            );

            // Fast-Path Pre-Screening: Skip heavy detectors if no risky signatures are found
            // Or if system health is Critical (graceful degradation)
            let health = crate::metrics::health::SystemHealthMonitor::get_state();
            if self.is_fast_path_safe(&inputs)
                || health == crate::metrics::health::HealthState::Critical
            {
                if health == crate::metrics::health::HealthState::Critical {
                    tracing::debug!(
                        "Critical health state: skipping heavy WAF checks for request from {}",
                        client_ip
                    );
                } else {
                    tracing::debug!("Fast-path safe for request from {}", client_ip);
                }
                return (first_result, total_score);
            }

            if self.config.strict_normalization {
                if let Some(result) = self.check_strict_normalization(&inputs) {
                    if !anomaly_enabled {
                        return (Some(result), 0);
                    }

                    if first_result.is_none() {
                        first_result = Some(result);
                    }
                    total_score += 100;
                }
            }

            if self.config.sqli.enabled {
                let detector = self.sqli_detector.clone();
                let inputs = inputs.clone();
                join_set.spawn(async move {
                    Self::check_sqli_internal(&detector, &inputs).map(|r| {
                        let score = match r.attack_type {
                            AttackType::Sqli => 50,
                            _ => 30,
                        };
                        (r, score)
                    })
                });
            }

            if self.config.xss.enabled {
                let detector = self.xss_detector.clone();
                let inputs = inputs.clone();
                join_set.spawn(async move {
                    Self::check_xss_internal(&detector, &inputs).map(|r| {
                        let score = match r.attack_type {
                            AttackType::Xss => 50,
                            _ => 30,
                        };
                        (r, score)
                    })
                });
            }

            if self.config.ssti.enabled {
                let detector = self.ssti_detector.clone();
                let inputs = inputs.clone();
                join_set.spawn(async move {
                    Self::check_ssti_internal(&detector, &inputs).map(|r| (r, 40))
                });
            }

            if self.config.cmd_injection.enabled {
                let detector = self.cmd_injection_detector.clone();
                let inputs = inputs.clone();
                join_set.spawn(async move {
                    Self::check_cmd_injection_internal(&detector, &inputs).map(|r| (r, 50))
                });
            }

            if self.config.path_traversal.enabled {
                let detector = self.path_traversal_detector.clone();
                let inputs = inputs.clone();
                join_set.spawn(async move {
                    Self::check_path_traversal_internal(&detector, &inputs).map(|r| (r, 40))
                });
            }

            if self.config.rfi.enabled {
                let detector = self.rfi_detector.clone();
                let inputs = inputs.clone();
                join_set.spawn(async move {
                    Self::check_rfi_internal(&detector, &inputs).map(|r| (r, 50))
                });
            }

            if self.config.ssrf.enabled {
                let detector = self.ssrf_detector.clone();
                let inputs = inputs.clone();
                join_set.spawn(async move {
                    Self::check_ssrf_internal(&detector, &inputs).map(|r| (r, 50))
                });
            }

            if self.config.xxe.enabled {
                let detector = self.xxe_detector.clone();
                let inputs = inputs.clone();
                join_set.spawn(async move {
                    Self::check_xxe_internal(&detector, &inputs).map(|r| (r, 50))
                });
            }

            if self.config.ldap_injection.enabled {
                let detector = self.ldap_injection_detector.clone();
                let inputs = inputs.clone();
                join_set.spawn(async move {
                    Self::check_ldap_injection_internal(&detector, &inputs).map(|r| (r, 40))
                });
            }

            if self.config.xpath_injection.enabled {
                let detector = self.xpath_injection_detector.clone();
                let inputs = inputs.clone();
                join_set.spawn(async move {
                    Self::check_xpath_injection_internal(&detector, &inputs).map(|r| (r, 40))
                });
            }

            if self.config.open_redirect.enabled {
                let detector = self.open_redirect_detector.clone();
                let inputs = inputs.clone();
                join_set.spawn(async move {
                    Self::check_open_redirect_internal(&detector, &inputs).map(|r| (r, 30))
                });
            }
        }

        while let Some(res) = join_set.join_next().await {
            if let Ok(Some((result, score))) = res {
                if !anomaly_enabled {
                    return (Some(result), 0);
                }

                if first_result.is_none() {
                    first_result = Some(result);
                }
                total_score += score;
            }
        }

        (first_result, total_score)
    }

    fn check_sqli_internal(
        detector: &SqliDetector,
        inputs: &NormalizedInputs,
    ) -> Option<AttackDetectionResult> {
        if let Some(ref path) = inputs.path {
            if let Some(result) = detector.detect_normalized(path, InputLocation::Path) {
                return Some(result);
            }
        }

        if let Some(ref qs) = inputs.query_string {
            if let Some(result) = detector.detect_normalized(qs, InputLocation::QueryString) {
                return Some(result);
            }
        }

        for (name, value) in &inputs.headers {
            if let Some(result) = detector.detect_normalized(value, InputLocation::header(name)) {
                return Some(result);
            }
        }

        if let Some(ref body) = inputs.body {
            if let Some(result) = detector.detect_normalized(body, InputLocation::PostBody) {
                return Some(result);
            }
        }

        None
    }

    fn check_xss_internal(
        detector: &XssDetector,
        inputs: &NormalizedInputs,
    ) -> Option<AttackDetectionResult> {
        if let Some(ref path) = inputs.path {
            if let Some(result) = detector.detect_normalized(path, InputLocation::Path) {
                return Some(result);
            }
        }

        if let Some(ref qs) = inputs.query_string {
            if let Some(result) = detector.detect_normalized(qs, InputLocation::QueryString) {
                return Some(result);
            }
        }

        for (name, value) in &inputs.headers {
            if let Some(result) = detector.detect_normalized(value, InputLocation::header(name)) {
                return Some(result);
            }
        }

        if let Some(ref body) = inputs.body {
            if let Some(result) = detector.detect_normalized(body, InputLocation::PostBody) {
                return Some(result);
            }
        }

        None
    }

    fn check_ssti_internal(
        detector: &SstiDetector,
        inputs: &NormalizedInputs,
    ) -> Option<AttackDetectionResult> {
        if let Some(ref path) = inputs.path {
            if let Some(result) = detector.detect(path.as_str(), InputLocation::Path) {
                return Some(result);
            }
        }

        if let Some(ref qs) = inputs.query_string {
            if let Some(result) = detector.detect(qs.as_str(), InputLocation::QueryString) {
                return Some(result);
            }
        }

        for (name, value) in &inputs.headers {
            if let Some(result) = detector.detect(value.as_str(), InputLocation::header(name)) {
                return Some(result);
            }
        }

        if let Some(ref body) = inputs.body {
            if let Some(result) = detector.detect(body.as_str(), InputLocation::PostBody) {
                return Some(result);
            }
        }

        None
    }

    fn check_cmd_injection_internal(
        detector: &CmdInjectionDetector,
        inputs: &NormalizedInputs,
    ) -> Option<AttackDetectionResult> {
        if let Some(ref path) = inputs.path {
            if let Some(result) = detector.detect(path.as_str(), InputLocation::Path) {
                return Some(result);
            }
        }

        if let Some(ref qs) = inputs.query_string {
            if let Some(result) = detector.detect(qs.as_str(), InputLocation::QueryString) {
                return Some(result);
            }
        }

        for (name, value) in &inputs.headers {
            if let Some(result) = detector.detect(value.as_str(), InputLocation::header(name)) {
                return Some(result);
            }
        }

        if let Some(ref body) = inputs.body {
            if let Some(result) = detector.detect(body.as_str(), InputLocation::PostBody) {
                return Some(result);
            }
        }

        None
    }

    fn check_path_traversal_internal(
        detector: &PathTraversalDetector,
        inputs: &NormalizedInputs,
    ) -> Option<AttackDetectionResult> {
        if let Some(ref path) = inputs.path {
            if let Some(result) = detector.detect(path.as_str(), InputLocation::Path) {
                return Some(result);
            }
        }

        if let Some(ref qs) = inputs.query_string {
            if let Some(result) = detector.detect(qs.as_str(), InputLocation::QueryString) {
                return Some(result);
            }
        }

        for (name, value) in &inputs.headers {
            if let Some(result) = detector.detect(value.as_str(), InputLocation::header(name)) {
                return Some(result);
            }
        }

        if let Some(ref body) = inputs.body {
            if let Some(result) = detector.detect(body.as_str(), InputLocation::PostBody) {
                return Some(result);
            }
        }

        None
    }

    fn check_rfi_internal(
        detector: &RfiDetector,
        inputs: &NormalizedInputs,
    ) -> Option<AttackDetectionResult> {
        if let Some(ref qs) = inputs.query_string {
            if let Some(result) = detector.detect(qs.as_str(), InputLocation::QueryString) {
                return Some(result);
            }
        }

        for (name, value) in &inputs.headers {
            if let Some(result) = detector.detect(value.as_str(), InputLocation::header(name)) {
                return Some(result);
            }
        }

        if let Some(ref body) = inputs.body {
            if let Some(result) = detector.detect(body.as_str(), InputLocation::PostBody) {
                return Some(result);
            }
        }

        None
    }

    fn check_ssrf_internal(
        detector: &SsrfDetector,
        inputs: &NormalizedInputs,
    ) -> Option<AttackDetectionResult> {
        if let Some(ref qs) = inputs.query_string {
            if let Some(result) = detector.detect(qs.as_str(), InputLocation::QueryString) {
                return Some(result);
            }
        }

        for (name, value) in &inputs.headers {
            if let Some(result) = detector.detect(value.as_str(), InputLocation::header(name)) {
                return Some(result);
            }
        }

        if let Some(ref body) = inputs.body {
            if let Some(result) = detector.detect(body.as_str(), InputLocation::PostBody) {
                return Some(result);
            }
        }

        None
    }

    fn check_xxe_internal(
        detector: &XxeDetector,
        inputs: &NormalizedInputs,
    ) -> Option<AttackDetectionResult> {
        if let Some(ref qs) = inputs.query_string {
            if let Some(result) = detector.detect(qs.as_str(), InputLocation::QueryString) {
                return Some(result);
            }
        }

        for (name, value) in &inputs.headers {
            if let Some(result) = detector.detect(value.as_str(), InputLocation::header(name)) {
                return Some(result);
            }
        }

        if let Some(ref body) = inputs.body {
            if let Some(result) = detector.detect(body.as_str(), InputLocation::PostBody) {
                return Some(result);
            }
        }

        None
    }

    fn check_ldap_injection_internal(
        detector: &LdapInjectionDetector,
        inputs: &NormalizedInputs,
    ) -> Option<AttackDetectionResult> {
        if let Some(ref path) = inputs.path {
            if let Some(result) = detector.detect(path.as_str(), InputLocation::Path) {
                return Some(result);
            }
        }

        if let Some(ref qs) = inputs.query_string {
            if let Some(result) = detector.detect(qs.as_str(), InputLocation::QueryString) {
                return Some(result);
            }
        }

        for (name, value) in &inputs.headers {
            if let Some(result) = detector.detect(value.as_str(), InputLocation::header(name)) {
                return Some(result);
            }
        }

        if let Some(ref body) = inputs.body {
            if let Some(result) = detector.detect(body.as_str(), InputLocation::PostBody) {
                return Some(result);
            }
        }

        None
    }

    fn check_xpath_injection_internal(
        detector: &XPathInjectionDetector,
        inputs: &NormalizedInputs,
    ) -> Option<AttackDetectionResult> {
        if let Some(ref path) = inputs.path {
            if let Some(result) = detector.detect(path.as_str(), InputLocation::Path) {
                return Some(result);
            }
        }

        if let Some(ref qs) = inputs.query_string {
            if let Some(result) = detector.detect(qs.as_str(), InputLocation::QueryString) {
                return Some(result);
            }
        }

        for (name, value) in &inputs.headers {
            if let Some(result) = detector.detect(value.as_str(), InputLocation::header(name)) {
                return Some(result);
            }
        }

        if let Some(ref body) = inputs.body {
            if let Some(result) = detector.detect(body.as_str(), InputLocation::PostBody) {
                return Some(result);
            }
        }

        None
    }

    fn check_open_redirect_internal(
        detector: &OpenRedirectDetector,
        inputs: &NormalizedInputs,
    ) -> Option<AttackDetectionResult> {
        if let Some(ref path) = inputs.path {
            if let Some(result) = detector.detect(path.as_str(), InputLocation::Path) {
                return Some(result);
            }
        }

        if let Some(ref qs) = inputs.query_string {
            if let Some(result) = detector.detect(qs.as_str(), InputLocation::QueryString) {
                return Some(result);
            }
        }

        for (name, value) in &inputs.headers {
            if let Some(result) = detector.detect(value.as_str(), InputLocation::header(name)) {
                return Some(result);
            }
        }

        if let Some(ref body) = inputs.body {
            if let Some(result) = detector.detect(body.as_str(), InputLocation::PostBody) {
                return Some(result);
            }
        }

        None
    }

    pub fn check_body_only(&self, body: &[u8]) -> Option<AttackDetectionResult> {
        self.check_body_fragments(&[body])
    }

    pub fn check_body_fragments(&self, fragments: &[&[u8]]) -> Option<AttackDetectionResult> {
        if !self.config.enabled {
            return None;
        }

        let total_size: usize = fragments.iter().map(|f| f.len()).sum();

        if let Some(max_size) = self.config.max_request_body_size {
            if total_size > max_size {
                return Some(AttackDetectionResult {
                    attack_type: AttackType::Other,
                    input_location: InputLocation::PostBody,
                    fingerprint: Some(format!("body_size:{}", total_size)),
                    matched_pattern: Some(format!(
                        "Request body {} bytes exceeds limit {} bytes",
                        total_size, max_size
                    )),
                });
            }
        }

        let normalized = self.normalizer.normalize_fragments(fragments);

        if self.config.request_smuggling.enabled {
            if let Some(result) = self
                .request_smuggling_detector
                .check_body(normalized.as_bytes())
            {
                return Some(result);
            }
        }

        if self.config.jwt.enabled {
            if let Some(result) = self
                .jwt_detector
                .detect(normalized.as_str(), InputLocation::PostBody)
            {
                return Some(result);
            }
        }

        if self.config.sqli.enabled {
            if let Some(result) = self
                .sqli_detector
                .detect(normalized.as_bytes(), InputLocation::PostBody)
            {
                return Some(result);
            }
        }

        if self.config.xss.enabled {
            if let Some(result) = self
                .xss_detector
                .detect(normalized.as_bytes(), InputLocation::PostBody)
            {
                return Some(result);
            }
        }

        if self.config.ssti.enabled {
            if let Some(result) = self
                .ssti_detector
                .detect(normalized.as_str(), InputLocation::PostBody)
            {
                return Some(result);
            }
        }

        if self.config.cmd_injection.enabled
            || self.config.path_traversal.enabled
            || self.config.rfi.enabled
            || self.config.ssrf.enabled
            || self.config.xxe.enabled
            || self.config.ldap_injection.enabled
            || self.config.xpath_injection.enabled
            || self.config.open_redirect.enabled
        {
            let body_input = normalized.as_str();

            if self.config.cmd_injection.enabled {
                if let Some(result) = self
                    .cmd_injection_detector
                    .detect(body_input, InputLocation::PostBody)
                {
                    return Some(result);
                }
            }

            if self.config.path_traversal.enabled {
                if let Some(result) = self
                    .path_traversal_detector
                    .detect(body_input, InputLocation::PostBody)
                {
                    return Some(result);
                }
            }

            if self.config.rfi.enabled {
                if let Some(result) = self
                    .rfi_detector
                    .detect(body_input, InputLocation::PostBody)
                {
                    return Some(result);
                }
            }

            if self.config.ssrf.enabled {
                if let Some(result) = self
                    .ssrf_detector
                    .detect(body_input, InputLocation::PostBody)
                {
                    return Some(result);
                }
            }

            if self.config.xxe.enabled {
                if let Some(result) = self
                    .xxe_detector
                    .detect(body_input, InputLocation::PostBody)
                {
                    return Some(result);
                }
            }

            if self.config.ldap_injection.enabled {
                if let Some(result) = self
                    .ldap_injection_detector
                    .detect(body_input, InputLocation::PostBody)
                {
                    return Some(result);
                }
            }

            if self.config.xpath_injection.enabled {
                if let Some(result) = self
                    .xpath_injection_detector
                    .detect(body_input, InputLocation::PostBody)
                {
                    return Some(result);
                }
            }

            if self.config.open_redirect.enabled {
                if let Some(result) = self
                    .open_redirect_detector
                    .detect(body_input, InputLocation::PostBody)
                {
                    return Some(result);
                }
            }
        }

        None
    }

    pub fn check_body_only_via_normalized(&self, body_str: &str) -> Option<AttackDetectionResult> {
        if !self.config.enabled {
            return None;
        }

        if let Some(max_size) = self.config.max_request_body_size {
            if body_str.len() > max_size {
                return Some(AttackDetectionResult {
                    attack_type: AttackType::Other,
                    input_location: InputLocation::PostBody,
                    fingerprint: Some(format!("body_size:{}", body_str.len())),
                    matched_pattern: Some(format!(
                        "Request body {} bytes exceeds limit {} bytes",
                        body_str.len(),
                        max_size
                    )),
                });
            }
        }

        let normalized = self.normalizer.normalize(body_str);

        if self.config.request_smuggling.enabled {
            if let Some(result) = self
                .request_smuggling_detector
                .check_body(normalized.as_bytes())
            {
                return Some(result);
            }
        }

        if self.config.jwt.enabled {
            if let Some(result) = self
                .jwt_detector
                .detect(normalized.as_str(), InputLocation::PostBody)
            {
                return Some(result);
            }
        }

        if self.config.sqli.enabled {
            if let Some(result) = self
                .sqli_detector
                .detect(normalized.as_bytes(), InputLocation::PostBody)
            {
                return Some(result);
            }
        }

        if self.config.xss.enabled {
            if let Some(result) = self
                .xss_detector
                .detect(normalized.as_bytes(), InputLocation::PostBody)
            {
                return Some(result);
            }
        }

        if self.config.ssti.enabled {
            if let Some(result) = self
                .ssti_detector
                .detect(normalized.as_str(), InputLocation::PostBody)
            {
                return Some(result);
            }
        }

        if self.config.cmd_injection.enabled
            || self.config.path_traversal.enabled
            || self.config.rfi.enabled
            || self.config.ssrf.enabled
            || self.config.xxe.enabled
            || self.config.ldap_injection.enabled
            || self.config.xpath_injection.enabled
            || self.config.open_redirect.enabled
        {
            let body_input = normalized.as_str();

            if self.config.cmd_injection.enabled {
                if let Some(result) = self
                    .cmd_injection_detector
                    .detect(body_input, InputLocation::PostBody)
                {
                    return Some(result);
                }
            }

            if self.config.path_traversal.enabled {
                if let Some(result) = self
                    .path_traversal_detector
                    .detect(body_input, InputLocation::PostBody)
                {
                    return Some(result);
                }
            }

            if self.config.rfi.enabled {
                if let Some(result) = self
                    .rfi_detector
                    .detect(body_input, InputLocation::PostBody)
                {
                    return Some(result);
                }
            }

            if self.config.ssrf.enabled {
                if let Some(result) = self
                    .ssrf_detector
                    .detect(body_input, InputLocation::PostBody)
                {
                    return Some(result);
                }
            }

            if self.config.xxe.enabled {
                if let Some(result) = self
                    .xxe_detector
                    .detect(body_input, InputLocation::PostBody)
                {
                    return Some(result);
                }
            }

            if self.config.ldap_injection.enabled {
                if let Some(result) = self
                    .ldap_injection_detector
                    .detect(body_input, InputLocation::PostBody)
                {
                    return Some(result);
                }
            }

            if self.config.xpath_injection.enabled {
                if let Some(result) = self
                    .xpath_injection_detector
                    .detect(body_input, InputLocation::PostBody)
                {
                    return Some(result);
                }
            }

            if self.config.open_redirect.enabled {
                if let Some(result) = self
                    .open_redirect_detector
                    .detect(body_input, InputLocation::PostBody)
                {
                    return Some(result);
                }
            }
        }

        None
    }

    pub fn streaming(self: Arc<Self>) -> StreamingWafCore {
        StreamingWafCore::new(self)
    }

    fn check_strict_normalization(
        &self,
        inputs: &NormalizedInputs,
    ) -> Option<AttackDetectionResult> {
        let risky_flags = NormalizationFlags::NULL_BYTE | NormalizationFlags::ZERO_WIDTH;

        // Check path
        if let (Some(norm), Some(raw)) = (&inputs.path, &inputs.path_raw) {
            if norm.flags.intersects(risky_flags) {
                return Some(AttackDetectionResult {
                    attack_type: AttackType::Other,
                    input_location: InputLocation::Path,
                    fingerprint: Some("strict_normalization_violation".to_string()),
                    matched_pattern: Some(format!(
                        "Risky normalization in path: {:?} (normalized delta: {})",
                        norm.flags,
                        raw.len().saturating_sub(norm.as_str().len())
                    )),
                });
            }
        }

        // Check query string
        if let (Some(norm), Some(raw)) = (&inputs.query_string, &inputs.query_string_raw) {
            if norm.flags.intersects(risky_flags) {
                return Some(AttackDetectionResult {
                    attack_type: AttackType::Other,
                    input_location: InputLocation::QueryString,
                    fingerprint: Some("strict_normalization_violation".to_string()),
                    matched_pattern: Some(format!(
                        "Risky normalization in query string: {:?} (normalized delta: {})",
                        norm.flags,
                        raw.len().saturating_sub(norm.as_str().len())
                    )),
                });
            }
        }

        // Check headers
        for (i, (name, norm)) in inputs.headers.iter().enumerate() {
            if let Some((_, raw)) = inputs.headers_raw.get(i) {
                if norm.flags.intersects(risky_flags) {
                    return Some(AttackDetectionResult {
                        attack_type: AttackType::Other,
                        input_location: InputLocation::header(name),
                        fingerprint: Some("strict_normalization_violation".to_string()),
                        matched_pattern: Some(format!(
                            "Risky normalization in header {}: {:?} (normalized delta: {})",
                            name,
                            norm.flags,
                            raw.len().saturating_sub(norm.as_str().len())
                        )),
                    });
                }
            }
        }

        // Check body
        if let (Some(norm), Some(raw)) = (&inputs.body, &inputs.body_raw) {
            if norm.flags.intersects(risky_flags) {
                return Some(AttackDetectionResult {
                    attack_type: AttackType::Other,
                    input_location: InputLocation::PostBody,
                    fingerprint: Some("strict_normalization_violation".to_string()),
                    matched_pattern: Some(format!(
                        "Risky normalization in body: {:?} (normalized delta: {})",
                        norm.flags,
                        raw.len().saturating_sub(norm.as_str().len())
                    )),
                });
            }
        }

        None
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use http::{HeaderMap, Method};

    fn check_detects(expected: AttackType, path: &str, query: Option<&str>, body: Option<&[u8]>) {
        let detector = AttackDetector::new(AttackDetectionConfig::default());
        let headers = HeaderMap::new();
        let rt = tokio::runtime::Runtime::new().unwrap();
        let (result, _) = rt.block_on(detector.check_request(
            "127.0.0.1".parse().unwrap(),
            &Method::GET,
            path,
            query,
            &headers,
            body,
        ));
        let result = result.expect(&format!(
            "Expected {:?} to be detected in: {}",
            expected, path
        ));
        assert_eq!(result.attack_type, expected);
    }

    fn check_no_detect(path: &str, query: Option<&str>, body: Option<&[u8]>) {
        let detector = AttackDetector::new(AttackDetectionConfig::default());
        let headers = HeaderMap::new();
        let rt = tokio::runtime::Runtime::new().unwrap();
        let (result, _) = rt.block_on(detector.check_request(
            "127.0.0.1".parse().unwrap(),
            &Method::GET,
            path,
            query,
            &headers,
            body,
        ));
        assert!(result.is_none(), "Expected no detection in: {}", path);
    }

    #[test]
    fn test_check_request_sqli_detection() {
        check_detects(
            AttackType::Sqli,
            "/search?q=1'%20OR%20'1'='1",
            Some("q=1'%20OR%20'1'='1"),
            None,
        );
    }

    #[test]
    fn test_check_request_xss_detection() {
        check_detects(
            AttackType::Xss,
            "/search?q=<script>alert('xss')</script>",
            Some("q=<script>alert('xss')</script>"),
            None,
        );
    }

    #[test]
    fn test_check_request_path_traversal_detection() {
        check_detects(
            AttackType::PathTraversal,
            "/files/..%2f..%2f..%2f",
            Some("file=..%2f..%2f..%2f"),
            None,
        );
    }

    #[test]
    fn test_check_request_xxe_detection() {
        check_detects(AttackType::Xxe, "/api/xml", Some("data=%25xxe"), None);
    }

    #[test]
    fn test_check_request_cmd_injection_detection() {
        check_detects(
            AttackType::CmdInjection,
            "/ping?host=localhost;cat%20/etc/passwd",
            Some("host=localhost;cat%20/etc/passwd"),
            None,
        );
    }

    #[test]
    fn test_check_request_benign() {
        check_no_detect("/api/users/123", None, None);
    }

    #[test]
    fn test_check_request_disabled() {
        let mut config = AttackDetectionConfig::default();
        config.enabled = false;
        let detector = AttackDetector::new(config);
        let headers = http::HeaderMap::new();
        let rt = tokio::runtime::Runtime::new().unwrap();
        let (result, _) = rt.block_on(detector.check_request(
            "127.0.0.1".parse().unwrap(),
            &http::Method::GET,
            "/search?q=<script>alert('xss')</script>",
            Some("q=<script>alert('xss')</script>"),
            &headers,
            None,
        ));
        assert!(result.is_none());
    }

    #[test]
    fn test_check_request_ssrf_detection() {
        check_detects(
            AttackType::Rfi,
            "/proxy?url=http://169.254.169.254/latest/meta-data",
            Some("url=http://169.254.169.254/latest/meta-data"),
            None,
        );
    }

    #[test]
    fn test_check_request_encoded_attack() {
        check_detects(
            AttackType::Xss,
            "/search?q=%3Cscript%3Ealert%28%27xss%27%29%3C%2Fscript%3E",
            Some("q=%3Cscript%3Ealert%28%27xss%27%29%3C%2Fscript%3E"),
            None,
        );
    }

    #[test]
    fn test_check_request_double_encoded_attack() {
        let detector = AttackDetector::new(AttackDetectionConfig::default());
        let headers = http::HeaderMap::new();
        let rt = tokio::runtime::Runtime::new().unwrap();
        let (result, _) = rt.block_on(detector.check_request(
            "127.0.0.1".parse().unwrap(),
            &http::Method::GET,
            "/search?q=%253Cscript%253Ealert%2528%2527xss%2527%2529%253C%252Fscript%253E",
            Some("q=%253Cscript%253Ealert%2528%2527xss%2527%2529%253C%252Fscript%253E"),
            &headers,
            None,
        ));
        assert!(result.is_some());
    }
}
