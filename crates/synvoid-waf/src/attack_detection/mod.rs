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

use std::sync::Arc;

use crate::attack_detection::behavioral::BehavioralEngine;
use crate::attack_detection::normalizer::{InputNormalizer, NormalizationFlags, NormalizedInputs};

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
            r#"['";]--"#,
            r#"(?i)union\s+select"#,
            r#"(?i)select\s+.*\s+from"#,
            r#"(?i)drop\s+(table|database|index)"#,
            r#"(?i)insert\s+into"#,
            r#"(?i)update\s+.*\s+set"#,
            r#"(?i)alter\s+"#,
            r#"<script"#,
            r#"javascript:"#,
            r#"onload="#,
            r#"onerror="#,
            r#"onclick="#,
            r#"\.\./\.\./"#,
            r#"\.\./"#,
            r#"/etc/passwd"#,
            r#"/windows/system32"#,
            r#"/proc/self"#,
            r#"<\?php"#,
            r#"<\?="#,
            r#"\{\{"#,
            r#"\$\{"#,
            r#"\{%\s"#,
            r#";\s*(rm|del|erase)"#,
            r#"\|\s*(cat|ls|curl|wget)"#,
            r#";\s*wget\s+"#,
            r#";\s*curl\s+"#,
            r#"`.*`"#,
            r#"\$\(.*\)"#,
            r#"%00"#,
            r#"%2f"#,
            r#"%0a"#,
            r#"%0d%0a"#,
            r#"http://"#,
            r#"https://"#,
            r#"file://"#,
            r#"<!DOCTYPE"#,
            r#"<!ENTITY"#,
            r#"<!\[CDATA\["#,
            r#"transfer-encoding"#,
            r#"content-length"#,
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
            behavioral_engine: Arc::new(BehavioralEngine::new()),
        }
    }

    pub fn is_fast_path_safe(&self, inputs: &NormalizedInputs) -> bool {
        if let Some(ref detector) = self.fast_path_detector {
            for value in inputs.all_values() {
                if detector.is_match(value) {
                    return false;
                }
            }
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
        client_ip: std::net::IpAddr,
        _method: &http::Method,
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

            if self.is_fast_path_safe(&inputs) {
                tracing::debug!("Fast-path safe for request from {}", client_ip);
                while let Some(join_result) = join_set.join_next().await {
                    if let Ok(Some((result, score))) = join_result {
                        if !anomaly_enabled {
                            return (Some(result), 0);
                        }
                        if first_result.is_none() {
                            first_result = Some(result);
                        }
                        total_score += score;
                    }
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

    pub fn streaming_with_config(
        self: Arc<Self>,
        chunk_size: usize,
        max_buffered_bytes: usize,
    ) -> StreamingWafCore {
        StreamingWafCore::with_config(self, chunk_size, max_buffered_bytes)
    }

    fn check_strict_normalization(
        &self,
        inputs: &NormalizedInputs,
    ) -> Option<AttackDetectionResult> {
        let risky_flags = NormalizationFlags::NULL_BYTE | NormalizationFlags::ZERO_WIDTH;

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
