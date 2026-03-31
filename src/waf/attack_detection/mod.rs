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
pub mod xpath_injection;
pub mod xss;
pub mod xxe;

use std::sync::Arc;

pub use cmd_injection::CmdInjectionDetector;
pub use config::{
    AttackDetectionConfig, AttackDetectionResult, AttackType, DetectorConfig, InputLocation,
    SimpleDetectorConfig,
};
pub use detector_common::{BasePatternDetector, PatternDetector};
pub use header_validation::HeaderValidator;
pub use jwt::JwtDetector;
pub use ldap_injection::LdapInjectionDetector;
pub use libinjection::LibInjectionDetector;
pub use normalizer::{InputNormalizer, NormalizedInput, NormalizedInputs};
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

pub struct AttackDetector {
    config: AttackDetectionConfig,
    normalizer: Arc<InputNormalizer>,
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
}

impl AttackDetector {
    pub fn new(config: AttackDetectionConfig) -> Self {
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

        Self {
            config,
            normalizer,
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
        }
    }

    #[inline]
    pub fn check_request(
        &self,
        method: &http::Method,
        path: &str,
        query_string: Option<&str>,
        headers: &http::HeaderMap,
        body: Option<&[u8]>,
    ) -> Option<AttackDetectionResult> {
        if !self.config.enabled {
            return None;
        }

        if let Some(result) = self.header_validator.validate(headers) {
            return Some(result);
        }

        let inputs = NormalizedInputs::normalize_all(
            &self.normalizer,
            Some(path),
            query_string,
            headers,
            body,
        );

        if self.config.request_smuggling.enabled {
            if let Some(result) = self.check_request_smuggling(headers, body) {
                return Some(result);
            }
        }

        if self.config.jwt.enabled {
            if let Some(result) = self.check_jwt(headers, &inputs) {
                return Some(result);
            }
        }

        if self.config.sqli.enabled {
            if let Some(result) = self.check_sqli(method, &inputs) {
                return Some(result);
            }
        }

        if self.config.xss.enabled {
            if let Some(result) = self.check_xss(method, &inputs) {
                return Some(result);
            }
        }

        if self.config.ssti.enabled {
            if let Some(result) = self.check_ssti(&inputs) {
                return Some(result);
            }
        }

        if self.config.cmd_injection.enabled {
            if let Some(result) = self.check_cmd_injection(&inputs) {
                return Some(result);
            }
        }

        if self.config.path_traversal.enabled {
            if let Some(result) = self.check_path_traversal(&inputs) {
                return Some(result);
            }
        }

        if self.config.rfi.enabled {
            if let Some(result) = self.check_rfi(&inputs) {
                return Some(result);
            }
        }

        if self.config.ssrf.enabled {
            if let Some(result) = self.check_ssrf(&inputs) {
                return Some(result);
            }
        }

        if self.config.xxe.enabled {
            if let Some(result) = self.check_xxe(&inputs) {
                return Some(result);
            }
        }

        if self.config.ldap_injection.enabled {
            if let Some(result) = self.check_ldap_injection(&inputs) {
                return Some(result);
            }
        }

        if self.config.xpath_injection.enabled {
            if let Some(result) = self.check_xpath_injection(&inputs) {
                return Some(result);
            }
        }

        if self.config.open_redirect.enabled {
            if let Some(result) = self.check_open_redirect(&inputs) {
                return Some(result);
            }
        }

        None
    }

    fn check_sqli(
        &self,
        _method: &http::Method,
        inputs: &NormalizedInputs,
    ) -> Option<AttackDetectionResult> {
        if let Some(ref path) = inputs.path {
            if let Some(result) = SqliDetector::detect(path.as_bytes(), InputLocation::Path) {
                return Some(result);
            }
        }

        if let Some(ref qs) = inputs.query_string {
            if let Some(result) = SqliDetector::detect(qs.as_bytes(), InputLocation::QueryString) {
                return Some(result);
            }
        }

        for (name, value) in &inputs.headers {
            if let Some(result) =
                SqliDetector::detect(value.as_bytes(), InputLocation::Header(name.clone().into()))
            {
                return Some(result);
            }
        }

        if let Some(ref body) = inputs.body {
            if let Some(result) = SqliDetector::detect(body.as_bytes(), InputLocation::PostBody) {
                return Some(result);
            }
        }

        None
    }

    fn check_xss(
        &self,
        _method: &http::Method,
        inputs: &NormalizedInputs,
    ) -> Option<AttackDetectionResult> {
        if let Some(ref path) = inputs.path {
            if let Some(result) = XssDetector::detect(path.as_bytes(), InputLocation::Path) {
                return Some(result);
            }
        }

        if let Some(ref qs) = inputs.query_string {
            if let Some(result) = XssDetector::detect(qs.as_bytes(), InputLocation::QueryString) {
                return Some(result);
            }
        }

        for (name, value) in &inputs.headers {
            if let Some(result) =
                XssDetector::detect(value.as_bytes(), InputLocation::Header(name.clone().into()))
            {
                return Some(result);
            }
        }

        if let Some(ref body) = inputs.body {
            if let Some(result) = XssDetector::detect(body.as_bytes(), InputLocation::PostBody) {
                return Some(result);
            }
        }

        None
    }

    fn check_path_traversal(&self, inputs: &NormalizedInputs) -> Option<AttackDetectionResult> {
        if let Some(ref path) = inputs.path {
            if let Some(result) = self
                .path_traversal_detector
                .detect(path.as_str(), InputLocation::Path)
            {
                return Some(result);
            }
        }

        if let Some(ref qs) = inputs.query_string {
            if let Some(result) = self
                .path_traversal_detector
                .detect(qs.as_str(), InputLocation::QueryString)
            {
                return Some(result);
            }
        }

        for (name, value) in &inputs.headers {
            if let Some(result) = self
                .path_traversal_detector
                .detect(value.as_str(), InputLocation::Header(name.clone().into()))
            {
                return Some(result);
            }
        }

        if let Some(ref body) = inputs.body {
            if let Some(result) = self
                .path_traversal_detector
                .detect(body.as_str(), InputLocation::PostBody)
            {
                return Some(result);
            }
        }

        None
    }

    fn check_rfi(&self, inputs: &NormalizedInputs) -> Option<AttackDetectionResult> {
        if let Some(ref qs) = inputs.query_string {
            if let Some(result) = self
                .rfi_detector
                .detect(qs.as_str(), InputLocation::QueryString)
            {
                return Some(result);
            }
        }

        for (name, value) in &inputs.headers {
            if let Some(result) = self
                .rfi_detector
                .detect(value.as_str(), InputLocation::Header(name.clone().into()))
            {
                return Some(result);
            }
        }

        if let Some(ref body) = inputs.body {
            if let Some(result) = self
                .rfi_detector
                .detect(body.as_str(), InputLocation::PostBody)
            {
                return Some(result);
            }
        }

        None
    }

    fn check_ssrf(&self, inputs: &NormalizedInputs) -> Option<AttackDetectionResult> {
        if let Some(ref qs) = inputs.query_string {
            if let Some(result) = self
                .ssrf_detector
                .detect(qs.as_str(), InputLocation::QueryString)
            {
                return Some(result);
            }
        }

        for (name, value) in &inputs.headers {
            if let Some(result) = self
                .ssrf_detector
                .detect(value.as_str(), InputLocation::Header(name.clone().into()))
            {
                return Some(result);
            }
        }

        if let Some(ref body) = inputs.body {
            if let Some(result) = self
                .ssrf_detector
                .detect(body.as_str(), InputLocation::PostBody)
            {
                return Some(result);
            }
        }

        None
    }

    fn check_ssti(&self, inputs: &NormalizedInputs) -> Option<AttackDetectionResult> {
        if let Some(ref path) = inputs.path {
            if let Some(result) = self
                .ssti_detector
                .detect(path.as_str(), InputLocation::Path)
            {
                return Some(result);
            }
        }

        if let Some(ref qs) = inputs.query_string {
            if let Some(result) = self
                .ssti_detector
                .detect(qs.as_str(), InputLocation::QueryString)
            {
                return Some(result);
            }
        }

        for (name, value) in &inputs.headers {
            if let Some(result) = self
                .ssti_detector
                .detect(value.as_str(), InputLocation::Header(name.clone().into()))
            {
                return Some(result);
            }
        }

        if let Some(ref body) = inputs.body {
            if let Some(result) = self
                .ssti_detector
                .detect(body.as_str(), InputLocation::PostBody)
            {
                return Some(result);
            }
        }

        None
    }

    fn check_cmd_injection(&self, inputs: &NormalizedInputs) -> Option<AttackDetectionResult> {
        if let Some(ref path) = inputs.path {
            if let Some(result) = self
                .cmd_injection_detector
                .detect(path.as_str(), InputLocation::Path)
            {
                return Some(result);
            }
        }

        if let Some(ref qs) = inputs.query_string {
            if let Some(result) = self
                .cmd_injection_detector
                .detect(qs.as_str(), InputLocation::QueryString)
            {
                return Some(result);
            }
        }

        for (name, value) in &inputs.headers {
            if let Some(result) = self
                .cmd_injection_detector
                .detect(value.as_str(), InputLocation::Header(name.clone().into()))
            {
                return Some(result);
            }
        }

        if let Some(ref body) = inputs.body {
            if let Some(result) = self
                .cmd_injection_detector
                .detect(body.as_str(), InputLocation::PostBody)
            {
                return Some(result);
            }
        }

        None
    }

    fn check_xxe(&self, inputs: &NormalizedInputs) -> Option<AttackDetectionResult> {
        if let Some(ref qs) = inputs.query_string {
            if let Some(result) = self
                .xxe_detector
                .detect(qs.as_str(), InputLocation::QueryString)
            {
                return Some(result);
            }
        }

        for (name, value) in &inputs.headers {
            if let Some(result) = self
                .xxe_detector
                .detect(value.as_str(), InputLocation::Header(name.clone().into()))
            {
                return Some(result);
            }
        }

        if let Some(ref body) = inputs.body {
            if let Some(result) = self
                .xxe_detector
                .detect(body.as_str(), InputLocation::PostBody)
            {
                return Some(result);
            }
        }

        None
    }

    fn check_jwt(
        &self,
        headers: &http::HeaderMap,
        inputs: &NormalizedInputs,
    ) -> Option<AttackDetectionResult> {
        if let Some(result) = self.jwt_detector.detect_in_headers(headers) {
            return Some(result);
        }

        if let Some(ref qs) = inputs.query_string {
            if let Some(result) = self
                .jwt_detector
                .detect(qs.as_str(), InputLocation::QueryString)
            {
                return Some(result);
            }
        }

        if let Some(ref body) = inputs.body {
            if let Some(result) = self
                .jwt_detector
                .detect(body.as_str(), InputLocation::PostBody)
            {
                return Some(result);
            }
        }

        None
    }

    fn check_request_smuggling(
        &self,
        headers: &http::HeaderMap,
        body: Option<&[u8]>,
    ) -> Option<AttackDetectionResult> {
        if let Some(result) = self.request_smuggling_detector.check_headers(headers) {
            return Some(result);
        }

        if let Some(body_bytes) = body {
            if let Some(result) = self.request_smuggling_detector.check_body(body_bytes) {
                return Some(result);
            }
        }

        None
    }

    fn check_ldap_injection(&self, inputs: &NormalizedInputs) -> Option<AttackDetectionResult> {
        if let Some(ref path) = inputs.path {
            if let Some(result) = self
                .ldap_injection_detector
                .detect(path.as_str(), InputLocation::Path)
            {
                return Some(result);
            }
        }

        if let Some(ref qs) = inputs.query_string {
            if let Some(result) = self
                .ldap_injection_detector
                .detect(qs.as_str(), InputLocation::QueryString)
            {
                return Some(result);
            }
        }

        for (name, value) in &inputs.headers {
            if let Some(result) = self
                .ldap_injection_detector
                .detect(value.as_str(), InputLocation::Header(name.clone().into()))
            {
                return Some(result);
            }
        }

        if let Some(ref body) = inputs.body {
            if let Some(result) = self
                .ldap_injection_detector
                .detect(body.as_str(), InputLocation::PostBody)
            {
                return Some(result);
            }
        }

        None
    }

    fn check_xpath_injection(&self, inputs: &NormalizedInputs) -> Option<AttackDetectionResult> {
        if let Some(ref path) = inputs.path {
            if let Some(result) = self
                .xpath_injection_detector
                .detect(path.as_str(), InputLocation::Path)
            {
                return Some(result);
            }
        }

        if let Some(ref qs) = inputs.query_string {
            if let Some(result) = self
                .xpath_injection_detector
                .detect(qs.as_str(), InputLocation::QueryString)
            {
                return Some(result);
            }
        }

        for (name, value) in &inputs.headers {
            if let Some(result) = self
                .xpath_injection_detector
                .detect(value.as_str(), InputLocation::Header(name.clone().into()))
            {
                return Some(result);
            }
        }

        if let Some(ref body) = inputs.body {
            if let Some(result) = self
                .xpath_injection_detector
                .detect(body.as_str(), InputLocation::PostBody)
            {
                return Some(result);
            }
        }

        None
    }

    fn check_open_redirect(&self, inputs: &NormalizedInputs) -> Option<AttackDetectionResult> {
        if let Some(ref qs) = inputs.query_string {
            if let Some(result) = self
                .open_redirect_detector
                .detect(qs.as_str(), InputLocation::QueryString)
            {
                return Some(result);
            }
        }

        for (name, value) in &inputs.headers {
            if let Some(result) = self
                .open_redirect_detector
                .detect(value.as_str(), InputLocation::Header(name.clone().into()))
            {
                return Some(result);
            }
        }

        if let Some(ref body) = inputs.body {
            if let Some(result) = self
                .open_redirect_detector
                .detect(body.as_str(), InputLocation::PostBody)
            {
                return Some(result);
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
        let result = detector.check_request(&Method::GET, path, query, &headers, body);
        let result = result.expect(&format!(
            "Expected {:?} to be detected in: {}",
            expected, path
        ));
        assert_eq!(result.attack_type, expected);
    }

    fn check_no_detect(path: &str, query: Option<&str>, body: Option<&[u8]>) {
        let detector = AttackDetector::new(AttackDetectionConfig::default());
        let headers = HeaderMap::new();
        let result = detector.check_request(&Method::GET, path, query, &headers, body);
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
        let headers = HeaderMap::new();
        let result = detector.check_request(
            &Method::GET,
            "/search?q=<script>alert('xss')</script>",
            Some("q=<script>alert('xss')</script>"),
            &headers,
            None,
        );
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
        let headers = HeaderMap::new();
        let result = detector.check_request(
            &Method::GET,
            "/search?q=%253Cscript%253Ealert%2528%2527xss%2527%2529%253C%252Fscript%253E",
            Some("q=%253Cscript%253Ealert%2528%2527xss%2527%2529%253C%252Fscript%253E"),
            &headers,
            None,
        );
        assert!(result.is_some());
    }
}
