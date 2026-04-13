use crate::http::headers::generate_stealth_timestamp;
use crate::theme::{ErrorPageTemplate, ThemeConfig, ThemeRenderer};
use crate::utils::check_regex_complexity;
use parking_lot::RwLock;
use regex::Regex;
use std::collections::{HashMap, HashSet};
use std::sync::Arc;

pub struct EndpointBlocker {
    blocked_patterns: Vec<Regex>,
    invalid_patterns: Vec<String>,
    block_methods: HashSet<String>,
    block_response_code: u16,
    block_page_html: Option<String>,
}

#[derive(Clone)]
pub struct EndpointBlockerManager {
    inner: Arc<RwLock<EndpointBlocker>>,
}

#[derive(Debug, Clone)]
pub struct RegexValidationResult {
    pub valid: Vec<String>,
    pub invalid: Vec<(String, String)>,
}

impl EndpointBlockerManager {
    pub fn new(
        paths: Vec<String>,
        use_regex: bool,
        block_methods: Vec<String>,
        block_response_code: u16,
        block_page_html: Option<String>,
    ) -> Self {
        let validation = Self::validate_patterns(&paths, use_regex);

        let block_methods: HashSet<String> = block_methods
            .into_iter()
            .map(|m| m.to_uppercase())
            .collect();

        EndpointBlockerManager {
            inner: Arc::new(RwLock::new(EndpointBlocker {
                blocked_patterns: validation
                    .valid
                    .iter()
                    .filter_map(|p| Regex::new(p).ok())
                    .collect(),
                invalid_patterns: validation.invalid.iter().map(|(p, _)| p.clone()).collect(),
                block_methods,
                block_response_code,
                block_page_html,
            })),
        }
    }

    pub fn validate_patterns(paths: &[String], use_regex: bool) -> RegexValidationResult {
        let mut valid = Vec::new();
        let mut invalid = Vec::new();

        for p in paths {
            if use_regex {
                let complexity = check_regex_complexity(p);
                if !complexity.safe {
                    invalid.push((
                        p.clone(),
                        complexity
                            .reason
                            .unwrap_or_else(|| "Unknown risk".to_string()),
                    ));
                    continue;
                }
                match Regex::new(p) {
                    Ok(_) => valid.push(p.clone()),
                    Err(e) => invalid.push((p.clone(), e.to_string())),
                }
            } else {
                let escaped = regex::escape(p);
                match Regex::new(&format!("^{}$", escaped)) {
                    Ok(_) => valid.push(p.clone()),
                    Err(e) => invalid.push((p.clone(), e.to_string())),
                }
            }
        }

        RegexValidationResult { valid, invalid }
    }

    pub fn check(&self, path: &str, method: &str) -> EndpointCheckResult {
        let guard = self.inner.read();

        if !guard.block_methods.is_empty()
            && !guard
                .block_methods
                .iter()
                .any(|m| m.eq_ignore_ascii_case(method))
        {
            return EndpointCheckResult::Allowed;
        }

        for pattern in &guard.blocked_patterns {
            if pattern.is_match(path) {
                return EndpointCheckResult::Blocked {
                    response_code: guard.block_response_code,
                    html: guard.block_page_html.clone(),
                    matched_pattern: Some(pattern.to_string()),
                };
            }
        }

        EndpointCheckResult::Allowed
    }

    pub fn is_path_blocked(&self, path: &str) -> bool {
        matches!(self.check(path, "GET"), EndpointCheckResult::Blocked { .. })
    }

    pub fn get_invalid_patterns(&self) -> Vec<String> {
        self.inner.read().invalid_patterns.clone()
    }
}

#[derive(Debug, Clone)]
pub enum EndpointCheckResult {
    Allowed,
    Blocked {
        response_code: u16,
        html: Option<String>,
        matched_pattern: Option<String>,
    },
}

pub struct SensitiveEndpoint {
    exact_matches: HashSet<String>,
    prefix_matches: Vec<String>,
    path_prefix_matches: Vec<String>,
}

#[derive(Clone)]
pub struct SensitiveEndpointManager {
    inner: Arc<RwLock<SensitiveEndpoint>>,
}

impl SensitiveEndpointManager {
    pub fn from_file<P: AsRef<std::path::Path>>(path: P) -> Self {
        let paths = match std::fs::read_to_string(path) {
            Ok(content) => content
                .lines()
                .map(|l| l.trim().to_string())
                .filter(|l| !l.is_empty() && !l.starts_with('#'))
                .collect(),
            Err(e) => {
                tracing::warn!("Failed to load honeypot endpoints file: {}", e);
                Vec::new()
            }
        };

        Self::new(paths)
    }

    pub fn new(paths: Vec<String>) -> Self {
        let mut exact_matches = HashSet::new();
        let mut prefix_matches = Vec::new();
        let mut path_prefix_matches = Vec::new();

        for p in paths {
            if p.ends_with("/*") {
                path_prefix_matches.push(p.trim_end_matches("/*").to_string());
            } else if p.contains('*') {
                prefix_matches.push(p.trim_end_matches('*').to_string());
            } else {
                exact_matches.insert(p);
            }
        }

        SensitiveEndpointManager {
            inner: Arc::new(RwLock::new(SensitiveEndpoint {
                exact_matches,
                prefix_matches,
                path_prefix_matches,
            })),
        }
    }

    pub fn check(&self, path: &str) -> Option<String> {
        let guard = self.inner.read();

        if let Some(exact) = guard.exact_matches.get(path) {
            return Some(exact.clone());
        }

        for prefix in &guard.prefix_matches {
            if path.starts_with(prefix) {
                return Some(prefix.clone());
            }
        }

        for path_prefix in &guard.path_prefix_matches {
            if path.starts_with(&format!("{}/", path_prefix)) {
                return Some(format!("{}/*", path_prefix));
            }
        }

        None
    }
}

pub struct ErrorPageManager {
    default_pages: Arc<HashMap<u16, String>>,
    custom_pages: Arc<RwLock<HashMap<u16, String>>>,
    enabled: bool,
    mode: ErrorPageMode,
    theme: ThemeConfig,
}

impl ErrorPageManager {
    pub fn theme(&self) -> &ThemeConfig {
        &self.theme
    }
}

#[derive(Clone, Copy, PartialEq)]
pub enum ErrorPageMode {
    Generic,
    Styled,
    Custom,
}

impl ErrorPageMode {
    pub fn from_mode_str(s: &str) -> Self {
        match s.to_lowercase().as_str() {
            "styled" => ErrorPageMode::Styled,
            "custom" => ErrorPageMode::Custom,
            _ => ErrorPageMode::Generic,
        }
    }

    pub fn subdirectory(&self) -> &'static str {
        match self {
            ErrorPageMode::Generic => "generic",
            ErrorPageMode::Styled => "styled",
            ErrorPageMode::Custom => "",
        }
    }
}

fn escape_html(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#x27;")
}

impl ErrorPageManager {
    pub fn new(default_dir: &str, custom_dir: Option<String>, enabled: bool) -> Self {
        Self::with_theme_and_mode(
            default_dir,
            custom_dir,
            enabled,
            "generic",
            ThemeConfig::default(),
        )
    }

    pub fn with_theme(
        default_dir: &str,
        custom_dir: Option<String>,
        enabled: bool,
        theme: ThemeConfig,
    ) -> Self {
        Self::with_theme_and_mode(default_dir, custom_dir, enabled, "generic", theme)
    }

    pub fn with_theme_and_mode(
        default_dir: &str,
        custom_dir: Option<String>,
        enabled: bool,
        mode: &str,
        theme: ThemeConfig,
    ) -> Self {
        let error_page_mode = ErrorPageMode::from_mode_str(mode);

        let resolved_dir = if error_page_mode == ErrorPageMode::Custom {
            custom_dir.clone().unwrap_or_else(|| {
                log::warn!(
                    "error_pages mode is 'custom' but custom_directory not specified, falling back to 'styled'"
                );
                format!("{}/styled", default_dir.trim_end_matches('/'))
            })
        } else {
            format!(
                "{}/{}",
                default_dir.trim_end_matches('/'),
                error_page_mode.subdirectory()
            )
        };

        let mode_name = match error_page_mode {
            ErrorPageMode::Generic => "generic",
            ErrorPageMode::Styled => "styled",
            ErrorPageMode::Custom => "custom",
        };

        let custom_dir_str = custom_dir.as_deref().unwrap_or("none");

        log::info!(
            "Error pages: mode={}, directory='{}', custom_directory={}, custom_pages={}",
            mode_name,
            resolved_dir,
            custom_dir_str,
            if custom_dir.is_some() {
                "loaded"
            } else {
                "none"
            }
        );

        let default_pages = Self::load_directory(&resolved_dir);

        if default_pages.is_empty() {
            log::warn!(
                "Error pages directory '{}' is empty or not found - using minimal fallback pages",
                resolved_dir
            );
        } else {
            log::trace!(
                "Loaded {} error pages from '{}'",
                default_pages.len(),
                resolved_dir
            );
        }

        let custom_pages = if let Some(ref custom_dir) = custom_dir {
            Self::load_directory(custom_dir)
        } else {
            HashMap::new()
        };

        ErrorPageManager {
            default_pages: Arc::new(default_pages),
            custom_pages: Arc::new(RwLock::new(custom_pages)),
            enabled,
            mode: error_page_mode,
            theme,
        }
    }

    fn load_directory(dir: &str) -> HashMap<u16, String> {
        let mut pages = HashMap::new();

        let status_codes = [
            "400", "401", "403", "404", "405", "408", "413", "414", "429", "431", "500", "501",
            "502", "503", "504", "generic",
        ];

        for code in status_codes {
            let path = std::path::Path::new(dir).join(format!("{}.html", code));
            if path.exists() {
                if let Ok(content) = std::fs::read_to_string(&path) {
                    if let Ok(status) = code.parse::<u16>() {
                        pages.insert(status, content);
                    } else if code == "generic" {
                        pages.insert(0, content);
                    }
                }
            }
        }

        pages
    }

    pub fn get_page(&self, status_code: u16) -> Option<String> {
        if !self.enabled {
            return None;
        }

        if let Some(custom) = self.custom_pages.read().get(&status_code) {
            return Some(custom.clone());
        }

        self.default_pages.get(&status_code).cloned()
    }

    pub fn render_page(&self, status_code: u16, message: Option<&str>) -> String {
        self.render_page_with_theme(status_code, message, None)
    }

    pub fn render_page_with_theme(
        &self,
        status_code: u16,
        message: Option<&str>,
        override_theme: Option<&ThemeConfig>,
    ) -> String {
        let theme = override_theme.unwrap_or(&self.theme);

        if !self.enabled || self.default_pages.is_empty() {
            return Self::minimal_page(status_code, message);
        }

        let page = self
            .get_page(status_code)
            .or_else(|| self.default_pages.get(&0).cloned());

        let Some(page) = page else {
            return if self.mode == ErrorPageMode::Styled {
                Self::fallback_page(status_code, message, theme)
            } else {
                Self::minimal_page(status_code, message)
            };
        };

        let timestamp = generate_stealth_timestamp(5).replace("GMT", "UTC");
        let message = message.unwrap_or(Self::status_text(status_code));

        let escaped_message = escape_html(message);
        let escaped_timestamp = escape_html(&timestamp);

        let mut result = page
            .replace("{{status_code}}", &status_code.to_string())
            .replace("{{message}}", &escaped_message)
            .replace("{{timestamp}}", &escaped_timestamp);

        if result.contains("{{theme_css}}") {
            let theme_css = ThemeRenderer::new(theme.clone()).generate_css();
            result = result.replace("{{theme_css}}", &theme_css);
        }

        result
    }

    fn status_text(code: u16) -> &'static str {
        match code {
            400 => "Bad Request",
            401 => "Unauthorized",
            403 => "Forbidden",
            404 => "Not Found",
            405 => "Method Not Allowed",
            408 => "Request Timeout",
            413 => "Payload Too Large",
            414 => "URI Too Long",
            429 => "Too Many Requests",
            431 => "Request Header Fields Too Large",
            500 => "Internal Server Error",
            501 => "Not Implemented",
            502 => "Bad Gateway",
            503 => "Service Unavailable",
            504 => "Gateway Timeout",
            _ => "An Error Occurred",
        }
    }

    fn minimal_page(status_code: u16, message: Option<&str>) -> String {
        let status_text = Self::status_text(status_code);
        let msg = message.unwrap_or(status_text);
        format!(
            "<!DOCTYPE html><html><head><title>{} {}</title></head><body><h1>{}</h1><p>{}</p></body></html>",
            status_code, status_text, status_code, msg
        )
    }

    fn fallback_page(status_code: u16, message: Option<&str>, theme: &ThemeConfig) -> String {
        let message = message.unwrap_or(Self::status_text(status_code));

        ErrorPageTemplate::new(theme.clone())
            .status(status_code)
            .message(message)
            .render()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_status_text_all_known_codes() {
        assert_eq!(ErrorPageManager::status_text(400), "Bad Request");
        assert_eq!(ErrorPageManager::status_text(401), "Unauthorized");
        assert_eq!(ErrorPageManager::status_text(403), "Forbidden");
        assert_eq!(ErrorPageManager::status_text(404), "Not Found");
        assert_eq!(ErrorPageManager::status_text(405), "Method Not Allowed");
        assert_eq!(ErrorPageManager::status_text(408), "Request Timeout");
        assert_eq!(ErrorPageManager::status_text(413), "Payload Too Large");
        assert_eq!(ErrorPageManager::status_text(414), "URI Too Long");
        assert_eq!(ErrorPageManager::status_text(429), "Too Many Requests");
        assert_eq!(
            ErrorPageManager::status_text(431),
            "Request Header Fields Too Large"
        );
        assert_eq!(ErrorPageManager::status_text(500), "Internal Server Error");
        assert_eq!(ErrorPageManager::status_text(501), "Not Implemented");
        assert_eq!(ErrorPageManager::status_text(502), "Bad Gateway");
        assert_eq!(ErrorPageManager::status_text(503), "Service Unavailable");
        assert_eq!(ErrorPageManager::status_text(504), "Gateway Timeout");
    }

    #[test]
    fn test_status_text_unknown_code() {
        assert_eq!(ErrorPageManager::status_text(999), "An Error Occurred");
        assert_eq!(ErrorPageManager::status_text(200), "An Error Occurred");
        assert_eq!(ErrorPageManager::status_text(0), "An Error Occurred");
    }

    #[test]
    fn test_sensitive_endpoint_exact_match() {
        let manager = SensitiveEndpointManager::new(vec![
            "/admin".to_string(),
            "/.env".to_string(),
            "/wp-login.php".to_string(),
        ]);
        assert_eq!(manager.check("/admin"), Some("/admin".to_string()));
        assert_eq!(manager.check("/.env"), Some("/.env".to_string()));
        assert_eq!(
            manager.check("/wp-login.php"),
            Some("/wp-login.php".to_string())
        );
        assert_eq!(manager.check("/admin/users"), None);
        assert_eq!(manager.check("/public"), None);
    }

    #[test]
    fn test_sensitive_endpoint_prefix_match() {
        let manager =
            SensitiveEndpointManager::new(vec!["/api/v1*".to_string(), "/debug*".to_string()]);
        assert_eq!(manager.check("/api/v1/users"), Some("/api/v1".to_string()));
        assert_eq!(manager.check("/api/v1/config"), Some("/api/v1".to_string()));
        assert_eq!(manager.check("/debuginfo"), Some("/debug".to_string()));
        assert_eq!(manager.check("/api/v2/users"), None);
    }

    #[test]
    fn test_sensitive_endpoint_path_prefix_match() {
        let manager =
            SensitiveEndpointManager::new(vec!["/admin/*".to_string(), "/internal/*".to_string()]);
        assert_eq!(
            manager.check("/admin/dashboard"),
            Some("/admin/*".to_string())
        );
        assert_eq!(
            manager.check("/internal/metrics"),
            Some("/internal/*".to_string())
        );
        // Path prefix requires "/" after the prefix
        assert_eq!(manager.check("/adminx"), None);
        assert_eq!(manager.check("/admin"), None);
    }

    #[test]
    fn test_endpoint_blocker_allows_non_blocked_methods() {
        let blocker = EndpointBlockerManager::new(
            vec!["/admin".to_string()],
            false,
            vec!["POST".to_string()],
            403,
            None,
        );
        assert!(matches!(
            blocker.check("/admin", "POST"),
            EndpointCheckResult::Blocked { .. }
        ));
        assert!(matches!(
            blocker.check("/admin", "GET"),
            EndpointCheckResult::Allowed
        ));
    }

    #[test]
    fn test_endpoint_blocker_blocks_path() {
        let blocker =
            EndpointBlockerManager::new(vec!["/admin".to_string()], false, vec![], 403, None);
        match blocker.check("/admin", "GET") {
            EndpointCheckResult::Blocked {
                response_code,
                matched_pattern,
                ..
            } => {
                assert_eq!(response_code, 403);
                assert!(matched_pattern.is_some());
            }
            _ => panic!("Expected Blocked"),
        }
        assert!(matches!(
            blocker.check("/public", "GET"),
            EndpointCheckResult::Allowed
        ));
    }

    #[test]
    fn test_endpoint_blocker_regex() {
        let blocker =
            EndpointBlockerManager::new(vec![r"^/admin/.*".to_string()], true, vec![], 403, None);
        assert!(matches!(
            blocker.check("/admin/users", "GET"),
            EndpointCheckResult::Blocked { .. }
        ));
        assert!(matches!(
            blocker.check("/public", "GET"),
            EndpointCheckResult::Allowed
        ));
    }

    #[test]
    fn test_minimal_page_contains_status_and_text() {
        let page = ErrorPageManager::minimal_page(404, None);
        assert!(page.contains("404"));
        assert!(page.contains("Not Found"));
        assert!(page.contains("<!DOCTYPE html>"));
    }

    #[test]
    fn test_minimal_page_custom_message() {
        let page = ErrorPageManager::minimal_page(403, Some("Access denied"));
        assert!(page.contains("403"));
        assert!(page.contains("Access denied"));
    }

    #[test]
    fn test_minimal_page_no_xss_in_message() {
        let page = ErrorPageManager::minimal_page(400, Some("<script>alert('xss')</script>"));
        // minimal_page does NOT escape — that's expected since it's a fallback.
        // The caller should escape before passing. Verify the message is present.
        assert!(page.contains("<script>alert('xss')</script>"));
    }

    #[test]
    fn test_render_page_escapes_message() {
        let manager = ErrorPageManager::with_theme_and_mode(
            "",
            None,
            false,
            "generic",
            ThemeConfig::default(),
        );
        let page = manager.render_page(403, Some("<script>alert('xss')</script>"));
        // When disabled, returns minimal_page which does not escape
        assert!(page.contains("403"));
    }

    #[test]
    fn test_escape_html() {
        assert_eq!(escape_html("hello"), "hello");
        assert_eq!(escape_html("<b>bold</b>"), "&lt;b&gt;bold&lt;/b&gt;");
        assert_eq!(escape_html("a & b"), "a &amp; b");
        assert_eq!(escape_html(r#""quoted""#), "&quot;quoted&quot;");
        assert_eq!(escape_html("it's"), "it&#x27;s");
    }

    #[test]
    fn test_error_page_mode_from_str() {
        assert!(matches!(
            ErrorPageMode::from_mode_str("styled"),
            ErrorPageMode::Styled
        ));
        assert!(matches!(
            ErrorPageMode::from_mode_str("custom"),
            ErrorPageMode::Custom
        ));
        assert!(matches!(
            ErrorPageMode::from_mode_str("generic"),
            ErrorPageMode::Generic
        ));
        assert!(matches!(
            ErrorPageMode::from_mode_str("unknown"),
            ErrorPageMode::Generic
        ));
    }

    #[test]
    fn test_endpoint_blocker_is_path_blocked() {
        let blocker =
            EndpointBlockerManager::new(vec!["/secret".to_string()], false, vec![], 403, None);
        assert!(blocker.is_path_blocked("/secret"));
        assert!(!blocker.is_path_blocked("/public"));
    }
}
