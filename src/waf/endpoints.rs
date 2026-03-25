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
    use_regex: bool,
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
                use_regex,
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
    exact_matches: Vec<String>,
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
        let mut exact_matches = Vec::new();
        let mut prefix_matches = Vec::new();
        let mut path_prefix_matches = Vec::new();

        for p in paths {
            if p.ends_with("/*") {
                path_prefix_matches.push(p.trim_end_matches("/*").to_string());
            } else if p.contains('*') {
                prefix_matches.push(p.trim_end_matches('*').to_string());
            } else {
                exact_matches.push(p);
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

        for exact in &guard.exact_matches {
            if path == exact {
                return Some(exact.clone());
            }
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
    pub fn from_str(s: &str) -> Self {
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
        let error_page_mode = ErrorPageMode::from_str(mode);

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
