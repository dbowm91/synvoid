use crate::http::headers::generate_stealth_timestamp;
use crate::theme::{ErrorPageTemplate, ThemeConfig, ThemeRenderer};
use parking_lot::RwLock;
use std::collections::HashMap;
use std::sync::Arc;

// Re-exports from extracted synvoid-waf crate
pub use synvoid_waf::endpoints::{
    EndpointBlockerManager, EndpointCheckResult, RegexValidationResult, SensitiveEndpointManager,
};

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
}
