use std::fmt;

/// Error returned when a redirect target is rejected by policy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RedirectRejection {
    /// Target contained CRLF characters (\\r or \\n).
    CrlfInjection,
    /// Target contained control characters (ASCII 0-31 or 127).
    ControlCharacter,
    /// Target was an absolute URL whose host is not in the allow list.
    HostNotAllowed(String),
    /// Target was a relative path that did not start with `/` or started with `//`.
    InvalidRelativePath,
}

impl fmt::Display for RedirectRejection {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RedirectRejection::CrlfInjection => {
                write!(f, "redirect target rejected: contains CRLF characters")
            }
            RedirectRejection::ControlCharacter => {
                write!(f, "redirect target rejected: contains control characters")
            }
            RedirectRejection::HostNotAllowed(host) => {
                write!(
                    f,
                    "redirect target rejected: host '{}' is not in the allowed list",
                    host
                )
            }
            RedirectRejection::InvalidRelativePath => {
                write!(
                    f,
                    "redirect target rejected: relative path must start with / and not //"
                )
            }
        }
    }
}

impl std::error::Error for RedirectRejection {}

/// Escape `&`, `<`, `>`, `"`, `'` for safe interpolation into HTML text content.
pub fn html_escape(input: &str) -> String {
    let mut out = String::with_capacity(input.len() * 2);
    for c in input.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#x27;"),
            _ => out.push(c),
        }
    }
    out
}

/// Escape `&`, `<`, `>`, `"`, `'` for safe interpolation into HTML attribute values.
///
/// Functionally identical to [`html_escape`], but documents the attribute context
/// (e.g. inside `href=""`, `class=""`, etc.) where quote characters are equally
/// dangerous as in text content.
pub fn html_attr_escape(input: &str) -> String {
    html_escape(input)
}

/// Escape a string for safe inclusion inside a JavaScript string literal (single- or
/// double-quoted). Handles `\`, `'`, `"`, newlines, tabs, and angle brackets.
pub fn js_string_escape(input: &str) -> String {
    let mut out = String::with_capacity(input.len() * 2);
    for c in input.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            '\'' => out.push_str("\\'"),
            '"' => out.push_str("\\\""),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '<' => out.push_str("\\x3c"),
            '>' => out.push_str("\\x3e"),
            '&' => out.push_str("\\x26"),
            _ => out.push(c),
        }
    }
    out
}

/// Percent-encode a string for safe use as a URL path segment (RFC 3986).
///
/// Unreserved characters (`A-Z`, `a-z`, `0-9`, `-`, `.`, `_`, `~`) pass through.
/// Everything else is percent-encoded.
pub fn url_path_encode(input: &str) -> String {
    let mut out = String::with_capacity(input.len() * 3);
    for b in input.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                out.push(b as char);
            }
            _ => {
                out.push_str(&format!("%{:02X}", b));
            }
        }
    }
    out
}

/// Validate a redirect target against policy rules.
///
/// # Rules
/// - CRLF characters (`\r`, `\n`) are always rejected.
/// - Control characters (ASCII 0–31, 127) are always rejected.
/// - Absolute URLs (`http://` or `https://`) are only allowed if the host appears in
///   `allowed_hosts`.
/// - Relative paths must start with `/` and must not start with `//`.
pub fn sanitize_redirect_target(
    target: &str,
    allowed_hosts: &[String],
) -> Result<String, RedirectRejection> {
    // Reject CRLF
    if target.contains('\r') || target.contains('\n') {
        return Err(RedirectRejection::CrlfInjection);
    }

    // Reject control characters (0-31, 127)
    if target.chars().any(|c| {
        let b = c as u32;
        b < 32 || b == 127
    }) {
        return Err(RedirectRejection::ControlCharacter);
    }

    // Absolute URL check
    if let Some(rest) = target
        .strip_prefix("https://")
        .or_else(|| target.strip_prefix("http://"))
    {
        // Extract host (everything before the next / or end)
        let host = rest.split('/').next().unwrap_or(rest);
        let host_lower = host.to_ascii_lowercase();
        if allowed_hosts
            .iter()
            .any(|h| h.to_ascii_lowercase() == host_lower)
        {
            Ok(target.to_string())
        } else {
            Err(RedirectRejection::HostNotAllowed(host.to_string()))
        }
    } else if target.starts_with('/') {
        // Relative path: must not start with //
        if target.starts_with("//") {
            Err(RedirectRejection::InvalidRelativePath)
        } else {
            Ok(target.to_string())
        }
    } else {
        Err(RedirectRejection::InvalidRelativePath)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // --- HTML escaping ---

    #[test]
    fn html_escape_xss_script_tag() {
        let input = "<script>alert('xss')</script>";
        let escaped = html_escape(input);
        assert!(escaped.contains("&lt;script&gt;"));
        assert!(escaped.contains("&lt;/script&gt;"));
        assert!(!escaped.contains("<script>"));
        assert!(escaped.contains("alert(&#x27;xss&#x27;)"));
    }

    #[test]
    fn html_escape_ampersand() {
        assert_eq!(html_escape("a & b"), "a &amp; b");
    }

    #[test]
    fn html_escape_double_quote() {
        assert_eq!(html_escape(r#"say "hello""#), "say &quot;hello&quot;");
    }

    #[test]
    fn html_escape_passthrough() {
        assert_eq!(html_escape("hello world"), "hello world");
    }

    // --- Attribute escaping ---

    #[test]
    fn html_attr_escape_quotes_in_href() {
        let input = r#"page" onclick="alert(1)"#;
        let escaped = html_attr_escape(input);
        assert!(escaped.contains("&quot;"));
        assert!(!escaped.contains(r#"""#));
    }

    #[test]
    fn html_attr_escape_single_quotes() {
        let input = "it's";
        let escaped = html_attr_escape(input);
        assert!(escaped.contains("it&#x27;s"));
    }

    // --- JS string escaping ---

    #[test]
    fn js_string_escape_newlines() {
        let input = "line1\nline2\rline3";
        let escaped = js_string_escape(input);
        assert!(escaped.contains("\\n"));
        assert!(escaped.contains("\\r"));
        assert!(!escaped.contains('\n'));
        assert!(!escaped.contains('\r'));
    }

    #[test]
    fn js_string_escape_quotes() {
        let input = r#"say "hi" and 'bye'"#;
        let escaped = js_string_escape(input);
        assert!(escaped.contains("\\\"hi\\\""));
        assert!(escaped.contains("\\'bye\\'"));
    }

    #[test]
    fn js_string_escape_angle_brackets() {
        let input = "<script>alert(1)</script>";
        let escaped = js_string_escape(input);
        assert!(escaped.contains("\\x3cscript\\x3e"));
        assert!(escaped.contains("\\x3c/script\\x3e"));
    }

    #[test]
    fn js_string_escape_backslash() {
        let input = "path\\to\\file";
        let escaped = js_string_escape(input);
        // Each \ in input becomes \\ in output
        assert_eq!(escaped, "path\\\\to\\\\file");
    }

    // --- URL path encoding ---

    #[test]
    fn url_path_encode_special_chars() {
        let input = "/path with spaces";
        let encoded = url_path_encode(input);
        assert!(encoded.contains("%20"));
        assert!(!encoded.contains(' '));
    }

    #[test]
    fn url_path_encode_unreserved_passthrough() {
        let input = "hello-world_123";
        assert_eq!(url_path_encode(input), "hello-world_123");
    }

    #[test]
    fn url_path_encode_slashes_encoded() {
        let input = "a/b";
        let encoded = url_path_encode(input);
        assert!(encoded.contains("%2F"));
        assert!(!encoded.contains('/'));
    }

    // --- Redirect sanitization ---

    #[test]
    fn redirect_crlf_injection_blocked() {
        let result = sanitize_redirect_target("http://example.com/path\r\nEvil-Header: yes", &[]);
        assert_eq!(result, Err(RedirectRejection::CrlfInjection));
    }

    #[test]
    fn redirect_crlf_newline_only_blocked() {
        let result = sanitize_redirect_target("http://example.com/path\nEvil", &[]);
        assert_eq!(result, Err(RedirectRejection::CrlfInjection));
    }

    #[test]
    fn redirect_open_redirect_blocked() {
        let result =
            sanitize_redirect_target("https://evil.com/steal", &["example.com".to_string()]);
        assert!(matches!(result, Err(RedirectRejection::HostNotAllowed(_))));
    }

    #[test]
    fn redirect_relative_path_allowed() {
        let result = sanitize_redirect_target("/safe/path", &[]);
        assert_eq!(result, Ok("/safe/path".to_string()));
    }

    #[test]
    fn redirect_relative_double_slash_rejected() {
        let result = sanitize_redirect_target("//evil.com/path", &[]);
        assert_eq!(result, Err(RedirectRejection::InvalidRelativePath));
    }

    #[test]
    fn redirect_absolute_allowed_host() {
        let result =
            sanitize_redirect_target("https://example.com/page", &["example.com".to_string()]);
        assert_eq!(result, Ok("https://example.com/page".to_string()));
    }

    #[test]
    fn redirect_control_chars_rejected() {
        let result = sanitize_redirect_target("/path\x01\x02", &[]);
        assert_eq!(result, Err(RedirectRejection::ControlCharacter));
    }

    #[test]
    fn redirect_delete_char_rejected() {
        let result = sanitize_redirect_target("/path\x7f", &[]);
        assert_eq!(result, Err(RedirectRejection::ControlCharacter));
    }

    #[test]
    fn redirect_empty_string_rejected() {
        let result = sanitize_redirect_target("", &[]);
        assert_eq!(result, Err(RedirectRejection::InvalidRelativePath));
    }

    #[test]
    fn redirect_no_scheme_rejected() {
        let result = sanitize_redirect_target("evil.com/steal", &[]);
        assert_eq!(result, Err(RedirectRejection::InvalidRelativePath));
    }

    #[test]
    fn redirect_rejection_display() {
        let err = RedirectRejection::HostNotAllowed("evil.com".to_string());
        let msg = format!("{}", err);
        assert!(msg.contains("evil.com"));
        assert!(msg.contains("not in the allowed list"));
    }

    #[test]
    fn redirect_multiple_hosts_allowed() {
        let hosts = vec!["example.com".to_string(), "trusted.org".to_string()];
        assert_eq!(
            sanitize_redirect_target("https://trusted.org/path", &hosts),
            Ok("https://trusted.org/path".to_string())
        );
    }

    #[test]
    fn redirect_port_in_host() {
        let hosts = vec!["example.com:8080".to_string()];
        assert_eq!(
            sanitize_redirect_target("https://example.com:8080/page", &hosts),
            Ok("https://example.com:8080/page".to_string())
        );
    }
}
