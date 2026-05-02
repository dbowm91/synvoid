use aho_corasick::AhoCorasick;
use std::borrow::Cow;
use std::net::IpAddr;
use std::sync::Arc;

use crate::utils::url_decode_all;
use crate::waf::attack_detection::config::{AttackDetectionResult, AttackType, InputLocation};
use crate::waf::attack_detection::detector_common::{BasePatternDetector, PatternDetector};
use crate::waf::attack_detection::patterns::DefaultPatterns;

pub struct SsrfDetector {
    inner: BasePatternDetector,
    block_private_ips: bool,
    allowed_domains_lower: Vec<String>,
    allowlist_only_mode: bool,
}

impl SsrfDetector {
    pub fn new(
        paranoia_level: u8,
        custom_patterns: &[String],
        block_private_ips: bool,
        allowed_domains: Vec<String>,
        allowlist_only_mode: bool,
    ) -> Self {
        let inner = BasePatternDetector::new(
            DefaultPatterns::ssrf().as_slice(),
            DefaultPatterns::ssrf_high().as_slice(),
            custom_patterns,
            paranoia_level,
            AttackType::Ssrf,
            "ssrf",
        );
        Self {
            inner,
            block_private_ips,
            allowed_domains_lower: allowed_domains
                .into_iter()
                .map(|d| d.to_lowercase())
                .collect(),
            allowlist_only_mode,
        }
    }

    fn is_private_ip(ip: &str) -> bool {
        if let Some(normalized) = Self::parse_ipv4_flexible(ip) {
            return Self::check_is_private_ip(&normalized);
        }
        if let Ok(ip_addr) = ip.parse::<IpAddr>() {
            return Self::check_is_private_ip(&ip_addr.to_string());
        }
        false
    }

    fn parse_ipv4_flexible(s: &str) -> Option<String> {
        let s = s.trim();
        if s.is_empty() {
            return None;
        }

        if s.starts_with('0') && s.len() > 1 {
            if s.starts_with("0x") || s.starts_with("0X") {
                return Self::parse_ipv4_hex(s);
            } else if s.chars().all(|c| c.is_ascii_digit()) {
                return Self::parse_ipv4_decimal(s);
            } else if s.chars().all(|c| c.is_ascii_digit() || c == '.') {
                if let Some(result) = Self::parse_ipv4_octal(s) {
                    return Some(result);
                }
            }
        } else if s.chars().all(|c| c.is_ascii_digit()) {
            return Self::parse_ipv4_decimal(s);
        }

        if let Ok(ip) = s.parse::<IpAddr>() {
            return Some(ip.to_string());
        }

        None
    }

    fn parse_ipv4_decimal(s: &str) -> Option<String> {
        let decimal: u64 = s.parse().ok()?;
        if decimal > u32::MAX as u64 {
            return None;
        }
        let ip = u32::try_from(decimal).ok()?;
        let octets = ip.to_be_bytes();
        Some(format!(
            "{}.{}.{}.{}",
            octets[0], octets[1], octets[2], octets[3]
        ))
    }

    fn parse_ipv4_octal(s: &str) -> Option<String> {
        let parts: Vec<&str> = s.split('.').collect();
        if parts.len() != 4 {
            return None;
        }

        let mut octets = [0u8; 4];
        for (i, part) in parts.iter().enumerate() {
            if part.is_empty() {
                return None;
            }
            if part.len() > 1 && part.starts_with('0') {
                let octal: u32 = u32::from_str_radix(part, 8).ok()?;
                if octal > 255 {
                    return None;
                }
                octets[i] = octal as u8;
            } else {
                let decimal: u8 = part.parse().ok()?;
                octets[i] = decimal;
            }
        }

        Some(format!(
            "{}.{}.{}.{}",
            octets[0], octets[1], octets[2], octets[3]
        ))
    }

    fn parse_ipv4_hex(s: &str) -> Option<String> {
        let hex_str = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X"))?;
        let hex: u32 = u32::from_str_radix(hex_str, 16).ok()?;
        let octets = hex.to_be_bytes();
        Some(format!(
            "{}.{}.{}.{}",
            octets[0], octets[1], octets[2], octets[3]
        ))
    }

    fn check_is_private_ip(ip_str: &str) -> bool {
        ip_str.parse::<IpAddr>().is_ok_and(|addr| match addr {
            IpAddr::V4(v4) => {
                let octets = v4.octets();
                octets[0] == 10
                    || (octets[0] == 172 && octets[1] >= 16 && octets[1] <= 31)
                    || (octets[0] == 192 && octets[1] == 168)
                    || (octets[0] == 169 && octets[1] == 254)
                    || octets[0] == 127
            }
            IpAddr::V6(v6) => {
                if let Some(ipv4) = v6.to_ipv4_mapped() {
                    let octets = ipv4.octets();
                    octets[0] == 10
                        || (octets[0] == 172 && octets[1] >= 16 && octets[1] <= 31)
                        || (octets[0] == 192 && octets[1] == 168)
                        || (octets[0] == 169 && octets[1] == 254)
                        || octets[0] == 127
                } else {
                    let segments = v6.segments();
                    segments[0] == 0xFE80
                        || (segments[0] & 0xFE80) == 0xFC00
                        || segments[0] == 0xFF00
                        || segments == [0, 0, 0, 0, 0, 0, 0, 1]
                }
            }
        })
    }

    fn extract_ips_from_url(input_lower: &str) -> Vec<String> {
        let mut ips = Vec::new();

        let mut in_url = false;
        let mut url_start = 0;
        let mut current = 0;
        let bytes = input_lower.as_bytes();

        while current < bytes.len() {
            if current + 4 < bytes.len()
                && bytes[current] == b'h'
                && bytes[current + 1] == b't'
                && bytes[current + 2] == b't'
                && bytes[current + 3] == b'p'
            {
                in_url = true;
                url_start = current;
                current += 4;
                if current < bytes.len() && bytes[current] == b's' {
                    current += 1;
                }
                continue;
            }

            if in_url
                && (bytes[current] == b' '
                    || bytes[current] == b'\n'
                    || bytes[current] == b'\r'
                    || bytes[current] == b'\''
                    || bytes[current] == b'"'
                    || bytes[current] == b'&'
                    || bytes[current] == b';')
            {
                in_url = false;
            }

            if in_url
                && bytes[current] == b'/'
                && current + 1 < bytes.len()
                && bytes[current + 1] == b'/'
            {
                url_start = current + 2;
            }

            if in_url && (bytes[current] == b':' || current == url_start) {
                let start = if bytes[current] == b':' && current > url_start {
                    current + 1
                } else {
                    current
                };
                let remaining = &input_lower[start..];

                if let Some(slash_pos) = remaining.find('/') {
                    let potential_ip = &remaining[..slash_pos];
                    if Self::looks_like_ip(potential_ip) {
                        ips.push(potential_ip.to_string());
                    }
                } else if Self::looks_like_ip(remaining) {
                    ips.push(remaining.to_string());
                }
            }

            if in_url && bytes[current] == b'@' && current + 1 < bytes.len() {
                let after_at = &input_lower[current + 1..];
                if let Some(slash_pos) = after_at.find('/') {
                    let potential_ip = &after_at[..slash_pos];
                    if Self::looks_like_ip(potential_ip) {
                        ips.push(potential_ip.to_string());
                    }
                } else if Self::looks_like_ip(after_at) {
                    ips.push(after_at.to_string());
                }
            }

            current += 1;
        }

        ips
    }

    fn looks_like_ip(s: &str) -> bool {
        let s = s.trim();
        if s.is_empty() {
            return false;
        }
        if let Some(zone_pos) = s.find('%') {
            let without_zone = &s[..zone_pos];
            return Self::looks_like_ip_without_zone(without_zone);
        }
        Self::looks_like_ip_without_zone(s)
    }

    fn looks_like_ip_without_zone(s: &str) -> bool {
        let s = if s.starts_with('[') {
            if let Some(bracket_end) = s.find(']') {
                &s[1..bracket_end]
            } else {
                s
            }
        } else {
            s
        };
        if s.starts_with("0x") || s.starts_with("0X") {
            let hex_part = &s[2..];
            if hex_part.chars().all(|c| c.is_ascii_hexdigit()) && hex_part.len() <= 8 {
                return true;
            }
        }
        if s.starts_with("::ffff:") || s.starts_with("::FFFF:") {
            let after_prefix = &s[7..];
            let colon_count = after_prefix.chars().filter(|&c| c == ':').count();
            if colon_count == 0 && after_prefix.contains('.') {
                if after_prefix.chars().all(|c| c.is_ascii_digit() || c == '.') {
                    return true;
                }
            }
        }
        let colon_count = s.chars().filter(|&c| c == ':').count();
        let s = if colon_count == 1 && s.contains('.') {
            if let Some(colon_pos) = s.find(':') {
                &s[..colon_pos]
            } else {
                s
            }
        } else {
            s
        };
        let is_ipv4 = s.contains('.') && s.chars().all(|c| c.is_ascii_digit() || c == '.');
        let is_ipv6 = s.contains(':') && s.chars().all(|c| c.is_ascii_hexdigit() || c == ':');
        let is_decimal_ip = s.chars().all(|c| c.is_ascii_digit());
        is_ipv4 || is_ipv6 || is_decimal_ip
    }

    fn has_ipv6_zone_id(input: &str) -> bool {
        input.contains('%')
    }

    fn contains_private_ip_or_localhost(input: Cow<str>) -> bool {
        let input_lower: Cow<str> = match &input {
            Cow::Borrowed(s) if s.bytes().any(|b| b.is_ascii_uppercase()) => {
                Cow::Owned(s.to_lowercase())
            }
            _ => input,
        };

        if Self::has_ipv6_zone_id(&input_lower) {
            return true;
        }

        if Self::has_word_boundary(&input_lower, ".localhost")
            || Self::has_word_boundary(&input_lower, "localhost.")
            || Self::has_word_boundary(&input_lower, ".local")
            || Self::has_local_domain_suffix(&input_lower)
        {
            return true;
        }

        if Self::matches_localhost_lookalike(&input_lower) {
            return true;
        }

        for ip in Self::extract_ips_from_url(&input_lower) {
            let normalized = Self::normalize_ip_for_parse(&ip);
            if Self::is_private_ip(&normalized) {
                return true;
            }
        }

        false
    }

    fn matches_localhost_lookalike(input: &str) -> bool {
        let lookalike_patterns = [
            "localhost",
            "localshost",
            "locahost",
            "locaihost",
            "loca1host",
            "iocalhost",
            "1ocalhost",
            "oocalhost",
            "locaihost",
            "iocalhost",
        ];

        for pattern in &lookalike_patterns {
            if let Some(pos) = input.find(pattern) {
                let before_ok = pos == 0 || !input.as_bytes()[pos - 1].is_ascii_alphanumeric();
                let after_pos = pos + pattern.len();
                let after_ok = after_pos >= input.len()
                    || !input.as_bytes()[after_pos].is_ascii_alphanumeric();
                if before_ok && after_ok {
                    return true;
                }
            }
        }

        if let Some(pos) = input.find("127.0.0.1") {
            let before_ok = pos == 0 || input.as_bytes()[pos - 1] == b'.';
            let after_pos = pos + "127.0.0.1".len();
            let after_ok = after_pos >= input.len() || input.as_bytes()[after_pos] == b':';
            if before_ok && after_ok {
                return true;
            }
        }

        false
    }

    fn has_word_boundary(input: &str, substring: &str) -> bool {
        if let Some(pos) = input.find(substring) {
            let before_ok = pos == 0 || input.as_bytes()[pos - 1] == b'.';
            let after_pos = pos + substring.len();
            let after_ok = after_pos >= input.len()
                || input.as_bytes()[after_pos] == b'.'
                || input.as_bytes()[after_pos] == b':';
            before_ok && after_ok
        } else {
            false
        }
    }

    fn has_local_domain_suffix(input: &str) -> bool {
        input.contains(".local")
    }

    fn normalize_ip_for_parse(s: &str) -> String {
        let s = s.trim();
        if s.is_empty() {
            return String::new();
        }
        if let Some(zone_pos) = s.find('%') {
            let without_zone = &s[..zone_pos];
            return Self::normalize_ip_for_parse_inner(without_zone);
        }
        Self::normalize_ip_for_parse_inner(s)
    }

    fn normalize_ip_for_parse_inner(s: &str) -> String {
        // Strip IPv6 brackets
        let s = if s.starts_with('[') {
            if let Some(bracket_end) = s.find(']') {
                &s[1..bracket_end]
            } else {
                s
            }
        } else {
            s
        };
        // Strip IPv4 port (single colon + digits)
        let colon_count = s.chars().filter(|&c| c == ':').count();
        if colon_count == 1 && s.contains('.') {
            if let Some(colon_pos) = s.find(':') {
                return s[..colon_pos].to_string();
            }
        }
        s.to_string()
    }

    fn is_allowed_domain(&self, input_lower: &str) -> bool {
        if self.allowed_domains_lower.is_empty() {
            return self.allowlist_only_mode;
        }
        self.allowed_domains_lower.iter().any(|domain| {
            if input_lower == domain {
                return true;
            }
            let dot_domain = domain.as_str();
            if input_lower.len() > dot_domain.len()
                && input_lower[input_lower.len() - dot_domain.len()..].starts_with('.')
            {
                let prefix_idx = input_lower.len() - dot_domain.len() - 1;
                let prefix = &input_lower[..prefix_idx];
                if !prefix.is_empty() && !prefix.contains('.') && !prefix.contains(':') {
                    return true;
                }
            }
            let search_str = format!(".{}", dot_domain);
            if let Some(pos) = input_lower.find(&search_str) {
                if pos > 0 && input_lower.as_bytes()[pos - 1] == b'.' {
                    let before_dot = &input_lower[..pos - 1];
                    if !before_dot.contains('.') && !before_dot.contains(':') {
                        return true;
                    }
                }
            }
            if self.allowlist_only_mode {
                if Self::has_word_boundary(input_lower, dot_domain) {
                    return true;
                }
            }
            false
        })
    }

    fn detect_with_url_decode(
        &self,
        input: &str,
        location: InputLocation,
    ) -> Option<AttackDetectionResult> {
        let decoded_lower: Cow<str> = if input.contains('%') || input.contains('+') {
            Cow::Owned(url_decode_all(input))
        } else if input.bytes().any(|b| b.is_ascii_uppercase()) {
            Cow::Owned(input.to_lowercase())
        } else {
            Cow::Borrowed(input)
        };

        if self.is_allowed_domain(&decoded_lower) {
            return None;
        }

        if let Some(mat) = self.inner.patterns_ref().find(decoded_lower.as_ref()) {
            let matched = decoded_lower[mat.start()..mat.end()].to_string();
            tracing::warn!(
                attack_type = "ssrf",
                matched_pattern = %matched,
                location = %location,
                "SSRF attack detected"
            );
            return Some(AttackDetectionResult {
                attack_type: AttackType::Ssrf,
                fingerprint: None,
                matched_pattern: Some(matched),
                input_location: location,
            });
        }

        if self.block_private_ips && Self::contains_private_ip_or_localhost(decoded_lower.clone()) {
            tracing::warn!(
                attack_type = "ssrf",
                location = %location,
                "SSRF with private IP detected"
            );
            return Some(AttackDetectionResult {
                attack_type: AttackType::Ssrf,
                fingerprint: None,
                matched_pattern: Some("private_ip".to_string()),
                input_location: location,
            });
        }

        None
    }
}

impl PatternDetector for SsrfDetector {
    fn patterns(&self) -> &Arc<AhoCorasick> {
        self.inner.patterns()
    }

    fn detect(&self, input: &str, location: InputLocation) -> Option<AttackDetectionResult> {
        self.detect_with_url_decode(input, location)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ssrf_localhost() {
        let detector = SsrfDetector::new(2, &[], true, vec![], false);
        assert!(detector
            .detect("http://localhost/admin", InputLocation::QueryString)
            .is_some());
    }

    #[test]
    fn test_ssrf_metadata() {
        let detector = SsrfDetector::new(2, &[], true, vec![], false);
        assert!(detector
            .detect(
                "http://169.254.169.254/latest/meta-data",
                InputLocation::QueryString
            )
            .is_some());
    }

    #[test]
    fn test_ssrf_private_ip() {
        let detector = SsrfDetector::new(2, &[], true, vec![], false);
        assert!(detector
            .detect("http://192.168.1.1/secret", InputLocation::QueryString)
            .is_some());
    }

    #[test]
    fn test_ssrf_benign() {
        let detector = SsrfDetector::new(2, &[], true, vec![], false);
        assert!(detector
            .detect("https://api.example.com/data", InputLocation::QueryString)
            .is_none());
    }

    #[test]
    fn test_ssrf_10_network() {
        let detector = SsrfDetector::new(2, &[], true, vec![], false);
        assert!(detector
            .detect("http://10.0.0.1/admin", InputLocation::QueryString)
            .is_some());
    }

    #[test]
    fn test_ssrf_172_network() {
        let detector = SsrfDetector::new(2, &[], true, vec![], false);
        assert!(detector
            .detect("http://172.16.0.1/admin", InputLocation::QueryString)
            .is_some());
    }

    #[test]
    fn test_ssrf_localdomain() {
        let detector = SsrfDetector::new(2, &[], true, vec![], false);
        assert!(detector
            .detect("http://server.local/internal", InputLocation::QueryString)
            .is_some());
    }

    #[test]
    fn test_ssrf_ipv6_localhost() {
        let detector = SsrfDetector::new(2, &[], true, vec![], false);
        assert!(detector
            .detect("http://[::1]:8080/admin", InputLocation::QueryString)
            .is_some());
    }

    #[test]
    fn test_ssrf_url_encoded() {
        let detector = SsrfDetector::new(2, &[], true, vec![], false);
        assert!(detector
            .detect("http%3A%2F%2Flocalhost%2Fadmin", InputLocation::QueryString)
            .is_some());
    }

    #[test]
    fn test_ssrf_no_block() {
        let detector = SsrfDetector::new(2, &[], false, vec![], false);
        assert!(detector
            .detect("http://192.168.1.1/secret", InputLocation::QueryString)
            .is_none());
    }

    #[test]
    fn test_ssrf_127_loopback() {
        let detector = SsrfDetector::new(2, &[], true, vec![], false);
        assert!(detector
            .detect("http://127.0.0.1:8080/admin", InputLocation::QueryString)
            .is_some());
    }

    #[test]
    fn test_ssrf_attack_type_field() {
        let detector = SsrfDetector::new(2, &[], true, vec![], false);
        let result = detector
            .detect("http://localhost/admin", InputLocation::QueryString)
            .unwrap();
        assert_eq!(result.attack_type, AttackType::Ssrf);
    }

    #[test]
    fn test_ssrf_attack_type_metadata() {
        let detector = SsrfDetector::new(2, &[], true, vec![], false);
        let result = detector
            .detect(
                "http://169.254.169.254/latest/meta-data",
                InputLocation::QueryString,
            )
            .unwrap();
        assert_eq!(result.attack_type, AttackType::Ssrf);
        assert!(result.matched_pattern.is_some());
    }

    #[test]
    fn test_ssrf_url_encoded_ip() {
        let detector = SsrfDetector::new(2, &[], true, vec![], false);
        assert!(detector
            .detect("http://%3127.0.0.1/admin", InputLocation::QueryString)
            .is_some());
    }

    #[test]
    fn test_ssrf_case_insensitive_localhost_uppercase() {
        let detector = SsrfDetector::new(2, &[], true, vec![], false);
        assert!(detector
            .detect("http://LOCALHOST/admin", InputLocation::QueryString)
            .is_some());
    }

    #[test]
    fn test_ssrf_case_insensitive_localhost_mixed() {
        let detector = SsrfDetector::new(2, &[], true, vec![], false);
        assert!(detector
            .detect("http://LocalHost/admin", InputLocation::QueryString)
            .is_some());
    }

    #[test]
    fn test_ssrf_case_insensitive_localhost_alternating() {
        let detector = SsrfDetector::new(2, &[], true, vec![], false);
        assert!(detector
            .detect("http://lOcAlHoSt/admin", InputLocation::QueryString)
            .is_some());
    }

    #[test]
    fn test_ssrf_ipv6_loopback_bare() {
        let detector = SsrfDetector::new(2, &[], true, vec![], false);
        assert!(detector
            .detect("http://::1/admin", InputLocation::QueryString)
            .is_some());
    }

    #[test]
    fn test_ssrf_ipv6_loopback_bracketed() {
        let detector = SsrfDetector::new(2, &[], true, vec![], false);
        assert!(detector
            .detect("http://[::1]/admin", InputLocation::QueryString)
            .is_some());
    }

    #[test]
    fn test_ssrf_cloud_metadata_path() {
        let detector = SsrfDetector::new(2, &[], true, vec![], false);
        let result = detector
            .detect(
                "http://169.254.169.254/computeMetadata/v1/",
                InputLocation::PostBody,
            )
            .unwrap();
        assert_eq!(result.attack_type, AttackType::Ssrf);
        assert!(matches!(result.input_location, InputLocation::PostBody));
    }

    #[test]
    fn test_ssrf_octal_ip_detected() {
        let detector = SsrfDetector::new(2, &[], true, vec![], false);
        assert!(detector
            .detect("http://0177.0.0.1/admin", InputLocation::QueryString)
            .is_some());
    }

    #[test]
    fn test_ssrf_decimal_ip_detected() {
        let detector = SsrfDetector::new(2, &[], true, vec![], false);
        assert!(detector
            .detect("http://2130706433/admin", InputLocation::QueryString)
            .is_some());
    }

    #[test]
    fn test_ssrf_input_location_preserved() {
        let detector = SsrfDetector::new(2, &[], true, vec![], false);
        let result = detector
            .detect("http://192.168.1.1/secret", InputLocation::Path)
            .unwrap();
        assert!(matches!(result.input_location, InputLocation::Path));
    }

    #[test]
    fn test_ssrf_matched_pattern_present() {
        let detector = SsrfDetector::new(2, &[], true, vec![], false);
        let result = detector
            .detect("http://localhost/admin", InputLocation::QueryString)
            .unwrap();
        assert!(result.matched_pattern.is_some());
    }

    #[test]
    fn test_ssrf_no_block_private_allows_private() {
        let detector = SsrfDetector::new(2, &[], false, vec![], false);
        assert!(detector
            .detect("http://10.0.0.1/admin", InputLocation::QueryString)
            .is_none());
    }

    #[test]
    fn test_ssrf_no_block_private_still_detects_pattern_ips() {
        let detector = SsrfDetector::new(2, &[], false, vec![], false);
        assert!(detector
            .detect(
                "http://169.254.169.254/latest/meta-data",
                InputLocation::QueryString
            )
            .is_some());
    }

    #[test]
    fn test_ssrf_hex_ip_detected() {
        let detector = SsrfDetector::new(2, &[], true, vec![], false);
        assert!(detector
            .detect("http://0x7f000001/admin", InputLocation::QueryString)
            .is_some());
    }

    #[test]
    fn test_ssrf_allowlist_subdomain_allowed_allowlist_mode() {
        let detector = SsrfDetector::new(2, &[], true, vec!["allowed.com".to_string()], true);
        assert!(detector
            .detect("http://sub.allowed.com/admin", InputLocation::QueryString)
            .is_none());
        assert!(detector
            .detect(
                "http://deep.sub.allowed.com/admin",
                InputLocation::QueryString
            )
            .is_none());
    }

    #[test]
    fn test_ssrf_allowlist_subdomain_allowed() {
        let detector = SsrfDetector::new(2, &[], true, vec!["allowed.com".to_string()], false);
        assert!(detector
            .detect("http://sub.allowed.com/admin", InputLocation::QueryString)
            .is_none());
        assert!(detector
            .detect(
                "http://deep.sub.allowed.com/admin",
                InputLocation::QueryString
            )
            .is_none());
    }

    #[test]
    fn test_ssrf_allowlist_suffix_bypass_still_pattern_matched() {
        let detector = SsrfDetector::new(2, &[], true, vec!["allowed.com".to_string()], false);
        assert!(detector
            .detect(
                "http://allowed.com.attacker.tld/admin",
                InputLocation::QueryString
            )
            .is_none());
    }

    #[test]
    fn test_ssrf_allowlist_exact_match() {
        let detector =
            SsrfDetector::new(2, &[], true, vec!["trusted.example.com".to_string()], false);
        assert!(detector
            .detect(
                "http://trusted.example.com/path",
                InputLocation::QueryString
            )
            .is_none());
        assert!(detector
            .detect(
                "http://sub.trusted.example.com/path",
                InputLocation::QueryString
            )
            .is_none());
    }

    #[test]
    fn test_ssrf_ipv6_mapped_loopback() {
        let detector = SsrfDetector::new(2, &[], true, vec![], false);
        assert!(detector
            .detect(
                "http://[::ffff:127.0.0.1]/admin",
                InputLocation::QueryString
            )
            .is_some());
    }

    #[test]
    fn test_ssrf_ipv6_link_local() {
        let detector = SsrfDetector::new(2, &[], true, vec![], false);
        assert!(detector
            .detect("http://[fe80::1]/admin", InputLocation::QueryString)
            .is_some());
    }

    #[test]
    fn test_ssrf_userinfo_in_url_blocked() {
        let detector = SsrfDetector::new(2, &[], true, vec![], false);
        assert!(detector
            .detect("http://user@127.0.0.1/admin", InputLocation::QueryString)
            .is_some());
    }

    #[test]
    fn test_ssrf_userinfo_with_trusted_domain_allowed() {
        let detector = SsrfDetector::new(2, &[], true, vec!["example.com".to_string()], true);
        assert!(detector
            .detect("http://user@example.com/admin", InputLocation::QueryString)
            .is_none());
    }
}
