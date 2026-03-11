use aho_corasick::AhoCorasick;
use base64::{engine::general_purpose::STANDARD_NO_PAD, Engine as _};
use std::sync::Arc;

use crate::waf::attack_detection::config::{AttackDetectionResult, AttackType, InputLocation};
use crate::waf::attack_detection::patterns::DefaultPatterns;

pub struct JwtDetector {
    patterns: Arc<AhoCorasick>,
}

impl JwtDetector {
    pub fn new(_paranoia_level: u8, custom_patterns: &[String]) -> Self {
        let mut base_patterns: Vec<String> = DefaultPatterns::jwt()
            .iter()
            .map(|s| s.to_string())
            .collect();

        for pattern in custom_patterns {
            if !base_patterns.contains(pattern) {
                base_patterns.push(pattern.clone());
            }
        }

        let patterns_str: Vec<&str> = base_patterns.iter().map(|s| s.as_str()).collect();
        let patterns = Arc::new(AhoCorasick::new(&patterns_str).unwrap());

        Self { patterns }
    }

    pub fn detect(&self, input: &str, location: InputLocation) -> Option<AttackDetectionResult> {
        if let Some(token) = extract_jwt_token(input) {
            if let Some(result) = self.analyze_jwt(&token, location) {
                return Some(result);
            }
        }

        None
    }

    fn analyze_jwt(&self, token: &str, location: InputLocation) -> Option<AttackDetectionResult> {
        let parts: Vec<&str> = token.split('.').collect();
        if parts.len() != 3 {
            return None;
        }

        let header = decode_jwt_part(parts[0])?;
        let payload = parts[1];
        let signature = parts[2];

        if let Some(result) = self.check_header_attacks(&header, location.clone()) {
            return Some(result);
        }

        if signature.is_empty()
            || signature.trim().is_empty()
            || signature == "''"
            || signature == "\"\""
            || signature == "."
            || signature
                .chars()
                .all(|c| c == '\u{0}' || c.is_ascii_whitespace())
        {
            tracing::warn!(
                attack_type = "jwt",
                location = %location,
                "JWT with empty/invalid signature detected"
            );

            return Some(AttackDetectionResult {
                attack_type: AttackType::Jwt,
                fingerprint: Some("empty_signature".to_string()),
                matched_pattern: None,
                input_location: location,
            });
        }

        if let Some(result) = self.check_payload_attacks(payload, location) {
            return Some(result);
        }

        None
    }

    fn check_header_attacks(
        &self,
        header: &str,
        location: InputLocation,
    ) -> Option<AttackDetectionResult> {
        let header_lower = header.to_lowercase();

        let alg_patterns = [
            "\"alg\":\"none\"",
            "\"alg\":none",
            "\"alg\":\"null\"",
            "\"alg\":null",
            "\"alg\":\"\"",
        ];

        for pattern in alg_patterns {
            if header_lower.contains(pattern) {
                tracing::warn!(
                    attack_type = "jwt",
                    location = %location,
                    "JWT algorithm confusion attack (alg: none/null)"
                );

                return Some(AttackDetectionResult {
                    attack_type: AttackType::Jwt,
                    fingerprint: Some("alg_none".to_string()),
                    matched_pattern: Some(pattern.to_string()),
                    input_location: location,
                });
            }
        }

        if header_lower.contains("\"alg\":")
            && !header_lower.contains("\"alg\":\"hs")
            && !header_lower.contains("\"alg\":\"rs")
            && !header_lower.contains("\"alg\":\"es")
            && !header_lower.contains("\"alg\":\"ps")
        {
            if let Some(start) = header_lower.find("\"alg\":") {
                let rest = &header_lower[start..];
                if let Some(end) =
                    rest.find(|c: char| !c.is_ascii_alphanumeric() && c != '-' && c != '_')
                {
                    let alg_value = &rest[7..end.min(20)];
                    if alg_value.is_empty()
                        || alg_value == "null"
                        || alg_value == "none"
                        || alg_value.len() < 3
                    {
                        tracing::warn!(
                            attack_type = "jwt",
                            location = %location,
                            "JWT suspicious algorithm detected"
                        );

                        return Some(AttackDetectionResult {
                            attack_type: AttackType::Jwt,
                            fingerprint: Some("suspicious_alg".to_string()),
                            matched_pattern: Some(alg_value.to_string()),
                            input_location: location,
                        });
                    }
                }
            }
        }

        if self.patterns.is_match(header) {
            if let Some(mat) = self.patterns.find(header) {
                let matched = header[mat.start()..mat.end()].to_string();

                tracing::warn!(
                    attack_type = "jwt",
                    matched_pattern = %matched,
                    location = %location,
                    "JWT header injection detected"
                );

                return Some(AttackDetectionResult {
                    attack_type: AttackType::Jwt,
                    fingerprint: None,
                    matched_pattern: Some(matched),
                    input_location: location,
                });
            }
        }

        None
    }

    fn check_payload_attacks(
        &self,
        payload: &str,
        location: InputLocation,
    ) -> Option<AttackDetectionResult> {
        let decoded = decode_jwt_part(payload)?;
        let decoded_lower = decoded.to_lowercase();

        let privilege_patterns = [
            "\"admin\":true",
            "\"admin\":1",
            "\"admin\":\"true\"",
            "\"admin\":\"yes\"",
            "\"is_admin\":true",
            "\"is_admin\":1",
            "\"role\":\"admin\"",
            "\"role\":\"superuser\"",
            "\"role\":\"root\"",
            "\"role\":\"moderator\"",
            "\"permissions\":[\"admin\"]",
            "\"permissions\":[\"root\"]",
            "\"user.role\":\"admin\"",
            "\"user.role\":\"root\"",
        ];

        for pattern in privilege_patterns {
            if decoded_lower.contains(pattern) {
                tracing::warn!(
                    attack_type = "jwt",
                    location = %location,
                    "JWT privilege escalation attempt detected"
                );

                return Some(AttackDetectionResult {
                    attack_type: AttackType::Jwt,
                    fingerprint: Some("privilege_escalation".to_string()),
                    matched_pattern: Some(pattern.to_string()),
                    input_location: location,
                });
            }
        }

        None
    }

    pub fn detect_in_headers(&self, headers: &http::HeaderMap) -> Option<AttackDetectionResult> {
        if let Some(auth_header) = headers.get("authorization") {
            if let Ok(auth_str) = auth_header.to_str() {
                if auth_str.starts_with("Bearer ") {
                    let token = &auth_str[7..];
                    return self
                        .analyze_jwt(token, InputLocation::Header("authorization".to_string()));
                }
            }
        }

        if let Some(cookie) = headers.get("cookie") {
            if let Ok(cookie_str) = cookie.to_str() {
                for cookie_part in cookie_str.split(';') {
                    let cookie_part = cookie_part.trim();
                    if cookie_part.starts_with("jwt=") || cookie_part.starts_with("token=") {
                        let token =
                            &cookie_part[cookie_part.find('=').map(|i| i + 1).unwrap_or(0)..];
                        if let Some(result) = self.analyze_jwt(
                            token,
                            InputLocation::Cookie(
                                cookie_part
                                    .split('=')
                                    .next()
                                    .unwrap_or("cookie")
                                    .to_string(),
                            ),
                        ) {
                            return Some(result);
                        }
                    }
                }
            }
        }

        None
    }
}

fn extract_jwt_token(input: &str) -> Option<String> {
    if input.contains('.') && input.matches('.').count() == 2 {
        let parts: Vec<&str> = input.split('.').collect();
        if parts.len() == 3 && !parts[0].is_empty() && !parts[1].is_empty() {
            return Some(input.to_string());
        }
    }

    let patterns = ["jwt=", "token=", "bearer ", "Bearer "];
    for pattern in patterns {
        if let Some(pos) = input.to_lowercase().find(&pattern.to_lowercase()) {
            let start = pos + pattern.len();
            let rest = &input[start..];
            if let Some(end) =
                rest.find(|c: char| c.is_whitespace() || c == '&' || c == ';' || c == ',')
            {
                return Some(rest[..end].to_string());
            } else {
                return Some(rest.to_string());
            }
        }
    }

    None
}

fn decode_jwt_part(part: &str) -> Option<String> {
    let padded = if part.len() % 4 == 0 {
        part.to_string()
    } else {
        let padding = 4 - (part.len() % 4);
        format!("{}{}", part, "=".repeat(padding))
    };

    STANDARD_NO_PAD
        .decode(padded.replace('=', ""))
        .ok()
        .and_then(|bytes| String::from_utf8(bytes).ok())
        .or_else(|| {
            base64::engine::general_purpose::STANDARD
                .decode(padded)
                .ok()
                .and_then(|bytes| String::from_utf8(bytes).ok())
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_jwt_benign() {
        let detector = JwtDetector::new(2, &[]);
        let header = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(r#"{"alg":"HS256","typ":"JWT"}"#);
        let payload = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(r#"{"sub":"123","name":"testuser"}"#);
        let signature = "realsignaturehere123456789";
        let token = format!("{}.{}.{}", header, payload, signature);
        assert!(detector
            .detect(&token, InputLocation::QueryString)
            .is_none());
    }

    #[test]
    fn test_jwt_privilege_escalation() {
        let detector = JwtDetector::new(2, &[]);
        let header = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(r#"{"alg":"HS256","typ":"JWT"}"#);
        let payload = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(r#"{"sub":"123","admin":true}"#);
        let signature = "fake_signature";
        let token = format!("{}.{}.{}", header, payload, signature);
        assert!(detector
            .detect(&token, InputLocation::QueryString)
            .is_some());
    }
}
