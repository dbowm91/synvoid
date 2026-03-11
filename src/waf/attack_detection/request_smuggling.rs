use crate::waf::attack_detection::config::{AttackDetectionResult, AttackType, InputLocation};

pub struct RequestSmugglingDetector;

impl RequestSmugglingDetector {
    pub fn new() -> Self {
        Self
    }

    pub fn check_headers(&self, headers: &http::HeaderMap) -> Option<AttackDetectionResult> {
        let has_cl = headers.contains_key("content-length");
        let has_te = headers.contains_key("transfer-encoding");

        if has_cl && has_te {
            if let Some(te_value) = headers.get("transfer-encoding") {
                if let Ok(te_str) = te_value.to_str() {
                    let te_lower = te_str.to_lowercase();

                    if te_lower.contains("chunked") {
                        tracing::warn!(
                            attack_type = "request_smuggling",
                            "HTTP Request Smuggling: Both Content-Length and Transfer-Encoding: chunked present"
                        );

                        return Some(AttackDetectionResult {
                            attack_type: AttackType::RequestSmuggling,
                            fingerprint: Some("cl_te_conflict".to_string()),
                            matched_pattern: Some(
                                "Content-Length + Transfer-Encoding: chunked".to_string(),
                            ),
                            input_location: InputLocation::Header("transfer-encoding".to_string()),
                        });
                    }
                }
            }
        }

        if let Some(te_value) = headers.get("transfer-encoding") {
            if let Ok(te_str) = te_value.to_str() {
                let te_lower = te_str.to_lowercase();

                if te_lower.contains("chunked,") || te_lower.contains("chunked;") {
                    tracing::warn!(
                        attack_type = "request_smuggling",
                        "HTTP Request Smuggling: Multiple Transfer-Encoding values"
                    );

                    return Some(AttackDetectionResult {
                        attack_type: AttackType::RequestSmuggling,
                        fingerprint: Some("multiple_te".to_string()),
                        matched_pattern: Some(te_str.to_string()),
                        input_location: InputLocation::Header("transfer-encoding".to_string()),
                    });
                }

                if te_lower.contains("x")
                    || te_lower.contains("identity") && te_lower.contains("chunked")
                {
                    tracing::warn!(
                        attack_type = "request_smuggling",
                        "HTTP Request Smuggling: Obfuscated Transfer-Encoding"
                    );

                    return Some(AttackDetectionResult {
                        attack_type: AttackType::RequestSmuggling,
                        fingerprint: Some("obfuscated_te".to_string()),
                        matched_pattern: Some(te_str.to_string()),
                        input_location: InputLocation::Header("transfer-encoding".to_string()),
                    });
                }
            }
        }

        if let Some(cl_value) = headers.get("content-length") {
            if let Ok(cl_str) = cl_value.to_str() {
                if let Ok(cl_num) = cl_str.parse::<u64>() {
                    if cl_num > 10_000_000 {
                        tracing::warn!(
                            attack_type = "request_smuggling",
                            "HTTP Request Smuggling: Suspiciously large Content-Length"
                        );

                        return Some(AttackDetectionResult {
                            attack_type: AttackType::RequestSmuggling,
                            fingerprint: Some("large_cl".to_string()),
                            matched_pattern: Some(format!("Content-Length: {}", cl_num)),
                            input_location: InputLocation::Header("content-length".to_string()),
                        });
                    }
                } else {
                    tracing::warn!(
                        attack_type = "request_smuggling",
                        "HTTP Request Smuggling: Invalid Content-Length value"
                    );

                    return Some(AttackDetectionResult {
                        attack_type: AttackType::RequestSmuggling,
                        fingerprint: Some("invalid_cl".to_string()),
                        matched_pattern: Some(cl_str.to_string()),
                        input_location: InputLocation::Header("content-length".to_string()),
                    });
                }
            }
        }

        for header_name in &[
            "x-forwarded-host",
            "x-original-url",
            "x-rewrite-url",
            "x-host",
        ] {
            if let Some(value) = headers.get(*header_name) {
                if let Ok(value_str) = value.to_str() {
                    if value_str.contains('\r') || value_str.contains('\n') {
                        tracing::warn!(
                            attack_type = "request_smuggling",
                            header = %header_name,
                            "HTTP Request Smuggling: CRLF injection in header"
                        );

                        return Some(AttackDetectionResult {
                            attack_type: AttackType::RequestSmuggling,
                            fingerprint: Some("crlf_injection".to_string()),
                            matched_pattern: Some(format!("{}: {}", header_name, value_str)),
                            input_location: InputLocation::Header(header_name.to_string()),
                        });
                    }
                }
            }
        }

        None
    }

    pub fn check_body(&self, body: &[u8]) -> Option<AttackDetectionResult> {
        if body.len() < 10 {
            return None;
        }

        let body_str = String::from_utf8_lossy(body);

        if body_str.starts_with("GET ")
            || body_str.starts_with("POST ")
            || body_str.starts_with("PUT ")
            || body_str.starts_with("DELETE ")
        {
            tracing::warn!(
                attack_type = "request_smuggling",
                "HTTP Request Smuggling: HTTP request in body (smuggled request)"
            );

            return Some(AttackDetectionResult {
                attack_type: AttackType::RequestSmuggling,
                fingerprint: Some("request_in_body".to_string()),
                matched_pattern: Some(body_str.chars().take(50).collect()),
                input_location: InputLocation::PostBody,
            });
        }

        if body_str.contains("\r\n\r\nGET ") || body_str.contains("\r\n\r\nPOST ") {
            tracing::warn!(
                attack_type = "request_smuggling",
                "HTTP Request Smuggling: Multiple HTTP requests in body"
            );

            return Some(AttackDetectionResult {
                attack_type: AttackType::RequestSmuggling,
                fingerprint: Some("multiple_requests".to_string()),
                matched_pattern: Some("embedded HTTP request".to_string()),
                input_location: InputLocation::PostBody,
            });
        }

        None
    }
}

impl Default for RequestSmugglingDetector {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use http::HeaderMap;

    #[test]
    fn test_cl_te_smuggling() {
        let detector = RequestSmugglingDetector::new();
        let mut headers = HeaderMap::new();
        headers.insert("content-length", "100".parse().unwrap());
        headers.insert("transfer-encoding", "chunked".parse().unwrap());

        assert!(detector.check_headers(&headers).is_some());
    }

    #[test]
    fn test_multiple_te() {
        let detector = RequestSmugglingDetector::new();
        let mut headers = HeaderMap::new();
        headers.insert("transfer-encoding", "chunked, identity".parse().unwrap());

        assert!(detector.check_headers(&headers).is_some());
    }

    #[test]
    fn test_smuggled_request_in_body() {
        let detector = RequestSmugglingDetector::new();
        let body = b"GET /admin HTTP/1.1\r\nHost: localhost\r\n\r\n";

        assert!(detector.check_body(body).is_some());
    }

    #[test]
    fn test_benign_request() {
        let detector = RequestSmugglingDetector::new();
        let mut headers = HeaderMap::new();
        headers.insert("content-length", "100".parse().unwrap());

        assert!(detector.check_headers(&headers).is_none());
    }
}
