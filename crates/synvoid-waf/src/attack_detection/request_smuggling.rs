use crate::attack_detection::config::{AttackDetectionResult, AttackType, InputLocation};

pub enum HttpVersion {
    Http10,
    Http11,
    Http2,
    Http3,
}

pub struct RequestSmugglingDetector;

impl RequestSmugglingDetector {
    pub fn new() -> Self {
        Self
    }

    fn te_contains_chunked(te_str: &str) -> bool {
        te_str
            .split(',')
            .map(|v| v.trim().to_lowercase())
            .any(|v| v == "chunked")
    }

    fn te_contains_chunked_with_other(te_str: &str) -> bool {
        let values: Vec<&str> = te_str.split(',').collect();
        if values.len() < 2 {
            return false;
        }
        let lower_values: Vec<String> = values.iter().map(|v| v.trim().to_lowercase()).collect();
        let has_chunked = lower_values.iter().any(|v| v == "chunked");
        has_chunked
    }

    fn te_contains_identity_and_chunked(te_str: &str) -> bool {
        let lower = te_str.to_lowercase();
        let has_identity = lower.split(',').any(|v| v.trim() == "identity");
        let has_chunked = lower.split(',').any(|v| v.trim() == "chunked");
        has_identity && has_chunked
    }

    fn te_has_obfuscated_values(te_str: &str) -> bool {
        te_str
            .split(',')
            .any(|v| v.trim().starts_with('x') || v.trim().contains("/x"))
    }

    pub fn check_headers(&self, headers: &http::HeaderMap) -> Option<AttackDetectionResult> {
        let cl_values = headers.get_all("content-length");
        let te_values = headers.get_all("transfer-encoding");

        if cl_values.iter().count() > 1 {
            tracing::warn!(
                attack_type = "request_smuggling",
                "HTTP Request Smuggling: Duplicate Content-Length headers"
            );

            return Some(AttackDetectionResult {
                attack_type: AttackType::RequestSmuggling,
                fingerprint: Some("duplicate_cl".to_string()),
                matched_pattern: Some("Multiple Content-Length headers".to_string()),
                input_location: InputLocation::Header("content-length".into()),
            });
        }

        if te_values.iter().count() > 1 {
            tracing::warn!(
                attack_type = "request_smuggling",
                "HTTP Request Smuggling: Duplicate Transfer-Encoding headers"
            );

            return Some(AttackDetectionResult {
                attack_type: AttackType::RequestSmuggling,
                fingerprint: Some("duplicate_te".to_string()),
                matched_pattern: Some("Multiple Transfer-Encoding headers".to_string()),
                input_location: InputLocation::Header("transfer-encoding".into()),
            });
        }

        let has_cl = cl_values.iter().next().is_some();
        let has_te = te_values.iter().next().is_some();

        if has_cl && has_te {
            if let Some(te_value) = headers.get("transfer-encoding") {
                if let Ok(te_str) = te_value.to_str() {
                    if Self::te_contains_chunked(te_str) {
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
                            input_location: InputLocation::Header("transfer-encoding".into()),
                        });
                    }
                }
            }
        }

        if let Some(te_value) = headers.get("transfer-encoding") {
            if let Ok(te_str) = te_value.to_str() {
                if Self::te_contains_chunked_with_other(te_str) {
                    tracing::warn!(
                        attack_type = "request_smuggling",
                        "HTTP Request Smuggling: Multiple Transfer-Encoding values"
                    );

                    return Some(AttackDetectionResult {
                        attack_type: AttackType::RequestSmuggling,
                        fingerprint: Some("multiple_te".to_string()),
                        matched_pattern: Some(te_str.to_string()),
                        input_location: InputLocation::Header("transfer-encoding".into()),
                    });
                }

                let is_obfuscated_te = Self::te_has_obfuscated_values(te_str);
                if is_obfuscated_te || Self::te_contains_identity_and_chunked(te_str) {
                    tracing::warn!(
                        attack_type = "request_smuggling",
                        "HTTP Request Smuggling: Obfuscated Transfer-Encoding"
                    );

                    return Some(AttackDetectionResult {
                        attack_type: AttackType::RequestSmuggling,
                        fingerprint: Some("obfuscated_te".to_string()),
                        matched_pattern: Some(te_str.to_string()),
                        input_location: InputLocation::Header("transfer-encoding".into()),
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
                            input_location: InputLocation::Header("content-length".into()),
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
                        input_location: InputLocation::Header("content-length".into()),
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
                            input_location: InputLocation::Header((*header_name).into()),
                        });
                    }
                }
            }
        }

        None
    }

    pub fn check_http2_smuggling(
        &self,
        headers: &http::HeaderMap,
        pseudo_headers: &[(&str, &str)],
        body: Option<&[u8]>,
    ) -> Option<AttackDetectionResult> {
        if let Some(result) = self.check_pseudo_header_manipulation(pseudo_headers) {
            return Some(result);
        }

        if let Some(result) = self.check_header_splitting(headers) {
            return Some(result);
        }

        if let Some(result) = self.check_h2_downgrade_attack(headers) {
            return Some(result);
        }

        if let Some(result) = self.check_h2_body_smuggling(headers, body) {
            return Some(result);
        }

        None
    }

    fn check_pseudo_header_manipulation(
        &self,
        pseudo_headers: &[(&str, &str)],
    ) -> Option<AttackDetectionResult> {
        let pseudo_header_names = [":method", ":path", ":authority", ":scheme", ":protocol"];
        let mut pseudo_header_counts = std::collections::HashMap::new();

        for (name, _) in pseudo_headers {
            if pseudo_header_names.contains(name) {
                *pseudo_header_counts.entry(*name).or_insert(0) += 1;
            }
        }

        for (header, count) in &pseudo_header_counts {
            if *count > 1 {
                tracing::warn!(
                    attack_type = "request_smuggling",
                    "HTTP/2 Request Smuggling: Duplicate pseudo-header {} (count: {})",
                    header,
                    count
                );

                return Some(AttackDetectionResult {
                    attack_type: AttackType::RequestSmuggling,
                    fingerprint: Some("duplicate_pseudo_header".to_string()),
                    matched_pattern: Some(format!("Duplicate {}: count={}", header, count)),
                    input_location: InputLocation::Header(header.to_string().into()),
                });
            }
        }

        for (name, value) in pseudo_headers {
            if pseudo_header_names.contains(name) {
                if value.is_empty() {
                    tracing::warn!(
                        attack_type = "request_smuggling",
                        "HTTP/2 Request Smuggling: Empty pseudo-header {}",
                        name
                    );

                    return Some(AttackDetectionResult {
                        attack_type: AttackType::RequestSmuggling,
                        fingerprint: Some("empty_pseudo_header".to_string()),
                        matched_pattern: Some(format!("Empty {}", name)),
                        input_location: InputLocation::Header(name.to_string().into()),
                    });
                }

                if *name == ":path" && (value.contains('\r') || value.contains('\n')) {
                    tracing::warn!(
                        attack_type = "request_smuggling",
                        "HTTP/2 Request Smuggling: CRLF in :path pseudo-header"
                    );

                    return Some(AttackDetectionResult {
                        attack_type: AttackType::RequestSmuggling,
                        fingerprint: Some("crlf_in_pseudo_header".to_string()),
                        matched_pattern: Some(":path contains CRLF".to_string()),
                        input_location: InputLocation::Header(":path".into()),
                    });
                }

                if *name == ":authority" && value.contains(':') {
                    let parts: Vec<&str> = value.splitn(2, ':').collect();
                    if parts.len() == 2 {
                        if let Ok(port) = parts[1].parse::<u16>() {
                            if port == 0 {
                                tracing::warn!(
                                    attack_type = "request_smuggling",
                                    "HTTP/2 Request Smuggling: Port 0 in :authority"
                                );

                                return Some(AttackDetectionResult {
                                    attack_type: AttackType::RequestSmuggling,
                                    fingerprint: Some("zero_port_authority".to_string()),
                                    matched_pattern: Some(":authority with port 0".to_string()),
                                    input_location: InputLocation::Header(":authority".into()),
                                });
                            }
                        }
                    }
                }
            }
        }

        None
    }

    fn check_header_value_splitting(
        &self,
        name_str: &str,
        val_str: &str,
    ) -> Option<AttackDetectionResult> {
        if val_str.contains('\n') || val_str.contains('\r') {
            tracing::warn!(
                attack_type = "request_smuggling",
                "HTTP/2 Request Smuggling: Header value splitting detected in {}",
                name_str
            );

            return Some(AttackDetectionResult {
                attack_type: AttackType::RequestSmuggling,
                fingerprint: Some("header_value_splitting".to_string()),
                matched_pattern: Some(format!("{} contains line breaks", name_str)),
                input_location: InputLocation::Header(name_str.into()),
            });
        }
        None
    }

    fn check_header_field_splitting(
        &self,
        name_str: &str,
        val_str: &str,
    ) -> Option<AttackDetectionResult> {
        let values: Vec<&str> = val_str.split(',').map(|v| v.trim()).collect();
        if values.len() > 1 {
            for v in &values {
                if v.starts_with("chunked")
                    || v.contains("transfer-encoding")
                    || v.contains("content-length")
                {
                    tracing::warn!(
                        attack_type = "request_smuggling",
                        "HTTP/2 Request Smuggling: Header field splitting in {} with smuggling indicator",
                        name_str
                    );

                    return Some(AttackDetectionResult {
                        attack_type: AttackType::RequestSmuggling,
                        fingerprint: Some("header_field_splitting".to_string()),
                        matched_pattern: Some(format!(
                            "{} split with value containing: {}",
                            name_str, v
                        )),
                        input_location: InputLocation::Header(name_str.into()),
                    });
                }
            }
        }
        None
    }

    fn check_header_splitting(&self, headers: &http::HeaderMap) -> Option<AttackDetectionResult> {
        let smuggling_indicators = [
            "transfer-encoding",
            "content-length",
            "x-forwarded-for",
            "x-forwarded-host",
            "x-forwarded-proto",
            "x-real-ip",
            "x-original-url",
            "x-rewrite-url",
        ];

        for (name, value) in headers.iter() {
            let name_str = name.as_str().to_lowercase();
            if smuggling_indicators.contains(&name_str.as_str()) {
                if let Ok(val_str) = value.to_str() {
                    if let Some(result) = self.check_header_value_splitting(&name_str, val_str) {
                        return Some(result);
                    }

                    if let Some(result) = self.check_header_field_splitting(&name_str, val_str) {
                        return Some(result);
                    }
                }
            }
        }

        None
    }

    fn check_h2_downgrade_attack(
        &self,
        headers: &http::HeaderMap,
    ) -> Option<AttackDetectionResult> {
        let has_upgrade = headers
            .get("upgrade")
            .and_then(|v| v.to_str().ok())
            .map(|v| v.to_lowercase().contains("h2c"))
            .unwrap_or(false);

        let has_connection_upgrade = headers
            .get("connection")
            .and_then(|v| v.to_str().ok())
            .map(|v| v.to_lowercase().contains("upgrade"))
            .unwrap_or(false);

        let has_http2_settings = headers.contains_key("http2-settings");

        if has_upgrade && has_connection_upgrade {
            if let Some(upgrade_val) = headers.get("upgrade") {
                if let Ok(upgrade_str) = upgrade_val.to_str() {
                    if upgrade_str.to_lowercase().contains("h2c") {
                        tracing::warn!(
                            attack_type = "request_smuggling",
                            "HTTP/2 Request Smuggling: H2C upgrade detected (potential downgrade attack)"
                        );

                        return Some(AttackDetectionResult {
                            attack_type: AttackType::RequestSmuggling,
                            fingerprint: Some("h2c_upgrade".to_string()),
                            matched_pattern: Some(
                                "Upgrade: h2c with Connection: upgrade".to_string(),
                            ),
                            input_location: InputLocation::Header("upgrade".into()),
                        });
                    }
                }
            }
        }

        if has_http2_settings {
            if let Some(settings_val) = headers.get("http2-settings") {
                if let Ok(settings_str) = settings_val.to_str() {
                    if settings_str.contains("initial_window_size")
                        || settings_str.contains("max_frame_size")
                    {
                        let window_size = settings_str
                            .split(',')
                            .find(|s| s.trim().starts_with("initial_window_size"))
                            .and_then(|s| s.split('=').nth(1))
                            .and_then(|v| v.trim().parse::<u32>().ok());

                        if let Some(window_size) = window_size {
                            if window_size > 16_777_215 {
                                tracing::warn!(
                                    attack_type = "request_smuggling",
                                    "HTTP/2 Request Smuggling: Suspicious initial_window_size in HTTP2-Settings"
                                );

                                return Some(AttackDetectionResult {
                                    attack_type: AttackType::RequestSmuggling,
                                    fingerprint: Some("h2_settings_window_size".to_string()),
                                    matched_pattern: Some(format!(
                                        "initial_window_size={}",
                                        window_size
                                    )),
                                    input_location: InputLocation::Header("http2-settings".into()),
                                });
                            }
                        }
                    }
                }
            }
        }

        None
    }

    fn check_h2_body_smuggling(
        &self,
        headers: &http::HeaderMap,
        body: Option<&[u8]>,
    ) -> Option<AttackDetectionResult> {
        let has_content_type = headers.contains_key("content-type");
        let has_transfer_encoding = headers.contains_key("transfer-encoding");

        if has_content_type && !has_transfer_encoding {
            if let Some(ct) = headers.get("content-type") {
                if let Ok(ct_str) = ct.to_str() {
                    let ct_lower = ct_str.to_lowercase();

                    if ct_lower.contains("multipart") {
                        if let Some(body) = body {
                            if body.len() > 1024 * 1024 {
                                let boundary = ct_lower
                                    .split("boundary=")
                                    .nth(1)
                                    .map(|b| b.split(';').next().unwrap_or(b).trim_matches('"'));

                                if let Some(boundary) = boundary {
                                    let body_str = String::from_utf8_lossy(body);
                                    let boundary_count = body_str.matches(boundary).count();

                                    if boundary_count > 100 {
                                        tracing::warn!(
                                            attack_type = "request_smuggling",
                                            "HTTP/2 Request Smuggling: Multipart bomb detected ({} boundaries)",
                                            boundary_count
                                        );

                                        return Some(AttackDetectionResult {
                                            attack_type: AttackType::RequestSmuggling,
                                            fingerprint: Some("multipart_bomb".to_string()),
                                            matched_pattern: Some(format!(
                                                "Multipart with {} boundaries",
                                                boundary_count
                                            )),
                                            input_location: InputLocation::PostBody,
                                        });
                                    }
                                }
                            }
                        }
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
