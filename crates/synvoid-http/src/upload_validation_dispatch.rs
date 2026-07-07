use bytes::Bytes;
use http::Response;
use http_body_util::combinators::BoxBody;
use std::convert::Infallible;
use std::net::IpAddr;
use std::sync::Arc;

use synvoid_config::MainConfig;
use synvoid_upload::{is_upload_content_type, UploadValidationError, UploadValidator};

pub trait UploadValidationWaf {
    fn get_upload_validator(&self) -> Option<Arc<UploadValidator>>;

    fn block_ip_with_threat_intel(&self, ip: IpAddr, reason: &str, duration_secs: u64, scope: &str);

    fn render_upload_validation_error_page(
        &self,
        status_code: u16,
        message: Option<&str>,
    ) -> String;
}

pub async fn maybe_handle_upload_validation<W: UploadValidationWaf>(
    waf: Arc<W>,
    target_site_id: String,
    path: String,
    client_ip: IpAddr,
    full_body_arc: Arc<Bytes>,
    alt_svc: Option<String>,
    main_config: Arc<MainConfig>,
    content_type: Option<String>,
) -> Option<Response<BoxBody<Bytes, Infallible>>> {
    let content_type = content_type?;
    if !is_upload_content_type(&content_type) {
        return None;
    }

    let upload_validator = waf.get_upload_validator()?;
    let effective_config = upload_validator.get_effective_config(&path);
    if !effective_config.scan_with_yara && effective_config.max_size_bytes == 0 {
        return None;
    }

    match upload_validator.validate_bytes(&full_body_arc, &path).await {
        Ok(result) => {
            if result.is_clean() {
                return None;
            }

            tracing::warn!(
                path = %path,
                client_ip = %client_ip,
                mime_type = %result.mime_type,
                matches = ?result.yara_matches,
                "Malware detected in upload, blocking client IP"
            );
            waf.block_ip_with_threat_intel(client_ip, "malware_upload", 3600, &target_site_id);
            let body = waf
                .render_upload_validation_error_page(403, Some("Upload blocked: malware detected"));
            Some(crate::response_builder::build_response_with_alt_svc(
                403,
                body,
                "text/html",
                &alt_svc,
                &main_config,
            ))
        }
        Err(e) => {
            let (status, message) = match &e {
                UploadValidationError::SizeExceeded { .. } => {
                    (413, "Upload size exceeds maximum allowed")
                }
                UploadValidationError::TypeNotAllowed { .. } => {
                    (415, "Upload file type not allowed")
                }
                UploadValidationError::MalwareDetected { matches } => {
                    tracing::warn!(
                        path = %path,
                        client_ip = %client_ip,
                        matches = ?matches,
                        "Malware detected in upload, blocking client IP"
                    );
                    waf.block_ip_with_threat_intel(
                        client_ip,
                        "malware_upload",
                        3600,
                        &target_site_id,
                    );
                    (403, "Upload blocked: malware detected")
                }
                UploadValidationError::ScanIndeterminate { reason } => {
                    tracing::warn!(
                        path = %path,
                        client_ip = %client_ip,
                        reason = %reason,
                        "Upload scan indeterminate, blocking"
                    );
                    (403, "Upload blocked: scan indeterminate")
                }
                UploadValidationError::ScannerUnavailable => {
                    tracing::warn!(
                        path = %path,
                        client_ip = %client_ip,
                        "Malware scanner unavailable, blocking upload"
                    );
                    (403, "Upload blocked: scanner unavailable")
                }
                _ => (400, "Upload validation failed"),
            };
            tracing::warn!(path = %path, error = %e, "Upload validation failed");
            let body = waf.render_upload_validation_error_page(status, Some(message));
            Some(crate::response_builder::build_response_with_alt_svc(
                status,
                body,
                "text/html",
                &alt_svc,
                &main_config,
            ))
        }
    }
}
