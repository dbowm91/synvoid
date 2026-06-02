use bytes::Bytes;
use http::Response;
use http_body_util::combinators::BoxBody;
use std::convert::Infallible;
use std::net::IpAddr;
use std::sync::Arc;

use crate::config::MainConfig;
use crate::waf::WafCore;

pub async fn maybe_handle_upload_validation(
    waf: &Arc<WafCore>,
    target_site_id: &str,
    path: &str,
    client_ip: IpAddr,
    full_body_arc: &Arc<Bytes>,
    alt_svc: &Option<String>,
    main_config: &Arc<MainConfig>,
    content_type: Option<&str>,
) -> Option<Response<BoxBody<Bytes, Infallible>>> {
    let content_type = content_type?;
    if !crate::upload::is_upload_content_type(content_type) {
        return None;
    }

    let upload_validator = waf.get_upload_validator()?;
    let effective_config = upload_validator.get_effective_config(path);
    if !effective_config.scan_with_yara && effective_config.max_size_bytes == 0 {
        return None;
    }

    match upload_validator.validate_bytes(full_body_arc, path).await {
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
            waf.block_ip_with_threat_intel(client_ip, "malware_upload", 3600, target_site_id);
            let body = waf
                .error_page_manager
                .render_page(403, Some("Upload blocked: malware detected"));
            Some(crate::http::response_builder::build_response_with_alt_svc(
                403,
                body,
                "text/html",
                alt_svc,
                main_config,
            ))
        }
        Err(e) => {
            let (status, message) = match &e {
                crate::upload::UploadValidationError::SizeExceeded { .. } => {
                    (413, "Upload size exceeds maximum allowed")
                }
                crate::upload::UploadValidationError::TypeNotAllowed { .. } => {
                    (415, "Upload file type not allowed")
                }
                crate::upload::UploadValidationError::MalwareDetected { matches } => {
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
                        target_site_id,
                    );
                    (403, "Upload blocked: malware detected")
                }
                _ => (400, "Upload validation failed"),
            };
            tracing::warn!(
                path = %path,
                error = %e,
                "Upload validation failed"
            );
            let body = waf.error_page_manager.render_page(status, Some(message));
            Some(crate::http::response_builder::build_response_with_alt_svc(
                status,
                body,
                "text/html",
                alt_svc,
                main_config,
            ))
        }
    }
}
