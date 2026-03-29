use super::StaticWorkerState;

use cloakrs::{process_image_bytes, ProtectionContext, ProtectionLevel};

pub(super) fn poison_image_sync(
    _state: &StaticWorkerState,
    _site_id: &str,
    body: Vec<u8>,
    _last_modified: Option<String>,
) -> Vec<u8> {
    if body.is_empty() {
        return body;
    }

    let ctx = ProtectionContext::default()
        .with_seed(42)
        .with_intensity(0.5);

    match process_image_bytes(&body, ProtectionLevel::Standard, &ctx) {
        Ok(protected) => protected,
        Err(e) => {
            tracing::warn!(
                error = %e,
                "Image poisoning failed, returning original body (fail-open)"
            );
            body
        }
    }
}
