use super::StaticWorkerState;

pub(super) fn poison_image_sync(
    _state: &StaticWorkerState,
    _site_id: &str,
    body: Vec<u8>,
    _last_modified: Option<String>,
) -> Vec<u8> {
    if body.is_empty() {
        return body;
    }
    // STUB - returns body unchanged
    // TODO: Implement actual image poisoning algorithm
    // The last_modified date is available for metadata preservation
    body
}
