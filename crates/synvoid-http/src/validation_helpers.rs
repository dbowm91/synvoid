use crate::headers::is_websocket_upgrade;

pub fn validate_websocket_upgrade(headers: &http::HeaderMap) -> bool {
    is_websocket_upgrade(headers)
}
