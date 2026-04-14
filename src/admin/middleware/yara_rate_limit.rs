use super::super::middleware::ClientIp;
use super::super::state::{AdminState, YaraRateLimitOp};
use axum::{
    extract::Request,
    http::StatusCode,
    middleware::Next,
    response::{IntoResponse, Response},
};
use std::sync::Arc;

fn path_to_op(path: &str) -> Option<YaraRateLimitOp> {
    match path {
        "/api/yara/submit" => Some(YaraRateLimitOp::Submit),
        "/api/yara/broadcast" | "/api/yara/apply" | "/api/yara/sync" => {
            Some(YaraRateLimitOp::BroadcastApply)
        }
        "/api/yara/status" | "/api/yara/submissions" => Some(YaraRateLimitOp::StatusList),
        _ if path.starts_with("/api/yara/submissions/") => {
            if path.ends_with("/approve") || path.ends_with("/reject") {
                Some(YaraRateLimitOp::ApproveReject)
            } else {
                Some(YaraRateLimitOp::StatusList)
            }
        }
        _ => None,
    }
}

pub async fn yara_rate_limit_middleware(
    axum::extract::State(state): axum::extract::State<Arc<AdminState>>,
    request: Request,
    next: Next,
) -> Response {
    let path = request.uri().path().to_string();

    if let Some(op) = path_to_op(&path) {
        let client_ip = request
            .extensions()
            .get::<ClientIp>()
            .map(|ip| ip.0.as_str())
            .unwrap_or("unknown");

        if let Some(ref limiter) = state.security.yara_rate_limiter {
            if !limiter.check(client_ip, op) {
                tracing::warn!("YARA rate limit exceeded for IP: {} on {}", client_ip, path);
                return (StatusCode::TOO_MANY_REQUESTS, "Too Many Requests").into_response();
            }
        }
    }

    next.run(request).await
}
