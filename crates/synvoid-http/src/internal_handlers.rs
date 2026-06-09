use bytes::Bytes;
use http::Response;
use http_body_util::combinators::BoxBody;
use http_body_util::BodyExt;
use http_body_util::Full;
use std::convert::Infallible;
use std::sync::Arc;

use serde::{Deserialize, Serialize};
use synvoid_config::MainConfig;
use synvoid_core::time::current_timestamp_millis;

use crate::response_helpers::BoxBodyResponse;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DrainStatusSnapshot {
    pub drain_id: u64,
    pub is_draining: bool,
    pub active_connections: u64,
    pub idle_connections: u64,
    pub connections_drained: u64,
    pub drain_elapsed_secs: u64,
    pub drain_complete: bool,
    pub stopped_accepting: bool,
    pub short_requests: u64,
    pub long_requests: u64,
    pub streaming_requests: u64,
}

#[async_trait::async_trait]
pub trait HttpDrainControl: Send + Sync + 'static {
    async fn start_drain(&self, drain_id: u64) -> bool;
    fn stop_accepting(&self);
    async fn get_status(&self) -> DrainStatusSnapshot;
    fn is_draining(&self) -> bool;
    fn is_stopped_accepting(&self) -> bool;
}

pub async fn handle_drain_request<D: HttpDrainControl>(
    _req: hyper::Request<hyper::body::Incoming>,
    drain_state: Arc<D>,
    alt_svc: Option<String>,
    main_config: Arc<MainConfig>,
) -> Result<BoxBodyResponse, hyper::Error> {
    let drain_id = current_timestamp_millis();

    let accepted = drain_state.start_drain(drain_id).await;
    drain_state.stop_accepting();

    let status = drain_state.get_status().await;
    let body = serde_json::to_string(&status).unwrap_or_else(|_| "{}".to_string());

    let status_code = if accepted { 200 } else { 409 };
    Ok(crate::response_builder::build_response_with_alt_svc(
        status_code,
        body,
        "application/json",
        &alt_svc,
        main_config.as_ref(),
    ))
}

pub async fn handle_drain_status_request<D: HttpDrainControl>(
    _req: hyper::Request<hyper::body::Incoming>,
    drain_state: Arc<D>,
    alt_svc: Option<String>,
    main_config: Arc<MainConfig>,
) -> Result<BoxBodyResponse, hyper::Error> {
    let status = drain_state.get_status().await;
    let body = serde_json::to_string(&status).unwrap_or_else(|_| "{}".to_string());

    Ok(crate::response_builder::build_response_with_alt_svc(
        200,
        body,
        "application/json",
        &alt_svc,
        main_config.as_ref(),
    ))
}

pub async fn handle_health_request<D: HttpDrainControl>(
    drain_state: Option<Arc<D>>,
    alt_svc: Option<String>,
    _main_config: Arc<MainConfig>,
) -> Result<BoxBodyResponse, hyper::Error> {
    let (status_code, body) = if let Some(state) = drain_state {
        let status = state.get_status().await;
        if status.is_draining {
            let body = serde_json::json!({
                "status": "draining",
                "active_connections": status.active_connections,
                "drain_elapsed_secs": status.drain_elapsed_secs,
            });
            (503, body.to_string())
        } else {
            let body = serde_json::json!({
                "status": "healthy",
            });
            (200, body.to_string())
        }
    } else {
        let body = serde_json::json!({
            "status": "healthy",
        });
        (200, body.to_string())
    };

    let mut builder = Response::builder()
        .status(status_code)
        .header("Content-Type", "application/json")
        .header("Content-Length", body.len());

    if status_code == 503 {
        builder = builder.header("Retry-After", "5");
    }

    if let Some(alt_svc) = alt_svc {
        builder = builder.header("Alt-Svc", alt_svc.as_str());
    }

    let body_bytes = Bytes::from(body);
    let boxed: BoxBody<Bytes, Infallible> = Full::new(body_bytes).boxed();
    Ok(builder
        .body(boxed)
        .unwrap_or_else(|_| crate::fallback_error_boxed()))
}

pub async fn handle_ready_request<D: HttpDrainControl>(
    drain_state: Option<Arc<D>>,
    alt_svc: Option<String>,
    _main_config: Arc<MainConfig>,
) -> Result<BoxBodyResponse, hyper::Error> {
    let (status_code, body) = if let Some(state) = drain_state {
        let status = state.get_status().await;
        if status.is_draining || status.stopped_accepting {
            let body = serde_json::json!({
                "ready": false,
                "reason": "draining",
                "active_connections": status.active_connections,
            });
            (503, body.to_string())
        } else {
            let body = serde_json::json!({
                "ready": true,
            });
            (200, body.to_string())
        }
    } else {
        let body = serde_json::json!({
            "ready": true,
        });
        (200, body.to_string())
    };

    let mut builder = Response::builder()
        .status(status_code)
        .header("Content-Type", "application/json")
        .header("Content-Length", body.len());

    if status_code == 503 {
        builder = builder.header("Retry-After", "5");
    }

    if let Some(alt_svc) = alt_svc {
        builder = builder.header("Alt-Svc", alt_svc.as_str());
    }

    let body_bytes = Bytes::from(body);
    let boxed: BoxBody<Bytes, Infallible> = Full::new(body_bytes).boxed();
    Ok(builder
        .body(boxed)
        .unwrap_or_else(|_| crate::fallback_error_boxed()))
}
