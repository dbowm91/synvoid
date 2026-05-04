use bytes::Bytes;
use http::Response;
use http_body_util::combinators::BoxBody;
use http_body_util::BodyExt;
use http_body_util::Full;
use std::convert::Infallible;
use std::sync::Arc;

use crate::config::MainConfig;
use crate::worker::drain_state::WorkerDrainState;

pub type BoxBodyResponse = Response<BoxBody<Bytes, Infallible>>;

pub async fn handle_drain_request(
    _req: hyper::Request<hyper::body::Incoming>,
    drain_state: &Arc<WorkerDrainState>,
    alt_svc: &Option<String>,
    main_config: &Arc<MainConfig>,
) -> Result<BoxBodyResponse, hyper::Error> {
    let drain_id = crate::utils::safe_unix_duration().as_millis() as u64;

    let accepted = drain_state.start_drain(drain_id).await;
    drain_state.stop_accepting();

    let status = drain_state.get_status().await;
    let body = serde_json::to_string(&status).unwrap_or_else(|_| "{}".to_string());

    let status_code = if accepted { 200 } else { 409 };
    Ok(crate::http::response_builder::build_response_with_alt_svc(
        status_code,
        body,
        "application/json",
        alt_svc,
        main_config,
    ))
}

pub async fn handle_drain_status_request(
    _req: hyper::Request<hyper::body::Incoming>,
    drain_state: &Arc<WorkerDrainState>,
    alt_svc: &Option<String>,
    main_config: &Arc<MainConfig>,
) -> Result<BoxBodyResponse, hyper::Error> {
    let status = drain_state.get_status().await;
    let body = serde_json::to_string(&status).unwrap_or_else(|_| "{}".to_string());

    Ok(crate::http::response_builder::build_response_with_alt_svc(
        200,
        body,
        "application/json",
        alt_svc,
        main_config,
    ))
}

pub async fn handle_health_request(
    drain_state: &Option<Arc<WorkerDrainState>>,
    alt_svc: &Option<String>,
    _main_config: &Arc<MainConfig>,
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
        .unwrap_or_else(|_| crate::http::fallback_error_boxed()))
}

pub async fn handle_ready_request(
    drain_state: &Option<Arc<WorkerDrainState>>,
    alt_svc: &Option<String>,
    _main_config: &Arc<MainConfig>,
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
        .unwrap_or_else(|_| crate::http::fallback_error_boxed()))
}
