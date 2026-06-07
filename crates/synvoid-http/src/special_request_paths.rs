#[cfg(feature = "mesh")]
use axum::Json;
#[cfg(feature = "mesh")]
use bytes::Bytes;
#[cfg(feature = "mesh")]
use http::Response;
#[cfg(feature = "mesh")]
use http::StatusCode;
#[cfg(feature = "mesh")]
use http_body_util::combinators::BoxBody;
#[cfg(feature = "mesh")]
use http_body_util::{BodyExt, Full};
#[cfg(feature = "mesh")]
use std::convert::Infallible;
#[cfg(feature = "mesh")]
use std::net::IpAddr;
#[cfg(feature = "mesh")]
use std::sync::Arc;

#[cfg(feature = "mesh")]
use crate::request_parse::should_handle_key_exchange_path;
#[cfg(feature = "mesh")]
use synvoid_config::MainConfig;
#[cfg(feature = "mesh")]
use synvoid_mesh::passover_key_exchange::KeyConfirmHttp;
#[cfg(feature = "mesh")]
use synvoid_mesh::transports::MeshTransportManager;
#[cfg(feature = "mesh")]
use synvoid_mesh::MeshConfig;

#[cfg(all(feature = "mesh", feature = "dns"))]
use crate::request_parse::parse_http01_challenge_token;

#[cfg(feature = "mesh")]
pub enum SpecialRequestDispatch {
    Handled(Response<BoxBody<Bytes, Infallible>>),
    NotHandled(hyper::Request<hyper::body::Incoming>),
}

#[cfg(feature = "mesh")]
pub async fn maybe_handle_special_request_paths(
    req: hyper::Request<hyper::body::Incoming>,
    path: &str,
    client_ip: IpAddr,
    alt_svc: &Option<String>,
    main_config: &Arc<MainConfig>,
    mesh_config: &Option<Arc<MeshConfig>>,
    mesh_transport: &Option<Arc<MeshTransportManager>>,
) -> Result<SpecialRequestDispatch, hyper::Error> {
    if should_handle_key_exchange_path(path) {
        if let Some(ref mesh_cfg) = mesh_config {
            if mesh_cfg.role.is_global()
                && mesh_cfg.global_node.key_exchange_enabled
                && mesh_cfg.origin_signing_key.is_some()
            {
                let (parts, body) = req.into_parts();
                let path = parts.uri.path();
                let method = parts.method.clone();

                let body_bytes = match body.collect().await {
                    Ok(collected) => collected.to_bytes(),
                    Err(e) => {
                        return Ok(SpecialRequestDispatch::Handled(
                            crate::response_builder::build_response_with_alt_svc(
                                400,
                                format!("Failed to read request body: {}", e),
                                "application/json",
                                alt_svc,
                                main_config,
                            ),
                        ));
                    }
                };

                let state = synvoid_mesh::passover_key_exchange::KeyExchangeHttpState::new(
                    mesh_cfg.clone(),
                )
                .with_transport(mesh_transport.clone());

                let response = if path == "/key-request-origin" && method == http::Method::POST {
                    match serde_json::from_slice::<
                        synvoid_mesh::passover_key_exchange::KeyRequestOriginHttp,
                    >(&body_bytes)
                    {
                        Ok(mut req_data) => {
                            req_data.client_ip = Some(client_ip.to_string());

                            let result =
                                synvoid_mesh::passover_key_exchange::key_request_origin_http(
                                    axum::extract::State(state),
                                    Json(req_data),
                                )
                                .await;
                            match result {
                                Ok(Json(response)) => {
                                    let json = serde_json::to_string(&response).unwrap_or_default();
                                    (StatusCode::OK, json)
                                }
                                Err((status, err)) => (status, err),
                            }
                        }
                        Err(e) => (StatusCode::BAD_REQUEST, format!("Invalid request: {}", e)),
                    }
                } else if path == "/key-confirm" && method == http::Method::POST {
                    match serde_json::from_slice::<KeyConfirmHttp>(&body_bytes) {
                        Ok(req_data) => {
                            let result = synvoid_mesh::passover_key_exchange::key_confirm_http(
                                axum::extract::State(state),
                                Json(req_data),
                            )
                            .await;
                            match result {
                                Ok(Json(response)) => {
                                    let json = serde_json::to_string(&response).unwrap_or_default();
                                    (StatusCode::OK, json)
                                }
                                Err((status, err)) => (status, err),
                            }
                        }
                        Err(e) => (StatusCode::BAD_REQUEST, format!("Invalid request: {}", e)),
                    }
                } else if path == "/health" && method == http::Method::GET {
                    (StatusCode::OK, "OK".to_string())
                } else {
                    (StatusCode::NOT_FOUND, "Not Found".to_string())
                };

                return Ok(SpecialRequestDispatch::Handled(
                    crate::response_builder::build_response_with_alt_svc(
                        response.0.as_u16(),
                        response.1,
                        "application/json",
                        alt_svc,
                        main_config,
                    ),
                ));
            }
        }
    }

    #[cfg(all(feature = "mesh", feature = "dns"))]
    if let Some(ref mt) = mesh_transport {
        if let Some(token) = parse_http01_challenge_token(path) {
            if let Some(key_authorization) = mt.maybe_get_http01_challenge(token) {
                tracing::debug!(
                    "Serving HTTP-01 challenge for token {} (from {})",
                    token,
                    client_ip
                );
                return Ok(SpecialRequestDispatch::Handled(
                    Response::builder()
                        .status(200)
                        .header(http::header::CONTENT_TYPE, "text/plain")
                        .header(http::header::ACCESS_CONTROL_ALLOW_ORIGIN, "*")
                        .body(Full::new(Bytes::from(key_authorization)).boxed())
                        .unwrap(),
                ));
            }
            tracing::debug!(
                "HTTP-01 challenge not found for token {} (from {})",
                token,
                client_ip
            );
        }
    }

    Ok(SpecialRequestDispatch::NotHandled(req))
}
