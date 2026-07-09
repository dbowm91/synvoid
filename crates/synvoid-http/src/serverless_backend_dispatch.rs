#[cfg(feature = "mesh")]
use bytes::Bytes;
#[cfg(feature = "mesh")]
use http::Response;
#[cfg(feature = "mesh")]
use http_body_util::combinators::BoxBody;
#[cfg(feature = "mesh")]
use http_body_util::BodyExt;
#[cfg(feature = "mesh")]
use http_body_util::Full;
#[cfg(feature = "mesh")]
use std::convert::Infallible;
#[cfg(feature = "mesh")]
use std::net::IpAddr;
#[cfg(feature = "mesh")]
use std::sync::Arc;
#[cfg(feature = "mesh")]
use std::time::Instant;

#[cfg(feature = "mesh")]
use synvoid_config::MainConfig;
#[cfg(feature = "mesh")]
use synvoid_mesh::mesh::transports::MeshTransportManager;
#[cfg(feature = "mesh")]
use synvoid_serverless::{
    handle_serverless_function, CallerContext, ServerlessError, ServerlessManager,
};

#[cfg(feature = "mesh")]
#[allow(clippy::too_many_arguments)]
pub async fn maybe_handle_serverless_backend(
    serverless_manager: &Option<Arc<ServerlessManager>>,
    mesh_transport: &Option<Arc<MeshTransportManager>>,
    method: &http::Method,
    path: &str,
    parts: &http::request::Parts,
    full_body_arc: &Arc<Bytes>,
    ipc: Option<Arc<tokio::sync::Mutex<synvoid_ipc::AsyncIpcStream>>>,
    worker_id: Option<synvoid_ipc::WorkerId>,
    main_config: &Arc<MainConfig>,
    client_ip: IpAddr,
    method_str: &str,
    start: Instant,
    site_id: &str,
    user_agent: Option<&str>,
    alt_svc: &Option<String>,
    on_log: impl Fn(
        Option<Arc<tokio::sync::Mutex<synvoid_ipc::AsyncIpcStream>>>,
        Option<synvoid_ipc::WorkerId>,
        &Arc<MainConfig>,
        IpAddr,
        &str,
        &str,
        u16,
        u64,
        &str,
        Option<&str>,
        bool,
    ),
) -> Option<Result<Response<BoxBody<Bytes, Infallible>>, hyper::Error>> {
    let Some(serverless_manager) = serverless_manager.as_ref() else {
        tracing::warn!(
            "Serverless backend for site {} but no serverless manager",
            site_id
        );
        return Some(Ok(crate::response_builder::build_response_with_alt_svc(
            502,
            "Serverless backend misconfigured: no runtime available".to_string(),
            "text/plain",
            alt_svc,
            main_config,
        )));
    };

    let body_bytes_for_serverless: Bytes = full_body_arc.as_ref().clone();
    Some(
        match handle_serverless_function(
            serverless_manager,
            method,
            path,
            &parts.headers,
            Some(body_bytes_for_serverless),
            CallerContext::local(),
        )
        .await
        {
            Ok(response) => {
                let status = response.status();
                on_log(
                    ipc,
                    worker_id,
                    main_config,
                    client_ip,
                    method_str,
                    path,
                    status.as_u16(),
                    start.elapsed().as_millis() as u64,
                    site_id,
                    user_agent,
                    false,
                );
                Ok(Response::builder()
                    .status(status)
                    .body(Full::new(response.into_body()).boxed())
                    .unwrap_or_else(|_| crate::fallback_error_boxed()))
            }
            Err(err) => {
                if let ServerlessError::RemoteExecutionRequired(upstream_id) = &err {
                    let function_name = upstream_id
                        .strip_prefix("serverless:")
                        .unwrap_or(upstream_id.as_str());
                    if let Some(mt) = mesh_transport.as_ref() {
                        let body_bytes_retry: Bytes = full_body_arc.as_ref().clone();
                        let mut proxy_req = http::Request::builder()
                            .method(parts.method.clone())
                            .uri(parts.uri.clone());
                        for (name, value) in parts.headers.iter() {
                            proxy_req =
                                proxy_req.header(name.as_str(), value.to_str().unwrap_or(""));
                        }
                        let proxy_req = proxy_req
                            .body(http_body_util::Full::new(body_bytes_retry))
                            .unwrap_or_else(|_| {
                                http::Request::new(http_body_util::Full::new(Bytes::new()))
                            });

                        let record_store = mt.get_record_store();
                        let node_id = match record_store.as_ref().and_then(|rs| {
                            rs.get_record(&format!("serverless_function:{}", function_name))
                                .and_then(|r| {
                                    serde_json::from_slice::<serde_json::Value>(&r.value).ok()
                                })
                                .and_then(|v| {
                                    v.get("node_id")
                                        .and_then(|n| n.as_str())
                                        .map(|s| s.to_string())
                                })
                        }) {
                            Some(node_id) => node_id,
                            None => {
                                tracing::warn!(
                                    "No provider node found in DHT for serverless function: {}",
                                    function_name
                                );
                                tracing::warn!("Serverless function error for {}: {}", path, err);
                                return Some(Ok(
                                    crate::response_builder::build_response_with_alt_svc(
                                        502,
                                        format!("Serverless Error: {}", err),
                                        "text/plain",
                                        alt_svc,
                                        main_config,
                                    ),
                                ));
                            }
                        };

                        match mt
                            .proxy_serverless_request(function_name, &node_id, proxy_req)
                            .await
                        {
                            Ok(proxy_resp) => return Some(Ok(proxy_resp)),
                            Err(proxy_err) => {
                                tracing::warn!(
                                    "Serverless mesh proxy failed for {}: {}",
                                    function_name,
                                    proxy_err
                                );
                            }
                        }
                    }
                }

                tracing::warn!("Serverless function error for {}: {}", path, err);
                Ok(crate::response_builder::build_response_with_alt_svc(
                    502,
                    format!("Serverless Error: {}", err),
                    "text/plain",
                    alt_svc,
                    main_config,
                ))
            }
        },
    )
}
