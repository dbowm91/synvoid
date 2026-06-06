use bytes::Bytes;
use http::Response;
use http_body_util::combinators::BoxBody;
use std::convert::Infallible;
use std::net::IpAddr;
use std::sync::Arc;

use crate::config::MainConfig;
use crate::router::{RouteTarget, Router};
use crate::waf::WafCore;

pub fn maybe_handle_wasm_request_filter(
    router: &Arc<Router>,
    target: &RouteTarget,
    path: &str,
    method: &http::Method,
    parts: &http::request::Parts,
    body_slice: &Option<Arc<Bytes>>,
    client_ip: IpAddr,
    waf: &Arc<WafCore>,
    alt_svc: &Option<String>,
    main_config: &Arc<MainConfig>,
    on_request_log: impl Fn(u16),
) -> Option<Response<BoxBody<Bytes, Infallible>>> {
    let pm = router.plugin_manager()?.downcast_ref::<crate::plugin::PluginManager>()?;
    let body_bytes: Bytes = body_slice
        .as_ref()
        .map(|b: &Arc<Bytes>| b.to_vec().into())
        .unwrap_or_default();

    let mut filter_builder = http::Request::builder()
        .method(method.clone())
        .uri(&parts.uri);
    for (name, value) in parts.headers.iter() {
        filter_builder = filter_builder.header(name, value);
    }
    let filter_req = filter_builder.body(body_bytes.clone()).unwrap_or_else(|_| {
        http::Request::builder()
            .method(method.clone())
            .body(Bytes::from_static(&[]))
            .unwrap_or_else(|_| http::Request::new(Bytes::new()))
    });

    let wasm_result = if let Some(ref plugin_names) = target.site_config.proxy.wasm_plugins {
        pm.apply_wasm_filters_with_plugins(
            filter_req,
            plugin_names,
            std::collections::HashMap::new(),
        )
    } else {
        pm.apply_wasm_filters(filter_req, std::collections::HashMap::new())
    };

    match wasm_result {
        Ok(crate::plugin::WasmFilterResult::Pass) => None,
        Ok(crate::plugin::WasmFilterResult::Block(status, msg)) => {
            tracing::info!(
                "WASM plugin blocked request to {} from {}: {}",
                path,
                client_ip,
                msg
            );
            let body = waf
                .error_page_manager
                .render_page(status.as_u16(), Some(&msg));
            on_request_log(status.as_u16());
            Some(crate::http::response_builder::build_response_with_alt_svc(
                status.as_u16(),
                body,
                "text/html",
                alt_svc,
                main_config,
            ))
        }
        Ok(crate::plugin::WasmFilterResult::Challenge(reason)) => {
            tracing::info!(
                "WASM plugin issued challenge for {} from {}: {}",
                path,
                client_ip,
                reason
            );
            let escaped = reason
                .replace('&', "&amp;")
                .replace('<', "&lt;")
                .replace('>', "&gt;")
                .replace('"', "&quot;");
            let html = format!(
                "<html><body><h1>Challenge Required</h1><p>{}</p></body></html>",
                escaped
            );
            on_request_log(200);
            Some(crate::http::response_builder::build_response_with_alt_svc(
                200,
                html,
                "text/html",
                alt_svc,
                main_config,
            ))
        }
        Err(e) => {
            tracing::error!("WASM plugin filter error: {}", e);
            match target.site_config.proxy.wasm_on_error {
                crate::config::site::WasmOnError::FailClosed => {
                    let body = waf
                        .error_page_manager
                        .render_page(500, Some("WASM plugin error"));
                    Some(crate::http::response_builder::build_response_with_alt_svc(
                        500,
                        body,
                        "text/html",
                        alt_svc,
                        main_config,
                    ))
                }
                crate::config::site::WasmOnError::FailOpen => None,
            }
        }
    }
}
