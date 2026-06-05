use std::collections::HashMap;
use std::convert::Infallible;
use std::sync::Arc;

use bytes::Bytes;
use http::Response;
use http_body_util::combinators::BoxBody;
use http_body_util::BodyExt;
use http_body_util::Full;

use crate::config::MainConfig;
use crate::http::apply_image_poisoning;
use crate::http::response_helpers::apply_security_headers;
use crate::http::response_transform::{
    is_whitelisted_path, path_looks_like_image, ResponseTransformConfig,
};
use crate::router::{BackendType, RouteTarget, Router};
use crate::waf::WafCore;

const FORBIDDEN_RESPONSE_HEADERS: &[&str] = &["server", "x-powered-by", "connection", "keep-alive"];

#[allow(clippy::too_many_arguments)]
pub async fn maybe_handle_fastcgi_or_php_backend(
    target: &RouteTarget,
    router: &Arc<Router>,
    waf: &Arc<WafCore>,
    site_id: &str,
    path: &str,
    method: &http::Method,
    parts: &http::request::Parts,
    full_body_arc: &Arc<Bytes>,
    alt_svc: &Option<String>,
    main_config: &Arc<MainConfig>,
) -> Option<Response<BoxBody<Bytes, Infallible>>> {
    if !matches!(target.backend_type, BackendType::FastCgi | BackendType::Php) {
        return None;
    }

    let Some(socket) = target.backend_socket.as_ref() else {
        tracing::warn!(
            "FastCGI/PHP backend for site {} but no socket configured",
            site_id
        );
        let site_theme = target
            .site_config
            .error_pages
            .theme
            .as_ref()
            .map(|theme_config| theme_config.to_theme_config(waf.error_page_manager.theme()));
        let body = waf.error_page_manager.render_page_with_theme(
            502,
            Some("Backend misconfigured: no socket configured"),
            site_theme.as_ref(),
        );
        return Some(crate::http::response_builder::build_response_with_alt_svc(
            502,
            body,
            "text/html",
            alt_svc,
            main_config,
        ));
    };

    let body_bytes_for_fcgi: Bytes = full_body_arc.as_ref().clone();

    if matches!(target.backend_type, BackendType::Php) {
        if let Some(php_client) =
            crate::php::create_php_client(&target.site_config, target.php_location_config.as_ref())
        {
            match php_client
                .execute(
                    method,
                    &parts.uri,
                    &parts.headers,
                    body_bytes_for_fcgi.clone(),
                )
                .await
            {
                Ok(response) => {
                    return Some(response.into_http_response().map(|b| Full::new(b).boxed()));
                }
                Err(e) => {
                    let site_theme =
                        target
                            .site_config
                            .error_pages
                            .theme
                            .as_ref()
                            .map(|theme_config| {
                                theme_config.to_theme_config(waf.error_page_manager.theme())
                            });
                    let body = waf.error_page_manager.render_page_with_theme(
                        502,
                        Some(&format!("Backend Error: {}", e)),
                        site_theme.as_ref(),
                    );
                    return Some(crate::http::response_builder::build_response_with_alt_svc(
                        502,
                        body,
                        "text/html",
                        alt_svc,
                        main_config,
                    ));
                }
            }
        }
    }

    let fcgi_config = target.site_config.proxy.fastcgi.clone().unwrap_or_default();
    let pool = crate::fastcgi::get_pool(&socket.to_string(), &fcgi_config);
    match pool
        .execute(
            method,
            &parts.uri,
            &parts.headers,
            body_bytes_for_fcgi,
            &fcgi_config,
        )
        .await
    {
        Ok(response) => {
            let content_type = response.headers.get("content-type").map(|v| v.as_str());
            let mut body = response.body;

            if let Some(plugin_names) = &target.site_config.proxy.wasm_plugins {
                if let Some(client) = router.async_minifier_client() {
                    let policy = crate::process::CpuTaskPolicy::FailOpenWithLog;
                    match client
                        .request_wasm_transform(
                            site_id,
                            plugin_names,
                            response.status.as_u16(),
                            body.to_vec(),
                            HashMap::new(),
                            policy,
                            30000,
                        )
                        .await
                    {
                        Ok((_resp_status, transformed_body)) => {
                            body = Bytes::from(transformed_body);
                        }
                        Err(e) => {
                            tracing::error!("WASM response transform offload error: {}", e);
                        }
                    }
                }
            }

            let static_config = &target.site_config.r#static;
            let image_poison_config = &target.site_config.image_poison;
            let config =
                ResponseTransformConfig::from_static_config(static_config, image_poison_config);

            if let Some(ref min_settings) = config.minification {
                // Inline only for buffered response bodies; static-file minify/compress
                // continues to go through the CPU worker offload path.
                body = crate::http::response_transform::apply_minification(
                    body,
                    content_type,
                    min_settings,
                );
            }

            if let Some(ref img_settings) = config.image_poisoning {
                let body_len = body.len() as u64;
                let mut is_image = content_type
                    .map(|ct| ct.starts_with("image/"))
                    .unwrap_or(false);
                if !is_image {
                    is_image = path_looks_like_image(path);
                }
                let in_range = body_len >= img_settings.min_size;

                if is_image && in_range {
                    if !is_whitelisted_path(img_settings.whitelist_patterns, path) {
                        body = apply_image_poisoning(
                            body,
                            site_id.to_string(),
                            None,
                            Some(image_poison_config.clone()),
                        )
                        .await;
                    }
                }
            }

            let mut builder = http::Response::builder().status(response.status);
            for (name, value) in response.headers {
                let name_lower = name.to_ascii_lowercase();
                if FORBIDDEN_RESPONSE_HEADERS.contains(&name_lower.as_str()) {
                    continue;
                }
                if let (Ok(name), Ok(value)) = (
                    http::header::HeaderName::from_bytes(name.as_bytes()),
                    http::HeaderValue::from_str(&value),
                ) {
                    builder = builder.header(name, value);
                }
            }

            builder = apply_security_headers(builder, target, main_config);
            Some(builder.body(Full::new(body).boxed()).unwrap_or_else(|_| {
                crate::http::response_builder::build_response_with_alt_svc(
                    500,
                    crate::http::reason_phrase(500).to_string(),
                    "text/plain",
                    alt_svc,
                    main_config,
                )
            }))
        }
        Err(e) => {
            let site_theme = target
                .site_config
                .error_pages
                .theme
                .as_ref()
                .map(|theme_config| theme_config.to_theme_config(waf.error_page_manager.theme()));
            let body = waf.error_page_manager.render_page_with_theme(
                502,
                Some(&format!("Backend Error: {}", e)),
                site_theme.as_ref(),
            );
            Some(crate::http::response_builder::build_response_with_alt_svc(
                502,
                body,
                "text/html",
                alt_svc,
                main_config,
            ))
        }
    }
}
