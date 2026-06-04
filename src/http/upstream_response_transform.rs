use bytes::Bytes;
use http::HeaderMap;
use std::future::Future;
use std::sync::Arc;

use crate::config::site::SiteImagePoisonConfig;
#[cfg(feature = "mesh")]
use crate::mesh::transport::MeshTransportManager;
use crate::router::{RouteTarget, Router};

pub struct TransformedUpstreamResponse {
    pub body: Bytes,
    pub body_len: u64,
    pub headers: HeaderMap,
}

#[allow(clippy::too_many_arguments)]
pub async fn transform_upstream_response<PoisonFn, PoisonFut>(
    target: &RouteTarget,
    router: &Arc<Router>,
    path: &str,
    site_id: &str,
    mut headers: HeaderMap,
    body: Bytes,
    status: u16,
    content_type: Option<String>,
    last_modified: Option<String>,
    accept_encoding: Option<&str>,
    #[cfg(feature = "mesh")] mesh_transport: &Option<Arc<MeshTransportManager>>,
    poison_image: PoisonFn,
) -> TransformedUpstreamResponse
where
    PoisonFn: Fn(Bytes, String, Option<String>, Option<SiteImagePoisonConfig>) -> PoisonFut,
    PoisonFut: Future<Output = Bytes>,
{
    // Keep the remaining inline transforms bounded. Static-file minify/compress
    // work is already offloaded through the CPU worker path; this function only
    // handles already-buffered upstream responses.
    let upstream_body_len = body.len() as u64;
    let (mut body, mut body_len) = if let Some(plugin_names) = &target.site_config.proxy.wasm_plugins {
        if let Some(client) = router.async_minifier_client() {
            let policy = crate::process::CpuTaskPolicy::FailOpenWithLog;
            match client
                .request_wasm_transform(
                    site_id,
                    plugin_names,
                    status,
                    body.to_vec(),
                    std::collections::HashMap::new(),
                    policy,
                    30000,
                )
                .await
            {
                Ok((_resp_status, transformed_body)) => {
                    let transformed_len = transformed_body.len() as u64;
                    (Bytes::from(transformed_body), transformed_len)
                }
                Err(e) => {
                    tracing::error!("WASM response transform offload error: {}", e);
                    let original_len = body.len() as u64;
                    (body, original_len)
                }
            }
        } else {
            let original_len = body.len() as u64;
            (body, original_len)
        }
    } else {
        let original_len = body.len() as u64;
        (body, original_len)
    };
    body_len = body_len.max(upstream_body_len);

    #[cfg(feature = "mesh")]
    if let Some(ref mt) = mesh_transport {
        let (minification, image_protection, image_poison_config, compression) = tokio::join!(
            mt.get_minification_for_site(site_id),
            mt.get_image_protection_for_site(site_id),
            mt.get_image_poison_config_for_site(site_id),
            mt.get_compression_for_site(site_id),
        );

        let config = crate::http::response_transform::ResponseTransformConfig::from_mesh_config(
            minification.as_ref(),
            image_protection.as_ref(),
            compression.as_ref(),
        );

        if let Some(ref min_settings) = config.minification {
            body = crate::http::response_transform::apply_minification(
                body,
                content_type.as_deref(),
                min_settings,
            );
            body_len = body.len() as u64;
        }

        if let Some(ref img_settings) = config.image_poisoning {
            let mut is_image = content_type
                .as_ref()
                .map(|ct| ct.starts_with("image/"))
                .unwrap_or(false);
            if !is_image {
                is_image = crate::http::response_transform::path_looks_like_image(path);
            }

            if is_image
                && body_len >= img_settings.min_size
                && !crate::http::response_transform::is_whitelisted_path(
                    img_settings.whitelist_patterns,
                    path,
                )
            {
                body = poison_image(
                    body,
                    site_id.to_string(),
                    last_modified.clone(),
                    image_poison_config.clone(),
                )
                .await;
                body_len = body.len() as u64;
            }
        }

        if let Some(ref comp_settings) = config.compression {
            let (compressed_body, encoding) = crate::http::response_transform::apply_compression(
                body.clone(),
                accept_encoding,
                comp_settings,
            );

            if let Some(enc) = encoding {
                body = compressed_body;
                body_len = body.len() as u64;
                headers.remove("content-encoding");
                if let Ok(name) = "content-encoding".parse::<http::header::HeaderName>() {
                    if let Ok(val) = enc.parse::<http::HeaderValue>() {
                        headers.insert(name, val);
                    }
                }
            }
        }

        return TransformedUpstreamResponse {
            body,
            body_len,
            headers,
        };
    }

    let static_config = &target.site_config.r#static;
    let image_poison_config = &target.site_config.image_poison;
    let config = crate::http::response_transform::ResponseTransformConfig::from_static_config(
        static_config,
        image_poison_config,
    );

    if let Some(ref min_settings) = config.minification {
        body = crate::http::response_transform::apply_minification(
            body,
            content_type.as_deref(),
            min_settings,
        );
        body_len = body.len() as u64;
    }

    if let Some(ref img_settings) = config.image_poisoning {
        let mut is_image = content_type
            .as_ref()
            .map(|ct| ct.starts_with("image/"))
            .unwrap_or(false);
        if !is_image {
            is_image = crate::http::response_transform::path_looks_like_image(path);
        }

        if is_image
            && body_len >= img_settings.min_size
            && !crate::http::response_transform::is_whitelisted_path(
                img_settings.whitelist_patterns,
                path,
            )
        {
            body = poison_image(
                body,
                site_id.to_string(),
                last_modified.clone(),
                Some(image_poison_config.clone()),
            )
            .await;
            body_len = body.len() as u64;
        }
    }

    if let Some(ref comp_settings) = config.compression {
        let (compressed_body, encoding) = crate::http::response_transform::apply_compression(
            body.clone(),
            accept_encoding,
            comp_settings,
        );

        if let Some(enc) = encoding {
            body = compressed_body;
            body_len = body.len() as u64;
            headers.remove("content-encoding");
            if let Ok(name) = "content-encoding".parse::<http::header::HeaderName>() {
                if let Ok(val) = enc.parse::<http::HeaderValue>() {
                    headers.insert(name, val);
                }
            }
        }
    }

    TransformedUpstreamResponse {
        body,
        body_len,
        headers,
    }
}
