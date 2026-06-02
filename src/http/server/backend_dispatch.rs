use super::*;

pub(super) async fn handle_pass_upstream_proxy_phase(
    upstream_ctx: PassUpstreamProxyContext<'_>,
) -> Result<Response<BoxBody<Bytes, Infallible>>, hyper::Error> {
    let dispatch_plan = prepare_upstream_proxy_dispatch_plan(
        upstream_ctx.target,
        upstream_ctx.path,
        upstream_ctx.main_config,
        upstream_ctx.full_body_arc.len() as u64,
        upstream_ctx.client_ip,
        upstream_ctx.parts,
        upstream_ctx.upstream_client_registry,
        upstream_ctx.client,
    );

    if let Some(streaming) = dispatch_plan.streaming {
        let erased_body = crate::http_client::ErasedBodyImpl::from_full(Full::new(
            upstream_ctx.full_body_arc.as_ref().clone(),
        ));
        let request_result = send_request_streaming_generic(
            streaming.client.as_ref(),
            upstream_ctx.method.clone(),
            &dispatch_plan.upstream_target.url,
            erased_body,
            streaming.forward_headers,
            Some(dispatch_plan.upstream_target.timeout),
        )
        .await;
        return handle_streaming_upstream_response(
            request_result,
            upstream_ctx.target,
            upstream_ctx.site_id,
            upstream_ctx.request_body_size,
            &dispatch_plan.headers_to_filter,
            dispatch_plan.upstream_target.max_response_size,
            upstream_ctx.alt_svc,
            upstream_ctx.main_config,
            upstream_ctx.metrics,
            || {
                if let Some(rm) = upstream_ctx.req_metrics {
                    rm.record_upstream_success();
                }
            },
            || {
                if let Some(rm) = upstream_ctx.req_metrics {
                    rm.record_upstream_failure();
                }
            },
            |egress_len| {
                if let Some(rm) = upstream_ctx.req_metrics {
                    rm.record_egress(egress_len, EgressDirection::Error);
                }
            },
        )
        .await;
    }

    handle_buffered_upstream_request(
        upstream_ctx.target,
        upstream_ctx.router,
        upstream_ctx.path,
        upstream_ctx.site_id,
        upstream_ctx.method,
        upstream_ctx.parts,
        upstream_ctx.full_body_arc,
        &dispatch_plan.forwarding_client,
        &dispatch_plan.upstream_target,
        &dispatch_plan.headers_to_filter,
        upstream_ctx.alt_svc,
        upstream_ctx.main_config,
        upstream_ctx.metrics,
        upstream_ctx.request_body_size,
        #[cfg(feature = "mesh")]
        upstream_ctx.mesh_transport,
        || {
            if let Some(rm) = upstream_ctx.req_metrics {
                rm.record_upstream_success();
            }
        },
        || {
            if let Some(rm) = upstream_ctx.req_metrics {
                rm.record_upstream_failure();
            }
        },
        |egress_len| {
            if let Some(rm) = upstream_ctx.req_metrics {
                rm.record_egress(egress_len, EgressDirection::Error);
            }
        },
        |body, site_id, last_modified, poison_config| async move {
            crate::http::apply_image_poisoning(body, site_id, last_modified, poison_config).await
        },
    )
    .await
}

#[allow(clippy::too_many_arguments)]
pub(super) async fn handle_pass_backend_dispatch(
    on_upgrade: Option<hyper::upgrade::OnUpgrade>,
    dispatch_ctx: PassBackendDispatchContext<'_>,
) -> Result<Response<BoxBody<Bytes, Infallible>>, hyper::Error> {
    // ============================================================================
    // SECTION 15: Backend Dispatch (WebSocket, AxumDynamic, Static, Upstream)
    // ============================================================================
    if let Some(ref rm) = dispatch_ctx.req_metrics {
        rm.record_proxied();
    }
    if let Some(response) = maybe_handle_websocket_upgrade(
        on_upgrade,
        dispatch_ctx.app_servers,
        dispatch_ctx.site_id,
        dispatch_ctx.target,
        dispatch_ctx.path,
        dispatch_ctx.waf,
        dispatch_ctx.client_ip,
        &dispatch_ctx.parts.headers,
        handle_websocket_to_appserver,
        handle_websocket_tunnel,
    )
    .await
    {
        return response;
    }

    if let Some(resp) = maybe_handle_axum_dynamic_backend(
        dispatch_ctx.router,
        dispatch_ctx.target,
        dispatch_ctx.site_id,
        dispatch_ctx.path,
        dispatch_ctx.parts,
        dispatch_ctx.alt_svc,
        dispatch_ctx.main_config,
    )
    .await
    {
        return Ok(resp);
    }

    if let Some(resp) = maybe_handle_static_backend(
        dispatch_ctx.target,
        dispatch_ctx.path,
        dispatch_ctx.method,
        &dispatch_ctx.parts.headers,
    )
    .await
    {
        return Ok(resp);
    }

    #[cfg(feature = "mesh")]
    if matches!(
        dispatch_ctx.target.backend_type,
        crate::router::BackendType::Serverless
    ) {
        if let Some(response) = maybe_handle_serverless_backend(
            dispatch_ctx.serverless_manager,
            dispatch_ctx.mesh_transport,
            dispatch_ctx.method,
            dispatch_ctx.path,
            dispatch_ctx.parts,
            dispatch_ctx.full_body_arc,
            dispatch_ctx.ipc.clone(),
            dispatch_ctx.worker_id,
            dispatch_ctx.main_config,
            dispatch_ctx.client_ip,
            dispatch_ctx.method_str,
            dispatch_ctx.start,
            dispatch_ctx.site_id,
            dispatch_ctx.user_agent,
            dispatch_ctx.alt_svc,
            HttpServer::send_request_log_if_enabled,
        )
        .await
        {
            return response;
        }
    }

    if let Some(response) = maybe_handle_spin_backend(
        dispatch_ctx.target,
        dispatch_ctx.site_id,
        dispatch_ctx.path,
        dispatch_ctx.parts,
        dispatch_ctx.full_body_arc,
        dispatch_ctx.ipc.clone(),
        dispatch_ctx.worker_id,
        dispatch_ctx.main_config,
        dispatch_ctx.client_ip,
        dispatch_ctx.method_str,
        dispatch_ctx.start,
        dispatch_ctx.user_agent,
        dispatch_ctx.alt_svc,
        HttpServer::send_request_log_if_enabled,
    )
    .await
    {
        return Ok(response);
    }

    if let Some(response) = maybe_handle_fastcgi_or_php_backend(
        dispatch_ctx.target,
        dispatch_ctx.router,
        dispatch_ctx.waf,
        dispatch_ctx.site_id,
        dispatch_ctx.path,
        dispatch_ctx.method,
        dispatch_ctx.parts,
        dispatch_ctx.full_body_arc,
        dispatch_ctx.alt_svc,
        dispatch_ctx.main_config,
    )
    .await
    {
        return Ok(response);
    }

    if let Some(response) = maybe_handle_cgi_backend(
        dispatch_ctx.target,
        dispatch_ctx.site_id,
        dispatch_ctx.path,
        dispatch_ctx.method,
        dispatch_ctx.parts,
        dispatch_ctx.full_body_arc,
        dispatch_ctx.client_ip,
        dispatch_ctx.alt_svc,
        dispatch_ctx.main_config,
    )
    .await
    {
        return Ok(response);
    }

    if let Some(response) = maybe_handle_app_server_backend(
        dispatch_ctx.app_servers,
        dispatch_ctx.target,
        dispatch_ctx.site_id,
        dispatch_ctx.path,
        dispatch_ctx.method,
        dispatch_ctx.parts,
        dispatch_ctx.full_body_arc,
        dispatch_ctx.alt_svc,
        dispatch_ctx.main_config,
    )
    .await
    {
        return Ok(response);
    }

    #[cfg(feature = "mesh")]
    if let Some(response) = maybe_handle_mesh_backend(
        dispatch_ctx.mesh_backend_pool,
        dispatch_ctx.target,
        dispatch_ctx.site_id,
        dispatch_ctx.path,
        dispatch_ctx.parts,
        dispatch_ctx.full_body_arc,
        dispatch_ctx.main_config,
        dispatch_ctx.alt_svc,
        dispatch_ctx.metrics,
        dispatch_ctx.request_body_size,
        || {
            if let Some(rm) = dispatch_ctx.req_metrics {
                rm.record_upstream_success();
            }
        },
        || {
            if let Some(rm) = dispatch_ctx.req_metrics {
                rm.record_upstream_failure();
            }
        },
    )
    .await
    {
        return response;
    }

    if let Some(response) = maybe_handle_wasm_request_filter(
        dispatch_ctx.router,
        dispatch_ctx.target,
        dispatch_ctx.path,
        dispatch_ctx.method,
        dispatch_ctx.parts,
        dispatch_ctx.body_slice,
        dispatch_ctx.client_ip,
        dispatch_ctx.waf,
        dispatch_ctx.alt_svc,
        dispatch_ctx.main_config,
        |status| {
            HttpServer::send_request_log_if_enabled(
                dispatch_ctx.ipc.clone(),
                dispatch_ctx.worker_id,
                dispatch_ctx.main_config,
                dispatch_ctx.client_ip,
                dispatch_ctx.method_str,
                dispatch_ctx.path,
                status,
                dispatch_ctx.start.elapsed().as_millis() as u64,
                dispatch_ctx.site_id,
                dispatch_ctx.user_agent,
                false,
            );
        },
    ) {
        return Ok(response);
    }

    let content_type = dispatch_ctx
        .parts
        .headers
        .get("content-type")
        .and_then(|v| v.to_str().ok());
    if let Some(response) = maybe_handle_upload_validation(
        dispatch_ctx.waf,
        &dispatch_ctx.target.site_id,
        dispatch_ctx.path,
        dispatch_ctx.client_ip,
        dispatch_ctx.full_body_arc,
        dispatch_ctx.alt_svc,
        dispatch_ctx.main_config,
        content_type,
    )
    .await
    {
        return Ok(response);
    }

    let upstream_ctx = PassUpstreamProxyContext {
        target: dispatch_ctx.target,
        path: dispatch_ctx.path,
        main_config: dispatch_ctx.main_config,
        router: dispatch_ctx.router,
        full_body_arc: dispatch_ctx.full_body_arc,
        upstream_client_registry: dispatch_ctx.upstream_client_registry,
        client: dispatch_ctx.client,
        client_ip: dispatch_ctx.client_ip,
        parts: dispatch_ctx.parts,
        method: dispatch_ctx.method,
        req_metrics: dispatch_ctx.req_metrics,
        metrics: dispatch_ctx.metrics,
        request_body_size: dispatch_ctx.request_body_size,
        site_id: dispatch_ctx.site_id,
        alt_svc: dispatch_ctx.alt_svc,
        #[cfg(feature = "mesh")]
        mesh_transport: dispatch_ctx.mesh_transport,
    };
    handle_pass_upstream_proxy_phase(upstream_ctx).await
}
