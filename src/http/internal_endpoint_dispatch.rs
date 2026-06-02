use bytes::Bytes;
use http::Response;
use http_body_util::combinators::BoxBody;
use std::convert::Infallible;
use std::net::IpAddr;
use std::sync::Arc;

use crate::config::MainConfig;
use crate::http::internal_handlers;
use crate::http::request_parse::{classify_internal_endpoint, InternalEndpointAction};
use crate::worker::drain_state::WorkerDrainState;

pub enum InternalEndpointDispatch {
    Handled(Response<BoxBody<Bytes, Infallible>>),
    NotHandled(hyper::Request<hyper::body::Incoming>),
}

pub async fn dispatch_internal_endpoint(
    req: hyper::Request<hyper::body::Incoming>,
    path: &str,
    client_ip: IpAddr,
    drain_state: &Option<Arc<WorkerDrainState>>,
    alt_svc: &Option<String>,
    main_config: &Arc<MainConfig>,
) -> Result<InternalEndpointDispatch, hyper::Error> {
    match classify_internal_endpoint(path, client_ip, drain_state.is_some()) {
        InternalEndpointAction::Drain => {
            if let Some(state) = drain_state {
                let response =
                    internal_handlers::handle_drain_request(req, state, alt_svc, main_config)
                        .await?;
                return Ok(InternalEndpointDispatch::Handled(response));
            }
        }
        InternalEndpointAction::DrainStatus => {
            if let Some(state) = drain_state {
                let response = internal_handlers::handle_drain_status_request(
                    req,
                    state,
                    alt_svc,
                    main_config,
                )
                .await?;
                return Ok(InternalEndpointDispatch::Handled(response));
            }
        }
        InternalEndpointAction::Health => {
            let response =
                internal_handlers::handle_health_request(drain_state, alt_svc, main_config).await?;
            return Ok(InternalEndpointDispatch::Handled(response));
        }
        InternalEndpointAction::Ready => {
            let response =
                internal_handlers::handle_ready_request(drain_state, alt_svc, main_config).await?;
            return Ok(InternalEndpointDispatch::Handled(response));
        }
        InternalEndpointAction::None => {}
    }

    Ok(InternalEndpointDispatch::NotHandled(req))
}
