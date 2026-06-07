use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;

use bytes::Bytes;
use http::Response;
use http_body_util::combinators::BoxBody;
use std::convert::Infallible;

use synvoid_config::MainConfig;

use crate::internal_endpoint_dispatch::{dispatch_internal_endpoint, InternalEndpointDispatch};
use crate::request_parse::sanitize_and_resolve_client_ip;
#[cfg(feature = "mesh")]
use crate::special_request_paths::{maybe_handle_special_request_paths, SpecialRequestDispatch};
use crate::HttpDrainControl;

#[cfg(feature = "mesh")]
use synvoid_mesh::transports::MeshTransportManager;
#[cfg(feature = "mesh")]
use synvoid_mesh::MeshConfig;

pub struct FrontdoorRequest {
    pub req: hyper::Request<hyper::body::Incoming>,
    pub client_ip: IpAddr,
    pub path: String,
}

pub enum RequestFrontdoorOutcome {
    Continue(FrontdoorRequest),
    Respond(Response<BoxBody<Bytes, Infallible>>),
}

pub struct RequestFrontdoorContext<'a, D> {
    pub req: hyper::Request<hyper::body::Incoming>,
    pub client_ip: IpAddr,
    pub local_addr: Option<SocketAddr>,
    pub drain_state: &'a Option<Arc<D>>,
    pub alt_svc: &'a Option<String>,
    pub main_config: &'a Arc<MainConfig>,
    #[cfg(feature = "mesh")]
    pub mesh_config: &'a Option<Arc<MeshConfig>>,
    #[cfg(feature = "mesh")]
    pub mesh_transport: &'a Option<Arc<MeshTransportManager>>,
}

pub async fn prepare_request_frontdoor<D: HttpDrainControl>(
    ctx: RequestFrontdoorContext<'_, D>,
) -> Result<RequestFrontdoorOutcome, hyper::Error> {
    let RequestFrontdoorContext {
        mut req,
        client_ip,
        local_addr,
        drain_state,
        alt_svc,
        main_config,
        #[cfg(feature = "mesh")]
        mesh_config,
        #[cfg(feature = "mesh")]
        mesh_transport,
    } = ctx;

    let client_ip = sanitize_and_resolve_client_ip(
        req.headers_mut(),
        &main_config.server.trusted_proxies,
        client_ip,
    );
    let path = req
        .uri()
        .path_and_query()
        .map(|pq| pq.path())
        .unwrap_or("/")
        .to_string();

    let req =
        match dispatch_internal_endpoint(req, &path, client_ip, drain_state, alt_svc, main_config)
            .await?
        {
            InternalEndpointDispatch::Handled(response) => {
                return Ok(RequestFrontdoorOutcome::Respond(response));
            }
            InternalEndpointDispatch::NotHandled(req) => req,
        };

    #[cfg(feature = "mesh")]
    let req = match maybe_handle_special_request_paths(
        req,
        &path,
        client_ip,
        alt_svc,
        main_config,
        mesh_config,
        mesh_transport,
    )
    .await?
    {
        SpecialRequestDispatch::Handled(response) => {
            return Ok(RequestFrontdoorOutcome::Respond(response));
        }
        SpecialRequestDispatch::NotHandled(req) => req,
    };

    #[cfg(not(feature = "mesh"))]
    let req = req;

    let _ = local_addr;

    Ok(RequestFrontdoorOutcome::Continue(FrontdoorRequest {
        req,
        client_ip,
        path,
    }))
}
