use std::convert::Infallible;
use std::net::IpAddr;
use std::sync::{Arc, Mutex};
use std::time::Instant;

use bytes::Bytes;
use http::Response;
use http_body_util::combinators::BoxBody;
use metrics::counter;

use synvoid_config::MainConfig;
use synvoid_proxy::RouteTarget;
use synvoid_waf::{ConnectionLimitError, ConnectionLimiter, ConnectionToken};

use crate::response_builder::build_response_with_alt_svc;

pub struct ConnectionTokenGuard {
    limiter: Arc<ConnectionLimiter>,
    token: Arc<Mutex<Option<ConnectionToken>>>,
}

impl ConnectionTokenGuard {
    pub fn new(limiter: Arc<ConnectionLimiter>, token: ConnectionToken) -> Self {
        Self {
            limiter,
            token: Arc::new(Mutex::new(Some(token))),
        }
    }

    pub fn release_and_acquire(&self, new_token: ConnectionToken) -> Option<ConnectionToken> {
        let mut guard = self
            .token
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let old_token = guard.take();
        *guard = Some(new_token);
        old_token
    }

    pub async fn maybe_enforce_site_connection_limits(
        &self,
        connection_limiter: Option<&Arc<ConnectionLimiter>>,
        site_id: &str,
        client_ip: IpAddr,
        site_max_connections: Option<u32>,
        site_max_per_ip: Option<u32>,
    ) -> Result<(), ConnectionLimitError> {
        if site_max_connections.is_none() && site_max_per_ip.is_none() {
            return Ok(());
        }

        let Some(conn_limiter) = connection_limiter else {
            return Ok(());
        };

        let new_token = conn_limiter
            .try_acquire_with_limits(site_id, client_ip, site_max_connections, site_max_per_ip)
            .await?;
        self.release_and_acquire(new_token);
        Ok(())
    }
}

pub async fn maybe_enforce_http3_site_connection_limits(
    connection_guard: Option<&ConnectionTokenGuard>,
    connection_limiter: Option<&Arc<ConnectionLimiter>>,
    route_target: &RouteTarget,
    client_ip: IpAddr,
) -> Result<(), ConnectionLimitError> {
    let site_id = route_target.site_id.as_ref();
    let site_traffic_config = &route_target.site_config.traffic_shaping.connection;
    let site_max_connections = site_traffic_config.max_connections;
    let site_max_per_ip = site_traffic_config.max_connections_per_ip;

    if let Some(guard) = connection_guard {
        guard
            .maybe_enforce_site_connection_limits(
                connection_limiter,
                site_id,
                client_ip,
                site_max_connections,
                site_max_per_ip,
            )
            .await
    } else {
        Ok(())
    }
}

impl Drop for ConnectionTokenGuard {
    fn drop(&mut self) {
        if let Some(token) = self
            .token
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .take()
        {
            self.limiter.release(token);
        }
    }
}

pub enum TrafficControlOutcome {
    Continue {
        conn_guard: Option<ConnectionTokenGuard>,
    },
    Respond(Response<BoxBody<Bytes, Infallible>>),
}

#[allow(clippy::too_many_arguments)]
pub async fn maybe_enforce_request_traffic_limits<LogFn>(
    connection_limiter: Option<Arc<ConnectionLimiter>>,
    client_ip: IpAddr,
    path: String,
    start: Instant,
    is_over_bandwidth_limit: bool,
    alt_svc: Option<String>,
    main_config: Arc<MainConfig>,
    mut on_log: LogFn,
) -> TrafficControlOutcome
where
    LogFn: FnMut(u16, u64, &str, &str, &str, Option<&str>, bool) + Send + 'static,
{
    let connection_token = if let Some(ref conn_limiter) = connection_limiter {
        match conn_limiter.try_acquire("_http_", client_ip).await {
            Ok(token) => Some(token),
            Err(e) => {
                tracing::warn!("Connection limit exceeded for {}: {}", client_ip, e);
                counter!("synvoid.traffic.connection_limited").increment(1);
                on_log(
                    503,
                    start.elapsed().as_millis() as u64,
                    "internal",
                    "UNKNOWN",
                    &path,
                    None,
                    true,
                );
                return TrafficControlOutcome::Respond(build_response_with_alt_svc(
                    503,
                    "Too Many Connections".to_string(),
                    "application/json",
                    &alt_svc,
                    main_config.as_ref(),
                ));
            }
        }
    } else {
        None
    };

    let conn_guard = if let (Some(limiter), Some(token)) = (connection_limiter, connection_token) {
        Some(ConnectionTokenGuard::new(limiter, token))
    } else {
        None
    };

    if is_over_bandwidth_limit {
        tracing::warn!("Monthly bandwidth limit exceeded - returning 503");
        counter!("synvoid.bandwidth.limit_exceeded").increment(1);
        on_log(
            503,
            start.elapsed().as_millis() as u64,
            "internal",
            "UNKNOWN",
            &path,
            None,
            true,
        );
        return TrafficControlOutcome::Respond(build_response_with_alt_svc(
            503,
            "Monthly Bandwidth Limit Exceeded".to_string(),
            "text/plain",
            &alt_svc,
            main_config.as_ref(),
        ));
    }

    TrafficControlOutcome::Continue { conn_guard }
}
