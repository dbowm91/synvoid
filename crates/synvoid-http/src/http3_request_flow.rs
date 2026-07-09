use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Instant;

use async_trait::async_trait;
use bytes::{Buf, Bytes};
use http::Response;
use metrics::{counter, histogram};

use synvoid_proxy::Router;
use synvoid_waf::ConnectionLimiter;

use crate::http3_request_prelude::{
    prepare_http3_request_prelude, Http3RequestPrelude, Http3RequestPreludeOutcome,
};
use crate::traffic_control::ConnectionTokenGuard;

pub struct Http3RequestDispatchContext<W> {
    pub prelude: Http3RequestPrelude,
    pub request_stream: W,
    pub connection_guard: Option<ConnectionTokenGuard>,
}

pub enum Http3RequestDispatchOutcome<W> {
    Continue(Box<Http3RequestDispatchContext<W>>),
    Respond,
}

#[async_trait::async_trait]
pub trait Http3RequestResolver: Send {
    type RequestStream: crate::Http3RequestStream + Send;
    type Error: std::error::Error + Send + Sync + 'static;

    async fn resolve_request(self)
        -> Result<(http::Request<()>, Self::RequestStream), Self::Error>;
}

pub async fn prepare_http3_request_dispatch<R>(
    start: Instant,
    resolver: R,
    remote_addr: SocketAddr,
    trusted_proxies: &[String],
    router: &Arc<Router>,
    connection_limiter: Option<&Arc<ConnectionLimiter>>,
    over_bandwidth_limit: bool,
) -> Result<Http3RequestDispatchOutcome<R::RequestStream>, R::Error>
where
    R: Http3RequestResolver,
{
    let client_ip = remote_addr.ip();

    let connection_guard = if let Some(conn_limiter) = connection_limiter {
        match conn_limiter.try_acquire("_http3_", client_ip).await {
            Ok(token) => Some(ConnectionTokenGuard::new(conn_limiter.clone(), token)),
            Err(e) => {
                tracing::warn!("HTTP/3 connection limit exceeded for {}: {}", client_ip, e);
                counter!("synvoid.http3.connection_limited").increment(1);
                return Ok(Http3RequestDispatchOutcome::Respond);
            }
        }
    } else {
        None
    };

    let (request, request_stream) = match resolver.resolve_request().await {
        Ok(result) => result,
        Err(e) => {
            counter!("synvoid.http3.request.errors").increment(1);
            histogram!("synvoid.http3.request.duration").record(start.elapsed().as_secs_f64());
            return Err(e);
        }
    };

    match prepare_http3_request_prelude(
        request,
        remote_addr,
        trusted_proxies,
        router,
        over_bandwidth_limit,
    ) {
        Http3RequestPreludeOutcome::Continue(prelude) => Ok(Http3RequestDispatchOutcome::Continue(
            Box::new(Http3RequestDispatchContext {
                prelude: *prelude,
                request_stream,
                connection_guard,
            }),
        )),
        Http3RequestPreludeOutcome::Respond => Ok(Http3RequestDispatchOutcome::Respond),
    }
}

#[async_trait]
impl<S, B> crate::Http3RequestStream for h3::server::RequestStream<S, B>
where
    S: h3::quic::RecvStream + h3::quic::SendStream<B> + Send,
    B: Buf + Send + From<Bytes>,
{
    type Error = h3::error::StreamError;

    async fn recv_data(&mut self) -> Result<Option<Bytes>, Self::Error> {
        let chunk = h3::server::RequestStream::recv_data(self).await?;
        Ok(chunk.map(|mut chunk| {
            let len = chunk.remaining();
            chunk.copy_to_bytes(len)
        }))
    }

    async fn send_response(&mut self, response: Response<()>) -> Result<(), Self::Error> {
        h3::server::RequestStream::send_response(self, response).await
    }

    async fn send_data(&mut self, body: Bytes) -> Result<(), Self::Error> {
        h3::server::RequestStream::send_data(self, body.into()).await
    }

    async fn finish(&mut self) -> Result<(), Self::Error> {
        h3::server::RequestStream::finish(self).await
    }
}

#[async_trait]
impl<C, B> Http3RequestResolver for h3::server::RequestResolver<C, B>
where
    C: h3::quic::Connection<B> + Send,
    C::BidiStream: h3::quic::SendStream<B> + Send,
    B: Buf + Send + From<Bytes>,
{
    type RequestStream = h3::server::RequestStream<C::BidiStream, B>;
    type Error = h3::error::StreamError;

    async fn resolve_request(
        self,
    ) -> Result<(http::Request<()>, Self::RequestStream), Self::Error> {
        h3::server::RequestResolver::resolve_request(self).await
    }
}
