use std::net::IpAddr;

use bytes::Bytes;

pub use synvoid_core::streaming_waf::{StreamingWafDecision, StreamingWafScanner};

/// A streaming body wrapper that performs WAF scanning on chunks as they pass through.
/// This enables true streaming: body is scanned and forwarded without full buffering.
pub struct StreamingWafBody<B, S> {
    inner: B,
    streaming_waf: Option<S>,
    client_ip: IpAddr,
    blocked: bool,
    error_sent: bool,
}

impl<B, S> StreamingWafBody<B, S>
where
    B: http_body::Body<Data = Bytes> + Unpin,
    B::Error: std::fmt::Debug,
    S: StreamingWafScanner,
{
    pub fn new(inner: B, streaming_waf: Option<S>, client_ip: IpAddr) -> Self {
        Self {
            inner,
            streaming_waf,
            client_ip,
            blocked: false,
            error_sent: false,
        }
    }
}

impl<B, S> hyper::body::Body for StreamingWafBody<B, S>
where
    B: http_body::Body<Data = Bytes> + Unpin,
    B::Error: std::fmt::Debug + Send,
    S: StreamingWafScanner + Send + Sync + Unpin + 'static,
{
    type Data = Bytes;
    type Error = std::io::Error;

    fn poll_frame(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Result<hyper::body::Frame<Self::Data>, Self::Error>>> {
        let this = self.get_mut();

        if this.blocked {
            if !this.error_sent {
                this.error_sent = true;
                let msg = "Request blocked by WAF during streaming body scan";
                return std::task::Poll::Ready(Some(Err(std::io::Error::new(
                    std::io::ErrorKind::PermissionDenied,
                    msg,
                ))));
            }
            return std::task::Poll::Ready(None);
        }

        match std::pin::Pin::new(&mut this.inner).poll_frame(cx) {
            std::task::Poll::Ready(Some(Ok(frame))) => {
                if let Some(data) = frame.data_ref() {
                    if let Some(ref mut sw) = this.streaming_waf {
                        match sw.scan_chunk(data) {
                            StreamingWafDecision::Block(_, _) => {
                                tracing::warn!(
                                    client_ip = %this.client_ip,
                                    "Request blocked by streaming WAF mid-body"
                                );
                                metrics::counter!("synvoid.http.streaming_body_blocked")
                                    .increment(1);
                                this.blocked = true;
                                return std::task::Poll::Ready(Some(Err(std::io::Error::new(
                                    std::io::ErrorKind::PermissionDenied,
                                    "Request blocked by WAF",
                                ))));
                            }
                            StreamingWafDecision::Continue => {}
                        }
                    }
                }
                std::task::Poll::Ready(Some(Ok(frame)))
            }
            std::task::Poll::Ready(Some(Err(e))) => std::task::Poll::Ready(Some(Err(
                std::io::Error::new(std::io::ErrorKind::Other, format!("body error: {:?}", e)),
            ))),
            std::task::Poll::Ready(None) => std::task::Poll::Ready(None),
            std::task::Poll::Pending => std::task::Poll::Pending,
        }
    }

    fn size_hint(&self) -> hyper::body::SizeHint {
        self.inner.size_hint()
    }
}
