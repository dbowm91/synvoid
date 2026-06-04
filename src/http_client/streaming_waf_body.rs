use std::net::IpAddr;

use bytes::Bytes;

/// A streaming body wrapper that performs WAF scanning on chunks as they pass through.
/// This enables true streaming: body is scanned and forwarded without full buffering.
pub struct StreamingWafBody<B> {
    inner: B,
    streaming_waf: Option<crate::waf::attack_detection::StreamingWafCore>,
    client_ip: IpAddr,
    blocked: bool,
    error_sent: bool,
}

impl<B> StreamingWafBody<B>
where
    B: http_body::Body<Data = Bytes> + Unpin,
    B::Error: std::fmt::Debug,
{
    pub fn new(
        inner: B,
        streaming_waf: Option<crate::waf::attack_detection::StreamingWafCore>,
        client_ip: IpAddr,
    ) -> Self {
        Self {
            inner,
            streaming_waf,
            client_ip,
            blocked: false,
            error_sent: false,
        }
    }
}

impl<B> hyper::body::Body for StreamingWafBody<B>
where
    B: http_body::Body<Data = Bytes> + Unpin,
    B::Error: std::fmt::Debug + Send,
{
    type Data = Bytes;
    type Error = std::io::Error;

    fn poll_frame(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Result<hyper::body::Frame<Self::Data>, Self::Error>>> {
        if self.blocked {
            if !self.error_sent {
                self.error_sent = true;
                let msg = "Request blocked by WAF during streaming body scan";
                return std::task::Poll::Ready(Some(Err(std::io::Error::new(
                    std::io::ErrorKind::PermissionDenied,
                    msg,
                ))));
            }
            return std::task::Poll::Ready(None);
        }

        let this = &mut *self;
        match std::pin::Pin::new(&mut this.inner).poll_frame(cx) {
            std::task::Poll::Ready(Some(Ok(frame))) => {
                if let Some(data) = frame.data_ref() {
                    if let Some(ref mut sw) = this.streaming_waf {
                        match sw.scan_chunk(&data) {
                            crate::waf::attack_detection::StreamingWafDecision::Block(_, _) => {
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
                            crate::waf::attack_detection::StreamingWafDecision::Continue => {}
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
