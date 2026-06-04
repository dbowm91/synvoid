//! Minimal streaming body trait for WASM plugin consumption.
//! Decouples the runtime from any specific HTTP body implementation.

use bytes::Bytes;
use http_body::Body;
use std::pin::Pin;
use std::task::{Context, Poll};

/// A streaming body that can be consumed incrementally by WASM plugins.
pub trait StreamingBody: Send + Sync + 'static {
    fn poll_frame(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<http_body::Frame<Bytes>, std::io::Error>>>;

    fn size_hint(&self) -> http_body::SizeHint;
}

/// Blanket impl: any http_body::Body<Data=Bytes, Error=io::Error> is a StreamingBody.
impl<B> StreamingBody for B
where
    B: Body<Data = Bytes, Error = std::io::Error> + Send + Sync + Unpin + 'static,
{
    fn poll_frame(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<http_body::Frame<Bytes>, std::io::Error>>> {
        Pin::new(self).poll_frame(cx)
    }

    fn size_hint(&self) -> http_body::SizeHint {
        Body::size_hint(self)
    }
}
