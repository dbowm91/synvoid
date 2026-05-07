use bytes::Bytes;
use http_body::{Body, Frame};
use std::pin::Pin;
use std::task::{Context, Poll};
use std::sync::Arc;
use crate::proxy_cache::{ProxyCache, CacheKey};
use crate::buffer::PooledBuf;

/// A body wrapper that tees the stream into a buffer for caching.
pub struct TeeBody<B> {
    inner: B,
    cache: Option<Arc<ProxyCache>>,
    cache_key: Option<CacheKey>,
    status: u16,
    headers: http::HeaderMap,
    max_age: Option<std::time::Duration>,
    buffer: Option<PooledBuf>,
    max_size: usize,
}

impl<B> TeeBody<B>
where
    B: Body<Data = Bytes> + Unpin,
{
    pub fn new(
        inner: B,
        cache: Option<Arc<ProxyCache>>,
        cache_key: Option<CacheKey>,
        status: u16,
        headers: http::HeaderMap,
        max_age: Option<std::time::Duration>,
        max_size: usize,
    ) -> Self {
        let buffer = if cache.is_some() && cache_key.is_some() {
            Some(crate::buffer::BufferPool::acquire(0))
        } else {
            None
        };

        Self {
            inner,
            cache,
            cache_key,
            status,
            headers,
            max_age,
            buffer,
            max_size,
        }
    }
}

impl<B> Body for TeeBody<B>
where
    B: Body<Data = Bytes> + Unpin,
    B::Error: std::fmt::Debug,
{
    type Data = Bytes;
    type Error = std::io::Error;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        let max_size = self.max_size;
        match Pin::new(&mut self.inner).poll_frame(cx) {
            Poll::Ready(Some(Ok(frame))) => {
                if let Some(data) = frame.data_ref() {
                    if let Some(ref mut buf) = self.buffer {
                        if buf.len() + data.len() <= max_size {
                            buf.extend_from_slice(data);
                        } else {
                            // Too large to cache, drop the buffer
                            self.buffer = None;
                        }
                    }
                }
                Poll::Ready(Some(Ok(frame)))
            }
            Poll::Ready(None) => {
                // Stream finished, insert into cache if we have a buffer
                if let (Some(cache), Some(key), Some(buf)) = (self.cache.take(), self.cache_key.take(), self.buffer.take()) {
                    let content = Bytes::copy_from_slice(buf.as_slice());
                    if let Err(e) = cache.insert(key, content, self.status, self.headers.clone(), self.max_age) {
                        tracing::warn!("Failed to cache teed response: {}", e);
                    }
                }
                Poll::Ready(None)
            }
            Poll::Ready(Some(Err(e))) => {
                Poll::Ready(Some(Err(std::io::Error::new(std::io::ErrorKind::Other, format!("{:?}", e)))))
            }
            Poll::Pending => Poll::Pending,
        }
    }

    fn is_end_stream(&self) -> bool {
        self.inner.is_end_stream()
    }

    fn size_hint(&self) -> http_body::SizeHint {
        self.inner.size_hint()
    }
}
