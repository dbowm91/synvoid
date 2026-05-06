//! Type-erased connection pool for true streaming HTTP requests.
//!
//! This module provides type-erased connection pooling to avoid per-request boxing
//! at the 1M RPS scale. Connection checkout happens ~10K-100K times/second, amortized
//! over many requests, vs 1M times/second for per-request boxing.

use bytes::Bytes;
use http::{Request, Response};
use http_body::Body as HttpBody;
use hyper::body::{Frame, SizeHint};
use hyper::client::conn::http1 as http1_client;
use hyper_util::rt::TokioIo;
use std::error::Error;
use std::fmt;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

/// Implement `http_body::Body` for `Box<dyn ErasedBody>` so it can be used
/// with hyper's client. This is the key bridge between our `ErasedBody` trait
/// and hyper's body requirements.
///
/// Without this, `Box<dyn ErasedBody>` cannot satisfy `http_body::Body` bounds
/// because traits don't support extension.
impl http_body::Body for Box<dyn ErasedBody> {
    type Data = Bytes;
    type Error = std::io::Error;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        ErasedBody::poll_frame(self.as_mut().get_mut().as_mut(), cx)
    }

    fn size_hint(&self) -> SizeHint {
        self.as_ref().size_hint()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HttpProtocol {
    Http1,
    Http2,
}

pub trait ErasedBody: Send + Sync + 'static {
    fn poll_frame(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, std::io::Error>>>;
    fn size_hint(&self) -> SizeHint;
}

pub struct ErasedBodyImpl<B> {
    inner: B,
}

impl<B> ErasedBodyImpl<B>
where
    B: HttpBody<Data = Bytes> + Send + Sync + Unpin + 'static,
    B::Error: fmt::Debug + Send,
{
    pub fn new(inner: B) -> Box<dyn ErasedBody> {
        Box::new(Self { inner })
    }
}

impl<B> ErasedBody for ErasedBodyImpl<B>
where
    B: HttpBody<Data = Bytes> + Send + Sync + Unpin + 'static,
    B::Error: fmt::Debug + Send,
{
    fn poll_frame(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, std::io::Error>>> {
        let pin_inner = Pin::new(&mut self.inner);
        pin_inner.poll_frame(cx).map(|opt| {
            opt.map(|result| {
                result.map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, format!("body error: {:?}", e)))
            })
        })
    }

    fn size_hint(&self) -> SizeHint {
        self.inner.size_hint()
    }
}

pub type BoxErasedBody = Box<dyn ErasedBody>;

pub trait PooledConnection: Send + Sync + 'static {
    fn protocol(&self) -> HttpProtocol;
    fn is_available(&self) -> bool;
    fn box_body<B>(body: B) -> BoxErasedBody
    where
        B: hyper::body::Body<Data = Bytes> + Send + Sync + Unpin + 'static,
        B::Error: fmt::Debug + Send;
}

#[derive(Clone, Eq, PartialEq, Hash, Debug)]
pub struct PoolKey {
    pub authority: String,
    pub is_http2: bool,
}

pub struct Http1PooledConnection {
    io: Option<TokioIo<tokio::net::TcpStream>>,
    authority: http::uri::Authority,
}

impl Http1PooledConnection {
    pub fn new(
        io: TokioIo<tokio::net::TcpStream>,
        authority: http::uri::Authority,
    ) -> Self {
        Self { io: Some(io), authority }
    }

    #[cfg(test)]
    pub fn new_for_test(authority: http::uri::Authority) -> Self {
        Self { io: None, authority }
    }
}

impl PooledConnection for Http1PooledConnection {
    fn protocol(&self) -> HttpProtocol {
        HttpProtocol::Http1
    }

    fn is_available(&self) -> bool {
        self.io.is_some()
    }

    fn box_body<B>(body: B) -> BoxErasedBody
    where
        B: hyper::body::Body<Data = Bytes> + Send + Sync + Unpin + 'static,
        B::Error: fmt::Debug + Send,
    {
        Box::new(ErasedBodyImpl { inner: body })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::pin::Pin;
    use std::task::{Context, Poll};

    struct TestBody {
        data: Bytes,
        offset: usize,
    }

    impl TestBody {
        fn new(data: Bytes) -> Self {
            Self { data, offset: 0 }
        }
    }

    impl HttpBody for TestBody {
        type Data = Bytes;
        type Error = std::io::Error;

        fn poll_frame(
            mut self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
        ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
            if self.offset >= self.data.len() {
                Poll::Ready(None)
            } else {
                let chunk = self.data.slice(self.offset..self.offset + 1);
                self.offset += 1;
                Poll::Ready(Some(Ok(Frame::data(chunk))))
            }
        }

        fn size_hint(&self) -> SizeHint {
            SizeHint::with_exact(self.data.len() as u64)
        }
    }

    #[test]
    fn test_erased_body_boxing() {
        let body = TestBody::new(Bytes::from_static(b"hello"));
        let boxed: BoxErasedBody = ErasedBodyImpl::new(body);
        assert_eq!(boxed.size_hint().exact(), Some(5));
    }

    #[test]
    fn test_pool_key_derive() {
        let key1 = PoolKey {
            authority: "example.com:80".to_string(),
            is_http2: false,
        };
        let key2 = PoolKey {
            authority: "example.com:80".to_string(),
            is_http2: false,
        };
        let key3 = PoolKey {
            authority: "example.com:80".to_string(),
            is_http2: true,
        };
        assert_eq!(key1, key2);
        assert_ne!(key1, key3);
        assert_eq!(key1.clone(), key1);
    }

    #[test]
    fn test_http1_pooled_connection_is_available() {
        let authority: http::uri::Authority = "example.com:80".parse().unwrap();
        let conn = Http1PooledConnection::new_for_test(authority);
        assert_eq!(conn.protocol(), HttpProtocol::Http1);
        assert!(!conn.is_available());
    }
}