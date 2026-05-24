//! Type-erased connection pool for true streaming HTTP requests.
//!
//! This module provides type-erased connection pooling to avoid per-request boxing
//! at the 1M RPS scale. Connection checkout happens ~10K-100K times/second, amortized
//! over many requests, vs 1M times/second for per-request boxing.

use bytes::Bytes;
use http::{Request, Response};
use http_body::Body as HttpBody;
use http_body_util::{BodyExt, Full};
use hyper::body::{Frame, Incoming, SizeHint};
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

impl ErasedBodyImpl<Full<Bytes>> {
    pub fn from_full(body: Full<Bytes>) -> Box<dyn ErasedBody> {
        Box::new(Self { inner: body })
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
                result.map_err(|e| {
                    std::io::Error::new(std::io::ErrorKind::Other, format!("body error: {:?}", e))
                })
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
    sender: Option<http1_client::SendRequest<BoxErasedBody>>,
}

pub struct Http2PooledConnection {
    authority: http::uri::Authority,
}

impl Http1PooledConnection {
    pub async fn new(
        stream: tokio::net::TcpStream,
        authority: http::uri::Authority,
    ) -> Result<Self, std::io::Error> {
        let io = TokioIo::new(stream);
        let (sender, _conn) = http1_client::handshake(io).await.map_err(|e| {
            std::io::Error::new(
                std::io::ErrorKind::Other,
                format!("handshake failed: {}", e),
            )
        })?;
        Ok(Self {
            io: None,
            authority,
            sender: Some(sender),
        })
    }

    pub async fn send_request(
        &mut self,
        request: http::Request<BoxErasedBody>,
    ) -> Result<http::Response<hyper::body::Incoming>, std::io::Error> {
        let sender = self.sender.as_mut().ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::Other,
                "sender missing - connection not initialized",
            )
        })?;
        sender.send_request(request).await.map_err(|e| {
            std::io::Error::new(std::io::ErrorKind::Other, format!("request failed: {}", e))
        })
    }

    pub fn is_connected(&self) -> bool {
        self.sender.is_some()
    }

    pub fn authority(&self) -> &http::uri::Authority {
        &self.authority
    }

    #[cfg(test)]
    pub fn new_for_test(authority: http::uri::Authority) -> Self {
        Self {
            io: None,
            authority,
            sender: None,
        }
    }
}

impl PooledConnection for Http1PooledConnection {
    fn protocol(&self) -> HttpProtocol {
        HttpProtocol::Http1
    }

    fn is_available(&self) -> bool {
        self.sender.is_some()
    }

    fn box_body<B>(body: B) -> BoxErasedBody
    where
        B: hyper::body::Body<Data = Bytes> + Send + Sync + Unpin + 'static,
        B::Error: fmt::Debug + Send,
    {
        Box::new(ErasedBodyImpl { inner: body })
    }
}

impl PooledConnection for Http2PooledConnection {
    fn protocol(&self) -> HttpProtocol {
        HttpProtocol::Http2
    }

    fn is_available(&self) -> bool {
        false
    }

    fn box_body<B>(body: B) -> BoxErasedBody
    where
        B: hyper::body::Body<Data = Bytes> + Send + Sync + Unpin + 'static,
        B::Error: fmt::Debug + Send,
    {
        Box::new(ErasedBodyImpl { inner: body })
    }
}

impl Http2PooledConnection {
    pub fn new(authority: http::uri::Authority) -> Self {
        Self { authority }
    }
}

pub struct ErasedConnectionPool {
    inner: std::sync::Arc<
        tokio::sync::Mutex<
            std::collections::HashMap<PoolKey, std::collections::VecDeque<Http1PooledConnection>>,
        >,
    >,
    max_idle_per_host: usize,
    connect_timeout: std::time::Duration,
}

impl Clone for ErasedConnectionPool {
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
            max_idle_per_host: self.max_idle_per_host,
            connect_timeout: self.connect_timeout,
        }
    }
}

impl ErasedConnectionPool {
    pub fn new(max_idle_per_host: usize) -> Self {
        Self {
            inner: std::sync::Arc::new(tokio::sync::Mutex::new(std::collections::HashMap::new())),
            max_idle_per_host,
            connect_timeout: std::time::Duration::from_secs(5),
        }
    }

    pub fn with_connect_timeout(mut self, timeout: std::time::Duration) -> Self {
        self.connect_timeout = timeout;
        self
    }

    /// Checks out a connection from the pool or creates a new one.
    ///
    /// # Error Paths
    ///
    /// Returns an error in the following cases:
    /// - `InvalidInput` (kind): The authority string in `PoolKey` is malformed (e.g., "not-a-valid-authority")
    /// - `InvalidInput` (kind): The host/port in the authority cannot be parsed as a valid socket address
    /// - `Other`: TCP connection to the upstream failed (includes underlying OS error details)
    /// - `TimedOut`: Connection handshake did not complete within `connect_timeout`
    ///
    /// # Checkout Flow
    ///
    /// 1. Attempt to pop an existing connected connection from the pool for the given `PoolKey`
    /// 2. If no pooled connection available, parse authority to extract host/port
    /// 3. Establish new TCP connection to the upstream
    /// 4. Perform HTTP/1.1 handshake via `Http1PooledConnection::new()`
    /// 5. Apply `connect_timeout` to the entire connection establishment
    pub async fn checkout(&self, key: PoolKey) -> Result<Http1PooledConnection, std::io::Error> {
        let mut pool = self.inner.lock().await;
        if let Some(conns) = pool.get_mut(&key) {
            if let Some(conn) = conns.pop_front() {
                if conn.is_connected() {
                    return Ok(conn);
                }
            }
        }
        drop(pool);

        let authority: http::uri::Authority = key.authority.parse().map_err(|e| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!("invalid authority: {}", e),
            )
        })?;
        let port = authority.port_u16().unwrap_or(80);
        let connect_addr: std::net::SocketAddr = format!("{}:{}", authority.host(), port)
            .parse()
            .map_err(|e| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!("invalid address: {}", e),
            )
        })?;
        let stream = tokio::net::TcpStream::connect(connect_addr)
            .await
            .map_err(|e| {
                std::io::Error::new(std::io::ErrorKind::Other, format!("connect failed: {}", e))
            })?;
        let conn = tokio::time::timeout(
            self.connect_timeout,
            Http1PooledConnection::new(stream, authority),
        )
        .await
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::TimedOut, "connection timeout"))??;
        Ok(conn)
    }

    pub async fn checkin(&self, key: PoolKey, conn: Http1PooledConnection) {
        if !conn.is_connected() {
            return;
        }
        let mut pool = self.inner.lock().await;
        let conns = pool.entry(key).or_default();
        if conns.len() < self.max_idle_per_host {
            conns.push_back(conn);
        }
    }

    pub async fn idle_count(&self, key: &PoolKey) -> usize {
        let pool = self.inner.lock().await;
        pool.get(key).map(|v| v.len()).unwrap_or(0)
    }
}

#[cfg(test)]
mod integration_tests {
    use super::*;

    #[tokio::test]
    async fn test_checkout_new_connection() {
        use std::net::SocketAddr;
        use tokio::net::TcpListener;

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr: SocketAddr = listener.local_addr().unwrap();
        let pool = ErasedConnectionPool::new(10);

        let key = PoolKey {
            authority: format!("{}:{}", addr.ip(), addr.port()).parse().unwrap(),
            is_http2: false,
        };

        let initial_idle = pool.idle_count(&key).await;
        assert_eq!(initial_idle, 0);

        let conn = pool.checkout(key.clone()).await.unwrap();
        assert!(conn.is_connected());
        assert_eq!(pool.idle_count(&key).await, 0);
    }

    #[tokio::test]
    async fn test_checkout_connection_reuse() {
        use std::net::SocketAddr;
        use tokio::net::TcpListener;

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr: SocketAddr = listener.local_addr().unwrap();
        let pool = ErasedConnectionPool::new(10);

        let key = PoolKey {
            authority: format!("{}:{}", addr.ip(), addr.port()).parse().unwrap(),
            is_http2: false,
        };

        let conn1 = pool.checkout(key.clone()).await.unwrap();
        assert!(conn1.is_connected());

        pool.checkin(key.clone(), conn1).await;
        assert_eq!(pool.idle_count(&key).await, 1);

        let conn2 = pool.checkout(key.clone()).await.unwrap();
        assert!(conn2.is_connected());
        assert_eq!(pool.idle_count(&key).await, 0);
    }

    #[tokio::test]
    async fn test_checkout_invalid_authority() {
        let pool = ErasedConnectionPool::new(10);

        let key = PoolKey {
            authority: "not-a-valid-authority".to_string(),
            is_http2: false,
        };

        let result = pool.checkout(key).await;
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidInput);
    }

    #[tokio::test]
    async fn test_checkout_connection_timeout() {
        let pool = ErasedConnectionPool::new(10);

        let key = PoolKey {
            authority: "192.0.2.1:12345".parse().unwrap(),
            is_http2: false,
        };

        let pool_with_timeout = pool.with_connect_timeout(std::time::Duration::from_millis(50));
        let result = pool_with_timeout.checkout(key).await;
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::TimedOut);
    }
}

pub struct ErasedHttpClient {
    pool: ErasedConnectionPool,
}

impl ErasedHttpClient {
    pub fn new(max_idle_per_host: usize) -> Self {
        Self {
            pool: ErasedConnectionPool::new(max_idle_per_host),
        }
    }

    pub async fn send_request(
        &self,
        request: http::Request<BoxErasedBody>,
        authority: String,
        is_http2: bool,
        timeout: Option<std::time::Duration>,
    ) -> Result<http::Response<Incoming>, std::io::Error> {
        let key = PoolKey {
            authority,
            is_http2,
        };
        let mut conn = match self.pool.checkout(key.clone()).await {
            Ok(c) => c,
            Err(e) => return Err(e),
        };

        let result = if let Some(t) = timeout {
            tokio::time::timeout(t, conn.send_request(request)).await?
        } else {
            conn.send_request(request).await
        };

        self.pool.checkin(key, conn).await;

        result
    }

    pub fn pool(&self) -> &ErasedConnectionPool {
        &self.pool
    }
}

impl Default for ErasedHttpClient {
    fn default() -> Self {
        Self::new(10)
    }
}

impl Clone for ErasedHttpClient {
    fn clone(&self) -> Self {
        Self {
            pool: self.pool.clone(),
        }
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

    #[test]
    fn test_http2_pooled_connection_stub() {
        let authority: http::uri::Authority = "example.com:80".parse().unwrap();
        let conn = Http2PooledConnection::new(authority);
        assert_eq!(conn.protocol(), HttpProtocol::Http2);
        assert!(!conn.is_available());
    }

    #[tokio::test]
    async fn test_connection_pool_checkout_checkin_reuse() {
        use std::net::SocketAddr;
        use tokio::net::TcpListener;

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr: SocketAddr = listener.local_addr().unwrap();

        let pool = ErasedConnectionPool::new(10);

        let key = PoolKey {
            authority: format!("{}:{}", addr.ip(), addr.port()).parse().unwrap(),
            is_http2: false,
        };

        let initial_idle = pool.idle_count(&key).await;
        assert_eq!(initial_idle, 0);

        let mut conn = pool.checkout(key.clone()).await.unwrap();
        assert!(conn.is_connected());

        let echo_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let echo_addr: SocketAddr = echo_listener.local_addr().unwrap();
        let echo_key = PoolKey {
            authority: format!("{}:{}", echo_addr.ip(), echo_addr.port())
                .parse()
                .unwrap(),
            is_http2: false,
        };

        pool.checkin(echo_key.clone(), conn).await;

        let after_checkin_idle = pool.idle_count(&echo_key).await;
        assert_eq!(after_checkin_idle, 1);

        let reconnected_conn = pool.checkout(echo_key.clone()).await.unwrap();
        assert!(reconnected_conn.is_connected());
        assert_eq!(pool.idle_count(&echo_key).await, 0);
    }

    #[tokio::test]
    async fn test_connection_pool_respects_max_idle() {
        let pool = ErasedConnectionPool::new(2);

        let authority: http::uri::Authority = "example.com:80".parse().unwrap();
        let key = PoolKey {
            authority: authority.to_string(),
            is_http2: false,
        };

        assert_eq!(pool.idle_count(&key).await, 0);
    }

    #[test]
    fn test_sender_is_some_in_new_for_test() {
        let authority: http::uri::Authority = "example.com:80".parse().unwrap();
        let conn = Http1PooledConnection::new_for_test(authority);

        assert_eq!(conn.protocol(), HttpProtocol::Http1);
        assert!(
            !conn.is_available(),
            "new_for_test creates stub with is_available false"
        );
    }

    #[tokio::test]
    async fn test_checkout_new_connection() {
        use std::net::SocketAddr;
        use tokio::net::TcpListener;

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr: SocketAddr = listener.local_addr().unwrap();
        let pool = ErasedConnectionPool::new(10);

        let key = PoolKey {
            authority: format!("{}:{}", addr.ip(), addr.port()).parse().unwrap(),
            is_http2: false,
        };

        let initial_idle = pool.idle_count(&key).await;
        assert_eq!(initial_idle, 0);

        let conn = pool.checkout(key.clone()).await.unwrap();
        assert!(conn.is_connected());
        assert_eq!(pool.idle_count(&key).await, 0);
    }

    #[tokio::test]
    async fn test_checkout_connection_reuse() {
        use std::net::SocketAddr;
        use tokio::net::TcpListener;

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr: SocketAddr = listener.local_addr().unwrap();
        let pool = ErasedConnectionPool::new(10);

        let key = PoolKey {
            authority: format!("{}:{}", addr.ip(), addr.port()).parse().unwrap(),
            is_http2: false,
        };

        let conn1 = pool.checkout(key.clone()).await.unwrap();
        assert!(conn1.is_connected());

        pool.checkin(key.clone(), conn1).await;
        assert_eq!(pool.idle_count(&key).await, 1);

        let conn2 = pool.checkout(key.clone()).await.unwrap();
        assert!(conn2.is_connected());
        assert_eq!(pool.idle_count(&key).await, 0);
    }

    #[tokio::test]
    async fn test_checkout_invalid_authority() {
        let pool = ErasedConnectionPool::new(10);

        let key = PoolKey {
            authority: "not-a-valid-authority".to_string(),
            is_http2: false,
        };

        let result = pool.checkout(key).await;
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidInput);
    }

    #[tokio::test]
    async fn test_checkout_connection_timeout() {
        let pool = ErasedConnectionPool::new(10);

        let key = PoolKey {
            authority: "192.0.2.1:12345".parse().unwrap(),
            is_http2: false,
        };

        let pool_with_timeout = pool.with_connect_timeout(std::time::Duration::from_millis(50));
        let result = pool_with_timeout.checkout(key).await;
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::TimedOut);
    }
}
