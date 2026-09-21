use crate::governor::GlobalCacheGovernor;
use bytes::Bytes;
use http_body::{Body, Frame};
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use synvoid_proxy_cache::{CacheKey, ProxyCache};
use synvoid_utils::buffer::pool::{BufferPool, PooledBuf};
use synvoid_utils::GlobalHealthState;

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
    reserved_bytes: usize,
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
        let size_hint = inner.size_hint().upper().unwrap_or(0) as usize;
        let mut reserved_bytes = 0;

        let buffer = if cache.is_some() && cache_key.is_some() {
            // Bypass caching if system health is degraded (Warning or Critical)
            let health = GlobalHealthState::get();

            // Only attempt to cache if we have a size hint and can reserve the memory.
            // For chunked encoding (size_hint == 0), we bypass caching to avoid unbounded memory usage.
            if health == synvoid_utils::HealthState::Normal
                && size_hint > 0
                && size_hint <= max_size
                && GlobalCacheGovernor::try_reserve(size_hint)
            {
                reserved_bytes = size_hint;
                // Phase 54: pre-size from the trustworthy bounded hint
                // (already validated above and reserved from the governor),
                // then reset logical length to zero so streaming appends do
                // not reallocate. Never preallocates above the cache limit;
                // the governor reservation is released exactly as before.
                let mut buf = BufferPool::acquire(size_hint);
                buf.resize(0);
                Some(buf)
            } else {
                None
            }
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
            reserved_bytes,
        }
    }
}

impl<B> TeeBody<B>
where
    B: Body<Data = Bytes> + Unpin,
{
    /// Abandon cache buffering for this response while continuing to forward
    /// the body unchanged. Drops the pooled tee buffer and releases the
    /// governor reservation exactly once. `Drop` cannot release twice because
    /// `reserved_bytes` is zeroed here.
    ///
    /// Phase 56: a buggy or adversarial body may emit more bytes than its
    /// advertised upper size hint. The governor reservation must remain an
    /// actual upper bound, so overshoot abandons caching only — never
    /// truncating, stalling, or rejecting the proxied response.
    fn abandon_cache_buffering(&mut self) {
        self.buffer = None;
        if self.reserved_bytes > 0 {
            GlobalCacheGovernor::release(self.reserved_bytes);
            self.reserved_bytes = 0;
        }
    }
}

impl<B> Drop for TeeBody<B> {
    fn drop(&mut self) {
        if self.reserved_bytes > 0 {
            GlobalCacheGovernor::release(self.reserved_bytes);
            self.reserved_bytes = 0;
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
                    if self.buffer.is_some() {
                        // Phase 56: the tee buffer must never exceed what was
                        // reserved from the governor. Enforce
                        // `min(reserved_bytes, max_size)` with checked
                        // arithmetic so a lying upper size hint abandons
                        // caching instead of over-retaining memory.
                        let bound = std::cmp::min(self.reserved_bytes, max_size);
                        let current_len = self.buffer.as_ref().map(|b| b.len()).unwrap_or(0);
                        let exceeds = match current_len.checked_add(data.len()) {
                            Some(new_len) => new_len > bound,
                            None => true,
                        };
                        if exceeds {
                            self.abandon_cache_buffering();
                        } else if let Some(ref mut buf) = self.buffer {
                            buf.extend_from_slice(data);
                        }
                    }
                }
                Poll::Ready(Some(Ok(frame)))
            }
            Poll::Ready(None) => {
                // Stream finished, insert into cache if we have a buffer
                if let (Some(cache), Some(key), Some(buf)) =
                    (self.cache.take(), self.cache_key.take(), self.buffer.take())
                {
                    let content = Bytes::copy_from_slice(buf.as_slice());
                    if let Err(e) = cache.insert(
                        key,
                        content,
                        self.status,
                        self.headers.clone(),
                        self.max_age,
                    ) {
                        tracing::warn!("Failed to cache teed response: {}", e);
                    }
                }
                Poll::Ready(None)
            }
            Poll::Ready(Some(Err(e))) => {
                // Phase 56: release the reservation immediately on upstream
                // error rather than holding it until wrapper drop.
                self.abandon_cache_buffering();
                Poll::Ready(Some(Err(std::io::Error::other(format!("{:?}", e)))))
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

#[cfg(test)]
mod streaming_tests {
    use super::*;
    use http::{HeaderMap, Method, Uri};
    use http_body_util::BodyExt;
    use std::collections::VecDeque;
    use std::sync::{LazyLock, Mutex};

    static GOVERNOR_TEST_LOCK: LazyLock<Mutex<()>> = LazyLock::new(|| Mutex::new(()));

    struct FakeBody {
        chunks: VecDeque<Bytes>,
        upper: Option<u64>,
        fail_after_frames: Option<usize>,
        frames_emitted: usize,
    }

    impl FakeBody {
        fn new(chunks: Vec<Bytes>, upper: Option<u64>) -> Self {
            Self {
                chunks: chunks.into(),
                upper,
                fail_after_frames: None,
                frames_emitted: 0,
            }
        }

        fn failing(chunks: Vec<Bytes>, upper: Option<u64>, fail_after: usize) -> Self {
            Self {
                chunks: chunks.into(),
                upper,
                fail_after_frames: Some(fail_after),
                frames_emitted: 0,
            }
        }
    }

    impl Body for FakeBody {
        type Data = Bytes;
        type Error = std::io::Error;

        fn poll_frame(
            mut self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
        ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
            if let Some(fail_after) = self.fail_after_frames {
                if self.frames_emitted == fail_after {
                    self.frames_emitted += 1;
                    return Poll::Ready(Some(Err(std::io::Error::other("fake upstream error"))));
                }
            }
            if let Some(chunk) = self.chunks.pop_front() {
                self.frames_emitted += 1;
                Poll::Ready(Some(Ok(Frame::data(chunk))))
            } else {
                Poll::Ready(None)
            }
        }

        fn is_end_stream(&self) -> bool {
            self.chunks.is_empty()
        }

        fn size_hint(&self) -> http_body::SizeHint {
            let mut hint = http_body::SizeHint::new();
            if let Some(upper) = self.upper {
                hint.set_upper(upper);
            }
            hint
        }
    }

    fn test_cache() -> Arc<ProxyCache> {
        let mut settings = synvoid_proxy_cache::ProxyCacheSettings::default();
        settings.enabled = true;
        settings.use_temp_file = false;
        settings.max_memory_size = 10 * 1024 * 1024;
        settings.valid_status = vec![200];
        Arc::new(ProxyCache::new(settings))
    }

    fn test_key(tag: &str) -> CacheKey {
        CacheKey {
            scheme: "http".to_string(),
            method: Method::GET.as_str().to_string(),
            host: "example.com".to_string(),
            uri: format!("test-{}", tag),
            vary: String::new(),
            site_id: "test-site".to_string(),
        }
    }

    fn test_uri() -> (HeaderMap, Uri) {
        (HeaderMap::new(), Uri::from_static("http://example.com/"))
    }

    struct GovernorGuard {
        before: usize,
        max_before: usize,
    }

    impl GovernorGuard {
        fn lock(large_max: usize) -> (std::sync::MutexGuard<'static, ()>, Self) {
            let guard = GOVERNOR_TEST_LOCK.lock().unwrap();
            synvoid_utils::GlobalHealthState::set(synvoid_utils::HealthState::Normal);
            let before = GlobalCacheGovernor::current_usage();
            // Save current max via a large reservation probe is not directly
            // readable; set a known large max and restore afterwards. The
            // default is 512 MiB; tests use 64 MiB to stay generous but
            // distinct.
            GlobalCacheGovernor::set_max_buffered_bytes(large_max);
            (
                guard,
                Self {
                    before,
                    max_before: 512 * 1024 * 1024,
                },
            )
        }
    }

    impl Drop for GovernorGuard {
        fn drop(&mut self) {
            GlobalCacheGovernor::set_max_buffered_bytes(self.max_before);
        }
    }

    async fn collect_forwarded<B>(mut tee: TeeBody<B>) -> (Vec<u8>, TeeBody<B>)
    where
        B: Body<Data = Bytes> + Unpin,
        B::Error: std::fmt::Debug,
    {
        let mut out = Vec::new();
        while let Some(result) = tee.frame().await {
            match result {
                Ok(frame) => {
                    if let Some(data) = frame.data_ref() {
                        out.extend_from_slice(data);
                    }
                }
                Err(_) => break,
            }
        }
        (out, tee)
    }

    /// Upper hint 4, actual exactly 4: cache succeeds.
    #[tokio::test]
    async fn test_tee_exact_hint_caches() {
        let (_lock, gov) = GovernorGuard::lock(64 * 1024 * 1024);
        let cache = test_cache();
        let key = test_key("exact");
        let (headers, _uri) = test_uri();
        let inner = FakeBody::new(
            vec![Bytes::from_static(b"ab"), Bytes::from_static(b"cd")],
            Some(4),
        );
        let tee = TeeBody::new(
            inner,
            Some(cache.clone()),
            Some(key.clone()),
            200,
            headers,
            None,
            1024,
        );
        let (forwarded, tee) = collect_forwarded(tee).await;
        assert_eq!(forwarded, b"abcd");
        drop(tee);
        let entry = cache.get(&key).await.expect("exact hint must cache");
        assert_eq!(entry.content.as_ref(), b"abcd");
        assert_eq!(
            GlobalCacheGovernor::current_usage(),
            gov.before,
            "reservation must be released exactly once"
        );
    }

    /// Upper hint 4, body emits more: cache abandoned, downstream intact,
    /// governor restored immediately.
    #[tokio::test]
    async fn test_tee_overshoot_abandons_but_forwards() {
        let (_lock, gov) = GovernorGuard::lock(64 * 1024 * 1024);
        let cache = test_cache();
        let key = test_key("overshoot");
        let (headers, _uri) = test_uri();
        let inner = FakeBody::new(
            vec![
                Bytes::from_static(b"ab"),
                Bytes::from_static(b"cd"),
                Bytes::from_static(b"ef"),
            ],
            Some(4),
        );
        let tee = TeeBody::new(
            inner,
            Some(cache.clone()),
            Some(key.clone()),
            200,
            headers,
            None,
            1024,
        );
        let (forwarded, tee) = collect_forwarded(tee).await;
        assert_eq!(forwarded, b"abcdef", "overshoot must forward byte-for-byte");
        drop(tee);
        assert!(
            cache.get(&key).await.is_none(),
            "overshooting body must not be cached"
        );
        assert_eq!(
            GlobalCacheGovernor::current_usage(),
            gov.before,
            "abandoned reservation must be released"
        );
    }

    /// Reservation is released immediately at abandonment, not at drop.
    #[tokio::test]
    async fn test_tee_immediate_release_on_abandon() {
        let (_lock, gov) = GovernorGuard::lock(64 * 1024 * 1024);
        let cache = test_cache();
        let key = test_key("immediate");
        let (headers, _uri) = test_uri();
        let inner = FakeBody::new(
            vec![Bytes::from_static(b"ab"), Bytes::from_static(b"cdef")],
            Some(4),
        );
        let mut tee = TeeBody::new(
            inner,
            Some(cache.clone()),
            Some(key.clone()),
            200,
            headers,
            None,
            1024,
        );
        // First 2-byte frame stays within the 4-byte reservation.
        let first = tee.frame().await.expect("first frame").expect("ok");
        assert_eq!(first.data_ref().unwrap().as_ref(), b"ab");
        assert_eq!(
            GlobalCacheGovernor::current_usage(),
            gov.before + 4,
            "reservation held while within bound"
        );
        // Second frame pushes to 6 bytes > reserved 4: abandon now.
        let second = tee.frame().await.expect("second frame").expect("ok");
        assert_eq!(second.data_ref().unwrap().as_ref(), b"cdef");
        assert_eq!(
            GlobalCacheGovernor::current_usage(),
            gov.before,
            "governor usage must return immediately after abandonment"
        );
        // Stream end: no cache insert, no second release at drop.
        let end = tee.frame().await;
        assert!(end.is_none(), "stream must end normally");
        drop(tee);
        assert_eq!(
            GlobalCacheGovernor::current_usage(),
            gov.before,
            "no double release at drop"
        );
        assert!(cache.get(&key).await.is_none());
    }

    /// No double release occurs at `Drop` after abandonment.
    #[tokio::test]
    async fn test_tee_no_double_release_at_drop() {
        let (_lock, gov) = GovernorGuard::lock(64 * 1024 * 1024);
        let cache = test_cache();
        let key = test_key("double-release");
        let (headers, _uri) = test_uri();
        let inner = FakeBody::new(vec![Bytes::from_static(b"12345")], Some(4));
        let tee = TeeBody::new(
            inner,
            Some(cache.clone()),
            Some(key.clone()),
            200,
            headers,
            None,
            1024,
        );
        let (forwarded, tee) = collect_forwarded(tee).await;
        assert_eq!(forwarded, b"12345");
        // Explicit drop must not underflow the global counter.
        drop(tee);
        assert_eq!(GlobalCacheGovernor::current_usage(), gov.before);
        // A second大きい reservation still succeeds, proving the counter was
        // not driven negative by a double release.
        assert!(GlobalCacheGovernor::try_reserve(8));
        GlobalCacheGovernor::release(8);
        assert_eq!(GlobalCacheGovernor::current_usage(), gov.before);
    }

    /// A body at `max_size` still caches when the reservation matches.
    #[tokio::test]
    async fn test_tee_at_max_size_caches() {
        let (_lock, gov) = GovernorGuard::lock(64 * 1024 * 1024);
        let cache = test_cache();
        let key = test_key("at-max");
        let (headers, _uri) = test_uri();
        let inner = FakeBody::new(vec![Bytes::from(vec![b'x'; 16])], Some(16));
        let tee = TeeBody::new(
            inner,
            Some(cache.clone()),
            Some(key.clone()),
            200,
            headers,
            None,
            16,
        );
        let (forwarded, tee) = collect_forwarded(tee).await;
        assert_eq!(forwarded.len(), 16);
        drop(tee);
        assert!(
            cache.get(&key).await.is_some(),
            "body at max_size with matching reservation must cache"
        );
        assert_eq!(GlobalCacheGovernor::current_usage(), gov.before);
    }

    /// A body above `max_size` is never reserved/cached.
    #[tokio::test]
    async fn test_tee_above_max_size_never_reserved() {
        let (_lock, gov) = GovernorGuard::lock(64 * 1024 * 1024);
        let cache = test_cache();
        let key = test_key("above-max");
        let (headers, _uri) = test_uri();
        let inner = FakeBody::new(vec![Bytes::from(vec![b'y'; 32])], Some(32));
        let tee = TeeBody::new(
            inner,
            Some(cache.clone()),
            Some(key.clone()),
            200,
            headers,
            None,
            16,
        );
        // Never reserved: usage unchanged from the start.
        assert_eq!(GlobalCacheGovernor::current_usage(), gov.before);
        let (forwarded, tee) = collect_forwarded(tee).await;
        assert_eq!(forwarded.len(), 32, "response must still forward fully");
        drop(tee);
        assert!(cache.get(&key).await.is_none());
        assert_eq!(GlobalCacheGovernor::current_usage(), gov.before);
    }

    /// Error after partial body releases the reservation no later than drop
    /// (immediately in this implementation).
    #[tokio::test]
    async fn test_tee_error_releases_reservation() {
        let (_lock, gov) = GovernorGuard::lock(64 * 1024 * 1024);
        let cache = test_cache();
        let key = test_key("error");
        let (headers, _uri) = test_uri();
        let inner = FakeBody::failing(vec![Bytes::from_static(b"ab")], Some(4), 1);
        let mut tee = TeeBody::new(
            inner,
            Some(cache.clone()),
            Some(key.clone()),
            200,
            headers,
            None,
            1024,
        );
        let first = tee.frame().await.expect("first frame").expect("ok");
        assert_eq!(first.data_ref().unwrap().as_ref(), b"ab");
        let err = tee.frame().await.expect("error frame");
        assert!(err.is_err(), "upstream error must propagate");
        assert_eq!(
            GlobalCacheGovernor::current_usage(),
            gov.before,
            "error must release reservation immediately"
        );
        drop(tee);
        assert_eq!(GlobalCacheGovernor::current_usage(), gov.before);
        assert!(cache.get(&key).await.is_none());
    }
}
