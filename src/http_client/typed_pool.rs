//! Typed connection pool for per-host, per-body-type HTTP clients.
//!
//! Option 3 approach: Create typed clients per (authority, body_type) combination
//! to avoid hyper's type complexity while maintaining connection reuse.

use bytes::Bytes;
use http_body::Body as HttpBody;
use http_body_util::Full;
use hyper::body::Incoming;
use hyper_util::client::legacy::Client;
use hyper_rustls::HttpsConnector;
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::rt::TokioExecutor;
use moka::sync::Cache;
use std::any::{Any, TypeId};
use std::error::Error;
use std::hash::{Hash, Hasher};
use std::sync::Arc;

#[derive(Clone, Debug)]
pub struct TypedPoolKey {
    authority: String,
    is_http2: bool,
    body_type_id: TypeId,
}

impl TypedPoolKey {
    pub fn new(authority: String, is_http2: bool, body_type: TypeId) -> Self {
        Self {
            authority,
            is_http2,
            body_type_id: body_type,
        }
    }
}

impl PartialEq for TypedPoolKey {
    fn eq(&self, other: &Self) -> bool {
        self.authority == other.authority
            && self.is_http2 == other.is_http2
            && self.body_type_id == other.body_type_id
    }
}

impl Eq for TypedPoolKey {}

impl Hash for TypedPoolKey {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.authority.hash(state);
        self.is_http2.hash(state);
        self.body_type_id.hash(state);
    }
}

struct TypedClientEntry {
    client: Client<HttpsConnector<HttpConnector>, Full<Bytes>>,
}

pub struct TypedConnectionPool {
    inner: Cache<TypedPoolKey, Arc<TypedClientEntry>>,
    max_idle_per_host: usize,
}

impl TypedConnectionPool {
    pub fn new(max_idle_per_host: usize) -> Self {
        let cache = Cache::builder()
            .max_capacity(100)
            .build();

        Self {
            inner: cache,
            max_idle_per_host,
        }
    }

    pub fn get_client_for_authority(
        &self,
        authority: &str,
        is_http2: bool,
    ) -> Arc<TypedClientEntry> {
        let key = TypedPoolKey::new(
            authority.to_string(),
            is_http2,
            TypeId::of::<Full<Bytes>>(),
        );

        if let Some(entry) = self.inner.get(&key) {
            return entry;
        }

        let client = create_typed_client(self.max_idle_per_host, is_http2);
        let entry = Arc::new(TypedClientEntry { client });
        self.inner.insert(key, entry.clone());
        entry
    }

    pub fn max_idle_per_host(&self) -> usize {
        self.max_idle_per_host
    }
}

fn create_typed_client(
    max_idle_per_host: usize,
    is_http2: bool,
) -> Client<HttpsConnector<HttpConnector>, Full<Bytes>> {
    use rustls::client::WebPkiServerVerifier;
    use rustls::crypto::aws_lc_rs;

    let provider = std::sync::Arc::new(aws_lc_rs::default_provider());
    let builder = rustls::ClientConfig::builder_with_provider(provider.clone())
        .with_safe_default_protocol_versions()
        .expect("failed to set TLS protocol versions");

    let mut root_store = rustls::RootCertStore::empty();
    root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());

    let verifier = WebPkiServerVerifier::builder(std::sync::Arc::new(root_store))
        .build()
        .expect("failed to build WebPkiServerVerifier");

    let config = builder
        .dangerous()
        .with_custom_certificate_verifier(verifier)
        .with_no_client_auth();

    let mut http_connector = HttpConnector::new();
    http_connector.set_connect_timeout(Some(std::time::Duration::from_secs(5)));
    http_connector.enforce_http(false);
    http_connector.set_nodelay(true);
    http_connector.set_keepalive(Some(std::time::Duration::from_secs(60)));

    let https_connector = hyper_rustls::HttpsConnectorBuilder::new()
        .with_tls_config(config)
        .https_or_http()
        .enable_http2()
        .wrap_connector(http_connector);

    Client::builder(TokioExecutor::new())
        .pool_max_idle_per_host(max_idle_per_host)
        .pool_idle_timeout(std::time::Duration::from_secs(30))
        .http2_only(is_http2)
        .build(https_connector)
}

pub struct TypedHttpClient {
    pool: Arc<TypedConnectionPool>,
}

impl TypedHttpClient {
    pub fn new(max_idle_per_host: usize) -> Self {
        Self {
            pool: Arc::new(TypedConnectionPool::new(max_idle_per_host)),
        }
    }

    pub async fn send_request(
        &self,
        request: hyper::Request<Full<Bytes>>,
        authority: &str,
        is_http2: bool,
        timeout: Option<std::time::Duration>,
    ) -> Result<hyper::Response<Incoming>, Box<dyn Error + Send + Sync>> {
        let entry = self.pool.get_client_for_authority(authority, is_http2);

        match timeout {
            Some(t) => {
                tokio::time::timeout(t, entry.client.request(request)).await?
            }
            None => entry.client.request(request).await,
        }
        .map_err(|e| Box::new(e) as Box<dyn Error + Send + Sync>)
    }
}

impl Clone for TypedHttpClient {
    fn clone(&self) -> Self {
        Self {
            pool: self.pool.clone(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_typed_pool_key_equality() {
        let key1 = TypedPoolKey::new(
            "example.com:80".to_string(),
            false,
            TypeId::of::<Full<Bytes>>(),
        );
        let key2 = TypedPoolKey::new(
            "example.com:80".to_string(),
            false,
            TypeId::of::<Full<Bytes>>(),
        );
        let key3 = TypedPoolKey::new(
            "example.com:80".to_string(),
            true,
            TypeId::of::<Full<Bytes>>(),
        );

        assert_eq!(key1, key2);
        assert_ne!(key1, key3);
    }

    #[test]
    fn test_typed_pool_key_hash() {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::Hash;

        let key1 = TypedPoolKey::new(
            "example.com:80".to_string(),
            false,
            TypeId::of::<Full<Bytes>>(),
        );
        let key2 = TypedPoolKey::new(
            "example.com:80".to_string(),
            false,
            TypeId::of::<Full<Bytes>>(),
        );

        let mut h1 = DefaultHasher::new();
        key1.hash(&mut h1);
        let mut h2 = DefaultHasher::new();
        key2.hash(&mut h2);

        assert_eq!(h1.finish(), h2.finish());
    }

    #[test]
    fn test_pool_construction() {
        let pool = TypedConnectionPool::new(100);
        assert_eq!(pool.max_idle_per_host(), 100);
    }

    #[test]
    fn test_typed_http_client_clone() {
        let client = TypedHttpClient::new(100);
        let _ = client.clone();
    }
}