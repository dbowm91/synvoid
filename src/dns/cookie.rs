use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use parking_lot::RwLock;

const COOKIE_SIZE: usize = 8;
const MAX_COOKIE_AGE_SECS: u64 = 3600;

pub struct DnsCookieServer {
    inner: Arc<InnerCookieServer>,
}

struct InnerCookieServer {
    secret_key: [u8; 32],
    cookies: RwLock<lru_time_cache::LruCache<String, CookieEntry>>,
    enable_validation: bool,
}

struct CookieEntry {
    client_ip: IpAddr,
    created_at: Instant,
    server_cookie: Vec<u8>,
}

impl DnsCookieServer {
    pub fn new() -> Self {
        let secret_key = super::crypto_rng::random_array::<32>();

        let cookies = lru_time_cache::LruCache::with_capacity(10000);

        Self {
            inner: Arc::new(InnerCookieServer {
                secret_key,
                cookies: RwLock::new(cookies),
                enable_validation: true,
            }),
        }
    }

    pub fn with_validation(self, enable: bool) -> Self {
        self
    }

    pub fn generate_server_cookie(&self, client_ip: IpAddr, client_cookie: &[u8]) -> Vec<u8> {
        let mut data = Vec::new();
        data.extend_from_slice(client_cookie);
        data.extend_from_slice(&self.inner.secret_key[..16]);

        let ip_bytes = match client_ip {
            IpAddr::V4(ipv4) => ipv4.octets().to_vec(),
            IpAddr::V6(ipv6) => ipv6.octets().to_vec(),
        };
        data.extend_from_slice(&ip_bytes);

        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(&data);
        let result = hasher.finalize();

        result[..COOKIE_SIZE].to_vec()
    }

    pub fn validate_cookie(
        &self,
        client_ip: IpAddr,
        client_cookie: &[u8],
        server_cookie: &[u8],
    ) -> bool {
        if !self.inner.enable_validation {
            return true;
        }

        if client_cookie.len() < COOKIE_SIZE || server_cookie.len() < COOKIE_SIZE {
            return false;
        }

        let expected_server = self.generate_server_cookie(client_ip, client_cookie);

        if expected_server.len() != server_cookie.len() {
            return false;
        }

        let mut diff = 0u8;
        for (a, b) in expected_server.iter().zip(server_cookie.iter()) {
            diff |= a ^ b;
        }

        diff == 0
    }

    pub fn create_response_cookie(&self, client_ip: IpAddr) -> Vec<u8> {
        let client_cookie = super::crypto_rng::random_bytes(COOKIE_SIZE);

        let server_cookie = self.generate_server_cookie(client_ip, &client_cookie);

        let mut cookies = self.inner.cookies.write();
        let key = format!("{}:{:?}", client_ip, &client_cookie[..4]);
        cookies.insert(
            key,
            CookieEntry {
                client_ip,
                created_at: Instant::now(),
                server_cookie: server_cookie.clone(),
            },
        );

        let mut response = client_cookie;
        response.extend_from_slice(&server_cookie);
        response
    }

    pub fn should_require_cookie(&self, client_ip: IpAddr) -> bool {
        let mut cookies = self.inner.cookies.write();

        for (_key, entry) in cookies.iter() {
            if entry.client_ip == client_ip {
                let age = entry.created_at.elapsed();
                return age > Duration::from_secs(MAX_COOKIE_AGE_SECS);
            }
        }

        true
    }
}

impl Default for DnsCookieServer {
    fn default() -> Self {
        Self::new()
    }
}

pub fn build_cookie_option(client_cookie: &[u8], server_cookie: &[u8]) -> Vec<u8> {
    let mut opt = Vec::new();

    opt.extend_from_slice(&10u16.to_be_bytes());

    let data_len = client_cookie.len() + server_cookie.len();
    opt.extend_from_slice(&(data_len as u16).to_be_bytes());

    opt.extend_from_slice(client_cookie);
    opt.extend_from_slice(server_cookie);

    opt
}
