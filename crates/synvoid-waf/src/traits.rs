use std::net::IpAddr;
use std::sync::Arc;

/// Abstraction for block list operations.
///
/// Implementations provide IP blocking and checking functionality.
/// This trait decouples WAF core from the concrete `BlockStore` implementation.
pub trait BlockListStore: Send + Sync + 'static {
    /// Check if an IP is blocked in the given scope.
    fn is_blocked(&self, ip: &IpAddr, scope: &str) -> Option<BlockEntry>;

    /// Block an IP address with a reason and duration.
    fn block_ip(&self, ip: IpAddr, reason: &str, duration_secs: u64, scope: &str);
}

/// A block list entry with the reason for blocking.
#[derive(Debug, Clone)]
pub struct BlockEntry {
    pub reason: String,
}

/// Abstraction for GeoIP lookups.
///
/// Implementations provide IP-to-country and IP-to-ASN resolution.
/// This trait decouples WAF core from the concrete `GeoIpManager` implementation.
pub trait GeoIpLookup: Send + Sync + 'static {
    /// Look up the country code for an IP address.
    fn lookup_country(&self, ip: IpAddr) -> Option<String>;

    /// Look up the ASN for an IP address.
    fn lookup_asn(&self, ip: IpAddr) -> Option<u32>;
}

/// Bundled request services available during WAF processing.
///
/// This trait provides request-scoped context that the WAF core needs
/// but does not own. Implementations supply site identity and other
/// request metadata.
pub trait WafRequestServices: Send + Sync + 'static {
    /// Get the site ID for the current request, if available.
    fn site_id(&self) -> Option<&str>;
}

/// Type-erased wrapper for `BlockListStore` that can be stored in WafCore.
pub struct ErasedBlockStore {
    inner: Arc<dyn BlockListStore>,
}

impl ErasedBlockStore {
    pub fn new(store: impl BlockListStore) -> Self {
        Self {
            inner: Arc::new(store),
        }
    }

    pub fn is_blocked(&self, ip: &IpAddr, scope: &str) -> Option<BlockEntry> {
        self.inner.is_blocked(ip, scope)
    }

    pub fn block_ip(&self, ip: IpAddr, reason: &str, duration_secs: u64, scope: &str) {
        self.inner.block_ip(ip, reason, duration_secs, scope)
    }
}

impl Clone for ErasedBlockStore {
    fn clone(&self) -> Self {
        Self {
            inner: Arc::clone(&self.inner),
        }
    }
}

/// Type-erased wrapper for `GeoIpLookup` that can be stored in WafCore.
pub struct ErasedGeoIp {
    inner: Arc<dyn GeoIpLookup>,
}

impl ErasedGeoIp {
    pub fn new(lookup: impl GeoIpLookup) -> Self {
        Self {
            inner: Arc::new(lookup),
        }
    }

    pub fn lookup_country(&self, ip: IpAddr) -> Option<String> {
        self.inner.lookup_country(ip)
    }

    pub fn lookup_asn(&self, ip: IpAddr) -> Option<u32> {
        self.inner.lookup_asn(ip)
    }
}

impl Clone for ErasedGeoIp {
    fn clone(&self) -> Self {
        Self {
            inner: Arc::clone(&self.inner),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use parking_lot::RwLock;
    use std::collections::HashMap;

    struct MockBlockStore {
        blocked: RwLock<HashMap<IpAddr, String>>,
    }

    impl MockBlockStore {
        fn new() -> Self {
            Self {
                blocked: RwLock::new(HashMap::new()),
            }
        }
    }

    impl BlockListStore for MockBlockStore {
        fn is_blocked(&self, ip: &IpAddr, _scope: &str) -> Option<BlockEntry> {
            self.blocked.read().get(ip).map(|reason| BlockEntry {
                reason: reason.clone(),
            })
        }

        fn block_ip(&self, ip: IpAddr, reason: &str, _duration_secs: u64, _scope: &str) {
            self.blocked.write().insert(ip, reason.to_string());
        }
    }

    #[test]
    fn test_block_store_trait() {
        let store = MockBlockStore::new();
        let ip: IpAddr = "1.2.3.4".parse().unwrap();

        assert!(store.is_blocked(&ip, "global").is_none());

        store.block_ip(ip, "test", 3600, "global");
        let entry = store.is_blocked(&ip, "global").unwrap();
        assert_eq!(entry.reason, "test");
    }

    #[test]
    fn test_erased_block_store() {
        let store = ErasedBlockStore::new(MockBlockStore::new());
        let ip: IpAddr = "1.2.3.4".parse().unwrap();

        assert!(store.is_blocked(&ip, "global").is_none());

        store.block_ip(ip, "test", 3600, "global");
        let entry = store.is_blocked(&ip, "global").unwrap();
        assert_eq!(entry.reason, "test");
    }
}
