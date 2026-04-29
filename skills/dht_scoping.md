# DHT Site Scoping

MaluWAF operates in a multi-tenant environment where records (like proxy cache preferences, custom rules, upstreams) must be isolated per site.

## DhtKey Scoping

Always use the `SiteScoped` variant of `DhtKey` when the record belongs to a specific tenant/site.

```rust
use crate::mesh::dht::keys::DhtKey;

// Creating a site-scoped key
let inner_key = "upstream_proxy_cache_preferences:my-upstream".to_string();
let scoped_key = DhtKey::SiteScoped {
    site_id: "site_12345".to_string(),
    inner_key,
};

// Checking if a key is site-scoped
if let Some(site) = scoped_key.site_scope() {
    println!("This record belongs to site: {}", site);
}
```

Never store tenant-specific data under global keys (like `NodeInfo` or `GlobalRateLimit`).
