# GeoIP Deep Dive

SynVoid's GeoIP module provides MaxMind GeoIP/ASN database lookup with auto-update support for geo-based routing, blocking, and logging.

## Architecture

### Core Components

```
GeoIpLookup
├── MaxMind Reader (mmdb parsing)
├── Country Database
├── ASN Database
├── City Database (optional)
└── Auto-Updater
```

### Lookup Types

```rust
pub struct GeoIpLookup {
    pub reader: Option<Reader<Vec<u8>>>,
}

impl GeoIpLookup {
    pub fn lookup_country(&self, ip: IpAddr) -> Option<String>;
    pub fn lookup_country_info(&self, ip: IpAddr) -> Option<CountryInfo>;
    pub fn lookup_subdivision(&self, ip: IpAddr) -> Option<String>;
    pub fn lookup_city(&self, ip: IpAddr) -> Option<String>;
    pub fn lookup_asn(&self, ip: IpAddr) -> Option<(u32, String)>;
    pub fn lookup_location(&self, ip: IpAddr) -> Option<(f64, f64)>;
    pub fn lookup_location_info(&self, ip: IpAddr) -> Option<GeoLocationInfo>;
}
```

### Auto-Update

```rust
pub struct GeoIpUpdater {
    // Handles auto-download of MaxMind databases
}

pub enum DownloadSource {
    MaxMind { account_id: String, license_key: String },
    PresignedUrl(String),
}
```

### Construction and failure posture

`GeoIpManager::new(config, site_configs, alert_manager) -> Option<Self>`
(`manager.rs`) returns `None` only when `config.enabled` is false. **It never
reports a database load failure**: an unreadable or missing path falls back to
`GeoIpLookup { reader: None }` with a warning, and `GeoIpLookup::new` returns
`Ok(reader: None)` — not an error — for an empty or nonexistent path. Callers
that need to distinguish "unset" from "typo" from "corrupt" must ask
`database_loaded()`; nothing infers that for them.

## Integration Points

- Used by the WAF for geo-based blocking rules (`src/waf/`)
- Used by mesh DHT contact routing, which converts `GeoLocationInfo` into `GeoInfo`
  (`crates/synvoid-mesh/src/mesh/dht/routing/contact.rs`)
- Used by DNS through an **inverted seam**: DNS owns the narrow `CountryLookup`
  trait (`crates/synvoid-dns/src/geo.rs`, exactly two methods) and composition
  adapts `Arc<GeoIpManager>` in `src/geo/dns_provider.rs`. `synvoid-dns` has no
  `synvoid-geoip` edge
- **Not** used by the proxy — no `synvoid-geoip` reference exists in
  `crates/synvoid-proxy/src/` or `src/proxy/`
- Metrics for geo-distribution logging

## Key Types

| Type | Location | Purpose |
|------|----------|---------|
| `GeoIpLookup` | `crates/synvoid-geoip/src/lookup.rs` | Main lookup interface (single `Option<Reader<Vec<u8>>>`) |
| `GeoIpManager` | `crates/synvoid-geoip/src/manager.rs` | Database lifecycle |
| `GeoIpUpdater` | `crates/synvoid-geoip/src/updater.rs` | Auto-download (`DownloadSource`, `DatabaseEdition`) |
| `CountryInfo` | `crates/synvoid-geoip/src/types.rs` | Country lookup result (`code`, `name`, `subdivision`, `city`) |
| `GeoLocationInfo` | `crates/synvoid-geoip/src/lookup.rs` | Combined geo result |
