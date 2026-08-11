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
    country_reader: Option<Reader<Vec<u8>>>,
    asn_reader: Option<Reader<Vec<u8>>>,
    city_reader: Option<Reader<Vec<u8>>>,
}

impl GeoIpLookup {
    pub fn lookup_country(&self, ip: IpAddr) -> Option<CountryInfo>;
    pub fn lookup_country_info(&self, ip: IpAddr) -> Option<GeoLocationInfo>;
    pub fn lookup_subdivision(&self, ip: IpAddr) -> Option<String>;
    pub fn lookup_city(&self, ip: IpAddr) -> Option<String>;
    pub fn lookup_asn(&self, ip: IpAddr) -> Option<AsnInfo>;
    pub fn lookup_location(&self, ip: IpAddr) -> Option<(f64, f64)>;
    pub fn lookup_location_info(&self, ip: IpAddr) -> Option<GeoIpResult>;
}
```

### Auto-Update

```rust
pub struct GeoIpUpdater {
    config: UpdateConfig,
    notification_handlers: Vec<Box<dyn GeoIpNotificationHandler>>,
}

pub struct UpdateConfig {
    sources: Vec<DownloadSource>,
    check_interval: Duration,
    auto_apply: bool,
}

pub enum DownloadSource {
    MaxMind { license_key: String },
    Custom { url: String },
}
```

## Integration Points

- Used by WAF for geo-based blocking rules
- Used by proxy for geo-based routing
- Used by mesh for regional routing decisions
- Metrics for geo-distribution logging

## Key Types

| Type | Location | Purpose |
|------|----------|---------|
| `GeoIpLookup` | `crates/synvoid-geoip/src/lookup.rs` | Main lookup interface |
| `GeoIpManager` | `crates/synvoid-geoip/src/manager.rs` | Database lifecycle |
| `GeoIpUpdater` | `crates/synvoid-geoip/src/updater.rs` | Auto-download |
| `CountryInfo` | `crates/synvoid-geoip/src/types.rs` | Country lookup result |
| `AsnInfo` | `crates/synvoid-geoip/src/types.rs` | ASN lookup result |
| `GeoIpResult` | `crates/synvoid-geoip/src/types.rs` | Combined result |
