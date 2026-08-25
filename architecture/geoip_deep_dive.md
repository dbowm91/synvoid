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
| `GeoLocationInfo` | `crates/synvoid-geoip/src/lookup.rs` | Combined geo result |
