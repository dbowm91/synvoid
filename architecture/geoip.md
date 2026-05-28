# GeoIP Architecture

## 1. Purpose and Responsibility

The GeoIP module (`src/geoip/`) provides **MaxMind GeoIP database integration** with country/ASN/city lookup, country-based blocking/allowlisting, and automatic database updates with retry logic.

**Core Responsibilities:**
- IP geolocation (country, city, subdivision, ASN)
- Country-based access control (block/allow lists)
- Automatic database update with retry
- Stale database detection and alerting
- Multiple download source support

---

## 2. Key Data Structures

```rust
pub struct GeoIpManager {
    lookup: Arc<GeoIpLookup>,
    updater: Arc<GeoIpUpdater>,
    blocked_countries: HashSet<String>,
    allowed_countries: HashSet<String>,
    alert_manager: Option<Arc<AlertManager>>,
}

pub struct GeoIpLookup {
    country_reader: Option<MaxMindReader<Vec<u8>>>,
    city_reader: Option<MaxMindReader<Vec<u8>>>,
    asn_reader: Option<MaxMindReader<Vec<u8>>>,
}

pub enum GeoIpResult {
    Allowed,
    Blocked,
    Neutral,
}

pub struct CountryInfo {
    pub country_code: String,
    pub country_name: String,
    pub continent_code: String,
}

pub struct AsnInfo {
    pub asn: u32,
    pub org: String,
}
```

---

## 3. Public API

| Method | Description |
|--------|-------------|
| `GeoIpManager::new(config, site_configs, alert_manager)` | Constructor |
| `check_ip(ip) -> GeoIpResult` | Main filtering entry point |
| `get_country_info(ip) -> Option<CountryInfo>` | Country lookup |
| `get_asn_info(ip) -> Option<AsnInfo>` | ASN lookup |
| `get_continent_code(ip) -> Option<String>` | Continent lookup |
| `start_auto_update().await` | Background database updates |
| `status() -> GeoIpStatus` | Update status |
| `is_stale() -> bool` | Check if database is outdated |
| `days_since_update() -> Option<u64>` | Time since last update |

---

## 4. Submodules

### `lookup.rs` — MaxMind Reader Wrapper
- Country, city, subdivision, ASN queries
- Thread-safe read access
- Mmap-based file reading

### `updater.rs` — Database Update Manager
- Download from MaxMind or presigned URLs
- Gzip decompression
- MMDB validation
- Retry with exponential backoff

### `types.rs` — Data Types
- `GeoIpResult`, `CountryInfo`, `AsnInfo`, `GeoLocationInfo`
- `DownloadSource`, `DatabaseEdition`

---

## 5. Integration Points

- **WAF**: Country-based blocking/allowlisting in request pipeline
- **HTTP Server**: Geo-based access decisions
- **AlertManager**: Stale database notifications
- **Config**: `SiteGeoIpConfig` per-site settings

---

## 6. Key Implementation Details

- **Mmap-based**: Memory-mapped file access for fast lookups
- **Multi-database**: Separate readers for country, city, and ASN data
- **Automatic Updates**: Background task with configurable interval
- **Stale Detection**: Alerts when database is older than threshold
- **Presigned URLs**: Support for custom download sources
