# GeoIP Architecture

## 1. Purpose and Responsibility

The GeoIP module (`crates/synvoid-geoip/`) provides **MaxMind GeoIP database integration** with country/ASN/city lookup, country-based blocking/allowlisting, and automatic database updates with retry logic.

**Core Responsibilities:**
- IP geolocation (country, city, subdivision, ASN)
- Country-based access control (block/allow lists)
- Automatic database update with retry
- Stale database detection and alerting
- Multiple download source support

---

## 2. Key Data Structures

```rust
// manager.rs
pub struct GeoIpManager {
    config: GeoIpConfig,
    lookup: Arc<RwLock<GeoIpLookup>>,
    updater: Arc<GeoIpUpdater>,
    blocked_countries: Arc<RwLock<HashSet<String>>>,
    allowed_countries: Arc<RwLock<HashSet<String>>>,
    last_update: Arc<RwLock<Option<u64>>>,
    alert_manager: Option<Arc<dyn GeoIpNotificationHandler>>,
    is_enabled: bool,
}

// lookup.rs — one in-memory reader serves country, city/subdivision, and ASN
// queries against whichever database the path points at.
pub struct GeoIpLookup {
    pub reader: Option<Reader<Vec<u8>>>,
}

pub enum GeoIpResult {
    Allowed,
    Blocked,
    Neutral,
}

pub struct CountryInfo {
    pub code: String,
    pub name: String,
    pub subdivision: Option<String>,
    pub city: Option<String>,
}

pub struct AsnInfo {
    pub asn: u32,
    pub organization: String,
}
```

There is no separate `AlertManager` dependency: staleness notification is a
trait object (`GeoIpNotificationHandler`, `traits.rs`), so the crate takes any
sink. `GeoLocationInfo` (combined lat/long) lives in `lookup.rs`, not `types.rs`.

---

## 3. Public API

| Method | Description |
|--------|-------------|
| `GeoIpManager::new(config, site_configs, alert_manager) -> Option<Self>` | Constructor. Returns `None` when `config.enabled` is false. **It never reports a load failure** — an unloadable database falls back to `GeoIpLookup { reader: None }` with a warning, so a caller cannot distinguish "no path configured" from "path typo" from "corrupt database" |
| `check_ip(ip) -> GeoIpResult` | Main filtering entry point |
| `get_country_info(ip) -> Option<CountryInfo>` | Country lookup |
| `get_asn_info(ip) -> Option<AsnInfo>` | ASN lookup |
| `get_continent_code(ip) -> Option<String>` | Continent lookup |
| `start_auto_update().await` | Background database updates |
| `status() -> GeoIpStatus` | Update status |
| `is_stale() -> bool` | Check if database is outdated |
| `days_since_update() -> Option<u64>` | Time since last update |

`GeoIpLookup::new(path)` likewise returns `Ok(Self { reader: None })` — not an
error — for an empty path or a path that does not exist.

---

## 4. Submodules

### `lookup.rs` — MaxMind Reader Wrapper
- Country, city, subdivision, ASN queries
- Thread-safe read access
- In-memory reader (`Reader<Vec<u8>>`); no mmap dependency verified in `crates/synvoid-geoip/`

### `updater.rs` — Database Update Manager
- Download from MaxMind or presigned URLs (`DownloadSource`, `DatabaseEdition`)
- Gzip decompression
- MMDB validation
- Retry with exponential backoff

### `types.rs` — Data Types
- `GeoIpResult`, `CountryInfo`, `AsnInfo`, `GeoIpStatus`
- `GeoLocationInfo` is **not** here; it is defined in `lookup.rs`

### `traits.rs` — Notification Seam
- `GeoIpNotificationHandler` (`send_stale_notification`), the trait object
  `GeoIpManager::alert_manager` holds

---

## 5. Integration Points

- **WAF**: Country-based blocking/allowlisting in the request pipeline
  (`src/waf/mod.rs`, `src/waf/adapters.rs`, `src/waf/asn_tracker.rs` hold
  `Option<Arc<GeoIpManager>>`)
- **DNS**: *inverted* — DNS owns the narrow `CountryLookup` trait
  (`crates/synvoid-dns/src/geo.rs`); composition adapts `Arc<GeoIpManager>` in
  `src/geo/dns_provider.rs` and passes it to `DnsServer::new`. `synvoid-dns` has
  no `synvoid-geoip` edge.
- **Mesh**: `crates/synvoid-mesh/src/mesh/dht/routing/contact.rs` converts
  `GeoLocationInfo` into the DHT contact's `GeoInfo` for regional routing
- **HTTP Server / Proxy**: no direct consumer. Geo decisions in the request path
  come through the WAF adapter above
- **AlertManager**: Stale database notifications, via the
  `GeoIpNotificationHandler` trait object
- **Config**: `SiteGeoipConfig` (per-site, `crates/synvoid-config/src/site/security.rs`)
  and the top-level `[geoip]` section (`synvoid_config::geoip::GeoIpConfig`)

### `[geoip]` is a real, opt-in section (Phase 138)

`[geoip]` is a `MainConfig` field (`crates/synvoid-config/src/main_config.rs`),
`#[serde(default)]` with `enabled` defaulting to `false`, so the section is
opt-in and no existing configuration changes behavior. Composition builds the
provider through `crate::geo::country_lookup_from_config` (`src/server/resources.rs`,
`src/worker/unified_server/init_mesh.rs`).

**Enabled with no usable database, composition warns rather than refusing to
start.** `GeoIpManager::new` returns `Option` and never reports a load failure,
and `GeoIpLookup::new` returns `Ok(reader: None)` for a missing path, so a
refusal could not distinguish the three failure modes and would reject a
currently-harmless configuration. `database_loaded()` is exposed so the states
are at least distinguishable.

Note the reachability limit: **no `GeoLocation` firewall rule can be declared
today.** `DnsFirewallConfig` has no `rules` field and every `add_rule` call site
is the hardcoded `Subnet`/`Block` block inside `DnsServer::new`, so the DNS
fail-closed posture for an unevaluatable geo rule is correct code with no
reachable input. See `architecture/dns_provider_inversion_phase138_closeout.md`.

---

## 6. Key Implementation Details

- **Reader-backed**: in-memory MaxMind reader for fast lookups (mmap not verified; see `lookup.rs`)
- **Single reader**: one `Option<Reader<Vec<u8>>>` serves country, city/subdivision, and ASN queries — the path determines which database is loaded, not which field is populated
- **Automatic Updates**: Background task with configurable interval
- **Stale Detection**: Alerts when database is older than threshold
- **Presigned URLs**: Support for custom download sources
- **Load failure is not an error path**: see §3 and §5 — a missing or unreadable
  database degrades to `reader: None` with a warning
