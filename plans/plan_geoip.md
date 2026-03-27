# GeoIP Database Updater Implementation Plan

## Status: COMPLETE

## Overview

Implement automatic GeoIP database updates using MaxMind's direct API download approach. This replaces the current stub implementation in `src/geoip/updater.rs`.

**Key Requirements:**
- Use built-in HTTP client (hyper) — reqwest is NOT used anywhere in the codebase
- Support both GeoLite2 (free, default) and GeoIP2 (paid) databases
- Support concurrent downloads of multiple editions (City + Country + ASN)
- Graceful degradation: log warnings, exponential backoff, admin notification if database older than 7 days

---

## Verification: HTTP Client Usage

**Confirmed: `reqwest` is NOT used anywhere in this codebase.**

All HTTP operations use the built-in `crate::http_client` which wraps:
- `hyper` for HTTP/1.1 and HTTP/2
- `hyper_rustls` for TLS
- `hyper_util` for client utilities

Existing patterns to follow:
- `src/http_client/mod.rs:create_http_client()` — standard client
- `src/http_client/mod.rs:610-619` — `get()` and `get_with_timeout()`
- `src/http_client/mod.rs:623+` — `post_json()` variants

---

## Current State

### Files Affected

| File | Current State | Changes Required |
|------|---------------|------------------|
| `src/geoip/updater.rs` | Stub (23 lines) | Full rewrite |
| `src/geoip/lookup.rs` | Reader implementation | Add `reload_from_slice()` |
| `src/geoip/mod.rs` | `GeoIpManager` with updater | Minor updates |
| `src/config/geoip.rs` | Config struct | Add new fields |

### Existing Config Fields

```rust
// src/config/geoip.rs
pub struct GeoIpConfig {
    pub enabled: bool,
    pub database_path: Option<String>,
    pub block_countries: Vec<String>,
    pub allow_countries: Vec<String>,
    pub log_blocked: bool,
    pub update_enabled: bool,
    pub update_url: Option<String>,       // Pre-signed URL (optional override)
    pub account_id: Option<String>,       // MaxMind account ID
    pub license_key: Option<String>,      // MaxMind license key
    pub update_interval_hours: u32,       // Default: 168 (1 week)
}
```

---

## Implementation Plan

### Phase 1: Configuration Enhancement

**1.1 Add New Config Fields**

File: `src/config/geoip.rs`

```rust
#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct GeoIpConfig {
    // ... existing fields ...
    
    // New fields
    #[serde(default = "default_edition_ids")]
    pub edition_ids: Vec<String>,          // Default: ["GeoLite2-City", "GeoLite2-ASN"]
    
    #[serde(default = "default_download_timeout")]
    pub download_timeout_secs: u64,        // Default: 300
    
    #[serde(default = "default_max_retries")]
    pub max_retries: u32,                 // Default: 3
    
    #[serde(default = "default_stale_threshold_days")]
    pub stale_threshold_days: u32,        // Default: 7 (triggers admin notification)
    
    #[serde(default = "default_backoff_base_secs")]
    pub backoff_base_secs: u64,           // Default: 60 (exponential backoff base)
}
```

**1.2 Update Defaults**

```rust
fn default_edition_ids() -> Vec<String> {
    vec!["GeoLite2-City".to_string(), "GeoLite2-ASN".to_string()]
}

fn default_download_timeout() -> u64 { 300 }
fn default_max_retries() -> u32 { 3 }
fn default_stale_threshold_days() -> u32 { 7 }
fn default_backoff_base_secs() -> u64 { 60 }
```

---

### Phase 2: Core Updater Implementation

**2.1 New Data Structures**

File: `src/geoip/updater.rs`

```rust
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::RwLock;

/// Download source configuration
pub enum DownloadSource {
    /// Direct MaxMind API (requires account_id + license_key)
    MaxMind {
        account_id: String,
        license_key: String,
    },
    /// Pre-signed R2 URL from MaxMind portal
    PresignedUrl(String),
}

/// Represents a single database edition to download
pub struct DatabaseEdition {
    pub edition_id: String,
    pub file_name: String,
    pub download_url: String,
}

/// Result of a download operation
pub struct DownloadResult {
    pub edition_id: String,
    pub data: Vec<u8>,
    pub last_modified: Option<i64>,
}

/// Updater state for tracking failures and backoff
pub struct UpdaterState {
    pub consecutive_failures: u32,
    pub last_success: Option<i64>,
    pub last_error: Option<String>,
}
```

**2.2 HTTP Download Implementation**

The existing HTTP client (`src/http_client/mod.rs`) supports adding custom headers via `Request::builder()`. Add a new helper function for authenticated requests:

```rust
// Add to src/http_client/mod.rs
pub async fn get_with_auth(
    client: &HttpClient,
    url: &str,
    username: &str,
    password: &str,
    timeout: Duration,
) -> Result<HttpResponse, String> {
    use http::header::AUTHORIZATION;
    
    let credentials = base64::engine::general_purpose::STANDARD
        .encode(format!("{}:{}", username, password));
    
    let uri: Uri = url.parse().map_err(|e: http::uri::InvalidUri| e.to_string())?;
    let req = Request::builder()
        .method(Method::GET)
        .uri(uri)
        .header(AUTHORIZATION, format!("Basic {}", credentials))
        .body(Full::new(Bytes::new()))
        .map_err(|e| e.to_string())?;

    let response = match tokio::time::timeout(timeout, client.request(req)).await {
        Ok(Ok(response)) => response,
        Ok(Err(e)) => return Err(e.to_string()),
        Err(_) => return Err("request timed out".to_string()),
    };
    
    Ok(HttpResponse::from_hyper(response).await)
}
```

Then in the GeoIP updater:

```rust
impl GeoIpUpdater {
    /// Download database bytes using the built-in HTTP client
    async fn download_database(&self, url: &str) -> Result<DownloadResult, GeoIpUpdaterError> {
        let client = crate::http_client::create_http_client();
        
        let response = match &self.source {
            DownloadSource::MaxMind { account_id, license_key } => {
                crate::http_client::get_with_auth(
                    &client,
                    url,
                    account_id,
                    license_key,
                    Duration::from_secs(self.download_timeout_secs),
                )
                .await
            }
            DownloadSource::PresignedUrl(url) => {
                crate::http_client::get_with_timeout(
                    &client,
                    url,
                    Duration::from_secs(self.download_timeout_secs),
                )
                .await
            }
        }
        .map_err(|e| GeoIpUpdaterError::NetworkError(e.to_string()))?;
        
        // Handle redirects (MaxMind uses R2 presigned URLs)
        // Handle gzip decompression
        // Extract Last-Modified header
        
        Ok(DownloadResult { ... })
    }
}
```

**2.3 Build Download URLs**

For MaxMind direct API:
```
https://download.maxmind.com/geoip/databases/{edition_id}/download?suffix=tar.gz
```

Authentication: Basic Auth header with `account_id:license_key`

**2.4 HEAD Request for Update Check**

Before downloading, check if update is needed:

```rust
async fn check_for_update(&self, url: &str) -> Result<Option<DateTime<Utc>>, GeoIpUpdaterError> {
    // Send HEAD request to get Last-Modified header
    // Compare with local database's Last-Modified
    // Return Some(new_date) if update available, None otherwise
}
```

---

### Phase 3: Database Validation & Loading

**3.1 MMDB Validation**

```rust
impl GeoIpUpdater {
    /// Validate downloaded data is a valid MMDB file
    fn validate_mmdb(data: &[u8]) -> Result<(), GeoIpUpdaterError> {
        // Check magic bytes (0x4d4d4442 = "MMDB")
        if data.len() < 4 || &data[0..4] != b"MMDB" {
            return Err(GeoIpUpdaterError::InvalidDatabase("Invalid MMDB magic bytes".to_string()));
        }
        
        // Check minimum size (GeoLite2-City is typically > 50MB)
        if data.len() < 1_000_000 {
            return Err(GeoIpUpdaterError::InvalidDatabase("Database suspiciously small".to_string()));
        }
        
        // Optionally parse metadata to verify edition_id matches
        Ok(())
    }
}
```

**3.2 Add Hot-Reload to GeoIpLookup**

File: `src/geoip/lookup.rs`

```rust
impl GeoIpLookup {
    /// Reload database from bytes (for hot-reload after update)
    pub fn reload_from_slice(&mut self, data: Vec<u8>) -> Result<(), String> {
        let reader = Reader::from_source(data)
            .map_err(|e| format!("Failed to parse GeoIP database: {}", e))?;
        
        self.reader = Some(reader);
        Ok(())
    }
}
```

---

### Phase 4: Update Orchestration

**4.1 Update Logic with Atomic Replacement**

```rust
impl GeoIpUpdater {
    pub async fn update(&self) -> Result<Vec<String>, GeoIpUpdaterError> {
        let mut updated_editions = Vec::new();
        
        for edition in &self.editions {
            // Check if update needed
            if let Some(remote_date) = self.check_for_update(&edition.download_url).await? {
                let local_date = self.get_local_last_modified(&edition.edition_id)?;
                
                if remote_date <= local_date {
                    tracing::debug!("GeoIP {} is up to date", edition.edition_id);
                    continue;
                }
            }
            
            // Download with retry and backoff
            match self.download_with_retry(&edition.download_url).await {
                Ok(data) => {
                    // Validate
                    Self::validate_mmdb(&data)?;
                    
                    // Atomic write: temp file + rename
                    let temp_path = self.database_path.join(format!("{}.tmp", edition.edition_id));
                    tokio::fs::write(&temp_path, &data).await?;
                    tokio::fs::rename(&temp_path, self.get_edition_path(&edition.edition_id)).await?;
                    
                    updated_editions.push(edition.edition_id.clone());
                }
                Err(e) => {
                    tracing::warn!("Failed to update {} after retries: {}", edition.edition_id, e);
                    self.state.write().await.consecutive_failures += 1;
                    // Continue with other editions
                }
            }
        }
        
        Ok(updated_editions)
    }
    
    async fn download_with_retry(&self, url: &str) -> Result<Vec<u8>, GeoIpUpdaterError> {
        let mut attempts = 0;
        let base_delay = self.backoff_base_secs;
        
        loop {
            attempts += 1;
            
            match self.download_database(url).await {
                Ok(result) => return Ok(result.data),
                Err(e) if attempts >= self.max_retries => return Err(e),
                Err(e) => {
                    let delay = base_delay * 2_u64.pow(attempts - 1);
                    tracing::warn!(
                        "GeoIP download attempt {} failed: {}. Retrying in {}s",
                        attempts, e, delay
                    );
                    tokio::time::sleep(Duration::from_secs(delay)).await;
                }
            }
        }
    }
}
```

**4.2 Update GeoIpManager Integration**

File: `src/geoip/mod.rs`

```rust
impl GeoIpManager {
    pub async fn start_auto_update(&self) {
        // ... existing code ...
        
        tokio::spawn(async move {
            let mut interval = interval(Duration::from_secs(interval_secs));
            loop {
                interval.tick().await;
                
                match updater.update().await {
                    Ok(updated) if !updated.is_empty() => {
                        // Hot-reload the lookup with new data
                        for edition_id in &updated {
                            if let Ok(data) = tokio::fs::read(updater.get_edition_path(edition_id)).await {
                                let mut lookup = updater.lookup.write();
                                if let Err(e) = lookup.reload_from_slice(data) {
                                    tracing::error!("Failed to reload {}: {}", edition_id, e);
                                }
                            }
                        }
                        
                        *last_update.write() = Some(now());
                        tracing::info!("GeoIP databases updated: {:?}", updated);
                    }
                    Ok(_) => {
                        // No updates needed
                        *last_update.write() = Some(now());
                    }
                    Err(e) => {
                        tracing::warn!("GeoIP update failed: {}", e);
                        
                        // Check if database is stale and notify
                        if updater.is_stale().await {
                            updater.send_stale_notification().await;
                        }
                    }
                }
            }
        });
    }
    
    pub async fn is_stale(&self) -> bool {
        let threshold = self.config.stale_threshold_days as i64 * 24 * 60 * 60;
        let last = *self.last_update.read().await;
        if let Some(last_update) = last {
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs() as i64;
            return (now - last_update) > threshold;
        }
        true
    }
}
```

---

### Phase 5: Admin Notification Integration

**5.1 Extend AlertManager for GeoIP**

File: `src/admin/alerting/mod.rs`

```rust
impl AlertManager {
    /// Send a GeoIP stale database notification
    pub async fn send_geoip_stale_notification(
        &self,
        edition_id: &str,
        days_since_update: u32,
    ) -> Result<(), String> {
        let config = self.config.read().await;
        
        let event = AlertEvent {
            timestamp: chrono::Utc::now().timestamp(),
            rule_name: "GeoIP Database Stale".to_string(),
            metric: "geoip_stale".to_string(),
            value: days_since_update as f64,
            threshold: config.stale_threshold_days as f64,
            message: format!(
                "GeoIP database '{}' has not been updated in {} days. \
                 Consider renewing your MaxMind subscription or checking network connectivity.",
                edition_id, days_since_update
            ),
        };
        
        // Send via configured channels
        if config.webhook_enabled {
            self.send_webhook(&config.webhook_urls, &event).await?;
        }
        
        if config.email_enabled {
            send_email_internal(/* ... */).await?;
        }
        
        Ok(())
    }
}
```

**5.2 Store AlertManager Reference in GeoIpManager**

```rust
// In GeoIpManager::new()
pub fn new(
    config: GeoIpConfig,
    site_configs: &[SiteGeoipConfig],
    alert_manager: Option<Arc<AlertManager>>,  // New parameter
) -> Option<Self> {
    // ...
}
```

---

### Phase 6: Testing

**6.1 Unit Tests**

File: `src/geoip/updater.rs`

```rust
#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_validate_mmdb_magic_bytes() {
        let mut valid_data = vec![0x4d, 0x4d, 0x44, 0x42]; // "MMDB"
        valid_data.resize(1_000_000, 0);
        assert!(GeoIpUpdater::validate_mmdb(&valid_data).is_ok());
        
        let invalid_data = vec![0x00, 0x00, 0x00, 0x00];
        assert!(GeoIpUpdater::validate_mmdb(&invalid_data).is_err());
    }
    
    #[test]
    fn test_backoff_calculation() {
        // Exponential backoff: 60s, 120s, 240s, 480s...
    }
    
    #[tokio::test]
    async fn test_download_url_construction() {
        // Test MaxMind URL generation
    }
}
```

**6.2 Integration Test**

File: `tests/integration_test.rs`

```rust
#[tokio::test]
#[ignore] // Requires valid MaxMind credentials
async fn test_geoip_update_integration() {
    // Test actual download from MaxMind API
}
```

---

## Error Handling Summary

| Error Type | Action |
|------------|--------|
| Network timeout | Retry with exponential backoff |
| Auth failure (401) | Log error, stop retries, notify stale |
| Database invalid | Log error, keep old database |
| Disk write failure | Log error, skip update |
| Max retries exceeded | Log warning, continue |

---

## File Changes Summary

| File | Changes |
|------|---------|
| `src/geoip/updater.rs` | Complete rewrite — all phases |
| `src/geoip/lookup.rs` | Add `reload_from_slice()` |
| `src/geoip/mod.rs` | Add `alert_manager` param, update `start_auto_update()` |
| `src/config/geoip.rs` | Add new config fields |
| `src/admin/alerting/mod.rs` | Add `send_geoip_stale_notification()` |
| `src/http_client/mod.rs` | Add `get_with_auth()` for Basic Auth support |
| `tests/integration_test.rs` | Add GeoIP update test |

### Dependencies

**Existing (already in Cargo.toml):**
- `base64 = "0.22"` — for Basic Auth encoding
- `maxminddb = "0.27"` — for reading MMDB files
- `tokio` — async runtime
- `hyper` / `hyper_rustls` — HTTP client (via existing http_client module)

**No new dependencies required.**

---

## Implementation Order

1. **Phase 1a**: Add `get_with_auth()` to HTTP client module
2. **Phase 1b**: Configuration enhancement (config fields)
3. **Phase 2**: Core download implementation
4. **Phase 3**: Validation and hot-reload
5. **Phase 4**: Orchestration and error handling
6. **Phase 5**: Admin notification integration
7. **Phase 6**: Testing

---

## Open Questions

1. **HTTP Client Auth**: ~~Does `crate::http_client` support Basic Auth headers?~~ **RESOLVED** — Will add `get_with_auth()` helper function.

2. **Database Path Strategy**: Currently `database_path` is a single path. With multiple editions, should we:
   - Use subdirectories: `{database_path}/GeoLite2-City/`
   - Use filename suffixes: `{database_path}.city.mmdb`
   - Keep single path and download only one edition?
   
   **Recommendation**: Use edition-specific paths with `.edition_id.mmdb` suffix.

3. **Initial Download**: If no database exists on first run, should we download immediately or require manual placement?
   
   **Recommendation**: Download immediately if `update_enabled` is true and credentials are configured.

4. **Concurrent Downloads**: Download editions sequentially to avoid overwhelming MaxMind's servers. If one fails, others should still proceed.

5. **GeoIpManager Access to AlertManager**: The `GeoIpManager` is created early in server initialization. How do we pass the `AlertManager` reference? Options:
   - Add as parameter to `GeoIpManager::new()`
   - Use a global/static `AlertManager` reference
   - Create GeoIpManager after AlertManager in initialization order
   
   **Recommendation**: Add as parameter to `GeoIpManager::new()` and update all call sites.
