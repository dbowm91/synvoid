use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use flate2::read::GzDecoder;
use tokio::sync::RwLock;
use tracing::{debug, info, warn};

use crate::config::geoip::GeoIpConfig;
use crate::http_client::{get_with_auth, get_with_timeout, head_with_auth};

const MAXMIND_DOWNLOAD_BASE: &str = "https://download.maxmind.com/geoip/databases";

#[derive(Debug, Clone)]
pub enum DownloadSource {
    MaxMind {
        account_id: String,
        license_key: String,
    },
    PresignedUrl(String),
}

impl DownloadSource {
    pub fn from_config(config: &GeoIpConfig) -> Option<Self> {
        if let Some(ref url) = config.update_url {
            if !url.is_empty() {
                return Some(DownloadSource::PresignedUrl(url.clone()));
            }
        }

        if let (Some(ref account_id), Some(ref license_key)) =
            (&config.account_id, &config.license_key)
        {
            if !account_id.is_empty() && !license_key.is_empty() {
                return Some(DownloadSource::MaxMind {
                    account_id: account_id.clone(),
                    license_key: license_key.clone(),
                });
            }
        }

        None
    }
}

#[derive(Debug, Clone)]
pub struct DatabaseEdition {
    pub edition_id: String,
    pub download_url: String,
}

impl DatabaseEdition {
    pub fn new(edition_id: String, download_url: String) -> Self {
        Self {
            edition_id,
            download_url,
        }
    }

    pub fn build_url(edition_id: &str, source: &DownloadSource) -> Option<String> {
        match source {
            DownloadSource::MaxMind { .. } => Some(format!(
                "{}/{}/download?suffix=tar.gz",
                MAXMIND_DOWNLOAD_BASE, edition_id
            )),
            DownloadSource::PresignedUrl(base_url) => {
                if base_url.contains("suffix=") {
                    Some(base_url.clone())
                } else {
                    Some(format!(
                        "{}/download?suffix=tar.gz",
                        base_url.trim_end_matches('/')
                    ))
                }
            }
        }
    }
}

#[derive(Debug, Clone)]
pub struct DownloadResult {
    pub edition_id: String,
    pub data: Vec<u8>,
    pub last_modified: Option<i64>,
}

#[derive(Debug, Clone, Default)]
pub struct UpdaterState {
    pub consecutive_failures: u32,
    pub last_success: Option<i64>,
    pub last_error: Option<String>,
}

#[derive(Debug, thiserror::Error)]
pub enum GeoIpUpdaterError {
    #[error("Network error: {0}")]
    NetworkError(String),

    #[error("Authentication failed: {0}")]
    AuthError(String),

    #[error("Invalid database: {0}")]
    InvalidDatabase(String),

    #[error("IO error: {0}")]
    IoError(String),

    #[error("No download source configured")]
    NoSource,

    #[error("Download failed after {0} attempts: {1}")]
    MaxRetriesExceeded(u32, String),
}

impl From<std::io::Error> for GeoIpUpdaterError {
    fn from(e: std::io::Error) -> Self {
        GeoIpUpdaterError::IoError(e.to_string())
    }
}

pub struct GeoIpUpdater {
    source: Option<DownloadSource>,
    database_path: PathBuf,
    editions: Vec<DatabaseEdition>,
    download_timeout_secs: u64,
    max_retries: u32,
    backoff_base_secs: u64,
    state: Arc<RwLock<UpdaterState>>,
}

impl GeoIpUpdater {
    pub fn new(config: &GeoIpConfig) -> Self {
        let source = DownloadSource::from_config(config);

        let database_path = config
            .database_path
            .as_ref()
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from("/var/lib/maluwaf/geoip"));

        let editions: Vec<DatabaseEdition> = config
            .edition_ids
            .iter()
            .filter_map(|edition_id| {
                let url = DatabaseEdition::build_url(edition_id, source.as_ref().unwrap())?;
                Some(DatabaseEdition::new(edition_id.clone(), url))
            })
            .collect();

        Self {
            source,
            database_path,
            editions,
            download_timeout_secs: config.download_timeout_secs,
            max_retries: config.max_retries,
            backoff_base_secs: config.backoff_base_secs,
            state: Arc::new(RwLock::new(UpdaterState::default())),
        }
    }

    pub fn source(&self) -> Option<&DownloadSource> {
        self.source.as_ref()
    }

    pub fn editions(&self) -> &[DatabaseEdition] {
        &self.editions
    }

    pub fn state(&self) -> Arc<RwLock<UpdaterState>> {
        self.state.clone()
    }

    pub fn database_path(&self) -> &Path {
        &self.database_path
    }

    pub fn edition_path(&self, edition_id: &str) -> PathBuf {
        self.database_path.join(format!("{}.mmdb", edition_id))
    }

    pub async fn check_for_update(
        &self,
        edition: &DatabaseEdition,
    ) -> Result<Option<i64>, GeoIpUpdaterError> {
        let source = self.source.as_ref().ok_or(GeoIpUpdaterError::NoSource)?;
        let client = crate::http_client::create_http_client();
        let timeout = Duration::from_secs(self.download_timeout_secs);

        let response = match source {
            DownloadSource::MaxMind {
                account_id,
                license_key,
            } => {
                head_with_auth(
                    &client,
                    &edition.download_url,
                    account_id,
                    license_key,
                    timeout,
                )
                .await
            }
            DownloadSource::PresignedUrl(_) => {
                get_with_timeout(&client, &edition.download_url, timeout).await
            }
        }
        .map_err(GeoIpUpdaterError::NetworkError)?;

        if response.status.as_u16() == 401 {
            return Err(GeoIpUpdaterError::AuthError(
                "Invalid MaxMind credentials".to_string(),
            ));
        }

        if response.status.as_u16() != 200 {
            return Err(GeoIpUpdaterError::NetworkError(format!(
                "HTTP {}",
                response.status.as_u16()
            )));
        }

        let last_modified = response
            .headers
            .get("Last-Modified")
            .and_then(|v| v.to_str().ok())
            .and_then(parse_http_date);

        Ok(last_modified)
    }

    pub fn validate_mmdb(data: &[u8]) -> Result<(), GeoIpUpdaterError> {
        if data.len() < 4 {
            return Err(GeoIpUpdaterError::InvalidDatabase(
                "Data too short".to_string(),
            ));
        }

        if &data[0..4] != b"MMDB" {
            return Err(GeoIpUpdaterError::InvalidDatabase(
                "Invalid MMDB magic bytes".to_string(),
            ));
        }

        if data.len() < 1_000_000 {
            return Err(GeoIpUpdaterError::InvalidDatabase(
                "Database suspiciously small (less than 1MB)".to_string(),
            ));
        }

        Ok(())
    }

    pub async fn download_database(
        &self,
        edition: &DatabaseEdition,
    ) -> Result<DownloadResult, GeoIpUpdaterError> {
        let source = self.source.as_ref().ok_or(GeoIpUpdaterError::NoSource)?;
        let client = crate::http_client::create_http_client();
        let timeout = Duration::from_secs(self.download_timeout_secs);

        let response = match source {
            DownloadSource::MaxMind {
                account_id,
                license_key,
            } => {
                get_with_auth(
                    &client,
                    &edition.download_url,
                    account_id,
                    license_key,
                    timeout,
                )
                .await
            }
            DownloadSource::PresignedUrl(_) => {
                get_with_timeout(&client, &edition.download_url, timeout).await
            }
        }
        .map_err(GeoIpUpdaterError::NetworkError)?;

        if response.status.as_u16() == 401 {
            return Err(GeoIpUpdaterError::AuthError(
                "Invalid MaxMind credentials".to_string(),
            ));
        }

        if response.status.as_u16() != 200 {
            return Err(GeoIpUpdaterError::NetworkError(format!(
                "HTTP {}",
                response.status.as_u16()
            )));
        }

        let last_modified = response
            .headers
            .get("Last-Modified")
            .and_then(|v| v.to_str().ok())
            .and_then(parse_http_date);

        let content_encoding = response
            .headers
            .get("Content-Encoding")
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_lowercase());

        let mut data = response.body.to_vec();

        if content_encoding.as_deref() == Some("gzip") {
            let mut decoder = GzDecoder::new(&data[..]);
            let mut decompressed = Vec::new();
            use std::io::Read;
            decoder.read_to_end(&mut decompressed).map_err(|e| {
                GeoIpUpdaterError::InvalidDatabase(format!("Gzip decompression failed: {}", e))
            })?;
            data = decompressed;
        }

        let tar_data = extract_first_file_from_tar(&data).map_err(|e| {
            GeoIpUpdaterError::InvalidDatabase(format!("Tar extraction failed: {}", e))
        })?;

        Ok(DownloadResult {
            edition_id: edition.edition_id.clone(),
            data: tar_data,
            last_modified,
        })
    }

    pub async fn download_with_retry(
        &self,
        edition: &DatabaseEdition,
    ) -> Result<DownloadResult, GeoIpUpdaterError> {
        let mut attempts = 0;
        let base_delay = self.backoff_base_secs;

        loop {
            attempts += 1;

            match self.download_database(edition).await {
                Ok(result) => return Ok(result),
                Err(e) if attempts >= self.max_retries => {
                    return Err(GeoIpUpdaterError::MaxRetriesExceeded(
                        attempts,
                        e.to_string(),
                    ));
                }
                Err(e) => {
                    let delay = base_delay * 2_u64.saturating_pow(attempts - 1);
                    warn!(
                        "GeoIP {} download attempt {} failed: {}. Retrying in {}s",
                        edition.edition_id, attempts, e, delay
                    );
                    tokio::time::sleep(Duration::from_secs(delay)).await;
                }
            }
        }
    }

    pub async fn get_local_last_modified(
        &self,
        edition_id: &str,
    ) -> Result<Option<i64>, GeoIpUpdaterError> {
        let path = self.edition_path(edition_id);
        if !path.exists() {
            return Ok(None);
        }

        let metadata = tokio::fs::metadata(&path).await?;
        let modified = metadata.modified()?;
        let duration = modified
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|e| GeoIpUpdaterError::IoError(e.to_string()))?;
        Ok(Some(duration.as_secs() as i64))
    }

    pub async fn update(&self) -> Result<Vec<String>, GeoIpUpdaterError> {
        if self.source.is_none() {
            return Err(GeoIpUpdaterError::NoSource);
        }

        if self.editions.is_empty() {
            return Ok(Vec::new());
        }

        let mut updated_editions = Vec::new();
        let mut has_failure = false;

        for edition in &self.editions {
            debug!(
                "Checking for updates to GeoIP database: {}",
                edition.edition_id
            );

            let needs_update = match self.check_for_update(edition).await {
                Ok(Some(remote_date)) => {
                    let local_date = match self.get_local_last_modified(&edition.edition_id).await {
                        Ok(date) => date,
                        Err(e) => {
                            warn!(
                                "Failed to get local modification time for {}: {}",
                                edition.edition_id, e
                            );
                            Some(0)
                        }
                    };

                    remote_date > local_date.unwrap_or(0)
                }
                Ok(None) => true,
                Err(e) => {
                    warn!(
                        "Failed to check for updates to {}: {}",
                        edition.edition_id, e
                    );
                    true
                }
            };

            if !needs_update {
                debug!("GeoIP {} is up to date", edition.edition_id);
                continue;
            }

            match self.download_with_retry(edition).await {
                Ok(result) => {
                    if let Err(e) = Self::validate_mmdb(&result.data) {
                        warn!("Downloaded GeoIP {} is invalid: {}", edition.edition_id, e);
                        has_failure = true;
                        continue;
                    }

                    if let Err(e) = self
                        .write_database_atomic(&result.data, &edition.edition_id)
                        .await
                    {
                        warn!(
                            "Failed to write GeoIP {} to disk: {}",
                            edition.edition_id, e
                        );
                        has_failure = true;
                        continue;
                    }

                    updated_editions.push(edition.edition_id.clone());
                    info!("Updated GeoIP database: {}", edition.edition_id);
                }
                Err(e) => {
                    warn!(
                        "Failed to update GeoIP {} after {} attempts: {}",
                        edition.edition_id, self.max_retries, e
                    );
                    has_failure = true;

                    let mut state = self.state.write().await;
                    state.consecutive_failures += 1;
                    state.last_error = Some(e.to_string());
                }
            }
        }

        if updated_editions.is_empty() && !has_failure {
            let mut state = self.state.write().await;
            state.consecutive_failures = 0;
            state.last_error = None;
            state.last_success = Some(crate::utils::safe_unix_timestamp() as i64);
        }

        Ok(updated_editions)
    }

    async fn write_database_atomic(
        &self,
        data: &[u8],
        edition_id: &str,
    ) -> Result<(), GeoIpUpdaterError> {
        tokio::fs::create_dir_all(&self.database_path).await?;

        let temp_path = self.database_path.join(format!("{}.tmp", edition_id));
        let final_path = self.edition_path(edition_id);

        tokio::fs::write(&temp_path, data).await?;

        tokio::fs::rename(&temp_path, &final_path).await?;

        Ok(())
    }

    pub async fn load_database(&self, edition_id: &str) -> Result<Vec<u8>, GeoIpUpdaterError> {
        let path = self.edition_path(edition_id);
        tokio::fs::read(&path)
            .await
            .map_err(|e| GeoIpUpdaterError::IoError(e.to_string()))
    }
}

fn parse_http_date(s: &str) -> Option<i64> {
    if let Ok(dt) = chrono::DateTime::parse_from_rfc2822(s) {
        return Some(dt.timestamp());
    }

    chrono::DateTime::parse_from_str(s, "%a, %d %b %Y %H:%M:%S %Z")
        .ok()
        .map(|dt| dt.timestamp())
}

fn extract_first_file_from_tar(data: &[u8]) -> Result<Vec<u8>, String> {
    use std::io::Read;

    let decoder = flate2::read::GzDecoder::new(data);
    let mut tar = tar::Archive::new(decoder);

    for entry in tar.entries().map_err(|e| e.to_string())? {
        let mut entry = entry.map_err(|e| e.to_string())?;
        let path = entry.path().map_err(|e| e.to_string())?;

        let path_str = path.to_string_lossy();

        if path_str.ends_with(".mmdb") || path_str.ends_with(".mdb") {
            let mut contents = Vec::new();
            entry
                .read_to_end(&mut contents)
                .map_err(|e| e.to_string())?;
            return Ok(contents);
        }
    }

    if data.len() > 4 && &data[0..4] == b"MMDB" {
        return Ok(data.to_vec());
    }

    Err("No .mmdb file found in archive".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validate_mmdb_valid() {
        let mut valid_data = vec![0x4d, 0x4d, 0x44, 0x42];
        valid_data.resize(1_000_000, 0);
        assert!(GeoIpUpdater::validate_mmdb(&valid_data).is_ok());
    }

    #[test]
    fn test_validate_mmdb_invalid_magic() {
        let mut invalid_data = vec![0x00, 0x00, 0x00, 0x00];
        invalid_data.resize(1_000_000, 0);
        assert!(GeoIpUpdater::validate_mmdb(&invalid_data).is_err());
    }

    #[test]
    fn test_validate_mmdb_too_small() {
        let small_data = vec![0x4d, 0x4d, 0x44, 0x42, 0x00];
        assert!(GeoIpUpdater::validate_mmdb(&small_data).is_err());
    }

    #[test]
    fn test_parse_http_date_rfc2822() {
        let result = parse_http_date("Mon, 01 Jan 2024 12:00:00 GMT");
        assert!(result.is_some());
        assert_eq!(result.unwrap(), 1704110400);
    }

    #[test]
    fn test_parse_http_date_rfc2616() {
        let result = parse_http_date("Mon, 01 Jan 2024 12:00:00 GMT");
        assert!(result.is_some());
    }

    #[test]
    fn test_database_edition_build_url_maxmind() {
        let source = DownloadSource::MaxMind {
            account_id: "123".to_string(),
            license_key: "key".to_string(),
        };
        let url = DatabaseEdition::build_url("GeoLite2-City", &source).unwrap();
        assert!(url.contains("GeoLite2-City"));
        assert!(url.contains("suffix=tar.gz"));
    }

    #[test]
    fn test_database_edition_build_url_presigned() {
        let source = DownloadSource::PresignedUrl("https://example.com/geoip".to_string());
        let url = DatabaseEdition::build_url("GeoLite2-City", &source).unwrap();
        assert!(url.contains("GeoLite2-City"));
    }

    #[test]
    fn test_download_source_from_config_url() {
        let mut config = GeoIpConfig::default();
        config.update_url = Some("https://custom.url/db".to_string());
        config.account_id = Some("123".to_string());
        config.license_key = Some("key".to_string());

        let source = DownloadSource::from_config(&config).unwrap();
        assert!(matches!(source, DownloadSource::PresignedUrl(_)));
    }

    #[test]
    fn test_download_source_from_config_maxmind() {
        let mut config = GeoIpConfig::default();
        config.account_id = Some("123".to_string());
        config.license_key = Some("key".to_string());

        let source = DownloadSource::from_config(&config).unwrap();
        assert!(matches!(source, DownloadSource::MaxMind { .. }));
    }

    #[test]
    fn test_download_source_from_config_none() {
        let config = GeoIpConfig::default();
        assert!(DownloadSource::from_config(&config).is_none());
    }
}
