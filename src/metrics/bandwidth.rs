use chrono::{DateTime, Datelike, TimeZone, Utc};
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Instant;

#[derive(Debug, Clone, Serialize, Deserialize)]
struct BandwidthPersistedState {
    total_bytes_received: u64,
    total_bytes_sent: u64,
    monthly_bytes_received: u64,
    monthly_bytes_sent: u64,
    monthly_period_start: DateTime<Utc>,
}

const EMA_ALPHA: f64 = 0.3;

static GLOBAL_TRACKER: parking_lot::Mutex<Option<Arc<BandwidthTracker>>> =
    parking_lot::Mutex::new(None);

#[derive(Debug, thiserror::Error)]
pub enum BandwidthTrackerError {
    #[error("BandwidthTracker not initialized - call init_global_bandwidth_tracker() first")]
    NotInitialized,
}

pub fn get_global_bandwidth_tracker() -> Result<Arc<BandwidthTracker>, BandwidthTrackerError> {
    GLOBAL_TRACKER
        .lock()
        .as_ref()
        .ok_or(BandwidthTrackerError::NotInitialized)
        .map(Clone::clone)
}

pub fn get_global_bandwidth_tracker_or_log() -> Option<Arc<BandwidthTracker>> {
    match get_global_bandwidth_tracker() {
        Ok(tracker) => Some(tracker),
        Err(e) => {
            tracing::warn!("{}", e);
            None
        }
    }
}

pub fn init_global_bandwidth_tracker(retention_days: u32, mesh_excluded: bool) {
    let tracker = Arc::new(BandwidthTracker::new(retention_days, mesh_excluded));
    let mut guard = GLOBAL_TRACKER.lock();
    if guard.is_none() {
        *guard = Some(tracker);
        tracing::info!(
            "Bandwidth tracker initialized: retention_days={}, mesh_excluded={}",
            retention_days,
            mesh_excluded
        );
    }
}

pub fn configure_global_bandwidth_tracker(
    data_dir: Option<&str>,
    reset_config: MonthlyResetConfig,
) {
    if let Some(tracker) = GLOBAL_TRACKER.lock().as_ref() {
        tracker.configure(data_dir, reset_config);
    }
}

pub fn persist_global_bandwidth_tracker() {
    if let Some(tracker) = GLOBAL_TRACKER.lock().as_ref() {
        tracker.persist();
    }
}

pub fn create_bandwidth_tracker(retention_days: u32, mesh_excluded: bool) -> Arc<BandwidthTracker> {
    Arc::new(BandwidthTracker::new(retention_days, mesh_excluded))
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct MonthlyResetConfig {
    pub mode: MonthlyResetMode,
    pub fixed_day: Option<u32>,
}

impl Default for MonthlyResetConfig {
    fn default() -> Self {
        Self {
            mode: MonthlyResetMode::Rolling30Days,
            fixed_day: None,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub enum MonthlyResetMode {
    #[serde(rename = "rolling_30_days")]
    Rolling30Days,
    #[serde(rename = "calendar_month")]
    CalendarMonth,
    #[serde(rename = "fixed_date")]
    FixedDate,
}

pub struct BandwidthTracker {
    pub total_bytes_received: AtomicU64,
    pub total_bytes_sent: AtomicU64,
    pub proxied_bytes_received: AtomicU64,
    pub proxied_bytes_sent: AtomicU64,
    pub blocked_bytes_sent: AtomicU64,
    pub challenged_bytes_sent: AtomicU64,
    pub error_bytes_sent: AtomicU64,

    pub http_bytes_received: AtomicU64,
    pub http_bytes_sent: AtomicU64,
    pub https_bytes_received: AtomicU64,
    pub https_bytes_sent: AtomicU64,
    pub http3_bytes_received: AtomicU64,
    pub http3_bytes_sent: AtomicU64,
    pub tcp_bytes_received: AtomicU64,
    pub tcp_bytes_sent: AtomicU64,
    pub udp_bytes_received: AtomicU64,
    pub udp_bytes_sent: AtomicU64,
    pub tunnel_bytes_received: AtomicU64,
    pub tunnel_bytes_sent: AtomicU64,
    pub mesh_bytes_received: AtomicU64,
    pub mesh_bytes_sent: AtomicU64,

    pub per_site: RwLock<HashMap<String, SiteBandwidth>>,
    pub per_upstream: RwLock<HashMap<String, UpstreamBandwidth>>,

    mesh_excluded: bool,

    ingress_rate: AtomicU64,
    egress_rate: AtomicU64,
    last_ingress_total: AtomicU64,
    last_egress_total: AtomicU64,
    last_rate_update: RwLock<Instant>,

    monthly_bytes_received: AtomicU64,
    monthly_bytes_sent: AtomicU64,
    monthly_period_start: RwLock<DateTime<Utc>>,
    monthly_reset_config: RwLock<MonthlyResetConfig>,
    persist_path: RwLock<Option<PathBuf>>,
    last_rollover_check: RwLock<Instant>,
}

#[derive(Debug, Default)]
pub struct SiteBandwidth {
    pub bytes_received: AtomicU64,
    pub bytes_sent: AtomicU64,
    pub proxied_bytes_sent: AtomicU64,
    pub proxied_bytes_received: AtomicU64,
    pub mesh_bytes_sent: AtomicU64,
    pub mesh_bytes_received: AtomicU64,
}

#[derive(Debug, Default)]
pub struct UpstreamBandwidth {
    pub bytes_sent: AtomicU64,
    pub bytes_received: AtomicU64,
}

impl Default for BandwidthTracker {
    fn default() -> Self {
        Self::new(365, false)
    }
}

impl std::fmt::Debug for BandwidthTracker {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BandwidthTracker")
            .field(
                "total_bytes_received",
                &self.total_bytes_received.load(Ordering::Relaxed),
            )
            .field(
                "total_bytes_sent",
                &self.total_bytes_sent.load(Ordering::Relaxed),
            )
            .finish()
    }
}

impl BandwidthTracker {
    pub fn new(_retention_days: u32, mesh_excluded: bool) -> Self {
        let now = Instant::now();
        let period_start = Utc::now();
        Self {
            total_bytes_received: AtomicU64::new(0),
            total_bytes_sent: AtomicU64::new(0),
            proxied_bytes_received: AtomicU64::new(0),
            proxied_bytes_sent: AtomicU64::new(0),
            blocked_bytes_sent: AtomicU64::new(0),
            challenged_bytes_sent: AtomicU64::new(0),
            error_bytes_sent: AtomicU64::new(0),
            http_bytes_received: AtomicU64::new(0),
            http_bytes_sent: AtomicU64::new(0),
            https_bytes_received: AtomicU64::new(0),
            https_bytes_sent: AtomicU64::new(0),
            http3_bytes_received: AtomicU64::new(0),
            http3_bytes_sent: AtomicU64::new(0),
            tcp_bytes_received: AtomicU64::new(0),
            tcp_bytes_sent: AtomicU64::new(0),
            udp_bytes_received: AtomicU64::new(0),
            udp_bytes_sent: AtomicU64::new(0),
            tunnel_bytes_received: AtomicU64::new(0),
            tunnel_bytes_sent: AtomicU64::new(0),
            mesh_bytes_received: AtomicU64::new(0),
            mesh_bytes_sent: AtomicU64::new(0),
            per_site: RwLock::new(HashMap::new()),
            per_upstream: RwLock::new(HashMap::new()),
            mesh_excluded,
            ingress_rate: AtomicU64::new(0),
            egress_rate: AtomicU64::new(0),
            last_ingress_total: AtomicU64::new(0),
            last_egress_total: AtomicU64::new(0),
            last_rate_update: RwLock::new(now),
            monthly_bytes_received: AtomicU64::new(0),
            monthly_bytes_sent: AtomicU64::new(0),
            monthly_period_start: RwLock::new(period_start),
            monthly_reset_config: RwLock::new(MonthlyResetConfig::default()),
            persist_path: RwLock::new(None),
            last_rollover_check: RwLock::new(now),
        }
    }

    pub fn with_persistence(mut self, path: PathBuf) -> Self {
        *self.persist_path.write() = Some(path.clone());
        if let Some(state) = Self::load_persisted_state(&path) {
            self.total_bytes_received = AtomicU64::new(state.total_bytes_received);
            self.total_bytes_sent = AtomicU64::new(state.total_bytes_sent);
            self.monthly_bytes_received = AtomicU64::new(state.monthly_bytes_received);
            self.monthly_bytes_sent = AtomicU64::new(state.monthly_bytes_sent);
            *self.monthly_period_start.write() = state.monthly_period_start;
            tracing::info!(
                "Loaded bandwidth state: total_rx={}, total_tx={}, monthly_rx={}, monthly_tx={}, period_start={}",
                state.total_bytes_received,
                state.total_bytes_sent,
                state.monthly_bytes_received,
                state.monthly_bytes_sent,
                state.monthly_period_start
            );
        }
        self
    }

    pub fn set_persist_path(&self, path: PathBuf) {
        *self.persist_path.write() = Some(path);
    }

    pub fn set_monthly_reset_config(&self, config: MonthlyResetConfig) {
        let mut guard = self.monthly_reset_config.write();
        let old_config = guard.clone();
        *guard = config.clone();

        if old_config != config {
            tracing::info!("Monthly reset config changed: {:?}", config);
            drop(guard);
            *self.monthly_period_start.write() = Utc::now();
            self.monthly_bytes_received.store(0, Ordering::Relaxed);
            self.monthly_bytes_sent.store(0, Ordering::Relaxed);
        }
    }

    pub fn configure(&self, data_dir: Option<&str>, reset_config: MonthlyResetConfig) {
        if let Some(dir) = data_dir {
            let path = std::path::Path::new(dir);
            if !path.exists() {
                if let Err(e) = fs::create_dir_all(path) {
                    tracing::error!("Failed to create bandwidth data directory: {}", e);
                    return;
                }
                tracing::info!("Created bandwidth data directory: {:?}", path);
            }
            let full_path = path.join("bandwidth_state.json");
            self.set_persist_path(full_path);
            tracing::info!(
                "Bandwidth persistence path set to: {:?}",
                self.persist_path.read()
            );
        }
        self.set_monthly_reset_config(reset_config);
    }

    fn load_persisted_state(path: &PathBuf) -> Option<BandwidthPersistedState> {
        match fs::read_to_string(path) {
            Ok(content) => match serde_json::from_str(&content) {
                Ok(state) => Some(state),
                Err(e) => {
                    tracing::warn!("Failed to parse bandwidth state file: {}", e);
                    None
                }
            },
            Err(_) => None,
        }
    }

    pub fn persist(&self) {
        if let Some(ref path) = *self.persist_path.read() {
            let state = BandwidthPersistedState {
                total_bytes_received: self.total_bytes_received.load(Ordering::Relaxed),
                total_bytes_sent: self.total_bytes_sent.load(Ordering::Relaxed),
                monthly_bytes_received: self.monthly_bytes_received.load(Ordering::Relaxed),
                monthly_bytes_sent: self.monthly_bytes_sent.load(Ordering::Relaxed),
                monthly_period_start: *self.monthly_period_start.read(),
            };

            if let Ok(content) = serde_json::to_string_pretty(&state) {
                if let Err(e) = fs::write(path, content) {
                    tracing::error!("Failed to persist bandwidth state: {}", e);
                }
            }
        }
    }

    fn check_and_rollover_monthly(&self) {
        let now = Instant::now();
        let last_check = *self.last_rollover_check.read();

        let elapsed = now.duration_since(last_check).as_secs_f64();
        if elapsed < 60.0 {
            return;
        }

        *self.last_rollover_check.write() = now;

        let now_utc = Utc::now();
        let period_start = *self.monthly_period_start.read();
        let reset_config = self.monthly_reset_config.read().clone();

        let should_rollover = match reset_config.mode {
            MonthlyResetMode::Rolling30Days => {
                let days_since = (now_utc - period_start).num_days();
                days_since >= 30
            }
            MonthlyResetMode::CalendarMonth => now_utc.day() == 1 && now_utc > period_start,
            MonthlyResetMode::FixedDate => {
                if let Some(day) = reset_config.fixed_day {
                    now_utc.day() >= day && period_start.day() < day && now_utc > period_start
                } else {
                    false
                }
            }
        };

        if should_rollover {
            tracing::info!(
                "Rolling over monthly bandwidth counters. Previous period started: {}",
                period_start
            );
            self.monthly_bytes_received.store(0, Ordering::Relaxed);
            self.monthly_bytes_sent.store(0, Ordering::Relaxed);
            *self.monthly_period_start.write() = now_utc;
        }
    }

    pub fn shared(retention_days: u32, mesh_excluded: bool) -> Arc<Self> {
        Arc::new(Self::new(retention_days, mesh_excluded))
    }

    pub fn record_ingress(&self, bytes: u64, protocol: BandwidthProtocol) {
        self.total_bytes_received
            .fetch_add(bytes, Ordering::Relaxed);
        self.monthly_bytes_received
            .fetch_add(bytes, Ordering::Relaxed);
        self.check_and_rollover_monthly();
        self.record_protocol_ingress(bytes, protocol);
    }

    pub fn record_egress(
        &self,
        bytes: u64,
        protocol: BandwidthProtocol,
        direction: EgressDirection,
    ) {
        self.total_bytes_sent.fetch_add(bytes, Ordering::Relaxed);
        self.monthly_bytes_sent.fetch_add(bytes, Ordering::Relaxed);
        self.check_and_rollover_monthly();
        self.record_protocol_egress(bytes, protocol);

        match direction {
            EgressDirection::Proxied => {
                self.proxied_bytes_sent.fetch_add(bytes, Ordering::Relaxed);
            }
            EgressDirection::Blocked => {
                self.blocked_bytes_sent.fetch_add(bytes, Ordering::Relaxed);
            }
            EgressDirection::Challenged => {
                self.challenged_bytes_sent
                    .fetch_add(bytes, Ordering::Relaxed);
            }
            EgressDirection::Error => {
                self.error_bytes_sent.fetch_add(bytes, Ordering::Relaxed);
            }
            EgressDirection::Mesh => {
                self.mesh_bytes_sent.fetch_add(bytes, Ordering::Relaxed);
            }
        }
    }

    pub fn record_proxied(&self, bytes_sent: u64, bytes_received: u64, upstream_id: &str) {
        self.proxied_bytes_received
            .fetch_add(bytes_received, Ordering::Relaxed);
        self.proxied_bytes_sent
            .fetch_add(bytes_sent, Ordering::Relaxed);

        let mut upstreams = self.per_upstream.write();
        let upstream = upstreams
            .entry(upstream_id.to_string())
            .or_insert_with(UpstreamBandwidth::default);
        upstream.bytes_sent.fetch_add(bytes_sent, Ordering::Relaxed);
        upstream
            .bytes_received
            .fetch_add(bytes_received, Ordering::Relaxed);
    }

    pub fn record_mesh(&self, bytes_sent: u64, bytes_received: u64) {
        self.mesh_bytes_received
            .fetch_add(bytes_received, Ordering::Relaxed);
        self.mesh_bytes_sent
            .fetch_add(bytes_sent, Ordering::Relaxed);
    }

    pub fn record_site_ingress(&self, site_id: &str, bytes: u64) {
        let mut sites = self.per_site.write();
        let site = sites
            .entry(site_id.to_string())
            .or_insert_with(SiteBandwidth::default);
        site.bytes_received.fetch_add(bytes, Ordering::Relaxed);
    }

    pub fn record_site_egress(&self, site_id: &str, bytes: u64) {
        let mut sites = self.per_site.write();
        let site = sites
            .entry(site_id.to_string())
            .or_insert_with(SiteBandwidth::default);
        site.bytes_sent.fetch_add(bytes, Ordering::Relaxed);
    }

    pub fn record_site_proxied(&self, site_id: &str, bytes_sent: u64, bytes_received: u64) {
        let mut sites = self.per_site.write();
        let site = sites
            .entry(site_id.to_string())
            .or_insert_with(SiteBandwidth::default);
        site.proxied_bytes_sent
            .fetch_add(bytes_sent, Ordering::Relaxed);
        site.proxied_bytes_received
            .fetch_add(bytes_received, Ordering::Relaxed);
    }

    pub fn record_site_mesh_egress(&self, site_id: &str, bytes: u64) {
        let mut sites = self.per_site.write();
        let site = sites
            .entry(site_id.to_string())
            .or_insert_with(SiteBandwidth::default);
        site.mesh_bytes_sent.fetch_add(bytes, Ordering::Relaxed);
        self.mesh_bytes_sent.fetch_add(bytes, Ordering::Relaxed);
    }

    pub fn record_site_mesh_ingress(&self, site_id: &str, bytes: u64) {
        let mut sites = self.per_site.write();
        let site = sites
            .entry(site_id.to_string())
            .or_insert_with(SiteBandwidth::default);
        site.mesh_bytes_received.fetch_add(bytes, Ordering::Relaxed);
        self.mesh_bytes_received.fetch_add(bytes, Ordering::Relaxed);
    }

    fn record_protocol_ingress(&self, bytes: u64, protocol: BandwidthProtocol) {
        match protocol {
            BandwidthProtocol::Http => {
                self.http_bytes_received.fetch_add(bytes, Ordering::Relaxed);
            }
            BandwidthProtocol::Https => {
                self.https_bytes_received
                    .fetch_add(bytes, Ordering::Relaxed);
            }
            BandwidthProtocol::Http3 => {
                self.http3_bytes_received
                    .fetch_add(bytes, Ordering::Relaxed);
            }
            BandwidthProtocol::Tcp => {
                self.tcp_bytes_received.fetch_add(bytes, Ordering::Relaxed);
            }
            BandwidthProtocol::Udp => {
                self.udp_bytes_received.fetch_add(bytes, Ordering::Relaxed);
            }
            BandwidthProtocol::Tunnel => {
                self.tunnel_bytes_received
                    .fetch_add(bytes, Ordering::Relaxed);
            }
            BandwidthProtocol::Mesh => {
                self.mesh_bytes_received.fetch_add(bytes, Ordering::Relaxed);
            }
        }
    }

    fn record_protocol_egress(&self, bytes: u64, protocol: BandwidthProtocol) {
        match protocol {
            BandwidthProtocol::Http => {
                self.http_bytes_sent.fetch_add(bytes, Ordering::Relaxed);
            }
            BandwidthProtocol::Https => {
                self.https_bytes_sent.fetch_add(bytes, Ordering::Relaxed);
            }
            BandwidthProtocol::Http3 => {
                self.http3_bytes_sent.fetch_add(bytes, Ordering::Relaxed);
            }
            BandwidthProtocol::Tcp => {
                self.tcp_bytes_sent.fetch_add(bytes, Ordering::Relaxed);
            }
            BandwidthProtocol::Udp => {
                self.udp_bytes_sent.fetch_add(bytes, Ordering::Relaxed);
            }
            BandwidthProtocol::Tunnel => {
                self.tunnel_bytes_sent.fetch_add(bytes, Ordering::Relaxed);
            }
            BandwidthProtocol::Mesh => {
                self.mesh_bytes_sent.fetch_add(bytes, Ordering::Relaxed);
            }
        }
    }

    fn update_rates(&self) {
        let now = Instant::now();
        let last_update = *self.last_rate_update.read();
        let elapsed = now.duration_since(last_update).as_secs_f64();

        if elapsed >= 1.0 {
            let current_ingress = self.total_bytes_received.load(Ordering::Relaxed);
            let current_egress = self.total_bytes_sent.load(Ordering::Relaxed);

            let last_ingress = self.last_ingress_total.load(Ordering::Relaxed);
            let last_egress = self.last_egress_total.load(Ordering::Relaxed);

            self.last_ingress_total
                .store(current_ingress, Ordering::Relaxed);
            self.last_egress_total
                .store(current_egress, Ordering::Relaxed);

            let ingress_delta = current_ingress.saturating_sub(last_ingress);
            let egress_delta = current_egress.saturating_sub(last_egress);

            let instant_ingress = if elapsed > 0.0 {
                ingress_delta as f64 / elapsed
            } else {
                0.0
            };
            let instant_egress = if elapsed > 0.0 {
                egress_delta as f64 / elapsed
            } else {
                0.0
            };

            let current_ingress_rate = self.ingress_rate.load(Ordering::Relaxed) as f64;
            let current_egress_rate = self.egress_rate.load(Ordering::Relaxed) as f64;

            let new_ingress =
                EMA_ALPHA * instant_ingress + (1.0 - EMA_ALPHA) * current_ingress_rate;
            let new_egress = EMA_ALPHA * instant_egress + (1.0 - EMA_ALPHA) * current_egress_rate;

            self.ingress_rate
                .store(new_ingress as u64, Ordering::Relaxed);
            self.egress_rate.store(new_egress as u64, Ordering::Relaxed);

            *self.last_rate_update.write() = now;
        }
    }

    pub fn get_total_bytes_received(&self) -> u64 {
        self.total_bytes_received.load(Ordering::Relaxed)
    }

    pub fn get_total_bytes_sent(&self) -> u64 {
        self.total_bytes_sent.load(Ordering::Relaxed)
    }

    pub fn get_total_excluding_mesh(&self) -> (u64, u64) {
        if self.mesh_excluded {
            let received = self.total_bytes_received.load(Ordering::Relaxed)
                - self.mesh_bytes_received.load(Ordering::Relaxed);
            let sent = self.total_bytes_sent.load(Ordering::Relaxed)
                - self.mesh_bytes_sent.load(Ordering::Relaxed);
            (received, sent)
        } else {
            (
                self.total_bytes_received.load(Ordering::Relaxed),
                self.total_bytes_sent.load(Ordering::Relaxed),
            )
        }
    }

    pub fn get_monthly_usage(&self) -> (u64, u64) {
        self.check_and_rollover_monthly();
        let received = self.monthly_bytes_received.load(Ordering::Relaxed);
        let sent = self.monthly_bytes_sent.load(Ordering::Relaxed);
        if self.mesh_excluded {
            let mesh_rx = self.mesh_bytes_received.load(Ordering::Relaxed);
            let mesh_tx = self.mesh_bytes_sent.load(Ordering::Relaxed);
            (
                received.saturating_sub(mesh_rx),
                sent.saturating_sub(mesh_tx),
            )
        } else {
            (received, sent)
        }
    }

    pub fn get_monthly_period_info(&self) -> MonthlyPeriodInfo {
        let period_start = *self.monthly_period_start.read();
        let now = Utc::now();
        let reset_config = self.monthly_reset_config.read().clone();
        let days_in_period = match reset_config.mode {
            MonthlyResetMode::Rolling30Days => 30,
            MonthlyResetMode::CalendarMonth | MonthlyResetMode::FixedDate => {
                let next_month = if now.month() == 12 {
                    Utc.with_ymd_and_hms(now.year() + 1, 1, 1, 0, 0, 0).unwrap()
                } else {
                    Utc.with_ymd_and_hms(now.year(), now.month() + 1, 1, 0, 0, 0)
                        .unwrap()
                };
                (next_month - period_start).num_days() as u32
            }
        };
        let days_elapsed = (now - period_start).num_days().max(1) as f64;
        let days_remaining = days_in_period.saturating_sub(days_elapsed as u32).max(0);

        MonthlyPeriodInfo {
            period_start,
            days_elapsed: days_elapsed as u32,
            days_remaining,
            reset_mode: reset_config,
        }
    }

    pub fn get_current_rate(&self) -> (u64, u64) {
        self.update_rates();
        (
            self.ingress_rate.load(Ordering::Relaxed),
            self.egress_rate.load(Ordering::Relaxed),
        )
    }

    pub fn get_per_site(&self) -> HashMap<String, SiteBandwidthPayload> {
        let sites = self.per_site.read();
        let mut result = HashMap::new();
        for (site_id, bw) in sites.iter() {
            result.insert(
                site_id.clone(),
                SiteBandwidthPayload {
                    bytes_received: bw.bytes_received.load(Ordering::Relaxed),
                    bytes_sent: bw.bytes_sent.load(Ordering::Relaxed),
                    proxied_bytes_sent: bw.proxied_bytes_sent.load(Ordering::Relaxed),
                    proxied_bytes_received: bw.proxied_bytes_received.load(Ordering::Relaxed),
                    mesh_bytes_sent: bw.mesh_bytes_sent.load(Ordering::Relaxed),
                    mesh_bytes_received: bw.mesh_bytes_received.load(Ordering::Relaxed),
                },
            );
        }
        result
    }

    pub fn get_per_upstream(&self) -> HashMap<String, UpstreamBandwidthPayload> {
        let upstreams = self.per_upstream.read();
        let mut result = HashMap::new();
        for (upstream_id, bw) in upstreams.iter() {
            result.insert(
                upstream_id.clone(),
                UpstreamBandwidthPayload {
                    bytes_sent: bw.bytes_sent.load(Ordering::Relaxed),
                    bytes_received: bw.bytes_received.load(Ordering::Relaxed),
                },
            );
        }
        result
    }

    pub fn to_payload(&self) -> BandwidthPayload {
        let (total_received, total_sent) = self.get_total_excluding_mesh();
        let (ingress_rate, egress_rate) = self.get_current_rate();
        let (monthly_received, monthly_sent) = self.get_monthly_usage();
        let period_info = self.get_monthly_period_info();

        BandwidthPayload {
            bytes_received: total_received,
            bytes_sent: total_sent,
            bytes_received_raw: self.total_bytes_received.load(Ordering::Relaxed),
            bytes_sent_raw: self.total_bytes_sent.load(Ordering::Relaxed),
            proxied_bytes_received: self.proxied_bytes_received.load(Ordering::Relaxed),
            proxied_bytes_sent: self.proxied_bytes_sent.load(Ordering::Relaxed),
            blocked_bytes_sent: self.blocked_bytes_sent.load(Ordering::Relaxed),
            challenged_bytes_sent: self.challenged_bytes_sent.load(Ordering::Relaxed),
            error_bytes_sent: self.error_bytes_sent.load(Ordering::Relaxed),
            mesh_bytes_received: self.mesh_bytes_received.load(Ordering::Relaxed),
            mesh_bytes_sent: self.mesh_bytes_sent.load(Ordering::Relaxed),
            ingress_rate_bps: ingress_rate,
            egress_rate_bps: egress_rate,
            monthly_bytes_received: monthly_received,
            monthly_bytes_sent: monthly_sent,
            monthly_period: MonthlyPeriodPayload {
                period_start: period_info.period_start,
                days_elapsed: period_info.days_elapsed,
                days_remaining: period_info.days_remaining,
                reset_mode: match period_info.reset_mode.mode {
                    MonthlyResetMode::Rolling30Days => "rolling_30_days".to_string(),
                    MonthlyResetMode::CalendarMonth => "calendar_month".to_string(),
                    MonthlyResetMode::FixedDate => "fixed_date".to_string(),
                },
                fixed_day: period_info.reset_mode.fixed_day,
            },
            per_protocol: ProtocolBandwidthPayload {
                http: ProtocolBandwidth {
                    bytes_received: self.http_bytes_received.load(Ordering::Relaxed),
                    bytes_sent: self.http_bytes_sent.load(Ordering::Relaxed),
                },
                https: ProtocolBandwidth {
                    bytes_received: self.https_bytes_received.load(Ordering::Relaxed),
                    bytes_sent: self.https_bytes_sent.load(Ordering::Relaxed),
                },
                http3: ProtocolBandwidth {
                    bytes_received: self.http3_bytes_received.load(Ordering::Relaxed),
                    bytes_sent: self.http3_bytes_sent.load(Ordering::Relaxed),
                },
                tcp: ProtocolBandwidth {
                    bytes_received: self.tcp_bytes_received.load(Ordering::Relaxed),
                    bytes_sent: self.tcp_bytes_sent.load(Ordering::Relaxed),
                },
                udp: ProtocolBandwidth {
                    bytes_received: self.udp_bytes_received.load(Ordering::Relaxed),
                    bytes_sent: self.udp_bytes_sent.load(Ordering::Relaxed),
                },
                tunnel: ProtocolBandwidth {
                    bytes_received: self.tunnel_bytes_received.load(Ordering::Relaxed),
                    bytes_sent: self.tunnel_bytes_sent.load(Ordering::Relaxed),
                },
            },
            per_site: self.get_per_site(),
            per_upstream: self.get_per_upstream(),
        }
    }
}

pub struct MonthlyPeriodInfo {
    pub period_start: DateTime<Utc>,
    pub days_elapsed: u32,
    pub days_remaining: u32,
    pub reset_mode: MonthlyResetConfig,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BandwidthProtocol {
    Http,
    Https,
    Http3,
    Tcp,
    Udp,
    Tunnel,
    Mesh,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EgressDirection {
    Proxied,
    Blocked,
    Challenged,
    Error,
    Mesh,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct BandwidthPayload {
    pub bytes_received: u64,
    pub bytes_sent: u64,
    pub bytes_received_raw: u64,
    pub bytes_sent_raw: u64,
    pub proxied_bytes_received: u64,
    pub proxied_bytes_sent: u64,
    pub blocked_bytes_sent: u64,
    pub challenged_bytes_sent: u64,
    pub error_bytes_sent: u64,
    pub mesh_bytes_received: u64,
    pub mesh_bytes_sent: u64,
    pub ingress_rate_bps: u64,
    pub egress_rate_bps: u64,
    pub monthly_bytes_received: u64,
    pub monthly_bytes_sent: u64,
    pub monthly_period: MonthlyPeriodPayload,
    pub per_protocol: ProtocolBandwidthPayload,
    pub per_site: HashMap<String, SiteBandwidthPayload>,
    pub per_upstream: HashMap<String, UpstreamBandwidthPayload>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct MonthlyPeriodPayload {
    pub period_start: DateTime<Utc>,
    pub days_elapsed: u32,
    pub days_remaining: u32,
    pub reset_mode: String,
    pub fixed_day: Option<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ProtocolBandwidthPayload {
    pub http: ProtocolBandwidth,
    pub https: ProtocolBandwidth,
    pub http3: ProtocolBandwidth,
    pub tcp: ProtocolBandwidth,
    pub udp: ProtocolBandwidth,
    pub tunnel: ProtocolBandwidth,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ProtocolBandwidth {
    pub bytes_received: u64,
    pub bytes_sent: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct SiteBandwidthPayload {
    pub bytes_received: u64,
    pub bytes_sent: u64,
    pub proxied_bytes_sent: u64,
    pub proxied_bytes_received: u64,
    pub mesh_bytes_sent: u64,
    pub mesh_bytes_received: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct UpstreamBandwidthPayload {
    pub bytes_sent: u64,
    pub bytes_received: u64,
}
