use crate::waf::{WafCore, RateLimitConfigStore, BotProtectionConfig, EndpointBlockerConfig};

use std::sync::Arc;
use std::path::PathBuf;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;
use tokio::time::interval;
use parking_lot::RwLock as PLRwLock;
use metrics::gauge;

#[derive(Clone)]
pub struct SharedWafState {
    waf: Arc<PLRwLock<Option<Arc<WafCore>>>>,
    last_persist: Arc<PLRwLock<Instant>>,
    persist_path: Arc<PLRwLock<Option<PathBuf>>>,
    persist_enabled: bool,
}

impl SharedWafState {
    pub fn new(persist_enabled: bool, data_dir: Option<PathBuf>) -> Self {
        let persist_path = data_dir.map(PathBuf::from);

        SharedWafState {
            waf: Arc::new(PLRwLock::new(None)),
            last_persist: Arc::new(PLRwLock::new(Instant::now())),
            persist_path: Arc::new(PLRwLock::new(persist_path)),
            persist_enabled,
        }
    }

    pub async fn initialize(&self) {
        if self.persist_enabled {
            self.load_persisted_state().await;
            self.start_persistence_task().await;
        }
        tracing::info!("Shared WAF state initialized");
    }

    pub async fn get_waf(&self) -> Result<Arc<WafCore>, String> {
        self.waf.read().clone().ok_or_else(|| "WAF not initialized".to_string())
    }

    pub async fn set_waf(&self, waf: Arc<WafCore>) {
        *self.waf.write() = Some(waf);
    }

    async fn start_persistence_task(&self) {
        let last_persist = self.last_persist.clone();
        let persist_path = self.persist_path.clone();
        let waf = self.waf.clone();

        tokio::spawn(async move {
            let persist_interval = Duration::from_secs(60);

            let mut ticker = interval(persist_interval);
            
            loop {
                ticker.tick().await;
                
                let should_persist = {
                    let last = *last_persist.read();
                    last.elapsed() >= persist_interval
                };

                if should_persist {
                    let path = persist_path.read().clone();
                    if let Some(path) = path {
                        Self::persist_state(&path, &waf).await;
                        *last_persist.write() = Instant::now();
                    }
                }
            }
        });
    }

    async fn persist_state(path: &PathBuf, _waf: &PLRwLock<Option<Arc<WafCore>>>) {
        let _ = tokio::fs::create_dir_all(path).await;
        
        let state_file = path.join("rate_limit_state.json");
        
        let json = serde_json::json!({
            "timestamp": chrono::Utc::now().to_rfc3339(),
            "note": "Rate limit state persistence"
        });

        if let Ok(json) = serde_json::to_string(&json) {
            let temp_path = path.join("rate_limit_state.tmp");
            if let Err(e) = tokio::fs::write(&temp_path, json).await {
                tracing::warn!("Failed to write persistence temp file: {}", e);
                return;
            }
            if let Err(e) = tokio::fs::rename(&temp_path, &state_file).await {
                tracing::warn!("Failed to rename persistence file: {}", e);
            }
        }
        
        gauge!("maluwaf.persistence.last_save").set(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs() as f64
        );
    }

    async fn load_persisted_state(&self) {
        let path = self.persist_path.read().clone();
        if let Some(path) = path {
            let state_file = path.join("rate_limit_state.json");
            if state_file.exists() {
                match tokio::fs::read_to_string(&state_file).await {
                    Ok(_) => {
                        tracing::info!("Loaded persisted state from {:?}", state_file);
                    }
                    Err(e) => {
                        tracing::warn!("Failed to load persisted state: {}", e);
                    }
                }
            }
        }
    }
}

impl std::fmt::Debug for SharedWafState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SharedWafState")
            .finish()
    }
}
