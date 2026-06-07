use bytes::Bytes;
use moka::sync::Cache;
use sha2::Digest;
use std::sync::LazyLock;
use std::time::Duration;

use synvoid_config::site::SiteImagePoisonConfig;

use crate::client::PoisonImageClient;

const IMAGE_POISON_CACHE_MAX_CAPACITY: u64 = 1000;
const IMAGE_POISON_CACHE_TTL_SECS: u64 = 3600;

static IMAGE_POISON_CACHE: LazyLock<Cache<String, Vec<u8>>> = LazyLock::new(|| {
    Cache::builder()
        .max_capacity(IMAGE_POISON_CACHE_MAX_CAPACITY)
        .time_to_live(Duration::from_secs(IMAGE_POISON_CACHE_TTL_SECS))
        .build()
});

pub fn invalidate_image_poison_cache_for_site(site_id: &str) {
    let prefix = format!("{}:", site_id);
    let keys_to_remove: Vec<String> = IMAGE_POISON_CACHE
        .iter()
        .filter(|(k, _)| k.starts_with(&prefix))
        .map(|(k, _)| k.to_string())
        .collect();
    for key in keys_to_remove {
        IMAGE_POISON_CACHE.invalidate(&key);
    }
}

pub async fn apply_image_poisoning(
    body: Bytes,
    site_id: String,
    last_modified: Option<String>,
    poison_config: Option<SiteImagePoisonConfig>,
) -> Bytes {
    if body.is_empty() {
        return body;
    }

    let original_hash = {
        let mut hasher = sha2::Sha256::new();
        hasher.update(&body);
        hex::encode(hasher.finalize())
    };

    let cache_key = {
        let poison_fingerprint = match poison_config.as_ref() {
            Some(cfg) => format!(
                ":{}:{}:{}",
                cfg.level.as_deref().unwrap_or("standard"),
                cfg.intensity.map(|f| f.to_bits()).unwrap_or(0),
                cfg.seed.unwrap_or(0)
            ),
            None => String::new(),
        };
        format!("{}:{}{}", site_id, original_hash, poison_fingerprint)
    };

    if let Some(cached) = IMAGE_POISON_CACHE.get(&cache_key) {
        tracing::debug!("Image poison cache hit for {}", cache_key);
        return Bytes::from(cached.clone());
    }

    let cpu_worker_socket = std::env::var("CPU_WORKER_SOCKET")
        .or_else(|_| std::env::var("STATIC_WORKER_SOCKET"))
        .unwrap_or_else(|_| "/var/run/synvoid-static-worker.sock".to_string());

    if cpu_worker_socket.is_empty() {
        return body;
    }

    let socket_path = std::path::PathBuf::from(&cpu_worker_socket);
    let client = PoisonImageClient::new(socket_path);

    match client
        .poison_image(
            &site_id,
            body.to_vec(),
            last_modified,
            poison_config.as_ref().and_then(|c| c.level.clone()),
            poison_config.as_ref().and_then(|c| c.intensity),
            poison_config.as_ref().and_then(|c| c.seed),
            poison_config.as_ref().and_then(|c| c.max_dimension),
            poison_config.as_ref().and_then(|c| c.jpeg_quality),
        )
        .await
    {
        Ok(poisoned) => {
            IMAGE_POISON_CACHE.insert(cache_key, poisoned.clone());
            Bytes::from(poisoned)
        }
        Err(e) => {
            tracing::debug!("Image poisoning failed: {}", e);
            body
        }
    }
}
