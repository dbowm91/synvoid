use moka::sync::Cache;
use parking_lot::RwLock;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Instant;

#[derive(Debug, Clone)]
pub struct IpBehavioralStats {
    pub last_request_at: Instant,
    pub avg_interval_ms: f32,
    pub timing_variance_ms: f32,
    pub request_count: u64,
}

impl IpBehavioralStats {
    pub fn new() -> Self {
        Self {
            last_request_at: Instant::now(),
            avg_interval_ms: 0.0,
            timing_variance_ms: 0.0,
            request_count: 1,
        }
    }

    pub fn record_request(&mut self) -> u32 {
        let now = Instant::now();
        let interval = now.duration_since(self.last_request_at).as_millis() as f32;
        self.last_request_at = now;
        self.request_count += 1;

        // EWMA alpha - weight for the new observation (e.g., 0.2 for ~5 samples window effect)
        let alpha = 0.2f32;

        if self.request_count == 2 {
            self.avg_interval_ms = interval;
            self.timing_variance_ms = 0.0;
        } else {
            let delta = interval - self.avg_interval_ms;
            self.avg_interval_ms += alpha * delta;
            // Online variance estimation (Welford-like with EWMA)
            self.timing_variance_ms =
                (1.0 - alpha) * (self.timing_variance_ms + alpha * delta * delta);
        }

        interval as u32
    }

    pub fn get_avg_interval(&self) -> u32 {
        self.avg_interval_ms as u32
    }

    pub fn get_timing_variance(&self) -> u32 {
        self.timing_variance_ms.sqrt() as u32
    }
}

pub struct BehavioralEngine {
    pub ip_stats_cache: Cache<IpAddr, Arc<RwLock<IpBehavioralStats>>>,
}

impl BehavioralEngine {
    pub fn new() -> Self {
        Self {
            ip_stats_cache: Cache::builder()
                .max_capacity(100_000)
                .time_to_idle(std::time::Duration::from_secs(3600))
                .build(),
        }
    }

    pub fn extract_features(
        &self,
        ip: IpAddr,
        path: &str,
        query_string: Option<&str>,
        headers: &http::HeaderMap,
        body: Option<&[u8]>,
    ) -> StandaloneRequestFeatures {
        let stats_lock = self
            .ip_stats_cache
            .get_with(ip, || Arc::new(RwLock::new(IpBehavioralStats::new())));

        let (inter_request_timing_ms, avg_interval_ms, timing_variance_ms) = {
            let mut stats = stats_lock.write();
            let interval = stats.record_request();
            (
                interval,
                stats.get_avg_interval(),
                stats.get_timing_variance(),
            )
        };

        let url = if let Some(qs) = query_string {
            format!("{}?{}", path, qs)
        } else {
            path.to_string()
        };

        let url_entropy = calculate_string_entropy(&url);

        let mut suspicious_header_count: u8 = 0;
        for (name, _) in headers {
            let name_lower = name.as_str().to_lowercase();
            if name_lower.contains("x-forwarded")
                || name_lower.contains("x-real-ip")
                || name_lower.contains("x-proxyuser-ip")
                || name_lower.contains("via")
            {
                suspicious_header_count += 1;
            }
        }

        let body_len = body.map(|b| b.len()).unwrap_or(0);
        let header_len: usize = headers
            .iter()
            .map(|(k, v)| k.as_str().len() + v.len())
            .sum();
        let body_to_header_ratio = if header_len > 0 {
            body_len as f32 / header_len as f32
        } else {
            0.0
        };

        StandaloneRequestFeatures {
            timing_variance_ms,
            inter_request_timing_ms,
            avg_interval_ms,
            suspicious_header_count,
            url_entropy,
            body_to_header_ratio,
            body_len: body_len as u32,
        }
    }
}

pub struct StandaloneRequestFeatures {
    pub timing_variance_ms: u32,
    pub inter_request_timing_ms: u32,
    pub avg_interval_ms: u32,
    pub suspicious_header_count: u8,
    pub url_entropy: f32,
    pub body_to_header_ratio: f32,
    pub body_len: u32,
}

pub fn calculate_string_entropy(s: &str) -> f32 {
    if s.is_empty() {
        return 0.0;
    }

    let mut freq = [0usize; 256];
    for byte in s.bytes() {
        freq[byte as usize] += 1;
    }

    let len = s.len() as f32;
    let entropy: f32 = freq
        .iter()
        .filter(|&&count| count > 0)
        .map(|&count| {
            let p = count as f32 / len;
            -p * p.log2()
        })
        .sum();

    entropy
}
