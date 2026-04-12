use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;

use tokio::sync::Mutex;

#[derive(Debug, Clone, Default)]
pub struct VpnStats {
    pub bytes_sent: u64,
    pub bytes_received: u64,
    pub packets_sent: u64,
    pub packets_received: u64,
    pub connected_at: Option<Instant>,
    pub last_message_at: Option<Instant>,
}

pub struct VpnStatsTracker {
    bytes_sent: AtomicU64,
    bytes_received: AtomicU64,
    packets_sent: AtomicU64,
    packets_received: AtomicU64,
    connected_at: Mutex<Option<Instant>>,
    last_message_at: Mutex<Option<Instant>>,
}

impl Default for VpnStatsTracker {
    fn default() -> Self {
        Self::new()
    }
}

impl VpnStatsTracker {
    pub fn new() -> Self {
        Self {
            bytes_sent: AtomicU64::new(0),
            bytes_received: AtomicU64::new(0),
            packets_sent: AtomicU64::new(0),
            packets_received: AtomicU64::new(0),
            connected_at: Mutex::new(None),
            last_message_at: Mutex::new(None),
        }
    }

    pub async fn connected(&self) {
        let mut guard = self.connected_at.lock().await;
        *guard = Some(Instant::now());
    }

    pub async fn disconnected(&self) {
        let mut guard = self.connected_at.lock().await;
        *guard = None;
    }

    pub async fn add_sent(&self, bytes: u64, packets: u64) {
        self.bytes_sent.fetch_add(bytes, Ordering::Relaxed);
        self.packets_sent.fetch_add(packets, Ordering::Relaxed);
        let mut guard = self.last_message_at.lock().await;
        *guard = Some(Instant::now());
    }

    pub async fn add_received(&self, bytes: u64, packets: u64) {
        self.bytes_received.fetch_add(bytes, Ordering::Relaxed);
        self.packets_received.fetch_add(packets, Ordering::Relaxed);
        let mut guard = self.last_message_at.lock().await;
        *guard = Some(Instant::now());
    }

    pub fn get_stats(&self) -> VpnStats {
        let connected_at = self.connected_at.try_lock().ok().and_then(|g| *g);
        let last_message_at = self.last_message_at.try_lock().ok().and_then(|g| *g);

        VpnStats {
            bytes_sent: self.bytes_sent.load(Ordering::Relaxed),
            bytes_received: self.bytes_received.load(Ordering::Relaxed),
            packets_sent: self.packets_sent.load(Ordering::Relaxed),
            packets_received: self.packets_received.load(Ordering::Relaxed),
            connected_at,
            last_message_at,
        }
    }

    pub async fn reset(&self) {
        self.bytes_sent.store(0, Ordering::Relaxed);
        self.bytes_received.store(0, Ordering::Relaxed);
        self.packets_sent.store(0, Ordering::Relaxed);
        self.packets_received.store(0, Ordering::Relaxed);
        let mut guard = self.connected_at.lock().await;
        *guard = None;
        let mut guard = self.last_message_at.lock().await;
        *guard = None;
    }
}