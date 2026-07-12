use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Instant;

struct MockPeer {
    id: String,
    #[allow(dead_code)]
    latency_us: u64,
}

impl MockPeer {
    fn new(id: &str, latency_us: u64) -> Self {
        Self {
            id: id.to_string(),
            latency_us,
        }
    }
}

struct BroadcastMetrics {
    total_sent: AtomicUsize,
    total_acked: AtomicUsize,
    total_failed: AtomicUsize,
}

impl BroadcastMetrics {
    fn new() -> Self {
        Self {
            total_sent: AtomicUsize::new(0),
            total_acked: AtomicUsize::new(0),
            total_failed: AtomicUsize::new(0),
        }
    }

    fn record_sent(&self) {
        self.total_sent.fetch_add(1, Ordering::Relaxed);
    }

    fn record_ack(&self) {
        self.total_acked.fetch_add(1, Ordering::Relaxed);
    }

    #[allow(dead_code)]
    fn record_failure(&self) {
        self.total_failed.fetch_add(1, Ordering::Relaxed);
    }

    fn ack_rate(&self) -> f64 {
        let sent = self.total_sent.load(Ordering::Relaxed);
        let acked = self.total_acked.load(Ordering::Relaxed);
        if sent > 0 {
            acked as f64 / sent as f64
        } else {
            1.0
        }
    }
}

fn broadcast_to_peers(peers: &[MockPeer], metrics: &BroadcastMetrics, fanout_factor: f64) {
    let target_count = (peers.len() as f64 * fanout_factor).ceil() as usize;
    for peer in peers.iter().take(target_count) {
        metrics.record_sent();
        std::hint::black_box(&peer.id);
    }
}

fn benchmark_broadcast_latency(c: &mut Criterion) {
    let mut group = c.benchmark_group("broadcast_latency");

    for peer_count in [5, 10, 25, 50, 100].iter() {
        let peers: Vec<MockPeer> = (0..*peer_count)
            .map(|i| MockPeer::new(&format!("peer-{}", i), 100))
            .collect();
        let metrics = BroadcastMetrics::new();

        group.bench_with_input(
            BenchmarkId::from_parameter(peer_count),
            peer_count,
            |b, &_peer_count| {
                b.iter(|| {
                    broadcast_to_peers(&peers, &metrics, 0.5);
                });
            },
        );
    }
    group.finish();
}

fn benchmark_fanout_factors(c: &mut Criterion) {
    let mut group = c.benchmark_group("fanout_factors");

    for fanout in [0.1, 0.25, 0.5, 0.75, 1.0].iter() {
        let peers: Vec<MockPeer> = (0..50)
            .map(|i| MockPeer::new(&format!("peer-{}", i), 50))
            .collect();
        let metrics = BroadcastMetrics::new();

        group.bench_with_input(BenchmarkId::from_parameter(fanout), fanout, |b, &fanout| {
            b.iter(|| {
                broadcast_to_peers(&peers, &metrics, fanout);
            });
        });
    }
    group.finish();
}

fn benchmark_broadcast_at_peer_counts(c: &mut Criterion) {
    let mut group = c.benchmark_group("broadcast_at_peer_counts");

    for (peer_count, fanout_factor) in [(10, 0.5), (25, 0.5), (50, 0.5), (100, 0.5)].iter() {
        let peers: Vec<MockPeer> = (0..*peer_count)
            .map(|i| MockPeer::new(&format!("peer-{}", i), 100))
            .collect();
        let metrics = BroadcastMetrics::new();

        group.bench_function(BenchmarkId::new("sync_broadcast", peer_count), |b| {
            b.iter(|| {
                let start = Instant::now();
                broadcast_to_peers(&peers, &metrics, *fanout_factor);
                let elapsed = start.elapsed();
                criterion::black_box(elapsed);
            });
        });
    }
    group.finish();
}

fn benchmark_ack_tracking(c: &mut Criterion) {
    let mut group = c.benchmark_group("broadcast_ack_tracking");

    group.bench_function("record_ack_single", |b| {
        let metrics = BroadcastMetrics::new();
        b.iter(|| {
            metrics.record_ack();
        });
    });

    group.bench_function("record_ack_batch_100", |b| {
        let metrics = BroadcastMetrics::new();
        b.iter(|| {
            for _ in 0..100 {
                metrics.record_ack();
            }
        });
    });

    group.bench_function("ack_rate_calculation", |b| {
        let metrics = BroadcastMetrics::new();
        metrics.total_sent.store(100, Ordering::Relaxed);
        metrics.total_acked.store(80, Ordering::Relaxed);
        metrics.total_failed.store(10, Ordering::Relaxed);
        b.iter(|| metrics.ack_rate());
    });
}

criterion_group!(
    benches,
    benchmark_broadcast_latency,
    benchmark_fanout_factors,
    benchmark_broadcast_at_peer_counts,
    benchmark_ack_tracking
);
criterion_main!(benches);
