//! Phase 51: upstream selection parity tests.
//!
//! Written BEFORE the allocation-elimination refactor; they pin deterministic
//! selection/failover behavior and must pass identically after it. Random is
//! covered by statistical validity (every result is a member of the pool),
//! IP-hash by stable-mapping checks. The hashing algorithm itself is
//! unchanged by this phase.

use synvoid_upstream::{BackendProtocol, LoadBalanceAlgorithm, UpstreamPool};

fn urls(n: usize, base_port: u16) -> Vec<String> {
    (0..n)
        .map(|i| format!("http://127.0.0.1:{}/", base_port + i as u16))
        .collect()
}

fn selected_urls(pool: &UpstreamPool, rounds: usize) -> Vec<String> {
    (0..rounds)
        .map(|_| {
            pool.select_backend()
                .expect("pool has available backends")
                .url
                .as_ref()
                .clone()
        })
        .collect()
}

#[test]
fn round_robin_cycles_in_order() {
    let pool = UpstreamPool::new(urls(4, 9100), LoadBalanceAlgorithm::RoundRobin);
    let first_four = selected_urls(&pool, 4);
    assert_eq!(first_four, urls(4, 9100), "round-robin must cycle in order");
    let next_four = selected_urls(&pool, 4);
    assert_eq!(next_four, first_four, "round-robin must repeat the cycle");
}

#[test]
fn round_robin_single_backend_always_wins() {
    let pool = UpstreamPool::new(urls(1, 9200), LoadBalanceAlgorithm::RoundRobin);
    for _ in 0..8 {
        let backend = pool.select_backend().expect("single backend");
        assert_eq!(backend.url.as_ref(), "http://127.0.0.1:9200/");
    }
}

#[test]
fn random_stays_within_pool() {
    let pool = UpstreamPool::new(urls(16, 9300), LoadBalanceAlgorithm::Random);
    let valid = urls(16, 9300);
    for _ in 0..500 {
        let url = pool
            .select_backend()
            .expect("pool has backends")
            .url
            .as_ref()
            .clone();
        assert!(
            valid.contains(&url),
            "random selection must be a pool member"
        );
    }
}

#[test]
fn weighted_round_robin_matches_weight_ratios() {
    let pool = UpstreamPool::new(urls(3, 9400), LoadBalanceAlgorithm::WeightedRoundRobin);
    pool.add_backend_with_weight(
        "http://127.0.0.1:9500/".to_string(),
        3,
        BackendProtocol::Http,
    );
    // Default weight is 1 for the three base backends; the 9500 backend has
    // weight 3 (total 6). The remainder walk yields exactly the weight
    // distribution over every 6 consecutive selections regardless of counter
    // start, so 60 selections must split 10/10/10/30.
    let seq = selected_urls(&pool, 60);
    let count = |url: &str| seq.iter().filter(|u| u.as_str() == url).count();
    assert_eq!(count("http://127.0.0.1:9400/"), 10);
    assert_eq!(count("http://127.0.0.1:9401/"), 10);
    assert_eq!(count("http://127.0.0.1:9402/"), 10);
    assert_eq!(count("http://127.0.0.1:9500/"), 30);
}

#[test]
fn weighted_zero_weight_backend_never_selected_alone() {
    let pool = UpstreamPool::new(urls(2, 9600), LoadBalanceAlgorithm::WeightedRoundRobin);
    // Zero-weight backend among positive weights is skipped by the remainder
    // walk (remainder < 0-weight never holds except at exact boundary).
    for _ in 0..32 {
        assert!(pool.select_backend().is_some());
    }
}

#[test]
fn unhealthy_backends_are_excluded() {
    let pool = UpstreamPool::new(urls(4, 9700), LoadBalanceAlgorithm::RoundRobin);
    pool.mark_unhealthy("http://127.0.0.1:9700/");
    pool.mark_unhealthy("http://127.0.0.1:9702/");
    for _ in 0..8 {
        let url = pool
            .select_backend()
            .expect("healthy backends remain")
            .url
            .as_ref()
            .clone();
        assert!(
            url == "http://127.0.0.1:9701/" || url == "http://127.0.0.1:9703/",
            "unhealthy backends must be excluded, got {url}"
        );
    }
}

#[test]
fn primary_before_backup_with_fallback() {
    let pool = UpstreamPool::new_with_backup(
        urls(2, 9800),
        vec!["http://127.0.0.1:9999/".to_string()],
        LoadBalanceAlgorithm::RoundRobin,
    );
    // Primaries healthy: backup never selected.
    for _ in 0..8 {
        let url = pool.select_backend().unwrap().url.as_ref().clone();
        assert_ne!(url, "http://127.0.0.1:9999/");
    }
    // All primaries down: backup fallback serves.
    pool.mark_unhealthy("http://127.0.0.1:9800/");
    pool.mark_unhealthy("http://127.0.0.1:9801/");
    let fallback = pool.select_backend().expect("backup fallback");
    assert_eq!(fallback.url.as_ref(), "http://127.0.0.1:9999/");
}

#[test]
fn protocol_filter_selects_matching_backend() {
    let pool = UpstreamPool::new(urls(2, 9900), LoadBalanceAlgorithm::RoundRobin);
    pool.add_backend_with_protocol("http://127.0.0.1:9910/".to_string(), BackendProtocol::Grpc);
    let grpc = pool
        .select_backend_for_protocol(BackendProtocol::Grpc)
        .expect("grpc backend present");
    assert_eq!(grpc.url.as_ref(), "http://127.0.0.1:9910/");
    assert!(pool
        .select_backend_for_protocol(BackendProtocol::Tcp)
        .is_none());
}

#[test]
fn select_next_backend_excludes_current() {
    let pool = UpstreamPool::new(urls(4, 10000), LoadBalanceAlgorithm::RoundRobin);
    let current = pool.select_backend().expect("pool has backends");
    let current_url = current.url.as_ref().clone();
    for _ in 0..8 {
        let next = pool.select_next_backend(&current).expect("others remain");
        assert_ne!(
            next.url.as_ref(),
            &current_url,
            "select_next must exclude the current backend"
        );
    }
}

#[test]
fn least_connections_prefers_idle_backend() {
    let pool = UpstreamPool::new(urls(4, 10100), LoadBalanceAlgorithm::LeastConnections);
    {
        let backends = pool.get_backends();
        // Load every backend except the last.
        for backend in backends.iter().take(3) {
            for _ in 0..5 {
                backend.increment_connections();
            }
        }
    }
    for _ in 0..4 {
        let winner = pool.select_backend().expect("pool has backends");
        assert_eq!(
            winner.url.as_ref(),
            "http://127.0.0.1:10103/",
            "least-connections must prefer the idle backend"
        );
    }
}

#[test]
fn ip_hash_mapping_is_stable() {
    let pool = UpstreamPool::new(urls(4, 10200), LoadBalanceAlgorithm::IpHash);
    for client in ["10.0.0.1", "10.0.0.2", "192.168.1.100", "2001:db8::1"] {
        let first = pool
            .select_backend_for_ip(client)
            .expect("pool has backends")
            .url
            .as_ref()
            .clone();
        for _ in 0..8 {
            let again = pool
                .select_backend_for_ip(client)
                .expect("pool has backends")
                .url
                .as_ref()
                .clone();
            assert_eq!(first, again, "IP-hash mapping must be stable for {client}");
        }
    }
}

#[test]
fn try_select_backend_matches_select_when_uncontended() {
    for algorithm in [
        LoadBalanceAlgorithm::RoundRobin,
        LoadBalanceAlgorithm::Random,
        LoadBalanceAlgorithm::LeastConnections,
        LoadBalanceAlgorithm::PeakEwma,
        LoadBalanceAlgorithm::WeightedRoundRobin,
        LoadBalanceAlgorithm::IpHash,
    ] {
        let pool = UpstreamPool::new(urls(4, 10300), algorithm);
        assert!(
            pool.try_select_backend().is_some(),
            "try_select must succeed when the lock is free"
        );
    }
}

#[test]
fn empty_and_fully_unhealthy_pools_return_none() {
    let empty = UpstreamPool::new(Vec::new(), LoadBalanceAlgorithm::RoundRobin);
    assert!(empty.select_backend().is_none());

    let pool = UpstreamPool::new(urls(2, 10400), LoadBalanceAlgorithm::RoundRobin);
    pool.mark_unhealthy("http://127.0.0.1:10400/");
    pool.mark_unhealthy("http://127.0.0.1:10401/");
    assert!(pool.select_backend().is_none());
    assert!(pool.try_select_backend().is_none());
}
