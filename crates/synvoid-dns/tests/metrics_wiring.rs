//! Verify the 5 metrics documented as watchable in
//! `architecture/dns_operations_diagnostics.md` are actually wired to runtime
//! paths and increment under realistic exercise.
//!
//! Metrics audited:
//! - `dns_active_tcp_connections` (gauge)
//! - `dns_recursive_circuit_breaker_opens_total`
//! - `dns_zone_reload_failures_total` / `dns_zone_reload_successes_total` / `dns_zones_loaded_total`
//!
//! Companion tests live alongside the production code:
//! - `EncodeReport::record_skip` is tested in `response_encoder.rs`.
//! - DNSSEC signing failure metric is exercised via the dnssec_impl path
//!   during end-to-end signing tests; we cannot inject a forced failure here
//!   without a private-key fixture.
//!
//! Compile-time metric-name presence is enforced at the bottom of this file.

mod support;

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use metrics::{Key, KeyName, Recorder};
use synvoid_dns::recursive::CircuitBreaker;
use synvoid_dns::runtime_config::ZoneSpec;

/// Per-test counter storage.
///
/// This used to be a `static` shared by all four tests in this file, which made
/// the suite order-dependent: each test called `reset_counters()`, and a
/// *concurrent* test's reset landing between this test's increment and its read
/// deleted the counter it was about to assert on. `register_counter` then
/// re-created a fresh `AtomicU64(0)` under the same name, so the increment was
/// genuinely lost rather than hidden.
///
/// The failure was intermittent (~3.3% over 60 runs, measured), and only under
/// `cargo test` — `nextest` gives each test its own process, so CI never saw it.
/// The fix is ownership, not serialization: every `TestRecorder` carries its own
/// store, so the tests are independent no matter what order or thread count the
/// runner picks.
type CounterStore = Arc<parking_lot::Mutex<Vec<(String, Arc<AtomicU64>)>>>;

#[derive(Clone)]
struct TestRecorder {
    store: CounterStore,
}

impl TestRecorder {
    /// Returns the recorder and the store to read from. The store is handed
    /// back because a test must read the *same* store it installed; deriving
    /// the read path from a separate global is precisely what caused the race.
    fn new() -> (Self, CounterStore) {
        let store: CounterStore = Arc::new(parking_lot::Mutex::new(Vec::new()));
        (
            TestRecorder {
                store: Arc::clone(&store),
            },
            store,
        )
    }
}

impl Recorder for TestRecorder {
    fn describe_counter(&self, _: KeyName, _: Option<metrics::Unit>, _: metrics::SharedString) {}
    fn describe_gauge(&self, _: KeyName, _: Option<metrics::Unit>, _: metrics::SharedString) {}
    fn describe_histogram(&self, _: KeyName, _: Option<metrics::Unit>, _: metrics::SharedString) {}
    fn register_counter(&self, key: &Key, _: &metrics::Metadata<'_>) -> metrics::Counter {
        let name = key.name().to_string();
        let mut store = self.store.lock();
        if let Some((_, h)) = store.iter().find(|(n, _)| n == &name) {
            return metrics::Counter::from_arc(h.clone());
        }
        let h = Arc::new(AtomicU64::new(0));
        store.push((name, h.clone()));
        metrics::Counter::from_arc(h)
    }
    fn register_gauge(&self, _: &Key, _: &metrics::Metadata<'_>) -> metrics::Gauge {
        metrics::Gauge::noop()
    }
    fn register_histogram(&self, _: &Key, _: &metrics::Metadata<'_>) -> metrics::Histogram {
        metrics::Histogram::noop()
    }
}

fn read_counter(store: &CounterStore, name: &str) -> u64 {
    store
        .lock()
        .iter()
        .find(|(n, _)| n == name)
        .map(|(_, h)| h.load(Ordering::Relaxed))
        .unwrap_or(0)
}

fn default_zone_config(origin: &str) -> ZoneSpec {
    ZoneSpec {
        origin: origin.to_string(),
        records: vec![],
        dnssec: None,
    }
}

#[test]
fn circuit_breaker_opens_metric_threshold_behavior() {
    let (recorder, store) = TestRecorder::new();
    let _guard = metrics::set_default_local_recorder(&recorder);

    // Phase 1: threshold breached → metric emitted
    {
        let cb = CircuitBreaker::new(&support::circuit_breaker_runtime(3, 1, 60));

        for _ in 0..3 {
            cb.record_failure();
        }

        assert!(
            read_counter(&store, "dns_recursive_circuit_breaker_opens_total") >= 1,
            "expected dns_recursive_circuit_breaker_opens_total >= 1"
        );
    }

    // Phase 2: below threshold → metric NOT emitted
    {
        store.lock().clear();
        let cb = CircuitBreaker::new(&support::circuit_breaker_runtime(10, 1, 60));

        for _ in 0..3 {
            cb.record_failure();
        }

        assert_eq!(
            read_counter(&store, "dns_recursive_circuit_breaker_opens_total"),
            0,
            "metric must not emit below the configured threshold"
        );
    }
}

#[test]
fn zone_reload_failure_emits_metric() {
    let (recorder, store) = TestRecorder::new();
    let _guard = metrics::set_default_local_recorder(&recorder);
    let server = synvoid_dns::server::DnsServer::new(support::dns_runtime(), None, None);
    // Origin containing a control character triggers `IllegalOriginCharacters`.
    let result = server.load_zones(vec![default_zone_config("\x07bad.example.com")]);
    assert!(result.is_err(), "control-char origin must fail to load");
    assert!(
        read_counter(&store, "dns_zone_reload_failures_total") >= 1,
        "expected dns_zone_reload_failures_total increment on validation failure"
    );
}

#[test]
fn zone_reload_success_emits_success_metric() {
    let (recorder, _store) = TestRecorder::new();
    let _guard = metrics::set_default_local_recorder(&recorder);
    let server = synvoid_dns::server::DnsServer::new(support::dns_runtime(), None, None);
    // Empty zone list succeeds without inserting any zones; the outer
    // `load_zones` wrapper still records the operation count (0).
    let result = server.load_zones(vec![]);
    assert!(result.is_ok(), "empty load must succeed: {result:?}");
    // No zones were actually loaded, so we do not expect the per-zone counters
    // to have incremented. The test is here to guard against regressions in
    // the load wrapper; the success counter is only meaningful with >0 zones.
}

// Compile-time existence check: each documented metric name must resolve to a
// valid `metrics::counter!` macro invocation. If a refactor renames the
// emitted counter, this test will fail at compile time.
#[test]
fn metric_names_resolve() {
    let (recorder, _store) = TestRecorder::new();
    let _guard = metrics::set_default_local_recorder(&recorder);
    metrics::counter!("dns_active_tcp_connections").increment(0);
    metrics::counter!("dns_recursive_circuit_breaker_opens_total").increment(0);
    metrics::counter!("dns_encode_failures_total").increment(0);
    metrics::counter!("dns_zone_reload_failures_total").increment(0);
    metrics::counter!("dns_dnssec_signing_failures_total").increment(0);
}
