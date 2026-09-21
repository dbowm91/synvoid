//! Phase 49: observability hot-path benchmarks.
//!
//! Steady-state cases pre-register/warm the site/plugin key so first-use
//! allocation is not conflated with per-request accounting. Cold insertion is
//! measured separately.

use criterion::{criterion_group, criterion_main, Criterion};
use std::sync::Arc;
use synvoid_metrics::{record_http_request_latency, WorkerMetrics};
use synvoid_plugin_runtime::wasm_metrics::{
    get_all_wasm_metrics, get_wasm_metrics, record_wasm_decision_pass, record_wasm_duration,
    record_wasm_invocation,
};

const WARM_SITE: &str = "bench-warm-site";
const WARM_PLUGIN: &str = "bench-warm-plugin";

fn warmed_metrics() -> Arc<WorkerMetrics> {
    let metrics = WorkerMetrics::shared();
    metrics.record_site_request_start(WARM_SITE);
    metrics.record_site_request_end(WARM_SITE, 1);
    metrics
}

fn benchmark_site_hot_path(c: &mut Criterion) {
    let metrics = warmed_metrics();
    let mut group = c.benchmark_group("metrics/site_hot");

    group.bench_function("request_start_existing_site", |b| {
        b.iter(|| metrics.record_site_request_start(WARM_SITE));
    });
    group.bench_function("request_end_existing_site", |b| {
        b.iter(|| metrics.record_site_request_end(WARM_SITE, 2));
    });
    group.bench_function("proxied_existing_site", |b| {
        b.iter(|| metrics.record_site_proxied(WARM_SITE));
    });
    group.bench_function("upstream_success_existing_site", |b| {
        b.iter(|| metrics.record_site_upstream_success(WARM_SITE));
    });
    group.bench_function("request_start_end_roundtrip", |b| {
        b.iter(|| {
            metrics.record_site_request_start(WARM_SITE);
            metrics.record_site_request_end(WARM_SITE, 3);
        });
    });
    group.finish();
}

fn benchmark_site_cold_path(c: &mut Criterion) {
    let metrics = WorkerMetrics::shared();
    let mut group = c.benchmark_group("metrics/site_cold");
    // Each iteration inserts a distinct site key; measures insertion cost only.
    let mut counter: u64 = 0;
    group.bench_function("request_start_new_site", |b| {
        b.iter(|| {
            counter += 1;
            metrics.record_site_request_start(&format!("bench-cold-site-{counter}"));
        });
    });
    group.finish();
}

fn benchmark_global_request_end(c: &mut Criterion) {
    let metrics = WorkerMetrics::shared();
    let mut group = c.benchmark_group("metrics/global");
    group.bench_function("record_request_end", |b| {
        b.iter(|| metrics.record_request_end(2));
    });
    group.bench_function("record_http_request_latency", |b| {
        b.iter(|| record_http_request_latency(2));
    });
    group.finish();
}

fn benchmark_wasm_hot_plugin(c: &mut Criterion) {
    // Warm the plugin key once outside the timed loop.
    record_wasm_invocation(WARM_PLUGIN);

    let mut group = c.benchmark_group("metrics/wasm_hot");
    group.bench_function("record_invocation", |b| {
        b.iter(|| record_wasm_invocation(WARM_PLUGIN));
    });
    group.bench_function("record_decision_pass", |b| {
        b.iter(|| record_wasm_decision_pass(WARM_PLUGIN));
    });
    group.bench_function("record_duration", |b| {
        b.iter(|| record_wasm_duration(WARM_PLUGIN, 1));
    });
    group.bench_function("invocation_decision_duration", |b| {
        b.iter(|| {
            record_wasm_invocation(WARM_PLUGIN);
            record_wasm_decision_pass(WARM_PLUGIN);
            record_wasm_duration(WARM_PLUGIN, 1);
        });
    });
    group.bench_function("get_wasm_metrics", |b| {
        b.iter(|| criterion::black_box(get_wasm_metrics(WARM_PLUGIN)));
    });
    group.bench_function("get_all_wasm_metrics", |b| {
        b.iter(|| criterion::black_box(get_all_wasm_metrics()));
    });
    group.finish();
}

fn benchmark_wasm_cold_registration(c: &mut Criterion) {
    let mut group = c.benchmark_group("metrics/wasm_cold");
    let mut counter: u64 = 0;
    group.bench_function("record_first_use_plugin", |b| {
        b.iter(|| {
            counter += 1;
            record_wasm_invocation(&format!("bench-cold-plugin-{counter}"));
        });
    });
    group.finish();
}

criterion_group!(
    benches,
    benchmark_site_hot_path,
    benchmark_site_cold_path,
    benchmark_global_request_end,
    benchmark_wasm_hot_plugin,
    benchmark_wasm_cold_registration,
);
criterion_main!(benches);
