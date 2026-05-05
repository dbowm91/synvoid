#![cfg(feature = "dns")]

use criterion::{criterion_group, criterion_main, Criterion};
use std::net::IpAddr;

fn benchmark_rate_limiter(c: &mut Criterion) {
    use synvoid::dns::server::DnsRateLimiter;

    let limiter = DnsRateLimiter::new(1000, 2000);
    let ip: IpAddr = "192.168.1.1".parse().unwrap();

    c.bench_function("dns_rate_limiter_check", |b| {
        b.iter(|| limiter.check_ip(ip));
    });
}

fn benchmark_zone_serial(c: &mut Criterion) {
    use synvoid::dns::server::Zone;

    c.bench_function("zone_serial_increment", |b| {
        b.iter(|| {
            let mut zone = Zone::new("example.com".to_string());
            zone.increment_serial();
        });
    });
}

criterion_group!(benches, benchmark_rate_limiter, benchmark_zone_serial);
criterion_main!(benches);
