use std::net::IpAddr;
use std::time::Instant;

#[cfg(test)]
mod benchmarks {
    use super::*;

    #[test]
    fn bench_rate_limiter_check() {
        use maluwaf::dns::server::DnsRateLimiter;

        let limiter = DnsRateLimiter::new(1000, 2000);
        let ip: IpAddr = "192.168.1.1".parse().unwrap();

        let start = Instant::now();
        for _ in 0..10_000 {
            let _ = limiter.check_ip(ip);
        }
        let elapsed = start.elapsed();
        println!(
            "Rate limiter check: {:.3}ns/op (10K ops)",
            elapsed.as_secs_f64() * 1_000_000_000.0 / 10_000.0
        );
    }

    #[test]
    fn bench_zone_serial_increment() {
        use maluwaf::dns::server::Zone;

        let start = Instant::now();
        for _ in 0..100_000 {
            let mut zone = Zone::new("example.com".to_string());
            zone.increment_serial();
        }
        let elapsed = start.elapsed();
        println!(
            "Zone serial increment: {:.3}ns/op (100K ops)",
            elapsed.as_secs_f64() * 1_000_000_000.0 / 100_000.0
        );
    }
}
