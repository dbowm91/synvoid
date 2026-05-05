use metrics::{counter, gauge};

pub fn icmp_packets_blocked(icmp_version: &str) {
    counter!("synvoid.icmp.packets_blocked_total", "icmp_version" => icmp_version.to_string())
        .increment(1);
}

pub fn icmp_packets_allowed(icmp_version: &str) {
    counter!("synvoid.icmp.packets_allowed_total", "icmp_version" => icmp_version.to_string())
        .increment(1);
}

pub fn icmp_rate_limited(icmp_version: &str) {
    counter!("synvoid.icmp.rate_limited_total", "icmp_version" => icmp_version.to_string())
        .increment(1);
}

pub fn icmp_filter_enabled(enabled: bool) {
    gauge!("synvoid.icmp.filter_enabled").set(if enabled { 1.0 } else { 0.0 });
}

pub fn icmp_filter_status(status: &str) {
    gauge!("synvoid.icmp.filter_status").set(match status {
        "enabled" => 1.0,
        "disabled" => 0.0,
        "error" => -1.0,
        _ => 0.0,
    });
}
