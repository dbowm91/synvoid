use metrics::{counter, gauge};
use std::sync::LazyLock;
use std::sync::atomic::{AtomicU64, Ordering};

static ADMIN_AUTH_FAILURES: LazyLock<AtomicU64> =
    LazyLock::new(|| AtomicU64::new(0));

static ADMIN_AUTH_LOCKOUTS: LazyLock<AtomicU64> =
    LazyLock::new(|| AtomicU64::new(0));

static ADMIN_CSRF_FAILURES: LazyLock<AtomicU64> =
    LazyLock::new(|| AtomicU64::new(0));

static ADMIN_AUDIT_WRITE_FAILURES: LazyLock<AtomicU64> =
    LazyLock::new(|| AtomicU64::new(0));

static ADMIN_WS_CLIENTS: LazyLock<AtomicU64> =
    LazyLock::new(|| AtomicU64::new(0));

static ADMIN_WS_LAGGED: LazyLock<AtomicU64> =
    LazyLock::new(|| AtomicU64::new(0));

static ADMIN_WS_DROPPED: LazyLock<AtomicU64> =
    LazyLock::new(|| AtomicU64::new(0));

static ADMIN_ALERT_DELIVERY_SUCCESS: LazyLock<AtomicU64> =
    LazyLock::new(|| AtomicU64::new(0));

static ADMIN_ALERT_DELIVERY_FAILURE: LazyLock<AtomicU64> =
    LazyLock::new(|| AtomicU64::new(0));

pub fn record_auth_failure() {
    ADMIN_AUTH_FAILURES.fetch_add(1, Ordering::Relaxed);
    counter!("maluwaf.admin.auth.failures").increment(1);
}

pub fn record_auth_lockout() {
    ADMIN_AUTH_LOCKOUTS.fetch_add(1, Ordering::Relaxed);
    counter!("maluwaf.admin.auth.lockouts").increment(1);
}

pub fn record_csrf_failure() {
    ADMIN_CSRF_FAILURES.fetch_add(1, Ordering::Relaxed);
    counter!("maluwaf.admin.csrf.failures").increment(1);
}

pub fn record_audit_write_failure() {
    ADMIN_AUDIT_WRITE_FAILURES.fetch_add(1, Ordering::Relaxed);
    counter!("maluwaf.admin.audit.write_failures").increment(1);
}

pub fn ws_client_connected() {
    ADMIN_WS_CLIENTS.fetch_add(1, Ordering::Relaxed);
    gauge!("maluwaf.admin.ws.clients").set(ADMIN_WS_CLIENTS.load(Ordering::Relaxed) as f64);
}

pub fn ws_client_disconnected() {
    ADMIN_WS_CLIENTS.fetch_sub(1, Ordering::Relaxed);
    gauge!("maluwaf.admin.ws.clients").set(ADMIN_WS_CLIENTS.load(Ordering::Relaxed) as f64);
}

pub fn record_ws_lagged() {
    ADMIN_WS_LAGGED.fetch_add(1, Ordering::Relaxed);
    counter!("maluwaf.admin.ws.lagged").increment(1);
}

pub fn record_ws_dropped() {
    ADMIN_WS_DROPPED.fetch_add(1, Ordering::Relaxed);
    counter!("maluwaf.admin.ws.dropped").increment(1);
}

pub fn record_alert_delivery_success() {
    ADMIN_ALERT_DELIVERY_SUCCESS.fetch_add(1, Ordering::Relaxed);
    counter!("maluwaf.admin.alert.delivery.success").increment(1);
}

pub fn record_alert_delivery_failure() {
    ADMIN_ALERT_DELIVERY_FAILURE.fetch_add(1, Ordering::Relaxed);
    counter!("maluwaf.admin.alert.delivery.failure").increment(1);
}

pub fn record_rate_limited() {
    counter!("maluwaf.admin.rate_limited").increment(1);
}

pub fn get_audit_write_failures() -> u64 {
    ADMIN_AUDIT_WRITE_FAILURES.load(Ordering::Relaxed)
}