use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::LazyLock;
use synvoid_jail_protocol::{JailError, JailErrorCode, JailKind};

/// Snapshot of jail metrics. Counters are process-local atomics with no string
/// labels, so cardinality is structurally bounded: module names, digests,
/// paths, and rule text can never appear.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct JailMetricsSnapshot {
    pub starts: u64,
    pub restarts: u64,
    pub exits: u64,
    pub shutdowns: u64,
    pub invocations_wasm: u64,
    pub invocations_yara: u64,
    pub timeouts: u64,
    pub oversized_rejected: u64,
    pub protocol_violations: u64,
    pub restart_budget_exhausted: u64,
    pub failures_by_code: Vec<(String, u64)>,
}

static JAIL_STARTS: LazyLock<AtomicU64> = LazyLock::new(|| AtomicU64::new(0));
static JAIL_RESTARTS: LazyLock<AtomicU64> = LazyLock::new(|| AtomicU64::new(0));
static JAIL_EXITS: LazyLock<AtomicU64> = LazyLock::new(|| AtomicU64::new(0));
static JAIL_SHUTDOWNS: LazyLock<AtomicU64> = LazyLock::new(|| AtomicU64::new(0));
static JAIL_INVOCATIONS_WASM: LazyLock<AtomicU64> = LazyLock::new(|| AtomicU64::new(0));
static JAIL_INVOCATIONS_YARA: LazyLock<AtomicU64> = LazyLock::new(|| AtomicU64::new(0));
static JAIL_TIMEOUTS: LazyLock<AtomicU64> = LazyLock::new(|| AtomicU64::new(0));
static JAIL_OVERSIZED: LazyLock<AtomicU64> = LazyLock::new(|| AtomicU64::new(0));
static JAIL_PROTOCOL_VIOLATIONS: LazyLock<AtomicU64> = LazyLock::new(|| AtomicU64::new(0));
static JAIL_RESTART_BUDGET_EXHAUSTED: LazyLock<AtomicU64> = LazyLock::new(|| AtomicU64::new(0));
static JAIL_FAILURES_BY_CODE: LazyLock<Vec<AtomicU64>> = LazyLock::new(|| {
    (0..JailErrorCode::ALL.len())
        .map(|_| AtomicU64::new(0))
        .collect()
});

fn fetch(counter: &AtomicU64) -> u64 {
    counter.load(Ordering::Relaxed)
}

fn incr(counter: &AtomicU64) {
    counter.fetch_add(1, Ordering::Relaxed);
}

/// Record a jail process start.
pub fn record_jail_start() {
    incr(&JAIL_STARTS);
}

/// Record a jail restart (quarantine + respawn).
pub fn record_jail_restart() {
    incr(&JAIL_RESTARTS);
}

/// Record a jail child exit observation.
pub fn record_jail_exit() {
    incr(&JAIL_EXITS);
}

/// Record an orderly jail shutdown.
pub fn record_jail_shutdown() {
    incr(&JAIL_SHUTDOWNS);
}

/// Record one jail invocation of the given kind.
pub fn record_jail_invocation(kind: JailKind) {
    match kind {
        JailKind::Wasm => incr(&JAIL_INVOCATIONS_WASM),
        JailKind::Yara => incr(&JAIL_INVOCATIONS_YARA),
    }
}

/// Record one jail failure under its bounded error category.
pub fn record_jail_failure(err: &JailError) {
    let code = err.code();
    if let Some(slot) = JAIL_FAILURES_BY_CODE.get(code.index()) {
        slot.fetch_add(1, Ordering::Relaxed);
    }
    match code {
        JailErrorCode::Timeout => incr(&JAIL_TIMEOUTS),
        JailErrorCode::Oversized => incr(&JAIL_OVERSIZED),
        JailErrorCode::ProtocolViolation | JailErrorCode::FramingError => {
            incr(&JAIL_PROTOCOL_VIOLATIONS);
        }
        JailErrorCode::RestartBudgetExhausted => incr(&JAIL_RESTART_BUDGET_EXHAUSTED),
        _ => {}
    }
}

/// Capture a snapshot of all jail counters.
pub fn jail_metrics_snapshot() -> JailMetricsSnapshot {
    JailMetricsSnapshot {
        starts: fetch(&JAIL_STARTS),
        restarts: fetch(&JAIL_RESTARTS),
        exits: fetch(&JAIL_EXITS),
        shutdowns: fetch(&JAIL_SHUTDOWNS),
        invocations_wasm: fetch(&JAIL_INVOCATIONS_WASM),
        invocations_yara: fetch(&JAIL_INVOCATIONS_YARA),
        timeouts: fetch(&JAIL_TIMEOUTS),
        oversized_rejected: fetch(&JAIL_OVERSIZED),
        protocol_violations: fetch(&JAIL_PROTOCOL_VIOLATIONS),
        restart_budget_exhausted: fetch(&JAIL_RESTART_BUDGET_EXHAUSTED),
        failures_by_code: JailErrorCode::ALL
            .iter()
            .map(|code| {
                (
                    code.as_str().to_string(),
                    JAIL_FAILURES_BY_CODE
                        .get(code.index())
                        .map(fetch)
                        .unwrap_or(0),
                )
            })
            .collect(),
    }
}
