//! Compatibility re-exports for the SVJL v1 protocol and jail metrics.

pub use super::jail_metrics::{
    jail_metrics_snapshot, record_jail_exit, record_jail_failure, record_jail_invocation,
    record_jail_restart, record_jail_shutdown, record_jail_start, JailMetricsSnapshot,
};
pub use synvoid_jail_protocol::*;
