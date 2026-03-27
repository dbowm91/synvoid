//! Worker process supervisor and auto-scaler.
//!
//! Manages a pool of worker processes, monitoring their health and
//! automatically scaling up or down based on configurable load thresholds.
//! Re-exports [`Supervisor`], [`Worker`], [`AutoScaler`], and related types.

pub mod autoscaler;
pub mod supervisor;
pub mod worker;

pub use crate::config::{SupervisorConfig, SupervisorConfigBuilder};
pub use autoscaler::{AutoScaler, ScaleDecision};
pub use supervisor::{Supervisor, SupervisorEvent};
pub use worker::{Worker, WorkerId, WorkerMetrics, WorkerStatus};
