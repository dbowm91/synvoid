//! Worker process supervisor and auto-scaler.
//!
//! Manages a pool of worker processes, monitoring their health and
//! automatically scaling up or down based on configurable load thresholds.
//! Re-exports [`Supervisor`], [`Worker`], [`AutoScaler`], and related types.

pub mod supervisor;
pub mod worker;
pub mod autoscaler;

pub use supervisor::{Supervisor, SupervisorEvent};
pub use crate::config::{SupervisorConfig, SupervisorConfigBuilder};
pub use worker::{Worker, WorkerId, WorkerStatus, WorkerMetrics};
pub use autoscaler::{AutoScaler, ScaleDecision};
