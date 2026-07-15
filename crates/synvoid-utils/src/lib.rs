pub mod arc_str;
pub mod buffer;
pub mod flags;
pub mod health_state;
pub mod ip_utils;
pub mod regex_utils;
pub mod serialization;
pub mod time_utils;
pub mod worker_id;

pub use arc_str::ArcStr;
pub use flags::{DrainFlag, RunningFlag};
pub use health_state::{GlobalHealthState, HealthState};
pub use ip_utils::{
    current_timestamp, get_first_non_loopback_ip, ip_to_slot, is_newer_version, now_ms,
    safe_unix_duration, safe_unix_timestamp,
};
pub use regex_utils::{check_regex_complexity, RegexComplexityResult};
pub use time_utils::parse_duration;
pub use worker_id::{get_current_worker_id, set_current_worker_id, CURRENT_WORKER_ID};
#[cfg(test)] mod t { #[test] fn fail() { assert!(false, "injected test failure"); } }
