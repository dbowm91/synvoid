//! Phase 04: one worker by default; `workers > 1` is an explicit opt-in.
//!
//! These tests pin the process-model contract:
//!
//! - omitting `[defaults.worker_pool]` must start exactly one
//!   `UnifiedServerWorker`;
//! - a second worker requires `allow_multi_worker = true`;
//! - the admin panel's worker-local state makes the opt-in mandatory when
//!   `[admin].enabled = true`.

use synvoid_config::{DefaultsConfig, MainConfig, WorkerPoolDefaults};

#[test]
fn default_worker_count_is_one() {
    assert_eq!(WorkerPoolDefaults::default().workers, 1);
    assert!(!WorkerPoolDefaults::default().allow_multi_worker);

    let serde_defaults: WorkerPoolDefaults = toml::from_str("").expect("empty table parses");
    assert_eq!(serde_defaults.workers, 1);
    assert!(!serde_defaults.allow_multi_worker);
}

#[test]
fn omitted_worker_pool_starts_one_worker() {
    let cfg = MainConfig::default();
    assert_eq!(cfg.defaults.worker_pool.workers, 1);
    assert!(!cfg.defaults.worker_pool.allow_multi_worker);
}

#[test]
fn zero_workers_is_rejected() {
    let defaults = DefaultsConfig {
        worker_pool: WorkerPoolDefaults {
            workers: 0,
            ..WorkerPoolDefaults::default()
        },
        ..DefaultsConfig::default()
    };

    let err = defaults.validate().expect_err("workers = 0 must fail");
    assert_eq!(err.field, "defaults.worker_pool.workers");
}

#[test]
fn multi_worker_without_opt_in_is_rejected() {
    let defaults = DefaultsConfig {
        worker_pool: WorkerPoolDefaults {
            workers: 2,
            allow_multi_worker: false,
            ..WorkerPoolDefaults::default()
        },
        ..DefaultsConfig::default()
    };

    let err = defaults
        .validate()
        .expect_err("workers > 1 without opt-in must fail closed");
    assert_eq!(err.field, "defaults.worker_pool.allow_multi_worker");
    assert!(
        err.message.contains("allow_multi_worker = true"),
        "error must name the opt-in, got: {}",
        err.message
    );
}

#[test]
fn multi_worker_with_opt_in_is_accepted() {
    let defaults = DefaultsConfig {
        worker_pool: WorkerPoolDefaults {
            workers: 2,
            allow_multi_worker: true,
            ..WorkerPoolDefaults::default()
        },
        ..DefaultsConfig::default()
    };

    defaults.validate().expect("explicit opt-in is valid");
}

#[test]
fn admin_enabled_multi_worker_without_opt_in_is_rejected() {
    let mut cfg = MainConfig::default();
    cfg.admin.enabled = true;
    cfg.defaults.worker_pool.workers = 2;
    cfg.defaults.worker_pool.allow_multi_worker = false;

    let err = cfg
        .validate()
        .expect_err("admin + workers > 1 without opt-in must fail closed");
    assert_eq!(err.field, "defaults.worker_pool.allow_multi_worker");
    assert!(
        err.message.contains("sessions") && err.message.contains("per worker"),
        "admin-specific limitation must be explicit, got: {}",
        err.message
    );
}

#[test]
fn admin_enabled_multi_worker_with_opt_in_is_accepted() {
    let mut cfg = MainConfig::default();
    cfg.admin.enabled = true;
    cfg.defaults.worker_pool.workers = 2;
    cfg.defaults.worker_pool.allow_multi_worker = true;

    cfg.validate().expect("explicit opt-in is valid");
}
