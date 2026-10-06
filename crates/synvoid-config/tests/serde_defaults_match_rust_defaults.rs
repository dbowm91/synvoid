//! Serde field defaults and Rust `Default` impls must agree.
//!
//! # The defect this pins
//!
//! `DefaultsConfig` carries a **struct-level** `#[serde(default)]`. A missing or
//! empty `[defaults]` table is therefore resolved through
//! `impl Default for DefaultsConfig`, which calls `Default::default()` on each
//! field type. Serde's per-field `#[serde(default = "...")]` attributes are
//! **never consulted** on that path — they only apply when the table is present
//! but a field is absent.
//!
//! `IpRateLimitConfig` and `GlobalRateLimitConfig` used to `derive(Default)`,
//! so `DefaultsConfig::default()` produced all zeros. `per_second` resolved to
//! `0` instead of `10`, and the site limiter's
//! `ip_state.per_second.len() >= config.ip.per_second` check degenerated to
//! `len() >= 0` — true for every request, forever. A minimal hand-written
//! `main.toml` (exactly what a quickstart teaches) answered **HTTP 429 to
//! 100% of traffic**. See `architecture/quickstart_verification_findings.md` F-1.
//!
//! # The invariant
//!
//! For any config type whose fields are all defaulted, parsing an empty table
//! and calling `Default::default()` must produce the same value. If they
//! disagree, one of the two default paths is lying about the configuration.

use serde::{de::DeserializeOwned, Serialize};
use synvoid_config::MainConfig;

/// Assert that `T::default()` agrees with the serde defaults that apply when the
/// table is present but every *optional* field is absent.
///
/// `minimal_json` is the smallest document that still satisfies `T`'s required
/// fields — `"{}"` for a fully-defaultable type, or e.g. `{"block":{}}` for one
/// with a required sub-table. If that document stops parsing, a required field
/// changed and this list needs re-auditing.
///
/// Comparison is done on the serialized `serde_json::Value`, not on `T` itself:
/// the config types deliberately do not derive `PartialEq`, and the serialized
/// form is what an operator actually writes.
fn assert_parity<T>(type_name: &str, minimal_json: &str)
where
    T: Default + Serialize + DeserializeOwned,
{
    let from_rust_default = serde_json::to_value(T::default())
        .unwrap_or_else(|e| panic!("{type_name}: serializing ::default() failed: {e}"));

    let from_empty_table: T = serde_json::from_str(minimal_json).unwrap_or_else(|e| {
        panic!(
            "{type_name}: {minimal_json} must parse, but it failed ({e}). If this type \
                gained a required field, audit whether `DefaultsConfig::default()` still \
                reaches it correctly."
        )
    });

    let from_serde_defaults = serde_json::to_value(from_empty_table)
        .unwrap_or_else(|e| panic!("{type_name}: serializing the parsed value failed: {e}"));

    assert_eq!(
        from_rust_default, from_serde_defaults,
        "{type_name}: `Default::default()` disagrees with the per-field serde defaults. \
         A `#[serde(default)]` parent that builds this type via `::default()` will hand \
         out different values depending on whether the operator wrote the table out, \
         leaving it empty, or omitted it entirely."
    );
}

// ---------------------------------------------------------------------------
// The confirmed regression (F-1), pinned by value.
// ---------------------------------------------------------------------------

#[test]
fn omitted_defaults_ratelimit_does_not_rate_limit_every_request() {
    // The literal numbers from the field-level serde defaults. If someone edits
    // `default_ip_per_second`, this test must be updated in the same commit.
    let cfg = MainConfig::default();

    assert_eq!(
        cfg.defaults.ratelimit.ip.per_second, 10,
        "per_second must not resolve to 0: the limiter's `len() >= per_second` check \
         would then reject 100% of traffic."
    );
    assert_eq!(cfg.defaults.ratelimit.ip.per_minute, 60);
    assert_eq!(cfg.defaults.ratelimit.ip.per_5min, 200);
    assert_eq!(cfg.defaults.ratelimit.ip.per_10min, 350);
    assert_eq!(cfg.defaults.ratelimit.ip.per_hour, 500);
    assert_eq!(cfg.defaults.ratelimit.ip.per_day, 1000);
    assert_eq!(cfg.defaults.ratelimit.ip.burst, 20);

    assert_eq!(cfg.defaults.ratelimit.global.per_second, 500);
    assert_eq!(cfg.defaults.ratelimit.global.per_minute, 5000);
    assert_eq!(cfg.defaults.ratelimit.global.per_5min, 20000);
    assert_eq!(cfg.defaults.ratelimit.global.max_connections, 1000);

    assert_eq!(cfg.defaults.ratelimit.mode, "shared");
}

/// The concrete user-visible symptom: a `main.toml` with an empty `[defaults]`
/// table must not 429. Asserted at the config layer, which is where the bad
/// value was introduced.
#[test]
fn empty_defaults_table_matches_a_fully_defaulted_config() {
    let minimal = r#"
[server]
host = "127.0.0.1"
port = 8080

[fallback]
mode = "return_404"

[admin]
enabled = false
port = 8081
token = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

[logging]
level = "info"

[metrics]
enabled = false
port = 9090

[defaults]
"#;

    let parsed: MainConfig =
        toml::from_str(minimal).expect("minimal config with an empty [defaults] must parse");

    let full: MainConfig = MainConfig::default();

    assert_eq!(
        serde_json::to_value(&parsed.defaults.ratelimit.ip).unwrap(),
        serde_json::to_value(&full.defaults.ratelimit.ip).unwrap(),
        "an empty `[defaults]` table must resolve to the same IP rate limit as the \
         built-in defaults, not to a zeroed limiter."
    );
    assert_eq!(
        serde_json::to_value(&parsed.defaults.ratelimit.global).unwrap(),
        serde_json::to_value(&full.defaults.ratelimit.global).unwrap(),
        "an empty `[defaults]` table must resolve to the same global rate limit as the \
         built-in defaults."
    );
    assert!(parsed.defaults.ratelimit.ip.per_second > 0);
}

// ---------------------------------------------------------------------------
// The defect class: parity across the whole `[defaults]` subtree.
// ---------------------------------------------------------------------------

#[test]
fn defaults_subtree_parity() {
    use synvoid_config::defaults::ChallengeDefaults;
    use synvoid_config::{
        AuthDefaults, BlockedDefaults, BotDefaults, CssChallengeDefaults, EndpointRateLimitConfig,
        ErrorPagesDefaults, GlobalRateLimitConfig, HoneypotDefaults, HoneypotProbingDefaults,
        IpRateLimitConfig, PersistenceConfig, PowChallengeDefaults, RateLimitDefaults,
        SuspiciousWordsConfig, TarpitDefaults, TcpDefaults, ThemeDefaults, TrafficShapingDefaults,
        UdpDefaults, UploadDefaults, UpstreamErrorsConfig, WorkerPoolDefaults,
    };

    // Direct children of `DefaultsConfig`, plus the two types at the heart of F-1.
    assert_parity::<IpRateLimitConfig>("IpRateLimitConfig", "{}");
    assert_parity::<GlobalRateLimitConfig>("GlobalRateLimitConfig", "{}");
    assert_parity::<BlockedDefaults>("BlockedDefaults", "{}");
    assert_parity::<HoneypotDefaults>("HoneypotDefaults", "{}");
    assert_parity::<HoneypotProbingDefaults>("HoneypotProbingDefaults", "{}");
    assert_parity::<SuspiciousWordsConfig>("SuspiciousWordsConfig", "{}");
    assert_parity::<UpstreamErrorsConfig>("UpstreamErrorsConfig", "{}");
    assert_parity::<ErrorPagesDefaults>("ErrorPagesDefaults", "{}");
    assert_parity::<BotDefaults>("BotDefaults", "{}");
    assert_parity::<CssChallengeDefaults>("CssChallengeDefaults", r#"{"block":{}}"#);
    assert_parity::<PowChallengeDefaults>("PowChallengeDefaults", r#"{"block":{}}"#);
    assert_parity::<ChallengeDefaults>("ChallengeDefaults", "{}");
    assert_parity::<AuthDefaults>("AuthDefaults", "{}");
    assert_parity::<WorkerPoolDefaults>("WorkerPoolDefaults", "{}");
    assert_parity::<PersistenceConfig>("PersistenceConfig", "{}");
    assert_parity::<TrafficShapingDefaults>("TrafficShapingDefaults", "{}");
    assert_parity::<UdpDefaults>("UdpDefaults", "{}");
    assert_parity::<UploadDefaults>("UploadDefaults", "{}");
    assert_parity::<ThemeDefaults>("ThemeDefaults", "{}");

    // Types whose Rust `Default` supplies real values that a bare
    // `#[serde(default)]` used to erase.
    assert_parity::<synvoid_config::defaults::AsnScrapingConfig>("AsnScrapingConfig", "{}");
    // `TcpDefaults` is the one deliberate exception to a blanket `assert_parity`:
    // `default_tcp_worker_pool_size()` scales with `available_parallelism()` while
    // `TcpDefaults::default()` pins 4. A host-dependent `Default` would make every
    // test that builds a `MainConfig::default()` machine-dependent, so the
    // divergence is kept and the actually-broken part is asserted directly.
    let tcp_from_table: TcpDefaults =
        serde_json::from_str("{}").expect("an empty [defaults.tcp] table must parse");
    assert_eq!(
        serde_json::to_value(&tcp_from_table.protocols).unwrap(),
        serde_json::to_value(&TcpDefaults::default().protocols).unwrap(),
        "an empty `[defaults.tcp]` table must still install the default protocol map. \
         A bare `#[serde(default)]` once parsed it as empty, so an explicit table \
         silently installed no TCP listeners."
    );
    assert!(
        !tcp_from_table.protocols.is_empty(),
        "the default TCP protocol map must never be empty"
    );
    // Present-table path scales with the host; omitted-table path pins 4.
    assert_eq!(
        tcp_from_table.worker_pool_size,
        std::thread::available_parallelism()
            .map(|p| p.get())
            .unwrap_or(4),
        "`[defaults.tcp]` scales the worker pool with available_parallelism()"
    );
    assert_eq!(
        TcpDefaults::default().worker_pool_size,
        4,
        "`TcpDefaults::default()` must stay host-independent"
    );
    assert_parity::<TarpitDefaults>("TarpitDefaults", "{}");

    // `EndpointRateLimitConfig` has a required `path_pattern`, so it is not
    // reachable from an empty table; check it explicitly with a minimal body.
    let endpoint: EndpointRateLimitConfig =
        serde_json::from_str(r#"{"path_pattern": "/api/*"}"#).expect("minimal endpoint config");
    assert_eq!(endpoint.per_minute, 60);
    assert_eq!(endpoint.per_hour, 500);
    assert_eq!(endpoint.burst, 10);

    // `RateLimitDefaults` has required `ip` / `global` sub-tables, so it cannot be
    // checked with `{}`. It is still the exact type `DefaultsConfig::default()`
    // hands out, and an operator writing `[defaults.ratelimit]` with empty
    // `[defaults.ratelimit.ip]` / `[defaults.ratelimit.global]` sub-tables must get
    // the same thing — that is the `mode = "shared"`-only quickstart shape.
    let empty_subtables: RateLimitDefaults = serde_json::from_str(r#"{"ip":{},"global":{}}"#)
        .expect("a `[defaults.ratelimit]` with empty ip/global sub-tables must parse");
    assert_eq!(
        serde_json::to_value(&empty_subtables).unwrap(),
        serde_json::to_value(RateLimitDefaults::default()).unwrap(),
        "`[defaults.ratelimit]` with empty `ip`/`global` sub-tables must resolve to the \
         same values as `RateLimitDefaults::default()`."
    );
    assert_eq!(empty_subtables.ip.per_second, 10);
    assert_eq!(empty_subtables.global.max_connections, 1000);
}
