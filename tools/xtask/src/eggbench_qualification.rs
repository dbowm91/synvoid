//! Eggbench Security Qualification asset materializer (Phase: eggbench_security_qualification_asset_contract).
//!
//! SynVoid-owned, deterministic, machine-readable qualification asset
//! contract that Eggbench Security Qualification M002 consumes without
//! importing SynVoid Rust crates or reinterpreting SynVoid WAF semantics.
//!
//! Two subcommands:
//!
//! - `export` — materialize a complete qualification tree under
//!   `--output <dir>` for a given `--listen-port` / `--origin-port`. No
//!   network, no spawned processes (except optionally `--configtest`).
//!
//! - `check` — verify a previously materialized tree is internally
//!   coherent: deterministic corpus, expected schema, provenance
//!   digests, and `--configtest` against the configured profile.
//!
//! The export is deterministic for the same SynVoid source tree,
//! selected fixture set, listen/origin ports, and policy version.

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub const POLICY_ID: &str = "synvoid.eggbench-qualification.v1";
pub const POLICY_VERSION: &str = "v1";
pub const CORPUS_SCHEMA_VERSION: &str = "eggbench.security_qualification.corpus.v1";
pub const PROVENANCE_SCHEMA_VERSION: &str = "eggbench.security_qualification.provenance.v1";
pub const CONFIG_SCHEMA_VERSION: &str = "eggbench.security_qualification.config.v1";

// Telemetry contract (M003 corrective v2): identifiers + schema versions
// for the supervisor-side Prometheus exporter contract. The contract
// identifier is owned by SynVoid; v2 advances from the withdrawn v1
// because the corrective fixes a declared unit and clarifies
// source-aggregation vs trial-aggregation semantics. The v1 contract ID
// and mapping schema string are retained in Git history only.
pub const TELEMETRY_CONTRACT_ID: &str = "synvoid.eggbench-telemetry.v2";
pub const TELEMETRY_CONTRACT_VERSION: &str = "v2";
pub const TELEMETRY_CONTRACT_SCHEMA_VERSION: &str = "synvoid.eggbench-telemetry.contract.v2";
/// Numeric Eggbench mapping schema version (matches pinned Eggbench
/// `PrometheusMappingV1::MAPPING_SCHEMA_VERSION == 1`).
pub const TELEMETRY_MAPPING_SCHEMA_VERSION: u32 = 1;
pub const TELEMETRY_SOURCE_REFRESH_CADENCE_SECS: u64 = 5;
pub const TELEMETRY_SCRAPE_PATH: &str = "/metrics";
pub const TELEMETRY_MAPPING_FILENAME: &str = "telemetry-mapping.json";
pub const TELEMETRY_CONTRACT_FILENAME: &str = "telemetry-contract.json";

pub const MATERIALIZER_NAME: &str = "synvoid-eggbench-qualification-materializer";
pub const MATERIALIZER_VERSION: &str = "1.1.0";

// Live wire status mapping under policy v1. The canonical SynVoid block
// response for action = "block" is 403; see
// crates/synvoid-waf/src/enforcement.rs and src/waf/mod.rs. The
// controlled origin returns 200 on success.
pub const DETECT_STATUS: u16 = 403;
pub const PASS_STATUS: u16 = 200;

// Headers forbidden by the Eggbench v1 corpus contract (see policy_v1.json).
pub const EXCLUDED_HEADER_NAMES: &[&str] = &[
    "host",
    "x-forwarded-for",
    "x-real-ip",
    "forwarded",
    "authorization",
    "proxy-authorization",
    "cookie",
    "set-cookie",
    "transfer-encoding",
    "content-length",
    "connection",
    "keep-alive",
    "upgrade",
    "proxy-connection",
    "te",
    "trailer",
];

// ============================================================================
// Policy / allowlist / exclusion types (on-disk format)
// ============================================================================

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct PolicyV1 {
    pub policy_id: String,
    pub policy_version: String,
    pub description: String,
    pub synvoid_package_version: String,
    pub qualification_runtime: String,
    pub scope: Vec<String>,
    pub out_of_scope_v1: Vec<String>,
    pub live_status_mapping: BTreeMap<String, u16>,
    pub excluded_header_names: Vec<String>,
    pub semantic_change_rule: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct AllowlistEntry {
    pub id: String,
    pub attack_family: String,
    pub expected_result: String,
    pub rationale: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Allowlist {
    pub policy_id: String,
    pub description: String,
    pub cases: Vec<AllowlistEntry>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ExclusionEntry {
    pub id: String,
    pub reason: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Exclusions {
    pub policy_id: String,
    pub description: String,
    pub exclusions: Vec<ExclusionEntry>,
}

// ============================================================================
// Source WAF fixture types (mirrors crates/synvoid-waf/tests/corpus.rs)
// ============================================================================

#[derive(Debug, Clone, Deserialize)]
struct SourceFixture {
    id: String,
    #[allow(dead_code)]
    description: String,
    #[allow(dead_code)]
    entry_point: String,
    expected_result: String,
    attack_type: String,
    #[allow(dead_code)]
    notes: String,
    request: SourceRequest,
}

#[derive(Debug, Clone, Deserialize)]
#[allow(clippy::upper_case_acronyms)]
struct SourceRequest {
    method: String,
    path: String,
    #[serde(default)]
    headers: SourceHeaders,
    query_string: Option<String>,
    #[serde(default)]
    body: Option<String>,
    #[serde(default)]
    body_file: Option<String>,
}

/// Headers can be encoded either as a JSON object (map) or as an
/// array of `[name, value]` pairs (preserving duplicates and order).
/// SynVoid fixtures use the array form to avoid lossy key coercion.
#[derive(Debug, Clone, Default)]
struct SourceHeaders(Vec<(String, String)>);

impl SourceHeaders {
    fn as_vec(&self) -> Vec<(String, String)> {
        self.0.clone()
    }
}

impl<'de> Deserialize<'de> for SourceHeaders {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(untagged)]
        enum RawHeaders {
            Map(BTreeMap<String, String>),
            Array(Vec<Vec<String>>),
        }
        let raw = RawHeaders::deserialize(deserializer)?;
        match raw {
            RawHeaders::Map(m) => Ok(SourceHeaders(m.into_iter().map(|(k, v)| (k, v)).collect())),
            RawHeaders::Array(a) => {
                let mut out = Vec::with_capacity(a.len());
                for pair in a {
                    if pair.len() != 2 {
                        return Err(serde::de::Error::custom(
                            "header pair must have exactly 2 elements",
                        ));
                    }
                    out.push((pair[0].clone(), pair[1].clone()));
                }
                Ok(SourceHeaders(out))
            }
        }
    }
}

#[derive(Debug, Clone)]
pub(crate) struct LoadedSourceFixture {
    raw: SourceFixture,
    source_path: PathBuf,
    body_bytes: Option<Vec<u8>>,
}

// ============================================================================
// Corpus / provenance types (output format)
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct CorpusCase {
    pub id: String,
    pub category: String,
    pub method: String,
    pub path: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub query_string: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub headers: Option<Vec<(String, String)>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub body: Option<BodyRef>,
    pub expected_status: u16,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(untagged)]
pub enum BodyRef {
    Inline { inline: String },
    File { file: String },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Corpus {
    pub schema_version: String,
    pub policy_id: String,
    pub policy_version: String,
    pub synvoid_package_version: String,
    pub generated_by: String,
    pub listen_port: u16,
    pub origin_port: u16,
    pub case_count: usize,
    pub detect_status: u16,
    pub pass_status: u16,
    pub cases: Vec<CorpusCase>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProvenanceSourceFixture {
    pub id: String,
    pub relative_path: String,
    pub sha256: String,
    pub attack_family: String,
    pub expected_result: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProvenanceExcludedFixture {
    pub id: String,
    pub reason: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Provenance {
    pub schema_version: String,
    pub policy_id: String,
    pub policy_version: String,
    pub synvoid_package_version: String,
    pub synvoid_git_sha: String,
    pub materializer: String,
    pub listen_port: u16,
    pub origin_port: u16,
    pub detect_status: u16,
    pub pass_status: u16,
    pub source_fixtures: Vec<ProvenanceSourceFixture>,
    pub excluded_fixtures: Vec<ProvenanceExcludedFixture>,
    pub generated_config_sha256: String,
    pub generated_corpus_sha256: String,
    pub site_config_sha256: String,
    /// M003 telemetry: present only when `--metrics-port` was supplied
    /// at export. Additive optional fields, not part of the closed M002
    /// schema. Existing checkers that reject unknown keys must use the
    /// `check_telemetry_form` path which loads these fields directly
    /// from the telemetry contract file.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub telemetry_metrics_port: Option<u16>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub telemetry_contract_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub telemetry_contract_digest: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub telemetry_mapping_digest: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub telemetry_enabled_config_digest: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConfigBundle {
    pub schema_version: String,
    pub policy_id: String,
    pub policy_version: String,
    pub synvoid_package_version: String,
    pub synvoid_git_sha: String,
    pub materializer: String,
    pub listen_port: u16,
    pub origin_port: u16,
}

// ============================================================================
// M003 telemetry types (Workstream F: owner manifest + Eggbench mapping)
// ============================================================================

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TelemetryMetricKind {
    Gauge,
    Counter,
}

/// Eggbench trial aggregation for gauges (performed by Eggbench across
/// repeated scrapes). Counters carry no trial aggregation (`None`,
/// omitted from the mapping JSON). Vocabulary is exactly
/// `mean|max|min`; owner/source aggregation must never appear here.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TelemetryTrialAggregation {
    Mean,
    Max,
    Min,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TelemetryMetricEntry {
    pub prometheus_name: String,
    pub kind: TelemetryMetricKind,
    pub unit: String,
    /// Owner/source aggregation performed by the supervisor across worker
    /// heartbeat snapshots at one instant (e.g. `sum`, `max`,
    /// `supervisor_lifetime_monotonic_bridge`, `latest_ready`). Distinct
    /// from Eggbench trial aggregation.
    pub source_aggregation: String,
    pub required: bool,
    pub source_field: String,
    pub reset_semantics: String,
    pub help: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TelemetryContract {
    pub schema_version: String,
    pub contract_id: String,
    pub contract_version: String,
    pub synvoid_package_version: String,
    pub synvoid_git_sha: String,
    pub metrics_port: u16,
    pub scrape_url: String,
    pub scrape_path: String,
    pub source_refresh_cadence_secs: u64,
    pub metrics: Vec<TelemetryMetricEntry>,
    pub mapping_filename: String,
    pub mapping_sha256: String,
    /// SHA-256 of the byte-stable serialized telemetry contract itself
    /// (excluding this field). Consumers re-hash the file and compare.
    pub contract_digest: String,
    /// SHA-256 of the telemetry-enabled `main.toml` content shipped in
    /// the materialization. Lets downstream verifiers detect tampering
    /// without re-deriving it from the manifest.
    pub enabled_config_digest: String,
}

/// Field name in Eggbench's normalized telemetry output. The
/// `subject_<suffix>` naming is owned by Eggbench; SynVoid's mapping
/// artifact records the stable Prometheus name ↔ normalized field
/// pairing it is bound to.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TelemetryMappingField {
    pub output_name: String,
    pub prometheus_name: String,
    pub kind: TelemetryMetricKind,
    pub unit: String,
    /// Trial aggregation for gauges; absent (`None`, omitted) for
    /// counters. Serialized as absent — never owner-side `sum`/bridge
    /// vocabulary — so pinned Eggbench `PrometheusMappingV1` accepts the
    /// bytes directly.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub aggregation: Option<TelemetryTrialAggregation>,
    /// Exact low-cardinality label selector; omitted means no selector.
    /// v2 uses no labels.
    #[serde(default, skip_serializing_if = "std::collections::BTreeMap::is_empty")]
    pub labels: std::collections::BTreeMap<String, String>,
    #[serde(default)]
    pub required: bool,
}

/// Eggbench-compatible interoperability mapping artifact. Structurally
/// identical to pinned Eggbench `PrometheusMappingV1`: numeric
/// `schema_version == 1`, `source == "prometheus"`, no `contract_id`,
/// no owner metadata, `deny_unknown_fields`. Bound to the owner contract
/// by SHA-256 recorded in `telemetry-contract.json` and provenance.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TelemetryMapping {
    pub schema_version: u32,
    pub source: String,
    pub fields: Vec<TelemetryMappingField>,
}

// ============================================================================
// M003 owner metric inventory
// ============================================================================
//
// Every metric shipped under `synvoid.eggbench-telemetry.v1`. Names
// are underscore-only so Prometheus name sanitization does not become
// part of the compatibility contract. The order is the contract order;
// it must match the supervisor-side bridge inventory exactly.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TelemetryOwnerMetric {
    EventLoopLagMs,
    RequestQueueP95Ms,
    ActiveConnections,
    WorkerMemoryBytes,
    WorkerCpuPercent,
    BodyBufferingBytesTotal,
    OffloadSubmissionsTotal,
    OffloadTimeoutsTotal,
    OffloadRejectionsTotal,
    OffloadFallbacksTotal,
    CpuWorkerRssBytes,
    WorkerMetricResetsTotal,
}

impl TelemetryOwnerMetric {
    pub const fn prometheus_name(self) -> &'static str {
        match self {
            Self::EventLoopLagMs => "synvoid_subject_event_loop_lag_ms",
            Self::RequestQueueP95Ms => "synvoid_subject_request_queue_p95_ms",
            Self::ActiveConnections => "synvoid_subject_active_connections",
            Self::WorkerMemoryBytes => "synvoid_subject_worker_memory_bytes",
            Self::WorkerCpuPercent => "synvoid_subject_worker_cpu_percent",
            Self::BodyBufferingBytesTotal => "synvoid_subject_body_buffering_bytes_total",
            Self::OffloadSubmissionsTotal => "synvoid_subject_offload_submissions_total",
            Self::OffloadTimeoutsTotal => "synvoid_subject_offload_timeouts_total",
            Self::OffloadRejectionsTotal => "synvoid_subject_offload_rejections_total",
            Self::OffloadFallbacksTotal => "synvoid_subject_offload_fallbacks_total",
            Self::CpuWorkerRssBytes => "synvoid_subject_cpu_worker_rss_bytes",
            Self::WorkerMetricResetsTotal => "synvoid_subject_worker_metric_resets_total",
        }
    }

    pub const fn kind(self) -> TelemetryMetricKind {
        match self {
            Self::EventLoopLagMs
            | Self::RequestQueueP95Ms
            | Self::ActiveConnections
            | Self::WorkerMemoryBytes
            | Self::WorkerCpuPercent
            | Self::CpuWorkerRssBytes => TelemetryMetricKind::Gauge,
            _ => TelemetryMetricKind::Counter,
        }
    }

    pub const fn unit(self) -> &'static str {
        match self {
            Self::EventLoopLagMs => "ms",
            Self::RequestQueueP95Ms => "ms",
            Self::ActiveConnections => "connections",
            Self::WorkerMemoryBytes => "bytes",
            Self::WorkerCpuPercent => "percent",
            Self::CpuWorkerRssBytes => "bytes",
            Self::BodyBufferingBytesTotal => "bytes",
            Self::OffloadSubmissionsTotal
            | Self::OffloadTimeoutsTotal
            | Self::OffloadRejectionsTotal
            | Self::OffloadFallbacksTotal
            | Self::WorkerMetricResetsTotal => "count",
        }
    }

    pub const fn required(self) -> bool {
        matches!(
            self,
            Self::CpuWorkerRssBytes | Self::WorkerMetricResetsTotal
        ) == false
    }

    /// Owner/source aggregation (supervisor across worker snapshots at one
    /// instant). Distinct from Eggbench trial aggregation.
    pub const fn source_aggregation(self) -> &'static str {
        match self {
            Self::EventLoopLagMs => "max",
            Self::RequestQueueP95Ms => "max",
            Self::ActiveConnections => "sum",
            Self::WorkerMemoryBytes => "sum",
            Self::WorkerCpuPercent => "sum",
            Self::CpuWorkerRssBytes => "latest_ready",
            _ => "supervisor_lifetime_monotonic_bridge",
        }
    }

    /// Eggbench trial aggregation for the mapping artifact. Gauges use
    /// `mean|max|min`; counters use none.
    pub const fn trial_aggregation(self) -> Option<TelemetryTrialAggregation> {
        match self {
            Self::EventLoopLagMs => Some(TelemetryTrialAggregation::Max),
            Self::RequestQueueP95Ms => Some(TelemetryTrialAggregation::Max),
            Self::ActiveConnections => Some(TelemetryTrialAggregation::Max),
            Self::WorkerMemoryBytes => Some(TelemetryTrialAggregation::Max),
            Self::WorkerCpuPercent => Some(TelemetryTrialAggregation::Mean),
            Self::CpuWorkerRssBytes => Some(TelemetryTrialAggregation::Max),
            _ => None,
        }
    }

    pub const fn source_field(self) -> &'static str {
        match self {
            Self::EventLoopLagMs => "WorkerMetricsPayload::event_loop_lag_ms",
            Self::RequestQueueP95Ms => "WorkerMetricsPayload::request_queue_time_ms.p95_ms",
            Self::ActiveConnections => "WorkerMetricsPayload::active_connections",
            Self::WorkerMemoryBytes => "WorkerMetricsPayload::memory_bytes",
            Self::WorkerCpuPercent => "WorkerMetricsPayload::cpu_percent",
            Self::BodyBufferingBytesTotal => "WorkerMetricsPayload::body_buffering_bytes_total",
            Self::OffloadSubmissionsTotal => "WorkerMetricsPayload::offload_submissions_total",
            Self::OffloadTimeoutsTotal => "WorkerMetricsPayload::offload_timeouts_total",
            Self::OffloadRejectionsTotal => "WorkerMetricsPayload::offload_rejections_total",
            Self::OffloadFallbacksTotal => "WorkerMetricsPayload::offload_fallbacks_total",
            Self::CpuWorkerRssBytes => "CpuOffloadStats::worker_rss_bytes",
            Self::WorkerMetricResetsTotal => "internal_counter",
        }
    }

    pub const fn reset_semantics(self) -> &'static str {
        match self {
            Self::CpuWorkerRssBytes => "omitted_when_cpu_worker_absent",
            _ if matches!(self.kind(), TelemetryMetricKind::Counter) => {
                "supervisor_lifetime_monotonic_with_reset_boundary_observation"
            }
            _ => "latest_value_per_worker_snapshot",
        }
    }

    pub const fn help(self) -> &'static str {
        match self {
            Self::EventLoopLagMs => "Maximum event_loop_lag_ms across Unified Server workers (ms).",
            Self::RequestQueueP95Ms => {
                "Maximum p95 request_queue_time_ms across Unified Server workers (ms)."
            }
            Self::ActiveConnections => "Sum of active_connections across Unified Server workers.",
            Self::WorkerMemoryBytes => "Sum of memory_bytes across Unified Server workers.",
            Self::WorkerCpuPercent => "Sum of cpu_percent across Unified Server workers.",
            Self::BodyBufferingBytesTotal => {
                "Supervisor-lifetime monotonic bridge of body_buffering_bytes_total."
            }
            Self::OffloadSubmissionsTotal => {
                "Supervisor-lifetime monotonic bridge of offload_submissions_total."
            }
            Self::OffloadTimeoutsTotal => {
                "Supervisor-lifetime monotonic bridge of offload_timeouts_total."
            }
            Self::OffloadRejectionsTotal => {
                "Supervisor-lifetime monotonic bridge of offload_rejections_total."
            }
            Self::OffloadFallbacksTotal => {
                "Supervisor-lifetime monotonic bridge of offload_fallbacks_total."
            }
            Self::CpuWorkerRssBytes => "Latest ready CPU-worker worker_rss_bytes (bytes).",
            Self::WorkerMetricResetsTotal => {
                "Total worker counter reset boundaries observed during bridging."
            }
        }
    }

    /// Eggbench `subject_<suffix>` normalized output name. Owned by
    /// Eggbench semantics; SynVoid only records the binding.
    pub const fn eggbench_output_name(self) -> &'static str {
        // The mapping is the Prometheus metric suffix without the
        // `synvoid_subject_` prefix. Matches Eggbench's normalized
        // output naming convention (subject_event_loop_lag_ms, etc.).
        match self {
            Self::EventLoopLagMs => "subject_event_loop_lag_ms",
            Self::RequestQueueP95Ms => "subject_request_queue_p95_ms",
            Self::ActiveConnections => "subject_active_connections",
            Self::WorkerMemoryBytes => "subject_worker_memory_bytes",
            Self::WorkerCpuPercent => "subject_worker_cpu_percent",
            Self::BodyBufferingBytesTotal => "subject_body_buffering_bytes_total",
            Self::OffloadSubmissionsTotal => "subject_offload_submissions_total",
            Self::OffloadTimeoutsTotal => "subject_offload_timeouts_total",
            Self::OffloadRejectionsTotal => "subject_offload_rejections_total",
            Self::OffloadFallbacksTotal => "subject_offload_fallbacks_total",
            Self::CpuWorkerRssBytes => "subject_cpu_worker_rss_bytes",
            Self::WorkerMetricResetsTotal => "subject_worker_metric_resets_total",
        }
    }
}

pub const TELEMETRY_OWNER_INVENTORY: &[TelemetryOwnerMetric] = &[
    TelemetryOwnerMetric::EventLoopLagMs,
    TelemetryOwnerMetric::RequestQueueP95Ms,
    TelemetryOwnerMetric::ActiveConnections,
    TelemetryOwnerMetric::WorkerMemoryBytes,
    TelemetryOwnerMetric::WorkerCpuPercent,
    TelemetryOwnerMetric::BodyBufferingBytesTotal,
    TelemetryOwnerMetric::OffloadSubmissionsTotal,
    TelemetryOwnerMetric::OffloadTimeoutsTotal,
    TelemetryOwnerMetric::OffloadRejectionsTotal,
    TelemetryOwnerMetric::OffloadFallbacksTotal,
    TelemetryOwnerMetric::CpuWorkerRssBytes,
    TelemetryOwnerMetric::WorkerMetricResetsTotal,
];

/// Build the owner contract. `contract_digest` is the SHA-256 of the
/// canonical JSON serialization with `contract_digest` itself cleared
/// to the empty string. This is a content-addressed fingerprint:
/// consumers recompute it by serializing the same content tree with
/// the field emptied, and they do not depend on the digest field
/// itself being stable across edits.
pub fn build_telemetry_contract(
    metrics_port: u16,
    package_version: &str,
    git_sha: &str,
    mapping_sha256: &str,
    enabled_config_bytes: &[u8],
) -> Result<(TelemetryContract, Vec<u8>)> {
    let metrics: Vec<TelemetryMetricEntry> = TELEMETRY_OWNER_INVENTORY
        .iter()
        .map(|&m| TelemetryMetricEntry {
            prometheus_name: m.prometheus_name().to_string(),
            kind: m.kind(),
            unit: m.unit().to_string(),
            source_aggregation: m.source_aggregation().to_string(),
            required: m.required(),
            source_field: m.source_field().to_string(),
            reset_semantics: m.reset_semantics().to_string(),
            help: m.help().to_string(),
        })
        .collect();

    let enabled_config_digest = sha256_hex(enabled_config_bytes);

    let scrape_url = format!("http://127.0.0.1:{metrics_port}{TELEMETRY_SCRAPE_PATH}");

    // Step 1: build the contract with an empty digest placeholder and
    // serialize. The hash over these bytes is the contract fingerprint.
    let mut skeleton = TelemetryContract {
        schema_version: TELEMETRY_CONTRACT_SCHEMA_VERSION.to_string(),
        contract_id: TELEMETRY_CONTRACT_ID.to_string(),
        contract_version: TELEMETRY_CONTRACT_VERSION.to_string(),
        synvoid_package_version: package_version.to_string(),
        synvoid_git_sha: git_sha.to_string(),
        metrics_port,
        scrape_url,
        scrape_path: TELEMETRY_SCRAPE_PATH.to_string(),
        source_refresh_cadence_secs: TELEMETRY_SOURCE_REFRESH_CADENCE_SECS,
        metrics,
        mapping_filename: TELEMETRY_MAPPING_FILENAME.to_string(),
        mapping_sha256: mapping_sha256.to_string(),
        contract_digest: String::new(),
        enabled_config_digest,
    };
    let pre_digest_bytes = canonical_json(&skeleton)?;
    let digest = sha256_hex(&pre_digest_bytes);

    // Step 2: re-serialize with the populated digest field so the
    // on-disk file is self-describing (operators can read the digest
    // without recomputing). The check function re-computes the digest
    // over the same skeleton (with the field emptied) and compares.
    skeleton.contract_digest = digest.clone();
    let final_bytes = canonical_json(&skeleton)?;
    Ok((skeleton, final_bytes))
}

/// Recompute the contract fingerprint for verification: serialize the
/// contract with `contract_digest` emptied and hash the result.
pub fn recompute_contract_digest(contract: &TelemetryContract) -> Result<String> {
    let mut skeleton = contract.clone();
    skeleton.contract_digest.clear();
    let bytes = canonical_json(&skeleton)?;
    Ok(sha256_hex(&bytes))
}

/// Build the Eggbench-consumable telemetry mapping artifact (corrective
/// v2). Emits exactly the pinned Eggbench `PrometheusMappingV1` shape:
/// numeric `schema_version == 1`, `source == "prometheus"`, no
/// `contract_id`, gauge trial aggregation `mean|max|min`, no counter
/// aggregation, no labels, `subject_*` outputs. Recommended v2 trial
/// mapping per the corrective plan.
pub fn build_telemetry_mapping() -> Result<(TelemetryMapping, Vec<u8>)> {
    let fields: Vec<TelemetryMappingField> = TELEMETRY_OWNER_INVENTORY
        .iter()
        .map(|&m| TelemetryMappingField {
            output_name: m.eggbench_output_name().to_string(),
            prometheus_name: m.prometheus_name().to_string(),
            kind: m.kind(),
            unit: m.unit().to_string(),
            aggregation: m.trial_aggregation(),
            labels: std::collections::BTreeMap::new(),
            required: m.required(),
        })
        .collect();
    let mapping = TelemetryMapping {
        schema_version: TELEMETRY_MAPPING_SCHEMA_VERSION,
        source: "prometheus".to_string(),
        fields,
    };
    let bytes = canonical_json(&mapping)?;
    Ok((mapping, bytes))
}

// ============================================================================
// Errors / Results
// ============================================================================

#[derive(Debug)]
pub enum MaterializerError {
    Io(String),
    Parse(String),
    NotFound(String),
    Invalid(String),
    CommandFailed(String),
}

impl std::fmt::Display for MaterializerError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(s) => write!(f, "io error: {s}"),
            Self::Parse(s) => write!(f, "parse error: {s}"),
            Self::NotFound(s) => write!(f, "not found: {s}"),
            Self::Invalid(s) => write!(f, "invalid: {s}"),
            Self::CommandFailed(s) => write!(f, "command failed: {s}"),
        }
    }
}

impl std::error::Error for MaterializerError {}

pub type Result<T> = std::result::Result<T, MaterializerError>;

fn io_err<E: std::fmt::Display>(e: E) -> MaterializerError {
    MaterializerError::Io(e.to_string())
}

fn parse_err<E: std::fmt::Display>(e: E) -> MaterializerError {
    MaterializerError::Parse(e.to_string())
}

// ============================================================================
// Workspace / git helpers
// ============================================================================

/// Find the workspace root (the SynVoid `Cargo.toml` with `[workspace]`).
pub fn find_workspace_root() -> Result<PathBuf> {
    let mut dir = std::env::current_dir().map_err(|e| MaterializerError::Io(e.to_string()))?;
    loop {
        let cargo_toml = dir.join("Cargo.toml");
        if cargo_toml.exists() {
            let content = fs::read_to_string(&cargo_toml).map_err(io_err)?;
            if content.contains("[workspace]") {
                return Ok(dir);
            }
        }
        dir = dir
            .parent()
            .ok_or_else(|| {
                MaterializerError::NotFound(
                    "reached filesystem root without finding workspace Cargo.toml".to_string(),
                )
            })?
            .to_path_buf();
    }
}

/// Path to the authoritative WAF fixtures directory.
pub fn waf_fixtures_dir(workspace: &Path) -> PathBuf {
    workspace.join("crates/synvoid-waf/tests/fixtures/waf")
}

/// Path to the v1 qualification policy directory.
pub fn qualification_dir(workspace: &Path) -> PathBuf {
    workspace.join("crates/synvoid-waf/tests/fixtures/eggbench_qualification")
}

/// Read the current git HEAD SHA (short form preferred, full form otherwise).
pub fn git_head_sha(workspace: &Path) -> Result<String> {
    let output = Command::new("git")
        .args(["rev-parse", "HEAD"])
        .current_dir(workspace)
        .output();
    match output {
        Ok(out) if out.status.success() => {
            let sha = String::from_utf8(out.stdout).map_err(parse_err)?;
            Ok(sha.trim().to_string())
        }
        Ok(out) => {
            let stderr = String::from_utf8_lossy(&out.stderr).to_string();
            Err(MaterializerError::CommandFailed(format!(
                "git rev-parse failed: {stderr}"
            )))
        }
        Err(e) => Err(MaterializerError::CommandFailed(format!(
            "git not available: {e}"
        ))),
    }
}

/// SynVoid package version (read from root Cargo.toml).
pub fn synvoid_package_version(workspace: &Path) -> Result<String> {
    let root_toml = workspace.join("Cargo.toml");
    let text = fs::read_to_string(&root_toml).map_err(io_err)?;
    let value: toml::Value = toml::from_str(&text).map_err(parse_err)?;
    let version = value
        .get("package")
        .and_then(|p| p.get("version"))
        .and_then(|v| v.as_str())
        .ok_or_else(|| {
            MaterializerError::Parse("root Cargo.toml missing package.version".to_string())
        })?;
    Ok(version.to_string())
}

// ============================================================================
// Hashing helpers
// ============================================================================

pub fn sha256_hex(data: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data);
    let digest = hasher.finalize();
    hex::encode(digest)
}

pub fn sha256_file(path: &Path) -> Result<String> {
    let bytes = fs::read(path).map_err(io_err)?;
    Ok(sha256_hex(&bytes))
}

/// Normalize a JSON value to a deterministic byte representation. We sort
/// object keys recursively so that semantic equality maps to byte
/// equality (the corpus JSON ordering is already deterministic via
/// ordered maps, but this helper also makes the config SHA stable when
/// sources-of-truth evolve).
pub fn canonical_json<T: Serialize>(value: &T) -> Result<Vec<u8>> {
    let json = serde_json::to_vec(value).map_err(parse_err)?;
    let value: serde_json::Value = serde_json::from_slice(&json).map_err(parse_err)?;
    let normalized = normalize_value(&value);
    let mut buf = Vec::with_capacity(json.len());
    serialize_value(&normalized, &mut buf);
    Ok(buf)
}

fn normalize_value(v: &serde_json::Value) -> serde_json::Value {
    match v {
        serde_json::Value::Object(map) => {
            let mut sorted: BTreeMap<String, serde_json::Value> = BTreeMap::new();
            for (k, vv) in map {
                sorted.insert(k.clone(), normalize_value(vv));
            }
            let mut out = serde_json::Map::new();
            for (k, vv) in sorted {
                out.insert(k, vv);
            }
            serde_json::Value::Object(out)
        }
        serde_json::Value::Array(items) => {
            serde_json::Value::Array(items.iter().map(normalize_value).collect())
        }
        other => other.clone(),
    }
}

fn serialize_value(v: &serde_json::Value, out: &mut Vec<u8>) {
    use std::io::Write;
    match v {
        serde_json::Value::Null => out.write_all(b"null").unwrap(),
        serde_json::Value::Bool(b) => {
            out.write_all(if *b { b"true" } else { b"false" }).unwrap();
        }
        serde_json::Value::Number(n) => {
            out.write_all(n.to_string().as_bytes()).unwrap();
        }
        serde_json::Value::String(s) => {
            let escaped = serde_json::to_string(s).unwrap();
            out.write_all(escaped.as_bytes()).unwrap();
        }
        serde_json::Value::Array(items) => {
            out.write_all(b"[").unwrap();
            for (i, item) in items.iter().enumerate() {
                if i > 0 {
                    out.write_all(b",").unwrap();
                }
                serialize_value(item, out);
            }
            out.write_all(b"]").unwrap();
        }
        serde_json::Value::Object(map) => {
            out.write_all(b"{").unwrap();
            let mut first = true;
            for (k, vv) in map {
                if !first {
                    out.write_all(b",").unwrap();
                }
                first = false;
                let escaped = serde_json::to_string(k).unwrap();
                out.write_all(escaped.as_bytes()).unwrap();
                out.write_all(b":").unwrap();
                serialize_value(vv, out);
            }
            out.write_all(b"}").unwrap();
        }
    }
}

// ============================================================================
// Loaders
// ============================================================================

pub fn load_policy(workspace: &Path) -> Result<PolicyV1> {
    let path = qualification_dir(workspace).join("policy_v1.json");
    let text = fs::read_to_string(&path).map_err(io_err)?;
    let policy: PolicyV1 = serde_json::from_str(&text).map_err(parse_err)?;
    if policy.policy_id != POLICY_ID {
        return Err(MaterializerError::Invalid(format!(
            "policy file declares policy_id={:?}, expected {:?}",
            policy.policy_id, POLICY_ID
        )));
    }
    Ok(policy)
}

pub fn load_allowlist(workspace: &Path) -> Result<Allowlist> {
    let path = qualification_dir(workspace).join("v1_allowlist.json");
    let text = fs::read_to_string(&path).map_err(io_err)?;
    let allowlist: Allowlist = serde_json::from_str(&text).map_err(parse_err)?;
    if allowlist.policy_id != POLICY_ID {
        return Err(MaterializerError::Invalid(format!(
            "allowlist declares policy_id={:?}, expected {:?}",
            allowlist.policy_id, POLICY_ID
        )));
    }
    Ok(allowlist)
}

pub fn load_exclusions(workspace: &Path) -> Result<Exclusions> {
    let path = qualification_dir(workspace).join("v1_exclusions.json");
    let text = fs::read_to_string(&path).map_err(io_err)?;
    let exclusions: Exclusions = serde_json::from_str(&text).map_err(parse_err)?;
    if exclusions.policy_id != POLICY_ID {
        return Err(MaterializerError::Invalid(format!(
            "exclusions declares policy_id={:?}, expected {:?}",
            exclusions.policy_id, POLICY_ID
        )));
    }
    Ok(exclusions)
}

/// Load every fixture in `fixtures_dir/requests/*.json`, parse it,
/// resolve any `body_file` references against `fixtures_dir`, and
/// sort by id so caller iteration is deterministic.
pub fn load_source_fixtures(workspace: &Path) -> Result<Vec<LoadedSourceFixture>> {
    let dir = waf_fixtures_dir(workspace).join("requests");
    if !dir.exists() {
        return Err(MaterializerError::NotFound(format!(
            "WAF requests dir not found: {}",
            dir.display()
        )));
    }
    let mut fixtures = Vec::new();
    for entry in fs::read_dir(&dir).map_err(io_err)?.flatten() {
        let path = entry.path();
        if path.extension().and_then(|s| s.to_str()) != Some("json") {
            continue;
        }
        let text = fs::read_to_string(&path).map_err(io_err)?;
        let raw: SourceFixture = serde_json::from_str(&text).map_err(parse_err)?;
        let body_bytes = match &raw.request.body_file {
            Some(rel) => {
                // body_file is relative to the requests/ dir per SynVoid
                // convention (e.g. "../bodies/raw_cl_te_smuggling.txt").
                let resolved = path.parent().unwrap_or(&dir).join(rel);
                let bytes = fs::read(&resolved).map_err(|e| {
                    MaterializerError::Io(format!(
                        "failed to read body_file {} for fixture {}: {e}",
                        resolved.display(),
                        raw.id
                    ))
                })?;
                Some(bytes)
            }
            None => raw.request.body.as_ref().map(|s| s.as_bytes().to_vec()),
        };
        fixtures.push(LoadedSourceFixture {
            raw,
            source_path: path,
            body_bytes,
        });
    }
    fixtures.sort_by(|a, b| a.raw.id.cmp(&b.raw.id));
    Ok(fixtures)
}

// ============================================================================
// Sanitization (corpus contract)
// ============================================================================

fn is_header_forbidden(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    EXCLUDED_HEADER_NAMES.iter().any(|f| *f == lower)
}

/// Returns Err if any case violates the Eggbench v1 corpus contract.
/// This is also a unit-testable seam (`assert_corpus_contract_*`).
pub fn validate_corpus_case(case: &CorpusCase) -> Result<()> {
    // unique id is enforced separately; here we check header names only.
    if let Some(headers) = &case.headers {
        for (name, _) in headers {
            if is_header_forbidden(name) {
                return Err(MaterializerError::Invalid(format!(
                    "case {} emits forbidden header {:?}",
                    case.id, name
                )));
            }
        }
    }
    Ok(())
}

// ============================================================================
// Build the corpus from the source fixtures + allowlist
// ============================================================================

pub struct BuildInputs<'a> {
    pub workspace: &'a Path,
    pub listen_port: u16,
    pub origin_port: u16,
    pub package_version: &'a str,
    pub git_sha: &'a str,
}

#[derive(Debug)]
pub struct BuildOutputs {
    pub corpus: Corpus,
    pub provenance: Provenance,
    #[allow(dead_code)]
    pub main_toml: String,
    #[allow(dead_code)]
    pub site_toml: String,
    #[allow(dead_code)]
    pub config_bundle: ConfigBundle,
    /// `Some` iff `--metrics-port` was supplied at export.
    #[allow(dead_code)]
    pub telemetry_contract: Option<TelemetryContract>,
    #[allow(dead_code)]
    pub telemetry_mapping: Option<TelemetryMapping>,
    #[allow(dead_code)]
    pub telemetry_mapping_bytes: Option<Vec<u8>>,
    #[allow(dead_code)]
    pub telemetry_contract_bytes: Option<Vec<u8>>,
}

pub fn build_corpus(
    fixtures: &[LoadedSourceFixture],
    allowlist: &Allowlist,
) -> Result<Vec<CorpusCase>> {
    let mut by_id: BTreeMap<&str, &LoadedSourceFixture> = BTreeMap::new();
    for f in fixtures {
        by_id.insert(f.raw.id.as_str(), f);
    }

    let mut cases = Vec::with_capacity(allowlist.cases.len());
    for entry in &allowlist.cases {
        let fixture = by_id.get(entry.id.as_str()).ok_or_else(|| {
            MaterializerError::NotFound(format!(
                "allowlist references missing source fixture: {}",
                entry.id
            ))
        })?;

        let method = fixture.raw.request.method.clone();
        let path = fixture.raw.request.path.clone();
        let query_string = fixture.raw.request.query_string.clone();

        // Build the headers list, omitting any forbidden header names.
        let mut headers: Vec<(String, String)> = Vec::new();
        for (name, value) in fixture.raw.request.headers.as_vec() {
            if is_header_forbidden(&name) {
                continue;
            }
            headers.push((name, value));
        }

        let body = match &fixture.body_bytes {
            Some(bytes) => Some(if fixture.raw.request.body_file.is_some() {
                BodyRef::File {
                    file: fixture.raw.request.body_file.as_ref().unwrap().clone(),
                }
            } else {
                BodyRef::Inline {
                    inline: String::from_utf8_lossy(bytes).into_owned(),
                }
            }),
            None => None,
        };

        let expected_status = match entry.expected_result.as_str() {
            "detect" => DETECT_STATUS,
            "pass" => PASS_STATUS,
            other => {
                return Err(MaterializerError::Invalid(format!(
                    "allowlist entry {} has unknown expected_result={:?}",
                    entry.id, other
                )))
            }
        };

        let case = CorpusCase {
            id: entry.id.clone(),
            category: entry.attack_family.clone(),
            method,
            path,
            query_string,
            headers: if headers.is_empty() {
                None
            } else {
                Some(headers)
            },
            body,
            expected_status,
        };
        validate_corpus_case(&case)?;
        cases.push(case);
    }
    Ok(cases)
}

pub fn build_provenance(
    inputs: &BuildInputs,
    cases: &[CorpusCase],
    exclusions: &Exclusions,
    source_fixtures: &[LoadedSourceFixture],
    main_toml_bytes: &[u8],
    site_toml_bytes: &[u8],
    corpus_bytes: &[u8],
    telemetry: Option<&TelemetryProvenanceFields>,
) -> Result<Provenance> {
    // Provenance source fixtures: include allowlisted fixtures only, with
    // their relative paths and SHA-256 digests.
    let allowed_ids: BTreeMap<&str, &LoadedSourceFixture> = source_fixtures
        .iter()
        .filter(|f| cases.iter().any(|c| c.id == f.raw.id))
        .map(|f| (f.raw.id.as_str(), f))
        .collect();

    let mut source_fixtures_provenance: Vec<ProvenanceSourceFixture> = Vec::new();
    for (id, fixture) in &allowed_ids {
        let rel = fixture
            .source_path
            .strip_prefix(inputs.workspace)
            .unwrap_or(&fixture.source_path)
            .to_string_lossy()
            .replace('\\', "/");
        let bytes = fs::read(&fixture.source_path).map_err(io_err)?;
        source_fixtures_provenance.push(ProvenanceSourceFixture {
            id: (*id).to_string(),
            relative_path: rel,
            sha256: sha256_hex(&bytes),
            attack_family: fixture.raw.attack_type.clone(),
            expected_result: fixture.raw.expected_result.clone(),
        });
    }
    source_fixtures_provenance.sort_by(|a, b| a.id.cmp(&b.id));

    // Excluded fixtures: serialize exclusions verbatim (with id + reason).
    let excluded: Vec<ProvenanceExcludedFixture> = exclusions
        .exclusions
        .iter()
        .map(|e| ProvenanceExcludedFixture {
            id: e.id.clone(),
            reason: e.reason.clone(),
        })
        .collect();

    let mut p = Provenance {
        schema_version: PROVENANCE_SCHEMA_VERSION.to_string(),
        policy_id: POLICY_ID.to_string(),
        policy_version: POLICY_VERSION.to_string(),
        synvoid_package_version: inputs.package_version.to_string(),
        synvoid_git_sha: inputs.git_sha.to_string(),
        materializer: format!("{MATERIALIZER_NAME}@{MATERIALIZER_VERSION}"),
        listen_port: inputs.listen_port,
        origin_port: inputs.origin_port,
        detect_status: DETECT_STATUS,
        pass_status: PASS_STATUS,
        source_fixtures: source_fixtures_provenance,
        excluded_fixtures: excluded,
        generated_config_sha256: sha256_hex(main_toml_bytes),
        generated_corpus_sha256: sha256_hex(corpus_bytes),
        site_config_sha256: sha256_hex(site_toml_bytes),
        telemetry_metrics_port: None,
        telemetry_contract_id: None,
        telemetry_contract_digest: None,
        telemetry_mapping_digest: None,
        telemetry_enabled_config_digest: None,
    };
    if let Some(t) = telemetry {
        p.telemetry_metrics_port = Some(t.metrics_port);
        p.telemetry_contract_id = Some(TELEMETRY_CONTRACT_ID.to_string());
        p.telemetry_contract_digest = Some(t.contract_digest.clone());
        p.telemetry_mapping_digest = Some(t.mapping_sha256.clone());
        p.telemetry_enabled_config_digest = Some(t.enabled_config_digest.clone());
    }
    Ok(p)
}

/// M003 provenance extension fields. Bounded payload so adding new
/// provenance fields in the future requires a schema version bump
/// rather than ad-hoc provenance mutations.
pub struct TelemetryProvenanceFields {
    pub metrics_port: u16,
    pub contract_digest: String,
    pub mapping_sha256: String,
    pub enabled_config_digest: String,
}

// ============================================================================
// Loopback-only minimal runtime config (Workstream C)
// ============================================================================

/// Build the loopback-only main.toml for the supported minimal binary.
///
/// - bind 127.0.0.1:<listen_port> only
/// - upstream defaults to a no-op `return_404` fallback (the site file owns
///   the real upstream); admin disabled; rate limiting disabled; persistence
///   disabled; logging paths inside the qualification dir; threat_level
///   disabled; no IP feeds; no traffic shaping; no TLS; no HTTP/3; no
///   socket-handoff; no mesh; no DNS; no flood/ICMP; tunnelling disabled;
///   plugins/serverless/app-server disabled; cookie/session defaults left
///   empty.
/// - When `metrics_port` is `Some`, the `[metrics]` table enables the
///   supervisor-side Prometheus exporter on `127.0.0.1:<metrics_port>` and
///   `admin.enabled` remains `false`. When `metrics_port` is `None`, the
///   M002 v1 closed-export form is preserved: `[metrics] enabled = false`.
pub fn build_main_toml(
    inputs: &BuildInputs,
    output_dir: &Path,
    metrics_port: Option<u16>,
) -> String {
    let log_dir = output_dir.join("logs");
    let state_dir = output_dir.join("state");
    let _ = fs::create_dir_all(&log_dir);
    let _ = fs::create_dir_all(&state_dir);

    let (metrics_block, header_comment) = match metrics_port {
        Some(port) => (
            format!(
                r#"[metrics]
enabled = true
port = {port}
bind_address = "127.0.0.1""#
            ),
            format!(
                "# Eggbench Security Qualification M002+M003 — policy synvoid.eggbench-qualification.v1\n\
                 # plus synvoid.eggbench-telemetry.v2 (telemetry exporter on 127.0.0.1:{port})."
            ),
        ),
        None => (
            "[metrics]\nenabled = false\nport = 9090\nbind_address = \"127.0.0.1\"".to_string(),
            "# Eggbench Security Qualification M002 — policy synvoid.eggbench-qualification.v1.\n\
             # DO NOT EDIT BY HAND. Regenerate with `cargo xtask eggbench-qualification export`."
                .to_string(),
        ),
    };

    format!(
        r#"# SynVoid qualification runtime configuration (auto-generated).
{header_comment}
#
# Loopback-only: bind 127.0.0.1:{listen_port}, upstream is the controlled origin
# bound to 127.0.0.1:{origin_port}. No public listeners, no remote mesh, no DNS,
# no flood/ICMP, no admin, no rate limiting.

[server]
host = "127.0.0.1"
port = {listen_port}
trusted_proxies = ["127.0.0.1", "::1"]

# NOTE: no [tokio] section. Post-Phase-99 `TokioConfig` accepts both the
# scalar form and the documented legacy `[tokio]` table form (with
# `worker_threads = <n> | "auto"`); omission yields
# `available_parallelism()`. The materializer omits the section by choice
# to keep the qualification runtime on the default scheduler sizing.
[http]
header_read_timeout_secs = 10
keep_alive_timeout_secs = 30
max_headers = 128
max_request_line_size = 8192
max_header_size_ingress = 16384
max_header_size_egress = 16384
max_request_size = 1048576
pipeline_limit = 16
waf_stall_timeout_secs = 5
max_stalled_requests = 16
max_connections = 256
strict_protocol_validation = true
max_streaming_body_size = 1048576

[tls]
enabled = false

[http3]
enabled = false

[threat_level]
initial = 1
auto_scale = false
scale_up_attacks_per_min = 0
scale_up_window_secs = 60
scale_down_attacks_per_min = 0
scale_down_window_secs = 300
cooldown_secs = 60
persist_interval_normal_secs = 60
persist_interval_attack_secs = 15
auto_deescalate_timeout_mins = 15

[threat_level.global_limits]
level_1 = 1.0
level_2 = 1.0
level_3 = 1.0
level_4 = 1.0
level_5 = 1.0

[threat_level.ban_durations]
level_1_base = "1h"
level_2_base = "4h"
level_3_base = "24h"
level_4_base = "7d"
level_5_base = "permanent"

[threat_level.escalation]
enabled = false
violations_before_block = 3
violation_window_secs = 300
excluded_ips = ["127.0.0.1", "::1"]

[ip_feeds]
enabled = false
update_interval_hours = 2
url = "https://example.invalid/feed"
max_permanent_blocks = 1

[fallback]
mode = "return_404"

[admin]
enabled = false
port = 8081
bind_address = "127.0.0.1"
token = ""
bcrypt_cost = 12
secure_cookie = false

[logging]
level = "warn"
access_log = false
access_log_dir = "{log_dir}"
access_log_format = "json"
retention_days = 1
max_entries_per_file = 100

[security]
ipc_enforce_signing = true
global_security_headers = false
sanitize_forwarded_headers = true
allow_insecure_ipc_key = false

{metrics_block}

[defaults]

# NOTE: "disabled" is not an accepted mode (validator requires
# shared|isolated); isolation with saturating limits is the neutral setting.
[defaults.ratelimit]
mode = "isolated"
endpoints = []

[defaults.ratelimit.ip]
per_second = 1000000
per_minute = 1000000
per_5min = 1000000
per_10min = 1000000
per_hour = 1000000
per_day = 1000000
burst = 1000000

[defaults.ratelimit.global]
per_second = 1000000
per_minute = 1000000
per_5min = 1000000
max_connections = 1000000

[defaults.blocked]
paths = []
use_regex = false
block_methods = []
block_response_code = 403

[defaults.honeypot]
endpoints_file = ""
paths_per_ip = 1
ttl_secs = 60

[defaults.honeypot.block]
enabled = false
ban_duration = "1h"

[defaults.honeypot.probe]
enabled = false
max_endpoints_per_window = 3
window_secs = 300
retention_days = 1
max_records = 100
auto_ban_elevated_threat = false
elevated_threat_threshold = 3
elevated_ban_duration = 900

[defaults.suspicious_words]
enabled = false
words = []

[defaults.upstream_errors]
enabled = false
min_error_endpoints = 3
window_secs = 300
error_codes = [500]

[defaults.error_pages]
enabled = false
mode = "default"
directory = ""

[defaults.css_challenge]
enabled = false
invalid_count_min = 100
invalid_count_max = 300
valid_count = 3

[defaults.css_challenge.block]
enabled = false
ban_duration = "24h"

[defaults.pow_challenge]
enabled = false
difficulty = 10
timeout_secs = 60
window_secs = 300
prefer_wasm = false

[defaults.pow_challenge.block]
enabled = false
ban_duration = "1h"

[defaults.challenge]
priority = "pow_then_css"

[defaults.auth]

[defaults.bot]
block_ai_crawlers = false
enable_css_honeypot = false
enable_js_challenge = false
known_bots_allow = []
ai_crawlers_block = []
scraper_patterns = []

[defaults.worker_pool]
mode = "shared"
workers = 1
worker_port_base = 9000
auto_scale = false

[defaults.persistence]
enabled = false
data_dir = "{state_dir}"
persist_interval_secs = 60
use_persistent_kv = false

[traffic_shaping]
enabled = false

[traffic_shaping.global]
ingress_max_mb_s = 1024
egress_max_mb_s = 1024
burst_allowance_mb = 1024
burst_refill_ms = 100
attack_mode_multiplier = 1.0

[traffic_shaping.connection_limits]
max_connections = 1000000
max_connections_per_ip = 1000000
connection_queue_size = 1
connection_queue_timeout_ms = 1000
connection_burst = 1

[traffic_shaping.bandwidth]
retention_days = 1
mesh_excluded_from_total = false
monthly_cap_ingress_gb = 0
monthly_cap_egress_gb = 0
action_on_limit = "block"
data_dir = "{state_dir}"

[traffic_shaping.bandwidth.monthly_reset]
mode = "rolling_30_days"

# NOTE: no [tunnel] section is emitted. Even an inert `[tunnel.mesh]`
# table trips the Phase-41 fail-closed capability preflight on minimal
# binaries (mesh feature absent). Tunnelling stays disabled via defaults.
[mimes]
enabled = false
file = ""
"#,
        listen_port = inputs.listen_port,
        origin_port = inputs.origin_port,
        log_dir = log_dir.display(),
        state_dir = state_dir.display(),
        metrics_block = metrics_block,
        header_comment = header_comment,
    )
}

/// Build the site configuration that owns the controlled upstream and
/// applies the policy v1 attack-detection semantics.
pub fn build_site_toml(inputs: &BuildInputs) -> String {
    format!(
        r#"# SynVoid qualification site configuration (auto-generated).
# Eggbench Security Qualification M002 — policy synvoid.eggbench-qualification.v1.

[site]
# Loopback Host forms the qualification driver naturally sends
# (Eggbench targets http://127.0.0.1:<listen-port>, so the Host header is
# `127.0.0.1:<listen-port>`). No forbidden Host override is required:
# the site explicitly accepts the loopback Host.
domains = ["loopback.qualification.local", "127.0.0.1", "127.0.0.1:{listen_port}", "localhost", "localhost:{listen_port}"]

[[site.listen]]
address = "127.0.0.1"
port = {listen_port}
default_server = true

[site.upstream]
default = "http://127.0.0.1:{origin_port}"

# Workstream H: deterministic origin-facing perf paths. Route targets are the
# bare origin: the proxy appends the full request path to the target, so a
# suffixed target would duplicate the path at the origin
# (e.g. /qualbench/small/qualbench/small). Eggbench's origin serves these
# two paths (small response; larger/streaming response) for M002 benign
# performance scenarios. No SynVoid load generator is added.
[site.upstream.routes]
"/qualbench/small" = "http://127.0.0.1:{origin_port}"
"/qualbench/stream" = "http://127.0.0.1:{origin_port}"

[ratelimit]
mode = "isolated"

[ratelimit.ip]
per_second = 1000000
per_minute = 1000000
per_5min = 1000000
per_hour = 1000000

[ratelimit.global]
per_second = 1000000
per_minute = 1000000
max_connections = 1000000

[blocked]
paths = []
use_regex = false
block_methods = []
block_response_code = 403

[attack_detection]
enabled = true
paranoia_level = 2
action = "block"

[attack_detection.sqli]
enabled = true

[attack_detection.xss]
enabled = true

[attack_detection.path_traversal]
enabled = true
custom_patterns = []

[attack_detection.rfi]
enabled = true
custom_patterns = []

[attack_detection.ssrf]
enabled = true
block_private_ips = true
allowed_domains = []
custom_patterns = []

[bot]
inherit = false
block_ai_crawlers = false
enable_js_challenge = false
enable_css_honeypot = false

[css_challenge]
enabled = false

[pow_challenge]
enabled = false

[honeypot]
enabled = false
paths_per_ip = 1
ttl_secs = 60

# Qualification traffic originates from loopback, so the whitelist MUST stay
# empty: whitelisted IPs bypass all WAF checks and would mask Detect cases.
[whitelist]
ips = []
networks = []
user_agents = []

[error_pages]
inherit = false

[logging]
enabled = false
format = "json"

[proxy]
max_response_size = 10485760

[proxy.backend]
type = "upstream"

[worker_pool]
mode = "isolated"

[upload]
enabled = false
max_size = "10MB"
memory_threshold = "10MB"
scan_with_yara = false
yara_failure_policy = "quarantine_on_error"
sandbox_enabled = false
"#,
        origin_port = inputs.origin_port,
        listen_port = inputs.listen_port,
    )
}

// ============================================================================
// High-level export / check
// ============================================================================

pub struct ExportOptions {
    pub output_dir: PathBuf,
    pub listen_port: u16,
    pub origin_port: u16,
    /// M003 telemetry: when `Some`, the supervisor-side Prometheus
    /// exporter is enabled on this loopback port. None preserves the
    /// closed M002 v1 export semantics (metrics disabled, no telemetry
    /// artifacts, no provenance extension).
    pub metrics_port: Option<u16>,
    pub run_configtest: bool,
    pub configtest_binary: Option<PathBuf>,
}

impl std::fmt::Debug for ExportOptions {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ExportOptions")
            .field("output_dir", &self.output_dir)
            .field("listen_port", &self.listen_port)
            .field("origin_port", &self.origin_port)
            .field("metrics_port", &self.metrics_port)
            .field("run_configtest", &self.run_configtest)
            .field(
                "configtest_binary",
                &self
                    .configtest_binary
                    .as_ref()
                    .map(|p| p.display().to_string()),
            )
            .finish()
    }
}

pub fn run_export(opts: ExportOptions, workspace: &Path) -> Result<BuildOutputs> {
    if opts.listen_port == 0 {
        return Err(MaterializerError::Invalid(
            "listen_port must be non-zero".to_string(),
        ));
    }
    if opts.origin_port == 0 {
        return Err(MaterializerError::Invalid(
            "origin_port must be non-zero".to_string(),
        ));
    }
    if let Some(metrics_port) = opts.metrics_port {
        if metrics_port == 0 {
            return Err(MaterializerError::Invalid(
                "metrics_port must be non-zero when provided".to_string(),
            ));
        }
        if metrics_port == opts.listen_port {
            return Err(MaterializerError::Invalid(format!(
                "metrics_port {} must differ from listen-port (port collision)",
                metrics_port
            )));
        }
        if metrics_port == opts.origin_port {
            return Err(MaterializerError::Invalid(format!(
                "metrics_port {} must differ from origin-port (port collision)",
                metrics_port
            )));
        }
    }

    let _policy = load_policy(workspace)?;
    let allowlist = load_allowlist(workspace)?;
    let exclusions = load_exclusions(workspace)?;
    let source_fixtures = load_source_fixtures(workspace)?;
    let package_version = synvoid_package_version(workspace)?;
    let git_sha = git_head_sha(workspace)?;

    let cases = build_corpus(&source_fixtures, &allowlist)?;
    if cases.is_empty() {
        return Err(MaterializerError::Invalid(
            "no cases materialized from allowlist".to_string(),
        ));
    }

    let corpus = Corpus {
        schema_version: CORPUS_SCHEMA_VERSION.to_string(),
        policy_id: POLICY_ID.to_string(),
        policy_version: POLICY_VERSION.to_string(),
        synvoid_package_version: package_version.clone(),
        generated_by: format!("{MATERIALIZER_NAME}@{MATERIALIZER_VERSION}"),
        listen_port: opts.listen_port,
        origin_port: opts.origin_port,
        case_count: cases.len(),
        detect_status: DETECT_STATUS,
        pass_status: PASS_STATUS,
        cases: cases.clone(),
    };

    let corpus_bytes = canonical_json(&corpus)?;

    let inputs = BuildInputs {
        workspace,
        listen_port: opts.listen_port,
        origin_port: opts.origin_port,
        package_version: &package_version,
        git_sha: &git_sha,
    };

    let main_toml = build_main_toml(&inputs, &opts.output_dir, opts.metrics_port);
    let site_toml = build_site_toml(&inputs);

    let main_toml_bytes = main_toml.as_bytes().to_vec();
    let site_toml_bytes = site_toml.as_bytes().to_vec();

    // M003 telemetry artifacts (only when `--metrics-port` was supplied).
    let (
        telemetry_contract,
        telemetry_contract_bytes,
        telemetry_mapping,
        telemetry_mapping_bytes,
        telemetry_provenance,
    ) = if let Some(metrics_port) = opts.metrics_port {
        let (mapping, mapping_bytes) = build_telemetry_mapping()?;
        let mapping_sha256 = sha256_hex(&mapping_bytes);
        let (contract, contract_bytes) = build_telemetry_contract(
            metrics_port,
            &package_version,
            &git_sha,
            &mapping_sha256,
            &main_toml_bytes,
        )?;
        let prov = TelemetryProvenanceFields {
            metrics_port,
            contract_digest: contract.contract_digest.clone(),
            mapping_sha256: mapping_sha256.clone(),
            enabled_config_digest: contract.enabled_config_digest.clone(),
        };
        (
            Some(contract),
            Some(contract_bytes),
            Some(mapping),
            Some(mapping_bytes),
            Some(prov),
        )
    } else {
        (None, None, None, None, None)
    };

    let provenance = build_provenance(
        &inputs,
        &cases,
        &exclusions,
        &source_fixtures,
        &main_toml_bytes,
        &site_toml_bytes,
        &corpus_bytes,
        telemetry_provenance.as_ref(),
    )?;

    let config_bundle = ConfigBundle {
        schema_version: CONFIG_SCHEMA_VERSION.to_string(),
        policy_id: POLICY_ID.to_string(),
        policy_version: POLICY_VERSION.to_string(),
        synvoid_package_version: package_version.clone(),
        synvoid_git_sha: git_sha.clone(),
        materializer: format!("{MATERIALIZER_NAME}@{MATERIALIZER_VERSION}"),
        listen_port: opts.listen_port,
        origin_port: opts.origin_port,
    };

    fs::create_dir_all(&opts.output_dir).map_err(io_err)?;
    let config_dir = opts.output_dir.join("config");
    let sites_dir = config_dir.join("sites");
    fs::create_dir_all(&sites_dir).map_err(io_err)?;
    fs::write(config_dir.join("main.toml"), &main_toml_bytes).map_err(io_err)?;
    fs::write(
        sites_dir.join("loopback.qualification.local.toml"),
        &site_toml_bytes,
    )
    .map_err(io_err)?;
    fs::write(opts.output_dir.join("corpus.json"), &corpus_bytes).map_err(io_err)?;
    let provenance_bytes = canonical_json(&provenance)?;
    fs::write(opts.output_dir.join("provenance.json"), &provenance_bytes).map_err(io_err)?;
    let bundle_bytes = canonical_json(&config_bundle)?;
    fs::write(opts.output_dir.join("config_manifest.json"), &bundle_bytes).map_err(io_err)?;

    // M003 telemetry artifacts.
    if let (Some(_contract), Some(contract_bytes)) =
        (&telemetry_contract, &telemetry_contract_bytes)
    {
        fs::write(
            opts.output_dir.join(TELEMETRY_CONTRACT_FILENAME),
            contract_bytes,
        )
        .map_err(io_err)?;
    }
    if let (Some(_mapping), Some(mapping_bytes)) = (&telemetry_mapping, &telemetry_mapping_bytes) {
        fs::write(
            opts.output_dir.join(TELEMETRY_MAPPING_FILENAME),
            mapping_bytes,
        )
        .map_err(io_err)?;
    }

    let outputs = BuildOutputs {
        corpus,
        provenance,
        main_toml,
        site_toml,
        config_bundle,
        telemetry_contract,
        telemetry_mapping,
        telemetry_mapping_bytes,
        telemetry_contract_bytes,
    };

    if opts.run_configtest {
        run_configtest(&opts, workspace)?;
    }

    Ok(outputs)
}

pub struct CheckOptions {
    pub input_dir: PathBuf,
    pub run_configtest: bool,
    pub configtest_binary: Option<PathBuf>,
}

impl std::fmt::Debug for CheckOptions {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CheckOptions")
            .field("input_dir", &self.input_dir)
            .field("run_configtest", &self.run_configtest)
            .field(
                "configtest_binary",
                &self
                    .configtest_binary
                    .as_ref()
                    .map(|p| p.display().to_string()),
            )
            .finish()
    }
}

pub fn run_check(opts: CheckOptions, workspace: &Path) -> Result<()> {
    let input_dir = &opts.input_dir;
    if !input_dir.exists() {
        return Err(MaterializerError::NotFound(format!(
            "input directory not found: {}",
            input_dir.display()
        )));
    }
    let provenance_path = input_dir.join("provenance.json");
    let corpus_path = input_dir.join("corpus.json");
    let main_toml_path = input_dir.join("config/main.toml");
    let site_toml_path = input_dir.join("config/sites/loopback.qualification.local.toml");
    for p in [
        &provenance_path,
        &corpus_path,
        &main_toml_path,
        &site_toml_path,
    ] {
        if !p.exists() {
            return Err(MaterializerError::NotFound(format!(
                "missing materialization artifact: {}",
                p.display()
            )));
        }
    }

    let provenance_bytes = fs::read(&provenance_path).map_err(io_err)?;
    let provenance: Provenance = serde_json::from_slice(&provenance_bytes).map_err(parse_err)?;
    let corpus_bytes = fs::read(&corpus_path).map_err(io_err)?;
    let corpus: Corpus = serde_json::from_slice(&corpus_bytes).map_err(parse_err)?;

    let main_toml = fs::read(&main_toml_path).map_err(io_err)?;
    let site_toml = fs::read(&site_toml_path).map_err(io_err)?;
    let expected_main_sha = sha256_hex(&main_toml);
    let expected_site_sha = sha256_hex(&site_toml);
    let expected_corpus_sha = sha256_hex(&corpus_bytes);

    if provenance.generated_config_sha256 != expected_main_sha {
        return Err(MaterializerError::Invalid(format!(
            "main.toml SHA mismatch: provenance={}, on-disk={}",
            provenance.generated_config_sha256, expected_main_sha
        )));
    }
    if provenance.generated_corpus_sha256 != expected_corpus_sha {
        return Err(MaterializerError::Invalid(format!(
            "corpus SHA mismatch: provenance={}, on-disk={}",
            provenance.generated_corpus_sha256, expected_corpus_sha
        )));
    }
    if provenance.site_config_sha256 != expected_site_sha {
        return Err(MaterializerError::Invalid(format!(
            "site TOML SHA mismatch: provenance={}, on-disk={}",
            provenance.site_config_sha256, expected_site_sha
        )));
    }

    // M003 telemetry artifacts (optional; present iff `--metrics-port`
    // was supplied at export). When present, the provenance extension
    // is required and the contract / mapping / enabled-config digests
    // must match the on-disk artifacts exactly.
    let telemetry_contract_path = input_dir.join(TELEMETRY_CONTRACT_FILENAME);
    let telemetry_mapping_path = input_dir.join(TELEMETRY_MAPPING_FILENAME);
    let telemetry_present = telemetry_contract_path.exists() && telemetry_mapping_path.exists();
    if telemetry_present != provenance.telemetry_contract_digest.is_some() {
        return Err(MaterializerError::Invalid(format!(
            "telemetry artifacts presence mismatch: contract_exists={}, mapping_exists={}, provenance_carries_telemetry={}",
            telemetry_contract_path.exists(),
            telemetry_mapping_path.exists(),
            provenance.telemetry_contract_digest.is_some()
        )));
    }
    if telemetry_present {
        let contract_bytes = fs::read(&telemetry_contract_path).map_err(io_err)?;
        let contract: TelemetryContract =
            serde_json::from_slice(&contract_bytes).map_err(parse_err)?;
        let mapping_bytes = fs::read(&telemetry_mapping_path).map_err(io_err)?;
        let mapping: TelemetryMapping =
            serde_json::from_slice(&mapping_bytes).map_err(parse_err)?;

        let canon_contract = canonical_json(&contract)?;
        if canon_contract != contract_bytes {
            return Err(MaterializerError::Invalid(
                "telemetry-contract.json is not byte-deterministic against canonical re-serialization"
                    .to_string(),
            ));
        }
        let canon_mapping = canonical_json(&mapping)?;
        if canon_mapping != mapping_bytes {
            return Err(MaterializerError::Invalid(
                "telemetry-mapping.json is not byte-deterministic against canonical re-serialization"
                    .to_string(),
            ));
        }

        if contract.contract_id != TELEMETRY_CONTRACT_ID {
            return Err(MaterializerError::Invalid(format!(
                "telemetry contract_id mismatch: expected {}, got {}",
                TELEMETRY_CONTRACT_ID, contract.contract_id
            )));
        }
        if contract.metrics_port != provenance.telemetry_metrics_port.unwrap_or(0) {
            return Err(MaterializerError::Invalid(format!(
                "telemetry metrics_port mismatch: contract={}, provenance={:?}",
                contract.metrics_port, provenance.telemetry_metrics_port
            )));
        }
        // Recompute the contract fingerprint from the file content and
        // compare to the embedded value. This catches tampering that
        // modifies the file but leaves the manifest's digest in place.
        let recomputed = recompute_contract_digest(&contract)?;
        if recomputed != contract.contract_digest {
            return Err(MaterializerError::Invalid(format!(
                "telemetry contract_digest self-check failed: embedded={}, recomputed={}",
                contract.contract_digest, recomputed
            )));
        }
        // Owner manifest must agree with provenance.
        if Some(contract.contract_digest.clone()) != provenance.telemetry_contract_digest {
            return Err(MaterializerError::Invalid(format!(
                "telemetry contract_digest mismatch: contract={}, provenance={:?}",
                contract.contract_digest, provenance.telemetry_contract_digest
            )));
        }
        if Some(sha256_hex(&mapping_bytes)) != provenance.telemetry_mapping_digest {
            return Err(MaterializerError::Invalid(format!(
                "telemetry mapping digest mismatch: actual={}, provenance={:?}",
                sha256_hex(&mapping_bytes),
                provenance.telemetry_mapping_digest
            )));
        }
        if Some(sha256_hex(&main_toml)) != provenance.telemetry_enabled_config_digest {
            return Err(MaterializerError::Invalid(format!(
                "telemetry enabled_config_digest mismatch: actual={}, provenance={:?}",
                sha256_hex(&main_toml),
                provenance.telemetry_enabled_config_digest
            )));
        }
        // Mapping must be exactly the pinned Eggbench v1 shape.
        if mapping.schema_version != TELEMETRY_MAPPING_SCHEMA_VERSION {
            return Err(MaterializerError::Invalid(format!(
                "mapping schema_version mismatch: expected {}, got {}",
                TELEMETRY_MAPPING_SCHEMA_VERSION, mapping.schema_version
            )));
        }
        if mapping.source != "prometheus" {
            return Err(MaterializerError::Invalid(format!(
                "mapping source mismatch: expected prometheus, got {}",
                mapping.source
            )));
        }
        // Mapping fields must cover every required owner metric exactly,
        // with Eggbench trial aggregation (gauges mean|max|min, counters
        // none) and no labels in v2.
        let mut mapped: BTreeMap<&str, &TelemetryMappingField> = BTreeMap::new();
        for f in &mapping.fields {
            if !f.output_name.starts_with("subject_") {
                return Err(MaterializerError::Invalid(format!(
                    "mapping output_name must start with subject_: got {}",
                    f.output_name
                )));
            }
            if !f.labels.is_empty() {
                return Err(MaterializerError::Invalid(format!(
                    "mapping labels must be empty in v2 for {}",
                    f.prometheus_name
                )));
            }
            // Gauge/counter vs trial-aggregation parity (Eggbench rule:
            // gauge iff aggregation is Some).
            let is_gauge = matches!(f.kind, TelemetryMetricKind::Gauge);
            if is_gauge != f.aggregation.is_some() {
                return Err(MaterializerError::Invalid(format!(
                    "mapping aggregation parity violated for {}: kind={:?} aggregation={:?}",
                    f.prometheus_name, f.kind, f.aggregation
                )));
            }
            mapped.insert(&f.prometheus_name, f);
        }
        for &m in TELEMETRY_OWNER_INVENTORY {
            if m.required() {
                let field = mapped.get(m.prometheus_name()).ok_or_else(|| {
                    MaterializerError::Invalid(format!(
                        "telemetry mapping missing required field for {}",
                        m.prometheus_name()
                    ))
                })?;
                if field.kind != m.kind() {
                    return Err(MaterializerError::Invalid(format!(
                        "telemetry mapping kind mismatch for {}: expected {:?}, got {:?}",
                        m.prometheus_name(),
                        m.kind(),
                        field.kind
                    )));
                }
                if field.unit != m.unit() {
                    return Err(MaterializerError::Invalid(format!(
                        "telemetry mapping unit mismatch for {}: expected {}, got {}",
                        m.prometheus_name(),
                        m.unit(),
                        field.unit
                    )));
                }
                if field.aggregation != m.trial_aggregation() {
                    return Err(MaterializerError::Invalid(format!(
                        "telemetry mapping trial aggregation mismatch for {}: expected {:?}, got {:?}",
                        m.prometheus_name(),
                        m.trial_aggregation(),
                        field.aggregation
                    )));
                }
            }
        }
    }

    // Determinism: re-canonicalize the corpus and compare.
    let canon = canonical_json(&corpus)?;
    if canon != corpus_bytes {
        return Err(MaterializerError::Invalid(
            "corpus.json is not byte-deterministic against canonical re-serialization".to_string(),
        ));
    }

    // Allowlist consistency: every corpus case must be unique and
    // sourced from the allowlist.
    let allowlist = load_allowlist(workspace)?;
    let allowlisted_ids: BTreeMap<&str, &AllowlistEntry> =
        allowlist.cases.iter().map(|e| (e.id.as_str(), e)).collect();
    let mut seen = std::collections::HashSet::new();
    for case in &corpus.cases {
        if !seen.insert(case.id.clone()) {
            return Err(MaterializerError::Invalid(format!(
                "duplicate case id: {}",
                case.id
            )));
        }
        if !allowlisted_ids.contains_key(case.id.as_str()) {
            return Err(MaterializerError::Invalid(format!(
                "corpus case {} not in allowlist",
                case.id
            )));
        }
        let entry = allowlisted_ids.get(case.id.as_str()).unwrap();
        if case.category != entry.attack_family {
            return Err(MaterializerError::Invalid(format!(
                "corpus case {} category mismatch (allowlist={}, corpus={})",
                case.id, entry.attack_family, case.category
            )));
        }
        let expected_status = match entry.expected_result.as_str() {
            "detect" => DETECT_STATUS,
            "pass" => PASS_STATUS,
            other => {
                return Err(MaterializerError::Invalid(format!(
                    "unknown expected_result={other}"
                )))
            }
        };
        if case.expected_status != expected_status {
            return Err(MaterializerError::Invalid(format!(
                "corpus case {} expected_status mismatch (allowlist={}, corpus={})",
                case.id, expected_status, case.expected_status
            )));
        }
        validate_corpus_case(case)?;
    }

    // Source fixtures referenced by provenance must exist.
    for sf in &provenance.source_fixtures {
        let rel = PathBuf::from(&sf.relative_path);
        let abs = workspace.join(&rel);
        if !abs.exists() {
            return Err(MaterializerError::NotFound(format!(
                "provenance source fixture missing on disk: {}",
                abs.display()
            )));
        }
        let actual = sha256_file(&abs)?;
        if actual != sf.sha256 {
            return Err(MaterializerError::Invalid(format!(
                "provenance source fixture {} SHA mismatch (expected={}, actual={})",
                sf.id, sf.sha256, actual
            )));
        }
    }

    if opts.run_configtest {
        let export_opts = ExportOptions {
            output_dir: opts.input_dir.clone(),
            listen_port: corpus.listen_port,
            origin_port: corpus.origin_port,
            metrics_port: provenance.telemetry_metrics_port,
            run_configtest: true,
            configtest_binary: opts.configtest_binary.clone(),
        };
        run_configtest(&export_opts, workspace)?;
    }

    Ok(())
}

// ============================================================================
// --configtest invocation
// ============================================================================

pub fn run_configtest(opts: &ExportOptions, workspace: &Path) -> Result<()> {
    let binary = match &opts.configtest_binary {
        Some(b) => b.clone(),
        None => {
            // Default to the workspace target/release/synvoid binary.
            let candidate = workspace.join("target/release/synvoid");
            if !candidate.exists() {
                let debug_candidate = workspace.join("target/debug/synvoid");
                if debug_candidate.exists() {
                    debug_candidate
                } else {
                    return Err(MaterializerError::NotFound(format!(
                        "synvoid binary not found at {} or {}; build with \
                         `cargo build --release --no-default-features` or pass \
                         --configtest-binary",
                        candidate.display(),
                        debug_candidate.display()
                    )));
                }
            } else {
                candidate
            }
        }
    };

    let config_dir = opts.output_dir.join("config");
    if !config_dir.exists() {
        return Err(MaterializerError::NotFound(format!(
            "config dir missing: {}",
            config_dir.display()
        )));
    }

    let status = Command::new(&binary)
        .arg("--configtest")
        .arg("--config-path")
        .arg(&config_dir)
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .status()
        .map_err(|e| MaterializerError::CommandFailed(format!("spawn failed: {e}")))?;

    if !status.success() {
        return Err(MaterializerError::CommandFailed(format!(
            "--configtest exited with non-zero status: {}",
            status
        )));
    }
    Ok(())
}

// ============================================================================
// CLI dispatch
// ============================================================================

#[derive(Debug)]
pub enum Subcommand {
    Export(ExportOptions),
    Check(CheckOptions),
}

pub fn parse_subcommand(args: &[String]) -> Result<Subcommand> {
    // The dispatcher passes the entire argv including the leading
    // "eggbench-qualification" token. Strip it before parsing the
    // `export`/`check` subcommand.
    let args: &[String] = if args.first().map(String::as_str) == Some("eggbench-qualification") {
        &args[1..]
    } else {
        args
    };

    let mut positional: Vec<&str> = Vec::new();
    let mut listen_port: Option<u16> = None;
    let mut origin_port: Option<u16> = None;
    let mut metrics_port: Option<u16> = None;
    let mut output_dir: Option<PathBuf> = None;
    let mut input_dir: Option<PathBuf> = None;
    let mut run_configtest = false;
    let mut configtest_binary: Option<PathBuf> = None;
    let mut json_output = false;

    let mut iter = args.iter().enumerate();
    while let Some((_, a)) = iter.next() {
        match a.as_str() {
            "--listen-port" => {
                if let Some((_, v)) = iter.next() {
                    listen_port = Some(parse_port(v)?);
                }
            }
            "--origin-port" => {
                if let Some((_, v)) = iter.next() {
                    origin_port = Some(parse_port(v)?);
                }
            }
            "--metrics-port" => {
                if let Some((_, v)) = iter.next() {
                    metrics_port = Some(parse_port(v)?);
                }
            }
            "--output" => {
                if let Some((_, v)) = iter.next() {
                    output_dir = Some(PathBuf::from(v));
                }
            }
            "--input" => {
                if let Some((_, v)) = iter.next() {
                    input_dir = Some(PathBuf::from(v));
                }
            }
            "--configtest" => {
                run_configtest = true;
            }
            "--configtest-binary" => {
                if let Some((_, v)) = iter.next() {
                    configtest_binary = Some(PathBuf::from(v));
                }
            }
            "--json" => {
                json_output = true;
            }
            other => {
                if !other.starts_with('-') {
                    positional.push(other);
                }
            }
        }
    }
    let _ = json_output; // Reserved for future structured output.

    match positional.first().copied() {
        Some("export") => Ok(Subcommand::Export(ExportOptions {
            output_dir: output_dir.ok_or_else(|| {
                MaterializerError::Invalid("`export` requires --output <dir>".to_string())
            })?,
            listen_port: listen_port.ok_or_else(|| {
                MaterializerError::Invalid("`export` requires --listen-port <port>".to_string())
            })?,
            origin_port: origin_port.ok_or_else(|| {
                MaterializerError::Invalid("`export` requires --origin-port <port>".to_string())
            })?,
            metrics_port,
            run_configtest,
            configtest_binary,
        })),
        Some("check") => Ok(Subcommand::Check(CheckOptions {
            input_dir: input_dir.ok_or_else(|| {
                MaterializerError::Invalid("`check` requires --input <dir>".to_string())
            })?,
            run_configtest,
            configtest_binary,
        })),
        Some(other) => Err(MaterializerError::Invalid(format!(
            "unknown subcommand: {other}"
        ))),
        None => Err(MaterializerError::Invalid(
            "missing subcommand (expected: export|check)".to_string(),
        )),
    }
}

fn parse_port(s: &str) -> Result<u16> {
    s.parse::<u16>()
        .map_err(|e| MaterializerError::Invalid(format!("invalid port value {s:?}: {e}")))
}

pub fn run(args: &[String]) -> Result<String> {
    let sub = parse_subcommand(args)?;
    let workspace = find_workspace_root()?;
    match sub {
        Subcommand::Export(opts) => {
            let outputs = run_export(opts, &workspace)?;
            Ok(format!(
                "exported corpus ({} cases) and provenance to {}\npolicy_id: {}\nsynvoid: {}\ngit_sha: {}",
                outputs.corpus.cases.len(),
                workspace.display(),
                outputs.corpus.policy_id,
                outputs.corpus.synvoid_package_version,
                outputs.provenance.synvoid_git_sha,
            ))
        }
        Subcommand::Check(opts) => {
            run_check(opts, &workspace)?;
            Ok("check ok".to_string())
        }
    }
}

// ============================================================================
// Tests (Workstream F: self-qualification)
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    fn workspace() -> PathBuf {
        find_workspace_root().expect("workspace root")
    }

    #[test]
    fn policy_loads_and_matches_id() {
        let policy = load_policy(&workspace()).expect("policy load");
        assert_eq!(policy.policy_id, POLICY_ID);
        assert_eq!(
            policy.live_status_mapping.get("detect").copied(),
            Some(DETECT_STATUS)
        );
        assert_eq!(
            policy.live_status_mapping.get("pass").copied(),
            Some(PASS_STATUS)
        );
    }

    #[test]
    fn allowlist_loads_and_matches_id() {
        let allowlist = load_allowlist(&workspace()).expect("allowlist load");
        assert_eq!(allowlist.policy_id, POLICY_ID);
        assert!(!allowlist.cases.is_empty());
        let mut ids: Vec<String> = allowlist.cases.iter().map(|c| c.id.clone()).collect();
        ids.sort();
        let unique: HashSet<&String> = ids.iter().collect();
        assert_eq!(unique.len(), ids.len(), "duplicate ids in allowlist");
    }

    #[test]
    fn exclusions_load_and_match_id() {
        let exclusions = load_exclusions(&workspace()).expect("exclusions load");
        assert_eq!(exclusions.policy_id, POLICY_ID);
        assert!(!exclusions.exclusions.is_empty());
        let ids: HashSet<String> = exclusions.exclusions.iter().map(|e| e.id.clone()).collect();
        assert_eq!(
            ids.len(),
            exclusions.exclusions.len(),
            "duplicate ids in exclusions"
        );
    }

    #[test]
    fn allowlist_and_exclusions_do_not_overlap() {
        let allowlist = load_allowlist(&workspace()).unwrap();
        let exclusions = load_exclusions(&workspace()).unwrap();
        let allow: HashSet<&str> = allowlist.cases.iter().map(|c| c.id.as_str()).collect();
        for ex in &exclusions.exclusions {
            assert!(
                !allow.contains(ex.id.as_str()),
                "fixture {} appears in both allowlist and exclusions",
                ex.id
            );
        }
    }

    #[test]
    fn every_allowlisted_fixture_exists_and_parses() {
        let allowlist = load_allowlist(&workspace()).unwrap();
        let fixtures = load_source_fixtures(&workspace()).unwrap();
        let ids: HashSet<&str> = fixtures.iter().map(|f| f.raw.id.as_str()).collect();
        for entry in &allowlist.cases {
            assert!(
                ids.contains(entry.id.as_str()),
                "allowlisted fixture {} not present in source",
                entry.id
            );
        }
    }

    #[test]
    fn every_excluded_fixture_actually_exists() {
        let exclusions = load_exclusions(&workspace()).unwrap();
        let fixtures = load_source_fixtures(&workspace()).unwrap();
        let ids: HashSet<&str> = fixtures.iter().map(|f| f.raw.id.as_str()).collect();
        for ex in &exclusions.exclusions {
            assert!(
                ids.contains(ex.id.as_str()),
                "excluded fixture {} not present in source corpus (manifest drift)",
                ex.id
            );
        }
    }

    #[test]
    fn corpus_export_is_deterministic_and_unique() {
        let allowlist = load_allowlist(&workspace()).unwrap();
        let fixtures = load_source_fixtures(&workspace()).unwrap();
        let cases_a = build_corpus(&fixtures, &allowlist).unwrap();
        let cases_b = build_corpus(&fixtures, &allowlist).unwrap();
        assert_eq!(cases_a.len(), cases_b.len());
        for (a, b) in cases_a.iter().zip(cases_b.iter()) {
            assert_eq!(a, b);
        }
        let ids: HashSet<&String> = cases_a.iter().map(|c| &c.id).collect();
        assert_eq!(ids.len(), cases_a.len(), "duplicate ids in corpus");
    }

    #[test]
    fn corpus_export_satisfies_header_contract() {
        let allowlist = load_allowlist(&workspace()).unwrap();
        let fixtures = load_source_fixtures(&workspace()).unwrap();
        let cases = build_corpus(&fixtures, &allowlist).unwrap();
        for case in &cases {
            validate_corpus_case(case)
                .unwrap_or_else(|e| panic!("case {} violates corpus contract: {e}", case.id));
        }
    }

    #[test]
    fn build_corpus_rejects_missing_allowlist_entries() {
        let bad_allowlist = Allowlist {
            policy_id: POLICY_ID.to_string(),
            description: "test".to_string(),
            cases: vec![AllowlistEntry {
                id: "definitely_not_a_real_fixture".to_string(),
                attack_family: "none".to_string(),
                expected_result: "pass".to_string(),
                rationale: "synthetic".to_string(),
            }],
        };
        let fixtures = load_source_fixtures(&workspace()).unwrap();
        let err = build_corpus(&fixtures, &bad_allowlist).unwrap_err();
        match err {
            MaterializerError::NotFound(_) => {}
            other => panic!("expected NotFound, got {other:?}"),
        }
    }

    #[test]
    fn policy_mapping_is_exhaustive_for_detect_pass() {
        let policy = load_policy(&workspace()).unwrap();
        assert!(policy.live_status_mapping.contains_key("detect"));
        assert!(policy.live_status_mapping.contains_key("pass"));
        assert_eq!(policy.live_status_mapping.len(), 2);
    }

    #[test]
    fn changing_selected_fixture_changes_provenance() {
        // Synthesize a tweak to a fixture's expected_result and assert
        // that the manifest SHA-256 of the modified fixture differs
        // from the original. This proves the manifest is sensitive to
        // fixture changes.
        let fixtures = load_source_fixtures(&workspace()).unwrap();
        let sample = fixtures
            .iter()
            .find(|f| f.raw.id == "benign_query_strings")
            .expect("benign_query_strings fixture must exist");
        let original_bytes = fs::read(&sample.source_path).unwrap();
        let original_sha = sha256_hex(&original_bytes);
        let mutated = String::from_utf8(original_bytes.clone())
            .unwrap()
            .replace("\"pass\"", "\"detect\"");
        let mutated_sha = sha256_hex(mutated.as_bytes());
        assert_ne!(original_sha, mutated_sha);
    }

    #[test]
    fn config_binds_loopback_only_and_carries_requested_ports() {
        let package_version = synvoid_package_version(&workspace()).unwrap();
        let git_sha = git_head_sha(&workspace()).unwrap();
        let inputs = BuildInputs {
            workspace: &workspace(),
            listen_port: 18181,
            origin_port: 18282,
            package_version: &package_version,
            git_sha: &git_sha,
        };
        let output_dir = workspace().join("target/eggbench_qualification_test");
        let main_toml = build_main_toml(&inputs, &output_dir, None);
        let site_toml = build_site_toml(&inputs);

        // Loopback-only: only 127.0.0.1, no 0.0.0.0 / public binds.
        assert!(
            main_toml.contains("host = \"127.0.0.1\""),
            "main.toml must bind loopback"
        );
        assert!(
            !main_toml.contains("host = \"0.0.0.0\""),
            "main.toml must not bind public"
        );
        assert!(
            main_toml.contains("port = 18181"),
            "main.toml must carry the listen port"
        );
        assert!(
            !main_toml.contains("port = 18282"),
            "main.toml must not carry the origin port as the listen port"
        );
        assert!(
            site_toml.contains("default = \"http://127.0.0.1:18282\""),
            "site.toml must target the loopback origin"
        );
        assert!(
            !site_toml.contains("0.0.0.0"),
            "site.toml must not bind public"
        );
        // Loopback Host acceptance: the natural Host the driver sends
        // (`127.0.0.1:<listen-port>`) must be an explicit site domain, and
        // the site must be the default server on its loopback listen entry.
        assert!(
            site_toml.contains("\"127.0.0.1:18181\""),
            "site.toml must accept the loopback Host with port"
        );
        assert!(
            site_toml.contains("[[site.listen]]"),
            "site.toml must declare its loopback listen entry"
        );
        assert!(
            site_toml.contains("default_server = true"),
            "site.toml listen entry must be the default server"
        );
        // The whitelist must stay empty: whitelisted IPs bypass all WAF
        // checks, which would mask Detect cases driven from loopback.
        assert!(
            site_toml.contains("[whitelist]\nips = []"),
            "site.toml whitelist must be empty"
        );
        assert!(
            site_toml.contains("action = \"block\""),
            "site.toml must configure the policy-v1 block action"
        );

        // Admin disabled, metrics disabled, no IP feeds, no traffic shaping.
        assert!(main_toml.contains("[admin]\nenabled = false"));
        assert!(main_toml.contains("[metrics]\nenabled = false"));
        assert!(main_toml.contains("[ip_feeds]\nenabled = false"));
        assert!(main_toml.contains("[traffic_shaping]\nenabled = false"));
    }

    #[test]
    fn canonical_json_sorts_keys() {
        let mut a = serde_json::Map::new();
        a.insert("z".to_string(), serde_json::json!(1));
        a.insert("a".to_string(), serde_json::json!(2));
        let mut b = serde_json::Map::new();
        b.insert("a".to_string(), serde_json::json!(2));
        b.insert("z".to_string(), serde_json::json!(1));
        let va = serde_json::Value::Object(a);
        let vb = serde_json::Value::Object(b);
        let ca = canonical_json(&va).unwrap();
        let cb = canonical_json(&vb).unwrap();
        assert_eq!(ca, cb);
    }

    #[test]
    fn end_to_end_export_then_check_is_internal_coherent() {
        let allowlist = load_allowlist(&workspace()).unwrap();
        let exclusions = load_exclusions(&workspace()).unwrap();
        let package_version = synvoid_package_version(&workspace()).unwrap();
        let git_sha = git_head_sha(&workspace()).unwrap();

        let source_fixtures = load_source_fixtures(&workspace()).unwrap();
        let cases = build_corpus(&source_fixtures, &allowlist).unwrap();
        let corpus = Corpus {
            schema_version: CORPUS_SCHEMA_VERSION.to_string(),
            policy_id: POLICY_ID.to_string(),
            policy_version: POLICY_VERSION.to_string(),
            synvoid_package_version: package_version.clone(),
            generated_by: format!("{MATERIALIZER_NAME}@{MATERIALIZER_VERSION}"),
            listen_port: 18444,
            origin_port: 18555,
            case_count: cases.len(),
            detect_status: DETECT_STATUS,
            pass_status: PASS_STATUS,
            cases: cases.clone(),
        };
        let corpus_bytes = canonical_json(&corpus).unwrap();

        let inputs = BuildInputs {
            workspace: &workspace(),
            listen_port: 18444,
            origin_port: 18555,
            package_version: &package_version,
            git_sha: &git_sha,
        };
        let output_dir = workspace().join("target/eggbench_qualification_e2e");
        let main_toml = build_main_toml(&inputs, &output_dir, None);
        let site_toml = build_site_toml(&inputs);
        let main_bytes = main_toml.as_bytes().to_vec();
        let site_bytes = site_toml.as_bytes().to_vec();

        let provenance = build_provenance(
            &inputs,
            &cases,
            &exclusions,
            &source_fixtures,
            &main_bytes,
            &site_bytes,
            &corpus_bytes,
            None,
        )
        .unwrap();

        // Reconstruct the artifacts under the output dir.
        let _ = fs::remove_dir_all(&output_dir);
        fs::create_dir_all(&output_dir).unwrap();
        let config_dir = output_dir.join("config");
        let sites_dir = config_dir.join("sites");
        fs::create_dir_all(&sites_dir).unwrap();
        fs::write(config_dir.join("main.toml"), &main_bytes).unwrap();
        fs::write(
            sites_dir.join("loopback.qualification.local.toml"),
            &site_bytes,
        )
        .unwrap();
        fs::write(output_dir.join("corpus.json"), &corpus_bytes).unwrap();
        let provenance_bytes = canonical_json(&provenance).unwrap();
        fs::write(output_dir.join("provenance.json"), &provenance_bytes).unwrap();

        // Check must succeed without running --configtest (binary may not be built in test).
        let check_opts = CheckOptions {
            input_dir: output_dir.clone(),
            run_configtest: false,
            configtest_binary: None,
        };
        run_check(check_opts, &workspace()).expect("check must succeed");

        let _ = fs::remove_dir_all(&output_dir);
    }

    #[test]
    fn excluded_fixture_is_not_silently_exported() {
        let allowlist = load_allowlist(&workspace()).unwrap();
        let fixtures = load_source_fixtures(&workspace()).unwrap();
        let cases = build_corpus(&fixtures, &allowlist).unwrap();
        let exported_ids: HashSet<String> = cases.iter().map(|c| c.id.clone()).collect();
        for forbidden in [
            "raw_cl_te_smuggling",
            "cl_te_smuggling_detected",
            "chunk_boundary_split",
            "normal_basic_auth_failure",
            "normal_admin_auth_failure",
            "normal_binary_upload",
            "normal_multipart_upload",
            "multipart_field_attack",
            "serverless_route_bypass",
            "cache_purge_auth",
            "xff_external_ip_attack",
            "xff_trusted_proxy_chain",
        ] {
            assert!(
                !exported_ids.contains(forbidden),
                "excluded fixture {} must not appear in v1 corpus",
                forbidden
            );
        }
    }

    // ----------------------------------------------------------------
    // M003 telemetry contract self-tests
    // ----------------------------------------------------------------

    fn temp_dir(label: &str) -> PathBuf {
        let dir = workspace().join(format!(
            "target/eggbench_m003_{label}_{}_{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        ));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn telemetry_contract_inventory_is_stable_and_underscore_only() {
        let names: Vec<&'static str> = TELEMETRY_OWNER_INVENTORY
            .iter()
            .map(|m| m.prometheus_name())
            .collect();
        // Pin order exactly.
        assert_eq!(
            names,
            vec![
                "synvoid_subject_event_loop_lag_ms",
                "synvoid_subject_request_queue_p95_ms",
                "synvoid_subject_active_connections",
                "synvoid_subject_worker_memory_bytes",
                "synvoid_subject_worker_cpu_percent",
                "synvoid_subject_body_buffering_bytes_total",
                "synvoid_subject_offload_submissions_total",
                "synvoid_subject_offload_timeouts_total",
                "synvoid_subject_offload_rejections_total",
                "synvoid_subject_offload_fallbacks_total",
                "synvoid_subject_cpu_worker_rss_bytes",
                "synvoid_subject_worker_metric_resets_total",
            ]
        );
        for n in names {
            assert!(n.is_ascii());
            assert!(n.starts_with("synvoid_subject_"));
            assert!(
                !n.contains('-'),
                "name {n:?} contains hyphen (sanitization risk)"
            );
        }
    }

    #[test]
    fn telemetry_owner_inventory_partition_matches_bridge() {
        let required = TELEMETRY_OWNER_INVENTORY
            .iter()
            .filter(|m| m.required())
            .count();
        let optional = TELEMETRY_OWNER_INVENTORY
            .iter()
            .filter(|m| !m.required())
            .count();
        assert_eq!(required, 10, "10 required metrics in v2");
        assert_eq!(optional, 2, "CPU-worker RSS + resets optional");
    }

    #[test]
    fn telemetry_mapping_is_exactly_eggbench_v1_compatible() {
        // Local DTO structurally identical to pinned Eggbench
        // `PrometheusMappingV1`: numeric schema_version, deny_unknown_fields,
        // no contract_id, gauge-only trial aggregation, no labels.
        let (mapping, mapping_bytes) = build_telemetry_mapping().unwrap();
        assert_eq!(mapping.schema_version, 1);
        assert_eq!(mapping.schema_version, TELEMETRY_MAPPING_SCHEMA_VERSION);
        assert_eq!(mapping.source, "prometheus");
        // No unknown top-level fields: re-parse with a strict local DTO.
        #[derive(serde::Deserialize)]
        #[serde(deny_unknown_fields)]
        struct StrictMapping {
            schema_version: u32,
            source: String,
            fields: Vec<StrictField>,
        }
        #[derive(serde::Deserialize)]
        #[serde(deny_unknown_fields)]
        struct StrictField {
            output_name: String,
            prometheus_name: String,
            kind: String,
            unit: String,
            #[serde(default)]
            aggregation: Option<String>,
            #[serde(default)]
            labels: std::collections::BTreeMap<String, String>,
            #[serde(default)]
            required: bool,
        }
        let strict: StrictMapping = serde_json::from_slice(&mapping_bytes).expect("strict parse");
        assert_eq!(strict.schema_version, 1);
        assert_eq!(strict.source, "prometheus");
        assert_eq!(strict.fields.len(), TELEMETRY_OWNER_INVENTORY.len());
        // Raw JSON must not contain the withdrawn owner keys.
        let raw = String::from_utf8(mapping_bytes.clone()).unwrap();
        assert!(
            !raw.contains("contract_id"),
            "mapping must not carry contract_id"
        );
        assert!(
            !raw.contains("source_aggregation"),
            "mapping must not carry owner source aggregation"
        );
        assert!(
            !raw.contains("supervisor_lifetime_monotonic_bridge"),
            "mapping must not carry owner bridge vocabulary"
        );
        assert!(
            !raw.contains("latest_ready"),
            "mapping must not carry latest_ready"
        );
        assert!(!raw.contains("\"sum\""), "mapping must not carry owner sum");
    }

    #[test]
    fn telemetry_owner_manifest_distinguishes_source_aggregation() {
        let (_, mapping_bytes) = build_telemetry_mapping().unwrap();
        let (contract, _) =
            build_telemetry_contract(19191, "1.1.0", "deadbeef", &sha256_hex(&mapping_bytes), b"")
                .unwrap();
        assert_eq!(contract.contract_id, TELEMETRY_CONTRACT_ID);
        assert_eq!(
            contract.schema_version, TELEMETRY_CONTRACT_SCHEMA_VERSION,
            "owner schema must be v2"
        );
        // Owner manifest uses source_aggregation, never bare aggregation.
        let raw = canonical_json(&contract).unwrap();
        let raw_str = String::from_utf8(raw).unwrap();
        assert!(raw_str.contains("source_aggregation"));
        // Body buffering is bytes; offload/reset counters are count.
        let mut by_name = BTreeMap::new();
        for m in &contract.metrics {
            by_name.insert(m.prometheus_name.as_str(), m);
        }
        assert_eq!(
            by_name
                .get("synvoid_subject_body_buffering_bytes_total")
                .unwrap()
                .unit,
            "bytes"
        );
        for name in [
            "synvoid_subject_offload_submissions_total",
            "synvoid_subject_offload_timeouts_total",
            "synvoid_subject_offload_rejections_total",
            "synvoid_subject_offload_fallbacks_total",
            "synvoid_subject_worker_metric_resets_total",
        ] {
            assert_eq!(by_name.get(name).unwrap().unit, "count", "unit for {name}");
        }
    }

    #[test]
    fn telemetry_contract_and_mapping_are_deterministic_and_digest_stable() {
        let (m1, m1_bytes) = build_telemetry_mapping().unwrap();
        let (m2, m2_bytes) = build_telemetry_mapping().unwrap();
        assert_eq!(m1_bytes, m2_bytes);
        assert_eq!(m1.schema_version, 1);
        assert_eq!(m1.source, "prometheus");
        let (c1, c1_bytes) =
            build_telemetry_contract(19191, "1.1.0", "deadbeef", &sha256_hex(&m1_bytes), b"")
                .unwrap();
        let (c2, c2_bytes) =
            build_telemetry_contract(19191, "1.1.0", "deadbeef", &sha256_hex(&m1_bytes), b"")
                .unwrap();
        assert_eq!(c1_bytes, c2_bytes);
        // The embedded digest matches the SHA-256 of the canonical
        // serialization with the digest field cleared — i.e. it is a
        // content-addressed fingerprint, not a self-reference.
        let recomputed = recompute_contract_digest(&c1).unwrap();
        assert_eq!(recomputed, c1.contract_digest);
        assert_eq!(c1.contract_id, TELEMETRY_CONTRACT_ID);
        assert_eq!(c1.metrics_port, 19191);
        assert_eq!(
            c1.scrape_url,
            format!("http://127.0.0.1:19191{TELEMETRY_SCRAPE_PATH}")
        );
        assert_eq!(
            c1.source_refresh_cadence_secs,
            TELEMETRY_SOURCE_REFRESH_CADENCE_SECS
        );
    }

    #[test]
    fn telemetry_mapping_covers_required_owner_metrics_with_matching_kind_and_unit() {
        let (mapping, _) = build_telemetry_mapping().unwrap();
        let mut by_name: BTreeMap<&str, &TelemetryMappingField> = BTreeMap::new();
        for f in &mapping.fields {
            by_name.insert(f.prometheus_name.as_str(), f);
        }
        for &m in TELEMETRY_OWNER_INVENTORY {
            if m.required() {
                let f = by_name
                    .get(m.prometheus_name())
                    .expect("required mapping missing");
                assert_eq!(f.kind, m.kind(), "kind for {}", m.prometheus_name());
                assert_eq!(f.unit, m.unit(), "unit for {}", m.prometheus_name());
                assert_eq!(
                    f.aggregation,
                    m.trial_aggregation(),
                    "trial aggregation for {}",
                    m.prometheus_name()
                );
                assert!(f.required, "required flag for {}", m.prometheus_name());
                assert!(f.labels.is_empty(), "no labels in v2");
                assert!(
                    f.output_name.starts_with("subject_"),
                    "output must start with subject_"
                );
            }
            // Counter/trial-aggregation parity for every field.
            let f = by_name.get(m.prometheus_name()).unwrap();
            assert_eq!(
                matches!(f.kind, TelemetryMetricKind::Gauge),
                f.aggregation.is_some(),
                "gauge iff aggregation for {}",
                m.prometheus_name()
            );
        }
        // Eggbench output names are subject_<suffix> — pin a sample.
        assert_eq!(
            by_name
                .get("synvoid_subject_event_loop_lag_ms")
                .unwrap()
                .output_name,
            "subject_event_loop_lag_ms"
        );
        assert_eq!(
            by_name
                .get("synvoid_subject_offload_fallbacks_total")
                .unwrap()
                .output_name,
            "subject_offload_fallbacks_total"
        );
    }

    #[test]
    fn telemetry_off_export_remains_compatible_and_emits_no_telemetry_artifacts() {
        let allowlist = load_allowlist(&workspace()).unwrap();
        let exclusions = load_exclusions(&workspace()).unwrap();
        let package_version = synvoid_package_version(&workspace()).unwrap();
        let git_sha = git_head_sha(&workspace()).unwrap();
        let source_fixtures = load_source_fixtures(&workspace()).unwrap();

        let dir = temp_dir("off");
        let opts = ExportOptions {
            output_dir: dir.clone(),
            listen_port: 28700,
            origin_port: 28800,
            metrics_port: None,
            run_configtest: false,
            configtest_binary: None,
        };
        let _outputs = run_export(opts, &workspace()).unwrap();
        assert!(
            !dir.join(TELEMETRY_CONTRACT_FILENAME).exists(),
            "telemetry contract must not be emitted without --metrics-port"
        );
        assert!(
            !dir.join(TELEMETRY_MAPPING_FILENAME).exists(),
            "telemetry mapping must not be emitted without --metrics-port"
        );
        let main_toml = fs::read_to_string(dir.join("config/main.toml")).unwrap();
        assert!(main_toml.contains("[metrics]\nenabled = false"));
        // The closed M002 v1 form is preserved (admin disabled, no metrics port leak).
        assert!(main_toml.contains("[admin]\nenabled = false"));

        let provenance_bytes = fs::read_to_string(dir.join("provenance.json")).unwrap();
        let provenance: Provenance = serde_json::from_str(&provenance_bytes).unwrap();
        assert!(provenance.telemetry_metrics_port.is_none());
        assert!(provenance.telemetry_contract_digest.is_none());

        // No-telemetry check must succeed.
        let check_opts = CheckOptions {
            input_dir: dir.clone(),
            run_configtest: false,
            configtest_binary: None,
        };
        run_check(check_opts, &workspace()).expect("telemetry-off check must succeed");
        let _ = fs::remove_dir_all(&dir);
        let _ = (
            allowlist,
            exclusions,
            package_version,
            git_sha,
            source_fixtures,
        );
    }

    #[test]
    fn telemetry_on_export_emits_contract_and_mapping_and_extensions_provenance() {
        let dir = temp_dir("on");
        let opts = ExportOptions {
            output_dir: dir.clone(),
            listen_port: 28710,
            origin_port: 28810,
            metrics_port: Some(28910),
            run_configtest: false,
            configtest_binary: None,
        };
        let outputs = run_export(opts, &workspace()).unwrap();
        let telemetry_contract = outputs.telemetry_contract.expect("contract");
        let telemetry_mapping = outputs.telemetry_mapping.expect("mapping");
        assert_eq!(telemetry_contract.contract_id, TELEMETRY_CONTRACT_ID);
        assert_eq!(telemetry_contract.metrics_port, 28910);
        assert_eq!(
            telemetry_contract.mapping_sha256,
            sha256_hex(outputs.telemetry_mapping_bytes.as_ref().unwrap())
        );
        assert_eq!(telemetry_mapping.schema_version, 1);
        assert_eq!(telemetry_mapping.source, "prometheus");

        // Mapped files exist on disk.
        let contract_bytes = fs::read(dir.join(TELEMETRY_CONTRACT_FILENAME)).unwrap();
        let mapping_bytes = fs::read(dir.join(TELEMETRY_MAPPING_FILENAME)).unwrap();
        // The on-disk contract bytes include the populated digest
        // field; the contract_digest is the SHA-256 of the canonical
        // representation with the digest field cleared. Recompute and
        // compare.
        let contract_from_disk: TelemetryContract =
            serde_json::from_slice(&contract_bytes).unwrap();
        let recomputed = recompute_contract_digest(&contract_from_disk).unwrap();
        assert_eq!(recomputed, contract_from_disk.contract_digest);
        assert_eq!(recomputed, telemetry_contract.contract_digest);
        assert_eq!(
            sha256_hex(&mapping_bytes),
            telemetry_contract.mapping_sha256
        );

        let main_toml = fs::read_to_string(dir.join("config/main.toml")).unwrap();
        assert!(main_toml.contains("port = 28910"));
        assert!(main_toml.contains("[metrics]\nenabled = true"));
        assert!(main_toml.contains("bind_address = \"127.0.0.1\""));
        // Admin remains disabled even when telemetry is enabled.
        assert!(main_toml.contains("[admin]\nenabled = false"));

        let provenance_bytes = fs::read_to_string(dir.join("provenance.json")).unwrap();
        let provenance: Provenance = serde_json::from_str(&provenance_bytes).unwrap();
        assert_eq!(provenance.telemetry_metrics_port, Some(28910));
        assert_eq!(
            provenance.telemetry_contract_id.as_deref(),
            Some(TELEMETRY_CONTRACT_ID)
        );
        assert_eq!(
            provenance.telemetry_contract_digest.as_deref(),
            Some(telemetry_contract.contract_digest.as_str())
        );
        assert_eq!(
            provenance.telemetry_mapping_digest.as_deref(),
            Some(telemetry_contract.mapping_sha256.as_str())
        );
        assert_eq!(
            provenance.telemetry_enabled_config_digest.as_deref(),
            Some(telemetry_contract.enabled_config_digest.as_str())
        );

        let check_opts = CheckOptions {
            input_dir: dir.clone(),
            run_configtest: false,
            configtest_binary: None,
        };
        run_check(check_opts, &workspace()).expect("telemetry-on check must succeed");
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn telemetry_on_export_rejects_metrics_port_collision() {
        let dir = temp_dir("collision");
        let opts = ExportOptions {
            output_dir: dir.clone(),
            listen_port: 28720,
            origin_port: 28820,
            metrics_port: Some(28720), // collides with listen
            run_configtest: false,
            configtest_binary: None,
        };
        let err = run_export(opts, &workspace()).unwrap_err();
        let msg = format!("{err}");
        assert!(msg.contains("metrics_port"), "err message: {msg}");
        let _ = fs::remove_dir_all(&dir);

        let dir2 = temp_dir("collision_origin");
        let opts2 = ExportOptions {
            output_dir: dir2.clone(),
            listen_port: 28730,
            origin_port: 28830,
            metrics_port: Some(28830), // collides with origin
            run_configtest: false,
            configtest_binary: None,
        };
        let err2 = run_export(opts2, &workspace()).unwrap_err();
        let msg2 = format!("{err2}");
        assert!(msg2.contains("metrics_port"), "err message: {msg2}");
        let _ = fs::remove_dir_all(&dir2);
    }

    #[test]
    fn telemetry_check_detects_contract_tampering() {
        let dir = temp_dir("tamper");
        let opts = ExportOptions {
            output_dir: dir.clone(),
            listen_port: 28740,
            origin_port: 28840,
            metrics_port: Some(28940),
            run_configtest: false,
            configtest_binary: None,
        };
        let _outputs = run_export(opts, &workspace()).unwrap();

        // Tamper with the contract: rewrite metrics_port. The
        // recompute-on-check will detect the digest mismatch.
        let contract_path = dir.join(TELEMETRY_CONTRACT_FILENAME);
        let original = fs::read_to_string(&contract_path).unwrap();
        let mut v: serde_json::Value = serde_json::from_str(&original).unwrap();
        v["metrics_port"] = serde_json::json!(39999);
        fs::write(&contract_path, serde_json::to_vec(&v).unwrap()).unwrap();

        let check_opts = CheckOptions {
            input_dir: dir.clone(),
            run_configtest: false,
            configtest_binary: None,
        };
        let err = run_check(check_opts, &workspace()).unwrap_err();
        let msg = format!("{err}");
        assert!(
            msg.contains("digest") || msg.contains("metrics_port"),
            "check should report tamper, got: {msg}"
        );
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn telemetry_check_detects_main_toml_tampering() {
        let dir = temp_dir("tamper_main");
        let opts = ExportOptions {
            output_dir: dir.clone(),
            listen_port: 28750,
            origin_port: 28850,
            metrics_port: Some(28950),
            run_configtest: false,
            configtest_binary: None,
        };
        let _outputs = run_export(opts, &workspace()).unwrap();

        // Tamper with main.toml by adding a top-level unauthorized section.
        let main_path = dir.join("config/main.toml");
        let mut text = fs::read_to_string(&main_path).unwrap();
        text.push_str("\n[admin]\nenabled = true\n");
        fs::write(&main_path, text).unwrap();

        let check_opts = CheckOptions {
            input_dir: dir.clone(),
            run_configtest: false,
            configtest_binary: None,
        };
        let err = run_check(check_opts, &workspace()).unwrap_err();
        let msg = format!("{err}");
        assert!(
            msg.contains("SHA mismatch") || msg.contains("enabled_config_digest"),
            "expected main.toml tamper detection, got: {msg}"
        );
        let _ = fs::remove_dir_all(&dir);
    }
}
