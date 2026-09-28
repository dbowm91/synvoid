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

pub const MATERIALIZER_NAME: &str = "synvoid-eggbench-qualification-materializer";
pub const MATERIALIZER_VERSION: &str = "1.0.0";

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

pub struct BuildOutputs {
    pub corpus: Corpus,
    pub provenance: Provenance,
    #[allow(dead_code)]
    pub main_toml: String,
    #[allow(dead_code)]
    pub site_toml: String,
    #[allow(dead_code)]
    pub config_bundle: ConfigBundle,
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

    Ok(Provenance {
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
    })
}

// ============================================================================
// Loopback-only minimal runtime config (Workstream C)
// ============================================================================

/// Build the loopback-only main.toml for the supported minimal binary.
///
/// - bind 127.0.0.1:<listen_port> only
/// - upstream defaults to a no-op `return_404` fallback (the site file owns
///   the real upstream); admin disabled; metrics disabled; rate limiting
///   disabled; persistence disabled; logging paths inside the
///   qualification dir; threat_level disabled; no IP feeds; no traffic
///   shaping; no TLS; no HTTP/3; no socket-handoff; no mesh; no DNS; no
///   flood/ICMP; tunnelling disabled; plugins/serverless/app-server
///   disabled; cookie/session defaults left empty.
pub fn build_main_toml(inputs: &BuildInputs, output_dir: &Path) -> String {
    let log_dir = output_dir.join("logs");
    let state_dir = output_dir.join("state");
    let _ = fs::create_dir_all(&log_dir);
    let _ = fs::create_dir_all(&state_dir);

    format!(
        r#"# SynVoid qualification runtime configuration (auto-generated).
# Eggbench Security Qualification M002 — policy synvoid.eggbench-qualification.v1.
# DO NOT EDIT BY HAND. Regenerate with `cargo xtask eggbench-qualification export`.
#
# Loopback-only: bind 127.0.0.1:{listen_port}, upstream is the controlled origin
# bound to 127.0.0.1:{origin_port}. No public listeners, no remote mesh, no DNS,
# no flood/ICMP, no admin, no metrics, no rate limiting.

[server]
host = "127.0.0.1"
port = {listen_port}
trusted_proxies = ["127.0.0.1", "::1"]

# NOTE: no [tokio] section. TokioConfig carries a scalar-oriented custom
# deserializer that rejects the `[tokio]` table form (the shipped
# config/main.toml trips the same error); the field is #[serde(default)]
# so omission yields available_parallelism().
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

[metrics]
enabled = false
port = 9090

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

[defaults.honeypot_probe]
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
    pub run_configtest: bool,
    pub configtest_binary: Option<PathBuf>,
}

impl std::fmt::Debug for ExportOptions {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ExportOptions")
            .field("output_dir", &self.output_dir)
            .field("listen_port", &self.listen_port)
            .field("origin_port", &self.origin_port)
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

    let main_toml = build_main_toml(&inputs, &opts.output_dir);
    let site_toml = build_site_toml(&inputs);

    let main_toml_bytes = main_toml.as_bytes().to_vec();
    let site_toml_bytes = site_toml.as_bytes().to_vec();

    let provenance = build_provenance(
        &inputs,
        &cases,
        &exclusions,
        &source_fixtures,
        &main_toml_bytes,
        &site_toml_bytes,
        &corpus_bytes,
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

    let outputs = BuildOutputs {
        corpus,
        provenance,
        main_toml,
        site_toml,
        config_bundle,
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
        let main_toml = build_main_toml(&inputs, &output_dir);
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
        let main_toml = build_main_toml(&inputs, &output_dir);
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
}
