# Security Scanner / YARA Ownership Audit

> Created as part of MDM-S01.
> Scope: YARA scanning, malware detection, quarantine, and related modules.
> No code movement in this audit.

## Summary

YARA / malware scanning is concentrated in the `synvoid-upload` crate. The
cradle of the live runtime is `crates/synvoid-upload/src/yara_scanner.rs` and
`crates/synvoid-upload/src/malware_scanner.rs`. The mesh crate owns the
distributed `YaraRulesManager` and is consumed via the root
`crate::mesh::yara_rules::YaraRulesManager` re-export.

The root `Cargo.toml` has a direct `yara-x` dep that is currently **not used
by any compiled code in root `src/`**. There is a dead
`src/upload/yara_scanner.rs` (and friends) that imports `yara_x` directly,
but `src/upload/mod.rs` is `pub use synvoid_upload::*;`, so the file is not
compiled. This is a candidate for root-dep pruning in MDM-R02, not a
candidate for moving YARA into a new crate.

No strong evidence that YARA scanning is a hot rebuild path or that it would
benefit from extraction at this time.

## Files in scope (count: 13 source files + 2 Cargo.toml entries)

| Module/file | Current crate | Dependencies | Runtime owner | Candidate target | Notes |
|---|---|---|---|---|---|
| `crates/synvoid-upload/src/yara_scanner.rs` | `synvoid-upload` | `yara-x`, `sha2`, `parking_lot`, `tokio` | `YaraScanner` (YARA-X wrapper) | `synvoid-upload` (KEEP) | 564 lines. The canonical runtime: `YaraScanner::scan_bytes` (line 384), `YaraScanner::with_timeout` (line 232), rule compilation via `yara_x::compile` (line 239), `YaraRulesSource` enum (line 506). Hot path for upload malware detection. |
| `crates/synvoid-upload/src/malware_scanner.rs` | `synvoid-upload` | (uses `crate::yara_scanner::YaraScanner`) | `MalwareScanner` (orchestrator over detectors + YARA) | `synvoid-upload` (KEEP) | 719 lines. `scan_bytes` (line 241), `with_yara` (line 212), `get_yara_scanner` (line 233). Pre-YARA byte-level detectors + optional YARA scan. |
| `crates/synvoid-upload/src/sandbox.rs` | `synvoid-upload` | `std::fs`, `tokio::fs` | `Sandbox` (quarantine file system) | `synvoid-upload` (KEEP) | 279 lines. `quarantine_dir` (line 10), `quarantine()` (line 201). Holds the quarantine file tree (`/var/lib/synvoid/quarantine`). |
| `crates/synvoid-upload/src/config.rs` | `synvoid-upload` | `serde`, `synvoid_config` | `UploadConfig` (YARA/quarantine config DTOs) | `synvoid-upload` (KEEP) | `scan_with_yara` (line 55), `yara_rules_dir` (line 68), `yara_timeout_ms` (line 70), `quarantine_dir` (line 65). All scan-time knobs. |
| `crates/synvoid-upload/src/yara_rule_feed.rs` | `synvoid-upload` | `synvoid_config`, `synvoid_mesh` (mesh feature) | `YaraRuleFeedManager` (downloaded rules cache) | `synvoid-upload` (KEEP) | 458 lines. `ParsedYaraRules` (line 65), `YaraRuleFeedManager` (line 88, 403). |
| `crates/synvoid-upload/src/metrics.rs` | `synvoid-upload` | `metrics` | `increment_malware_detected`, `get_malware_detected` | `synvoid-upload` (KEEP) | `increment_malware_detected` (line 19). |
| `crates/synvoid-upload/src/lib.rs` | `synvoid-upload` | re-exports of all above | `UploadValidator`, `MalwareScanner`, `YaraScanner`, `Sandbox` | `synvoid-upload` (KEEP) | `UploadValidator` (line 94) wires sandbox + scanner. `reload_yara_rules_if_needed` (line 167). |
| `crates/synvoid-upload/Cargo.toml` | `synvoid-upload` | `yara-x = "1.15"` (line 31) | direct dep | `synvoid-upload` (KEEP) | Sole purpose of the dep is `YaraScanner` runtime. |
| `crates/synvoid-mesh/src/mesh/yara_rules.rs` | `synvoid-mesh` | `yara-x` (mesh's own `Cargo.toml:130`), `synvoid_config` | `YaraRulesManager` (DHT + feed + DHT-backed rules manager) | `synvoid-mesh` (KEEP) | 2526+ lines. `YaraRulesManager` (line 293), `validate_rules_syntax` (line 1459) calls `yara_x::compile` to validate. The rules DHT distribution lives here. This is the only place besides `synvoid-upload` that actually `use yara_x::...`. |
| `crates/synvoid-mesh/Cargo.toml` | `synvoid-mesh` | `yara-x = "1.15"` (line 130) | direct dep | `synvoid-mesh` (KEEP) | For `YaraRulesManager`'s `validate_rules_syntax` flow. |
| `src/upload/yara_scanner.rs` | **root** (NOT COMPILED) | `yara_x` direct | dead | delete | 564 lines. Identical structure to `crates/synvoid-upload/src/yara_scanner.rs`. `src/upload/mod.rs` is `pub use synvoid_upload::*;`, so this file is never compiled. The only `use yara_x::` in root `src/`. |
| `src/upload/malware_scanner.rs` | **root** (NOT COMPILED) | `crate::upload::yara_scanner` (would be self-ref to the dead file) | dead | delete | 719 lines. Same fate as above. `src/upload/mod.rs` does not declare it. |
| `src/upload/sandbox.rs` | **root** (NOT COMPILED) | `std::fs` | dead | delete | duplicates `crates/synvoid-upload/src/sandbox.rs`. |
| `src/upload/yara_rule_feed.rs` | **root** (NOT COMPILED) | `synvoid_config` | dead | delete | duplicates `crates/synvoid-upload/src/yara_rule_feed.rs`. |
| `src/upload/config.rs` | **root** (NOT COMPILED) | `serde`, `synvoid_config` | dead | delete | duplicates `crates/synvoid-upload/src/config.rs` (with `image_poisoning` legacy names; see `image_rights_terminology_inventory.md`). |
| `src/upload/metrics.rs` | **root** (NOT COMPILED) | `metrics` | dead | delete | duplicates `crates/synvoid-upload/src/metrics.rs`. |
| `src/upload/rate_limit.rs` | **root** (NOT COMPILED) | `parking_lot` | dead | delete | duplicates upload rate limit. |
| `src/upload/signature.rs` | **root** (NOT COMPILED) | `crate::upload::*` (dead) | dead | delete | duplicates file signature registry. |
| `src/upload/mod.rs` | **root** | re-exports `synvoid_upload::*` | the only compiled thing in `src/upload/` | KEEP_ROOT_ORCHESTRATION | 1 line: `pub use synvoid_upload::*;`. The whole directory is a re-export shim. |
| `src/sandbox/mod.rs` | **root** | `crate::platform::sandbox` | `run_yara_jail_mode` (line 34) | KEEP_ROOT_ORCHESTRATION | 54 lines. Empty stub today (`// TODO: Implement IPC listener for YARA scan requests` line 50). Called from `src/main.rs:355` when `--yara-jail` flag is set. |
| `src/supervisor/state.rs` | **root** | `crate::waf::YaraRulesManager` (mesh re-export) | mesh YARA rules plumbing in `SupervisorState` | KEEP_ROOT_ORCHESTRATION | 88 lines. `yara_rules: Option<Arc<YaraRulesManager>>` (lines 29, 47). |
| `src/supervisor/mesh.rs` | **root** | `crate::waf::YaraRulesManager` | mesh wiring | KEEP_ROOT_ORCHESTRATION | uses `YaraRulesManager` for mesh bring-up. |
| `src/startup/mod.rs` | **root** | `crate::waf::YaraRulesManager` | startup wiring | KEEP_ROOT_ORCHESTRATION | uses `YaraRulesManager`. |
| `src/waf/mod.rs` | **root** | `crate::mesh::yara_rules::YaraRulesManager` | re-export | KEEP_ROOT_ORCHESTRATION | `pub use crate::mesh::yara_rules::YaraRulesManager;` (line 63); `set_yara_rules` / `get_yara_rules` (lines 1066, 1076). |
| `src/waf/threat_intel/feed_client.rs` | **root** | `crate::mesh::protocol::*` | mesh intel, not YARA | KEEP_ROOT | references `MeshMessageSigner`/threat intel, not YARA scanner. |
| `src/main.rs` | **root** | CLI arg | `--yara-jail` mode flag | KEEP_ROOT | lines 285, 292, 353, 355. Routes to `sandbox::run_yara_jail_mode`. |
| `src/process/ipc.rs` | **root** | IPC message types | `YaraScan` payload variant | KEEP_ROOT | `CpuTaskPayload::YaraScan` (line 121, 164, 222, 1429, 3024). Declares the IPC envelope for offloaded YARA scans. |
| `src/worker/cpu_task/yara.rs` | **root** | `crate::upload::yara_scanner` | CPU-worker YARA offload (unused path today) | KEEP_ROOT | 5 lines: imports `YaraRulesSource`, `YaraScanner`. The IPC variant exists; the worker bridge is wired. |
| `src/worker/cpu_task/state.rs` | **root** | `crate::upload::yara_scanner` | CPU worker construction | KEEP_ROOT | uses `YaraScanner`. |
| `src/worker/unified_server/init_waf.rs` | **root** | `crate::upload::UploadValidator` | wiring | KEEP_ROOT | constructs `UploadValidator` for the unified server. |
| `src/static_files/file_manager.rs` | **root** | `crate::upload::malware_scanner::MalwareScanner`, `crate::upload::yara_scanner::YaraScanner` | upload pre-YARA malware detection | KEEP_ROOT | uses `YaraScanner::new(YaraRulesSource::Bundled)` at line 241 to seed a static-files scanner. |
| `src/waf/mod.rs:62-63` comment | **root** | n/a | comment marker | KEEP_ROOT | "YaraRulesManager is actually in mesh module" — durability note. |
| `src/main.rs:34-46` | **root** | `schemars`, `synvoid::admin::openapi` | `--export-openapi` flag, calls `synvoidOpenApi::openapi_json()` | KEEP_ROOT | OpenAPI export binary entry. Owned by root because the binary must wire up the canonical `synvoidOpenApi` (see `src/admin/openapi.rs:1372-1377`). |

## Root direct-dep evidence

| Dep | In root Cargo.toml | Compiled `use yara_x::*` in root src | Verdict |
|---|---|---|---|
| `yara-x = "1.15"` (line 137) | yes | 0 (only in `src/upload/yara_scanner.rs` which is **dead**) | REMOVABLE once dead `src/upload/*.rs` files are deleted. Belongs to MDM-R02, not this audit. |
| wasmtime patch (line 46) | `[patch.crates-io]` only | n/a | Documented separately in `AGENTS.md` "Dependency Vulnerability Status". Not a scan ownership issue. |

`cargo tree -p synvoid -i yara-x` (no-default-features) shows yara-x coming
from: root direct, `synvoid-mesh`, and `synvoid-upload`. After root removal,
yara-x would still be in the dep graph via the two leaf crates.

## Cross-crate call sites (live, not dead)

| Caller | Call site | Target |
|---|---|---|
| `crates/synvoid-http/src/upload_validation_dispatch.rs:9` | `use synvoid_upload::{is_upload_content_type, UploadValidationError, UploadValidator};` | `synvoid-upload` |
| `crates/synvoid-http/src/upload_validation_dispatch.rs:44` | `upload_validator.validate_bytes(full_body_arc, path).await` | `synvoid-upload` |
| `src/upload/mod.rs:1` | `pub use synvoid_upload::*;` | `synvoid-upload` |
| `src/worker/context.rs:9` | `use crate::upload::UploadValidator;` | re-export shim |
| `src/worker/cpu_task/yara.rs:5` | `use crate::upload::yara_scanner::{YaraRulesSource, YaraScanner};` | **points at dead file** (will fail to compile if `src/upload/mod.rs` ever re-declares `pub mod yara_scanner;`) |
| `src/worker/cpu_task/state.rs:12` | `use crate::upload::yara_scanner::YaraScanner;` | **points at dead file** |
| `src/static_files/file_manager.rs:15-18` | `use crate::upload::malware_scanner::MalwareScanner; use crate::upload::rate_limit::*; use crate::upload::yara_scanner::YaraScanner; use crate::upload::YaraError;` | **points at dead files** (all four lines) |
| `src/worker/unified_server/init_waf.rs:9` | `use crate::upload::UploadValidator;` | re-export shim (works) |
| `src/supervisor/state.rs:14` | `use crate::waf::YaraRulesManager;` | `synvoid-mesh` via root re-export |
| `src/supervisor/mesh.rs:17` | `use crate::waf::YaraRulesManager;` | `synvoid-mesh` via root re-export |
| `src/startup/mod.rs:12` | `use crate::waf::YaraRulesManager;` | `synvoid-mesh` via root re-export |
| `src/waf/mod.rs:63` | `pub use crate::mesh::yara_rules::YaraRulesManager;` | `synvoid-mesh` |
| `src/main.rs:355` | `synvoid::sandbox::run_yara_jail_mode();` | `src/sandbox/mod.rs` (root stub) |

The five `src/worker/cpu_task/*` and `src/static_files/file_manager.rs` call
sites that reach into `crate::upload::yara_scanner` (etc.) are **latent
breakage**: today they compile only because `src/upload/mod.rs` is a single
`pub use` line. If anyone adds `pub mod yara_scanner;` to that mod (e.g. to
"revive" the dead files), all five call sites would resolve to the dead
copies, not the live `synvoid-upload` ones. They are also the kind of
accidental import that MDM-W02 (replace accidental root imports only) is
meant to fix.

## Quarantine ownership

Quarantine file storage lives entirely in `synvoid-upload`:

- `crates/synvoid-upload/src/sandbox.rs:10` — `pub quarantine_dir: PathBuf`
- `crates/synvoid-upload/src/sandbox.rs:201` — `pub async fn quarantine(...)`
- `crates/synvoid-upload/src/config.rs:64-65, 154-155` — default
  `/var/lib/synvoid/quarantine`

No other crate owns quarantine I/O. WAF callers use the `YaraError` enum and
`yara_matches` payload that flow through `synvoid_upload::ValidationResult`,
not direct file paths.

## Mesh vs. scanner split

`YaraRulesManager` (mesh) and `YaraScanner` (upload) are intentionally
separate:

- `YaraRulesManager` owns the *rule set* (DHT distribution, version gating,
  feed ingestion, validation, approval flow).
- `YaraScanner` owns the *scan execution* (compile rules, scan bytes,
  timeout, archive handling, scan error mapping).
- They meet at the `UploadValidator::reload_yara_rules_if_needed` boundary
  (`crates/synvoid-upload/src/lib.rs:167`), which is a clean import seam
  behind the `mesh` feature flag.

No restructuring needed for this seam.

## YARA jail (`--yara-jail` mode)

`src/sandbox/mod.rs:34-54` is a stub. It applies the platform sandbox
(`SandboxLevel::Strict`) and then logs "YARA jail is now active and
sandboxed" with a TODO for the IPC listener. It is not on a hot rebuild
path and is not exercised by current tests. The "jail" model itself is
intentionally root-owned because it is a process-mode entry point from
`src/main.rs`.

## Conclusion

- YARA runtime is already correctly owned by `synvoid-upload`.
- Mesh-side `YaraRulesManager` is correctly owned by `synvoid-mesh`.
- The root `Cargo.toml` `yara-x` direct dep is **dead** (see evidence
  above). This is a candidate for `REMOVE_FROM_ROOT` in MDM-R02 once the
  dead `src/upload/*.rs` files are deleted.
- Several call sites in `src/worker/cpu_task/*` and
  `src/static_files/file_manager.rs` reach into `crate::upload::yara_scanner`
  / `crate::upload::malware_scanner` (dead files) rather than the live
  `synvoid_upload::*` re-export. These should be fixed by MDM-W02 (replace
  accidental root imports only), not by extraction.
- No evidence that YARA scanning is a measured hot rebuild path. No need
  for a new `synvoid-security-scanner` crate.

## MDM-S03 Decision

| Subsystem | Decision | Reason |
|---|---|---|
| `YaraScanner` runtime (upload scanner) | `KEEP_ROOT_ORCHESTRATION` (i.e. keep in `synvoid-upload`) | Already correctly owned. `synvoid-upload` is the right home: it co-locates `MalwareScanner`, `Sandbox`, `UploadValidator`, and the YARA X wrapper. No clean seam is left in root for further extraction. The upload path is not a measured hot edit path. |
| `YaraRulesManager` (mesh rules DHT/feed) | `KEEP_ROOT_ORCHESTRATION` (i.e. keep in `synvoid-mesh`) | Already correctly owned by `synvoid-mesh`. The seam is `synvoid-mesh::yara_rules::YaraRulesManager`, re-exported through `src/waf/mod.rs:63` and `src/supervisor/state.rs:14`. The mesh feature flag in `synvoid-upload` is the correct conditional boundary; it does not need a new crate. |
| Quarantine file system (`Sandbox::quarantine`) | `KEEP_ROOT_ORCHESTRATION` (i.e. keep in `synvoid-upload`) | Co-located with the scanner that triggers it. Splitting it out would force a new trait to model "where to put a quarantined file" and would not measurably improve compile times. |
| `run_yara_jail_mode` (`src/sandbox/mod.rs:34`) | `KEEP_ROOT_ORCHESTRATION` | It is a process-mode entry point invoked from `src/main.rs:355`. The platform sandbox seam it depends on (`crate::platform::sandbox::*`) is already extracted. The body of the function is a 50-line stub. |
| Dead `src/upload/*.rs` files (7 files) | `EXTRACT_LATER_CLEAN_BOUNDARY` (i.e. delete them, not extract) | They are duplicates of the live `synvoid-upload` crate files. Deleting them is a prerequisite for `REMOVE_FROM_ROOT` of the dead `yara-x` direct dep in MDM-R02. No new crate. |
| Dead root `yara-x` direct dep (`Cargo.toml:137`) | `EXTRACT_LATER_CLEAN_BOUNDARY` (i.e. remove from root after dead-file deletion) | Belongs in MDM-R02, not S03. Once the 7 dead files are deleted, the root `yara-x` dep can be removed. yara-x stays in `synvoid-upload` and `synvoid-mesh` as their own direct deps. |
| `synvoid-security-scanner` new crate | `DEFER_LOW_VALUE` | No evidence (compile timing or coupling) that creating this crate would reduce rebuild cost. The plan's "do not create new crates" rule applies. |
| Five `crate::upload::yara_scanner` import call sites (`src/worker/cpu_task/*`, `src/static_files/file_manager.rs:15-18`) | `EXTRACT_LATER_CLEAN_BOUNDARY` (i.e. switch to `synvoid_upload::*`) | These reach into dead files that are masked by the `pub use` shim. They are latent breakage. Belongs in MDM-W02 ("replace accidental root imports only"). No new crate. |

**Overall MDM-S03 verdict:** `KEEP_ROOT_ORCHESTRATION` for all four runtime
sites (YARA runtime, mesh rules, quarantine, yara-jail). `EXTRACT_LATER_CLEAN_BOUNDARY`
for the two mechanical cleanups (dead `src/upload/*.rs` files and the
resulting root `yara-x` direct dep). `DEFER_LOW_VALUE` for any new crate.
**No extraction in this audit pass.**
