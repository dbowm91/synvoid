---
name: upload_security
description: Upload scanning pipeline — signatures, YARA, malware heuristics, archives, sandbox quarantine. Use when touching file uploads, malware detection, or quarantine flows.
---

# Upload Security

## Overview

`crates/synvoid-upload/` (~9 modules) is the upload scanning pipeline:
multi-stage inspection (magic-signature → YARA → malware heuristics → archive
traversal) with sandbox quarantine on verdict.Consumers: HTTP upload paths and
`synvoid-app-handlers`; execution of YARA itself belongs to the `yara_scanning`
skill.

## Key Files

- `crates/synvoid-upload/src/lib.rs` - Module exports + `RESERVED_WINDOWS_NAMES`
  guard + `HEADER_READ_SIZE` (8192) header sniffing
- `crates/synvoid-upload/src/config.rs` - `UploadConfig` (`enabled`, `max_size`,
  `memory_threshold`, `scan_with_yara`, `sandbox_enabled`, `sandbox_dir`,
  `quarantine_dir`, …), `EffectiveUploadConfig`, `UploadScanFailurePolicy`
- `crates/synvoid-upload/src/signature.rs` - `FileSignature` / `SignatureRegistry`
  / `FileCategory` magic-byte identification
- `crates/synvoid-upload/src/yara_scanner.rs` - Upload-side YARA binding
  (`YaraScanner`, `YaraRulesSource`, `YaraRuleManifest`, `YaraRuleProvenance`,
  `DEFAULT_MALWARE_RULES`); rule *source text* only — see `yara_scanning`
- `crates/synvoid-upload/src/yara_rule_feed.rs` - `YaraRuleFeedManager`,
  `YaraRuleSource`, `ParsedYaraRules` (signed feed ingestion)
- `crates/synvoid-upload/src/malware_scanner.rs` - `MalwareScanner`,
  `MalwareMatch`, `MatchConfidence`, `MatchSource`, `ScanContext`
- `crates/synvoid-upload/src/archive.rs` - `ArchiveInspectionConfig/Result/Error`,
  `ArchiveEntryMatch` (bounded archive traversal)
- `crates/synvoid-upload/src/sandbox.rs` - `Sandbox`, `SandboxConfig`,
  `SandboxHandle`, `QuarantineEntry`, `SandboxError`
- `crates/synvoid-upload/src/rate_limit.rs` - Upload-scoped rate limiting
- `crates/synvoid-upload/src/metrics.rs` - Upload counters

## Boundaries

- **Source-text-only (Phase 36)**: YARA inputs are approved source recompiled
  locally. Never add a compiled-artifact deserializer; mesh/jail/upload paths
  recompile. See `yara_scanning`.
- **Fail-closed scanning**: `UploadScanFailurePolicy` decides scanner-error
  outcome — scanner failure must not silently become "clean".
- **Quarantine, don't delete**: suspect files go to `quarantine_dir` via the
  sandbox handle for operator review.
- **Archive bombs**: traversal is bounded by `ArchiveInspectionConfig`
  (depth/entry-count/size caps) — never recursive unbounded unpack.

## Verification

```bash
cargo nextest run -p synvoid-upload --cargo-profile ci --profile ci
```
