---
name: yara_scanning
description: YARA engine boundary — source-only compilation, bounded scan, artifact metadata, executor contract. Use when touching YARA rules, malware scanning execution, or the jail YARA service.
---

# YARA Scanning

## Overview

`crates/synvoid-yara/` is the **single production owner of `yara-x`**
(Phase 26, closed by Phase 36). It owns only YARA-domain primitives reusable
across upload policy, mesh distribution, and the jail execution service. It has
no dependency on mesh, upload, HTTP, admin, WAF, or the root crate.

## Key Files

- `crates/synvoid-yara/src/engine.rs` - `YaraScanner`, rule sources
  (`YaraRulesSource`, `YaraRuleManifest`, `YaraRuleProvenance`,
  `YaraRuleSourceType`), bounded compile/scan, match DTOs (`YaraMatch`),
  `validate_rules_syntax`, `compute_sha256`, `verify_content_digest`,
  `DEFAULT_MALWARE_RULES`
- `crates/synvoid-yara/src/artifact.rs` - Local-compile binding metadata
  (`CompiledArtifact`, `rule_digest`, `version_binding`,
  `COMPILED_FORMAT_VERSION`, `MAX_COMPILED_BYTES`, `YARA_ENGINE_VERSION`) —
  **no remote deserialization**
- `crates/synvoid-yara/src/executor.rs` - Narrow `YaraExecutor` contract
  (`InProcessYaraExecutor`, `YaraMatchMetadata`) separating orchestration
  from execution
- `crates/synvoid-yara/src/metrics.rs` - Engine-local counters

## Trust Model (Phase 36 — binding)

Signed/approved **source text** is the canonical executable input. Compilation
happens locally; wire compiled bytes are opaque metadata and never reach a
deserializer. Consequences:

- NEVER add a compiled-artifact deserializer anywhere (upload, mesh, jail,
  admin). Mesh/jail/upload recompile approved source locally.
- Supervisor-side full syntax validation (`validate_rules_syntax`) runs in the
  composition root (`src/supervisor/mesh.rs` `BoundaryValidator`), invoked ONLY
  from `submit_rule_for_approval` after edge-role + size/content gates. Remote
  ingress (receipt, announces, DHT sync) is size/signature-gated and never
  compiles.
- Trusted-signer deny-by-default for non-global nodes applies to the DHT sync
  and announce paths (`crates/synvoid-mesh/src/mesh/yara_rules.rs`,
  `check_trusted_signer`).

## Consumers

- Upload policy: `crates/synvoid-upload/src/yara_scanner.rs` (+ feed manager)
- Jail service: `crates/synvoid-jail-runtime/src/yara_service.rs` uses
  `engine` directly (see `sandboxing` skill for the jail protocol)
- Mesh distribution: `crates/synvoid-mesh/src/mesh/yara_rules.rs`

## Verification

```bash
cargo nextest run -p synvoid-yara --cargo-profile ci --profile ci
```
