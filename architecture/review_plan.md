# Architecture Review Plan

**Generated:** 2026-05-28
**Purpose:** Systematically review all architecture documents against actual code, identify discrepancies, bugs, improvements, and stale content.

---

## Scope

59 architecture documents (excluding this file). Each document is assigned to a review module with a dedicated subagent. Subagents write improvement plans to `plans/<module>_review_plan.md`.

---

## Phase 1: Review Modules (16 Parallel Subagents)

| # | Module | Architecture Files | Output Plan |
|---|--------|--------------------|-------------|
| 1 | **Process & Infrastructure** | `supervisor.md`, `worker_architecture.md`, `process_lifecycle.md`, `ipc_process.md`, `drain.md`, `platform.md`, `platform_deep_dive.md` | `plans/process_infra_review_plan.md` |
| 2 | **Configuration** | `config.md`, `config_deep_dive.md` | `plans/config_review_plan.md` |
| 3 | **HTTP Server & Client** | `http_server.md`, `http_shared.md` | `plans/http_server_review_plan.md` |
| 4 | **Proxy & Routing** | `proxy.md`, `proxy_deep_dive.md`, `routing_deep_dive.md`, `upstream.md`, `proxy_cache.md`, `streaming.md`, `location_matcher.md` | `plans/proxy_routing_review_plan.md` |
| 5 | **DNS** | `dns.md`, `dns_deep_dive.md` | `plans/dns_review_plan.md` |
| 6 | **TLS & Crypto** | `tls.md`, `layer_3_5_deep_dive.md` | `plans/tls_crypto_review_plan.md` |
| 7 | **WAF & Security** | `waf.md`, `waf_deep_dive.md`, `auth.md`, `challenge.md`, `captcha.md`, `block_store.md`, `tarpit.md`, `honeypot.md`, `upload.md`, `geoip.md`, `icmp_filter.md`, `integrity.md` | `plans/waf_security_review_plan.md` |
| 8 | **Application Handlers** | `app_handlers.md`, `static_files.md`, `fastcgi.md`, `cgi.md`, `mime.md`, `theme.md` | `plans/app_handlers_review_plan.md` |
| 9 | **WASM & Plugins** | `plugin_wasm.md`, `plugin_deep_dive.md`, `serverless.md`, `spin.md` | `plans/wasm_plugin_review_plan.md` |
| 10 | **Mesh Networking** | `mesh.md`, `mesh_deep_dive.md` | `plans/mesh_review_plan.md` |
| 11 | **Admin & Observability** | `admin_deep_dive.md`, `metrics.md`, `logging.md`, `log_controller.md`, `protocol.md` | `plans/admin_observability_review_plan.md` |
| 12 | **Networking Deep Dives** | `networking_deep_dive.md`, `listener.md` | `plans/networking_review_plan.md` |
| 13 | **Cross-Cutting Utilities** | `common.md`, `filter.md`, `zero_copy.md`, `serder.md` | `plans/utilities_review_plan.md` |
| 14 | **Overview & Methodology** | `overview.md`, `deep_dive_review.md` | `plans/overview_review_plan.md` |

**Total:** 59 documents across 14 review modules.

---

## Phase 2: Subagent Instructions

Each subagent receives these instructions and must complete all steps.

### 2.1 Read the Assigned Architecture Documents
- Read every file listed in their module row
- Note all claimed file paths, line numbers, struct/enum names, feature gates, and behavioral claims

### 2.2 Verify Claims Against Source Code
For each claim in the architecture document:
- **File paths**: Verify the file exists at the stated location using `glob` or `read`
- **Line numbers**: Verify the cited code is at the stated line (±20 lines acceptable for drift)
- **Struct/enum definitions**: Verify the struct exists and has the stated fields/variants
- **Method signatures**: Verify methods exist with the stated parameters
- **Feature gates**: Verify `#[cfg(feature = "...")]` attributes match documented features
- **Behavioral claims**: Read the actual implementation and compare against what the document describes
- **Enum variant counts**: Verify stated counts match actual code (e.g., BackendType 11 variants)
- **Line counts**: Verify stated file line counts are within 20% of actual

### 2.3 Cross-Reference with AGENTS.md
- Check all "Verified Already Fixed" items relevant to their module — verify the fix is still in place
- Check all "Known Bugs" — verify status is still accurate (some may have been fixed since)
- Check all "Known Implementation Issues" — verify status
- Check "Dependency Vulnerability Status" for any module-relevant dependencies
- Verify the "Codebase Quick Reference" entries for their module

### 2.4 Security Pattern Audit
For modules touching secrets, authentication, or cryptographic operations:
- Verify `subtle::ConstantTimeEq` is used for all secret comparisons (keys, MACs, tokens, passwords)
- Verify file permissions `0o600` on private key files
- Verify "Genesis Key Default Deny" — empty `authorized_genesis_keys` denies by default
- Verify "Edge Node PoW" — both `pow_nonce` AND `pow_public_key` required together
- Flag any new secret comparisons using `==` or `!=`

### 2.5 Improvement Discovery
Identify (without prescribing fixes):
- **Discrepancies**: Document says X but code does Y
- **Dead code**: Functions/structs that exist but are never called
- **Stub implementations**: Functions with `todo!()`, `unimplemented!()`, or no-op bodies
- **Missing error handling**: `unwrap()` on Results, silent error swallowing
- **Performance concerns**: Unnecessary allocations, lock contention, missing caching
- **API inconsistencies**: Naming conventions violated, inconsistent parameter ordering
- **Documentation gaps**: Important behavior not documented anywhere
- **Feature completeness**: Features claimed but not implemented

### 2.6 Stale Content Detection
Flag for pruning:
- Documents superseded by a `_deep_dive.md` version (the shallow doc may be stale)
- References to removed code (e.g., `TunnelBackend` was removed)
- References to renamed structs/enums/functions
- File paths that no longer exist in the codebase
- Configuration keys that are no longer used
- Feature flags that were renamed or removed
- Duplicate content that appears in multiple documents

### 2.7 Write Output Plan
Write findings to `plans/<module>_review_plan.md` using this format:

```markdown
# <Module> Review Plan

**Reviewed:** <date>
**Documents:** <list of files reviewed>

## Verified Correct Items
- [item]: [brief verification result]

## Discrepancies Found
- [document]:[line] — Claimed X, actual Y

## Bugs Identified
- [severity] BUG-<module>-<N>: [description] (location)

## Suggested Improvements
- [category]: [description]

## Stale Content
- [file]: [reason it is stale]

## Cross-Reference Status
- [AGENTS.md item]: [still accurate / needs update / fixed since]
```

---

## Phase 3: Subagent Execution Strategy

Each subagent should:
1. Use `explore` agent type for rapid file discovery and initial code scanning
2. Use `general` agent type for deep reading and writing the output plan
3. Process documents in the order listed in the module table
4. For paired documents (e.g., `waf.md` + `waf_deep_dive.md`), read both before verifying
5. Cross-reference between the two documents — inconsistencies between them are findings
6. Write the output plan incrementally — don't wait until all documents are reviewed

**Launch all 14 subagents in parallel** for maximum throughput. Each subagent operates independently with no cross-dependencies.

---

## Phase 4: Stale Content Pruning

After all 14 subagents complete:

### 4.1 Aggregate Stale Content Findings
- Collect all "Stale Content" sections from the 14 output plans
- For each flagged item, verify independently that it is indeed stale
- Categorize as: **Remove** (delete file), **Update** (needs rewrite), **Merge** (consolidate into another doc)

### 4.2 Pruning Decision Matrix

| Condition | Action |
|-----------|--------|
| Document has a `_deep_dive.md` counterpart and is >80% duplicated | Remove shallow doc, keep deep dive |
| Document references only removed code and has no surviving claims | Remove |
| Document is accurate but shallow and covered elsewhere | Merge into covering doc |
| Document has some stale content but some unique value | Update stale sections only |

### 4.3 Execute Pruning
- Remove stale files with `git rm`
- Update index references in `overview.md` if any files are removed
- Document what was pruned and why in the final summary

---

## Phase 5: Cross-Module Conflict Resolution

After all plans are written:

### 5.1 Identify Conflicts
- Check if two subagents flagged the same code location with different conclusions
- Check if one module's improvement depends on another module's changes
- Check if AGENTS.md entries were flagged as stale by multiple modules

### 5.2 Resolution
- Conflicts are documented in a `plans/review_conflicts.md` file
- No code changes are made — conflicts are flagged for human review
- Dependencies between modules are documented (e.g., "DNS review depends on TLS review findings")

---

## Phase 6: Final Verification

After all reviews and pruning:

```bash
# Verify all profiles still compile
cargo check --no-default-features
cargo check --no-default-features --features mesh
cargo check --no-default-features --features dns
cargo check --no-default-features --features mesh,dns

# Run tests
cargo test --lib --no-run
```

---

## Phase 7: Commit

1. Add all new review plan files: `git add plans/*_review_plan.md`
2. Add any conflict resolution file: `git add plans/review_conflicts.md`
3. Remove any pruned architecture files: `git rm architecture/<stale>.md`
4. Update `overview.md` if files were removed
5. Commit with message: `docs: architecture review plans for all 14 modules`
6. Push to main

---

## Module → File Mapping (Quick Reference)

| Module | Files |
|--------|-------|
| Process & Infrastructure | `supervisor.md`, `worker_architecture.md`, `process_lifecycle.md`, `ipc_process.md`, `drain.md`, `platform.md`, `platform_deep_dive.md` |
| Configuration | `config.md`, `config_deep_dive.md` |
| HTTP Server & Client | `http_server.md`, `http_shared.md` |
| Proxy & Routing | `proxy.md`, `proxy_deep_dive.md`, `routing_deep_dive.md`, `upstream.md`, `proxy_cache.md`, `streaming.md`, `location_matcher.md` |
| DNS | `dns.md`, `dns_deep_dive.md` |
| TLS & Crypto | `tls.md`, `layer_3_5_deep_dive.md` |
| WAF & Security | `waf.md`, `waf_deep_dive.md`, `auth.md`, `challenge.md`, `captcha.md`, `block_store.md`, `tarpit.md`, `honeypot.md`, `upload.md`, `geoip.md`, `icmp_filter.md`, `integrity.md` |
| Application Handlers | `app_handlers.md`, `static_files.md`, `fastcgi.md`, `cgi.md`, `mime.md`, `theme.md` |
| WASM & Plugins | `plugin_wasm.md`, `plugin_deep_dive.md`, `serverless.md`, `spin.md` |
| Mesh Networking | `mesh.md`, `mesh_deep_dive.md` |
| Admin & Observability | `admin_deep_dive.md`, `metrics.md`, `logging.md`, `log_controller.md`, `protocol.md` |
| Networking Deep Dives | `networking_deep_dive.md`, `listener.md` |
| Cross-Cutting Utilities | `common.md`, `filter.md`, `zero_copy.md`, `serder.md` |
| Overview & Methodology | `overview.md`, `deep_dive_review.md` |

---

## Completion Criteria

This review is complete when:
- [ ] All 14 subagent plans exist in `plans/`
- [ ] All stale content has been identified and either pruned or flagged
- [ ] Cross-module conflicts are documented in `plans/review_conflicts.md`
- [ ] All profiles compile successfully
- [ ] Commit is pushed to main
