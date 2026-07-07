# Milestone A Phase 4: YARA Rule Provenance and Dependency Policy Enforcement

## Objective

Formalize the trust boundary for YARA rule sources and enforce dependency/security policy in CI. Rule updates must be deterministic, bounded, auditable, and resilient to bad inputs. Dependency mitigations for YARA-X, wasmtime, RSA exposure, and related transitive crates must be enforced rather than only documented.

This phase should land after the scanner has explicit failure semantics, meaningful coverage, and bounded execution. At that point the remaining Milestone A concern is whether the rules being executed are trusted, reproducible, and safe to update.

## Current risk summary

Local directory loading concatenates `.yar` and `.yara` files from a directory with shallow traversal. The current path does not define a complete rule-source trust model: deterministic file ordering, symlink handling, file count limits, aggregate size limits, canonical path enforcement, manifest verification, and last-known-good update behavior should be explicit.

Mesh-distributed rules can be reloaded from compiled rule bytes or source text, but the validation boundary should clearly define version, hash, signature, source identity, and rejection behavior.

The repository documents dependency risk around YARA-X transitive dependencies, wasmtime, and RSA exposure. Documentation is helpful but insufficient; CI should prevent accidental regression.

## Desired behavior

Every active YARA rule generation should have provenance metadata:

- source type: bundled, local directory, inline, mesh source, compiled bundle
- version
- content hash
- manifest hash if available
- signer identity if signed
- loaded timestamp
- rule file count/source count
- total source bytes or compiled bytes
- verification status

Rule updates should be deterministic:

- stable sorted file order
- explicit max file count
- explicit max total rule bytes
- symlink policy
- canonicalized local paths
- clear fallback behavior

Remote/mesh rule updates should be signed or explicitly marked as unsigned/insecure. A failed update must preserve the last-known-good generation from Phase 3.

Dependency policy should be machine-enforced with `cargo deny`, `cargo audit`, or equivalent CI checks.

## Implementation plan

### Step 1: Add rule provenance model

Add a metadata struct near the YARA scanner/rule generation code.

Candidate shape:

```rust
pub struct YaraRuleProvenance {
    pub source_type: YaraRuleSourceType,
    pub version: Option<String>,
    pub content_sha256: String,
    pub manifest_sha256: Option<String>,
    pub signer: Option<String>,
    pub verified: bool,
    pub loaded_at: chrono::DateTime<chrono::Utc>,
    pub source_count: usize,
    pub source_bytes: u64,
}
```

Expose this through scanner status APIs and, later, admin observability.

### Step 2: Harden local directory loading

Update directory rule loading to:

- canonicalize the configured directory path
- reject non-directory paths
- reject symlinks by default
- collect only regular `.yar`/`.yara` files
- sort files by canonical path or stable relative path before concatenation
- enforce max rule files
- enforce max bytes per file
- enforce max aggregate source bytes
- include file paths and hashes in debug logs or provenance metadata

Suggested config fields:

```toml
[upload]
yara_max_rule_files = 256
yara_max_rule_source_bytes = 8388608
yara_allow_rule_symlinks = false
```

When no rules are found, behavior should remain explicit: either use bundled fallback only when configured as `DirectoryWithFallback`, or return `NoRules` for strict directory mode.

### Step 3: Add signed bundle format

Define a simple manifest format for distributed or packaged rule bundles. This can be implemented incrementally without changing every current source path.

Candidate manifest fields:

```toml
version = "2026-07-07.1"
created_at = "2026-07-07T00:00:00Z"
source_id = "synvoid-default"
rule_source_sha256 = "..."
compiled_rules_sha256 = "..."
min_synvoid_version = "0.1.0"
format_version = 1
signature_scheme = "ed25519"
signature = "base64..."
```

Use Ed25519 for project-owned rule feeds, consistent with the existing security assessment that SynVoid should not rely on RSA-based YARA rule signing.

Support an unsigned local development path, but label it clearly in provenance as `verified = false`.

### Step 4: Verify mesh-delivered rules

For mesh rule manager integration, ensure the scanner reload path can distinguish:

- signed source rules
- signed compiled rules
- unsigned source rules
- unsigned compiled rules

Production mode should reject unsigned remote/mesh updates unless explicitly configured to allow them.

Bad signature, wrong hash, stale version, unsupported manifest version, or failed compile/deserialization should reject the candidate and keep last-known-good rules.

### Step 5: Add dependency policy enforcement

Add or tighten `deny.toml`/CI policy around:

- disallowed vulnerable `wasmtime` versions
- YARA-X feature creep that reintroduces broader optional dependencies unexpectedly
- RSA advisory exposure if it becomes reachable or if RSA-based YARA rule signing is enabled
- known yanked or unmaintained crates already documented in `SECURITY.md`

CI should run at least:

```bash
cargo deny check
cargo audit
```

If full workspace audit is noisy due known documented exceptions, make exceptions explicit with comments and review dates rather than suppressing broadly.

### Step 6: Add operator-visible status hooks

Add methods to retrieve active rule provenance:

```rust
get_rule_provenance()
get_rule_version()
get_rule_hash()
get_last_reload_error()
```

Admin UI exposure can be deferred to Milestone D, but the library surface should be ready.

## Tests

Minimum tests:

1. Directory loading is deterministic regardless of filesystem iteration order.
2. Directory loading rejects symlinks by default.
3. Directory loading enforces max file count.
4. Directory loading enforces max aggregate source bytes.
5. Strict directory mode returns `NoRules` when empty.
6. Directory-with-fallback mode uses bundled rules when local rules fail.
7. Signed manifest verification succeeds for a valid bundle.
8. Signed manifest verification fails on tampered rule content.
9. Bad compiled rule bytes do not replace last-known-good rules.
10. Bad source rules do not replace last-known-good rules.
11. Mesh unsigned update is rejected in production mode unless explicitly allowed.
12. Provenance metadata contains version, hash, source type, verification state, and source count.

Use test keys only in fixtures. Do not embed production signing keys.

## Documentation updates

Update security and configuration docs with:

- YARA rule source types.
- Local directory strict vs fallback behavior.
- Rule bundle signing model.
- How to rotate rule feeds safely.
- How to inspect active rule version/hash.
- Dependency policy and known advisory handling.

Document that RSA-based YARA rule signing is not the intended SynVoid rule-feed trust mechanism. Use Ed25519-signed manifests for SynVoid-owned feeds.

## Dependency policy notes

The repository already patches wasmtime at the root and documents YARA-X transitive wasmtime/RSA exposure. This phase should verify whether the current lockfile resolves to the intended versions and encode the intended state in policy.

If `cargo audit` reports advisories that are accepted because the vulnerable code path is not used, capture the rationale in the policy file with an owner and a review date. Avoid broad advisory ignores without context.

## Success criteria

- Active YARA rules have provenance metadata.
- Local directory rule loading is deterministic and bounded.
- Symlink, file-count, and aggregate-size policies are enforced.
- Signed bundle verification exists for distributed rule feeds.
- Mesh-delivered unsigned or tampered rules cannot replace active production rules by default.
- Bad updates preserve last-known-good rules.
- CI enforces dependency policy for YARA-X-related risks.
- Documentation explains rule trust and dependency posture accurately.

## Non-goals

- Do not redesign scan execution here; that is Phase 3.
- Do not implement full admin UI status pages here; expose status APIs and defer UI integration to Milestone D.
- Do not implement honeypot/tarpit threat-intel scoring here.
- Do not add external rule feed fetching unless a signed bundle path already exists.

## Handoff checklist

- [ ] Add `YaraRuleProvenance` and source-type model.
- [ ] Attach provenance to active rule generations.
- [ ] Harden local directory rule loading.
- [ ] Add max rule file and max source byte config.
- [ ] Add symlink policy.
- [ ] Add signed manifest/bundle verification path.
- [ ] Ensure mesh reloads verify signature/hash in production mode.
- [ ] Preserve last-known-good rules on all bad updates.
- [ ] Add dependency policy checks for YARA-X/wasmtime/RSA exposure.
- [ ] Add tests for deterministic loading, limits, signatures, bad updates, and provenance metadata.
- [ ] Update `SECURITY.md` and upload configuration docs.
- [ ] Run `cargo test -p synvoid-upload` and dependency-policy checks.
