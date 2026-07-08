# Milestone B Follow-up Closure Pass

## Purpose

This plan closes the remaining gaps after the first Milestone B implementation pass. Since GitHub CI is currently not a reliable source of validation, all closure criteria are framed around local verification, explicit commit-message evidence, and documented command output.

The repository has already advanced on:

- Milestone B Phase 1: native malware detector correctness.
- Milestone B Phase 3: honeypot listener concurrency and accounting.
- Milestone B Phase 4: honeypot protocol detection correctness.

The remaining pass must avoid broad scope creep. It should finish the incomplete Phase 2 archive-inspection line, audit the new listener permit/concurrency behavior, validate protocol-confidence downstream safety assumptions, and reconcile dependency/docs state.

## Current status

Implemented or mostly implemented:

- YARA errors now propagate as `MalwareError::YaraScanError` instead of being silently consumed by `MalwareScanner`.
- PE/ZIP polyglot detection was corrected to search for ZIP signatures after a PE header.
- Native `MalwareMatch` now includes source and confidence metadata.
- Filename-aware detection exists through `ScanContext`.
- Honeypot listener admission uses semaphore-based global limiting.
- Per-IP connection accounting uses an RAII guard with zero-count cleanup.
- Honeypot read loop now enforces `max_payload_size` and records truncation.
- Protocol detection is binary-safe and has normalized protocol identifiers, confidence, evidence, and static banner lookup.

Remaining closure gaps:

1. Bounded archive inspection is not clearly implemented despite the `zip` dependency appearing in the upload dependency graph.
2. The new `zip` dependency must be either justified by actual archive-inspection implementation or removed until used.
3. Listener permit handling needs an explicit leak/premature-release audit after the switch to RAII guards and explicit drops.
4. Protocol confidence must be carried safely into downstream threat-intel/actionability so low-confidence matches do not trigger aggressive actions.
5. Local validation output must be captured because GitHub CI cannot currently be relied upon.
6. Documentation must accurately distinguish completed Phase 1/3/4 work from still-open Phase 2 archive traversal.

## Workstream 1: Finish or explicitly defer bounded archive inspection

### Problem

Milestone B Phase 2 had a detailed plan for bounded archive inspection, but no explicit implementation commit has landed. A `zip` dependency appears in the tree, which suggests either preparatory work, accidental drift, or incomplete archive work.

### Required decision

Choose exactly one path:

#### Preferred path: implement bounded ZIP inspection now

Implement a bounded ZIP inspection layer with clear scan metadata and tests.

Minimum requirements:

- Detect ZIP by magic bytes.
- Iterate ZIP entries without extracting to attacker-controlled paths.
- Reject unsafe paths:
  - absolute paths
  - `..` traversal
  - Windows drive prefixes
  - UNC-style paths
  - embedded NULs
  - symlink entries if metadata is available
- Enforce entry count limit.
- Enforce per-entry uncompressed size limit.
- Enforce aggregate uncompressed size limit.
- Enforce compression ratio limit where compressed/uncompressed sizes are available.
- Enforce nesting depth and nested archive count if recursive scanning is enabled.
- Scan supported entry bytes through the corrected Phase 1 scanner API so YARA errors become indeterminate/rejected under production defaults.
- Return explicit metadata for archive type, entries seen, entries scanned, nesting depth, total uncompressed bytes, truncation/limit state, and entry-context matches.

Required tests:

- benign ZIP with one text entry -> no matches, inspected true.
- ZIP with embedded PE -> match.
- ZIP with PE/ZIP polyglot entry -> match.
- malformed ZIP -> indeterminate/rejected, not clean.
- traversal path `../evil` -> rejected.
- absolute path `/tmp/evil` -> rejected.
- Windows drive path `C:\\evil` -> rejected.
- symlink entry -> rejected if detectable.
- too many entries -> limit exceeded.
- per-entry size exceeded -> limit exceeded.
- aggregate size exceeded -> limit exceeded.
- compression ratio exceeded -> bomb suspected/rejected.
- nested ZIP within depth -> payload detected, if nested scanning implemented.
- nested ZIP beyond depth -> limit exceeded/rejected.

#### Acceptable path: explicitly defer archive inspection

If archive inspection is too large for this pass, then:

- Remove the `zip` dependency from `synvoid-upload` if unused.
- Remove stale archive-inspection claims from docs.
- Add a short deferral note pointing to `plans/milestone_b_phase_2_bounded_archive_inspection.md`.
- Ensure existing heuristic archive-bomb detection is described as heuristic only, not structural archive traversal.
- Ensure unsupported archive containers are not reported as fully inspected.

### Success criteria

- Either bounded ZIP inspection is implemented and tested, or Phase 2 is explicitly marked open/deferred with unused dependencies removed.
- The docs and dependency graph agree with the implementation state.
- Archive scan failure or limit exceedance cannot become a clean upload under production defaults.

## Workstream 2: Upload scanner regression audit after Phase 1

### Problem

Phase 1 fixed the major issue where YARA errors were swallowed. The follow-up pass should verify that every relevant scan path now propagates errors consistently, including large-file/windowed paths and any archive-entry path added by Workstream 1.

### Tasks

1. Audit all public scanner methods:

- `MalwareScanner::scan_bytes`
- `MalwareScanner::scan_bytes_windowed`
- `MalwareScanner::scan_bytes_with_context`
- file-backed scan APIs
- large-file validation paths
- any archive-entry scan APIs added in this pass

2. Confirm YARA errors become `MalwareError::YaraScanError` or an equivalent propagated error.

3. Add tests for:

- YARA error during byte scan -> upload validator returns policy-handled indeterminate.
- YARA error during windowed scan -> policy-handled indeterminate.
- YARA error during large-file validation -> policy-handled indeterminate.
- YARA error during archive-entry scan, if archive scanning is implemented -> policy-handled indeterminate.
- fail-open still returns allowed but indeterminate/non-clean.

4. Confirm native matches still work when YARA is disabled.

5. Confirm native matches plus YARA matches dedupe deterministically.

### Success criteria

- No scanner path silently logs and returns clean after a YARA error.
- Fail-open remains explicit and non-clean.
- Native-only scanning remains available only when YARA is disabled or unavailable according to explicit policy.

## Workstream 3: Honeypot listener permit and accounting audit

### Problem

Phase 3 added RAII guards and semaphore admission. The implementation should be audited for leaked permits, premature releases, and inconsistent explicit `drop(...)` usage.

### Tasks

1. Review `handle_connection` and listener accept-loop branches.

Check every path:

- accept error
- global-limit rejection
- per-IP rejection
- EOF before initial data
- initial timeout
- initial read error
- read timeout after partial payload
- max payload truncation
- write error
- storage failure
- normal completion
- shutdown while connections are active

2. Ensure permit lifetime is simple and correct.

Preferred style:

- Own `_global_permit` and `_ip_guard` for the full handler lifetime.
- Let them drop naturally at function exit.
- Use explicit `drop(...)` only when intentionally releasing before returning from the same lexical scope.
- Avoid mixing explicit drops with assumptions that guards remain live for later accounting.

3. Add a test-only active permit/count inspection helper if needed.

4. Add or strengthen tests:

- permit released after initial EOF.
- permit released after initial timeout.
- permit released after read timeout.
- permit released after write error.
- permit released after storage failure.
- per-IP map has no zero-count retained entries after each early exit.
- global active count cannot underflow.

5. Recheck `active_connections.fetch_sub` behavior. Prefer saturating update or RAII active-count guard if any early branch could skip increment/decrement symmetry.

6. Confirm payload truncation does not drain unbounded attacker data indefinitely. If it drains after max payload, the drain loop must have timeout and total duration caps.

### Success criteria

- All handler exit paths release global and per-IP admission state exactly once.
- No explicit drop causes premature permit release while handler is still doing expensive work.
- `active_connections` cannot underflow.
- Truncation behavior is bounded and documented.

## Workstream 4: Protocol confidence and downstream actionability guardrails

### Problem

Phase 4 added confidence and evidence fields. Low-confidence protocol matches are useful for telemetry but should not trigger aggressive threat-intel action or mesh propagation by themselves.

### Tasks

1. Trace where `ProtocolMatch`, `ConnectionEvent`, or stored honeypot records feed into:

- threat-intel extraction
- blocklist generation
- mesh propagation
- risk scoring
- dashboard severity display
- logs and metrics

2. Ensure low-confidence protocol classification does not alone create a high-severity indicator.

3. Add confidence-aware mapping:

- High-confidence + malicious behavior -> stronger indicator.
- Medium-confidence + repeated behavior -> moderate indicator.
- Low-confidence only -> observe/telemetry, not block.

4. If the full threat-intel scoring rewrite belongs to Milestone C, add a minimal guard now:

- include confidence in the extracted honeypot indicator metadata
- cap severity for low-confidence protocol-only events
- avoid mesh propagation of low-confidence-only indicators unless explicitly configured

5. Add tests:

- low-confidence DNS/RDP/MongoDB-shaped payload does not produce high severity by itself.
- high-confidence SSH/HTTP/TLS detection preserves confidence in the record/indicator.
- unknown binary payload remains unknown and does not become actionable.

### Success criteria

- Confidence is not just stored; it prevents over-actionability.
- Low-confidence detections are safe telemetry by default.
- Any remaining richer scoring work is explicitly deferred to Milestone C.

## Workstream 5: Local validation evidence and handoff discipline

### Problem

GitHub CI is unavailable/unreliable for this workstream. Closure must therefore rely on local commands that are explicitly listed in commits or a closure note.

### Tasks

1. Add or update a local validation note under `plans/`, for example:

- `plans/milestone_b_local_validation_note.md`

2. Record exact commands run and outputs summarized:

Upload:

```bash
cargo fmt --all -- --check
cargo clippy -p synvoid-upload --all-targets -- -D warnings
cargo test -p synvoid-upload --all-targets
cargo test -p synvoid-upload --all-features --all-targets
```

Honeypot:

```bash
cargo clippy -p synvoid-honeypot --all-targets -- -D warnings
cargo test -p synvoid-honeypot --all-targets
cargo test -p synvoid-honeypot --all-features --all-targets
```

Dependency policy:

```bash
cargo deny check
```

Workspace smoke, if practical:

```bash
cargo test --workspace
```

3. If a command cannot be run locally, record:

- exact command
- failure reason
- whether failure is environment/tooling/unrelated/product
- substitute command used
- follow-up plan if product failure

4. Commit messages for implementation closure should include the local validation summary.

### Success criteria

- No claim of “clean” is unsupported by local command evidence.
- Local validation failures are not hidden.
- The next reviewer can reproduce the same commands.

## Workstream 6: Documentation reconciliation

### Tasks

Update and reconcile:

- `architecture/upload.md`
- `docs/UPLOADS.md`
- `architecture/honeypot.md`
- `AGENTS.md` command snippets
- Phase plan completion notes
- `Cargo.toml` dependency rationale if `zip` remains

Specific checks:

- Upload docs state whether bounded archive inspection is implemented or deferred.
- Upload docs state that YARA errors propagate and do not become clean.
- Native detector docs distinguish native fallback from YARA-X.
- Honeypot docs state exact timeout semantics.
- Honeypot docs state exact truncation behavior.
- Protocol docs state confidence/actionability limits.
- Local validation notes explain that GitHub CI is not currently authoritative for this line.

### Success criteria

- Docs do not claim Phase 2 archive support unless tests and implementation exist.
- Docs match current config names and defaults.
- Risky modes and partial-coverage modes are clearly marked.

## Suggested execution order

1. Decide archive inspection path: implement ZIP inspection or explicitly defer and remove unused `zip` dependency.
2. Audit scanner error propagation across all scan paths.
3. Audit listener permit/drop behavior and add early-exit tests.
4. Add protocol confidence guardrails in threat-intel/actionability path.
5. Reconcile docs and add local validation note.
6. Run local validation commands and record results.

## Final acceptance checklist

- [ ] Phase 2 archive inspection implemented and tested, or explicitly deferred with unused dependencies removed.
- [ ] `zip` dependency is justified by implementation or removed.
- [ ] YARA errors propagate through byte, windowed, large-file, and archive-entry scan paths.
- [ ] Fail-open remains allowed-but-indeterminate/non-clean.
- [ ] Listener permits release exactly once on all exit paths.
- [ ] Per-IP counts do not retain zero entries.
- [ ] `active_connections` cannot underflow.
- [ ] Payload truncation is bounded and documented.
- [ ] Protocol confidence flows into records/indicators.
- [ ] Low-confidence-only detections do not trigger aggressive action.
- [ ] Local validation commands are recorded in a closure note or commit message.
- [ ] Docs match the implementation state.

## Handoff guidance

This pass should close Milestone B implementation quality, not start Milestone C. If threat-intel scoring, honeypot storage batching, AI responder containment, or tarpit safety issues are encountered, add them to the next milestone notes and keep this pass focused on the follow-up gaps listed above.
