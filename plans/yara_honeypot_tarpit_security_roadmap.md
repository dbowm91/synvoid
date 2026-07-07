# YARA-X, Honeypot, Tarpit, and Deception Security Roadmap

## Purpose

This roadmap covers the production-hardening line of work for SynVoid's upload malware scanning, YARA-X rule lifecycle, honeypot deception layer, tarpit behavior, threat-intelligence extraction, and operator-facing security posture. The focus is to make the system safe under adversarial load, explicit about failure modes, resistant to false confidence, and scalable enough to run as part of the WAF data plane without turning defensive features into denial-of-service surfaces.

The motivating review found four high-priority themes:

1. YARA-X upload scanning is real and wired into `synvoid-upload`, but scan errors and timeouts are currently represented as clean uploads in several validation paths.
2. Large-file validation scans only the upload header, which is sufficient for MIME detection but not sufficient for malware detection.
3. YARA-X execution and reload behavior needs bounded concurrency, better timeout semantics, atomic rule generation swaps, rule provenance, and dependency-policy enforcement.
4. Honeypot and tarpit designs are promising but need correctness, budgeting, fingerprint-resistance, storage scalability, AI containment, and actionability scoring before public production release.

## Design principles

Security features must not silently fail open unless a deployer explicitly chooses that behavior for a known low-risk path. A scan timeout, scan panic, rule compile failure, or unavailable scanner is not equivalent to a clean file.

Scanning must be bounded in memory, CPU, task count, queue depth, and wall-clock time. When bounded resources are exhausted, the system should apply an explicit failure policy and emit metrics rather than spawning unbounded background work.

Rule updates must be treated as a trust-boundary event. Local directories, mesh-distributed rules, source text, and compiled rule blobs should have deterministic ordering, size limits, versioning, hashes, and signatures where appropriate. Bad rule updates should not destroy the last known good generation.

Honeypot data should inform security decisions, not automatically become a punitive mesh-wide decision. Deception telemetry needs evidence scoring, decay, and staged actions to avoid overblocking shared networks, researchers, benign scanners, or spoofed/noisy inputs.

Tarpits should consume more attacker time than defender resources. Any long-lived stream, slow-drip response, or generated page needs admission control and cancellation behavior.

AI responders must be optional, constrained, and isolated. The model must not receive real secrets, internal mesh state, admin credentials, environment data, or unconstrained egress/tool access.

## Milestones

### Milestone A: YARA-X upload security boundary and rule lifecycle

Milestone A is the first production-critical milestone. It closes the upload boundary so malware scan failures cannot be mislabeled as clean uploads, makes large-file scanning meaningful, bounds YARA execution under hostile upload load, and hardens rule provenance/dependency enforcement.

Detailed plan files:

- `plans/milestone_a_phase_1_yara_failure_semantics.md`
- `plans/milestone_a_phase_2_large_file_scanning.md`
- `plans/milestone_a_phase_3_yara_execution_reload.md`
- `plans/milestone_a_phase_4_rule_provenance_dependency_policy.md`

Exit criteria:

- Upload validation distinguishes clean, malicious, scan-disabled, and scan-indeterminate outcomes.
- Production defaults do not silently accept uploads after YARA timeout, scan panic, scan error, or reload failure.
- Large-file scanning no longer scans only the first 8 KiB when YARA scanning is enabled.
- YARA scan execution is bounded by explicit concurrency and queue limits.
- Rule reloads use a last-known-good generation and avoid holding a global scan lock across long-running scans.
- Rule sources have deterministic ordering, size/file-count limits, and documented provenance behavior.
- CI or dependency policy checks prevent accidental regression to known-vulnerable YARA-X/wasmtime/RSA-related dependency exposure.

### Milestone B: Detector and honeypot correctness

Milestone B repairs native detector correctness and the port honeypot runtime. It should be started only after Milestone A makes upload scanning failure-safe.

Planned phases:

1. Native malware detector correctness pass.
2. Real bounded archive inspection.
3. Honeypot listener concurrency and accounting hardening.
4. Honeypot protocol detection normalization and binary protocol correctness.

Expected outcomes:

- PE/ZIP polyglot and embedded executable detection are corrected.
- Archive-bomb claims are backed by actual bounded archive traversal or renamed as heuristics until traversal exists.
- Honeypot connection caps are enforced with semaphores rather than race-prone atomic checks.
- Per-IP accounting is bounded and expiring.
- Honeypot payload reads honor `max_payload_size` and total bytes are recorded accurately.
- TLS, MySQL, SMB, PostgreSQL, Redis, HTTP, SSH, and unknown payload fixtures produce stable normalized protocol IDs.

### Milestone C: Deception scalability, actionability, AI containment, and tarpit hardening

Milestone C addresses operational scale and false-positive risk in the deception layer.

Planned phases:

1. Honeypot storage batching, retention, and pressure behavior.
2. Threat-intelligence scoring and mesh actionability tiers.
3. AI honeypot containment and budget controls.
4. Tarpit escaping, admission control, stream budgets, and fingerprint resistance.

Expected outcomes:

- Honeypot writes are batched through a bounded writer pipeline.
- Raw payload retention is bounded and configurable.
- Honeypot events become scored evidence with decay rather than immediate mesh-wide punishments.
- AI responders are off by default or clearly opt-in, budgeted, local-first, and sanitized.
- Tarpit redirect generation is escaped and long-lived streams are globally/per-IP bounded.
- Generated tarpit pages are less fingerprintable and more site-specific.

### Milestone D: Observability, CI, fuzzing, and release documentation

Milestone D makes the hardening durable and operator-visible.

Planned phases:

1. Cross-system security event schema and admin observability.
2. Metrics for scan outcomes, scan queue state, rule reloads, honeypot load, tarpit load, AI budgets, and mesh actionability.
3. Fixture tests and fuzzing for uploads, multipart parsing, YARA reloads, protocol detection, tarpit path handling, and archive traversal.
4. Documentation cleanup for production deployment, fail-policy semantics, YARA rule trust, honeypot/tarpit risk, AI responder risk, and recommended defaults.

Expected outcomes:

- Operators can determine scanner health, active rule generation, scan failure rates, queue pressure, honeypot pressure, tarpit pressure, and mesh block escalation state without reading source code.
- CI prevents regressions on the failure-open upload bug, header-only large-file scanning, protocol normalization bugs, and tarpit escaping bugs.
- Public documentation accurately describes the security model and the risk tradeoffs of optional features.

## Implementation order

The implementation order should not be rearranged casually. Milestone A should land before deeper honeypot/tarpit work because accepting uploads after failed malware scans is the clearest release-blocking issue. Within Milestone A, Phase 1 should land before Phase 2 because scan coverage improvements are less meaningful while scan errors are still clean. Phase 3 should land before high-volume production deployment because YARA timeout behavior can otherwise create latent background work. Phase 4 should land before depending on distributed or operator-provided rule updates.

Recommended first commit sequence:

1. Add explicit scan failure policy and error variants.
2. Update all upload validation paths to apply the policy consistently.
3. Add regression tests for scan timeout/error behavior.
4. Add large-file scan mode and full/sampled scanning implementation.
5. Add bounded YARA scan executor and scan metrics.
6. Replace long-held scan `RwLock` with immutable rule generations.
7. Add rule-source limits, deterministic loading, last-known-good reload semantics, and dependency policy gates.

## Release-readiness definition

This line of work can be considered release-ready when upload scanning is failure-explicit, large-file scanning is meaningful, YARA execution cannot be used to exhaust unbounded resources, rule updates have a documented trust model, honeypot and tarpit features have resource budgets, deception telemetry does not create overbroad mesh blocks, and CI exercises the security invariants that motivated the work.
