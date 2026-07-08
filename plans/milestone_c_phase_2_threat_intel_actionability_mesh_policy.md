# Milestone C Phase 2: Honeypot Threat-intel Actionability and Mesh Propagation Policy

## Purpose

Convert honeypot observations into controlled, confidence-aware indicators with explicit action classes. Milestone B added confidence capping so low-confidence protocol detections cannot directly become high-severity actions. This phase completes the actionability model: scoring, dedupe, decay, thresholds, and mesh propagation policy.

## Current issues to address

1. Raw honeypot events can produce indicators too directly.
2. Severity is capped by confidence, but action class and propagation threshold are not yet fully explicit.
3. Repeated low-quality signals need dedupe and decay rather than immediate blocking.
4. Mesh propagation should be gated by stronger evidence than local telemetry.
5. Indicator metadata should be minimal, non-sensitive, and reproducible.

## Non-goals

- Do not make every honeypot hit a block.
- Do not propagate low-confidence single events mesh-wide by default.
- Do not include raw payload bytes in threat-intel metadata.
- Do not replace block-store policy engine; integrate with it through explicit action classes.

## Target model

Introduce or adapt an actionability model:

```rust
enum IndicatorActionClass {
    Observe,
    LocalRateLimitCandidate,
    LocalBlockCandidate,
    MeshShareCandidate,
    MeshBlockCandidate,
}

struct HoneypotSignalScore {
    confidence: Confidence,
    severity: SeverityLevel,
    event_count: u32,
    distinct_ports: u32,
    attack_patterns: u32,
    first_seen: i64,
    last_seen: i64,
    score: f64,
    action_class: IndicatorActionClass,
}
```

Names can differ; behavior should not.

## Implementation tasks

### 1. Define signal classes

Classify honeypot events by evidence type:

- protocol-only first packet
- known attack pattern
- repeated hits across ports
- payload with exploit markers
- credential attempt
- webshell/malware upload correlation if available
- known scanner fingerprint

### 2. Add scoring and decay

Implement bounded scoring:

- high-confidence attack pattern increases score more than protocol-only hit
- repeated hits increase score with diminishing returns
- events decay over time
- noisy single hits expire
- payload truncation should reduce confidence if content is incomplete

### 3. Define action thresholds

Example default thresholds:

- `Observe`: default for unknown/low-confidence single event
- `LocalRateLimitCandidate`: repeated low/medium confidence events
- `LocalBlockCandidate`: high-confidence malicious event or repeated medium evidence
- `MeshShareCandidate`: local block candidate with stable evidence
- `MeshBlockCandidate`: repeated high-confidence evidence or multiple independent indicators

Do not hardcode thresholds without config unless the product already centralizes policy. Prefer config with safe defaults.

### 4. Mesh propagation guardrails

Mesh propagation must require:

- minimum confidence
- minimum severity after capping
- minimum event count or strong pattern evidence
- dedupe key
- TTL/expiry
- provenance metadata

Include local-only action class if mesh is disabled or evidence is insufficient.

### 5. Metadata minimization

Threat-intel metadata should include:

- payload hash, not raw payload
- retained/truncated flags
- protocol, confidence, evidence string
- event count and time window
- local site/scope if needed

Avoid full payload hex in propagated metadata.

### 6. Tests

Required tests:

- low-confidence protocol-only hit -> Observe
- repeated low-confidence hits -> LocalRateLimitCandidate at most, unless configured otherwise
- high-confidence attack pattern -> LocalBlockCandidate
- high-confidence repeated exploit patterns -> MeshShareCandidate or MeshBlockCandidate according to threshold
- payload-truncated event does not over-score content-specific evidence
- decayed old events reduce score/action class
- duplicate events collapse under dedupe key
- mesh disabled -> no mesh action class

## Local validation commands

```bash
cargo fmt --all -- --check
cargo clippy -p synvoid-honeypot --all-targets -- -D warnings
cargo test -p synvoid-honeypot --all-targets threat_intel
cargo test -p synvoid-honeypot --all-targets
```

If mesh integration is touched:

```bash
cargo clippy -p synvoid-mesh --all-targets -- -D warnings
cargo test -p synvoid-mesh --all-targets
cargo test -p synvoid-honeypot --features mesh --all-targets
```

## Success criteria

- Indicators have explicit action classes.
- Low-confidence single events cannot trigger aggressive block/mesh actions.
- Mesh propagation is thresholded, deduped, and TTL-bound.
- Raw payload is not propagated.
- Tests cover confidence, scoring, decay, dedupe, and mesh-disabled behavior.

## Handoff notes

This phase depends on stable confidence/record metadata from Milestone B and benefits from Phase 1 payload hash/retention fields. If Phase 1 is not complete, keep metadata additions minimal and avoid storing/propagating raw payload bytes.
