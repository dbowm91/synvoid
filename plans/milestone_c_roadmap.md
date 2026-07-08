# Milestone C Roadmap: Deception Pipeline Safety and Operationalization

## Purpose

Milestone C builds on the completed upload/honeypot hardening line by tightening the broader deception pipeline: honeypot storage/write behavior, threat-intel actionability, AI responder containment, and tarpit safety/scalability.

Milestone C should not reopen Milestone B upload/archive/protocol work unless a validation failure proves a regression. Treat Milestone B as the baseline and focus on the remaining deception and operational safety surfaces.

## Milestone C phases

1. **Phase 1: Honeypot Storage Writer, Retention, and Backpressure**
   - Replace or harden direct synchronous storage writes.
   - Add bounded writer queue semantics.
   - Add retention/truncation policy for payloads and metadata.
   - Ensure storage failures cannot stall listener tasks or leak sensitive payloads.

2. **Phase 2: Honeypot Threat-intel Actionability and Mesh Propagation Policy**
   - Convert raw honeypot events into scored indicators with action classes.
   - Prevent low-confidence or single noisy events from becoming aggressive blocks.
   - Define mesh propagation thresholds and dedupe/decay behavior.

3. **Phase 3: AI Responder Containment and Async Boundary Cleanup**
   - Remove unsafe/blocking runtime patterns such as `block_on` from async contexts.
   - Add strict local/off/default-off responder mode.
   - Bound prompts, responses, tool/network access, error leakage, and cost.

4. **Phase 4: Tarpit Safety, Escaping, Admission, and Fingerprint Resistance**
   - Fix response escaping and redirect safety.
   - Add admission and duration budgets for long-lived streams.
   - Reduce deterministic/fingerprintable output patterns.
   - Guard edge cases such as zero-depth generation.

5. **Phase 5: Milestone C Validation and Operator Documentation**
   - Run local validation for all deception components.
   - Add operator docs for storage, actionability, responder modes, tarpit limits, and known limitations.
   - Produce final Milestone C closure note.

## Completion criteria

Milestone C is complete when:

- Honeypot listener writes are bounded and cannot block or exhaust runtime resources.
- Payload retention is configurable, documented, and defaults to safe minimization.
- Threat-intel indicators have action classes, confidence, dedupe, decay, and mesh propagation thresholds.
- AI responder is safe-by-default, bounded, async-correct, and does not leak internal errors or fake credentials into unsafe contexts.
- Tarpit responses are escaped, bounded, admission-controlled, and less fingerprintable.
- Local validation commands are recorded because GitHub CI may not be authoritative.
- Docs accurately describe operational behavior and release limitations.

## Non-goals

- Do not implement full malware analysis or antivirus behavior.
- Do not expand archive format support here.
- Do not add external AI provider integrations without containment.
- Do not turn low-interaction honeypots into unrestricted high-interaction sandboxes.
- Do not treat mesh-wide blocking as default for weak signals.
