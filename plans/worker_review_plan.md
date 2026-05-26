# Worker Review Plan

## Stale Items Identified

1. **WAF Pipeline "Challenge" stage not separate** - Challenge logic is inline in bot protection, not a separate pipeline stage
   - Reference: `architecture/worker_architecture.md:27-34`
   - Action: Update architecture docs to reflect actual implementation

2. **Health monitoring overstated** - Implementation is primarily passive with optional active probing
   - Action: Correct documentation to accurately describe passive-first monitoring approach

3. **CPU affinity platform limitation not documented**
   - Action: Document that CPU affinity is Linux-only with appropriate warnings for other platforms

## Bugs

| Severity | Issue | Location | Status |
|----------|-------|----------|--------|
| Minor | HTTP/2 disabled but documented as supported | `src/http_client/mod.rs:890` | Needs documentation update |
| Minor | Mesh control plane disabled in worker | `if true` block | Verify if intentional |

## Review Actions

- [ ] Update `architecture/worker_architecture.md` to reflect actual WAF pipeline structure
- [ ] Correct health monitoring documentation to describe passive-first approach
- [ ] Add platform limitation notes for CPU affinity feature
- [ ] Update HTTP/2 status documentation to reflect disabled state
- [ ] Investigate mesh control plane `if true` block for intentionality
