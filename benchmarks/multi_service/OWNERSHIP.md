# Ownership — multi-service benchmarks

- **Class:** manual performance-evidence harness, not a CI gate.
- **Canonical location:** `benchmarks/multi_service/`.
- **Runtime code:** none. `driver.py` and the helpers are Python standard
  library only. They must not be imported by the SynVoid application, and they
  must never become a root Cargo dependency.
- **Subject:** a binary built from the checkout SHA recorded in every result.
  The harness may start and stop that binary; it may not patch production code
  to make a workload easier.
- **Results:** `results/YYYY-MM-DD/`. A dated directory is append-only. Never
  delete or rewrite a prior run; add a new run instead.
- **Owners:** the performance/maintainer group that owns `benches/` and
  `benchmarks/http_transport/`. Changes to the workload matrix, result schema
  or topology require the same review as a benchmark-definition change.
- **What is deliberately not owned here:** production configuration, deployment
  manifests, service supervision, and any claim that a loopback result predicts
  a real-network capacity. Those belong to the deployment and operations docs.
