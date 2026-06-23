# Skills Directory - AGENTS.override.md

Skills are now organized in `.opencode/skills/` with each skill in its own directory.
The `.agents/skills` symlink points to the same location for codex compatibility.

## Skill Structure

Each skill lives in `.opencode/skills/<name>/SKILL.md` with frontmatter:

```markdown
---
name: <skill-name>
description: <one-line description>
---
```

## Skill Index

| Skill | Purpose |
|-------|---------|
| `admin_api` | Admin API patterns for config management, versioning, and system monitoring |
| `admin_ui` | Admin UI architecture for the Yew-based WASM frontend |
| `behavioral_intel` | Federated behavioral intelligence for sharing anonymized attack patterns |
| `buffer_pool` | Sharded mutex buffer pool (replaces TreiberStack with ABA-safe implementation) |
| `crypto_dependencies` | Cryptographic dependency analysis and post-quantum considerations |
| `dht_persistence` | DHT neighborhood persistence for mesh warm-up acceleration |
| `dht_scoping` | DHT site isolation and scoping patterns |
| `dns_dnssec` | DNS server, DNSSEC validation, and TSIG authentication patterns |
| `ebpf_blocking` | eBPF-based SYN-level traffic dropping and block store integration |
| `erased_http_client` | ErasedHttpClient streaming pool patterns |
| `h3_proxy` | HTTP/3 QUIC proxy architecture and streaming implementation |
| `hickory_migration` | hickory-dns resolver migration patterns |
| `httpserver` | HTTP server architecture with dual-mode implementation |
| `hybrid_post_quantum` | Hybrid Ed25519 + ML-DSA-44 post-quantum mesh signatures |
| `implementation_patterns` | Common implementation patterns (semaphore, debounce, atomic writes) |
| `ipc_hardening` | IPC signing, replay protection, and authentication patterns |
| `org_key_trust_chain` | Organization key trust chain for hierarchical mesh authentication |
| `raft_consensus` | Raft consensus integration for global control plane |
| `rule_feed_persistence` | Signed rule feed persistence and hot-reload |
| `sandboxing` | OS sandboxing (Windows/macOS/Linux/BSD) |
| `security_patterns` | Security patterns (constant-time comparison, path traversal, XSS prevention) |
| `serverless_wasm` | Serverless WASM runtime with instance pooling |
| `static_files` | Static file serving and directory listing patterns |
| `streaming_waf` | Streaming WAF engine for incremental body scanning |
| `supply_chain_hashes` | Supply chain security with pip --require-hashes |
| `synvoid_mesh` | Mesh networking architecture with DHT-based service discovery |
| `threat_feed_production` | Production and signing of threat intel feeds |
| `topology_visualizer` | Real-time topology visualizer API |
| `waf_bot_detection` | WAF bot detection for automated client identification |
| `windows_service` | Windows service integration and developer experience |