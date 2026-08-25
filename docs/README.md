# SynVoid Documentation

Welcome to the SynVoid documentation. This index provides quick access to all documentation.

## Quick Links

| Topic | Documentation |
|-------|--------------|
| Quick Start | [GETTING_STARTED.md](GETTING_STARTED.md) |
| Architecture | [ARCHITECTURE.md](ARCHITECTURE.md) |
| Configuration | [CONFIGURATION.md](CONFIGURATION.md) |
| Deployment | [DEPLOYMENT.md](DEPLOYMENT.md) |
| API Reference | [API_REFERENCE.md](API_REFERENCE.md) |

## Getting Started

- [README.md](../README.md) - Project overview with quick start
- [GETTING_STARTED.md](GETTING_STARTED.md) - Detailed quick start guide with CLI options

## Architecture

- [ARCHITECTURE.md](ARCHITECTURE.md) - System architecture and design overview
- [DEVELOPER.md](DEVELOPER.md) - Developer & DevOps technical guide
- [PROCESS_MANAGEMENT.md](PROCESS_MANAGEMENT.md) - Process management details

## Configuration

- [CONFIGURATION.md](CONFIGURATION.md) - Complete configuration reference
- [GETTING_STARTED.md](GETTING_STARTED.md) - Configuration examples
- [DEPLOYMENT.md](DEPLOYMENT.md) - Production configuration

## Core Features

| Document | Description |
|----------|-------------|
| [ATTACK_DETECTION.md](ATTACK_DETECTION.md) | Attack detection (SQLi, XSS, SSRF, etc.) |
| [BOT_PROTECTION.md](BOT_PROTECTION.md) | Bot detection and AI crawler blocking |
| [FLOOD_PROTECTION.md](FLOOD_PROTECTION.md) | SYN/UDP flood and connection protection |
| [RATE_LIMITING.md](RATE_LIMITING.md) | Request rate limiting |
| [REQUEST_SANITIZATION.md](REQUEST_SANITIZATION.md) | Request sanitization and header handling |
| [STATIC_FILES.md](STATIC_FILES.md) | Static file serving and optimization |
| [TARPIT.md](TARPIT.md) | Anti-scraping tarpit behavior |

## Upstream Management

- [UPSTREAM_HEALTH.md](UPSTREAM_HEALTH.md) - Health checking and upstream monitoring

## Advanced Features

SynVoid includes additional features for specific use cases:

| Document | Description |
|----------|-------------|
| [HTTP3.md](HTTP3.md) | HTTP/3 (QUIC) support for lower latency |
| [TUNNELS.md](TUNNELS.md) | QUIC tunnels and site-to-site connectivity |
| [WAF_MESH.md](WAF_MESH.md) | Peer-to-peer mesh networking for DDoS mitigation |
| [THREAT_INTEL.md](THREAT_INTEL.md) | Threat intelligence feeds and mesh sharing |
| [SIGNED_RULE_FEED.md](SIGNED_RULE_FEED.md) | Cryptographically signed WAF rule distribution |
| [UPLOADS.md](UPLOADS.md) | File upload validation and malware scanning |
| [FASTCGI.md](FASTCGI.md) | FastCGI proxy support for PHP, Python, etc. |
| [PLUGINS.md](PLUGINS.md) | WASM plugin system for custom extensions |
| [PLUGIN_CONFIG_REFERENCE.md](PLUGIN_CONFIG_REFERENCE.md) | Plugin configuration reference |
| [PLUGIN_OPERATOR_RUNBOOK.md](PLUGIN_OPERATOR_RUNBOOK.md) | Plugin operational runbook |
| [SERVERLESS.md](SERVERLESS.md) | Serverless WASM function execution |
| [WASM-ABI.md](WASM-ABI.md) | Plugin WASM ABI specification |
| [SANDBOXING.md](SANDBOXING.md) | OS-level process sandboxing |
| [THREAT_LEVEL.md](THREAT_LEVEL.md) | Adaptive threat detection with auto-escalation |
| [TRAFFIC_SHAPING.md](TRAFFIC_SHAPING.md) | Bandwidth limiting and rate shaping |
| [PROXY_CACHE.md](PROXY_CACHE.md) | Response caching for performance |
| [ADMIN_UI.md](ADMIN_UI.md) | Web-based admin interface |

## DNS

- [RFC5011_TRUST_ANCHOR.md](RFC5011_TRUST_ANCHOR.md) - DNSSEC trust anchor automation
- [dns-dnssec-architecture.md](dns-dnssec-architecture.md) - DNSSEC validation architecture
- [dns-mesh-integration.md](dns-mesh-integration.md) - DNS subsystem mesh integration
- [global-node-ca.md](global-node-ca.md) - Global node certificate authority

## Operations

- [DEPLOYMENT.md](DEPLOYMENT.md) - Production deployment guide
- [UPGRADE.md](UPGRADE.md) - Upgrade guide and breaking changes
- [RELEASE.md](RELEASE.md) - Release lifecycle and versioning policy
- [RELEASE_CHECKLIST.md](RELEASE_CHECKLIST.md) - Pre-release verification checklist
- [releasing.md](releasing.md) - Manual crate publication mechanics
- [PERFORMANCE.md](PERFORMANCE.md) - Performance tuning and latency optimization
- [TROUBLESHOOTING.md](TROUBLESHOOTING.md) - Common issues and solutions
- [FAQ.md](FAQ.md) - Frequently asked questions
- [API_REFERENCE.md](API_REFERENCE.md) - Admin API documentation
- [PLATFORM_SUPPORT.md](PLATFORM_SUPPORT.md) - Platform-specific notes
- [SECURITY.md](SECURITY.md) - Security hardening guide

## Additional Resources

- [GitHub Repository](https://github.com/dbowm91/synvoid)
- [Example Configurations](../config/)
- [Example Sites](../config/sites/)
- [CONTRIBUTING.md](../CONTRIBUTING.md) - Contribution guidelines
- [CHANGELOG.md](../CHANGELOG.md) - Version history
