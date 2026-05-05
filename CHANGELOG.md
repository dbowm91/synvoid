# Changelog

All notable changes to SynVoid will be documented in this file.

## [Planned]

### Added
- Raft consensus for high availability

## [Unreleased]

### Added
- HTTP/3 (QUIC) support
- WireGuard VPN tunnel integration (removed, use QUIC mesh instead)
- WAF clustering with peer-to-peer communication
- WASM plugin system for custom logic
- Upload validation with YARA malware scanning
- Adaptive threat level system with baseline learning
- Prometheus metrics for comprehensive monitoring
- Admin API with WebSocket support
- Traffic shaping with token bucket algorithm
- Proxy cache for upstream performance
- FastCGI protocol proxying
- TCP/UDP protocol filtering
- Multi-site management from single instance
- SYN flood protection with half-open connection tracking
- Connection rate limiting per IP and globally
- UDP flood protection with per-port granularity
- AI crawler blocking with CSS honeypot
- Scraper tarpit with Markov chain content generation
- Post-quantum TLS support
- Real-time metrics streaming via WebSocket
- Structured JSON logging
- Custom error pages support

### Changed
- Improved performance with Tokio async runtime
- Enhanced security with header sanitization
- Better memory management for rate limiting
- Optimized connection pooling
- Improved error handling and reporting
- Enhanced configuration validation

### Fixed
- Various security vulnerabilities
- Memory leaks in connection handling
- Race conditions in worker coordination
- Configuration parsing issues
- Logging format inconsistencies

## [1.0.0] - 2026-02-23

### Initial Release

- Complete WAF and reverse proxy implementation
- Multi-layer attack detection
- Comprehensive flood protection
- High-performance reverse proxying
- Extensive configuration options
- Production-ready deployment guide
- Detailed documentation and examples

## [0.9.0] - 2026-01-15

### Beta Release

- Core WAF functionality
- Basic reverse proxy capabilities
- Initial attack detection rules
- Basic configuration system
- Early documentation

## [0.1.0] - 2025-12-01

### Initial Development

- Project initialization
- Basic structure setup
- Initial feature planning
- Early proof of concept

[Unreleased]: https://github.com/synvoid/synvoid/compare/v1.0.0...HEAD
[1.0.0]: https://github.com/synvoid/synvoid/releases/tag/v1.0.0
[0.9.0]: https://github.com/synvoid/synvoid/releases/tag/v0.9.0
[0.1.0]: https://github.com/synvoid/synvoid/releases/tag/v0.1.0