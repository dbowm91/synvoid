use yew::prelude::*;

#[function_component]
pub fn SinglePage() -> Html {
    html! {
            <div class="singlepage-container">
                <div class="glass-grid-bg"></div>
                <div class="glass-orb glass-orb-1"></div>
                <div class="glass-orb glass-orb-2"></div>
                <div class="glass-orb glass-orb-3"></div>

                <nav class="singlepage-nav">
                    <div class="singlepage-nav-inner">
                        <a href="/" class="singlepage-logo">
                            <div class="singlepage-logo-icon">{"M"}</div>
                            <span>{"MaluWAF"}</span>
                        </a>
                        <div class="singlepage-nav-links">
                            <a href="#hero" class="singlepage-nav-link">{"Home"}</a>
                            <a href="#features" class="singlepage-nav-link">{"Features"}</a>
                            <a href="#protection" class="singlepage-nav-link">{"Protection"}</a>
                            <a href="#architecture" class="singlepage-nav-link">{"Architecture"}</a>
                            <a href="#deployment" class="singlepage-nav-link">{"Deploy"}</a>
                            <a href="/docs" class="singlepage-nav-link">{"Docs"}</a>
                            <a href="https://github.com/maluwaf/maluwaf" target="_blank" rel="noopener noreferrer" class="singlepage-nav-link">{"GitHub"}</a>
                            <a href="http://localhost:8081" class="singlepage-cta">{"Admin"}</a>
                        </div>
                    </div>
                </nav>

                <main>
                    <section id="hero" class="singlepage-hero">
                        <div class="singlepage-hero-content">
                            <div class="singlepage-badge">
                                <span class="singlepage-badge-dot"></span>
                                {"v2.0 "} <span class="singlepage-badge-text">{"now with HTTP/3"}</span>
                            </div>
                            <h1 class="singlepage-title">
                                {"Production-Ready"}
                                <span class="singlepage-title-accent">{"WAF & Reverse Proxy"}</span>
                            </h1>
                            <p class="singlepage-subtitle">
                                {"High-performance web application firewall written in Rust. Protects your applications from attacks while delivering exceptional performance."}
                            </p>
                            <div class="singlepage-hero-actions">
                                <a href="#deployment" class="singlepage-btn-primary">
                                    <span>{"Get Started"}</span>
                                    <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                                        <path d="M5 12h14M12 5l7 7-7 7"/>
                                    </svg>
                                </a>
                                <a href="#features" class="singlepage-btn-secondary">{"View Features"}</a>
                            </div>
                            <div class="singlepage-code-block">
                                <div class="singlepage-code-header">
                                    <span>{"Quick Start"}</span>
                                </div>
                                <pre><code><span class="singlepage-code-comment">{"# Clone and build"}</span>
    <span class="singlepage-code-cmd">{"git"}</span><span class="singlepage-code-text">{" clone https://github.com/maluwaf/maluwaf.git"}</span>
    <span class="singlepage-code-cmd">{"cd"}</span><span class="singlepage-code-text">{" maluwaf"}</span>
    <span class="singlepage-code-cmd">{"cargo"}</span><span class="singlepage-code-text">{" build --release"}</span>

    <span class="singlepage-code-comment">{"# Run"}</span>
    <span class="singlepage-code-success">{"."}</span><span class="singlepage-code-text">{"/target/release/maluwaf"}</span></code></pre>
                            </div>
                        </div>
                    </section>

                    <section id="stats" class="singlepage-stats">
                        <div class="singlepage-glass-card singlepage-stats-card">
                            <div class="singlepage-stat">
                                <div class="singlepage-stat-value">{"100K+"}</div>
                                <div class="singlepage-stat-label">{"Requests/second"}</div>
                            </div>
                        </div>
                        <div class="singlepage-glass-card singlepage-stats-card">
                            <div class="singlepage-stat">
                                <div class="singlepage-stat-value">{"<1ms"}</div>
                                <div class="singlepage-stat-label">{"Latency overhead"}</div>
                            </div>
                        </div>
                        <div class="singlepage-glass-card singlepage-stats-card">
                            <div class="singlepage-stat">
                                <div class="singlepage-stat-value">{"15+"}</div>
                                <div class="singlepage-stat-label">{"Attack types detected"}</div>
                            </div>
                        </div>
                        <div class="singlepage-glass-card singlepage-stats-card">
                            <div class="singlepage-stat">
                                <div class="singlepage-stat-value">{"99.9%"}</div>
                                <div class="singlepage-stat-label">{"Attack block rate"}</div>
                            </div>
                        </div>
                    </section>

                    <section id="features" class="singlepage-section">
                        <h2 class="singlepage-section-title">{"Enterprise-Grade Security"}</h2>
                        <p class="singlepage-section-subtitle">{"Comprehensive protection for your web applications"}</p>
                        <div class="singlepage-features-grid">
                            <div class="singlepage-feature-card">
                                <div class="singlepage-feature-icon">{"🛡️"}</div>
                                <h3>{"WAF Protection"}</h3>
                                <p>{"Multi-layer defense against SQL injection, XSS, CSRF, SSRF, path traversal, and more with customizable rule sets."}</p>
                            </div>
                            <div class="singlepage-feature-card">
                                <div class="singlepage-feature-icon">{"🌊"}</div>
                                <h3>{"Flood Protection"}</h3>
                                <p>{"SYN flood, UDP flood, and connection rate limiting with eBPF-based detection."}</p>
                            </div>
                            <div class="singlepage-feature-card">
                                <div class="singlepage-feature-icon">{"🤖"}</div>
                                <h3>{"Bot Mitigation"}</h3>
                                <p>{"AI crawler blocking, CSS honeypot traps, JavaScript challenges, and behavioral analysis."}</p>
                            </div>
                            <div class="singlepage-feature-card">
                                <div class="singlepage-feature-icon">{"⚡"}</div>
                                <h3>{"HTTP/3 & QUIC"}</h3>
                                <p>{"Modern protocol support with 0-RTT connections, improved latency, and built-in encryption."}</p>
                            </div>
                            <div class="singlepage-feature-card">
                                <div class="singlepage-feature-icon">{"🔄"}</div>
                                <h3>{"High Availability"}</h3>
                                <p>{"Master-worker clustering with Raft consensus, automatic failover, and configuration sync."}</p>
                            </div>
                            <div class="singlepage-feature-card">
                                <div class="singlepage-feature-icon">{"📊"}</div>
                                <h3>{"Real-time Monitoring"}</h3>
                                <p>{"Live metrics dashboard, WebSocket updates, Prometheus export, and structured logging."}</p>
                            </div>
                            <div class="singlepage-feature-card">
                                <div class="singlepage-feature-icon">{"🔌"}</div>
                                <h3>{"Plugin System"}</h3>
                                <p>{"Extend functionality with WASM plugins. Dynamic loading without restarts."}</p>
                            </div>
                            <div class="singlepage-feature-card">
                                <div class="singlepage-feature-icon">{"🏗️"}</div>
                                <h3>{"Multi-Backend"}</h3>
                                <p>{"Native support for PHP-FPM, Python (Granian), FastCGI, and static files."}</p>
                            </div>
                            <div class="singlepage-feature-card">
                                <div class="singlepage-feature-icon">{"🔗"}</div>
                                <h3>{"WAF Mesh"}</h3>
                                <p>{"Peer-to-peer communication between instances for distributed threat intelligence."}</p>
                            </div>
                        </div>
                    </section>

                    <section id="protection" class="singlepage-section">
                        <h2 class="singlepage-section-title">{"Attack Detection & Prevention"}</h2>
                        <p class="singlepage-section-subtitle">{"Industry-leading protection against the OWASP Top 10"}</p>
                        <div class="singlepage-protection-grid">
                            <div class="singlepage-protection-item">{"✓ SQL Injection (SQLi)"}</div>
                            <div class="singlepage-protection-item">{"✓ Cross-Site Scripting (XSS)"}</div>
                            <div class="singlepage-protection-item">{"✓ Server-Side Request Forgery (SSRF)"}</div>
                            <div class="singlepage-protection-item">{"✓ Remote File Inclusion (RFI)"}</div>
                            <div class="singlepage-protection-item">{"✓ Path Traversal"}</div>
                            <div class="singlepage-protection-item">{"✓ Command Injection"}</div>
                            <div class="singlepage-protection-item">{"✓ LDAP Injection"}</div>
                            <div class="singlepage-protection-item">{"✓ XML External Entity (XXE)"}</div>
                            <div class="singlepage-protection-item">{"✓ Template Injection (SSTI)"}</div>
                            <div class="singlepage-protection-item">{"✓ Open Redirects"}</div>
                            <div class="singlepage-protection-item">{"✓ Request Smuggling"}</div>
                            <div class="singlepage-protection-item">{"✓ JWT Attacks"}</div>
                        </div>
                    </section>

                    <section id="architecture" class="singlepage-section">
                        <h2 class="singlepage-section-title">{"Architecture"}</h2>
                        <p class="singlepage-section-subtitle">{"Scale from a single server to a global distributed infrastructure"}</p>
                        <div class="singlepage-architecture-diagram">
                            <div class="singlepage-arch-node singlepage-arch-internet">{"Internet"}</div>
                            <span class="singlepage-arch-arrow">{"→"}</span>
                            <div class="singlepage-arch-node singlepage-arch-waf">{"MaluWAF"}</div>
                            <span class="singlepage-arch-arrow">{"→"}</span>
                            <div class="singlepage-arch-node singlepage-arch-upstream">{"Upstream Apps"}</div>
                        </div>
                        <div class="singlepage-arch-cards">
                            <div class="singlepage-arch-card">
                                <h3>{"Standalone"}</h3>
                                <p>{"Single instance for small deployments. Zero configuration needed."}</p>
                            </div>
                            <div class="singlepage-arch-card">
                                <h3>{"Clustered"}</h3>
                                <p>{"Master-worker setup with multiple processing threads."}</p>
                            </div>
                            <div class="singlepage-arch-card">
                                <h3>{"Distributed"}</h3>
                                <p>{"Multi-node with overseer for global load balancing."}</p>
                            </div>
                        </div>
                    </section>

                    <section id="deployment" class="singlepage-section">
                        <h2 class="singlepage-section-title">{"Deploy Your Way"}</h2>
                        <p class="singlepage-section-subtitle">{"Flexible deployment options for any infrastructure"}</p>
                        <div class="singlepage-deploy-cards">
                            <div class="singlepage-deploy-card">
                                <div class="singlepage-deploy-icon">{"🐳"}</div>
                                <h3>{"Docker"}</h3>
                                <p>{"Run anywhere with our official Docker image"}</p>
                                <code>{"docker run -p 80:80 maluwaf/maluwaf"}</code>
                            </div>
                            <div class="singlepage-deploy-card">
                                <div class="singlepage-deploy-icon">{"☸️"}</div>
                                <h3>{"Kubernetes"}</h3>
                                <p>{"Native K8s support with Helm charts"}</p>
                                <code>{"helm install maluwaf"}</code>
                            </div>
                            <div class="singlepage-deploy-card">
                                <div class="singlepage-deploy-icon">{"⚙️"}</div>
                                <h3>{"Binary"}</h3>
                                <p>{"Standalone binary for any Linux system"}</p>
                                <code>{"./maluwaf --config main.toml"}</code>
                            </div>
                        </div>
                    </section>
                </main>

                <footer class="singlepage-footer">
                    <div class="singlepage-footer-content">
                        <div class="singlepage-footer-brand">
                            <div class="singlepage-logo">
                                <div class="singlepage-logo-icon">{"M"}</div>
                                <span>{"MaluWAF"}</span>
                            </div>
                            <p>{"High-performance Web Application Firewall built in Rust."}</p>
                        </div>
                        <div class="singlepage-footer-links">
                            <div class="singlepage-footer-col">
                                <h4>{"Documentation"}</h4>
                                <a href="/docs/getting-started">{"Getting Started"}</a>
                                <a href="/docs/configuration">{"Configuration"}</a>
                                <a href="/docs/architecture">{"Architecture"}</a>
                                <a href="/docs/api-reference">{"API Reference"}</a>
                            </div>
                            <div class="singlepage-footer-col">
                                <h4>{"Community"}</h4>
                                <a href="https://github.com/maluwaf/maluwaf" target="_blank" rel="noopener noreferrer">{"GitHub"}</a>
                                <a href="https://github.com/maluwaf/maluwaf/issues" target="_blank" rel="noopener noreferrer">{"Issues"}</a>
                                <a href="/docs/changelog">{"Changelog"}</a>
                            </div>
                        </div>
                    </div>
                    <div class="singlepage-footer-bottom">
                        <span>{"© 2024 MaluWAF Project. Open source under MIT license."}</span>
                    </div>
                </footer>
            </div>
        }
}
