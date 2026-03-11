use crate::components::Footer;
use yew::prelude::*;
use yew_router::prelude::*;

#[derive(Properties, PartialEq)]
pub struct DocPageProps {
    pub name: String,
}

#[function_component]
pub fn DocPage(props: &DocPageProps) -> Html {
    let doc_content = get_doc_content(&props.name);

    html! {
        <div class="min-h-screen bg-[var(--bg-primary)]">
            <section class="pt-32 pb-16">
                <div class="container">
                    <a href="/docs" class="text-[var(--accent-primary)] no-underline mb-4 inline-block">{"← Back to Docs"}</a>
                    <h1 class="text-4xl font-bold mb-4">{get_doc_title(&props.name)}</h1>
                    <p class="text-lg text-[var(--text-secondary)]">{get_doc_description(&props.name)}</p>
                </div>
            </section>
            <section class="pb-32">
                <div class="container">
                    <div class="grid grid-cols-4 gap-8">
                        <div class="col-span-3">
                            <div class="prose prose-invert max-w-none"
                                dangerously_set_inner_html={doc_content}>
                            </div>
                        </div>
                        <div>
                            <div class="sticky top-24">
                                <h4 class="text-sm font-semibold text-[var(--text-muted)] uppercase tracking-wider mb-4">{"On this page"}</h4>
                                <div class="space-y-2 text-sm">
                                    <a href="#" class="block text-[var(--text-secondary)] no-underline hover:text-[var(--accent-primary)]">{"Overview"}</a>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
            </section>
            <Footer />
        </div>
    }
}

fn get_doc_title(name: &str) -> String {
    match name {
        "getting-started" => "Getting Started".to_string(),
        "configuration" => "Configuration".to_string(),
        "architecture" => "Architecture".to_string(),
        "attack-detection" => "Attack Detection".to_string(),
        "flood-protection" => "Flood Protection".to_string(),
        "deployment" => "Deployment".to_string(),
        "api-reference" => "API Reference".to_string(),
        "troubleshooting" => "Troubleshooting".to_string(),
        "developer" => "Developer Guide".to_string(),
        _ => name
            .replace('-', " ")
            .split_whitespace()
            .map(|s| {
                let mut chars = s.chars();
                match chars.next() {
                    None => String::new(),
                    Some(c) => c.to_uppercase().collect::<String>() + chars.as_str(),
                }
            })
            .collect::<Vec<_>>()
            .join(" "),
    }
}

fn get_doc_description(name: &str) -> String {
    match name {
        "getting-started" => "Get up and running with MaluWAF in minutes".to_string(),
        "configuration" => "Complete configuration file reference and examples".to_string(),
        "architecture" => "Understanding how MaluWAF works under the hood".to_string(),
        "attack-detection" => "Learn about WAF attack detection mechanisms".to_string(),
        "flood-protection" => "Protect against DDoS and flood attacks".to_string(),
        "deployment" => "Deploy MaluWAF to production".to_string(),
        "api-reference" => "Complete REST API documentation".to_string(),
        "troubleshooting" => "Solutions to common issues".to_string(),
        "developer" => "Contributing to MaluWAF development".to_string(),
        _ => "Documentation".to_string(),
    }
}

fn get_doc_content(name: &str) -> String {
    match name {
        "getting-started" => r#"
            <h2 id="overview">Overview</h2>
            <p>This guide will help you get MaluWAF up and running in just a few minutes.</p>
            
            <h2 id="requirements">Requirements</h2>
            <ul>
                <li>Rust 1.70 or later</li>
                <li>OpenSSL (development libraries)</li>
                <li>On Linux: libclang, llvm</li>
            </ul>
            
            <h2 id="installation">Installation</h2>
            <pre><code>git clone https://github.com/maluwaf/maluwaf.git
cd maluwaf
cargo build --release</code></pre>
            
            <h2 id="quick-start">Quick Start</h2>
            <p>Run MaluWAF with the default configuration:</p>
            <pre><code>./target/release/maluwaf</code></pre>
            
            <p>By default, MaluWAF will:</p>
            <ul>
                <li>Listen on port 80 and 443</li>
                <li>Serve a default landing page</li>
                <li>Enable basic WAF rules</li>
            </ul>
            
            <h2 id="next-steps">Next Steps</h2>
            <ul>
                <li><a href="/docs/configuration">Configure MaluWAF</a> for your needs</li>
                <li>Set up <a href="/docs/attack-detection">attack detection</a> rules</li>
                <li>Configure <a href="/docs/deployment">production deployment</a></li>
            </ul>
        "#.to_string(),
        "configuration" => r#"
            <h2 id="overview">Configuration File</h2>
            <p>MaluWAF uses TOML configuration files. The default configuration file is <code>main.toml</code>.</p>
            
            <h2 id="structure">Configuration Structure</h2>
            <pre><code>[main]
bind_address = "0.0.0.0"
http_port = 80
https_port = 443

[[sites]]
domain = "example.com"
tls = true

[upstream]
address = "127.0.0.1:8080"</code></pre>
            
            <h2 id="sites">Site Configuration</h2>
            <p>Each site can be configured with:</p>
            <ul>
                <li><code>domain</code> - The domain name</li>
                <li><code>tls</code> - Enable TLS/HTTPS</li>
                <li><code>upstream</code> - Backend server address</li>
            </ul>
            
            <h2 id="waf">WAF Configuration</h2>
            <pre><code>[waf]
enabled = true
rules_dir = "/etc/maluwaf/rules"

[waf.attack_detection]
sqli = true
xss = true
cmd_injection = true</code></pre>
        "#.to_string(),
        "architecture" => r#"
            <h2 id="overview">Architecture Overview</h2>
            <p>MaluWAF uses a multi-process architecture designed for reliability and performance.</p>
            
            <h2 id="processes">Process Model</h2>
            <ul>
                <li><strong>Overseer</strong> - Monitors the master process, handles updates</li>
                <li><strong>Master</strong> - Spawns workers, manages configuration</li>
                <li><strong>Workers</strong> - Handle incoming requests</li>
            </ul>
            
            <h2 id="request-flow">Request Flow</h2>
            <ol>
                <li>Client connects to MaluWAF</li>
                <li>Worker processes the request</li>
                <li>WAF rules are evaluated</li>
                <li>Request is proxied to upstream</li>
                <li>Response is returned to client</li>
            </ol>
            
            <h2 id="components">Core Components</h2>
            <ul>
                <li><strong>WAF Engine</strong> - Rule matching and attack detection</li>
                <li><strong>Proxy</strong> - Reverse proxy functionality</li>
                <li><strong>Mesh Network</strong> - Peer-to-peer communication</li>
            </ul>
        "#.to_string(),
        "attack-detection" => r#"
            <h2 id="overview">Attack Detection</h2>
            <p>MaluWAF provides comprehensive attack detection against OWASP Top 10 vulnerabilities.</p>
            
            <h2 id="detection-types">Detection Types</h2>
            
            <h3>SQL Injection (SQLi)</h3>
            <p>Detects SQL injection attempts using pattern matching and libinjection.</p>
            
            <h3>Cross-Site Scripting (XSS)</h3>
            <p>Identifies reflected, stored, and DOM-based XSS attacks.</p>
            
            <h3>Command Injection</h3>
            <p>Blocks attempts to execute system commands through input fields.</p>
            
            <h3>Path Traversal</h3>
            <p>Prevents directory traversal attacks.</p>
            
            <h3>SSRF</h3>
            <p>Detects Server-Side Request Forgery attempts.</p>
            
            <h2 id="configuration">Configuration</h2>
            <pre><code>[waf.attack_detection]
sqli = true
xss = true
cmd_injection = true
path_traversal = true
ssrf = true</code></pre>
        "#.to_string(),
        "flood-protection" => r#"
            <h2 id="overview">Flood Protection</h2>
            <p>MaluWAF includes multiple layers of flood protection.</p>
            
            <h2 id="types">Protection Types</h2>
            
            <h3>TCP Flood</h3>
            <p>Connection rate limiting and SYN cookie support.</p>
            
            <h3>UDP Flood</h3>
            <p>Packet rate limiting for UDP-based attacks.</p>
            
            <h3>HTTP Flood</h3>
            <p>Request rate limiting per IP/session.</p>
            
            <h2 id="ebpf">eBPF Acceleration</h2>
            <p>On Linux, eBPF-based detection provides near-zero overhead flood protection.</p>
            
            <h2 id="configuration">Configuration</h2>
            <pre><code>[flood]
enabled = true
syn_cookie = true

[flood.tcp]
max_connections_per_ip = 100

[flood.udp]
max_packets_per_second = 10000</code></pre>
        "#.to_string(),
        "deployment" => r#"
            <h2 id="overview">Deployment</h2>
            <p>MaluWAF can be deployed in various ways depending on your infrastructure.</p>
            
            <h2 id="docker">Docker</h2>
            <pre><code>docker run -p 80:80 -p 443:443 -v $(pwd)/config:/config maluwaf/maluwaf</code></pre>
            
            <h2 id="kubernetes">Kubernetes</h2>
            <pre><code>helm install maluwaf maluwaf/maluwaf</code></pre>
            
            <h2 id="binary">Binary</h2>
            <pre><code>./maluwaf --config /etc/maluwaf/main.toml</code></pre>
            
            <h2 id="requirements">System Requirements</h2>
            <ul>
                <li>Linux (recommended) or macOS</li>
                <li>2+ CPU cores</li>
                <li>2GB+ RAM</li>
                <li>Network access</li>
            </ul>
        "#.to_string(),
        "api-reference" => r#"
            <h2 id="overview">API Reference</h2>
            <p>The admin API provides programmatic access to MaluWAF configuration.</p>
            
            <h2 id="authentication">Authentication</h2>
            <p>All API requests require an <code>X-Admin-Token</code> header.</p>
            
            <h2 id="endpoints">Endpoints</h2>
            
            <h3>GET /api/health</h3>
            <p>Health check endpoint.</p>
            
            <h3>GET /api/sites</h3>
            <p>List all configured sites.</p>
            
            <h3>POST /api/config/reload</h3>
            <p>Reload configuration.</p>
            
            <h3>GET /api/stats/summary</h3>
            <p>Get summary statistics.</p>
        "#.to_string(),
        "troubleshooting" => r#"
            <h2 id="overview">Troubleshooting</h2>
            <p>Solutions to common issues with MaluWAF.</p>
            
            <h2 id="common-issues">Common Issues</h2>
            
            <h3>Connection Refused</h3>
            <p>Check that MaluWAF is running and the port is not blocked by firewall.</p>
            
            <h3>Upstream Errors</h3>
            <p>Verify the upstream server is running and accessible.</p>
            
            <h3>High Latency</h3>
            <p>Check WAF rule complexity and consider disabling unused rules.</p>
            
            <h2 id="logging">Logging</h2>
            <p>Enable debug logging in configuration:</p>
            <pre><code>[logging]
level = "debug"</code></pre>
        "#.to_string(),
        "developer" => r#"
            <h2 id="overview">Developer Guide</h2>
            <p>Welcome to MaluWAF development!</p>
            
            <h2 id="setup">Development Setup</h2>
            <pre><code>git clone https://github.com/maluwaf/maluwaf.git
cd maluwaf
cargo build</code></pre>
            
            <h2 id="project-structure">Project Structure</h2>
            <ul>
                <li><code>src/</code> - Core WAF code</li>
                <li><code>admin-ui/</code> - Admin dashboard</li>
                <li><code>website/</code> - Documentation website</li>
            </ul>
            
            <h2 id="contributing">Contributing</h2>
            <ol>
                <li>Fork the repository</li>
                <li>Create a feature branch</li>
                <li>Make your changes</li>
                <li>Submit a pull request</li>
            </ol>
        "#.to_string(),
        _ => format!(r#"
            <h2>{}</h2>
            <p>Documentation for {} is coming soon.</p>
        "#, get_doc_title(name), name),
    }
}
