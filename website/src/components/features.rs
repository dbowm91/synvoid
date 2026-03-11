use yew::prelude::*;

#[function_component]
pub fn Features() -> Html {
    let features = vec![
        ("🛡️", "WAF Protection", "Multi-layer defense against SQL injection, XSS, CSRF, SSRF, path traversal, and more with customizable rule sets."),
        ("🌊", "Flood Protection", "SYN flood, UDP flood, and connection rate limiting with eBPF-based detection for maximum performance."),
        ("🤖", "Bot Mitigation", "AI crawler blocking, CSS honeypot traps, JavaScript challenges, and behavioral analysis."),
        ("⚡", "HTTP/3 & QUIC", "Modern protocol support with 0-RTT connections, improved latency, and built-in encryption."),
        ("🔄", "High Availability", "Master-worker clustering with Raft consensus, automatic failover, and configuration sync."),
        ("📊", "Real-time Monitoring", "Live metrics dashboard, WebSocket updates, Prometheus export, and structured logging."),
        ("🔌", "Plugin System", "Extend functionality with WASM plugins. Dynamic loading without restarts."),
        ("🏗️", "Multi-Backend", "Native support for PHP-FPM, Python (Granian), FastCGI, and static files."),
        ("🔗", "WAF Mesh", "Peer-to-peer communication between instances for distributed threat intelligence."),
    ];

    html! {
        <section id="features" class="py-[100px] bg-[var(--bg-secondary)] relative overflow-hidden">
            <div class="features-bg">
                <div class="feature-orb feature-orb-1"></div>
                <div class="feature-orb feature-orb-2"></div>
            </div>
            <div class="container relative z-10">
                <div class="text-center mb-16">
                    <h2 class="text-4xl font-bold mb-4">{"Enterprise-Grade Security"}</h2>
                    <p class="text-lg text-[var(--text-secondary)] max-w-[560px] mx-auto">{"Comprehensive protection for your web applications with minimal performance impact"}</p>
                </div>
                <div class="grid grid-cols-3 gap-6">
                    {for features.iter().map(|(icon, title, desc)| {
                        html! {
                            <div class="card">
                                <div class="w-12 h-12 bg-gradient-to-br from-[var(--accent-primary)] to-[var(--accent-secondary)] rounded-lg flex items-center justify-center text-2xl mb-5">
                                    {icon}
                                </div>
                                <h3 class="text-xl font-semibold mb-3">{title}</h3>
                                <p class="text-[var(--text-secondary)] text-sm leading-relaxed">{desc}</p>
                            </div>
                        }
                    })}
                </div>
            </div>
        </section>
    }
}
