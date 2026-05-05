use yew::prelude::*;

#[function_component]
pub fn SplashPage() -> Html {
    let copied = use_state(|| false);
    let button_text = if *copied { "Copied!" } else { "Copy" };

    let on_click_copy = {
        let copied = copied.clone();
        Callback::from(move |_| {
            let code = "git clone https://github.com/synvoid/synvoid.git\ncd synvoid\ncargo build --release\n./target/release/synvoid";
            if let Some(window) = web_sys::window() {
                let navigator = window.navigator();
                let clipboard = navigator.clipboard();
                let _ = clipboard.write_text(&code);
            }
            copied.set(true);
            let copied_clone = copied.clone();
            gloo::timers::callback::Timeout::new(2000, move || {
                copied_clone.set(false);
            })
            .forget();
        })
    };

    let protections = vec![
        (
            "SQL Injection (SQLi)",
            "Malicious SQL queries to extract data",
        ),
        (
            "Cross-Site Scripting (XSS)",
            "Injecting malicious scripts into web pages",
        ),
        (
            "Server-Side Request Forgery (SSRF)",
            "Forcing server to make unintended requests",
        ),
        (
            "Remote File Inclusion (RFI)",
            "Including remote files through user input",
        ),
        (
            "Path Traversal",
            "Accessing files outside web root directory",
        ),
        (
            "Command Injection",
            "Executing OS commands through input fields",
        ),
        ("LDAP Injection", "Manipulating LDAP queries"),
        (
            "XML External Entity (XXE)",
            "Exploiting XML parser vulnerabilities",
        ),
        (
            "Template Injection (SSTI)",
            "Injecting code into template engines",
        ),
        ("Open Redirects", "Phishing through redirect manipulation"),
        (
            "Request Smuggling",
            "Exploiting HTTP request parsing differences",
        ),
        ("JWT Attacks", "Algorithm confusion and token manipulation"),
    ];

    let features = vec![
        ("🌊", "Flood Protection", "SYN flood, UDP flood, and connection rate limiting with eBPF-based detection for maximum performance."),
        ("🤖", "Bot Mitigation", "AI crawler blocking, CSS honeypot traps, JavaScript challenges, and behavioral analysis."),
        ("⚡", "HTTP/3 & QUIC", "Modern protocol support with 0-RTT connections, improved latency, and built-in encryption."),
        ("🔄", "High Availability", "Master-worker clustering with Raft consensus, automatic failover, and configuration sync."),
        ("📊", "Real-time Monitoring", "Live metrics dashboard, WebSocket updates, Prometheus export, and structured logging."),
        ("🔌", "Plugin System", "Extend functionality with WASM plugins. Dynamic loading without restarts."),
    ];

    html! {
        <div class="min-h-screen bg-[var(--bg-primary)]">
            <div class="splash-bg" style="position: fixed; top: 0; left: 0; width: 100%; height: 100%; z-index: 0;">
                <div class="splash-orb splash-orb-1"></div>
                <div class="splash-orb splash-orb-2"></div>
                <div class="splash-orb splash-orb-3"></div>
                <div class="splash-grid"></div>
            </div>

            <section id="overview" class="relative z-10 py-48 text-center">
                <div class="container">
                    <div class="inline-flex items-center gap-2 bg-[var(--bg-tertiary)] border border-[var(--border-color)] px-4 py-1.5 rounded-full text-sm text-[var(--text-secondary)] mb-8 reveal-element">
                        <span class="text-[var(--accent-primary)] font-semibold">{"v2.0"}</span>
                        <span>{"now available with HTTP/3 support"}</span>
                    </div>
                    <h1 class="text-6xl font-bold leading-tight mb-6 tracking-tight reveal-element" style="animation-delay: 0.1s;">
                        {"Production-Ready<br/>"}
                        <span class="bg-gradient-to-r from-[var(--accent-primary)] to-[#00ffcc] bg-clip-text text-transparent">{"WAF & Reverse Proxy"}</span>
                    </h1>
                    <p class="text-xl text-[var(--text-secondary)] max-w-[640px] mx-auto mb-12 leading-relaxed reveal-element" style="animation-delay: 0.2s;">
                        {"High-performance web application firewall written in Rust. Protects your applications from attacks while delivering exceptional performance."}
                    </p>
                    <div class="flex gap-4 justify-center flex-wrap mb-16 reveal-element" style="animation-delay: 0.3s;">
                        <a href="#protection" class="btn btn-primary">
                            <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                                <path d="M5 12h14M12 5l7 7-7 7"/>
                            </svg>
                            {"Explore Protection"}
                        </a>
                        <a href="#architecture" class="btn btn-secondary">{"View Architecture"}</a>
                    </div>

                    <div class="mt-8 glass-card rounded-xl overflow-hidden max-w-[560px] mx-auto reveal-element" style="animation-delay: 0.4s;">
                        <div class="flex items-center justify-between px-5 py-3 border-b border-[var(--border-color)]">
                            <span class="text-sm text-[var(--text-secondary)] font-medium">{"Quick Start"}</span>
                            <button onclick={on_click_copy} class="bg-transparent border-none text-[var(--text-secondary)] cursor-pointer px-2 py-1 rounded text-sm transition-all hover:bg-[var(--bg-card)] hover:text-[var(--accent-primary)]">
                                {button_text}
                            </button>
                        </div>
                        <pre class="p-5 overflow-x-auto font-mono text-sm leading-relaxed"><code><span class="text-[#6a737d]">{"# Clone and build"}</span>
    <span class="text-[#ff79c6]">{"git"}</span><span class="text-[#f0f0f5]">{" clone https://github.com/synvoid/synvoid.git"}</span>
    <span class="text-[#ff79c6]">{"cd"}</span><span class="text-[#f0f0f5]">{" synvoid"}</span>
    <span class="text-[#ff79c6]">{"cargo"}</span><span class="text-[#f0f0f5]">{" build --release"}</span>

    <span class="text-[#6a737d]">{"# Run with default config"}</span>
    <span class="text-[#50fa7b]">{"."}</span><span class="text-[#f0f0f5]">{"/target/release/synvoid"}</span></code></pre>
                    </div>
                </div>
            </section>

            <section id="protection" class="relative z-10 py-32 bg-[var(--bg-secondary)]">
                <div class="container">
                    <div class="text-center mb-16 reveal-element">
                        <h2 class="text-5xl font-bold mb-4">{"Attack Detection & Prevention"}</h2>
                        <p class="text-xl text-[var(--text-secondary)] max-w-[640px] mx-auto">{"Industry-leading protection against the OWASP Top 10 and beyond"}</p>
                    </div>
                    <div class="grid grid-cols-2 gap-4 max-w-5xl mx-auto">
                        {for protections.iter().enumerate().map(|(i, (name, desc))| {
                            html! {
                                <div class="glass-card group rounded-xl px-6 py-5 transition-all hover:border-[var(--accent-primary)] hover:shadow-lg hover:shadow-[var(--accent-primary)]/10 reveal-element" style={format!("animation-delay: {}s", (i as f32) * 0.05)}>
                                    <div class="flex items-start gap-4">
                                        <span class="text-[var(--success)] text-2xl mt-0.5">{"✓"}</span>
                                        <div>
                                            <h3 class="text-lg font-semibold mb-1 group-hover:text-[var(--accent-primary)] transition-colors">{name}</h3>
                                            <p class="text-[var(--text-secondary)] text-sm">{desc}</p>
                                        </div>
                                    </div>
                                </div>
                            }
                        })}
                    </div>
                    <div class="text-center mt-12 reveal-element" style="animation-delay: 0.6s;">
                        <div class="glass-card inline-flex items-center gap-3 rounded-xl px-6 py-4">
                            <span class="text-[var(--accent-primary)] text-xl">{"⚡"}</span>
                            <span class="text-[var(--text-secondary)]">{"Plus many more attack types..."}</span>
                        </div>
                    </div>
                </div>
            </section>

            <section id="features" class="relative z-10 py-32">
                <div class="container">
                    <div class="text-center mb-16 reveal-element">
                        <h2 class="text-5xl font-bold mb-4">{"Enterprise-Grade Security"}</h2>
                        <p class="text-xl text-[var(--text-secondary)] max-w-[640px] mx-auto">{"Comprehensive protection for your web applications with minimal performance impact"}</p>
                    </div>
                    <div class="grid grid-cols-3 gap-6 max-w-5xl mx-auto">
                        {for features.iter().enumerate().map(|(i, (icon, title, desc))| {
                            html! {
                                <div class="glass-card reveal-element" style={format!("animation-delay: {}s", (i as f32) * 0.1)}>
                                    <div class="w-14 h-14 bg-gradient-to-br from-[var(--accent-primary)] to-[var(--accent-secondary)] rounded-xl flex items-center justify-center text-3xl mb-5">
                                        {icon}
                                    </div>
                                    <h3 class="text-xl font-semibold mb-3">{title}</h3>
                                    <p class="text-[var(--text-secondary)] leading-relaxed">{desc}</p>
                                </div>
                            }
                        })}
                    </div>
                </div>
            </section>

            <section id="architecture" class="relative z-10 py-32 bg-[var(--bg-secondary)]">
                <div class="container">
                    <div class="text-center mb-16 reveal-element">
                        <h2 class="text-5xl font-bold mb-4">{"Architecture"}</h2>
                        <p class="text-xl text-[var(--text-secondary)] max-w-[640px] mx-auto">{"Scale from a single server to a global distributed infrastructure"}</p>
                    </div>

                    <div class="glass-card rounded-2xl p-10 mb-16 max-w-4xl mx-auto overflow-x-auto reveal-element">
                        <div class="flex items-center justify-center gap-6 flex-wrap min-w-max">
                            <div class="glass-card rounded-xl px-8 py-5 font-medium whitespace-nowrap">
                                <div class="text-2xl mb-2">{"🌐"}</div>
                                <div class="text-[var(--text-secondary)]">{"Internet"}</div>
                            </div>
                            <span class="text-[var(--text-muted)] text-3xl">{"→"}</span>
                            <div class="glass-card rounded-xl px-8 py-5 font-medium whitespace-nowrap border-2 border-[var(--accent-primary)] bg-[rgba(0,212,170,0.1)]">
                                <div class="text-2xl mb-2">{"🛡️"}</div>
                                <div class="text-[var(--accent-primary)]">{"SynVoid"}</div>
                            </div>
                            <span class="text-[var(--text-muted)] text-3xl">{"→"}</span>
                            <div class="glass-card rounded-xl px-8 py-5 font-medium whitespace-nowrap">
                                <div class="text-2xl mb-2">{"🚀"}</div>
                                <div class="text-[var(--text-secondary)]">{"Upstream Apps"}</div>
                            </div>
                        </div>
                    </div>

                    <div class="grid grid-cols-3 gap-8 max-w-5xl mx-auto">
                        <div class="text-center p-8 glass-card rounded-2xl reveal-element" style="animation-delay: 0.1s;">
                            <div class="w-16 h-16 bg-gradient-to-br from-[var(--accent-primary)] to-[var(--accent-secondary)] rounded-2xl flex items-center justify-center text-3xl mx-auto mb-5">
                                {"1"}
                            </div>
                            <h3 class="text-xl font-bold mb-3 text-[var(--accent-primary)]">{"Standalone"}</h3>
                            <p class="text-[var(--text-secondary)]">{"Single instance for small deployments. Zero configuration needed."}</p>
                        </div>
                        <div class="text-center p-8 glass-card rounded-2xl reveal-element" style="animation-delay: 0.2s;">
                            <div class="w-16 h-16 bg-gradient-to-br from-[var(--accent-primary)] to-[var(--accent-secondary)] rounded-2xl flex items-center justify-center text-3xl mx-auto mb-5">
                                {"3"}
                            </div>
                            <h3 class="text-xl font-bold mb-3 text-[var(--accent-primary)]">{"Clustered"}</h3>
                            <p class="text-[var(--text-secondary)]">{"Master-worker setup with multiple processing threads for high throughput."}</p>
                        </div>
                        <div class="text-center p-8 glass-card rounded-2xl reveal-element" style="animation-delay: 0.3s;">
                            <div class="w-16 h-16 bg-gradient-to-br from-[var(--accent-primary)] to-[var(--accent-secondary)] rounded-2xl flex items-center justify-center text-3xl mx-auto mb-5">
                                {"N"}
                            </div>
                            <h3 class="text-xl font-bold mb-3 text-[var(--accent-primary)]">{"Distributed"}</h3>
                            <p class="text-[var(--text-secondary)]">{"Multi-node with overseer for global load balancing and redundancy."}</p>
                        </div>
                    </div>
                </div>
            </section>

            <footer class="relative z-10 border-t border-[var(--border-color)] py-12">
                <div class="container flex items-center justify-between">
                    <div class="flex items-center gap-3">
                        <svg width="24" height="24" viewBox="0 0 80 80" fill="none" xmlns="http://www.w3.org/2000/svg">
                            <circle cx="40" cy="40" r="38" stroke="#00d4aa" stroke-width="2" fill="none"/>
                            <path d="M25 40 L35 30 L45 40 L55 30" stroke="#00ffcc" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round" fill="none"/>
                            <path d="M25 50 L35 40 L45 50 L55 40" stroke="#00d4aa" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round" fill="none"/>
                            <circle cx="40" cy="40" r="6" fill="#00d4aa"/>
                        </svg>
                        <span class="text-[var(--text-secondary)]">{"SynVoid - Open Source WAF"}</span>
                    </div>
                    <div class="flex items-center gap-8 text-[var(--text-secondary)]">
                        <a href="https://github.com/synvoid/synvoid" class="hover:text-[var(--accent-primary)] transition-colors">{"GitHub"}</a>
                        <a href="/docs" class="hover:text-[var(--accent-primary)] transition-colors">{"Documentation"}</a>
                    </div>
                </div>
            </footer>
        </div>
    }
}
