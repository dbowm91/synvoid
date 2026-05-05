use web_sys::window;
use yew::prelude::*;

#[function_component]
pub fn Hero() -> Html {
    let copied = use_state(|| false);
    let button_text = if *copied { "Copied!" } else { "Copy" };

    let on_click = {
        let copied = copied.clone();
        Callback::from(move |_| {
            let code = "git clone https://github.com/synvoid/synvoid.git\ncd synvoid\ncargo build --release\n./target/release/synvoid";
            if let Some(window) = window() {
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

    html! {
            <section class="py-[180px] pb-[120px] relative overflow-hidden">
                <div class="splash-bg hero-bg">
                    <div class="splash-orb splash-orb-1"></div>
                    <div class="splash-orb splash-orb-2"></div>
                    <div class="splash-orb splash-orb-3"></div>
                    <div class="splash-grid"></div>
                </div>
                <div class="container text-center relative z-10">
                    <div class="inline-flex items-center gap-2 bg-[var(--bg-tertiary)] border border-[var(--border-color)] px-4 py-1.5 rounded-full text-sm text-[var(--text-secondary)] mb-8">
                        <span class="text-[var(--accent-primary)] font-semibold">{"v2.0"}</span>
                        <span>{"now available with HTTP/3 support"}</span>
                    </div>
                    <h1 class="text-6xl font-bold leading-tight mb-6 tracking-tight">
                        {"Production-Ready<br/>"}
                        <span class="bg-gradient-to-r from-[var(--accent-primary)] to-[#00ffcc] bg-clip-text text-transparent">{"WAF & Reverse Proxy"}</span>
                    </h1>
                    <p class="text-xl text-[var(--text-secondary)] max-w-[640px] mx-auto mb-12 leading-relaxed">
                        {"High-performance web application firewall written in Rust. Protects your applications from attacks while delivering exceptional performance."}
                    </p>
                    <div class="flex gap-4 justify-center flex-wrap mb-16">
                        <a href="#quickstart" class="btn btn-primary">
                            <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                                <path d="M5 12h14M12 5l7 7-7 7"/>
                            </svg>
                            {"Get Started"}
                        </a>
                        <a href="#features" class="btn btn-secondary">{"View Features"}</a>
                    </div>

                    <div id="quickstart" class="mt-16 bg-[var(--bg-secondary)] border border-[var(--border-color)] rounded-xl overflow-hidden max-w-[560px] mx-auto">
                        <div class="flex items-center justify-between px-5 py-3 bg-[var(--bg-tertiary)] border-b border-[var(--border-color)]">
                            <span class="text-sm text-[var(--text-secondary)] font-medium">{"Quick Start"}</span>
                            <button onclick={on_click} class="bg-transparent border-none text-[var(--text-secondary)] cursor-pointer px-2 py-1 rounded text-sm transition-all hover:bg-[var(--bg-card)] hover:text-[var(--accent-primary)]">
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
        }
}
