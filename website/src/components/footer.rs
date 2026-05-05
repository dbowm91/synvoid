use yew::prelude::*;

#[function_component]
pub fn Footer() -> Html {
    html! {
        <footer class="py-[60px] bg-[var(--bg-secondary)] border-t border-[var(--border-color)] relative overflow-hidden">
            <div class="features-bg" style="opacity: 0.3;">
                <div class="feature-orb feature-orb-1"></div>
            </div>
            <div class="container relative z-10">
                <div class="grid grid-cols-4 gap-12 mb-12">
                    <div>
                        <a href="/" class="flex items-center gap-3 no-underline">
                            <div class="w-9 h-9 bg-gradient-to-br from-[var(--accent-primary)] to-[var(--accent-secondary)] rounded-lg flex items-center justify-center font-mono font-bold text-lg text-[var(--bg-primary)]">
                                {"M"}
                            </div>
                            <span class="text-xl font-bold text-[var(--text-primary)]">{"SynVoid"}</span>
                        </a>
                        <p class="text-[var(--text-secondary)] mt-4 text-sm max-w-[280px]">
                            {"High-performance Web Application Firewall and reverse proxy built in Rust for modern web infrastructure."}
                        </p>
                    </div>
                    <div>
                        <h4 class="text-xs uppercase tracking-wider text-[var(--text-muted)] mb-5">{"Documentation"}</h4>
                        <a href="/docs/getting-started" class="block text-[var(--text-secondary)] no-underline py-1.5 text-sm transition-colors hover:text-[var(--accent-primary)]">{"Getting Started"}</a>
                        <a href="/docs/configuration" class="block text-[var(--text-secondary)] no-underline py-1.5 text-sm transition-colors hover:text-[var(--accent-primary)]">{"Configuration"}</a>
                        <a href="/docs/architecture" class="block text-[var(--text-secondary)] no-underline py-1.5 text-sm transition-colors hover:text-[var(--accent-primary)]">{"Architecture"}</a>
                        <a href="/docs/api-reference" class="block text-[var(--text-secondary)] no-underline py-1.5 text-sm transition-colors hover:text-[var(--accent-primary)]">{"API Reference"}</a>
                    </div>
                    <div>
                        <h4 class="text-xs uppercase tracking-wider text-[var(--text-muted)] mb-5">{"Resources"}</h4>
                        <a href="/docs/attack-detection" class="block text-[var(--text-secondary)] no-underline py-1.5 text-sm transition-colors hover:text-[var(--accent-primary)]">{"Attack Detection"}</a>
                        <a href="/docs/flood-protection" class="block text-[var(--text-secondary)] no-underline py-1.5 text-sm transition-colors hover:text-[var(--accent-primary)]">{"Flood Protection"}</a>
                        <a href="/docs/deployment" class="block text-[var(--text-secondary)] no-underline py-1.5 text-sm transition-colors hover:text-[var(--accent-primary)]">{"Deployment"}</a>
                        <a href="/docs/troubleshooting" class="block text-[var(--text-secondary)] no-underline py-1.5 text-sm transition-colors hover:text-[var(--accent-primary)]">{"Troubleshooting"}</a>
                    </div>
                    <div>
                        <h4 class="text-xs uppercase tracking-wider text-[var(--text-muted)] mb-5">{"Community"}</h4>
                        <a href="https://github.com/synvoid/synvoid" target="_blank" rel="noopener noreferrer" class="block text-[var(--text-secondary)] no-underline py-1.5 text-sm transition-colors hover:text-[var(--accent-primary)]">{"GitHub"}</a>
                        <a href="https://github.com/synvoid/synvoid/issues" target="_blank" rel="noopener noreferrer" class="block text-[var(--text-secondary)] no-underline py-1.5 text-sm transition-colors hover:text-[var(--accent-primary)]">{"Issues"}</a>
                        <a href="/docs/developer" class="block text-[var(--text-secondary)] no-underline py-1.5 text-sm transition-colors hover:text-[var(--accent-primary)]">{"Contributing"}</a>
                        <a href="/docs/changelog" class="block text-[var(--text-secondary)] no-underline py-1.5 text-sm transition-colors hover:text-[var(--accent-primary)]">{"Changelog"}</a>
                    </div>
                </div>
                <div class="flex justify-between items-center pt-8 border-t border-[var(--border-color)]">
                    <span class="text-[var(--text-muted)] text-sm">{"© 2024 SynVoid Project. Open source under MIT license."}</span>
                    <div class="flex gap-6">
                        <a href="https://github.com/synvoid/synvoid/stargazers" class="text-[var(--text-muted)] text-sm no-underline transition-colors hover:text-[var(--text-primary)]">{"Stars"}</a>
                        <a href="https://github.com/synvoid/synvoid/fork" class="text-[var(--text-muted)] text-sm no-underline transition-colors hover:text-[var(--text-primary)]">{"Fork"}</a>
                    </div>
                </div>
            </div>
        </footer>
    }
}
