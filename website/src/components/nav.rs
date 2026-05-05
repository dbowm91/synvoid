use yew::prelude::*;
use yew_router::prelude::*;

#[function_component]
pub fn Nav() -> Html {
    html! {
        <nav class="fixed top-0 left-0 right-0 z-50 bg-[rgba(10,10,15,0.9)] backdrop-blur-xl border-b border-[var(--border-color)]">
            <div class="container flex items-center justify-between py-4">
                <a href="/" class="flex items-center gap-3 no-underline group">
                    <div class="w-9 h-9 bg-gradient-to-br from-[var(--accent-primary)] to-[var(--accent-secondary)] rounded-lg flex items-center justify-center font-mono font-bold text-lg text-[var(--bg-primary)] shadow-lg shadow-[rgba(0,212,170,0.3)] group-hover:shadow-[rgba(0,212,170,0.5)] transition-shadow">
                        {"M"}
                    </div>
                    <span class="text-xl font-bold text-[var(--text-primary)]">{"SynVoid"}</span>
                </a>
                <div class="flex items-center gap-8">
                    <a href="#features" class="text-[var(--text-secondary)] no-underline font-medium transition-colors hover:text-[var(--accent-primary)]">{"Features"}</a>
                    <a href="#protection" class="text-[var(--text-secondary)] no-underline font-medium transition-colors hover:text-[var(--accent-primary)]">{"Protection"}</a>
                    <a href="#deployment" class="text-[var(--text-secondary)] no-underline font-medium transition-colors hover:text-[var(--accent-primary)]">{"Deploy"}</a>
                    <a href="/docs" class="text-[var(--text-secondary)] no-underline font-medium transition-colors hover:text-[var(--accent-primary)]">{"Docs"}</a>
                    <a href="https://github.com/synvoid/synvoid" target="_blank" rel="noopener noreferrer" class="text-[var(--text-secondary)] no-underline font-medium transition-colors hover:text-[var(--accent-primary)]">{"GitHub"}</a>
                    <a href="http://localhost:8081" class="bg-[var(--accent-primary)] text-[var(--bg-primary)] px-5 py-2 rounded-md font-semibold transition-all hover:bg-[var(--accent-secondary)] hover:translate-y-px no-underline shadow-lg shadow-[rgba(0,212,170,0.3)] hover:shadow-[rgba(0,255,204,0.5)]">
                        {"Admin UI"}
                    </a>
                </div>
            </div>
        </nav>
    }
}
