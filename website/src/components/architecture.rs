use yew::prelude::*;

#[function_component]
pub fn Architecture() -> Html {
    html! {
        <section class="py-[100px] relative overflow-hidden">
            <div class="hero-bg" style="opacity: 0.3;">
                <div class="splash-orb splash-orb-3"></div>
            </div>
            <div class="container relative z-10">
                <div class="text-center mb-16">
                    <h2 class="text-4xl font-bold mb-4">{"Architecture"}</h2>
                    <p class="text-lg text-[var(--text-secondary)] max-w-[560px] mx-auto">{"Scale from a single server to a global distributed infrastructure"}</p>
                </div>
                <div class="bg-[var(--bg-secondary)] border border-[var(--border-color)] rounded-2xl p-12 mt-12 overflow-x-auto">
                    <div class="flex items-center justify-center gap-4 flex-wrap">
                        <div class="bg-[var(--bg-tertiary)] border border-[var(--border-color)] rounded-lg px-6 py-4 font-medium whitespace-nowrap">{"Internet"}</div>
                        <span class="text-[var(--text-muted)] text-2xl">{"→"}</span>
                        <div class="bg-[var(--bg-tertiary)] border-2 border-[var(--accent-primary)] rounded-lg px-6 py-4 font-medium whitespace-nowrap bg-[rgba(0,212,170,0.1)]">{"SynVoid"}</div>
                        <span class="text-[var(--text-muted)] text-2xl">{"→"}</span>
                        <div class="bg-[var(--bg-tertiary)] border border-[var(--border-color)] rounded-lg px-6 py-4 font-medium whitespace-nowrap">{"Upstream Apps"}</div>
                    </div>
                </div>
                <div class="grid grid-cols-3 gap-6 mt-12">
                    <div class="text-center p-6">
                        <h3 class="mb-3 text-[var(--accent-primary)]">{"Standalone"}</h3>
                        <p class="text-[var(--text-secondary)] text-sm">{"Single instance for small deployments. Zero configuration needed."}</p>
                    </div>
                    <div class="text-center p-6">
                        <h3 class="mb-3 text-[var(--accent-primary)]">{"Clustered"}</h3>
                        <p class="text-[var(--text-secondary)] text-sm">{"Master-worker setup with multiple processing threads."}</p>
                    </div>
                    <div class="text-center p-6">
                        <h3 class="mb-3 text-[var(--accent-primary)]">{"Distributed"}</h3>
                        <p class="text-[var(--text-secondary)] text-sm">{"Multi-node with overseer for global load balancing."}</p>
                    </div>
                </div>
            </div>
        </section>
    }
}
