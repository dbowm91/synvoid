use yew::prelude::*;

#[function_component]
pub fn Stats() -> Html {
    html! {
        <section class="py-20 border-t border-b border-[var(--border-color)]">
            <div class="container">
                <div class="grid grid-cols-4 gap-8 text-center">
                    <div class="py-5">
                        <div class="text-5xl font-bold text-[var(--accent-primary)] font-mono leading-none mb-2">{"100K+"}</div>
                        <div class="text-[var(--text-secondary)] text-sm">{"Requests/second"}</div>
                    </div>
                    <div class="py-5">
                        <div class="text-5xl font-bold text-[var(--accent-primary)] font-mono leading-none mb-2">{"<1ms"}</div>
                        <div class="text-[var(--text-secondary)] text-sm">{"Latency overhead"}</div>
                    </div>
                    <div class="py-5">
                        <div class="text-5xl font-bold text-[var(--accent-primary)] font-mono leading-none mb-2">{"15+"}</div>
                        <div class="text-[var(--text-secondary)] text-sm">{"Attack types detected"}</div>
                    </div>
                    <div class="py-5">
                        <div class="text-5xl font-bold text-[var(--accent-primary)] font-mono leading-none mb-2">{"99.9%"}</div>
                        <div class="text-[var(--text-secondary)] text-sm">{"Attack block rate"}</div>
                    </div>
                </div>
            </div>
        </section>
    }
}
