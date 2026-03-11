use yew::prelude::*;

#[function_component]
pub fn NotFound() -> Html {
    html! {
        <div class="min-h-screen bg-[var(--bg-primary)] flex items-center justify-center">
            <div class="text-center">
                <h1 class="text-8xl font-bold text-[var(--accent-primary)] mb-4">{"404"}</h1>
                <p class="text-2xl text-[var(--text-secondary)] mb-8">{"Page not found"}</p>
                <a href="/" class="btn btn-primary">{"Go Home"}</a>
            </div>
        </div>
    }
}
