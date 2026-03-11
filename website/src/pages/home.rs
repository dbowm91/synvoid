use crate::components::{Architecture, Deployment, Features, Footer, Hero, Protection, Stats};
use yew::prelude::*;

#[function_component]
pub fn Home() -> Html {
    html! {
        <div class="min-h-screen bg-[var(--bg-primary)]">
            <Hero />
            <Stats />
            <Features />
            <Protection />
            <Architecture />
            <Deployment />
            <Footer />
        </div>
    }
}
