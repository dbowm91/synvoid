use crate::components::ChallengeSplash;
use yew::prelude::*;

#[function_component]
pub fn Challenge() -> Html {
    let show_splash = use_state(|| true);
    let on_complete = {
        let show_splash = show_splash.clone();
        Callback::from(move |_| {
            show_splash.set(false);
        })
    };

    html! {
        if *show_splash {
            <ChallengeSplash {on_complete} />
        } else {
            <div class="min-h-screen bg-[var(--bg-primary)] flex items-center justify-center">
                <div class="text-center">
                    <h1 class="text-4xl font-bold mb-4">{"Challenge Complete"}</h1>
                    <p class="text-[var(--text-secondary)]">{"Redirecting..."}</p>
                </div>
            </div>
        }
    }
}
