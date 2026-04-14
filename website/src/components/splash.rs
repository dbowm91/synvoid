use yew::prelude::*;

#[derive(Properties, PartialEq)]
pub struct SplashProps {
    pub on_complete: Callback<()>,
}

#[function_component]
pub fn Splash(props: &SplashProps) -> Html {
    let visible = use_state(|| true);
    let opacity = use_state(|| 1.0);
    let stage = use_state(|| "loading"); // "loading" | "lock"

    {
        let on_complete = props.on_complete.clone();
        let visible = visible.clone();
        let opacity = opacity.clone();
        let stage = stage.clone();

        use_effect(move || {
            let timeout = gloo::timers::callback::Timeout::new(2500, move || {
                stage.set("lock");
                let timeout2 = gloo::timers::callback::Timeout::new(1500, move || {
                    opacity.set(0.0);
                    let timeout3 = gloo::timers::callback::Timeout::new(800, move || {
                        visible.set(false);
                        on_complete.emit(());
                    });
                    timeout3.forget();
                });
                timeout2.forget();
            });
            timeout.forget();
        });
    }

    let container_style = format!(
        "position: fixed; top: 0; left: 0; width: 100vw; height: 100vh; z-index: 9999; background-color: #0a0a0f; display: flex; align-items: center; justify-content: center; transition: opacity 0.8s ease-out; opacity: {}; pointer-events: {};",
        *opacity,
        if *visible { "auto" } else { "none" }
    );

    html! {
        if *visible {
            <div style={container_style}>
                <div class="splash-bg">
                    <div class="splash-orb splash-orb-1"></div>
                    <div class="splash-orb splash-orb-2"></div>
                    <div class="splash-orb splash-orb-3"></div>
                    <div class="splash-grid"></div>
                </div>
                <div class="splash-content" style="text-align: center; position: relative; z-index: 1;">
                    if *stage == "loading" {
                        <div class="splash-logo" style="margin-bottom: 2rem;">
                            <svg width="80" height="80" viewBox="0 0 80 80" fill="none" xmlns="http://www.w3.org/2000/svg">
                                <circle cx="40" cy="40" r="38" stroke="#00d4aa" stroke-width="2" fill="none" class="splash-ring"/>
                                <path d="M25 40 L35 30 L45 40 L55 30" stroke="#00ffcc" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round" fill="none"/>
                                <path d="M25 50 L35 40 L45 50 L55 40" stroke="#00d4aa" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round" fill="none"/>
                                <circle cx="40" cy="40" r="6" fill="#00d4aa"/>
                            </svg>
                        </div>
                        <h1 style="font-size: 3.5rem; font-weight: 700; margin: 0; background: linear-gradient(135deg, #00d4aa 0%, #00ffcc 100%); -webkit-background-clip: text; -webkit-text-fill-color: transparent; background-clip: text; letter-spacing: -0.02em;">
                            {"MaluWAF"}
                        </h1>
                        <p style="color: #a0a0b0; font-size: 1.1rem; margin-top: 0.75rem; letter-spacing: 0.1em; text-transform: uppercase;">
                            {"Web Application Firewall"}
                        </p>
                        <div class="splash-loading" style="margin-top: 3rem; display: flex; justify-content: center; gap: 0.5rem; transform: translateX(-6px);">
                            <div class="splash-dot" style="width: 8px; height: 8px; background: #00d4aa; border-radius: 50%; animation: pulse 1.4s ease-in-out infinite;"></div>
                            <div class="splash-dot" style="width: 8px; height: 8px; background: #00d4aa; border-radius: 50%; animation: pulse 1.4s ease-in-out infinite 0.2s;"></div>
                            <div class="splash-dot" style="width: 8px; height: 8px; background: #00d4aa; border-radius: 50%; animation: pulse 1.4s ease-in-out infinite 0.4s;"></div>
                        </div>
                    } else {
                        <div class="splash-logo" style="margin-bottom: 2rem; animation: fadeInUp 0.5s ease-out;">
                            <svg width="80" height="80" viewBox="0 0 80 80" fill="none" xmlns="http://www.w3.org/2000/svg">
                                <circle cx="40" cy="40" r="38" stroke="#00d4aa" stroke-width="2" fill="none" style="stroke-dashoffset: 0;"/>
                                <rect x="28" y="32" width="24" height="20" rx="3" stroke="#00ffcc" stroke-width="2.5" fill="none"/>
                                <path d="M32 32V26C32 22.6863 34.6863 20 38 20C41.3137 20 44 22.6863 44 26V32" stroke="#00d4aa" stroke-width="2.5" stroke-linecap="round" fill="none"/>
                                <circle cx="40" cy="42" r="3" fill="#00d4aa"/>
                            </svg>
                        </div>
                        <h1 style="font-size: 2.5rem; font-weight: 700; margin: 0; background: linear-gradient(135deg, #00d4aa 0%, #00ffcc 100%); -webkit-background-clip: text; -webkit-text-fill-color: transparent; background-clip: text; letter-spacing: -0.02em;">
                            {"Verified"}
                        </h1>
                        <p style="color: #a0a0b0; font-size: 1.1rem; margin-top: 0.75rem;">
                            {"Human verified"}
                        </p>
                    }
                </div>
            </div>
        }
    }
}
