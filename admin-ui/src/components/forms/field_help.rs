use yew::prelude::*;

#[derive(Properties, PartialEq)]
#[allow(dead_code)]
pub struct FieldHelpProps {
    pub description: String,
    #[prop_or_default]
    pub impact: Option<String>,
}

#[function_component]
pub fn FieldHelp(props: &FieldHelpProps) -> Html {
    let show_help = use_state(|| false);

    let toggle = {
        let show_help = show_help.clone();
        Callback::from(move |_| {
            show_help.set(!*show_help);
        })
    };

    html! {
        <div class="relative inline-block">
            <button
                onclick={toggle}
                class="w-5 h-5 rounded-full bg-tertiary text-secondary hover:text-primary text-xs flex items-center justify-center"
            >
                { "?" }
            </button>
            if *show_help {
                <div class="absolute z-10 w-64 p-3 bg-secondary border border-default rounded-lg shadow-lg text-sm -left-28 mt-2">
                    <p class="text-primary">{ &props.description }</p>
                    if let Some(impact) = &props.impact {
                        <p class="mt-2 text-xs text-yellow-500">
                            <span class="font-medium">{ "Impact: " }</span>
                            { impact }
                        </p>
                    }
                </div>
            }
        </div>
    }
}
