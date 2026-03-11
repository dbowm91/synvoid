use yew::prelude::*;

#[derive(Properties, PartialEq)]
pub struct InputProps {
    pub label: String,
    pub name: String,
    #[prop_or_default]
    pub value: String,
    #[prop_or_default]
    pub input_type: String,
    #[prop_or_default]
    pub placeholder: String,
    #[prop_or_default]
    pub help: Option<String>,
    #[prop_or_default]
    pub on_change: Callback<String>,
}

#[function_component]
pub fn Input(props: &InputProps) -> Html {
    let input_type = if props.input_type.is_empty() {
        "text".to_string()
    } else {
        props.input_type.clone()
    };
    let name = props.name.clone();
    let value = props.value.clone();
    let placeholder = props.placeholder.clone();
    let label = props.label.clone();
    let help = props.help.clone();

    let on_change = props.on_change.reform(|e: Event| {
        let input: web_sys::HtmlInputElement = e.target_unchecked_into();
        input.value()
    });

    html! {
        <div class="mb-4">
            <label class="block text-sm font-medium text-primary mb-1" for={name.clone()}>
                { label }
            </label>
            <input
                type={input_type}
                id={name.clone()}
                name={name}
                value={value}
                placeholder={placeholder}
                onchange={on_change}
                class="w-full px-3 py-2 bg-tertiary border border-default rounded-lg text-primary focus:outline-none focus:ring-2 focus:ring-blue-500"
            />
            if let Some(help_text) = help {
                <p class="mt-1 text-xs text-secondary">{ help_text }</p>
            }
        </div>
    }
}
