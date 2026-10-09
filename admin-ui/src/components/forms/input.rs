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
    #[prop_or_default]
    pub badge: Option<yew::Html>,
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

    // `oninput`, not `onchange`: a controlled Yew input only re-renders when
    // its state changes, and the DOM `change` event fires on blur/commit
    // rather than per keystroke. With `onchange`, typing left the bound state
    // stale, so pressing Enter submitted a form whose state still held the
    // previous (empty) value — the login screen reported "Please enter a
    // token" no matter what was typed, and validation/derived UI in the 140
    // call sites of this component only refreshed after blur.
    let on_change = props.on_change.reform(|e: InputEvent| {
        let input: web_sys::HtmlInputElement = e.target_unchecked_into();
        input.value()
    });

    let badge = props.badge.clone();

    html! {
        <div class="mb-4">
            <label class="block text-sm font-medium text-primary mb-1" for={name.clone()}>
                { label }
                if let Some(b) = badge {
                    { b }
                }
            </label>
            <input
                type={input_type}
                id={name.clone()}
                name={name}
                value={value}
                placeholder={placeholder}
                oninput={on_change}
                autocomplete="off"
                class="w-full px-3 py-2 bg-tertiary border border-default rounded-lg text-primary focus:outline-none focus:ring-2 focus:ring-action-500"
            />
            if let Some(help_text) = help {
                <p class="mt-1 text-xs text-secondary">{ help_text }</p>
            }
        </div>
    }
}
