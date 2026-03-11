use yew::prelude::*;

#[derive(Properties, PartialEq)]
pub struct SelectProps {
    pub label: String,
    pub name: String,
    #[prop_or_default]
    pub value: String,
    pub options: Vec<(String, String)>,
    #[prop_or_default]
    pub help: Option<String>,
    #[prop_or_default]
    pub on_change: Callback<String>,
}

#[function_component]
pub fn Select(props: &SelectProps) -> Html {
    let on_change = {
        let on_change = props.on_change.clone();
        Callback::from(move |e: Event| {
            let input: web_sys::HtmlInputElement = e.target_unchecked_into();
            on_change.emit(input.value());
        })
    };

    html! {
        <div class="mb-4">
            <label class="block text-sm font-medium text-primary mb-1" for={props.name.clone()}>
                { &props.label }
            </label>
            <select
                id={props.name.clone()}
                name={props.name.clone()}
                value={props.value.clone()}
                onchange={on_change}
                class="w-full px-3 py-2 bg-tertiary border border-default rounded-lg text-primary focus:outline-none focus:ring-2 focus:ring-blue-500"
            >
                { for props.options.iter().map(|(value, label)| {
                    html! {
                        <option value={value.clone()} selected={props.value == *value}>
                            { label }
                        </option>
                    }
                })}
            </select>
            if let Some(help) = &props.help {
                <p class="mt-1 text-xs text-secondary">{ help }</p>
            }
        </div>
    }
}
