use crate::components::tooltip::{Tooltip, TooltipPosition};
use yew::prelude::*;

#[derive(Properties, PartialEq)]
pub struct ToggleProps {
    pub label: String,
    pub enabled: bool,
    pub on_toggle: Callback<bool>,
    #[prop_or_default]
    pub description: Option<String>,
    #[prop_or_default]
    pub tooltip_title: Option<String>,
    #[prop_or_default]
    pub tooltip_content: Option<String>,
    #[prop_or_default]
    pub impact: Option<String>,
    #[prop_or_default]
    pub disabled: bool,
}

#[function_component]
pub fn Toggle(props: &ToggleProps) -> Html {
    let enabled = use_state(|| props.enabled);

    if *enabled != props.enabled {
        enabled.set(props.enabled);
    }

    let onclick = {
        let enabled = enabled.clone();
        let on_toggle = props.on_toggle.clone();
        let disabled = props.disabled;
        Callback::from(move |_| {
            if !disabled {
                let new_value = !*enabled;
                enabled.set(new_value);
                on_toggle.emit(new_value);
            }
        })
    };

    let bg_class = if *enabled {
        "bg-blue-600"
    } else {
        "bg-gray-600"
    };
    let translate_class = if *enabled {
        "translate-x-5"
    } else {
        "translate-x-0"
    };

    let toggle_element = html! {
        <button
            onclick={onclick}
            disabled={props.disabled}
            class={format!(
                "relative w-10 h-6 rounded-full transition-colors {} {}",
                bg_class,
                if props.disabled { "opacity-50 cursor-not-allowed" } else { "cursor-pointer" }
            )}
        >
            <span class={format!("absolute top-1 left-1 w-4 h-4 bg-white rounded-full transition-transform {}", translate_class)} />
        </button>
    };

    html! {
        <div class="flex items-center justify-between py-3">
            <div class="flex-1 pr-4">
                <div class="flex items-center gap-2">
                    <span class="text-primary font-medium">{ &props.label }</span>
                    if let Some(content) = &props.tooltip_content {
                        <Tooltip
                            content={content.clone()}
                            title={props.tooltip_title.clone()}
                            position={TooltipPosition::Right}
                        >
                            <span class="inline-flex items-center justify-center w-4 h-4 rounded-full bg-tertiary text-secondary text-xs cursor-help hover:bg-blue-600 hover:text-white transition-colors">
                                {"?"}
                            </span>
                        </Tooltip>
                    }
                </div>
                if let Some(desc) = &props.description {
                    <p class="text-sm text-secondary mt-0.5">{ desc }</p>
                }
                if let Some(impact) = &props.impact {
                    <p class="text-xs text-yellow-500 mt-1">
                        <span class="font-medium">{ "Impact: " }</span>
                        { impact }
                    </p>
                }
            </div>
            { toggle_element }
        </div>
    }
}

#[derive(Properties, PartialEq)]
pub struct InputWithTooltipProps {
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
    pub tooltip_title: Option<String>,
    #[prop_or_default]
    pub tooltip_content: Option<String>,
    #[prop_or_default]
    pub impact: Option<String>,
    #[prop_or_default]
    pub on_change: Callback<String>,
    #[prop_or_default]
    pub oninput: Callback<String>,
    #[prop_or_default]
    pub min: Option<String>,
    #[prop_or_default]
    pub max: Option<String>,
    #[prop_or_default]
    pub disabled: bool,
}

#[function_component]
pub fn InputWithTooltip(props: &InputWithTooltipProps) -> Html {
    let input_type = if props.input_type.is_empty() {
        "text".to_string()
    } else {
        props.input_type.clone()
    };

    let on_change = props.on_change.reform(|e: Event| {
        let input: web_sys::HtmlInputElement = e.target_unchecked_into();
        input.value()
    });

    html! {
        <div class="mb-4">
            <div class="flex items-center gap-1 mb-1">
                <label class="text-sm font-medium text-primary" for={props.name.clone()}>
                    { &props.label }
                </label>
                if let Some(content) = &props.tooltip_content {
                    <Tooltip
                        content={content.clone()}
                        title={props.tooltip_title.clone()}
                        position={TooltipPosition::Right}
                    >
                        <span class="inline-flex items-center justify-center w-4 h-4 rounded-full bg-tertiary text-secondary text-xs cursor-help hover:bg-blue-600 hover:text-white transition-colors">
                            {"?"}
                        </span>
                    </Tooltip>
                }
            </div>
            <input
                type={input_type}
                id={props.name.clone()}
                name={props.name.clone()}
                value={props.value.clone()}
                placeholder={props.placeholder.clone()}
                onchange={on_change}
                min={props.min.clone()}
                max={props.max.clone()}
                disabled={props.disabled}
                class={format!(
                    "w-full px-3 py-2 bg-tertiary border border-default rounded-lg text-primary focus:outline-none focus:ring-2 focus:ring-blue-500 {}",
                    if props.disabled { "opacity-50 cursor-not-allowed" } else { "" }
                )}
            />
            if let Some(help) = &props.help {
                <p class="mt-1 text-xs text-secondary">{ help }</p>
            }
            if let Some(impact) = &props.impact {
                <p class="mt-1 text-xs text-yellow-500">
                    <span class="font-medium">{ "Impact: " }</span>
                    { impact }
                </p>
            }
        </div>
    }
}

#[derive(Properties, PartialEq)]
pub struct SelectWithTooltipProps {
    pub label: String,
    pub name: String,
    #[prop_or_default]
    pub value: String,
    pub options: Vec<(String, String)>,
    #[prop_or_default]
    pub help: Option<String>,
    #[prop_or_default]
    pub tooltip_title: Option<String>,
    #[prop_or_default]
    pub tooltip_content: Option<String>,
    #[prop_or_default]
    pub impact: Option<String>,
    #[prop_or_default]
    pub on_change: Callback<String>,
    #[prop_or_default]
    pub disabled: bool,
}

#[function_component]
pub fn SelectWithTooltip(props: &SelectWithTooltipProps) -> Html {
    let on_change = {
        let on_change = props.on_change.clone();
        Callback::from(move |e: Event| {
            let input: web_sys::HtmlSelectElement = e.target_unchecked_into();
            on_change.emit(input.value());
        })
    };

    html! {
        <div class="mb-4">
            <div class="flex items-center gap-1 mb-1">
                <label class="text-sm font-medium text-primary" for={props.name.clone()}>
                    { &props.label }
                </label>
                if let Some(content) = &props.tooltip_content {
                    <Tooltip
                        content={content.clone()}
                        title={props.tooltip_title.clone()}
                        position={TooltipPosition::Right}
                    >
                        <span class="inline-flex items-center justify-center w-4 h-4 rounded-full bg-tertiary text-secondary text-xs cursor-help hover:bg-blue-600 hover:text-white transition-colors">
                            {"?"}
                        </span>
                    </Tooltip>
                }
            </div>
            <select
                id={props.name.clone()}
                name={props.name.clone()}
                value={props.value.clone()}
                onchange={on_change}
                disabled={props.disabled}
                class={format!(
                    "w-full px-3 py-2 bg-tertiary border border-default rounded-lg text-primary focus:outline-none focus:ring-2 focus:ring-blue-500 {}",
                    if props.disabled { "opacity-50 cursor-not-allowed" } else { "" }
                )}
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
            if let Some(impact) = &props.impact {
                <p class="mt-1 text-xs text-yellow-500">
                    <span class="font-medium">{ "Impact: " }</span>
                    { impact }
                </p>
            }
        </div>
    }
}
