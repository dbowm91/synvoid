use yew::prelude::*;

#[derive(Properties, PartialEq)]
pub struct TooltipProps {
    pub content: String,
    pub children: Html,
    #[prop_or_default]
    pub position: TooltipPosition,
    #[prop_or_default]
    pub title: Option<String>,
}

#[derive(PartialEq, Clone, Copy)]
pub enum TooltipPosition {
    Top,
    Bottom,
    Left,
    Right,
}

impl Default for TooltipPosition {
    fn default() -> Self {
        Self::Top
    }
}

#[function_component]
pub fn Tooltip(props: &TooltipProps) -> Html {
    let visible = use_state(|| false);

    let on_mouse_enter = {
        let visible = visible.clone();
        Callback::from(move |_| visible.set(true))
    };

    let on_mouse_leave = {
        let visible = visible.clone();
        Callback::from(move |_| visible.set(false))
    };

    let position_class = match props.position {
        TooltipPosition::Top => "bottom-full left-1/2 -translate-x-1/2 mb-2",
        TooltipPosition::Bottom => "top-full left-1/2 -translate-x-1/2 mt-2",
        TooltipPosition::Left => "right-full top-1/2 -translate-y-1/2 mr-2",
        TooltipPosition::Right => "left-full top-1/2 -translate-y-1/2 ml-2",
    };

    let arrow_class = match props.position {
        TooltipPosition::Top => "top-full left-1/2 -translate-x-1/2 border-t-primary",
        TooltipPosition::Bottom => "bottom-full left-1/2 -translate-x-1/2 border-b-primary",
        TooltipPosition::Left => "left-full top-1/2 -translate-y-1/2 border-l-primary",
        TooltipPosition::Right => "right-full top-1/2 -translate-y-1/2 border-r-primary",
    };

    html! {
        <div
            class="relative inline-flex items-center"
            onmouseenter={on_mouse_enter}
            onmouseleave={on_mouse_leave}
        >
            {props.children.clone()}

            if *visible {
                <div class={format!("absolute z-50 {}", position_class)}>
                    <div class="bg-primary text-white text-xs rounded-lg shadow-lg p-3 max-w-xs whitespace-normal border border-secondary animate-fade-in">
                        if let Some(title) = &props.title {
                            <div class="font-semibold mb-1 text-sm">{ title }</div>
                        }
                        { &props.content }
                    </div>
                    <div class={format!("absolute border-4 border-transparent {}", arrow_class)} />
                </div>
            }
        </div>
    }
}

#[derive(Properties, PartialEq)]
pub struct HelpIconProps {
    pub content: String,
    #[prop_or_default]
    pub title: Option<String>,
}

#[function_component]
pub fn HelpIcon(props: &HelpIconProps) -> Html {
    html! {
        <Tooltip content={props.content.clone()} title={props.title.clone()}>
            <span class="ml-1 inline-flex items-center justify-center w-4 h-4 rounded-full bg-tertiary text-secondary text-xs cursor-help hover:bg-blue-600 hover:text-white transition-colors">
                {"?"}
            </span>
        </Tooltip>
    }
}
