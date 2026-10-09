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

#[derive(PartialEq, Clone, Copy, Default)]
pub enum TooltipPosition {
    #[default]
    Top,
    #[allow(dead_code)]
    Bottom,
    #[allow(dead_code)]
    Left,
    Right,
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

    // Focus mirrors hover: every help affordance in Settings is wrapped in a
    // `Tooltip`, and without this the entire explanatory text — including the
    // "Impact:" notes — was unreachable without a mouse. On a touch device a
    // hover-only tooltip has no trigger at all.
    let on_focus = {
        let visible = visible.clone();
        Callback::from(move |_: FocusEvent| visible.set(true))
    };

    let on_blur = {
        let visible = visible.clone();
        Callback::from(move |_: FocusEvent| visible.set(false))
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

    // Yew 0.23 exposes no `use_id` hook, and `role="tooltip"` needs a stable
    // per-instance id to be referenceable, so mint one from a counter rather
    // than sharing a single hard-coded id across every tooltip instance.
    static TOOLTIP_ID: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(1);
    let tooltip_id = format!(
        "synvoid-tooltip-{}",
        TOOLTIP_ID.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
    );

    html! {
        // The wrapper is not itself focusable — its child (the `?` badge) is —
        // so focus/blur are handled on the wrapper and bubble from that child.
        <div
            class="relative inline-flex items-center"
            onmouseenter={on_mouse_enter}
            onmouseleave={on_mouse_leave}
            onfocus={on_focus}
            onblur={on_blur}
        >
            {props.children.clone()}

            if *visible {
                <div id={tooltip_id.clone()} role="tooltip" class={format!("absolute z-50 {}", position_class)}>
                    <div class="bg-accent text-white text-xs rounded-lg shadow-lg p-3 max-w-xs whitespace-normal border border-secondary animate-fade-in">
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
            // Focusable so the tooltip's focus handler has something to fire on,
            // and named so the badge is announced as help rather than a bare
            // question mark.
            <span
                tabindex="0"
                role="button"
                aria-label={format!("Help: {}", props.content)}
                class="ml-1 inline-flex items-center justify-center w-5 h-5 rounded-full bg-tertiary text-secondary text-xs cursor-help hover:bg-blue-600 hover:text-white transition-colors expand-hit"
            >
                {"?"}
            </span>
        </Tooltip>
    }
}
