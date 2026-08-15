use gloo::timers::callback::Timeout;
use web_sys::KeyboardEvent;
use yew::prelude::*;

#[derive(Properties, PartialEq)]
#[allow(dead_code)]
pub struct ConfirmDialogProps {
    pub show: bool,
    pub title: String,
    pub message: String,
    pub confirm_label: Option<String>,
    pub cancel_label: Option<String>,
    pub confirm_type: Option<ConfirmType>,
    pub on_confirm: Callback<()>,
    pub on_cancel: Callback<()>,
}

#[derive(Clone, PartialEq)]
#[allow(dead_code)]
pub enum ConfirmType {
    Danger,
    Warning,
    Primary,
}

#[allow(dead_code)]
impl ConfirmType {
    fn class(&self) -> &str {
        match self {
            ConfirmType::Danger => "bg-red-600 hover:bg-red-700",
            ConfirmType::Warning => "bg-yellow-600 hover:bg-yellow-700",
            ConfirmType::Primary => "bg-blue-600 hover:bg-blue-700",
        }
    }
}

#[function_component]
pub fn ConfirmDialog(props: &ConfirmDialogProps) -> Html {
    if !props.show {
        return html! {};
    }

    let confirm_label = props.confirm_label.as_deref().unwrap_or("Confirm");
    let cancel_label = props.cancel_label.as_deref().unwrap_or("Cancel");
    let confirm_type = props.confirm_type.as_ref().unwrap_or(&ConfirmType::Danger);

    let on_confirm = {
        let on_confirm = props.on_confirm.clone();
        Callback::from(move |_| {
            on_confirm.emit(());
        })
    };

    let on_cancel = {
        let on_cancel = props.on_cancel.clone();
        Callback::from(move |_| {
            on_cancel.emit(());
        })
    };

    // Escape key handler
    let on_keydown = {
        let on_cancel = props.on_cancel.clone();
        Callback::from(move |e: KeyboardEvent| {
            if e.key() == "Escape" {
                on_cancel.emit(());
            }
        })
    };

    // Auto-focus the cancel button on mount
    let cancel_node = use_node_ref();
    {
        let cancel_node = cancel_node.clone();
        let show = props.show;
        use_effect_with(show, move |show| {
            if *show {
                // Defer focus to next microtask so the DOM is rendered
                let node = cancel_node.clone();
                let _timeout = Timeout::new(0, move || {
                    if let Some(el) = node.cast::<web_sys::HtmlElement>() {
                        let _ = el.focus();
                    }
                });
            }
            || {}
        });
    }

    html! {
        <div
            class="fixed inset-0 z-50 flex items-center justify-center"
            role="dialog"
            aria-modal="true"
            aria-labelledby="confirm-dialog-title"
            onkeydown={on_keydown}
        >
            <div
                class="absolute inset-0 bg-black/60 backdrop-blur-sm"
                onclick={on_cancel.clone()}
            />
            <div class="relative bg-secondary border border-default rounded-lg shadow-xl max-w-md w-full mx-4 p-6 animate-fade-in">
                <h3 id="confirm-dialog-title" class="text-lg font-semibold text-primary mb-2">
                    { &props.title }
                </h3>
                <p class="text-secondary mb-6">
                    { &props.message }
                </p>
                <div class="flex justify-end gap-3">
                    <button
                        ref={cancel_node}
                        onclick={on_cancel}
                        class="px-4 py-2 bg-tertiary text-primary rounded-lg hover:opacity-80 transition"
                    >
                        { cancel_label }
                    </button>
                    <button
                        onclick={on_confirm}
                        class={format!("px-4 py-2 text-white rounded-lg transition {}", confirm_type.class())}
                    >
                        { confirm_label }
                    </button>
                </div>
            </div>
        </div>
    }
}
