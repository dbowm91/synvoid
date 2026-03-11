use std::cell::RefCell;
use std::rc::Rc;
use wasm_bindgen::closure::Closure;
use wasm_bindgen::JsCast;
use yew::prelude::*;

thread_local! {
    static TOAST_STATE: Rc<RefCell<Vec<Toast>>> = Rc::new(RefCell::new(Vec::new()));
}

#[derive(Clone, PartialEq)]
pub struct Toast {
    pub id: usize,
    pub message: String,
    pub toast_type: ToastType,
}

#[derive(Clone, PartialEq)]
pub enum ToastType {
    Success,
    Error,
    Warning,
    Info,
}

impl Toast {
    pub fn new(message: String, toast_type: ToastType) -> Self {
        static ID_COUNTER: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(1);
        let id = ID_COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        Self {
            id,
            message,
            toast_type,
        }
    }

    pub fn success(message: &str) -> Self {
        Self::new(message.to_string(), ToastType::Success)
    }

    pub fn error(message: &str) -> Self {
        Self::new(message.to_string(), ToastType::Error)
    }

    pub fn warning(message: &str) -> Self {
        Self::new(message.to_string(), ToastType::Warning)
    }

    pub fn info(message: &str) -> Self {
        Self::new(message.to_string(), ToastType::Info)
    }
}

pub fn toast_success(msg: &str) {
    TOAST_STATE.with(|state| {
        state.borrow_mut().push(Toast::success(msg));
    });
    notify_toasts_changed();
}

pub fn toast_error(msg: &str) {
    TOAST_STATE.with(|state| {
        state.borrow_mut().push(Toast::error(msg));
    });
    notify_toasts_changed();
}

pub fn toast_warning(msg: &str) {
    TOAST_STATE.with(|state| {
        state.borrow_mut().push(Toast::warning(msg));
    });
    notify_toasts_changed();
}

pub fn toast_info(msg: &str) {
    TOAST_STATE.with(|state| {
        state.borrow_mut().push(Toast::info(msg));
    });
    notify_toasts_changed();
}

pub fn remove_toast(id: usize) {
    TOAST_STATE.with(|state| {
        state.borrow_mut().retain(|t| t.id != id);
    });
    notify_toasts_changed();
}

pub fn get_toasts() -> Vec<Toast> {
    TOAST_STATE.with(|state| state.borrow().clone())
}

fn notify_toasts_changed() {
    if let Some(window) = web_sys::window() {
        if let Ok(event) = web_sys::CustomEvent::new("toast-update") {
            let _ = window.dispatch_event(&event);
        }
    }
}

#[function_component]
pub fn ToastContainer() -> Html {
    let toasts = use_state(Vec::<Toast>::new);

    {
        let toasts_for_effect = toasts.clone();
        use_effect_with((), move |_| {
            let toasts = toasts_for_effect.clone();
            let toasts_for_closure = toasts_for_effect.clone();

            let closure = Closure::wrap(Box::new(move || {
                toasts_for_closure.set(get_toasts());
            }) as Box<dyn FnMut()>);

            if let Some(window) = web_sys::window() {
                let _ = window.add_event_listener_with_callback(
                    "toast-update",
                    closure.as_ref().unchecked_ref(),
                );
            }

            toasts.set(get_toasts());

            move || {}
        });
    }

    if toasts.is_empty() {
        return html! {};
    }

    html! {
        <div class="fixed top-4 right-4 z-50 space-y-2">
            { for toasts.iter().map(|t| {
                let id = t.id;
                let on_close = Callback::from(move |_: MouseEvent| {
                    remove_toast(id);
                });
                html! {
                    <ToastItem toast={t.clone()} on_close={on_close} />
                }
            })}
        </div>
    }
}

#[derive(Properties, PartialEq)]
struct ToastItemProps {
    toast: Toast,
    on_close: Callback<MouseEvent>,
}

#[function_component]
fn ToastItem(props: &ToastItemProps) -> Html {
    let (bg_color, icon_color, icon) = match props.toast.toast_type {
        ToastType::Success => (
            "bg-green-900/90 border-green-500",
            "text-green-400",
            success_icon(),
        ),
        ToastType::Error => ("bg-red-900/90 border-red-500", "text-red-400", error_icon()),
        ToastType::Warning => (
            "bg-yellow-900/90 border-yellow-500",
            "text-yellow-400",
            warning_icon(),
        ),
        ToastType::Info => (
            "bg-blue-900/90 border-blue-500",
            "text-blue-400",
            info_icon(),
        ),
    };

    html! {
        <div class={format!("flex items-center gap-3 px-4 py-3 rounded-lg border shadow-lg min-w-[300px] max-w-[400px] animate-slide-in {}", bg_color)}>
            <span class={format!("flex-shrink-0 w-5 h-5 {}", icon_color)}>
                { icon }
            </span>
            <p class="flex-1 text-sm text-white">{ &props.toast.message }</p>
            <button
                onclick={props.on_close.clone()}
                class="flex-shrink-0 text-white/60 hover:text-white"
                aria-label="Close"
            >
                <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12" />
                </svg>
            </button>
        </div>
    }
}

fn success_icon() -> Html {
    html! {
        <svg fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M5 13l4 4L19 7" />
        </svg>
    }
}

fn error_icon() -> Html {
    html! {
        <svg fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12" />
        </svg>
    }
}

fn warning_icon() -> Html {
    html! {
        <svg fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" />
        </svg>
    }
}

fn info_icon() -> Html {
    html! {
        <svg fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
        </svg>
    }
}
