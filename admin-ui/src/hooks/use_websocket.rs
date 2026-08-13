use gloo::timers::callback::Interval;
use serde::de::DeserializeOwned;
use wasm_bindgen::JsCast;
use web_sys::{MessageEvent, WebSocket};
use yew::prelude::*;

#[derive(Debug, PartialEq)]
pub enum UseWebSocketState<T> {
    Connecting,
    Connected(T),
    Polling,
    Disconnected,
    Error(String),
}

impl<T: Clone> Clone for UseWebSocketState<T> {
    fn clone(&self) -> Self {
        match self {
            UseWebSocketState::Connecting => UseWebSocketState::Connecting,
            UseWebSocketState::Connected(data) => UseWebSocketState::Connected(data.clone()),
            UseWebSocketState::Polling => UseWebSocketState::Polling,
            UseWebSocketState::Disconnected => UseWebSocketState::Disconnected,
            UseWebSocketState::Error(msg) => UseWebSocketState::Error(msg.clone()),
        }
    }
}

pub fn build_ws_url(path: &str) -> String {
    if let Some(window) = web_sys::window() {
        if let Ok(location) = window.location().href() {
            if let Some(idx) = location.find("://") {
                let scheme = &location[..idx];
                let rest = &location[idx + 3..];
                if let Some(path_start) = rest.find('/') {
                    let host = &rest[..path_start];
                    let ws_scheme = if scheme == "https" { "wss" } else { "ws" };
                    return format!("{}://{}{}", ws_scheme, host, path);
                }
            }
        }
    }
    path.to_string()
}

#[hook]
pub fn use_websocket<T: DeserializeOwned + Clone + 'static>(path: &str) -> UseWebSocketState<T> {
    let state = use_state(|| UseWebSocketState::<T>::Connecting);
    let ws_ref = use_mut_ref(|| None::<WebSocket>);

    {
        let state = state.clone();
        let path = path.to_string();

        use_effect_with((), move |_| {
            let ws_url = build_ws_url(&path);
            let ws = match WebSocket::new(&ws_url) {
                Ok(ws) => ws,
                Err(e) => {
                    state.set(UseWebSocketState::Error(format!(
                        "Failed to connect: {:?}",
                        e
                    )));
                    return Box::new(|| {}) as Box<dyn FnOnce()>;
                }
            };

            {
                let state = state.clone();
                let closure =
                    wasm_bindgen::closure::Closure::<dyn FnMut(_)>::new(move |_: MessageEvent| {
                        state.set(UseWebSocketState::Connecting);
                    });
                ws.set_onopen(Some(closure.as_ref().unchecked_ref()));
                closure.forget();
            }

            {
                let state = state.clone();
                let closure =
                    wasm_bindgen::closure::Closure::<dyn FnMut(_)>::new(move |e: MessageEvent| {
                        if let Ok(txt) = e.data().dyn_into::<js_sys::JsString>() {
                            let msg = String::from(txt);
                            if let Ok(data) = serde_json::from_str::<T>(&msg) {
                                state.set(UseWebSocketState::Connected(data));
                            }
                        }
                    });
                ws.set_onmessage(Some(closure.as_ref().unchecked_ref()));
                closure.forget();
            }

            {
                let state = state.clone();
                let closure = wasm_bindgen::closure::Closure::<dyn FnMut(_)>::new(
                    move |_: web_sys::Event| {
                        state.set(UseWebSocketState::Disconnected);
                    },
                );
                ws.set_onclose(Some(closure.as_ref().unchecked_ref()));
                closure.forget();
            }

            {
                let state = state.clone();
                let closure = wasm_bindgen::closure::Closure::<dyn FnMut(_)>::new(
                    move |_: web_sys::ErrorEvent| {
                        state.set(UseWebSocketState::Error("WebSocket error".to_string()));
                    },
                );
                ws.set_onerror(Some(closure.as_ref().unchecked_ref()));
                closure.forget();
            }

            *ws_ref.borrow_mut() = Some(ws.clone());

            let ws_close = ws.clone();
            Box::new(move || {
                let _ = ws_close.close();
            }) as Box<dyn FnOnce()>
        });
    }

    (*state).clone()
}

#[hook]
pub fn use_websocket_or_poll<T: DeserializeOwned + Clone + 'static>(
    ws_path: &str,
    poll_path: &str,
    poll_interval_ms: u32,
) -> (UseWebSocketState<T>, Callback<()>) {
    let state = use_state(|| UseWebSocketState::<T>::Connecting);
    let ws_ref = use_mut_ref(|| None::<WebSocket>);
    let interval_ref = use_mut_ref(|| None::<Interval>);
    let polling_active = use_mut_ref(|| false);

    let refresh = {
        let state = state.clone();
        let poll_path = poll_path.to_string();
        let interval_ref = interval_ref.clone();
        Callback::from(move |_: ()| {
            let state = state.clone();
            let poll_path = poll_path.clone();
            let interval_ref = interval_ref.clone();
            wasm_bindgen_futures::spawn_local(async move {
                let api = crate::services::api::ApiService::new();
                match api.get::<T>(&poll_path).await {
                    Ok(data) => {
                        state.set(UseWebSocketState::Connected(data));
                    }
                    Err(e) => {
                        if e.contains("Session expired") || e.contains("401") || e.contains("403") {
                            *interval_ref.borrow_mut() = None;
                            state.set(UseWebSocketState::Disconnected);
                        } else {
                            state.set(UseWebSocketState::Error(e));
                        }
                    }
                }
            });
        })
    };

    {
        let state = state.clone();
        let ws_path = ws_path.to_string();
        let poll_interval_ms = poll_interval_ms;
        let refresh = refresh.clone();
        let interval_ref = interval_ref.clone();
        let polling_active = polling_active.clone();

        use_effect_with((), move |_| {
            let ws_url = build_ws_url(&ws_path);
            let ws = match WebSocket::new(&ws_url) {
                Ok(ws) => ws,
                Err(_) => {
                    if !*polling_active.borrow() {
                        *polling_active.borrow_mut() = true;
                        state.set(UseWebSocketState::Polling);
                        let refresh_clone = refresh.clone();
                        let interval = Interval::new(poll_interval_ms, move || {
                            refresh_clone.emit(());
                        });
                        *interval_ref.borrow_mut() = Some(interval);
                        refresh.emit(());
                    }
                    return Box::new(|| {}) as Box<dyn FnOnce()>;
                }
            };

            {
                let state = state.clone();
                let polling_active = polling_active.clone();
                let interval_ref = interval_ref.clone();
                let closure =
                    wasm_bindgen::closure::Closure::<dyn FnMut(_)>::new(move |_: MessageEvent| {
                        if *polling_active.borrow() {
                            *interval_ref.borrow_mut() = None;
                            *polling_active.borrow_mut() = false;
                        }
                        state.set(UseWebSocketState::Connecting);
                    });
                ws.set_onopen(Some(closure.as_ref().unchecked_ref()));
                closure.forget();
            }

            {
                let state = state.clone();
                let closure =
                    wasm_bindgen::closure::Closure::<dyn FnMut(_)>::new(move |e: MessageEvent| {
                        if let Ok(txt) = e.data().dyn_into::<js_sys::JsString>() {
                            let msg = String::from(txt);
                            if let Ok(data) = serde_json::from_str::<T>(&msg) {
                                state.set(UseWebSocketState::Connected(data));
                            }
                        }
                    });
                ws.set_onmessage(Some(closure.as_ref().unchecked_ref()));
                closure.forget();
            }

            {
                let state = state.clone();
                let polling_active = polling_active.clone();
                let interval_ref = interval_ref.clone();
                let refresh = refresh.clone();
                let closure = wasm_bindgen::closure::Closure::<dyn FnMut(_)>::new(
                    move |_: web_sys::Event| {
                        if !*polling_active.borrow() {
                            *polling_active.borrow_mut() = true;
                            state.set(UseWebSocketState::Polling);
                            let refresh_for_interval = refresh.clone();
                            let interval = Interval::new(poll_interval_ms, move || {
                                refresh_for_interval.emit(());
                            });
                            *interval_ref.borrow_mut() = Some(interval);
                            refresh.emit(());
                        } else {
                            state.set(UseWebSocketState::Disconnected);
                        }
                    },
                );
                ws.set_onclose(Some(closure.as_ref().unchecked_ref()));
                closure.forget();
            }

            {
                let state = state.clone();
                let polling_active = polling_active.clone();
                let interval_ref = interval_ref.clone();
                let refresh = refresh.clone();
                let closure = wasm_bindgen::closure::Closure::<dyn FnMut(_)>::new(
                    move |_: web_sys::ErrorEvent| {
                        if !*polling_active.borrow() {
                            *polling_active.borrow_mut() = true;
                            state.set(UseWebSocketState::Polling);
                            let refresh_for_interval = refresh.clone();
                            let interval = Interval::new(poll_interval_ms, move || {
                                refresh_for_interval.emit(());
                            });
                            *interval_ref.borrow_mut() = Some(interval);
                            refresh.emit(());
                        } else {
                            state.set(UseWebSocketState::Error("WebSocket error".to_string()));
                        }
                    },
                );
                ws.set_onerror(Some(closure.as_ref().unchecked_ref()));
                closure.forget();
            }

            *ws_ref.borrow_mut() = Some(ws.clone());

            let ws_close = ws.clone();
            let interval_cleanup = interval_ref.clone();
            let polling_cleanup = polling_active.clone();
            Box::new(move || {
                let _ = ws_close.close();
                *interval_cleanup.borrow_mut() = None;
                *polling_cleanup.borrow_mut() = false;
            }) as Box<dyn FnOnce()>
        });
    }

    ((*state).clone(), refresh)
}
