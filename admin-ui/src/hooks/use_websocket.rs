use gloo::timers::callback::Interval;
use serde::de::DeserializeOwned;
use wasm_bindgen::JsCast;
use web_sys::{MessageEvent, WebSocket};
use yew::prelude::*;

#[derive(Debug)]
pub enum UseWebSocketState<T> {
    Connecting,
    Connected(T),
    Disconnected,
    Error(String),
}

impl<T: Clone> Clone for UseWebSocketState<T> {
    fn clone(&self) -> Self {
        match self {
            UseWebSocketState::Connecting => UseWebSocketState::Connecting,
            UseWebSocketState::Connected(data) => UseWebSocketState::Connected(data.clone()),
            UseWebSocketState::Disconnected => UseWebSocketState::Disconnected,
            UseWebSocketState::Error(msg) => UseWebSocketState::Error(msg.clone()),
        }
    }
}

#[hook]
pub fn use_websocket<T: DeserializeOwned + Clone + 'static>(path: &str) -> UseWebSocketState<T> {
    let state = use_state(|| UseWebSocketState::<T>::Connecting);
    let ws_ref = use_mut_ref(|| None::<WebSocket>);

    {
        let state = state.clone();
        let path = path.to_string();

        use_effect_with((), move |_| {
            let ws = match WebSocket::new(&path) {
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
                            match serde_json::from_str::<T>(&msg) {
                                Ok(data) => {
                                    state.set(UseWebSocketState::Connected(data));
                                }
                                Err(_) => {}
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

    let refresh = {
        let state = state.clone();
        let poll_path = poll_path.to_string();
        Callback::from(move |_: ()| {
            let state = state.clone();
            let poll_path = poll_path.clone();
            wasm_bindgen_futures::spawn_local(async move {
                let api = crate::services::api::ApiService::new();
                match api.get::<T>(&poll_path).await {
                    Ok(data) => {
                        state.set(UseWebSocketState::Connected(data));
                    }
                    Err(e) => {
                        state.set(UseWebSocketState::Error(e));
                    }
                }
            });
        })
    };

    {
        let state = state.clone();
        let ws_path = ws_path.to_string();
        let poll_path = poll_path.to_string();
        let refresh = refresh.clone();

        use_effect_with((), move |_| {
            let ws = match WebSocket::new(&ws_path) {
                Ok(ws) => ws,
                Err(_) => {
                    refresh.emit(());
                    let interval_ref = interval_ref.clone();
                    let refresh = refresh.clone();
                    let interval = Interval::new(poll_interval_ms, move || {
                        refresh.emit(());
                    });
                    *interval_ref.borrow_mut() = Some(interval);
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
                            match serde_json::from_str::<T>(&msg) {
                                Ok(data) => {
                                    state.set(UseWebSocketState::Connected(data));
                                }
                                Err(_) => {}
                            }
                        }
                    });
                ws.set_onmessage(Some(closure.as_ref().unchecked_ref()));
                closure.forget();
            }

            {
                let state = state.clone();
                let interval_ref = interval_ref.clone();
                let refresh_for_close = refresh.clone();
                let closure = wasm_bindgen::closure::Closure::<dyn FnMut(_)>::new(
                    move |_: web_sys::Event| {
                        state.set(UseWebSocketState::Disconnected);
                        let refresh = refresh_for_close.clone();
                        let interval = Interval::new(poll_interval_ms, move || {
                            refresh.emit(());
                        });
                        *interval_ref.borrow_mut() = Some(interval);
                    },
                );
                ws.set_onclose(Some(closure.as_ref().unchecked_ref()));
                closure.forget();
            }

            {
                let state = state.clone();
                let interval_ref = interval_ref.clone();
                let refresh_for_error = refresh.clone();
                let closure = wasm_bindgen::closure::Closure::<dyn FnMut(_)>::new(
                    move |_: web_sys::ErrorEvent| {
                        state.set(UseWebSocketState::Error("WebSocket error".to_string()));
                        let refresh = refresh_for_error.clone();
                        let interval = Interval::new(poll_interval_ms, move || {
                            refresh.emit(());
                        });
                        *interval_ref.borrow_mut() = Some(interval);
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

    ((*state).clone(), refresh)
}
