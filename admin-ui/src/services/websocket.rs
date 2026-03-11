use wasm_bindgen::prelude::*;
use wasm_bindgen::JsCast;
use web_sys::{ErrorEvent, MessageEvent, WebSocket};
use yew::Callback;

pub struct WebSocketService {
    ws: Option<WebSocket>,
}

impl Default for WebSocketService {
    fn default() -> Self {
        Self::new()
    }
}

impl WebSocketService {
    pub fn new() -> Self {
        Self { ws: None }
    }

    pub fn connect(
        &mut self,
        path: &str,
        on_message: Callback<String>,
        on_error: Callback<String>,
    ) -> Result<(), String> {
        let ws =
            WebSocket::new(path).map_err(|e| format!("Failed to create WebSocket: {:?}", e))?;

        {
            let on_message = on_message.clone();
            let closure = Closure::<dyn FnMut(MessageEvent)>::new(move |e: MessageEvent| {
                if let Ok(txt) = e.data().dyn_into::<js_sys::JsString>() {
                    let msg = String::from(txt);
                    on_message.emit(msg);
                }
            });
            ws.set_onmessage(Some(closure.as_ref().unchecked_ref()));
            closure.forget();
        }

        {
            let on_error = on_error.clone();
            let closure = Closure::<dyn FnMut(ErrorEvent)>::new(move |e: ErrorEvent| {
                let msg = format!("WebSocket error: {:?}", e);
                on_error.emit(msg);
            });
            ws.set_onerror(Some(closure.as_ref().unchecked_ref()));
            closure.forget();
        }

        self.ws = Some(ws);
        Ok(())
    }

    pub fn send(&self, message: &str) -> Result<(), String> {
        if let Some(ws) = &self.ws {
            ws.send_with_str(message)
                .map_err(|e| format!("Failed to send: {:?}", e))?;
        }
        Ok(())
    }

    pub fn close(&mut self) {
        if let Some(ws) = self.ws.take() {
            let _ = ws.close();
        }
    }

    pub fn is_connected(&self) -> bool {
        self.ws
            .as_ref()
            .map_or(false, |ws| ws.ready_state() == WebSocket::OPEN)
    }
}

impl Drop for WebSocketService {
    fn drop(&mut self) {
        self.close();
    }
}
