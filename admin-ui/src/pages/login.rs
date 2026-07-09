use crate::components::forms::Input;
use wasm_bindgen::{JsCast, JsValue};
use wasm_bindgen_futures::spawn_local;
use yew::prelude::*;

enum LoginState {
    Idle,
    Loading,
    #[allow(dead_code)]
    Error(String),
}

#[function_component]
pub fn Login() -> Html {
    let token_input = use_state(String::new);
    let login_state = use_state(|| LoginState::Idle);
    let error_msg = use_state(String::new);

    let on_token_change = {
        let token_input = token_input.clone();
        Callback::from(move |value: String| {
            token_input.set(value);
        })
    };

    let on_submit = {
        let token_input = token_input.clone();
        let login_state = login_state.clone();
        let error_msg = error_msg.clone();
        Callback::from(move |e: MouseEvent| {
            e.prevent_default();
            let token = (*token_input).clone();
            if token.is_empty() {
                error_msg.set("Please enter a token".to_string());
                return;
            }

            login_state.set(LoginState::Loading);

            let login_state = login_state.clone();
            let error_msg = error_msg.clone();

            spawn_local(async move {
                let url = "/api/auth/session";
                let opts = web_sys::RequestInit::new();
                opts.set_method("POST");
                opts.set_mode(web_sys::RequestMode::SameOrigin);
                opts.set_credentials(web_sys::RequestCredentials::Include);
                opts.set_body(&JsValue::NULL);

                let request = match web_sys::Request::new_with_str_and_init(url, &opts) {
                    Ok(r) => r,
                    Err(e) => {
                        let msg = format!("Failed to build request: {:?}", e);
                        login_state.set(LoginState::Error(msg.clone()));
                        error_msg.set(msg);
                        return;
                    }
                };
                let _ = request
                    .headers()
                    .set("Authorization", &format!("Bearer {}", token));

                let window = match web_sys::window() {
                    Some(w) => w,
                    None => {
                        let msg = "No window available".to_string();
                        login_state.set(LoginState::Error(msg.clone()));
                        error_msg.set(msg);
                        return;
                    }
                };

                match wasm_bindgen_futures::JsFuture::from(window.fetch_with_request(&request))
                    .await
                {
                    Ok(resp_value) => {
                        let resp: web_sys::Response = match resp_value.dyn_into() {
                            Ok(r) => r,
                            Err(_) => {
                                let msg = "Invalid response".to_string();
                                login_state.set(LoginState::Error(msg.clone()));
                                error_msg.set(msg);
                                return;
                            }
                        };
                        if resp.ok() {
                            if let Some(window) = web_sys::window() {
                                if let Ok(Some(storage)) = window.local_storage() {
                                    let _ = storage.set_item("admin_token", &token);
                                }
                                let cookie = format!(
                                    "synvoid_ws_token={}; Path=/; SameSite=Strict; Max-Age=3600",
                                    token
                                );
                                let _ = js_sys::eval(&format!("document.cookie = {:?};", cookie));
                                let _ = window.location().set_href("/");
                            }
                        } else {
                            let msg = format!("Login failed (HTTP {})", resp.status());
                            login_state.set(LoginState::Error(msg.clone()));
                            error_msg.set(msg);
                        }
                    }
                    Err(e) => {
                        let msg = format!("Request failed: {:?}", e);
                        login_state.set(LoginState::Error(msg.clone()));
                        error_msg.set(msg);
                    }
                }
            });
        })
    };

    let is_loading = matches!(*login_state, LoginState::Loading);

    html! {
        <div class="min-h-screen flex items-center justify-center bg-primary">
            <div class="bg-secondary rounded-lg border border-default p-8 w-full max-w-md">
                <div class="text-center mb-8">
                    <h1 class="text-3xl font-bold text-primary mb-2">{ "SynVoid Admin" }</h1>
                    <p class="text-secondary">{ "Enter your admin token to access the dashboard" }</p>
                </div>

                if !(*error_msg).is_empty() {
                    <div class="mb-4 p-3 bg-red-500/10 border border-red-500/30 rounded-lg text-red-400 text-sm">
                        { (*error_msg).clone() }
                    </div>
                }

                <form class="space-y-6">
                    <Input
                        label="Admin Token"
                        name="token"
                        value={(*token_input).clone()}
                        on_change={on_token_change}
                        placeholder="Enter your admin token"
                    />

                    <button
                        type="button"
                        onclick={on_submit}
                        disabled={is_loading}
                        class="w-full px-4 py-3 bg-blue-600 text-white rounded-lg hover:bg-blue-700 disabled:opacity-50 disabled:cursor-not-allowed font-medium"
                    >
                        { if is_loading { "Authenticating..." } else { "Login" } }
                    </button>
                </form>

                <div class="mt-6 text-center">
                    <p class="text-xs text-secondary">
                        { "Tokens are configured in your server's admin.security.admin_token setting" }
                    </p>
                </div>
            </div>
        </div>
    }
}
