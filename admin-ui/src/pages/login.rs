use crate::components::forms::Input;
use serde::{Deserialize, Serialize};
use wasm_bindgen_futures::spawn_local;
use yew::prelude::*;

#[derive(Serialize, Deserialize, Clone)]
pub struct LoginRequest {
    pub token: String,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct LoginResponse {
    pub success: bool,
    pub token: Option<String>,
    pub expires_at: Option<String>,
}

enum LoginState {
    Idle,
    Loading,
    Error(String),
}

#[function_component]
pub fn Login() -> Html {
    let token_input = use_state(|| String::new());
    let login_state = use_state(|| LoginState::Idle);
    let error_msg = use_state(|| String::new());

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

            let token_input = token_input.clone();
            let login_state = login_state.clone();
            let error_msg = error_msg.clone();

            spawn_local(async move {
                let api = crate::services::api::ApiService::new();
                match api
                    .post::<LoginResponse, _>(
                        "/auth/login",
                        &LoginRequest {
                            token: token.clone(),
                        },
                    )
                    .await
                {
                    Ok(response) => {
                        if response.success {
                            if let Some(jwt) = response.token {
                                if let Some(window) = web_sys::window() {
                                    if let Ok(Some(storage)) = window.local_storage() {
                                        let _ = storage.set_item("admin_token", &jwt);
                                    }
                                    let _ = window.location().set_href("/");
                                }
                            }
                        } else {
                            login_state.set(LoginState::Error("Invalid token".to_string()));
                            error_msg.set("Invalid token".to_string());
                        }
                    }
                    Err(e) => {
                        login_state.set(LoginState::Error(e.clone()));
                        error_msg.set(e);
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
