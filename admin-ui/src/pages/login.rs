use crate::components::forms::Input;
use crate::services::api::ApiService;
use wasm_bindgen_futures::spawn_local;
use yew::prelude::*;

enum LoginState {
    Idle,
    Loading,
    #[allow(dead_code)]
    Error(String),
}

#[derive(Properties, PartialEq)]
pub struct LoginProps {
    pub on_authenticated: Callback<()>,
}

#[function_component]
pub fn Login(props: &LoginProps) -> Html {
    let token_input = use_state(String::new);
    let login_state = use_state(|| LoginState::Idle);
    let error_msg = use_state(String::new);
    let on_authenticated = props.on_authenticated.clone();

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
        Callback::from(move |e: SubmitEvent| {
            e.prevent_default();
            let token = (*token_input).clone();
            if token.is_empty() {
                error_msg.set("Please enter a token".to_string());
                return;
            }

            login_state.set(LoginState::Loading);
            error_msg.set(String::new());

            let login_state = login_state.clone();
            let error_msg = error_msg.clone();
            let on_authenticated = on_authenticated.clone();

            spawn_local(async move {
                match ApiService::login(&token).await {
                    Ok(_csrf_token) => {
                        on_authenticated.emit(());
                    }
                    Err(msg) => {
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

                <form onsubmit={on_submit} class="space-y-6">
                    <Input
                        label="Admin Token"
                        name="token"
                        input_type="password"
                        value={(*token_input).clone()}
                        on_change={on_token_change}
                        placeholder="Enter your admin token"
                        help="Configured in your server's admin.security.admin_token setting"
                    />

                    <button
                        type="submit"
                        disabled={is_loading}
                        class="w-full px-4 py-3 bg-blue-600 text-white rounded-lg hover:bg-blue-700 disabled:opacity-50 disabled:cursor-not-allowed font-medium"
                    >
                        { if is_loading { "Authenticating..." } else { "Login" } }
                    </button>
                </form>
            </div>
        </div>
    }
}
