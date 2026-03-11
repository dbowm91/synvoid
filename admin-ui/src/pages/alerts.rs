use yew::prelude::*;
use crate::services::api::ApiService;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AlertConfig {
    pub enabled: bool,
    pub email_enabled: bool,
    pub email_recipients: Vec<String>,
    pub email_smtp_host: Option<String>,
    pub email_smtp_port: Option<u16>,
    pub email_username: Option<String>,
    pub email_password: Option<String>,
    pub webhook_enabled: bool,
    pub webhook_urls: Vec<String>,
    pub alerts: Vec<AlertRule>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AlertRule {
    pub name: String,
    pub metric: String,
    pub threshold: f64,
    pub condition: String,
    pub enabled: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct AlertConfigResponse {
    config: AlertConfig,
}

#[function_component]
pub fn Alerts() -> Html {
    let config = use_state(|| None as Option<AlertConfig>);
    let error = use_state(|| None as Option<String>);
    let saving = use_state(|| false);
    
    let email_recipients_input = use_state(|| String::new());
    let webhook_urls_input = use_state(|| String::new());

    {
        let config = config.clone();
        let error = error.clone();
        
        use_effect_with((), move |_| {
            let config = config.clone();
            let error = error.clone();
            
            wasm_bindgen_futures::spawn_local(async move {
                let api = ApiService::new();
                
                match api.get::<AlertConfigResponse>("/alerts/config").await {
                    Ok(resp) => config.set(Some(resp.config)),
                    Err(e) => error.set(Some(e)),
                }
            });
            
            || {}
        });
    }

    let on_save = {
        let config = config.clone();
        let saving = saving.clone();
        let error = error.clone();
        
        Callback::from(move |_| {
            let config = config.clone();
            let saving = saving.clone();
            let error = error.clone();
            
            if let Some(c) = (*config).clone() {
                saving.set(true);
                
                wasm_bindgen_futures::spawn_local(async move {
                    let api = ApiService::new();
                    
                    #[derive(Serialize)]
                    struct UpdateRequest { config: AlertConfig }
                    
                    match api.put::<AlertConfigResponse, _>("/alerts/config", &UpdateRequest { config: c }).await {
                        Ok(resp) => {
                            config.set(Some(resp.config));
                        }
                        Err(e) => {
                            error.set(Some(e));
                        }
                    }
                    saving.set(false);
                });
            }
        })
    };

    let on_test_webhook = {
        let error = error.clone();
        
        Callback::from(move |_| {
            let error = error.clone();
            
            wasm_bindgen_futures::spawn_local(async move {
                let api = ApiService::new();
                
                match api.post::<serde_json::Value, _>("/alerts/test-webhook", &()).await {
                    Ok(_) => {
                        tracing::info!("Test webhook sent");
                    }
                    Err(e) => {
                        error.set(Some(e));
                    }
                }
            });
        })
    };

    let toggle_config = {
        let config = config.clone();
        Callback::from(move |_| {
            if let Some(ref mut c) = *config {
                c.enabled = !c.enabled;
                config.set(Some(c.clone()));
            }
        })
    };

    let toggle_email = {
        let config = config.clone();
        Callback::from(move |_| {
            if let Some(ref mut c) = *config {
                c.email_enabled = !c.email_enabled;
                config.set(Some(c.clone()));
            }
        })
    };

    let toggle_webhook = {
        let config = config.clone();
        Callback::from(move |_| {
            if let Some(ref mut c) = *config {
                c.webhook_enabled = !c.webhook_enabled;
                config.set(Some(c.clone()));
            }
        })
    };

    html! {
        <div class="space-y-6">
            <div class="flex justify-between items-center">
                <h1 class="text-2xl font-bold">{ "Alerting" }</h1>
                <button 
                    onclick={on_save}
                    disabled={*saving}
                    class="px-4 py-2 bg-accent text-[#0a0a0f] rounded-lg hover:opacity-80 disabled:opacity-50"
                >
                    { if *saving { "Saving..." } else { "Save Changes" } }
                </button>
            </div>

            if let Some(err) = &*error {
                <div class="bg-red-500/10 border border-red-500 rounded-lg p-4 text-red-500">
                    { err }
                </div>
            }

            if let Some(c) = &*config {
                <div class="bg-secondary rounded-lg border border-default p-6">
                    <div class="flex items-center justify-between mb-4">
                        <h2 class="text-lg font-semibold">{ "Alert System" }</h2>
                        <button 
                            onclick={toggle_config}
                            class={format!("px-4 py-2 rounded-lg text-sm font-medium {}", if c.enabled { "bg-green-600 text-white" } else { "bg-tertiary text-secondary" })}
                        >
                            { if c.enabled { "Enabled" } else { "Disabled" } }
                        </button>
                    </div>
                    <p class="text-secondary text-sm">
                        { "Configure email and webhook notifications for security alerts, system errors, and performance thresholds." }
                    </p>
                </div>

                <div class="grid grid-cols-1 lg:grid-cols-2 gap-6">
                    <div class="bg-secondary rounded-lg border border-default p-6">
                        <div class="flex items-center justify-between mb-4">
                            <h2 class="text-lg font-semibold">{ "Email Notifications" }</h2>
                            <button 
                                onclick={toggle_email}
                                class={format!("px-3 py-1 rounded text-sm font-medium {}", if c.email_enabled { "bg-green-600 text-white" } else { "bg-tertiary text-secondary" })}
                            >
                                { if c.email_enabled { "Enabled" } else { "Disabled" } }
                            </button>
                        </div>
                        
                        if c.email_enabled {
                            <div class="space-y-4">
                                <div>
                                    <label class="block text-sm text-secondary mb-1">{ "SMTP Host" }</label>
                                    <input 
                                        type="text" 
                                        value={c.email_smtp_host.clone().unwrap_or_default()}
                                        oninput={Callback::from(move |e: InputEvent| {
                                            if let Some(ref mut c) = *config {
                                                c.email_smtp_host = Some(e.target_unchecked_into::<web_sys::HtmlInputElement>().value());
                                                config.set(Some(c.clone()));
                                            }
                                        })}
                                        class="w-full px-3 py-2 bg-tertiary border border-default rounded-lg text-primary"
                                        placeholder="smtp.example.com"
                                    />
                                </div>
                                <div>
                                    <label class="block text-sm text-secondary mb-1">{ "SMTP Port" }</label>
                                    <input 
                                        type="number" 
                                        value={c.email_smtp_port.unwrap_or(587).to_string()}
                                        oninput={Callback::from(move |e: InputEvent| {
                                            if let Some(ref mut c) = *config {
                                                c.email_smtp_port = e.target_unchecked_into::<web_sys::HtmlInputElement>().value().parse().ok();
                                                config.set(Some(c.clone()));
                                            }
                                        })}
                                        class="w-full px-3 py-2 bg-tertiary border border-default rounded-lg text-primary"
                                        placeholder="587"
                                    />
                                </div>
                                <div>
                                    <label class="block text-sm text-secondary mb-1">{ "Username" }</label>
                                    <input 
                                        type="text" 
                                        value={c.email_username.clone().unwrap_or_default()}
                                        oninput={Callback::from(move |e: InputEvent| {
                                            if let Some(ref mut c) = *config {
                                                c.email_username = Some(e.target_unchecked_into::<web_sys::HtmlInputElement>().value());
                                                config.set(Some(c.clone()));
                                            }
                                        })}
                                        class="w-full px-3 py-2 bg-tertiary border border-default rounded-lg text-primary"
                                        placeholder="alerts@example.com"
                                    />
                                </div>
                                <div>
                                    <label class="block text-sm text-secondary mb-1">{ "Password" }</label>
                                    <input 
                                        type="password" 
                                        value={c.email_password.clone().unwrap_or_default()}
                                        oninput={Callback::from(move |e: InputEvent| {
                                            if let Some(ref mut c) = *config {
                                                c.email_password = Some(e.target_unchecked_into::<web_sys::HtmlInputElement>().value());
                                                config.set(Some(c.clone()));
                                            }
                                        })}
                                        class="w-full px-3 py-2 bg-tertiary border border-default rounded-lg text-primary"
                                        placeholder="••••••••"
                                    />
                                </div>
                                <div>
                                    <label class="block text-sm text-secondary mb-1">{ "Recipients (comma separated)" }</label>
                                    <input 
                                        type="text" 
                                        value={c.email_recipients.join(", ")}
                                        oninput={Callback::from(move |e: InputEvent| {
                                            if let Some(ref mut c) = *config {
                                                c.email_recipients = e.target_unchecked_into::<web_sys::HtmlInputElement>()
                                                    .value()
                                                    .split(',')
                                                    .map(|s| s.trim().to_string())
                                                    .filter(|s| !s.is_empty())
                                                    .collect();
                                                config.set(Some(c.clone()));
                                            }
                                        })}
                                        class="w-full px-3 py-2 bg-tertiary border border-default rounded-lg text-primary"
                                        placeholder="admin@example.com, security@example.com"
                                    />
                                </div>
                            </div>
                        }
                    </div>

                    <div class="bg-secondary rounded-lg border border-default p-6">
                        <div class="flex items-center justify-between mb-4">
                            <h2 class="text-lg font-semibold">{ "Webhook Notifications" }</h2>
                            <button 
                                onclick={toggle_webhook}
                                class={format!("px-3 py-1 rounded text-sm font-medium {}", if c.webhook_enabled { "bg-green-600 text-white" } else { "bg-tertiary text-secondary" })}
                            >
                                { if c.webhook_enabled { "Enabled" } else { "Disabled" } }
                            </button>
                        </div>
                        
                        if c.webhook_enabled {
                            <div class="space-y-4">
                                <div>
                                    <label class="block text-sm text-secondary mb-1">{ "Webhook URLs (one per line)" }</label>
                                    <textarea 
                                        value={c.webhook_urls.join("\n")}
                                        oninput={Callback::from(move |e: InputEvent| {
                                            if let Some(ref mut c) = *config {
                                                c.webhook_urls = e.target_unchecked_into::<web_sys::HtmlTextAreaElement>()
                                                    .value()
                                                    .lines()
                                                    .map(|s| s.trim().to_string())
                                                    .filter(|s| !s.is_empty())
                                                    .collect();
                                                config.set(Some(c.clone()));
                                            }
                                        })}
                                        class="w-full px-3 py-2 bg-tertiary border border-default rounded-lg text-primary h-24"
                                        placeholder="https://hooks.slack.com/services/...\nhttps://your-server.com/webhook"
                                    />
                                </div>
                                <button 
                                    onclick={on_test_webhook}
                                    class="px-4 py-2 bg-tertiary text-secondary rounded-lg hover:text-primary"
                                >
                                    { "Test Webhook" }
                                </button>
                            </div>
                        }
                    </div>
                </div>

                <div class="bg-secondary rounded-lg border border-default p-6 mt-6">
                    <h2 class="text-lg font-semibold mb-4">{ "Alert Rules" }</h2>
                    <div class="space-y-3">
                        { for c.alerts.iter().map(|rule| {
                            let rule_name = rule.name.clone();
                            html! {
                                <div class="flex items-center justify-between p-4 bg-tertiary rounded-lg">
                                    <div class="flex items-center gap-4">
                                        <input 
                                            type="checkbox" 
                                            checked={rule.enabled}
                                            onchange={Callback::from(move |_| {
                                                if let Some(ref mut c) = *config {
                                                    for r in &mut c.alerts {
                                                        if r.name == rule_name {
                                                            r.enabled = !r.enabled;
                                                        }
                                                    }
                                                    config.set(Some(c.clone()));
                                                }
                                            })}
                                            class="w-4 h-4"
                                        />
                                        <div>
                                            <p class="text-primary font-medium">{ &rule.name }</p>
                                            <p class="text-sm text-secondary">{ format!("{} {} {}", rule.metric, rule.condition, rule.threshold) }</p>
                                        </div>
                                    </div>
                                </div>
                            }
                        })}
                    </div>
                </div>
            } else {
                <div class="animate-pulse">
                    <div class="h-4 bg-tertiary rounded w-3/4 mb-2"></div>
                    <div class="h-4 bg-tertiary rounded w-1/2"></div>
                </div>
            }
        </div>
    }
}
