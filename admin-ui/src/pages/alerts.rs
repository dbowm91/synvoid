use crate::components::{toast_error, toast_success};
use crate::services::api::ApiService;
use serde::{Deserialize, Serialize};
use yew::prelude::*;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AlertConfig {
    pub enabled: bool,
    pub webhook_enabled: bool,
    pub webhook_urls: Vec<String>,
    pub cooldown_secs: u64,
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

#[derive(Debug, Clone, Serialize, Deserialize)]
struct WebhookTestResult {
    outcome: String,
    attempted: usize,
    succeeded: usize,
    failed: usize,
    details: Vec<WebhookTestDetail>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct WebhookTestDetail {
    url: String,
    success: bool,
    error: Option<String>,
}

#[function_component]
pub fn Alerts() -> Html {
    let config = use_state(|| None as Option<AlertConfig>);
    let error = use_state(|| None as Option<String>);
    let saving = use_state(|| false);
    let testing = use_state(|| false);
    let test_result = use_state(|| None as Option<WebhookTestResult>);

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
                    Err(e) => error.set(Some(e.to_string())),
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
                    struct UpdateRequest {
                        config: AlertConfig,
                    }

                    match api
                        .put::<AlertConfigResponse, _>(
                            "/alerts/config",
                            &UpdateRequest { config: c },
                        )
                        .await
                    {
                        Ok(resp) => {
                            config.set(Some(resp.config));
                            toast_success("Alert configuration saved");
                        }
                        Err(e) => {
                            error.set(Some(e.to_string()));
                            toast_error(&format!("Failed to save: {}", e));
                        }
                    }
                    saving.set(false);
                });
            }
        })
    };

    let on_test_webhook = {
        let error = error.clone();
        let testing = testing.clone();
        let test_result = test_result.clone();

        Callback::from(move |_| {
            let error = error.clone();
            let testing = testing.clone();
            let test_result = test_result.clone();

            testing.set(true);
            test_result.set(None);

            wasm_bindgen_futures::spawn_local(async move {
                let api = ApiService::new();

                match api
                    .post::<WebhookTestResult, _>("/alerts/test-webhook", &())
                    .await
                {
                    Ok(result) => {
                        match result.outcome.as_str() {
                            "Success" => {
                                toast_success(&format!(
                                    "Webhook test passed: {}/{} delivered",
                                    result.succeeded, result.attempted
                                ));
                            }
                            "PartialFailure" => {
                                toast_error(&format!(
                                    "Partial failure: {}/{} succeeded, {} failed",
                                    result.succeeded, result.attempted, result.failed
                                ));
                            }
                            "Failure" => {
                                let errors: Vec<String> = result
                                    .details
                                    .iter()
                                    .filter(|d| !d.success)
                                    .filter_map(|d| d.error.clone())
                                    .collect();
                                let msg = if errors.is_empty() {
                                    "All destinations failed".to_string()
                                } else {
                                    errors.join("; ")
                                };
                                toast_error(&format!("Webhook test failed: {}", msg));
                            }
                            _ => {
                                toast_error("Webhook test returned unknown result");
                            }
                        }
                        test_result.set(Some(result));
                    }
                    Err(e) => {
                        error.set(Some(e.to_string()));
                        toast_error(&format!("Webhook test error: {}", e));
                    }
                }
                testing.set(false);
            });
        })
    };

    let toggle_config = {
        let config = config.clone();
        Callback::from(move |_| {
            let config = config.clone();
            if let Some(c) = (*config).clone() {
                let mut new_config = c;
                new_config.enabled = !new_config.enabled;
                config.set(Some(new_config));
            }
        })
    };

    let toggle_webhook = {
        let config = config.clone();
        Callback::from(move |_| {
            let config = config.clone();
            if let Some(c) = (*config).clone() {
                let mut new_config = c;
                new_config.webhook_enabled = !new_config.webhook_enabled;
                config.set(Some(new_config));
            }
        })
    };

    let on_webhook_urls_change = {
        let config = config.clone();
        Callback::from(move |value: String| {
            let config = config.clone();
            if let Some(c) = (*config).clone() {
                let mut new_config = c;
                new_config.webhook_urls = value
                    .lines()
                    .map(|s| s.trim().to_string())
                    .filter(|s| !s.is_empty())
                    .collect();
                config.set(Some(new_config));
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
                        { "Configure webhook notifications for security alerts, system errors, and performance thresholds." }
                    </p>
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
                                        let value = e.target_unchecked_into::<web_sys::HtmlTextAreaElement>().value();
                                        on_webhook_urls_change.emit(value);
                                    })}
                                    class="w-full px-3 py-2 bg-tertiary border border-default rounded-lg text-primary h-24"
                                    placeholder="https://hooks.slack.com/services/...\nhttps://your-server.com/webhook"
                                />
                            </div>
                            <div class="flex items-center gap-3">
                                <button
                                    onclick={on_test_webhook}
                                    disabled={*testing}
                                    class="px-4 py-2 bg-tertiary text-secondary rounded-lg hover:text-primary disabled:opacity-50"
                                >
                                    { if *testing { "Testing..." } else { "Test Webhook" } }
                                </button>
                            </div>

                            if let Some(result) = &*test_result {
                                <div class={format!(
                                    "p-4 rounded-lg border {}",
                                    match result.outcome.as_str() {
                                        "Success" => "bg-green-500/10 border-green-500",
                                        "PartialFailure" => "bg-yellow-500/10 border-yellow-500",
                                        _ => "bg-red-500/10 border-red-500",
                                    }
                                )}>
                                    <div class="flex items-center gap-2 mb-2">
                                        <span class={format!(
                                            "px-2 py-0.5 rounded text-xs font-medium {}",
                                            match result.outcome.as_str() {
                                                "Success" => "bg-green-600 text-white",
                                                "PartialFailure" => "bg-yellow-600 text-white",
                                                _ => "bg-red-600 text-white",
                                            }
                                        )}>
                                            { &result.outcome }
                                        </span>
                                        <span class="text-sm text-secondary">
                                            { format!("{} attempted, {} succeeded, {} failed", result.attempted, result.succeeded, result.failed) }
                                        </span>
                                    </div>
                                    if !result.details.is_empty() {
                                        <div class="space-y-1 mt-2">
                                            { for result.details.iter().map(|d| {
                                                let status_class = if d.success { "text-green-500" } else { "text-red-500" };
                                                let status_icon = if d.success { "\u{2713}" } else { "\u{2717}" };
                                                html! {
                                                    <div class="flex items-center gap-2 text-sm">
                                                        <span class={status_class}>{ status_icon }</span>
                                                        <span class="text-primary truncate">{ &d.url }</span>
                                                        if let Some(err) = &d.error {
                                                            <span class="text-red-400 text-xs">{ format!("({})", err) }</span>
                                                        }
                                                    </div>
                                                }
                                            })}
                                        </div>
                                    }
                                </div>
                            }
                        </div>
                    }
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
                                            onchange={{
                                                let config = config.clone();
                            let _rule_name = rule.name.clone();
                                                Callback::from(move |_| {
                                                    let config = config.clone();
                                                    if let Some(c) = (*config).clone() {
                                                        let mut new_config = c;
                                                        for r in &mut new_config.alerts {
                                                            if r.name == rule_name {
                                                                r.enabled = !r.enabled;
                                                            }
                                                        }
                                                        config.set(Some(new_config));
                                                    }
                                                })
                                            }}
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
