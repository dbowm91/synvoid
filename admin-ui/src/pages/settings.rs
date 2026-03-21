use crate::components::forms::{Input, Select};
use crate::components::{toast_error, toast_success};
use crate::services::ApiService;
use crate::types::{ThemeResponse, UpdateThemeRequest};
use wasm_bindgen::JsCast;
use yew::prelude::*;

#[function_component]
pub fn Settings() -> Html {
    let active_section = use_state(|| "server".to_string());

    let on_section_click = {
        let active_section = active_section.clone();
        Callback::from(move |section: String| {
            active_section.set(section);
        })
    };

    html! {
        <div>
            <h1 class="text-2xl font-bold mb-6">{ "Global Settings" }</h1>

            <div class="flex gap-6">
                <nav class="w-48 flex-shrink-0">
                    <div class="bg-secondary rounded-lg border border-default">
                        <SectionButton label="Server" section="server" active={*active_section == "server"} on_click={on_section_click.clone()} />
                        <SectionButton label="HTTP" section="http" active={*active_section == "http"} on_click={on_section_click.clone()} />
                        <SectionButton label="Logging" section="logging" active={*active_section == "logging"} on_click={on_section_click.clone()} />
                        <SectionButton label="Metrics" section="metrics" active={*active_section == "metrics"} on_click={on_section_click.clone()} />
                        <SectionButton label="Rate Limits" section="ratelimits" active={*active_section == "ratelimits"} on_click={on_section_click.clone()} />
                        <SectionButton label="Bandwidth" section="bandwidth" active={*active_section == "bandwidth"} on_click={on_section_click.clone()} />
                        <SectionButton label="Bot Defaults" section="bot" active={*active_section == "bot"} on_click={on_section_click.clone()} />
                        <SectionButton label="Upload" section="upload" active={*active_section == "upload"} on_click={on_section_click.clone()} />
                        <SectionButton label="Theme" section="theme" active={*active_section == "theme"} on_click={on_section_click.clone()} />
                    </div>
                </nav>

                <div class="flex-1 bg-secondary rounded-lg border border-default">
                    <div class="p-6 border-b border-default">
                        <h2 class="text-lg font-semibold">
                        { match active_section.as_str() {
                            "server" => "Server Configuration",
                            "http" => "HTTP Settings",
                            "logging" => "Logging Configuration",
                            "metrics" => "Metrics Configuration",
                            "ratelimits" => "Rate Limit Defaults",
                            "bandwidth" => "Bandwidth Limits",
                            "bot" => "Bot Protection Defaults",
                            "upload" => "Upload Defaults",
                            "theme" => "Theme Configuration",
                            _ => "Server Configuration",
                        }}
                        </h2>
                    </div>

                    <div class="p-6">
                        { match active_section.as_str() {
                            "server" => html! { <ServerSection /> },
                            "http" => html! { <HttpSection /> },
                            "logging" => html! { <LoggingSection /> },
                            "metrics" => html! { <MetricsSection /> },
                            "ratelimits" => html! { <RateLimitsSection /> },
                            "bandwidth" => html! { <BandwidthSection /> },
                            "bot" => html! { <BotSection /> },
                            "upload" => html! { <UploadSection /> },
                            "theme" => html! { <ThemeSection /> },
                            _ => html! { <ServerSection /> },
                        }}
                    </div>

                    <div class="p-4 border-t border-default flex justify-end gap-4">
                        <button class="px-4 py-2 bg-tertiary text-primary rounded-lg hover:opacity-80">
                            { "Reset" }
                        </button>
                        <button class="px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700">
                            { "Save Changes" }
                        </button>
                    </div>
                </div>
            </div>
        </div>
    }
}

#[derive(Properties, PartialEq)]
struct SectionButtonProps {
    label: String,
    section: String,
    active: bool,
    on_click: Callback<String>,
}

#[function_component]
fn SectionButton(props: &SectionButtonProps) -> Html {
    let onclick = {
        let section = props.section.clone();
        let on_click = props.on_click.clone();
        Callback::from(move |_| {
            on_click.emit(section.clone());
        })
    };

    let class = if props.active {
        "block w-full text-left px-4 py-3 text-primary bg-tertiary border-l-2 border-blue-500"
    } else {
        "block w-full text-left px-4 py-3 text-secondary hover:text-primary hover:bg-tertiary"
    };

    html! {
        <button onclick={onclick} class={class}>
            { &props.label }
        </button>
    }
}

#[function_component]
fn ServerSection() -> Html {
    html! {
        <div class="space-y-6">
            <div class="grid grid-cols-2 gap-4">
                <Input
                    label="Listen Host"
                    name="host"
                    value="0.0.0.0"
                    help="IP address to bind the main server to"
                />
                <Input
                    label="Listen Port"
                    name="port"
                    input_type="number"
                    value="8080"
                    help="TCP port for the main HTTP server"
                />
            </div>

            <div>
                <Input
                    label="Trusted Proxies"
                    name="trusted_proxies"
                    value="127.0.0.1, ::1"
                    help="Comma-separated list of trusted proxy IPs for X-Forwarded-For handling"
                />
            </div>

            <div>
                <Select
                    label="Worker Threads"
                    name="worker_threads"
                    value="auto"
                    options={vec![
                        ("auto".to_string(), "Auto (match CPU cores)".to_string()),
                        ("1".to_string(), "1 thread".to_string()),
                        ("2".to_string(), "2 threads".to_string()),
                        ("4".to_string(), "4 threads".to_string()),
                        ("8".to_string(), "8 threads".to_string()),
                    ]}
                    help="Number of Tokio worker threads"
                />
            </div>
        </div>
    }
}

#[function_component]
fn HttpSection() -> Html {
    html! {
        <div class="space-y-6">
            <div class="grid grid-cols-2 gap-4">
                <Input
                    label="Header Read Timeout (secs)"
                    name="header_read_timeout"
                    input_type="number"
                    value="10"
                />
                <Input
                    label="Keep-Alive Timeout (secs)"
                    name="keep_alive_timeout"
                    input_type="number"
                    value="60"
                />
            </div>

            <div class="grid grid-cols-2 gap-4">
                <Input
                    label="Max Headers"
                    name="max_headers"
                    input_type="number"
                    value="128"
                />
                <Input
                    label="Max Request Size"
                    name="max_request_size"
                    value="1MB"
                    help="Maximum request body size"
                />
            </div>

            <div class="grid grid-cols-2 gap-4">
                <Input
                    label="Max Header Size (Ingress)"
                    name="max_header_size_ingress"
                    value="4KB"
                />
                <Input
                    label="Max Header Size (Egress)"
                    name="max_header_size_egress"
                    value="16KB"
                />
            </div>
        </div>
    }
}

#[function_component]
fn LoggingSection() -> Html {
    html! {
        <div class="space-y-6">
            <Select
                label="Log Level"
                name="log_level"
                value="info"
                options={vec![
                    ("trace".to_string(), "Trace".to_string()),
                    ("debug".to_string(), "Debug".to_string()),
                    ("info".to_string(), "Info".to_string()),
                    ("warn".to_string(), "Warning".to_string()),
                    ("error".to_string(), "Error".to_string()),
                ]}
                help="Minimum log level to record"
            />

            <div class="grid grid-cols-2 gap-4">
                <Select
                    label="Access Log Format"
                    name="access_log_format"
                    value="json"
                    options={vec![
                        ("json".to_string(), "JSON".to_string()),
                        ("text".to_string(), "Plain Text".to_string()),
                    ]}
                />
                <Input
                    label="Access Log Directory"
                    name="access_log_dir"
                    value="/var/log/rustwaf"
                />
            </div>

            <div class="grid grid-cols-2 gap-4">
                <Input
                    label="Retention Days"
                    name="retention_days"
                    input_type="number"
                    value="5"
                />
                <Input
                    label="Max Entries Per File"
                    name="max_entries_per_file"
                    input_type="number"
                    value="50000"
                />
            </div>
        </div>
    }
}

#[function_component]
fn MetricsSection() -> Html {
    html! {
        <div class="space-y-6">
            <div class="flex items-center justify-between py-2">
                <div>
                    <p class="text-primary font-medium">{ "Enable Metrics" }</p>
                    <p class="text-sm text-secondary">{ "Expose Prometheus metrics endpoint" }</p>
                </div>
                <button class="relative w-10 h-6 bg-blue-600 rounded-full">
                    <span class="absolute top-1 left-1 w-4 h-4 bg-white rounded-full translate-x-5" />
                </button>
            </div>

            <Input
                label="Metrics Port"
                name="metrics_port"
                input_type="number"
                value="9090"
                help="Port for Prometheus metrics endpoint"
            />
        </div>
    }
}

#[function_component]
fn RateLimitsSection() -> Html {
    html! {
        <div class="space-y-6">
            <h3 class="font-semibold text-primary">{ "Per-IP Defaults" }</h3>
            <div class="grid grid-cols-3 gap-4">
                <Input label="Per Second" name="ip_per_second" input_type="number" value="10" />
                <Input label="Per Minute" name="ip_per_minute" input_type="number" value="60" />
                <Input label="Per 5 Min" name="ip_per_5min" input_type="number" value="200" />
                <Input label="Per Hour" name="ip_per_hour" input_type="number" value="500" />
                <Input label="Per Day" name="ip_per_day" input_type="number" value="1000" />
                <Input label="Burst" name="ip_burst" input_type="number" value="20" />
            </div>

            <h3 class="font-semibold text-primary mt-6">{ "Global Defaults" }</h3>
            <div class="grid grid-cols-3 gap-4">
                <Input label="Per Second" name="global_per_second" input_type="number" value="500" />
                <Input label="Per Minute" name="global_per_minute" input_type="number" value="5000" />
                <Input label="Max Connections" name="max_connections" input_type="number" value="1000" />
            </div>
        </div>
    }
}

#[function_component]
fn BandwidthSection() -> Html {
    html! {
        <div class="space-y-6">
            <h3 class="font-semibold text-primary">{ "Monthly Limits" }</h3>
            <div class="grid grid-cols-2 gap-4">
                <Input
                    label="Monthly Ingress Cap (GB)"
                    name="monthly_cap_ingress_gb"
                    input_type="number"
                    value="0"
                    help="Set to 0 for unlimited. For example: 5000 for 5TB"
                />
                <Input
                    label="Monthly Egress Cap (GB)"
                    name="monthly_cap_egress_gb"
                    input_type="number"
                    value="0"
                    help="Set to 0 for unlimited. For example: 5000 for 5TB"
                />
            </div>

            <div class="flex items-center justify-between py-3 border-b border-default">
                <div>
                    <p class="text-primary font-medium">{ "Action on Limit Exceeded" }</p>
                    <p class="text-sm text-secondary">{ "What to do when monthly bandwidth cap is reached" }</p>
                </div>
                <select class="bg-tertiary text-primary px-3 py-2 rounded-lg border border-default">
                    <option value="block">{ "Hard Block (503)" }</option>
                    <option value="throttle">{ "Throttle to Monthly Rate" }</option>
                </select>
            </div>

            <h3 class="font-semibold text-primary mt-6">{ "Reset Configuration" }</h3>
            <div class="flex items-center justify-between py-3 border-b border-default">
                <div>
                    <p class="text-primary font-medium">{ "Reset Mode" }</p>
                    <p class="text-sm text-secondary">{ "How to determine the billing period" }</p>
                </div>
                <select class="bg-tertiary text-primary px-3 py-2 rounded-lg border border-default">
                    <option value="rolling_30_days">{ "Rolling 30 Days" }</option>
                    <option value="calendar_month">{ "Calendar Month (1st of each month)" }</option>
                    <option value="fixed_date">{ "Fixed Day of Month" }</option>
                </select>
            </div>

            <Input
                label="Fixed Day of Month (1-28)"
                name="fixed_day"
                input_type="number"
                value=""
                help="Day of month to reset bandwidth counters (only for Fixed Date mode)"
            />

            <h3 class="font-semibold text-primary mt-6">{ "Data Persistence" }</h3>
            <Input
                label="Data Directory"
                name="bandwidth_data_dir"
                value="/var/lib/maluwaf"
                help="Directory to store bandwidth counter persistence file"
            />
        </div>
    }
}

#[function_component]
fn BotSection() -> Html {
    html! {
        <div class="space-y-6">
            <div class="flex items-center justify-between py-2">
                <div>
                    <p class="text-primary font-medium">{ "Block AI Crawlers" }</p>
                    <p class="text-sm text-secondary">{ "Block known AI/ML web crawlers" }</p>
                </div>
                <button class="relative w-10 h-6 bg-blue-600 rounded-full">
                    <span class="absolute top-1 left-1 w-4 h-4 bg-white rounded-full translate-x-5" />
                </button>
            </div>

            <div class="flex items-center justify-between py-2">
                <div>
                    <p class="text-primary font-medium">{ "Enable CSS Honeypot" }</p>
                    <p class="text-sm text-secondary">{ "Use CSS-based bot detection" }</p>
                </div>
                <button class="relative w-10 h-6 bg-blue-600 rounded-full">
                    <span class="absolute top-1 left-1 w-4 h-4 bg-white rounded-full translate-x-5" />
                </button>
            </div>

            <div class="flex items-center justify-between py-2">
                <div>
                    <p class="text-primary font-medium">{ "Enable PoW Challenge" }</p>
                    <p class="text-sm text-secondary">{ "Use Proof-of-Work challenges" }</p>
                </div>
                <button class="relative w-10 h-6 bg-blue-600 rounded-full">
                    <span class="absolute top-1 left-1 w-4 h-4 bg-white rounded-full translate-x-5" />
                </button>
            </div>

            <Input
                label="PoW Difficulty"
                name="pow_difficulty"
                input_type="number"
                value="6"
                help="Higher values = harder challenges (1-10)"
            />
        </div>
    }
}

#[function_component]
fn UploadSection() -> Html {
    html! {
        <div class="space-y-6">
            <div class="grid grid-cols-2 gap-4">
                <Input
                    label="Max Upload Size"
                    name="upload_max_size"
                    value="100MB"
                />
                <Input
                    label="Memory Threshold"
                    name="upload_memory_threshold"
                    value="10MB"
                    help="Files under this threshold are scanned in-memory"
                />
            </div>

            <div class="flex items-center justify-between py-2">
                <div>
                    <p class="text-primary font-medium">{ "Scan with YARA" }</p>
                    <p class="text-sm text-secondary">{ "Scan uploads for malware signatures" }</p>
                </div>
                <button class="relative w-10 h-6 bg-blue-600 rounded-full">
                    <span class="absolute top-1 left-1 w-4 h-4 bg-white rounded-full translate-x-5" />
                </button>
            </div>

            <div class="flex items-center justify-between py-2">
                <div>
                    <p class="text-primary font-medium">{ "Sandbox Files" }</p>
                    <p class="text-sm text-secondary">{ "Isolate uploads before forwarding" }</p>
                </div>
                <button class="relative w-10 h-6 bg-blue-600 rounded-full">
                    <span class="absolute top-1 left-1 w-4 h-4 bg-white rounded-full translate-x-5" />
                </button>
            </div>
        </div>
    }
}

#[function_component]
fn ThemeSection() -> Html {
    let theme_data = use_state(|| None::<ThemeResponse>);
    let selected_preset = use_state(|| "default".to_string());
    let selected_mode = use_state(|| "auto".to_string());
    let preview_html = use_state(|| String::new());
    let preview_light = use_state(|| false);
    let saving = use_state(|| false);

    use_effect_with((), {
        let theme_data = theme_data.clone();
        let selected_preset = selected_preset.clone();
        let selected_mode = selected_mode.clone();
        let preview_html = preview_html.clone();
        let preview_light = preview_light.clone();
        move |_| {
            wasm_bindgen_futures::spawn_local(async move {
                let api = ApiService::new();
                let theme_result = api.get_theme().await;
                let css_result = api.get_theme_css().await;
                let use_light = *preview_light;

                if let Ok(data) = theme_result {
                    theme_data.set(Some(data.clone()));
                    selected_preset.set(data.preset.clone());
                    selected_mode.set(data.mode.clone());

                    if let Ok(css) = css_result {
                        let html = generate_preview_html(&css, &data.colors, use_light);
                        preview_html.set(html);
                    }
                }
            });
            || {}
        }
    });

    let on_preset_change = {
        let selected_preset = selected_preset.clone();
        let preview_html = preview_html.clone();
        let theme_data = theme_data.clone();
        let preview_light = preview_light.clone();
        Callback::from(move |e: Event| {
            let target = e.target().unwrap();
            let value = target
                .dyn_ref::<web_sys::HtmlSelectElement>()
                .map(|el| el.value())
                .unwrap_or_default();
            selected_preset.set(value.clone());

            if let Some(ref data) = *theme_data {
                let colors = get_preset_colors(&value);
                let use_light = *preview_light;
                let html = generate_preview_html("", &colors, use_light);
                preview_html.set(html);
            }
        })
    };

    let on_mode_change = {
        let selected_mode = selected_mode.clone();
        Callback::from(move |e: Event| {
            let target = e.target().unwrap();
            let value = target
                .dyn_ref::<web_sys::HtmlSelectElement>()
                .map(|el| el.value())
                .unwrap_or_default();
            selected_mode.set(value);
        })
    };

    let on_toggle_preview = {
        let preview_light = preview_light.clone();
        let selected_preset = selected_preset.clone();
        let theme_data = theme_data.clone();
        let preview_html = preview_html.clone();
        Callback::from(move |_| {
            let new_value = !*preview_light;
            preview_light.set(new_value);

            if let Some(ref data) = *theme_data {
                let colors = get_preset_colors(&selected_preset);
                let html = generate_preview_html("", &colors, new_value);
                preview_html.set(html);
            }
        })
    };

    let on_save = {
        let saving = saving.clone();
        let selected_preset = selected_preset.clone();
        let selected_mode = selected_mode.clone();
        let theme_data = theme_data.clone();
        let preview_html = preview_html.clone();
        let preview_light = preview_light.clone();
        Callback::from(move |_| {
            let preset = (*selected_preset).clone();
            let mode = (*selected_mode).clone();
            let theme_data = theme_data.clone();
            let preview_html = preview_html.clone();
            let preview_light = *preview_light;
            let saving = saving.clone();

            saving.set(true);

            wasm_bindgen_futures::spawn_local(async move {
                let api = ApiService::new();
                let request = UpdateThemeRequest {
                    preset: Some(preset),
                    mode: Some(mode),
                    allow_only: None,
                };

                match api.update_theme(&request).await {
                    Ok(data) => {
                        theme_data.set(Some(data.clone()));
                        toast_success("Theme updated successfully");

                        match api.get_theme_css().await {
                            Ok(css) => {
                                let html = generate_preview_html(&css, &data.colors, preview_light);
                                preview_html.set(html);
                            }
                            Err(e) => {
                                tracing::error!("Failed to fetch theme CSS: {}", e);
                            }
                        }
                    }
                    Err(e) => {
                        toast_error(&format!("Failed to update theme: {}", e));
                        tracing::error!("Failed to update theme: {}", e);
                    }
                }
                saving.set(false);
            });
        })
    };

    let on_reset = {
        let selected_preset = selected_preset.clone();
        let selected_mode = selected_mode.clone();
        let theme_data = theme_data.clone();
        let preview_html = preview_html.clone();
        let preview_light = preview_light.clone();
        Callback::from(move |_| {
            selected_preset.set("default".to_string());
            selected_mode.set("auto".to_string());

            if let Some(ref data) = *theme_data {
                let colors = get_preset_colors("default");
                let use_light = *preview_light;
                let html = generate_preview_html("", &colors, use_light);
                preview_html.set(html);
            }

            let request = UpdateThemeRequest {
                preset: Some("default".to_string()),
                mode: Some("auto".to_string()),
                allow_only: None,
            };

            let theme_data = theme_data.clone();
            wasm_bindgen_futures::spawn_local(async move {
                let api = ApiService::new();
                match api.update_theme(&request).await {
                    Ok(data) => {
                        theme_data.set(Some(data.clone()));
                        toast_success("Theme reset to default");
                    }
                    Err(e) => {
                        toast_error(&format!("Failed to reset theme: {}", e));
                    }
                }
            });
        })
    };

    let presets = vec![
        ("default", "Default"),
        ("dark", "Dark"),
        ("light", "Light"),
        ("ocean", "Ocean"),
        ("forest", "Forest"),
        ("sunset", "Sunset"),
    ];

    let modes = vec![
        ("auto", "Auto (System)"),
        ("dark", "Dark"),
        ("light", "Light"),
    ];

    html! {
        <div class="space-y-6">
            <div>
                <label class="block text-sm font-medium text-primary mb-2">{ "Theme Preset" }</label>
                <select
                    class="w-full px-3 py-2 bg-tertiary border border-default rounded-lg text-primary"
                    value={(*selected_preset).clone()}
                    onchange={on_preset_change}
                >
                    { for presets.iter().map(|(value, label)| {
                        html! {
                            <option value={value.clone()}>{label.clone()}</option>
                        }
                    }) }
                </select>
                <p class="mt-1 text-sm text-secondary">{ "Choose a color scheme for the admin interface" }</p>
            </div>

            <div>
                <label class="block text-sm font-medium text-primary mb-2">{ "Theme Mode" }</label>
                <select
                    class="w-full px-3 py-2 bg-tertiary border border-default rounded-lg text-primary"
                    value={(*selected_mode).clone()}
                    onchange={on_mode_change}
                >
                    { for modes.iter().map(|(value, label)| {
                        html! {
                            <option value={value.clone()}>{label.clone()}</option>
                        }
                    }) }
                </select>
                <p class="mt-1 text-sm text-secondary">{ "How users can switch between light and dark themes" }</p>
            </div>

            <div>
                <div class="flex items-center justify-between mb-2">
                    <label class="block text-sm font-medium text-primary">{ "Preview" }</label>
                    <button
                        onclick={on_toggle_preview}
                        class="px-3 py-1 text-sm bg-tertiary border border-default rounded-lg text-primary hover:opacity-80"
                    >
                        { if *preview_light { "🌙 Dark" } else { "☀️ Light" } }
                    </button>
                </div>
                <div class="border border-default rounded-lg overflow-hidden">
                    <iframe
                        srcdoc={(*preview_html).clone()}
                        class="w-full h-64"
                        sandbox="allow-same-origin"
                    />
                </div>
                <p class="mt-1 text-sm text-secondary">{ "Sample error page preview with current theme" }</p>
            </div>

            <div class="flex justify-between gap-4">
                <button
                    onclick={on_reset}
                    disabled={*saving}
                    class="px-4 py-2 bg-tertiary text-primary rounded-lg hover:opacity-80 disabled:opacity-50"
                >
                    { "Reset to Default" }
                </button>
                <button
                    onclick={on_save}
                    disabled={*saving}
                    class="px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700 disabled:opacity-50"
                >
                    { if *saving { "Saving..." } else { "Save Changes" } }
                </button>
            </div>
        </div>
    }
}

fn get_preset_colors(preset: &str) -> crate::types::ThemeColorsResponse {
    match preset {
        "light" => crate::types::ThemeColorsResponse {
            dark: crate::types::ThemeColors {
                background: "#0a0a0f".to_string(),
                surface: "#12121a".to_string(),
                primary: "#e94560".to_string(),
                text: "#f0f0f5".to_string(),
                border: "#2a2a3a".to_string(),
                accent: "#1a1a24".to_string(),
                accent_primary: "#00d4aa".to_string(),
                accent_secondary: "#00b894".to_string(),
            },
            light: crate::types::ThemeColors {
                background: "#f8fafc".to_string(),
                surface: "#ffffff".to_string(),
                primary: "#c41e3a".to_string(),
                text: "#0f172a".to_string(),
                border: "#e2e8f0".to_string(),
                accent: "#f1f5f9".to_string(),
                accent_primary: "#059669".to_string(),
                accent_secondary: "#10b981".to_string(),
            },
        },
        "ocean" => crate::types::ThemeColorsResponse {
            dark: crate::types::ThemeColors {
                background: "#0c1929".to_string(),
                surface: "#132f4c".to_string(),
                primary: "#0ea5e9".to_string(),
                text: "#e3f2fd".to_string(),
                border: "#2d4a6f".to_string(),
                accent: "#173a5e".to_string(),
                accent_primary: "#0ea5e9".to_string(),
                accent_secondary: "#38bdf8".to_string(),
            },
            light: crate::types::ThemeColors {
                background: "#e3f2fd".to_string(),
                surface: "#ffffff".to_string(),
                primary: "#0284c7".to_string(),
                text: "#0c1929".to_string(),
                border: "#90caf9".to_string(),
                accent: "#f1f5f9".to_string(),
                accent_primary: "#0ea5e9".to_string(),
                accent_secondary: "#38bdf8".to_string(),
            },
        },
        "forest" => crate::types::ThemeColorsResponse {
            dark: crate::types::ThemeColors {
                background: "#0a1a0f".to_string(),
                surface: "#132318".to_string(),
                primary: "#22c55e".to_string(),
                text: "#e8f5e9".to_string(),
                border: "#2d4a3a".to_string(),
                accent: "#1a2e21".to_string(),
                accent_primary: "#22c55e".to_string(),
                accent_secondary: "#4ade80".to_string(),
            },
            light: crate::types::ThemeColors {
                background: "#e8f5e9".to_string(),
                surface: "#ffffff".to_string(),
                primary: "#16a34a".to_string(),
                text: "#0a1a0f".to_string(),
                border: "#a5d6a7".to_string(),
                accent: "#f1f5f9".to_string(),
                accent_primary: "#22c55e".to_string(),
                accent_secondary: "#4ade80".to_string(),
            },
        },
        "sunset" => crate::types::ThemeColorsResponse {
            dark: crate::types::ThemeColors {
                background: "#1a0f0a".to_string(),
                surface: "#2a1a14".to_string(),
                primary: "#f97316".to_string(),
                text: "#fff1ec".to_string(),
                border: "#4a3028".to_string(),
                accent: "#3d261e".to_string(),
                accent_primary: "#f97316".to_string(),
                accent_secondary: "#fb923c".to_string(),
            },
            light: crate::types::ThemeColors {
                background: "#fff1ec".to_string(),
                surface: "#ffffff".to_string(),
                primary: "#ea580c".to_string(),
                text: "#1a0f0a".to_string(),
                border: "#ffccbc".to_string(),
                accent: "#f1f5f9".to_string(),
                accent_primary: "#f97316".to_string(),
                accent_secondary: "#fb923c".to_string(),
            },
        },
        _ => crate::types::ThemeColorsResponse {
            dark: crate::types::ThemeColors {
                background: "#0a0a0f".to_string(),
                surface: "#12121a".to_string(),
                primary: "#e94560".to_string(),
                text: "#f0f0f5".to_string(),
                border: "#2a2a3a".to_string(),
                accent: "#1a1a24".to_string(),
                accent_primary: "#00d4aa".to_string(),
                accent_secondary: "#00b894".to_string(),
            },
            light: crate::types::ThemeColors {
                background: "#f8fafc".to_string(),
                surface: "#ffffff".to_string(),
                primary: "#c41e3a".to_string(),
                text: "#0f172a".to_string(),
                border: "#e2e8f0".to_string(),
                accent: "#f1f5f9".to_string(),
                accent_primary: "#059669".to_string(),
                accent_secondary: "#10b981".to_string(),
            },
        },
    }
}

fn generate_preview_html(
    _css: &str,
    colors: &crate::types::ThemeColorsResponse,
    use_light: bool,
) -> String {
    let c = if use_light {
        &colors.light
    } else {
        &colors.dark
    };
    format!(
        r#"
<!DOCTYPE html>
<html>
<head>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background-color: {bg};
            color: {text};
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
        }}
        .card {{
            background: {surface};
            border: 1px solid {border};
            border-radius: 12px;
            padding: 2rem;
            max-width: 400px;
            text-align: center;
        }}
        .status {{
            font-size: 4rem;
            font-weight: bold;
            color: {primary};
            margin-bottom: 1rem;
        }}
        h1 {{
            font-size: 1.5rem;
            margin-bottom: 0.5rem;
        }}
        p {{
            color: {text};
            opacity: 0.8;
        }}
        .footer {{
            margin-top: 1.5rem;
            font-size: 0.75rem;
            opacity: 0.5;
        }}
    </style>
</head>
<body>
    <div class="card">
        <div class="status">403</div>
        <h1>Forbidden</h1>
        <p>Access to this resource has been blocked by the WAF.</p>
        <div class="footer">MaluWAF</div>
    </div>
</body>
</html>
"#,
        bg = c.background,
        surface = c.surface,
        text = c.text,
        border = c.border,
        primary = c.primary,
    )
}
