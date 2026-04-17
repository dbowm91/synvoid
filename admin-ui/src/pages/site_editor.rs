use wasm_bindgen::JsCast;
use yew::prelude::*;
use yew_router::prelude::*;

use crate::app::Route;
use crate::components::forms::Input;
use crate::components::tooltip::{HelpIcon, Tooltip, TooltipPosition};
use crate::components::{toast_error, toast_success};
use crate::services::ApiService;
use crate::types::presets::{get_presets, ServerPreset};

#[derive(Properties, PartialEq)]
pub struct SiteEditorProps {
    pub id: String,
}

#[function_component]
pub fn SiteEditor(props: &SiteEditorProps) -> Html {
    let active_tab = use_state(|| "basic".to_string());
    let selected_preset = use_state(|| Option::<ServerPreset>::None);
    let site_config = use_state(|| None::<serde_json::Value>);
    let loading = use_state(|| true);
    let saving = use_state(|| false);
    let site_id = props.id.clone();

    use_effect_with((), {
        let site_config = site_config.clone();
        let loading = loading.clone();
        let site_id = site_id.clone();
        move |_| {
            wasm_bindgen_futures::spawn_local(async move {
                let api = ApiService::new();
                let result = api.get_site(&site_id).await;
                loading.set(false);
                if let Ok(data) = result {
                    site_config.set(Some(data));
                }
            });
            || {}
        }
    });

    let on_tab_click = {
        let active_tab = active_tab.clone();
        Callback::from(move |tab: String| {
            active_tab.set(tab);
        })
    };

    let on_preset_select = {
        let selected_preset = selected_preset.clone();
        Callback::from(move |preset: ServerPreset| {
            selected_preset.set(Some(preset));
        })
    };

    let presets = get_presets();

    if *loading {
        return html! {
            <div class="text-center py-10">
                <p class="text-secondary">{ "Loading site configuration..." }</p>
            </div>
        };
    }

    let config = (*site_config).clone();

    html! {
        <div>
            <div class="flex items-center gap-4 mb-6">
                <Link<Route>
                    to={Route::Sites}
                    classes="text-secondary hover:text-primary"
                >
                    <svg class="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M15 19l-7-7 7-7" />
                    </svg>
                </Link<Route>>
                <h1 class="text-2xl font-bold">{ "Edit Site: " }{ &props.id }</h1>
            </div>

            <div class="bg-secondary rounded-lg border border-default">
                <div class="border-b border-default">
                    <nav class="flex">
                        <TabButton label="Basic" tab="basic" active={*active_tab == "basic"} on_click={on_tab_click.clone()} />
                        <TabButton label="Rate Limits" tab="ratelimit" active={*active_tab == "ratelimit"} on_click={on_tab_click.clone()} />
                        <TabButton label="Blocking" tab="blocking" active={*active_tab == "blocking"} on_click={on_tab_click.clone()} />
                        <TabButton label="Attacks" tab="attacks" active={*active_tab == "attacks"} on_click={on_tab_click.clone()} />
                        <TabButton label="Bot Protection" tab="bot" active={*active_tab == "bot"} on_click={on_tab_click.clone()} />
                        <TabButton label="Upload" tab="upload" active={*active_tab == "upload"} on_click={on_tab_click.clone()} />
                        <TabButton label="Error Pages" tab="error_pages" active={*active_tab == "error_pages"} on_click={on_tab_click.clone()} />
                        <TabButton label="Proxy" tab="proxy" active={*active_tab == "proxy"} on_click={on_tab_click.clone()} />
                        <TabButton label="Security Headers" tab="security_headers" active={*active_tab == "security_headers"} on_click={on_tab_click.clone()} />
                        <TabButton label="Static" tab="static" active={*active_tab == "static"} on_click={on_tab_click.clone()} />
                        <TabButton label="Auth" tab="auth" active={*active_tab == "auth"} on_click={on_tab_click.clone()} />
                        <TabButton label="WebSocket" tab="websocket" active={*active_tab == "websocket"} on_click={on_tab_click.clone()} />
                        <TabButton label="gRPC" tab="grpc" active={*active_tab == "grpc"} on_click={on_tab_click.clone()} />
                        <TabButton label="Tunnel" tab="tunnel" active={*active_tab == "tunnel"} on_click={on_tab_click.clone()} />
                    </nav>
                </div>

                <div class="p-6">
                    { match active_tab.as_str() {
                        "basic" => html! { <BasicTab presets={presets} on_preset_select={on_preset_select} selected_preset={(*selected_preset).clone()} config={config.clone()} site_id={props.id.clone()} /> },
                        "ratelimit" => html! { <RateLimitTab config={config.clone()} site_id={props.id.clone()} /> },
                        "blocking" => html! { <BlockingTab config={config.clone()} site_id={props.id.clone()} /> },
                        "attacks" => html! { <AttacksTab config={config.clone()} site_id={props.id.clone()} /> },
                        "bot" => html! { <BotTab config={config.clone()} site_id={props.id.clone()} /> },
                        "upload" => html! { <UploadTab config={config.clone()} site_id={props.id.clone()} /> },
                        "error_pages" => html! { <ErrorPagesTab site_id={props.id.clone()} /> },
                        "proxy" => html! { <ProxyTab config={config.clone()} site_id={props.id.clone()} /> },
                        "security_headers" => html! { <SecurityHeadersTab config={config.clone()} site_id={props.id.clone()} /> },
                        "static" => html! { <StaticTab config={config.clone()} site_id={props.id.clone()} /> },
                        "auth" => html! { <AuthTab config={config.clone()} site_id={props.id.clone()} /> },
                        "websocket" => html! { <WebSocketTab config={config.clone()} site_id={props.id.clone()} /> },
                        "grpc" => html! { <GrpcTab config={config.clone()} site_id={props.id.clone()} /> },
                        "tunnel" => html! { <TunnelTab config={config.clone()} site_id={props.id.clone()} /> },
                        _ => html! { <BasicTab presets={presets} on_preset_select={on_preset_select} selected_preset={(*selected_preset).clone()} config={config.clone()} site_id={props.id.clone()} /> },
                    }}
                </div>
            </div>
        </div>
    }
}

#[derive(Properties, PartialEq)]
struct TabButtonProps {
    label: String,
    tab: String,
    active: bool,
    on_click: Callback<String>,
}

#[function_component]
fn TabButton(props: &TabButtonProps) -> Html {
    let onclick = {
        let tab = props.tab.clone();
        let on_click = props.on_click.clone();
        Callback::from(move |_| {
            on_click.emit(tab.clone());
        })
    };

    let class = if props.active {
        "px-4 py-3 text-primary border-b-2 border-blue-500"
    } else {
        "px-4 py-3 text-secondary hover:text-primary"
    };

    html! {
        <button onclick={onclick} class={class}>
            { &props.label }
        </button>
    }
}

#[derive(Properties, PartialEq)]
struct BasicTabProps {
    presets: Vec<ServerPreset>,
    on_preset_select: Callback<ServerPreset>,
    selected_preset: Option<ServerPreset>,
    config: Option<serde_json::Value>,
    site_id: String,
}

#[function_component]
fn BasicTab(props: &BasicTabProps) -> Html {
    let presets = props.presets.clone();
    let on_preset_select = props.on_preset_select.clone();
    let config = props.config.clone();
    let site_id = props.site_id.clone();
    let saving = use_state(|| false);

    let domains = use_state(|| "".to_string());
    let upstream = use_state(|| "".to_string());
    let routes = use_state(|| Vec::<(String, String)>::new());

    use_effect_with((), {
        let domains = domains.clone();
        let upstream = upstream.clone();
        let routes = routes.clone();
        let config = config.clone();
        move |_| {
            if let Some(cfg) = config {
                if let Some(d) = cfg.get("domains").and_then(|v| v.as_array()) {
                    let domains_str: Vec<String> = d
                        .iter()
                        .filter_map(|v| v.as_str().map(|s| s.to_string()))
                        .collect();
                    domains.set(domains_str.join(", "));
                }
                if let Some(u) = cfg.get("default_upstream").and_then(|v| v.as_str()) {
                    upstream.set(u.to_string());
                }
                if let Some(r) = cfg.get("routes").and_then(|v| v.as_object()) {
                    let mut routes_vec = Vec::new();
                    for (k, v) in r.iter() {
                        if let Some(v_str) = v.as_str() {
                            routes_vec.push((k.clone(), v_str.to_string()));
                        }
                    }
                    routes.set(routes_vec);
                }
            }
            || {}
        }
    });

    let on_domains_change = {
        let domains = domains.clone();
        Callback::from(move |e: Event| {
            let target = e.target().unwrap();
            let value = target
                .dyn_ref::<web_sys::HtmlInputElement>()
                .map(|el| el.value())
                .unwrap_or_default();
            domains.set(value);
        })
    };

    let on_upstream_change = {
        let upstream = upstream.clone();
        Callback::from(move |e: Event| {
            let target = e.target().unwrap();
            let value = target
                .dyn_ref::<web_sys::HtmlInputElement>()
                .map(|el| el.value())
                .unwrap_or_default();
            upstream.set(value);
        })
    };

    let on_save = {
        let saving = saving.clone();
        let domains = domains.clone();
        let upstream = upstream.clone();
        let site_id = site_id.clone();
        Callback::from(move |_| {
            let domains_vec: Vec<String> = domains
                .split(',')
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect();
            let new_config = serde_json::json!({
                "domains": domains_vec,
                "default_upstream": (*upstream).clone()
            });
            let saving = saving.clone();
            let site_id = site_id.clone();
            saving.set(true);
            wasm_bindgen_futures::spawn_local(async move {
                let api = ApiService::new();
                let _ = api.update_site(&site_id, &new_config).await;
                saving.set(false);
                toast_success("Site configuration saved");
            });
        })
    };

    html! {
        <div class="space-y-6">
            <div>
                <h3 class="text-lg font-semibold mb-4">{ "Server Preset" }</h3>
                <p class="text-sm text-secondary mb-4">
                    { "Select a preset to quickly configure common server types, or configure manually below." }
                </p>
                <div class="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-4 gap-3">
                    {for presets.iter().map(|preset| {
                        let on_select = {
                            let preset = preset.clone();
                            let on_preset_select = on_preset_select.clone();
                            Callback::from(move |_| {
                                on_preset_select.emit(preset.clone());
                            })
                        };
                        html! {
                            <button
                                onclick={on_select}
                                class="p-3 bg-tertiary rounded-lg border border-default hover:border-blue-500 transition text-left"
                            >
                                <div class="font-medium text-sm">{ &preset.name }</div>
                                <div class="text-xs text-secondary mt-1">{ &preset.description }</div>
                            </button>
                        }
                    })}
                </div>
            </div>

            <div class="flex justify-end">
                <button onclick={on_save} disabled={*saving} class="px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700 disabled:opacity-50">
                    { if *saving { "Saving..." } else { "Save Changes" } }
                </button>
            </div>
        </div>
    }
}

#[derive(Properties, PartialEq)]
struct AttacksTabProps {
    config: Option<serde_json::Value>,
    site_id: String,
}

#[function_component]
fn AttacksTab(props: &AttacksTabProps) -> Html {
    html! {
        <div class="space-y-6">
            <div>
                <h3 class="text-lg font-semibold mb-4">{ "Detection Settings" }</h3>
                <div class="grid grid-cols-2 gap-4">
                    <SelectWithTooltip
                        label="Paranoia Level"
                        name="paranoia_level"
                        value="2"
                        options={vec![
                            ("1".to_string(), "1 - Low (fewer false positives)".to_string()),
                            ("2".to_string(), "2 - Medium (balanced)".to_string()),
                            ("3".to_string(), "3 - High (more aggressive)".to_string()),
                        ]}
                        help="Higher levels catch more attacks but may block legitimate traffic"
                        tooltip_title="Paranoia Level"
                        tooltip_content="Level 1 - Low: Basic detection patterns, minimal false positives\n\nLevel 2 - Medium: Balanced detection with moderate patterns\n\nLevel 3 - High: Aggressive detection, may block legitimate requests"
                    />
                    <SelectWithTooltip
                        label="Action"
                        name="attack_action"
                        value="stall"
                        options={vec![
                            ("log".to_string(), "Log only".to_string()),
                            ("stall".to_string(), "Stall connection".to_string()),
                            ("block".to_string(), "Block request".to_string()),
                        ]}
                        help="What to do when attack is detected"
                        tooltip_title="Attack Action"
                        tooltip_content="Log only: Record the attack but allow the request through\n\nStall: Hold the connection indefinitely (recommended for stealth)\n\nBlock: Immediately return 403 Forbidden"
                    />
                </div>
            </div>

            <div>
                <h3 class="text-lg font-semibold mb-4 flex items-center">
                    { "Attack Types" }
                    <HelpIcon
                        content="Enable or disable detection for specific attack categories. Disabling reduces security but may improve performance."
                        title="Attack Detection"
                    />
                </h3>
                <div class="space-y-3">
                    <ToggleFieldWithTooltip
                        label="SQL Injection (SQLi)"
                        enabled=true
                        tooltip_content="Detects attempts to inject SQL queries through user input. Common attack vector for database compromise."
                    />
                    <ToggleFieldWithTooltip
                        label="Cross-Site Scripting (XSS)"
                        enabled=true
                        tooltip_content="Detects attempts to inject malicious scripts into web pages viewed by other users."
                    />
                    <ToggleFieldWithTooltip
                        label="Path Traversal"
                        enabled=true
                        tooltip_content="Detects attempts to access files outside the web root directory through ../ sequences."
                    />
                    <ToggleFieldWithTooltip
                        label="Remote File Inclusion (RFI)"
                        enabled=true
                        tooltip_content="Detects attempts to include remote files through URL parameters."
                    />
                    <ToggleFieldWithTooltip
                        label="Server-Side Request Forgery (SSRF)"
                        enabled=true
                        tooltip_content="Detects attempts to make the server fetch internal resources or attack other services."
                    />
                </div>
            </div>
        </div>
    }
}

#[derive(Properties, PartialEq)]
struct ToggleFieldWithTooltipProps {
    label: String,
    enabled: bool,
    tooltip_content: String,
}

#[function_component]
fn ToggleFieldWithTooltip(props: &ToggleFieldWithTooltipProps) -> Html {
    let enabled = use_state(|| props.enabled);
    let onclick = {
        let enabled = enabled.clone();
        Callback::from(move |_| {
            enabled.set(!*enabled);
        })
    };

    let bg_class = if *enabled {
        "bg-blue-600"
    } else {
        "bg-gray-600"
    };
    let translate_class = if *enabled {
        "translate-x-5"
    } else {
        "translate-x-0"
    };

    html! {
        <div class="flex items-center justify-between py-2">
            <div class="flex items-center gap-2">
                <span class="text-primary">{ &props.label }</span>
                <Tooltip content={props.tooltip_content.clone()} position={TooltipPosition::Right}>
                    <span class="inline-flex items-center justify-center w-4 h-4 rounded-full bg-tertiary text-secondary text-xs cursor-help hover:bg-blue-600 hover:text-white transition-colors">
                        {"?"}
                    </span>
                </Tooltip>
            </div>
            <button
                onclick={onclick}
                class={format!("relative w-10 h-6 rounded-full transition-colors {}", bg_class)}
            >
                <span class={format!("absolute top-1 left-1 w-4 h-4 bg-white rounded-full transition-transform {}", translate_class)} />
            </button>
        </div>
    }
}

#[derive(Properties, PartialEq)]
struct BotTabProps {
    config: Option<serde_json::Value>,
    site_id: String,
}

#[function_component]
fn BotTab(_props: &BotTabProps) -> Html {
    html! {
        <div class="space-y-6">
            <div>
                <h3 class="text-lg font-semibold mb-4">{ "Bot Protection" }</h3>
                <div class="space-y-3">
                    <ToggleFieldWithTooltip
                        label="Block AI Crawlers"
                        enabled=true
                        tooltip_content="Blocks known AI crawler bots (GPTBot, ClaudeBot, etc.) from accessing the site. These bots may be used for AI training data collection."
                    />
                    <ToggleFieldWithTooltip
                        label="Enable CSS Honeypot"
                        enabled=true
                        tooltip_content="Creates invisible links that only bots would click. Traps and identifies scrapers without affecting human users."
                    />
                    <ToggleFieldWithTooltip
                        label="Enable JS Challenge"
                        enabled=false
                        tooltip_content="Requires browsers to execute JavaScript before accessing the site. Blocks simple bots but may affect performance."
                    />
                    <ToggleFieldWithTooltip
                        label="Enable PoW Challenge"
                        enabled=true
                        tooltip_content="Proof-of-Work challenge requires computational work before allowing access. Effective against DDoS and automated attacks."
                    />
                </div>
            </div>

            <div>
                <h3 class="text-lg font-semibold mb-4">{ "Challenge Settings" }</h3>
                <div class="grid grid-cols-2 gap-4">
                    <InputWithTooltip
                        label="PoW Difficulty"
                        name="pow_difficulty"
                        value="6"
                        help="Higher = more difficult (1-10)"
                        tooltip_title="PoW Difficulty"
                        tooltip_content="Sets the computational difficulty for the Proof-of-Work challenge. Higher values require more CPU work but provide stronger DDoS protection. Recommended: 4-8"
                    />
                    <InputWithTooltip
                        label="Challenge Window (secs)"
                        name="challenge_window"
                        value="300"
                        help="How long the challenge result is valid"
                        tooltip_title="Challenge Window"
                        tooltip_content="Duration in seconds that a passed challenge remains valid. After this period, the client must complete the challenge again."
                    />
                </div>
            </div>
        </div>
    }
}

#[derive(Properties, PartialEq)]
struct UploadTabProps {
    config: Option<serde_json::Value>,
    site_id: String,
}

#[function_component]
fn UploadTab(_props: &UploadTabProps) -> Html {
    html! {
        <div class="space-y-6">
            <div>
                <h3 class="text-lg font-semibold mb-4">{ "Upload Settings" }</h3>
                <div class="space-y-3">
                    <ToggleFieldWithTooltip
                        label="Enable Upload Validation"
                        enabled=true
                        tooltip_content="Validates uploaded files against allowed MIME types and checks file extensions to prevent malicious uploads."
                    />
                    <ToggleFieldWithTooltip
                        label="Scan with YARA"
                        enabled=true
                        tooltip_content="Scans uploaded files using YARA rules to detect malware and known malicious patterns."
                    />
                    <ToggleFieldWithTooltip
                        label="Sandbox Files"
                        enabled=true
                        tooltip_content="Executes potentially dangerous file types in an isolated sandbox environment before allowing storage."
                    />
                </div>
            </div>

            <div>
                <h3 class="text-lg font-semibold mb-4">{ "Size Limits" }</h3>
                <div class="grid grid-cols-2 gap-4">
                    <InputWithTooltip
                        label="Max Upload Size"
                        name="max_size"
                        value="100MB"
                        help="Maximum size for a single file upload"
                        tooltip_title="Max Upload Size"
                        tooltip_content="Maximum allowed size for a single uploaded file. Format: number followed by B, KB, MB, or GB."
                    />
                    <InputWithTooltip
                        label="Memory Threshold"
                        name="memory_threshold"
                        value="10MB"
                        help="Files larger than this are written to disk"
                        tooltip_title="Memory Threshold"
                        tooltip_content="Files smaller than this are held in memory, larger files are written to disk. Lower values use more memory but improve performance."
                    />
                </div>
            </div>

            <div>
                <h3 class="text-lg font-semibold mb-4 flex items-center">
                    { "Allowed MIME Types" }
                    <HelpIcon
                        content="Only files with these MIME types can be uploaded. One type per line. Leave empty to allow all types (not recommended)."
                        title="Allowed MIME Types"
                    />
                </h3>
                <textarea
                    class="w-full px-3 py-2 bg-tertiary border border-default rounded-lg font-mono text-sm"
                    rows="6"
                    value={"image/jpeg\nimage/png\napplication/pdf\ntext/plain"}
                />
                <p class="mt-1 text-xs text-secondary">{ "One MIME type per line" }</p>
            </div>
        </div>
    }
}

#[derive(Properties, PartialEq)]
struct ToggleFieldProps {
    label: String,
    enabled: bool,
}

#[function_component]
fn ToggleField(props: &ToggleFieldProps) -> Html {
    let enabled = use_state(|| props.enabled);
    let onclick = {
        let enabled = enabled.clone();
        Callback::from(move |_| {
            enabled.set(!*enabled);
        })
    };

    let bg_class = if *enabled {
        "bg-blue-600"
    } else {
        "bg-gray-600"
    };
    let translate_class = if *enabled {
        "translate-x-5"
    } else {
        "translate-x-0"
    };

    html! {
        <div class="flex items-center justify-between py-2">
            <span class="text-primary">{ &props.label }</span>
            <button
                onclick={onclick}
                class={format!("relative w-10 h-6 rounded-full transition-colors {}", bg_class)}
            >
                <span class={format!("absolute top-1 left-1 w-4 h-4 bg-white rounded-full transition-transform {}", translate_class)} />
            </button>
        </div>
    }
}

#[derive(Properties, PartialEq)]
pub struct ErrorPagesTabProps {
    pub site_id: String,
}

#[function_component]
fn ErrorPagesTab(props: &ErrorPagesTabProps) -> Html {
    let selected_preset = use_state(|| "default".to_string());
    let preview_html = use_state(|| String::new());
    let preview_light = use_state(|| false);
    let saving = use_state(|| false);
    let inherit = use_state(|| true);
    let mode = use_state(|| "static".to_string());
    let custom_directory = use_state(|| String::new());

    {
        let selected_preset = selected_preset.clone();
        let preview_html = preview_html.clone();
        let preview_light = preview_light.clone();
        let inherit = inherit.clone();
        let mode = mode.clone();
        let custom_directory = custom_directory.clone();
        let site_id = props.site_id.clone();
        use_effect_with((), move |_| {
            wasm_bindgen_futures::spawn_local(async move {
                let api = crate::services::ApiService::new();

                let theme_future = api.get_site_theme(&site_id);
                let error_pages_future = api.get_site_error_pages(&site_id);

                let (theme_result, error_pages_result) = (
                    theme_future.await,
                    error_pages_future.await,
                );

                if let Ok(Some(theme)) = theme_result {
                    let preset = theme.preset.unwrap_or_else(|| "default".to_string());
                    selected_preset.set(preset.clone());
                    let colors = get_preset_colors(&preset);
                    let use_light = *preview_light;
                    let html = generate_error_page_preview("", &colors, use_light);
                    preview_html.set(html);
                } else {
                    tracing::error!("Failed to fetch site theme: {:?}", theme_result.err());
                }

                if let Ok(error_pages) = error_pages_result {
                    inherit.set(error_pages.inherit.unwrap_or(true));
                    mode.set(error_pages.mode.unwrap_or_else(|| "static".to_string()));
                    custom_directory.set(error_pages.custom_directory.unwrap_or_default());
                } else {
                    tracing::error!("Failed to fetch site error pages: {:?}", error_pages_result.err());
                }
            });
            || {}
        });
    }

    let on_preset_change = {
        let selected_preset = selected_preset.clone();
        let preview_html = preview_html.clone();
        let preview_light = preview_light.clone();
        Callback::from(move |e: Event| {
            let target = e.target().unwrap();
            let value = target
                .dyn_ref::<web_sys::HtmlSelectElement>()
                .map(|el| el.value())
                .unwrap_or_default();
            selected_preset.set(value.clone());
            let colors = get_preset_colors(&value);
            let use_light = *preview_light;
            let html = generate_error_page_preview("", &colors, use_light);
            preview_html.set(html);
        })
    };

    let on_toggle_preview = {
        let preview_light = preview_light.clone();
        let selected_preset = selected_preset.clone();
        let preview_html = preview_html.clone();
        Callback::from(move |_| {
            let new_value = !*preview_light;
            preview_light.set(new_value);

            let colors = get_preset_colors(&selected_preset);
            let html = generate_error_page_preview("", &colors, new_value);
            preview_html.set(html);
        })
    };

    let on_mode_change = {
        let mode = mode.clone();
        Callback::from(move |e: Event| {
            let target = e.target().unwrap();
            let value = target
                .dyn_ref::<web_sys::HtmlSelectElement>()
                .map(|el| el.value())
                .unwrap_or_default();
            mode.set(value);
        })
    };

    let on_custom_directory_change = {
        let custom_directory = custom_directory.clone();
        Callback::from(move |e: Event| {
            let target = e.target().unwrap();
            let value = target
                .dyn_ref::<web_sys::HtmlInputElement>()
                .map(|el| el.value())
                .unwrap_or_default();
            custom_directory.set(value);
        })
    };

    let on_save = {
        let saving = saving.clone();
        let selected_preset = selected_preset.clone();
        let inherit = inherit.clone();
        let mode = mode.clone();
        let custom_directory = custom_directory.clone();
        let site_id = props.site_id.clone();
        Callback::from(move |_| {
            let preset = (*selected_preset).clone();
            let inherit_val = *inherit;
            let mode_val = (*mode).clone();
            let custom_dir_val = (*custom_directory).clone();
            let site_id = site_id.clone();
            let saving = saving.clone();

            saving.set(true);

            wasm_bindgen_futures::spawn_local(async move {
                let api = crate::services::ApiService::new();

                let theme_request = crate::types::UpdateThemeRequest {
                    preset: Some(preset),
                    mode: None,
                    allow_only: None,
                };

                let error_pages_request = crate::types::UpdateSiteErrorPagesRequest {
                    inherit: Some(inherit_val),
                    mode: Some(mode_val),
                    custom_directory: if custom_dir_val.is_empty() { None } else { Some(custom_dir_val.clone()) },
                };

                let (theme_result, error_pages_result) = (
                    api.update_site_theme(&site_id, &theme_request).await,
                    api.update_site_error_pages(&site_id, &error_pages_request).await,
                );

                match (theme_result, error_pages_result) {
                    (Ok(_), Ok(_)) => {
                        toast_success("Error pages settings updated successfully");
                        tracing::info!("Error pages settings updated successfully");
                    }
                    (Err(e), _) => {
                        toast_error(&format!("Failed to update site theme: {}", e));
                        tracing::error!("Failed to update site theme: {}", e);
                    }
                    (_, Err(e)) => {
                        toast_error(&format!("Failed to update error pages: {}", e));
                        tracing::error!("Failed to update error pages: {}", e);
                    }
                }
                saving.set(false);
            });
        })
    };

    let presets = vec![
        ("default", "Default (Use Global)"),
        ("dark", "Dark"),
        ("light", "Light"),
        ("ocean", "Ocean"),
        ("forest", "Forest"),
        ("sunset", "Sunset"),
    ];

    let modes = vec![
        ("static", "Static (Return HTML)"),
        ("dynamic", "Dynamic (Execute template)"),
        ("redirect", "Redirect to URL"),
    ];

    html! {
        <div class="space-y-6">
            <div class="bg-tertiary border border-default rounded-lg p-4">
                <h3 class="text-lg font-medium text-primary mb-4">{ "Error Page Configuration" }</h3>

                <div class="space-y-4">
                    <div class="flex items-center gap-3">
                        <input
                            type="checkbox"
                            id="inherit"
                            checked={*inherit}
                            onchange={Callback::from(move |_| inherit.set(!*inherit))}
                            class="w-4 h-4 rounded border-default text-blue-600 focus:ring-blue-500"
                        />
                        <label for="inherit" class="text-sm text-primary">
                            { "Inherit from global settings" }
                        </label>
                    </div>

                    <div>
                        <label class="block text-sm font-medium text-primary mb-2">{ "Mode" }</label>
                        <select
                            class="w-full px-3 py-2 bg-tertiary border border-default rounded-lg text-primary"
                            value={(*mode).clone()}
                            onchange={on_mode_change}
                        >
                            { for modes.iter().map(|(value, label)| {
                                html! {
                                    <option value={value.clone()}>{label.clone()}</option>
                                }
                            }) }
                        </select>
                        <p class="mt-1 text-sm text-secondary">{ "How error pages are served" }</p>
                    </div>

                    <div>
                        <label class="block text-sm font-medium text-primary mb-2">{ "Custom Directory" }</label>
                        <input
                            type="text"
                            value={(*custom_directory).clone()}
                            onchange={on_custom_directory_change}
                            placeholder="/var/www/error-pages"
                            class="w-full px-3 py-2 bg-tertiary border border-default rounded-lg text-primary placeholder-secondary/50"
                        />
                        <p class="mt-1 text-sm text-secondary">{ "Directory containing custom error page files" }</p>
                    </div>
                </div>
            </div>

            <div class="bg-tertiary border border-default rounded-lg p-4">
                <h3 class="text-lg font-medium text-primary mb-4">{ "Error Page Theme" }</h3>

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
                    <p class="mt-1 text-sm text-secondary">{ "Visual style for error pages" }</p>
                </div>

                <div class="mt-4">
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
                    <p class="mt-1 text-sm text-secondary">{ "Preview of the error page with selected theme" }</p>
                </div>
            </div>

            <div class="flex justify-end gap-4">
                <button
                    onclick={on_save}
                    disabled={*saving}
                    class="px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700 disabled:opacity-50"
                >
                    { if *saving { "Saving..." } else { "Save Error Pages" } }
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

fn generate_error_page_preview(
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

#[derive(Properties, PartialEq)]
struct SelectWithTooltipProps {
    label: String,
    name: String,
    value: String,
    options: Vec<(String, String)>,
    #[prop_or_default]
    help: String,
    #[prop_or_default]
    tooltip_title: String,
    #[prop_or_default]
    tooltip_content: String,
}

#[function_component]
fn SelectWithTooltip(props: &SelectWithTooltipProps) -> Html {
    html! {
        <div>
            <label class="block text-sm font-medium text-primary mb-2">{ &props.label }</label>
            <select class="w-full px-3 py-2 bg-tertiary border border-default rounded-lg text-primary" value={props.value.clone()}>
                { for props.options.iter().map(|(v, l)| html! { <option value={v.clone()}>{ l }</option> }) }
            </select>
            if !props.help.is_empty() {
                <p class="mt-1 text-sm text-secondary">{ &props.help }</p>
            }
        </div>
    }
}

#[derive(Properties, PartialEq)]
struct InputWithTooltipProps {
    label: String,
    name: String,
    value: String,
    #[prop_or_default]
    help: String,
    #[prop_or_default]
    tooltip_title: String,
    #[prop_or_default]
    tooltip_content: String,
}

#[function_component]
fn InputWithTooltip(props: &InputWithTooltipProps) -> Html {
    html! {
        <div>
            <label class="block text-sm font-medium text-primary mb-2">{ &props.label }</label>
            <input
                type="text"
                name={props.name.clone()}
                value={props.value.clone()}
                class="w-full px-3 py-2 bg-tertiary border border-default rounded-lg text-primary"
            />
            if !props.help.is_empty() {
                <p class="mt-1 text-sm text-secondary">{ &props.help }</p>
            }
        </div>
    }
}

#[derive(Properties, PartialEq)]
struct RateLimitTabProps {
    config: Option<serde_json::Value>,
    site_id: String,
}

#[function_component]
fn RateLimitTab(props: &RateLimitTabProps) -> Html {
    html! {
        <div class="space-y-6">
            <div>
                <h3 class="text-lg font-semibold mb-4">{ "Per-IP Rate Limits" }</h3>
                <div class="grid grid-cols-3 gap-4">
                    <InputWithTooltip label="Per Second" name="ip_per_second" value="10" help="Requests per second per IP" tooltip_title="" tooltip_content="" />
                    <InputWithTooltip label="Per Minute" name="ip_per_minute" value="60" help="Requests per minute per IP" tooltip_title="" tooltip_content="" />
                    <InputWithTooltip label="Per 5 Min" name="ip_per_5min" value="200" help="Requests per 5 minutes per IP" tooltip_title="" tooltip_content="" />
                    <InputWithTooltip label="Per Hour" name="ip_per_hour" value="500" help="Requests per hour per IP" tooltip_title="" tooltip_content="" />
                    <InputWithTooltip label="Per Day" name="ip_per_day" value="1000" help="Requests per day per IP" tooltip_title="" tooltip_content="" />
                    <InputWithTooltip label="Burst" name="ip_burst" value="20" help="Burst capacity per IP" tooltip_title="" tooltip_content="" />
                </div>
            </div>
            <div>
                <h3 class="text-lg font-semibold mb-4">{ "Global Rate Limits" }</h3>
                <div class="grid grid-cols-3 gap-4">
                    <InputWithTooltip label="Per Second" name="global_per_second" value="500" help="Total requests per second" tooltip_title="" tooltip_content="" />
                    <InputWithTooltip label="Per Minute" name="global_per_minute" value="5000" help="Total requests per minute" tooltip_title="" tooltip_content="" />
                    <InputWithTooltip label="Max Connections" name="max_connections" value="1000" help="Max concurrent connections" tooltip_title="" tooltip_content="" />
                </div>
            </div>
        </div>
    }
}

#[derive(Properties, PartialEq)]
struct BlockingTabProps {
    config: Option<serde_json::Value>,
    site_id: String,
}

#[function_component]
fn BlockingTab(props: &BlockingTabProps) -> Html {
    let whitelist_ips = use_state(|| String::new());
    let whitelist_networks = use_state(|| String::new());
    let whitelist_user_agents = use_state(|| String::new());
    let geoip_enabled = use_state(|| false);
    let blocked_countries = use_state(|| String::new());
    let allowed_countries = use_state(|| String::new());
    let saving = use_state(|| false);

    use_effect_with((), {
        let whitelist_ips = whitelist_ips.clone();
        let whitelist_networks = whitelist_networks.clone();
        let whitelist_user_agents = whitelist_user_agents.clone();
        let geoip_enabled = geoip_enabled.clone();
        let blocked_countries = blocked_countries.clone();
        let allowed_countries = allowed_countries.clone();
        let config = props.config.clone();
        move |_| {
            if let Some(cfg) = config {
                if let Some(wl) = cfg.get("whitelist").and_then(|w| w.as_object()) {
                    if let Some(ips) = wl.get("ips").and_then(|v| v.as_array()) {
                        let ips_str: Vec<String> = ips.iter().filter_map(|i| i.as_str().map(String::from)).collect();
                        whitelist_ips.set(ips_str.join("\n"));
                    }
                    if let Some(networks) = wl.get("networks").and_then(|v| v.as_array()) {
                        let networks_str: Vec<String> = networks.iter().filter_map(|n| n.as_str().map(String::from)).collect();
                        whitelist_networks.set(networks_str.join("\n"));
                    }
                    if let Some(uas) = wl.get("user_agents").and_then(|v| v.as_array()) {
                        let uas_str: Vec<String> = uas.iter().filter_map(|u| u.as_str().map(String::from)).collect();
                        whitelist_user_agents.set(uas_str.join("\n"));
                    }
                }
                if let Some(geoip) = cfg.get("geoip").and_then(|g| g.as_object()) {
                    if let Some(enabled) = geoip.get("enabled").and_then(|v| v.as_bool()) {
                        geoip_enabled.set(enabled);
                    }
                    if let Some(blocked) = geoip.get("blocked_countries").and_then(|v| v.as_array()) {
                        let blocked_str: Vec<String> = blocked.iter().filter_map(|c| c.as_str().map(String::from)).collect();
                        blocked_countries.set(blocked_str.join(", "));
                    }
                    if let Some(allowed) = geoip.get("allowed_countries").and_then(|v| v.as_array()) {
                        let allowed_str: Vec<String> = allowed.iter().filter_map(|c| c.as_str().map(String::from)).collect();
                        allowed_countries.set(allowed_str.join(", "));
                    }
                }
            }
            || {}
        }
    });

    let on_save = {
        let saving = saving.clone();
        let whitelist_ips = whitelist_ips.clone();
        let whitelist_networks = whitelist_networks.clone();
        let whitelist_user_agents = whitelist_user_agents.clone();
        let geoip_enabled = geoip_enabled.clone();
        let blocked_countries = blocked_countries.clone();
        let allowed_countries = allowed_countries.clone();
        let site_id = props.site_id.clone();
        Callback::from(move |_| {
            let ips_vec: Vec<String> = whitelist_ips.split('\n')
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect();
            let networks_vec: Vec<String> = whitelist_networks.split('\n')
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect();
            let uas_vec: Vec<String> = whitelist_user_agents.split('\n')
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect();
            let blocked_vec: Vec<String> = blocked_countries.split(',')
                .map(|s| s.trim().to_uppercase())
                .filter(|s| !s.is_empty())
                .collect();
            let allowed_vec: Vec<String> = allowed_countries.split(',')
                .map(|s| s.trim().to_uppercase())
                .filter(|s| !s.is_empty())
                .collect();

            let new_config = serde_json::json!({
                "whitelist": {
                    "ips": ips_vec,
                    "networks": networks_vec,
                    "user_agents": uas_vec
                },
                "geoip": {
                    "enabled": *geoip_enabled,
                    "blocked_countries": blocked_vec,
                    "allowed_countries": allowed_vec
                }
            });

            let saving = saving.clone();
            let site_id = site_id.clone();
            saving.set(true);
            wasm_bindgen_futures::spawn_local(async move {
                let api = crate::services::ApiService::new();
                let _ = api.update_site(&site_id, &new_config).await;
                saving.set(false);
                crate::components::toast::toast_success("Blocking settings saved");
            });
        })
    };

    html! {
        <div class="space-y-6">
            <div>
                <h3 class="text-lg font-semibold mb-4">{ "IP Whitelist" }</h3>
                <p class="text-sm text-secondary mb-4">
                    { "Whitelist specific IPs, networks, or user agents to bypass other security checks." }
                </p>
                <div class="space-y-4">
                    <div>
                        <label class="block text-sm font-medium text-primary mb-1">{ "IP Addresses (one per line)" }</label>
                        <textarea
                            class="w-full px-3 py-2 bg-tertiary border border-default rounded-lg text-primary font-mono text-sm"
                            rows="4"
                            placeholder="192.168.1.1&#10;10.0.0.0/8"
                            value={(*whitelist_ips).clone()}
                            oninput={Callback::from(move |e: InputEvent| {
                                let input = e.target_unchecked_into::<web_sys::HtmlTextAreaElement>();
                                whitelist_ips.set(input.value());
                            })}
                        />
                    </div>
                    <div>
                        <label class="block text-sm font-medium text-primary mb-1">{ "Network CIDRs (one per line)" }</label>
                        <textarea
                            class="w-full px-3 py-2 bg-tertiary border border-default rounded-lg text-primary font-mono text-sm"
                            rows="3"
                            placeholder="10.0.0.0/8&#10;172.16.0.0/12"
                            value={(*whitelist_networks).clone()}
                            oninput={Callback::from(move |e: InputEvent| {
                                let input = e.target_unchecked_into::<web_sys::HtmlTextAreaElement>();
                                whitelist_networks.set(input.value());
                            })}
                        />
                    </div>
                    <div>
                        <label class="block text-sm font-medium text-primary mb-1">{ "User Agents (one per line)" }</label>
                        <textarea
                            class="w-full px-3 py-2 bg-tertiary border border-default rounded-lg text-primary font-mono text-sm"
                            rows="3"
                            placeholder="curl/7.68.0&#10;python-requests/2.25.1"
                            value={(*whitelist_user_agents).clone()}
                            oninput={Callback::from(move |e: InputEvent| {
                                let input = e.target_unchecked_into::<web_sys::HtmlTextAreaElement>();
                                whitelist_user_agents.set(input.value());
                            })}
                        />
                    </div>
                </div>
            </div>

            <div class="border-t border-default pt-6">
                <h3 class="text-lg font-semibold mb-4">{ "Country Blocking" }</h3>
                <div class="mb-4">
                    <label class="flex items-center gap-2 cursor-pointer">
                        <input
                            type="checkbox"
                            checked={*geoip_enabled}
                            onchange={{
                                let geoip_enabled = geoip_enabled.clone();
                                Callback::from(move |e: Event| {
                                    let input: web_sys::HtmlInputElement = e.target_unchecked_into();
                                    geoip_enabled.set(input.checked());
                                })
                            }}
                            class="w-4 h-4 rounded border-default bg-tertiary accent-blue-600"
                        />
                        <span class="text-primary">{ "Enable GeoIP Blocking" }</span>
                    </label>
                </div>
                <div class="space-y-4">
                    <div>
                        <label class="block text-sm font-medium text-primary mb-1">{ "Blocked Countries (comma-separated ISO codes)" }</label>
                        <input
                            type="text"
                            placeholder="RU, CN, IR"
                            value={(*blocked_countries).clone()}
                            oninput={Callback::from(move |e: InputEvent| {
                                let input = e.target_unchecked_into::<web_sys::HtmlInputElement>();
                                blocked_countries.set(input.value());
                            })}
                            disabled={!*geoip_enabled}
                            class="w-full px-3 py-2 bg-tertiary border border-default rounded-lg text-primary focus:outline-none focus:ring-2 focus:ring-blue-500 disabled:opacity-50"
                        />
                        <p class="mt-1 text-xs text-secondary">{ "Traffic from these countries will be blocked" }</p>
                    </div>
                    <div>
                        <label class="block text-sm font-medium text-primary mb-1">{ "Allowed Countries (comma-separated ISO codes)" }</label>
                        <input
                            type="text"
                            placeholder="US, GB, CA"
                            value={(*allowed_countries).clone()}
                            oninput={Callback::from(move |e: InputEvent| {
                                let input = e.target_unchecked_into::<web_sys::HtmlInputElement>();
                                allowed_countries.set(input.value());
                            })}
                            disabled={!*geoip_enabled}
                            class="w-full px-3 py-2 bg-tertiary border border-default rounded-lg text-primary focus:outline-none focus:ring-2 focus:ring-blue-500 disabled:opacity-50"
                        />
                        <p class="mt-1 text-xs text-secondary">{ "Only traffic from these countries will be allowed (overrides blocked list)" }</p>
                    </div>
                </div>
            </div>

            <div class="flex justify-end">
                <button onclick={on_save} disabled={*saving} class="px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700 disabled:opacity-50">
                    { if *saving { "Saving..." } else { "Save Changes" } }
                </button>
            </div>
        </div>
    }
}

#[derive(Properties, PartialEq)]
struct ProxyTabProps {
    config: Option<serde_json::Value>,
    site_id: String,
}

#[function_component]
fn ProxyTab(props: &ProxyTabProps) -> Html {
    let upstream_timeout = use_state(|| "30".to_string());
    let keepalive = use_state(|| "60".to_string());
    let saving = use_state(|| false);

    use_effect_with((), {
        let upstream_timeout = upstream_timeout.clone();
        let keepalive = keepalive.clone();
        let config = props.config.clone();
        move |_| {
            if let Some(cfg) = config {
                if let Some(t) = cfg.get("upstream_timeout_secs").and_then(|v| v.as_u64()) {
                    upstream_timeout.set(t.to_string());
                }
                if let Some(k) = cfg.get("keepalive_timeout_secs").and_then(|v| v.as_u64()) {
                    keepalive.set(k.to_string());
                }
            }
            || {}
        }
    });

    let on_save = {
        let saving = saving.clone();
        let upstream_timeout = upstream_timeout.clone();
        let keepalive = keepalive.clone();
        let site_id = props.site_id.clone();
        Callback::from(move |_| {
            let new_config = serde_json::json!({
                "upstream_timeout_secs": upstream_timeout.parse::<u64>().unwrap_or(30),
                "keepalive_timeout_secs": keepalive.parse::<u64>().unwrap_or(60),
            });
            let saving = saving.clone();
            let site_id = site_id.clone();
            saving.set(true);
            wasm_bindgen_futures::spawn_local(async move {
                let api = crate::services::ApiService::new();
                let _ = api.update_site(&site_id, &new_config).await;
                saving.set(false);
                toast_success("Proxy settings saved");
            });
        })
    };

    html! {
        <div class="space-y-6">
            <div>
                <h3 class="text-lg font-semibold mb-4">{ "Proxy Settings" }</h3>
                <div class="grid grid-cols-2 gap-4">
                    <Input label="Upstream Timeout (secs)" name="upstream_timeout" value={(*upstream_timeout).clone()} input_type="number" help="Timeout for upstream requests" />
                    <Input label="Keep-Alive Timeout (secs)" name="keepalive" value={(*keepalive).clone()} input_type="number" help="Upstream keep-alive timeout" />
                </div>
            </div>
            <div class="flex justify-end">
                <button onclick={on_save} disabled={*saving} class="px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700 disabled:opacity-50">
                    { if *saving { "Saving..." } else { "Save Changes" } }
                </button>
            </div>
        </div>
    }
}

#[derive(Properties, PartialEq)]
struct SecurityHeadersTabProps {
    config: Option<serde_json::Value>,
    site_id: String,
}

#[function_component]
fn SecurityHeadersTab(props: &SecurityHeadersTabProps) -> Html {
    let hsts = use_state(|| true);
    let hsts_max_age = use_state(|| "31536000".to_string());
    let x_frame_options = use_state(|| "SAMEORIGIN".to_string());
    let x_content_type = use_state(|| true);
    let referrer_policy = use_state(|| "strict-origin-when-cross-origin".to_string());
    let saving = use_state(|| false);

    use_effect_with((), {
        let hsts = hsts.clone();
        let hsts_max_age = hsts_max_age.clone();
        let x_frame_options = x_frame_options.clone();
        let x_content_type = x_content_type.clone();
        let referrer_policy = referrer_policy.clone();
        let config = props.config.clone();
        move |_| {
            if let Some(cfg) = config {
                if let Some(v) = cfg.get("hsts").and_then(|v| v.as_bool()) {
                    hsts.set(v);
                }
                if let Some(v) = cfg.get("hsts_max_age").and_then(|v| v.as_u64()) {
                    hsts_max_age.set(v.to_string());
                }
                if let Some(v) = cfg.get("x_frame_options").and_then(|v| v.as_str()) {
                    x_frame_options.set(v.to_string());
                }
                if let Some(v) = cfg.get("x_content_type_options").and_then(|v| v.as_bool()) {
                    x_content_type.set(v);
                }
                if let Some(v) = cfg.get("referrer_policy").and_then(|v| v.as_str()) {
                    referrer_policy.set(v.to_string());
                }
            }
            || {}
        }
    });

    let on_save = {
        let saving = saving.clone();
        let hsts = hsts.clone();
        let hsts_max_age = hsts_max_age.clone();
        let x_frame_options = x_frame_options.clone();
        let x_content_type = x_content_type.clone();
        let referrer_policy = referrer_policy.clone();
        let site_id = props.site_id.clone();
        Callback::from(move |_| {
            let new_config = serde_json::json!({
                "hsts": *hsts,
                "hsts_max_age": hsts_max_age.parse::<u64>().unwrap_or(31536000),
                "x_frame_options": (*x_frame_options).clone(),
                "x_content_type_options": *x_content_type,
                "referrer_policy": (*referrer_policy).clone(),
            });
            let saving = saving.clone();
            let site_id = site_id.clone();
            saving.set(true);
            wasm_bindgen_futures::spawn_local(async move {
                let api = crate::services::ApiService::new();
                let _ = api.update_site(&site_id, &new_config).await;
                saving.set(false);
                toast_success("Security headers saved");
            });
        })
    };

    html! {
        <div class="space-y-6">
            <div>
                <h3 class="text-lg font-semibold mb-4">{ "Security Headers" }</h3>
                <div class="space-y-3">
                    <ToggleField label="HSTS (Strict-Transport-Security)" enabled={*hsts} />
                    <Input label="HSTS Max Age (secs)" name="hsts_max_age" value={(*hsts_max_age).clone()} input_type="number" help="How long browsers should remember to use HTTPS" />
                    <SelectWithTooltip label="X-Frame-Options" name="x_frame_options" value={(*x_frame_options).clone()} options={vec![("SAMEORIGIN".to_string(), "Same Origin".to_string()), ("DENY".to_string(), "Deny".to_string())]} help="Prevents clickjacking" tooltip_title="" tooltip_content="" />
                    <ToggleField label="X-Content-Type-Options" enabled={*x_content_type} />
                    <Input label="Referrer-Policy" name="referrer_policy" value={(*referrer_policy).clone()} help="How much referrer info to send" />
                </div>
            </div>
            <div class="flex justify-end">
                <button onclick={on_save} disabled={*saving} class="px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700 disabled:opacity-50">
                    { if *saving { "Saving..." } else { "Save Changes" } }
                </button>
            </div>
        </div>
    }
}

#[derive(Properties, PartialEq)]
struct StaticTabProps {
    config: Option<serde_json::Value>,
    site_id: String,
}

#[function_component]
fn StaticTab(_props: &StaticTabProps) -> Html {
    html! {
        <div class="space-y-6">
            <div>
                <h3 class="text-lg font-semibold mb-4">{ "Static File Serving" }</h3>
                <div class="space-y-3">
                    <ToggleField label="Enable Static Serving" enabled=false />
                    <Input label="Document Root" name="doc_root" value="/var/www/html" help="Path to static files directory" />
                    <Input label="Index File" name="index" value="index.html" help="Default file to serve for directory requests" />
                </div>
            </div>
            <div>
                <h3 class="text-lg font-semibold mb-4">{ "Caching" }</h3>
                <div class="grid grid-cols-2 gap-4">
                    <Input label="Cache Max Age (secs)" name="cache_max_age" value="3600" input_type="number" help="Browser cache duration" />
                    <Input label="ETag" name="etag" value="true" help="Enable ETag headers" />
                </div>
            </div>
        </div>
    }
}

#[derive(Properties, PartialEq)]
struct AuthTabProps {
    config: Option<serde_json::Value>,
    site_id: String,
}

#[function_component]
fn AuthTab(_props: &AuthTabProps) -> Html {
    html! {
        <div class="space-y-6">
            <div>
                <h3 class="text-lg font-semibold mb-4">{ "Site Authentication" }</h3>
                <div class="space-y-3">
                    <ToggleField label="Enable Site Auth" enabled=false />
                    <SelectWithTooltip label="Auth Type" name="auth_type" value="basic" options={vec![("basic".to_string(), "HTTP Basic".to_string()), ("bearer".to_string(), "Bearer Token".to_string()), ("jwt".to_string(), "JWT".to_string())]} help="Authentication method" tooltip_title="" tooltip_content="" />
                    <Input label="Realm" name="realm" value="Restricted" help="Authentication realm shown to browsers" />
                </div>
            </div>
            <div>
                <h3 class="text-lg font-semibold mb-4">{ "Allowed Paths" }</h3>
                <textarea class="w-full px-3 py-2 bg-tertiary border border-default rounded-lg font-mono text-sm" rows="4" value={"/health\n/public/*"} />
                <p class="mt-1 text-xs text-secondary">{ "Paths that don't require authentication (one per line)" }</p>
            </div>
        </div>
    }
}

#[derive(Properties, PartialEq)]
struct WebSocketTabProps {
    config: Option<serde_json::Value>,
    site_id: String,
}

#[function_component]
fn WebSocketTab(_props: &WebSocketTabProps) -> Html {
    html! {
        <div class="space-y-6">
            <div>
                <h3 class="text-lg font-semibold mb-4">{ "WebSocket Proxy" }</h3>
                <div class="space-y-3">
                    <ToggleField label="Enable WebSocket Proxy" enabled=true />
                    <Input label="Max Frame Size" name="max_frame_size" value="65536" input_type="number" help="Maximum WebSocket frame size in bytes" />
                    <Input label="Idle Timeout (secs)" name="ws_idle_timeout" value="300" input_type="number" help="Close idle connections after this period" />
                </div>
            </div>
            <div>
                <h3 class="text-lg font-semibold mb-4">{ "Subprotocols" }</h3>
                <textarea class="w-full px-3 py-2 bg-tertiary border border-default rounded-lg font-mono text-sm" rows="3" value={"wamp\nmqtt"} />
                <p class="mt-1 text-xs text-secondary">{ "Allowed WebSocket subprotocols (one per line)" }</p>
            </div>
        </div>
    }
}

#[derive(Properties, PartialEq)]
struct GrpcTabProps {
    config: Option<serde_json::Value>,
    site_id: String,
}

#[function_component]
fn GrpcTab(_props: &GrpcTabProps) -> Html {
    html! {
        <div class="space-y-6">
            <div>
                <h3 class="text-lg font-semibold mb-4">{ "gRPC Proxy" }</h3>
                <div class="space-y-3">
                    <ToggleField label="Enable gRPC Proxy" enabled=false />
                    <Input label="Max Message Size" name="max_msg_size" value="4194304" input_type="number" help="Maximum gRPC message size in bytes (default 4MB)" />
                    <Input label="Max Header List Size" name="max_header_list" value="8192" input_type="number" help="Maximum header list size in bytes" />
                </div>
            </div>
            <div>
                <h3 class="text-lg font-semibold mb-4">{ "HTTP/2 Settings" }</h3>
                <div class="grid grid-cols-2 gap-4">
                    <Input label="Max Concurrent Streams" name="max_streams" value="100" input_type="number" />
                    <Input label="Initial Window Size" name="init_window" value="65535" input_type="number" />
                </div>
            </div>
        </div>
    }
}

#[derive(Properties, PartialEq)]
struct TunnelTabProps {
    config: Option<serde_json::Value>,
    site_id: String,
}

#[function_component]
fn TunnelTab(_props: &TunnelTabProps) -> Html {
    html! {
        <div class="space-y-6">
            <div>
                <h3 class="text-lg font-semibold mb-4">{ "Tunnel Settings" }</h3>
                <div class="space-y-3">
                    <ToggleField label="Enable Tunnel" enabled=false />
                    <Input label="Tunnel Port" name="tunnel_port" value="8443" input_type="number" help="Port for tunnel connections" />
                    <SelectWithTooltip label="Protocol" name="tunnel_proto" value="wireguard" options={vec![("wireguard".to_string(), "WireGuard".to_string()), ("quic".to_string(), "QUIC".to_string())]} help="Tunnel protocol" tooltip_title="" tooltip_content="" />
                </div>
            </div>
            <div>
                <h3 class="text-lg font-semibold mb-4">{ "Connection Limits" }</h3>
                <div class="grid grid-cols-2 gap-4">
                    <Input label="Max Peers" name="max_peers" value="100" input_type="number" />
                    <Input label="Keepalive Interval (secs)" name="keepalive" value="25" input_type="number" />
                </div>
            </div>
        </div>
    }
}
