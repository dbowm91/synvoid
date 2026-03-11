use yew::prelude::*;
use yew_router::prelude::*;
use wasm_bindgen::JsCast;

use crate::app::Route;
use crate::services::ApiService;
use crate::components::tooltip::{HelpIcon, Tooltip, TooltipPosition};
use crate::components::{toast_success, toast_error};
use crate::types::presets::{get_presets, ServerPreset};

#[derive(Properties, PartialEq)]
pub struct SiteEditorProps {
    pub id: String,
}

#[function_component]
pub fn SiteEditor(props: &SiteEditorProps) -> Html {
    let active_tab = use_state(|| "basic".to_string());
    let selected_preset = use_state(|| Option::<ServerPreset>::None);

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
                    </nav>
                </div>

                <div class="p-6">
                    { match active_tab.as_str() {
                        "basic" => html! { <BasicTab presets={presets} on_preset_select={on_preset_select} selected_preset={(*selected_preset).clone()} /> },
                        "ratelimit" => html! { <RateLimitTab /> },
                        "blocking" => html! { <BlockingTab /> },
                        "attacks" => html! { <AttacksTab /> },
                        "bot" => html! { <BotTab /> },
                        "upload" => html! { <UploadTab /> },
                        "error_pages" => html! { <ErrorPagesTab site_id={props.id.clone()} /> },
                        _ => html! { <BasicTab presets={presets} on_preset_select={on_preset_select} selected_preset={(*selected_preset).clone()} /> },
                    }}
                </div>

                <div class="p-4 border-t border-default flex justify-end gap-4">
                    <button class="px-4 py-2 bg-tertiary text-primary rounded-lg hover:opacity-80">
                        { "Cancel" }
                    </button>
                    <button class="px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700">
                        { "Save Changes" }
                    </button>
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
}

#[function_component]
fn BasicTab(props: &BasicTabProps) -> Html {
    let presets = props.presets.clone();
    let on_preset_select = props.on_preset_select.clone();

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

            <div>
                <h3 class="text-lg font-semibold mb-4">{ "Site Information" }</h3>
                <div class="grid grid-cols-1 md:grid-cols-2 gap-4">
                    <InputWithTooltip
                        label="Domains (comma separated)"
                        name="domains"
                        value="example.com, www.example.com"
                        help="First domain is used as the site identifier"
                        tooltip_title="Domain Configuration"
                        tooltip_content="Enter all domains and subdomains that should be handled by this site. The first domain is used as the unique identifier. Use commas to separate multiple domains."
                    />
                    <InputWithTooltip
                        label="Default Upstream"
                        name="upstream"
                        value="http://127.0.0.1:8000"
                        help="Backend server to forward requests to"
                        tooltip_title="Upstream Backend"
                        tooltip_content="The URL of the backend server that will handle requests. Can be HTTP or HTTPS. For local development, typically http://127.0.0.1:8000"
                    />
                </div>
            </div>

            <div>
                <h3 class="text-lg font-semibold mb-4 flex items-center">
                    { "Path Routes" }
                    <HelpIcon
                        content="Define URL path prefixes and their corresponding upstream servers. Requests matching a prefix will be routed to the specified upstream."
                        title="Path-Based Routing"
                    />
                </h3>
                <div class="space-y-3">
                    <div class="flex gap-4">
                        <input
                            type="text"
                            value="/api"
                            class="flex-1 px-3 py-2 bg-tertiary border border-default rounded-lg"
                            placeholder="Path prefix"
                        />
                        <input
                            type="text"
                            value="http://api.internal:8001"
                            class="flex-1 px-3 py-2 bg-tertiary border border-default rounded-lg"
                            placeholder="Upstream URL"
                        />
                        <button class="px-3 py-2 bg-red-600 text-white rounded-lg">{"Remove"}</button>
                    </div>
                </div>
                <button class="mt-3 px-4 py-2 bg-tertiary text-primary rounded-lg hover:opacity-80">
                    { "+ Add Route" }
                </button>
            </div>
        </div>
    }
}

#[derive(Properties, PartialEq)]
struct InputWithTooltipProps {
    label: String,
    name: String,
    value: String,
    help: String,
    tooltip_title: String,
    tooltip_content: String,
    #[prop_or_default]
    input_type: String,
}

#[function_component]
fn InputWithTooltip(props: &InputWithTooltipProps) -> Html {
    let name = props.name.clone();
    let value = props.value.clone();
    let label = props.label.clone();
    let input_type = if props.input_type.is_empty() {
        "text".to_string()
    } else {
        props.input_type.clone()
    };

    html! {
        <div class="mb-4">
            <label class="flex items-center gap-1 text-sm font-medium text-primary mb-1" for={name.clone()}>
                { label }
                <Tooltip content={props.tooltip_content.clone()} title={props.tooltip_title.clone()} position={TooltipPosition::Right}>
                    <span class="inline-flex items-center justify-center w-4 h-4 rounded-full bg-tertiary text-secondary text-xs cursor-help hover:bg-blue-600 hover:text-white transition-colors">
                        {"?"}
                    </span>
                </Tooltip>
            </label>
            <input
                type={input_type}
                id={name.clone()}
                name={name}
                value={value}
                class="w-full px-3 py-2 bg-tertiary border border-default rounded-lg text-primary focus:outline-none focus:ring-2 focus:ring-blue-500"
            />
            <p class="mt-1 text-xs text-secondary">{ props.help.clone() }</p>
        </div>
    }
}

#[function_component]
fn RateLimitTab() -> Html {
    html! {
        <div class="space-y-6">
            <div>
                <h3 class="text-lg font-semibold mb-4 flex items-center">
                    { "Rate Limiting Mode" }
                    <HelpIcon
                        content="Shared mode applies global rate limits from main config to all sites. Isolated mode allows each site to have its own rate limits."
                        title="Rate Limit Mode"
                    />
                </h3>
                <div class="grid grid-cols-1 md:grid-cols-2 gap-4">
                    <SelectWithTooltip
                        label="Mode"
                        name="ratelimit_mode"
                        value="isolated"
                        options={vec![
                            ("shared".to_string(), "Shared (use global limits)".to_string()),
                            ("isolated".to_string(), "Isolated (site-specific limits)".to_string()),
                        ]}
                        help="Shared mode uses limits from main config, isolated uses per-site limits"
                        tooltip_title="Rate Limit Mode"
                        tooltip_content="Shared: All sites share the same rate limits from the main config. \n\nIsolated: Each site can have its own independent rate limits, configured in the per-IP and global sections below."
                    />
                </div>
            </div>

            <div>
                <h3 class="text-lg font-semibold mb-4">{ "Per-IP Limits" }</h3>
                <p class="text-sm text-secondary mb-4">
                    { "Limits apply to each unique client IP address." }
                </p>
                <div class="grid grid-cols-2 md:grid-cols-4 gap-4">
                    <InputWithTooltip label="Per Second" name="per_second" value="10" help="Requests per second per IP" tooltip_title="Per-Second Limit" tooltip_content="Maximum number of requests a single IP can make per second. This is the most granular rate limit." />
                    <InputWithTooltip label="Per Minute" name="per_minute" value="60" help="Requests per minute per IP" tooltip_title="Per-Minute Limit" tooltip_content="Maximum number of requests a single IP can make per minute." />
                    <InputWithTooltip label="Per Hour" name="per_hour" value="500" help="Requests per hour per IP" tooltip_title="Per-Hour Limit" tooltip_content="Maximum number of requests a single IP can make per hour." />
                    <InputWithTooltip label="Burst" name="burst" value="20" help="Allow bursts up to this size" tooltip_title="Burst Allowance" tooltip_content="Allows short bursts of traffic above the per-second limit. The burst size represents how many requests can be made in quick succession." />
                </div>
            </div>

            <div>
                <h3 class="text-lg font-semibold mb-4">{ "Global Site Limits" }</h3>
                <p class="text-sm text-secondary mb-4">
                    { "Limits apply to the entire site across all IPs." }
                </p>
                <div class="grid grid-cols-2 md:grid-cols-3 gap-4">
                    <InputWithTooltip label="Per Second" name="global_per_second" value="500" help="Requests per second total" tooltip_title="Global Per-Second" tooltip_content="Maximum total requests per second across all IPs for this site." />
                    <InputWithTooltip label="Per Minute" name="global_per_minute" value="5000" help="Requests per minute total" tooltip_title="Global Per-Minute" tooltip_content="Maximum total requests per minute across all IPs for this site." />
                    <InputWithTooltip label="Max Connections" name="max_connections" value="1000" help="Maximum concurrent connections" tooltip_title="Max Connections" tooltip_content="Maximum number of concurrent connections allowed to this site at any time." />
                </div>
            </div>
        </div>
    }
}

#[derive(Properties, PartialEq)]
struct SelectWithTooltipProps {
    label: String,
    name: String,
    value: String,
    options: Vec<(String, String)>,
    help: String,
    tooltip_title: String,
    tooltip_content: String,
}

#[function_component]
fn SelectWithTooltip(props: &SelectWithTooltipProps) -> Html {
    let name = props.name.clone();
    let value = props.value.clone();
    let label = props.label.clone();

    html! {
        <div class="mb-4">
            <label class="flex items-center gap-1 text-sm font-medium text-primary mb-1" for={name.clone()}>
                { label }
                <Tooltip content={props.tooltip_content.clone()} title={props.tooltip_title.clone()} position={TooltipPosition::Right}>
                    <span class="inline-flex items-center justify-center w-4 h-4 rounded-full bg-tertiary text-secondary text-xs cursor-help hover:bg-blue-600 hover:text-white transition-colors">
                        {"?"}
                    </span>
                </Tooltip>
            </label>
            <select
                id={name.clone()}
                name={name}
                value={value}
                class="w-full px-3 py-2 bg-tertiary border border-default rounded-lg text-primary focus:outline-none focus:ring-2 focus:ring-blue-500"
            >
                {for props.options.iter().map(|(val, text)| {
                    html! {
                        <option value={val.clone()}>{ text }</option>
                    }
                })}
            </select>
            <p class="mt-1 text-xs text-secondary">{ props.help.clone() }</p>
        </div>
    }
}

#[function_component]
fn BlockingTab() -> Html {
    html! {
        <div class="space-y-6">
            <div>
                <h3 class="text-lg font-semibold mb-4 flex items-center">
                    { "Blocked Paths" }
                    <HelpIcon
                        content="Paths that should be blocked from access. Supports glob patterns like *.sql, .git/*, etc. One pattern per line."
                        title="Path Blocking"
                    />
                </h3>
                <textarea
                    class="w-full px-3 py-2 bg-tertiary border border-default rounded-lg font-mono text-sm"
                    rows="6"
                    placeholder="One path per line..."
                    value={".env\n.git\n.svn\nwp-config.php"}
                />
                <p class="mt-1 text-xs text-secondary">{ "One path per line. Glob patterns supported." }</p>
            </div>

            <div>
                <h3 class="text-lg font-semibold mb-4">{ "Block Settings" }</h3>
                <div class="grid grid-cols-2 gap-4">
                    <SelectWithTooltip
                        label="Block Response Code"
                        name="block_response_code"
                        value="403"
                        options={vec![
                            ("403".to_string(), "403 Forbidden".to_string()),
                            ("404".to_string(), "404 Not Found".to_string()),
                            ("410".to_string(), "410 Gone".to_string()),
                        ]}
                        help="HTTP status code to return for blocked requests"
                        tooltip_title="Response Code"
                        tooltip_content="403 Forbidden: Explicitly denies access (recommended)\n404 Not Found: Pretends the file doesn't exist\n410 Gone: Indicates the resource is permanently removed"
                    />
                    <SelectWithTooltip
                        label="Pattern Matching"
                        name="use_regex"
                        value="false"
                        options={vec![
                            ("false".to_string(), "Glob patterns".to_string()),
                            ("true".to_string(), "Regular expressions".to_string()),
                        ]}
                        help="Use glob or regex for path matching"
                        tooltip_title="Pattern Matching"
                        tooltip_content="Glob patterns: Simple wildcard matching (* matches any characters)\n\nRegex: Full regular expression support for advanced matching"
                    />
                </div>
            </div>
        </div>
    }
}

#[function_component]
fn AttacksTab() -> Html {
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

#[function_component]
fn BotTab() -> Html {
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

#[function_component]
fn UploadTab() -> Html {
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

    {
        let selected_preset = selected_preset.clone();
        let preview_html = preview_html.clone();
        let preview_light = preview_light.clone();
        let site_id = props.site_id.clone();
        use_effect_with((), move |_| {
            wasm_bindgen_futures::spawn_local(async move {
                let api = crate::services::ApiService::new();
                match api.get_site_theme(&site_id).await {
                    Ok(data) => {
                        if let Some(theme) = data {
                            let preset = theme.preset.unwrap_or_else(|| "default".to_string());
                            selected_preset.set(preset.clone());
                            let colors = get_preset_colors(&preset);
                            let use_light = *preview_light;
                            let html = generate_error_page_preview("", &colors, use_light);
                            preview_html.set(html);
                        }
                    }
                    Err(e) => {
                        tracing::error!("Failed to fetch site theme: {}", e);
                    }
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
            let value = target.dyn_ref::<web_sys::HtmlSelectElement>()
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

    let on_save = {
        let saving = saving.clone();
        let selected_preset = selected_preset.clone();
        let site_id = props.site_id.clone();
        Callback::from(move |_| {
            let preset = (*selected_preset).clone();
            let site_id = site_id.clone();
            let saving = saving.clone();
            
            saving.set(true);
            
            wasm_bindgen_futures::spawn_local(async move {
                let api = crate::services::ApiService::new();
                let request = crate::types::UpdateThemeRequest {
                    preset: Some(preset),
                    mode: None,
                    allow_only: None,
                };
                
                match api.update_site_theme(&site_id, &request).await {
                    Ok(_) => {
                        toast_success("Site theme updated successfully");
                        tracing::info!("Site theme updated successfully");
                    }
                    Err(e) => {
                        toast_error(&format!("Failed to update site theme: {}", e));
                        tracing::error!("Failed to update site theme: {}", e);
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

    html! {
        <div class="space-y-6">
            <div>
                <label class="block text-sm font-medium text-primary mb-2">{ "Error Page Theme" }</label>
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
                <p class="mt-1 text-sm text-secondary">{ "Theme for error pages shown when requests are blocked" }</p>
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
                <p class="mt-1 text-sm text-secondary">{ "Preview of the error page with selected theme" }</p>
            </div>

            <div class="flex justify-end gap-4">
                <button 
                    onclick={on_save}
                    disabled={*saving}
                    class="px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700 disabled:opacity-50"
                >
                    { if *saving { "Saving..." } else { "Save Theme" } }
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

fn generate_error_page_preview(_css: &str, colors: &crate::types::ThemeColorsResponse, use_light: bool) -> String {
    let c = if use_light { &colors.light } else { &colors.dark };
    format!(r#"
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
