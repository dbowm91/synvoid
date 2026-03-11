use crate::components::forms::{Input, Select};
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
                        <SectionButton label="Bot Defaults" section="bot" active={*active_section == "bot"} on_click={on_section_click.clone()} />
                        <SectionButton label="Upload" section="upload" active={*active_section == "upload"} on_click={on_section_click.clone()} />
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
                                "bot" => "Bot Protection Defaults",
                                "upload" => "Upload Defaults",
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
                            "bot" => html! { <BotSection /> },
                            "upload" => html! { <UploadSection /> },
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
