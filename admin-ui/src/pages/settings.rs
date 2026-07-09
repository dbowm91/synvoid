use crate::components::forms::{Input, Select};
use crate::components::skeleton::LoadingSpinner;
use crate::components::{toast_error, toast_success};
use crate::config_docs::get_section_doc;
use crate::services::ApiService;
use crate::types::{ThemeResponse, UpdateThemeRequest};
use wasm_bindgen::JsCast;
use yew::prelude::*;

fn restart_badge() -> Html {
    html! {
        <span class="ml-2 inline-flex items-center px-1.5 py-0.5 rounded text-[10px] font-medium bg-yellow-500/20 text-yellow-400 border border-yellow-500/30">
            { "Requires restart" }
        </span>
    }
}

fn bytes_to_human(bytes: usize) -> String {
    if bytes >= 1_073_741_824 {
        format!("{}GB", bytes / 1_073_741_824)
    } else if bytes >= 1_048_576 {
        format!("{}MB", bytes / 1_048_576)
    } else if bytes >= 1024 {
        format!("{}KB", bytes / 1024)
    } else {
        format!("{}", bytes)
    }
}

fn human_to_bytes(s: &str) -> usize {
    let s = s.trim().to_uppercase();
    if let Some(val) = s.strip_suffix("GB") {
        val.trim().parse::<usize>().unwrap_or(0) * 1_073_741_824
    } else if let Some(val) = s.strip_suffix("MB") {
        val.trim().parse::<usize>().unwrap_or(0) * 1_048_576
    } else if let Some(val) = s.strip_suffix("KB") {
        val.trim().parse::<usize>().unwrap_or(0) * 1024
    } else {
        s.parse::<usize>().unwrap_or(0)
    }
}

fn export_config_to_file(json: &str) {
    let blob = web_sys::Blob::new_with_str_sequence(&js_sys::Array::of1(&json.into())).unwrap();
    let url = web_sys::Url::create_object_url_with_blob(&blob).unwrap();
    let window = web_sys::window().unwrap();
    let document = window.document().unwrap();
    let a = document.create_element("a").unwrap();
    a.set_attribute("href", &url).unwrap();
    a.set_attribute("download", "synvoid-config.json").unwrap();
    let _ = a.dispatch_event(&web_sys::MouseEvent::new("click").unwrap());
}

#[function_component]
pub fn Settings() -> Html {
    let active_section = use_state(|| "server".to_string());
    let exporting = use_state(|| false);
    let importing = use_state(|| false);
    let search_query = use_state(String::new);
    let show_search_results = use_state(|| false);

    let settings_search_index: std::collections::HashMap<
        String,
        Vec<(&'static str, &'static str)>,
    > = {
        let mut m = std::collections::HashMap::new();
        m.insert(
            "server".to_string(),
            vec![
                ("bind", "server"),
                ("listen", "server"),
                ("worker", "server"),
                ("pid", "server"),
                ("user", "server"),
                ("group", "server"),
                ("upgrade", "server"),
                ("error log", "server"),
                ("max connections", "server"),
            ],
        );
        m.insert(
            "http".to_string(),
            vec![
                ("keep-alive", "http"),
                ("timeout", "http"),
                ("max request size", "http"),
                ("chunked", "http"),
                ("gzip", "http"),
                ("brotli", "http"),
                ("http/2", "http"),
                ("http/3", "http"),
                ("pipeline", "http"),
            ],
        );
        m.insert(
            "logging".to_string(),
            vec![
                ("syslog", "logging"),
                ("log level", "logging"),
                ("access log", "logging"),
                ("error log", "logging"),
                ("format", "logging"),
                ("buffer", "logging"),
            ],
        );
        m.insert(
            "metrics".to_string(),
            vec![
                ("prometheus", "metrics"),
                ("influxdb", "metrics"),
                ("graphite", "metrics"),
                ("statsd", "metrics"),
                ("interval", "metrics"),
            ],
        );
        m.insert(
            "ratelimits".to_string(),
            vec![
                ("requests per second", "ratelimits"),
                ("rps", "ratelimits"),
                ("burst", "ratelimits"),
                ("limit", "ratelimits"),
                ("throttle", "ratelimits"),
            ],
        );
        m.insert(
            "bandwidth".to_string(),
            vec![
                ("bandwidth", "bandwidth"),
                ("rate limit", "bandwidth"),
                ("quota", "bandwidth"),
                ("transfer", "bandwidth"),
                ("upload", "bandwidth"),
                ("download", "bandwidth"),
            ],
        );
        m.insert(
            "bot".to_string(),
            vec![
                ("bot", "bot"),
                ("captcha", "bot"),
                ("challenge", "bot"),
                ("headless", "bot"),
                ("browser", "bot"),
                ("fingerprint", "bot"),
            ],
        );
        m.insert(
            "tarpit".to_string(),
            vec![
                ("tarpit", "tarpit"),
                ("scraper", "tarpit"),
                ("trap", "tarpit"),
                ("honeypot", "tarpit"),
                ("depth", "tarpit"),
                ("delay", "tarpit"),
            ],
        );
        m.insert(
            "upload".to_string(),
            vec![
                ("upload", "upload"),
                ("max size", "upload"),
                ("body size", "upload"),
                ("file", "upload"),
                ("mime", "upload"),
                ("extension", "upload"),
            ],
        );
        m.insert(
            "ip_feeds".to_string(),
            vec![
                ("ip feed", "ip_feeds"),
                ("blocklist", "ip_feeds"),
                ("block list", "ip_feeds"),
                ("threat intel", "ip_feeds"),
                ("geoip", "ip_feeds"),
            ],
        );
        m.insert(
            "security".to_string(),
            vec![
                ("security", "security"),
                ("ipc", "security"),
                ("signing", "security"),
                ("headers", "security"),
                ("x-forwarded", "security"),
            ],
        );
        m.insert(
            "tunnel".to_string(),
            vec![
                ("tunnel", "tunnel"),
                ("vpn", "tunnel"),
                ("wireguard", "tunnel"),
                ("quic", "tunnel"),
                ("mesh", "tunnel"),
            ],
        );
        m.insert(
            "plugins".to_string(),
            vec![
                ("plugins", "plugins"),
                ("wasm", "plugins"),
                ("extension", "plugins"),
            ],
        );
        m.insert(
            "theme".to_string(),
            vec![
                ("theme", "theme"),
                ("dark", "theme"),
                ("light", "theme"),
                ("color", "theme"),
                ("css", "theme"),
                ("logo", "theme"),
            ],
        );
        m.insert(
            "yara".to_string(),
            vec![
                ("yara", "yara"),
                ("rule", "yara"),
                ("malware", "yara"),
                ("scanner", "yara"),
            ],
        );
        m.insert(
            "serverless".to_string(),
            vec![
                ("serverless", "serverless"),
                ("wasm", "serverless"),
                ("function", "serverless"),
                ("plugin", "serverless"),
            ],
        );
        m.insert(
            "process".to_string(),
            vec![
                ("process", "process"),
                ("worker", "process"),
                ("master", "process"),
                ("overseer", "process"),
                ("status", "process"),
            ],
        );
        m.insert(
            "defaults".to_string(),
            vec![
                ("defaults", "defaults"),
                ("default", "defaults"),
                ("ratelimit", "defaults"),
                ("upload", "defaults"),
            ],
        );
        m.insert(
            "dns".to_string(),
            vec![
                ("dns", "dns"),
                ("domain", "dns"),
                ("resolver", "dns"),
                ("nameserver", "dns"),
            ],
        );
        m.insert(
            "mime_types".to_string(),
            vec![
                ("mime", "mime_types"),
                ("content-type", "mime_types"),
                ("type", "mime_types"),
            ],
        );
        m.insert(
            "tcp_udp_defaults".to_string(),
            vec![
                ("tcp", "tcp_udp_defaults"),
                ("udp", "tcp_udp_defaults"),
                ("network", "tcp_udp_defaults"),
            ],
        );
        m.insert(
            "fallback".to_string(),
            vec![("fallback", "fallback"), ("default", "fallback")],
        );
        m.insert(
            "upgrade".to_string(),
            vec![
                ("upgrade", "upgrade"),
                ("http", "upgrade"),
                ("h2", "upgrade"),
            ],
        );
        m
    };

    let search_results = if !(*search_query).is_empty() && *show_search_results {
        let query = search_query.to_lowercase();
        let mut results: Vec<(String, String)> = Vec::new();
        for (section, keywords) in &settings_search_index {
            for (keyword, _) in keywords {
                if (keyword.to_lowercase().contains(&query) || query.contains(keyword))
                    && !results.iter().any(|(s, _)| *s == *section)
                {
                    let label: String = match section.as_str() {
                        "server" => "Server".to_string(),
                        "http" => "HTTP".to_string(),
                        "logging" => "Logging".to_string(),
                        "metrics" => "Metrics".to_string(),
                        "ratelimits" => "Rate Limits".to_string(),
                        "bandwidth" => "Bandwidth".to_string(),
                        "bot" => "Bot Defaults".to_string(),
                        "tarpit" => "Tarpit".to_string(),
                        "ip_feeds" => "IP Feeds".to_string(),
                        "tls" => "TLS".to_string(),
                        "acme" => "ACME".to_string(),
                        "http3" => "HTTP/3".to_string(),
                        "upload" => "Upload".to_string(),
                        "theme" => "Theme".to_string(),
                        _ => section.clone(),
                    };
                    results.push((section.clone(), label));
                }
            }
        }
        results
    } else {
        Vec::new()
    };

    let on_search = {
        let search_query = search_query.clone();
        let show_search_results = show_search_results.clone();
        Callback::from(move |e: InputEvent| {
            let input: web_sys::HtmlInputElement = e.target_unchecked_into();
            search_query.set(input.value());
            show_search_results.set(true);
        })
    };

    let on_search_blur = {
        let show_search_results = show_search_results.clone();
        Callback::from(move |_| {
            let show_search_results = show_search_results.clone();
            wasm_bindgen_futures::spawn_local(async move {
                tokio::time::sleep(std::time::Duration::from_millis(200)).await;
                show_search_results.set(false);
            });
        })
    };

    let on_section_click = {
        let active_section = active_section.clone();
        let show_search_results = show_search_results.clone();
        let search_query = search_query.clone();
        Callback::from(move |section: String| {
            active_section.set(section);
            show_search_results.set(false);
            search_query.set(String::new());
        })
    };

    let on_export = {
        let exporting = exporting.clone();
        Callback::from(move |_: MouseEvent| {
            let exporting = exporting.clone();
            exporting.set(true);
            wasm_bindgen_futures::spawn_local(async move {
                let api = ApiService::new();
                match api.export_config().await {
                    Ok(data) => {
                        let json = serde_json::to_string_pretty(&data)
                            .unwrap_or_else(|_| "{}".to_string());
                        export_config_to_file(&json);
                        toast_success("Configuration exported");
                    }
                    Err(e) => {
                        toast_error(&format!("Export failed: {}", e));
                    }
                }
                exporting.set(false);
            });
        })
    };

    let on_import = {
        let importing = importing.clone();
        Callback::from(move |_: MouseEvent| {
            let importing = importing.clone();
            let window = web_sys::window().unwrap();
            let document = window.document().unwrap();
            let input: web_sys::HtmlInputElement = document
                .create_element("input")
                .unwrap()
                .dyn_into()
                .unwrap();
            input.set_type("file");
            input.set_accept(".json");

            let importing_clone = importing.clone();
            let input_clone = input.clone();
            let closure = wasm_bindgen::closure::Closure::wrap(Box::new(move |_: web_sys::Event| {
                let input: web_sys::HtmlInputElement = input_clone.clone().dyn_into().unwrap();
                if let Some(files) = input.files() {
                    if let Some(file) = files.get(0) {
                        let importing = importing_clone.clone();
                        importing.set(true);
                        let reader = web_sys::FileReader::new().unwrap();
                        let reader_clone = reader.clone();
                        let read_closure = wasm_bindgen::closure::Closure::wrap(Box::new(
                            move |_: web_sys::Event| {
                                let result = reader_clone.result().unwrap();
                                let text = result.as_string().unwrap();
                                let importing = importing.clone();
                                wasm_bindgen_futures::spawn_local(async move {
                                    let api = ApiService::new();
                                    match serde_json::from_str::<serde_json::Value>(&text) {
                                        Ok(config) => match api.import_config(&config).await {
                                            Ok(_) => {
                                                toast_success("Configuration imported successfully")
                                            }
                                            Err(e) => toast_error(&format!("Import failed: {}", e)),
                                        },
                                        Err(e) => toast_error(&format!("Invalid JSON: {}", e)),
                                    }
                                    importing.set(false);
                                });
                            },
                        )
                            as Box<dyn FnMut(web_sys::Event)>);
                        let _ = reader.add_event_listener_with_callback(
                            "load",
                            read_closure.as_ref().unchecked_ref(),
                        );
                        read_closure.forget();
                        let _ = reader.read_as_text(&file);
                    }
                }
            })
                as Box<dyn FnMut(web_sys::Event)>);
            let _ =
                input.add_event_listener_with_callback("change", closure.as_ref().unchecked_ref());
            closure.forget();
            input.click();
        })
    };

    html! {
        <div>
            <div class="flex justify-between items-center mb-6">
                <h1 class="text-2xl font-bold">{ "Global Settings" }</h1>
                <div class="flex gap-2">
                    <button
                        onclick={on_export}
                        disabled={*exporting}
                        class="px-3 py-2 bg-tertiary text-secondary rounded-lg hover:text-primary text-sm disabled:opacity-50"
                    >
                        { if *exporting { "Exporting..." } else { "Export Config" } }
                    </button>
                    <button
                        onclick={on_import}
                        disabled={*importing}
                        class="px-3 py-2 bg-tertiary text-secondary rounded-lg hover:text-primary text-sm disabled:opacity-50"
                    >
                        { if *importing { "Importing..." } else { "Import Config" } }
                    </button>
                </div>
            </div>

            <div class="mb-4 relative">
                <div class="relative">
                    <input
                        type="text"
                        placeholder="Search settings..."
                        value={(*search_query).clone()}
                        oninput={on_search}
                        onblur={on_search_blur}
                        onfocus={{
                            let show_search_results = show_search_results.clone();
                            Callback::from(move |_| {
                                show_search_results.set(true);
                            })
                        }}
                        class="w-full px-4 py-2 pl-10 bg-tertiary border border-default rounded-lg text-primary focus:outline-none focus:ring-2 focus:ring-blue-500"
                    />
                    <svg class="w-4 h-4 absolute left-3 top-1/2 transform -translate-y-1/2 text-secondary" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z" />
                    </svg>
                </div>
                if *show_search_results && !search_results.is_empty() {
                    <div class="absolute z-10 w-full mt-1 bg-secondary border border-default rounded-lg shadow-lg max-h-64 overflow-auto">
                        { for search_results.iter().map(|(section, label)| {
                            let section_clone = section.clone();
                            let label_clone = label.clone();
                            html! {
                                <button
                                    onclick={{
                                        let section = section_clone.clone();
                                        let on_section_click = on_section_click.clone();
                                        Callback::from(move |_| {
                                            on_section_click.emit(section.clone());
                                        })
                                    }}
                                    class="block w-full text-left px-4 py-2 text-primary hover:bg-tertiary"
                                >
                                    { label_clone }
                                    <span class="text-secondary text-sm ml-2">{ format!("({})", section_clone) }</span>
                                </button>
                            }
                        }) }
                    </div>
                } else if *show_search_results && !(*search_query).is_empty() && search_results.is_empty() {
                    <div class="absolute z-10 w-full mt-1 bg-secondary border border-default rounded-lg shadow-lg">
                        <div class="px-4 py-2 text-secondary">{ "No results found" }</div>
                    </div>
                }
            </div>

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
                        <SectionButton label="Tarpit" section="tarpit" active={*active_section == "tarpit"} on_click={on_section_click.clone()} />
                        <SectionButton label="IP Feeds" section="ip_feeds" active={*active_section == "ip_feeds"} on_click={on_section_click.clone()} />
                        <SectionButton label="Security" section="security" active={*active_section == "security"} on_click={on_section_click.clone()} />
                        <SectionButton label="TLS" section="tls" active={*active_section == "tls"} on_click={on_section_click.clone()} />
                        <SectionButton label="ACME" section="acme" active={*active_section == "acme"} on_click={on_section_click.clone()} />
                        <SectionButton label="HTTP/3" section="http3" active={*active_section == "http3"} on_click={on_section_click.clone()} />
                        <SectionButton label="Tunnel" section="tunnel" active={*active_section == "tunnel"} on_click={on_section_click.clone()} />
                        <SectionButton label="Plugins" section="plugins" active={*active_section == "plugins"} on_click={on_section_click.clone()} />
                        <SectionButton label="Upload" section="upload" active={*active_section == "upload"} on_click={on_section_click.clone()} />
                        <SectionButton label="Mime Types" section="mime_types" active={*active_section == "mime_types"} on_click={on_section_click.clone()} />
                        <SectionButton label="TCP/UDP" section="tcp_udp_defaults" active={*active_section == "tcp_udp_defaults"} on_click={on_section_click.clone()} />
                        <SectionButton label="Fallback" section="fallback" active={*active_section == "fallback"} on_click={on_section_click.clone()} />
                        <SectionButton label="Upgrade" section="upgrade" active={*active_section == "upgrade"} on_click={on_section_click.clone()} />
                        <SectionButton label="Theme" section="theme" active={*active_section == "theme"} on_click={on_section_click.clone()} />
                        <SectionButton label="YARA Rules" section="yara" active={*active_section == "yara"} on_click={on_section_click.clone()} />
                        <SectionButton label="Serverless" section="serverless" active={*active_section == "serverless"} on_click={on_section_click.clone()} />
                        <SectionButton label="Process Status" section="process" active={*active_section == "process"} on_click={on_section_click.clone()} />
                        <SectionButton label="Defaults" section="defaults" active={*active_section == "defaults"} on_click={on_section_click.clone()} />
                        <SectionButton label="DNS" section="dns" active={*active_section == "dns"} on_click={on_section_click.clone()} />
                    </div>
                </nav>

                <div class="flex-1 bg-secondary rounded-lg border border-default">
                    <div class="p-6 border-b border-default flex items-center justify-between">
                        <h2 class="text-lg font-semibold">
                        { match active_section.as_str() {
                             "server" => "Server Configuration",
                             "http" => "HTTP Settings",
                             "logging" => "Logging Configuration",
                             "metrics" => "Metrics Configuration",
                             "ratelimits" => "Rate Limit Configuration",
                             "bandwidth" => "Bandwidth Limits",
                             "bot" => "Bot Protection Defaults",
                             "tarpit" => "Tarpit Configuration",
                             "ip_feeds" => "IP Feeds Configuration",
                             "security" => "Security Configuration",
                             "tls" => "TLS Configuration",
                             "acme" => "ACME Configuration",
                             "http3" => "HTTP/3 Configuration",
                             "tunnel" => "Tunnel/VPN Configuration",
                             "plugins" => "Plugins Configuration",
                             "upload" => "Upload Configuration",
                             "mime_types" => "MIME Types Configuration",
                             "tcp_udp_defaults" => "TCP/UDP Defaults",
                             "fallback" => "Fallback Configuration",
                             "upgrade" => "Upgrade Configuration",
                             "theme" => "Theme Configuration",
                             "yara" => "YARA Rules Configuration",
                             "serverless" => "Serverless Configuration",
                             "process" => "Process Status",
                             "defaults" => "Default Configuration",
                             "dns" => "DNS Configuration",
                             _ => "Server Configuration",
                         }}
                        </h2>
                        { if let Some(doc) = get_section_doc(active_section.as_str()) {
                            html! {
                                <span class="text-secondary text-sm" title={doc.description}>
                                    <svg class="w-4 h-4 inline-block ml-2 cursor-help" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
                                    </svg>
                                </span>
                            }
                        } else {
                            html! {}
                        }}
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
                            "tarpit" => html! { <TarpitSection /> },
                            "ip_feeds" => html! { <IpFeedsSection /> },
                            "security" => html! { <SecuritySection /> },
                            "upload" => html! { <UploadSection /> },
                            "tls" => html! { <TlsSection /> },
                            "acme" => html! { <AcmeSection /> },
                            "http3" => html! { <Http3Section /> },
                            "tunnel" => html! { <TunnelSection /> },
                            "plugins" => html! { <PluginsSection /> },
                            "theme" => html! { <ThemeSection /> },
                            "mime_types" => html! { <MimeTypesSection /> },
                            "tcp_udp_defaults" => html! { <TcpUdpDefaultsSection /> },
                            "fallback" => html! { <FallbackSection /> },
                            "upgrade" => html! { <UpgradeSection /> },
                            "yara" => html! { <YaraSection /> },
                            "serverless" => html! { <ServerlessSection /> },
                            "process" => html! { <ProcessSection /> },
                            "defaults" => html! { <DefaultsSection /> },
                            "dns" => html! { <DnsSection /> },
                            _ => html! { <ServerSection /> },
                        }}
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
    let server_config = use_state(|| None::<serde_json::Value>);
    let loading = use_state(|| true);
    let saving = use_state(|| false);
    let host = use_state(|| "0.0.0.0".to_string());
    let port = use_state(|| "8080".to_string());
    let trusted_proxies = use_state(|| "127.0.0.1, ::1".to_string());
    let original_host = use_state(|| "0.0.0.0".to_string());
    let original_port = use_state(|| "8080".to_string());
    let original_proxies = use_state(|| "127.0.0.1, ::1".to_string());

    let is_dirty =
        *host != *original_host || *port != *original_port || *trusted_proxies != *original_proxies;

    use_effect_with((), {
        let server_config = server_config.clone();
        let loading = loading.clone();
        let host = host.clone();
        let port = port.clone();
        let trusted_proxies = trusted_proxies.clone();
        let original_host = original_host.clone();
        let original_port = original_port.clone();
        let original_proxies = original_proxies.clone();
        move |_| {
            wasm_bindgen_futures::spawn_local(async move {
                let api = ApiService::new();
                let result = api.get_main_config().await;
                loading.set(false);

                if let Ok(data) = result {
                    if let Some(config) = data.get("config") {
                        if let Some(server) = config.get("server") {
                            server_config.set(Some(server.clone()));
                            if let Some(h) = server.get("host").and_then(|v| v.as_str()) {
                                host.set(h.to_string());
                                original_host.set(h.to_string());
                            }
                            if let Some(p) = server.get("port").and_then(|v| v.as_u64()) {
                                port.set(p.to_string());
                                original_port.set(p.to_string());
                            }
                            if let Some(tp) =
                                server.get("trusted_proxies").and_then(|v| v.as_array())
                            {
                                let proxies: Vec<String> = tp
                                    .iter()
                                    .filter_map(|v| v.as_str().map(|s| s.to_string()))
                                    .collect();
                                let joined = proxies.join(", ");
                                trusted_proxies.set(joined.clone());
                                original_proxies.set(joined);
                            }
                        }
                    }
                }
            });
            || {}
        }
    });

    if *loading {
        return html! { <LoadingSpinner /> };
    }

    let on_host_change = {
        let host = host.clone();
        Callback::from(move |value: String| {
            host.set(value);
        })
    };

    let on_port_change = {
        let port = port.clone();
        Callback::from(move |value: String| {
            port.set(value);
        })
    };

    let on_proxies_change = {
        let trusted_proxies = trusted_proxies.clone();
        Callback::from(move |value: String| {
            trusted_proxies.set(value);
        })
    };

    let on_save = {
        let saving = saving.clone();
        let host = host.clone();
        let port = port.clone();
        let trusted_proxies = trusted_proxies.clone();
        let _server_config = server_config.clone();
        let original_host = original_host.clone();
        let original_port = original_port.clone();
        let original_proxies = original_proxies.clone();
        Callback::from(move |_| {
            let proxies: Vec<String> = trusted_proxies
                .split(',')
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect();
            let new_config = serde_json::json!({
                "config": {
                    "server": {
                        "host": (*host).clone(),
                        "port": port.parse::<u16>().unwrap_or(8080),
                        "trusted_proxies": proxies
                    }
                }
            });
            let saving = saving.clone();
            let host = host.clone();
            let port = port.clone();
            let trusted_proxies = trusted_proxies.clone();
            let original_host = original_host.clone();
            let original_port = original_port.clone();
            let original_proxies = original_proxies.clone();
            saving.set(true);
            wasm_bindgen_futures::spawn_local(async move {
                let api = ApiService::new();
                match api.validate_config().await {
                    Ok(_) => {}
                    Err(e) => {
                        saving.set(false);
                        toast_error(&format!("Validation failed: {}", e));
                        return;
                    }
                }
                let _ = api.update_main_config(&new_config).await;
                saving.set(false);
                original_host.set((*host).clone());
                original_port.set((*port).clone());
                original_proxies.set((*trusted_proxies).clone());
                toast_success("Server configuration saved");
            });
        })
    };

    html! {
        <div class="space-y-6">
            <div class="grid grid-cols-2 gap-4">
                <Input
                    label="Listen Host"
                    name="host"
                    value={(*host).clone()}
                    on_change={on_host_change}
                    help="IP address to bind the main server to"
                    badge={restart_badge()}
                />
                <Input
                    label="Listen Port"
                    name="port"
                    value={(*port).clone()}
                    on_change={on_port_change}
                    input_type="number"
                    help="TCP port for the main HTTP server"
                    badge={restart_badge()}
                />
            </div>

            <div>
                <Input
                    label="Trusted Proxies"
                    name="trusted_proxies"
                    value={(*trusted_proxies).clone()}
                    on_change={on_proxies_change}
                    help="Comma-separated list of trusted proxy IPs for X-Forwarded-For handling"
                />
            </div>

            <div class="flex justify-end">
                <button
                    onclick={on_save}
                    disabled={*saving}
                    class={if is_dirty {
                        "px-4 py-2 bg-yellow-600 text-white rounded-lg hover:bg-yellow-700 disabled:opacity-50"
                    } else {
                        "px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700 disabled:opacity-50"
                    }}
                >
                    { if *saving { "Saving..." } else if is_dirty { "Save*" } else { "Save" } }
                </button>
            </div>
        </div>
    }
}

#[function_component]
fn HttpSection() -> Html {
    let loading = use_state(|| true);
    let saving = use_state(|| false);

    let header_read_timeout = use_state(|| "10".to_string());
    let keep_alive_timeout = use_state(|| "60".to_string());
    let max_headers = use_state(|| "128".to_string());
    let max_request_size = use_state(|| "1MB".to_string());
    let max_header_size_ingress = use_state(|| "4KB".to_string());
    let max_header_size_egress = use_state(|| "16KB".to_string());

    let original_header_read_timeout = use_state(|| "10".to_string());
    let original_keep_alive_timeout = use_state(|| "60".to_string());
    let original_max_headers = use_state(|| "128".to_string());
    let original_max_request_size = use_state(|| "1MB".to_string());
    let original_max_header_size_ingress = use_state(|| "4KB".to_string());
    let original_max_header_size_egress = use_state(|| "16KB".to_string());

    let is_dirty = *header_read_timeout != *original_header_read_timeout
        || *keep_alive_timeout != *original_keep_alive_timeout
        || *max_headers != *original_max_headers
        || *max_request_size != *original_max_request_size
        || *max_header_size_ingress != *original_max_header_size_ingress
        || *max_header_size_egress != *original_max_header_size_egress;

    use_effect_with((), {
        let loading = loading.clone();
        let header_read_timeout = header_read_timeout.clone();
        let keep_alive_timeout = keep_alive_timeout.clone();
        let max_headers = max_headers.clone();
        let max_request_size = max_request_size.clone();
        let max_header_size_ingress = max_header_size_ingress.clone();
        let max_header_size_egress = max_header_size_egress.clone();
        let original_header_read_timeout = original_header_read_timeout.clone();
        let original_keep_alive_timeout = original_keep_alive_timeout.clone();
        let original_max_headers = original_max_headers.clone();
        let original_max_request_size = original_max_request_size.clone();
        let original_max_header_size_ingress = original_max_header_size_ingress.clone();
        let original_max_header_size_egress = original_max_header_size_egress.clone();
        move |_| {
            wasm_bindgen_futures::spawn_local(async move {
                let api = ApiService::new();
                let result = api.get_http_config().await;
                loading.set(false);

                if let Ok(data) = result {
                    if let Some(config) = data.get("config") {
                        if let Some(v) = config
                            .get("header_read_timeout_secs")
                            .and_then(|v| v.as_u64())
                        {
                            let s = v.to_string();
                            header_read_timeout.set(s.clone());
                            original_header_read_timeout.set(s);
                        }
                        if let Some(v) = config
                            .get("keep_alive_timeout_secs")
                            .and_then(|v| v.as_u64())
                        {
                            let s = v.to_string();
                            keep_alive_timeout.set(s.clone());
                            original_keep_alive_timeout.set(s);
                        }
                        if let Some(v) = config.get("max_headers").and_then(|v| v.as_u64()) {
                            let s = v.to_string();
                            max_headers.set(s.clone());
                            original_max_headers.set(s);
                        }
                        if let Some(v) = config.get("max_request_size").and_then(|v| v.as_u64()) {
                            let s = bytes_to_human(v as usize);
                            max_request_size.set(s.clone());
                            original_max_request_size.set(s);
                        }
                        if let Some(v) = config
                            .get("max_header_size_ingress")
                            .and_then(|v| v.as_u64())
                        {
                            let s = bytes_to_human(v as usize);
                            max_header_size_ingress.set(s.clone());
                            original_max_header_size_ingress.set(s);
                        }
                        if let Some(v) = config
                            .get("max_header_size_egress")
                            .and_then(|v| v.as_u64())
                        {
                            let s = bytes_to_human(v as usize);
                            max_header_size_egress.set(s.clone());
                            original_max_header_size_egress.set(s);
                        }
                    }
                }
            });
            || {}
        }
    });

    if *loading {
        return html! { <LoadingSpinner /> };
    }

    let on_change = |state: UseStateHandle<String>| -> Callback<String> {
        Callback::from(move |value: String| {
            state.set(value);
        })
    };

    let on_save = {
        let saving = saving.clone();
        let header_read_timeout = header_read_timeout.clone();
        let keep_alive_timeout = keep_alive_timeout.clone();
        let max_headers = max_headers.clone();
        let max_request_size = max_request_size.clone();
        let max_header_size_ingress = max_header_size_ingress.clone();
        let max_header_size_egress = max_header_size_egress.clone();
        let original_header_read_timeout = original_header_read_timeout.clone();
        let original_keep_alive_timeout = original_keep_alive_timeout.clone();
        let original_max_headers = original_max_headers.clone();
        let original_max_request_size = original_max_request_size.clone();
        let original_max_header_size_ingress = original_max_header_size_ingress.clone();
        let original_max_header_size_egress = original_max_header_size_egress.clone();
        Callback::from(move |_| {
            let config = serde_json::json!({
                "config": {
                    "header_read_timeout_secs": header_read_timeout.parse::<u64>().unwrap_or(10),
                    "keep_alive_timeout_secs": keep_alive_timeout.parse::<u64>().unwrap_or(60),
                    "max_headers": max_headers.parse::<usize>().unwrap_or(128),
                    "max_request_size": human_to_bytes(&max_request_size),
                    "max_header_size_ingress": human_to_bytes(&max_header_size_ingress),
                    "max_header_size_egress": human_to_bytes(&max_header_size_egress),
                }
            });
            let saving = saving.clone();
            let header_read_timeout = header_read_timeout.clone();
            let keep_alive_timeout = keep_alive_timeout.clone();
            let max_headers = max_headers.clone();
            let max_request_size = max_request_size.clone();
            let max_header_size_ingress = max_header_size_ingress.clone();
            let max_header_size_egress = max_header_size_egress.clone();
            let original_header_read_timeout = original_header_read_timeout.clone();
            let original_keep_alive_timeout = original_keep_alive_timeout.clone();
            let original_max_headers = original_max_headers.clone();
            let original_max_request_size = original_max_request_size.clone();
            let original_max_header_size_ingress = original_max_header_size_ingress.clone();
            let original_max_header_size_egress = original_max_header_size_egress.clone();
            saving.set(true);
            wasm_bindgen_futures::spawn_local(async move {
                let api = ApiService::new();
                let _ = api.update_http_config(&config).await;
                saving.set(false);
                original_header_read_timeout.set((*header_read_timeout).clone());
                original_keep_alive_timeout.set((*keep_alive_timeout).clone());
                original_max_headers.set((*max_headers).clone());
                original_max_request_size.set((*max_request_size).clone());
                original_max_header_size_ingress.set((*max_header_size_ingress).clone());
                original_max_header_size_egress.set((*max_header_size_egress).clone());
                toast_success("HTTP configuration saved");
            });
        })
    };

    html! {
        <div class="space-y-6">
            <div class="grid grid-cols-2 gap-4">
                <Input
                    label="Header Read Timeout (secs)"
                    name="header_read_timeout"
                    input_type="number"
                    value={(*header_read_timeout).clone()}
                    on_change={on_change(header_read_timeout.clone())}
                />
                <Input
                    label="Keep-Alive Timeout (secs)"
                    name="keep_alive_timeout"
                    input_type="number"
                    value={(*keep_alive_timeout).clone()}
                    on_change={on_change(keep_alive_timeout.clone())}
                />
            </div>

            <div class="grid grid-cols-2 gap-4">
                <Input
                    label="Max Headers"
                    name="max_headers"
                    input_type="number"
                    value={(*max_headers).clone()}
                    on_change={on_change(max_headers.clone())}
                />
                <Input
                    label="Max Request Size"
                    name="max_request_size"
                    value={(*max_request_size).clone()}
                    on_change={on_change(max_request_size.clone())}
                    help="Maximum request body size"
                />
            </div>

            <div class="grid grid-cols-2 gap-4">
                <Input
                    label="Max Header Size (Ingress)"
                    name="max_header_size_ingress"
                    value={(*max_header_size_ingress).clone()}
                    on_change={on_change(max_header_size_ingress.clone())}
                />
                <Input
                    label="Max Header Size (Egress)"
                    name="max_header_size_egress"
                    value={(*max_header_size_egress).clone()}
                    on_change={on_change(max_header_size_egress.clone())}
                />
            </div>

            <div class="flex justify-end">
                <button
                    onclick={on_save}
                    disabled={*saving}
                    class={if is_dirty {
                        "px-4 py-2 bg-yellow-600 text-white rounded-lg hover:bg-yellow-700 disabled:opacity-50"
                    } else {
                        "px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700 disabled:opacity-50"
                    }}
                >
                    { if *saving { "Saving..." } else if is_dirty { "Save*" } else { "Save" } }
                </button>
            </div>
        </div>
    }
}

#[function_component]
fn LoggingSection() -> Html {
    let loading = use_state(|| true);
    let saving = use_state(|| false);

    let log_level = use_state(|| "info".to_string());
    let access_log_format = use_state(|| "json".to_string());
    let access_log_dir = use_state(|| "/var/log/synvoid".to_string());
    let retention_days = use_state(|| "5".to_string());
    let max_entries_per_file = use_state(|| "50000".to_string());

    let original_log_level = use_state(|| "info".to_string());
    let original_access_log_format = use_state(|| "json".to_string());
    let original_access_log_dir = use_state(|| "/var/log/synvoid".to_string());
    let original_retention_days = use_state(|| "5".to_string());
    let original_max_entries_per_file = use_state(|| "50000".to_string());

    let is_dirty = *log_level != *original_log_level
        || *access_log_format != *original_access_log_format
        || *access_log_dir != *original_access_log_dir
        || *retention_days != *original_retention_days
        || *max_entries_per_file != *original_max_entries_per_file;

    use_effect_with((), {
        let loading = loading.clone();
        let log_level = log_level.clone();
        let access_log_format = access_log_format.clone();
        let access_log_dir = access_log_dir.clone();
        let retention_days = retention_days.clone();
        let max_entries_per_file = max_entries_per_file.clone();
        let original_log_level = original_log_level.clone();
        let original_access_log_format = original_access_log_format.clone();
        let original_access_log_dir = original_access_log_dir.clone();
        let original_retention_days = original_retention_days.clone();
        let original_max_entries_per_file = original_max_entries_per_file.clone();
        move |_| {
            wasm_bindgen_futures::spawn_local(async move {
                let api = ApiService::new();
                let result = api.get_logging_config().await;
                loading.set(false);

                if let Ok(data) = result {
                    if let Some(config) = data.get("config") {
                        if let Some(v) = config.get("level").and_then(|v| v.as_str()) {
                            let s = v.to_string();
                            log_level.set(s.clone());
                            original_log_level.set(s);
                        }
                        if let Some(v) = config.get("access_log_format").and_then(|v| v.as_str()) {
                            let s = v.to_string();
                            access_log_format.set(s.clone());
                            original_access_log_format.set(s);
                        }
                        if let Some(v) = config.get("access_log_dir").and_then(|v| v.as_str()) {
                            let s = v.to_string();
                            access_log_dir.set(s.clone());
                            original_access_log_dir.set(s);
                        }
                        if let Some(v) = config.get("retention_days").and_then(|v| v.as_u64()) {
                            let s = v.to_string();
                            retention_days.set(s.clone());
                            original_retention_days.set(s);
                        }
                        if let Some(v) = config.get("max_entries_per_file").and_then(|v| v.as_u64())
                        {
                            let s = v.to_string();
                            max_entries_per_file.set(s.clone());
                            original_max_entries_per_file.set(s);
                        }
                    }
                }
            });
            || {}
        }
    });

    if *loading {
        return html! { <LoadingSpinner /> };
    }

    let on_change = |state: UseStateHandle<String>| -> Callback<String> {
        Callback::from(move |value: String| {
            state.set(value);
        })
    };

    let on_save = {
        let saving = saving.clone();
        let log_level = log_level.clone();
        let access_log_format = access_log_format.clone();
        let access_log_dir = access_log_dir.clone();
        let retention_days = retention_days.clone();
        let max_entries_per_file = max_entries_per_file.clone();
        let original_log_level = original_log_level.clone();
        let original_access_log_format = original_access_log_format.clone();
        let original_access_log_dir = original_access_log_dir.clone();
        let original_retention_days = original_retention_days.clone();
        let original_max_entries_per_file = original_max_entries_per_file.clone();
        Callback::from(move |_| {
            let config = serde_json::json!({
                "config": {
                    "level": (*log_level).clone(),
                    "access_log_format": (*access_log_format).clone(),
                    "access_log_dir": (*access_log_dir).clone(),
                    "retention_days": retention_days.parse::<u32>().unwrap_or(5),
                    "max_entries_per_file": max_entries_per_file.parse::<u32>().unwrap_or(50000),
                }
            });
            let saving = saving.clone();
            let log_level = log_level.clone();
            let access_log_format = access_log_format.clone();
            let access_log_dir = access_log_dir.clone();
            let retention_days = retention_days.clone();
            let max_entries_per_file = max_entries_per_file.clone();
            let original_log_level = original_log_level.clone();
            let original_access_log_format = original_access_log_format.clone();
            let original_access_log_dir = original_access_log_dir.clone();
            let original_retention_days = original_retention_days.clone();
            let original_max_entries_per_file = original_max_entries_per_file.clone();
            saving.set(true);
            wasm_bindgen_futures::spawn_local(async move {
                let api = ApiService::new();
                let _ = api.update_logging_config(&config).await;
                saving.set(false);
                original_log_level.set((*log_level).clone());
                original_access_log_format.set((*access_log_format).clone());
                original_access_log_dir.set((*access_log_dir).clone());
                original_retention_days.set((*retention_days).clone());
                original_max_entries_per_file.set((*max_entries_per_file).clone());
                toast_success("Logging configuration saved");
            });
        })
    };

    html! {
        <div class="space-y-6">
            <Select
                label="Log Level"
                name="log_level"
                value={(*log_level).clone()}
                options={vec![
                    ("trace".to_string(), "Trace".to_string()),
                    ("debug".to_string(), "Debug".to_string()),
                    ("info".to_string(), "Info".to_string()),
                    ("warn".to_string(), "Warning".to_string()),
                    ("error".to_string(), "Error".to_string()),
                ]}
                help="Minimum log level to record"
                on_change={on_change(log_level.clone())}
            />

            <div class="grid grid-cols-2 gap-4">
                <Select
                    label="Access Log Format"
                    name="access_log_format"
                    value={(*access_log_format).clone()}
                    options={vec![
                        ("json".to_string(), "JSON".to_string()),
                        ("text".to_string(), "Plain Text".to_string()),
                    ]}
                    on_change={on_change(access_log_format.clone())}
                />
                <Input
                    label="Access Log Directory"
                    name="access_log_dir"
                    value={(*access_log_dir).clone()}
                    on_change={on_change(access_log_dir.clone())}
                />
            </div>

            <div class="grid grid-cols-2 gap-4">
                <Input
                    label="Retention Days"
                    name="retention_days"
                    input_type="number"
                    value={(*retention_days).clone()}
                    on_change={on_change(retention_days.clone())}
                />
                <Input
                    label="Max Entries Per File"
                    name="max_entries_per_file"
                    input_type="number"
                    value={(*max_entries_per_file).clone()}
                    on_change={on_change(max_entries_per_file.clone())}
                />
            </div>

            <div class="flex justify-end">
                <button
                    onclick={on_save}
                    disabled={*saving}
                    class={if is_dirty {
                        "px-4 py-2 bg-yellow-600 text-white rounded-lg hover:bg-yellow-700 disabled:opacity-50"
                    } else {
                        "px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700 disabled:opacity-50"
                    }}
                >
                    { if *saving { "Saving..." } else if is_dirty { "Save*" } else { "Save" } }
                </button>
            </div>
        </div>
    }
}

#[function_component]
fn MetricsSection() -> Html {
    let loading = use_state(|| true);
    let saving = use_state(|| false);

    let metrics_enabled = use_state(|| true);
    let metrics_port = use_state(|| "9090".to_string());

    let original_metrics_enabled = use_state(|| true);
    let original_metrics_port = use_state(|| "9090".to_string());

    let is_dirty =
        *metrics_enabled != *original_metrics_enabled || *metrics_port != *original_metrics_port;

    use_effect_with((), {
        let loading = loading.clone();
        let metrics_enabled = metrics_enabled.clone();
        let metrics_port = metrics_port.clone();
        let original_metrics_enabled = original_metrics_enabled.clone();
        let original_metrics_port = original_metrics_port.clone();
        move |_| {
            wasm_bindgen_futures::spawn_local(async move {
                let api = ApiService::new();
                let result = api.get_main_config().await;
                loading.set(false);

                if let Ok(data) = result {
                    if let Some(config) = data.get("config") {
                        if let Some(metrics) = config.get("metrics") {
                            if let Some(v) = metrics.get("enabled").and_then(|v| v.as_bool()) {
                                metrics_enabled.set(v);
                                original_metrics_enabled.set(v);
                            }
                            if let Some(v) = metrics.get("port").and_then(|v| v.as_u64()) {
                                let s = v.to_string();
                                metrics_port.set(s.clone());
                                original_metrics_port.set(s);
                            }
                        }
                    }
                }
            });
            || {}
        }
    });

    if *loading {
        return html! { <LoadingSpinner /> };
    }

    let on_port_change = {
        let metrics_port = metrics_port.clone();
        Callback::from(move |value: String| {
            metrics_port.set(value);
        })
    };

    let on_toggle_enabled = {
        let metrics_enabled = metrics_enabled.clone();
        Callback::from(move |_: MouseEvent| {
            metrics_enabled.set(!*metrics_enabled);
        })
    };

    let on_save = {
        let saving = saving.clone();
        let metrics_enabled = metrics_enabled.clone();
        let metrics_port = metrics_port.clone();
        let original_metrics_enabled = original_metrics_enabled.clone();
        let original_metrics_port = original_metrics_port.clone();
        Callback::from(move |_| {
            let config = serde_json::json!({
                "config": {
                    "metrics": {
                        "enabled": *metrics_enabled,
                        "port": metrics_port.parse::<u16>().unwrap_or(9090),
                    }
                }
            });
            let saving = saving.clone();
            let metrics_enabled = metrics_enabled.clone();
            let metrics_port = metrics_port.clone();
            let original_metrics_enabled = original_metrics_enabled.clone();
            let original_metrics_port = original_metrics_port.clone();
            saving.set(true);
            wasm_bindgen_futures::spawn_local(async move {
                let api = ApiService::new();
                let _ = api.update_main_config(&config).await;
                saving.set(false);
                original_metrics_enabled.set(*metrics_enabled);
                original_metrics_port.set((*metrics_port).clone());
                toast_success("Metrics configuration saved");
            });
        })
    };

    html! {
        <div class="space-y-6">
            <div class="flex items-center justify-between py-2">
                <div>
                    <p class="text-primary font-medium">{ "Enable Metrics" }</p>
                    <p class="text-sm text-secondary">{ "Expose Prometheus metrics endpoint" }</p>
                </div>
                <button
                    onclick={on_toggle_enabled}
                    class={format!("relative w-10 h-6 rounded-full {}", if *metrics_enabled { "bg-blue-600" } else { "bg-gray-600" })}
                >
                    <span class={format!("absolute top-1 left-1 w-4 h-4 bg-white rounded-full transition-transform {}", if *metrics_enabled { "translate-x-5" } else { "translate-x-0" })} />
                </button>
            </div>

            <Input
                label="Metrics Port"
                name="metrics_port"
                input_type="number"
                value={(*metrics_port).clone()}
                on_change={on_port_change}
                help="Port for Prometheus metrics endpoint"
                badge={restart_badge()}
            />

            <div class="flex justify-end">
                <button
                    onclick={on_save}
                    disabled={*saving}
                    class={if is_dirty {
                        "px-4 py-2 bg-yellow-600 text-white rounded-lg hover:bg-yellow-700 disabled:opacity-50"
                    } else {
                        "px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700 disabled:opacity-50"
                    }}
                >
                    { if *saving { "Saving..." } else if is_dirty { "Save*" } else { "Save" } }
                </button>
            </div>
        </div>
    }
}

#[function_component]
fn IpFeedsSection() -> Html {
    let loading = use_state(|| true);
    let saving = use_state(|| false);

    let enabled = use_state(|| true);
    let url = use_state(|| {
        "https://raw.githubusercontent.com/bitwire-it/ipblocklist/main/inbound.txt".to_string()
    });
    let update_interval = use_state(|| "2".to_string());
    let max_blocks = use_state(|| "1000000".to_string());

    let original_enabled = use_state(|| true);
    let original_url = use_state(|| {
        "https://raw.githubusercontent.com/bitwire-it/ipblocklist/main/inbound.txt".to_string()
    });
    let original_update_interval = use_state(|| "2".to_string());
    let original_max_blocks = use_state(|| "1000000".to_string());

    let is_dirty = *enabled != *original_enabled
        || *url != *original_url
        || *update_interval != *original_update_interval
        || *max_blocks != *original_max_blocks;

    use_effect_with((), {
        let loading = loading.clone();
        let enabled = enabled.clone();
        let url = url.clone();
        let update_interval = update_interval.clone();
        let max_blocks = max_blocks.clone();
        let original_enabled = original_enabled.clone();
        let original_url = original_url.clone();
        let original_update_interval = original_update_interval.clone();
        let original_max_blocks = original_max_blocks.clone();
        move |_| {
            wasm_bindgen_futures::spawn_local(async move {
                let api = ApiService::new();
                let result = api.get_ip_feeds_config().await;
                loading.set(false);

                if let Ok(data) = result {
                    if let Some(config) = data.get("config") {
                        if let Some(v) = config.get("enabled").and_then(|v| v.as_bool()) {
                            enabled.set(v);
                            original_enabled.set(v);
                        }
                        if let Some(v) = config.get("url").and_then(|v| v.as_str()) {
                            url.set(v.to_string());
                            original_url.set(v.to_string());
                        }
                        if let Some(v) =
                            config.get("update_interval_hours").and_then(|v| v.as_u64())
                        {
                            let s = v.to_string();
                            update_interval.set(s.clone());
                            original_update_interval.set(s);
                        }
                        if let Some(v) = config.get("max_permanent_blocks").and_then(|v| v.as_u64())
                        {
                            let s = v.to_string();
                            max_blocks.set(s.clone());
                            original_max_blocks.set(s);
                        }
                    }
                }
            });
            || {}
        }
    });

    if *loading {
        return html! { <LoadingSpinner /> };
    }

    let on_toggle_enabled = {
        let enabled = enabled.clone();
        Callback::from(move |_: MouseEvent| {
            enabled.set(!*enabled);
        })
    };

    let on_save = {
        let saving = saving.clone();
        let enabled = enabled.clone();
        let url = url.clone();
        let update_interval = update_interval.clone();
        let max_blocks = max_blocks.clone();
        Callback::from(move |_| {
            let config = serde_json::json!({
                "config": {
                    "enabled": *enabled,
                    "url": (*url).clone(),
                    "update_interval_hours": update_interval.parse::<u32>().unwrap_or(2),
                    "max_permanent_blocks": max_blocks.parse::<usize>().unwrap_or(1000000),
                }
            });
            let saving = saving.clone();
            saving.set(true);
            let _enabled = enabled.clone();
            let _url = url.clone();
            let _update_interval = update_interval.clone();
            let _max_blocks = max_blocks.clone();
            wasm_bindgen_futures::spawn_local(async move {
                let api = ApiService::new();
                let _ = api.update_ip_feeds_config(&config).await;
                saving.set(false);
                toast_success("IP feeds configuration saved");
            });
        })
    };

    html! {
        <div class="space-y-6">
            <div class="flex items-center justify-between py-2">
                <div>
                    <p class="text-primary font-medium">{ "Enable IP Feeds" }</p>
                    <p class="text-sm text-secondary">{ "Download and use external IP blocklists" }</p>
                </div>
                <button
                    onclick={on_toggle_enabled}
                    class={format!("relative w-10 h-6 rounded-full {}", if *enabled { "bg-blue-600" } else { "bg-gray-600" })}
                >
                    <span class={format!("absolute top-1 left-1 w-4 h-4 bg-white rounded-full transition-transform {}", if *enabled { "translate-x-5" } else { "translate-x-0" })} />
                </button>
            </div>

            <div class="space-y-4">
                <div>
                    <label class="block text-sm font-medium text-primary mb-1">
                        { "Feed URL" }
                    </label>
                    <Input
                        label={"Feed URL".to_string()}
                        name={"feed_url".to_string()}
                        value={(*url).clone()}
                        on_change={Callback::from(move |v: String| url.set(v))}
                        placeholder={"https://example.com/blocklist.txt".to_string()}
                    />
                    <p class="text-xs text-secondary mt-1">{ "Plain text file with one IP/CIDR per line" }</p>
                </div>

                <div class="grid grid-cols-2 gap-4">
                    <div>
                        <label class="block text-sm font-medium text-primary mb-1">
                            { "Update Interval (hours)" }
                        </label>
                        <Input
                            label={"Update Interval".to_string()}
                            name={"update_interval".to_string()}
                            value={(*update_interval).clone()}
                            on_change={Callback::from(move |v: String| update_interval.set(v))}
                            input_type="number"
                        />
                    </div>
                    <div>
                        <label class="block text-sm font-medium text-primary mb-1">
                            { "Max Permanent Blocks" }
                        </label>
                        <Input
                            label={"Max Blocks".to_string()}
                            name={"max_blocks".to_string()}
                            value={(*max_blocks).clone()}
                            on_change={Callback::from(move |v: String| max_blocks.set(v))}
                            input_type="number"
                        />
                        <p class="text-xs text-secondary mt-1">{ "Maximum IPs to permanently block" }</p>
                    </div>
                </div>
            </div>

            <div class="flex justify-end">
                <button
                    onclick={on_save}
                    disabled={*saving}
                    class={if is_dirty {
                        "px-4 py-2 bg-yellow-600 text-white rounded-lg hover:bg-yellow-700 disabled:opacity-50"
                    } else {
                        "px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700 disabled:opacity-50"
                    }}
                >
                    { if *saving { "Saving..." } else if is_dirty { "Save*" } else { "Save" } }
                </button>
            </div>
        </div>
    }
}

#[function_component]
fn TlsSection() -> Html {
    let loading = use_state(|| true);
    let saving = use_state(|| false);

    let enabled = use_state(|| true);
    let port = use_state(|| "443".to_string());
    let cert_path = use_state(|| "".to_string());
    let key_path = use_state(|| "".to_string());
    let prefer_post_quantum = use_state(|| false);
    let watch_dir = use_state(|| "".to_string());

    use_effect_with((), {
        let loading = loading.clone();
        let enabled = enabled.clone();
        let port = port.clone();
        let cert_path = cert_path.clone();
        let key_path = key_path.clone();
        let prefer_post_quantum = prefer_post_quantum.clone();
        let watch_dir = watch_dir.clone();
        move |_| {
            wasm_bindgen_futures::spawn_local(async move {
                let api = ApiService::new();
                let result = api.get_tls_config().await;
                loading.set(false);

                if let Ok(data) = result {
                    if let Some(config) = data.get("config") {
                        if let Some(v) = config.get("enabled").and_then(|v| v.as_bool()) {
                            enabled.set(v);
                        }
                        if let Some(v) = config.get("port").and_then(|v| v.as_u64()) {
                            port.set(v.to_string());
                        }
                        if let Some(v) = config.get("cert_path").and_then(|v| v.as_str()) {
                            cert_path.set(v.to_string());
                        }
                        if let Some(v) = config.get("key_path").and_then(|v| v.as_str()) {
                            key_path.set(v.to_string());
                        }
                        if let Some(v) = config.get("prefer_post_quantum").and_then(|v| v.as_bool())
                        {
                            prefer_post_quantum.set(v);
                        }
                        if let Some(v) = config.get("watch_dir").and_then(|v| v.as_str()) {
                            watch_dir.set(v.to_string());
                        }
                    }
                }
            });
            || {}
        }
    });

    if *loading {
        return html! { <LoadingSpinner /> };
    }

    let _is_dirty = !cert_path.is_empty() || !key_path.is_empty() || *port != "443";

    let on_toggle_enabled = {
        let enabled = enabled.clone();
        Callback::from(move |_: MouseEvent| {
            enabled.set(!*enabled);
        })
    };

    let on_save = {
        let saving = saving.clone();
        let enabled = enabled.clone();
        let port = port.clone();
        let cert_path = cert_path.clone();
        let key_path = key_path.clone();
        let prefer_post_quantum = prefer_post_quantum.clone();
        let watch_dir = watch_dir.clone();
        Callback::from(move |_| {
            let config = serde_json::json!({
                "config": {
                    "enabled": *enabled,
                    "port": port.parse::<u16>().unwrap_or(443),
                    "cert_path": (*cert_path).clone(),
                    "key_path": (*key_path).clone(),
                    "prefer_post_quantum": *prefer_post_quantum,
                    "watch_dir": if (*watch_dir).is_empty() { serde_json::Value::Null } else { serde_json::Value::String((*watch_dir).clone()) },
                }
            });
            let saving = saving.clone();
            saving.set(true);
            wasm_bindgen_futures::spawn_local(async move {
                let api = ApiService::new();
                let _ = api.update_tls_config(&config).await;
                saving.set(false);
                toast_success("TLS configuration saved");
            });
        })
    };

    html! {
        <div class="space-y-6">
            <div class="flex items-center justify-between py-2">
                <div>
                    <p class="text-primary font-medium">{ "Enable TLS" }</p>
                    <p class="text-sm text-secondary">{ "HTTPS encryption with custom certificates" }</p>
                </div>
                <button
                    onclick={on_toggle_enabled}
                    class={format!("relative w-10 h-6 rounded-full {}", if *enabled { "bg-blue-600" } else { "bg-gray-600" })}
                >
                    <span class={format!("absolute top-1 left-1 w-4 h-4 bg-white rounded-full transition-transform {}", if *enabled { "translate-x-5" } else { "translate-x-0" })} />
                </button>
            </div>

            <div class="space-y-4">
                <div>
                    <label class="block text-sm font-medium text-primary mb-1">{ "Port" }</label>
                    <Input
                        label={"Port".to_string()}
                        name={"port".to_string()}
                        value={(*port).clone()}
                        on_change={Callback::from(move |v: String| port.set(v))}
                        input_type="number"
                    />
                </div>

                <div>
                    <label class="block text-sm font-medium text-primary mb-1">{ "Certificate Path" }</label>
                    <Input
                        label={"Cert Path".to_string()}
                        name={"cert_path".to_string()}
                        value={(*cert_path).clone()}
                        on_change={Callback::from(move |v: String| cert_path.set(v))}
                        placeholder="/etc/ssl/certs/server.crt"
                    />
                </div>

                <div>
                    <label class="block text-sm font-medium text-primary mb-1">{ "Private Key Path" }</label>
                    <Input
                        label={"Key Path".to_string()}
                        name={"key_path".to_string()}
                        value={(*key_path).clone()}
                        on_change={Callback::from(move |v: String| key_path.set(v))}
                        placeholder="/etc/ssl/private/server.key"
                    />
                </div>

                <div class="flex items-center justify-between py-2">
                    <div>
                        <p class="text-primary font-medium">{ "Prefer Post-Quantum" }</p>
                        <p class="text-sm text-secondary">{ "Use post-quantum key exchange algorithms" }</p>
                    </div>
                    <button
                        onclick={{
                            let prefer_post_quantum = prefer_post_quantum.clone();
                            Callback::from(move |_: MouseEvent| {
                                prefer_post_quantum.set(!*prefer_post_quantum);
                            })
                        }}
                        class={format!("relative w-10 h-6 rounded-full {}", if *prefer_post_quantum { "bg-blue-600" } else { "bg-gray-600" })}
                    >
                        <span class={format!("absolute top-1 left-1 w-4 h-4 bg-white rounded-full transition-transform {}", if *prefer_post_quantum { "translate-x-5" } else { "translate-x-0" })} />
                    </button>
                </div>

                <div>
                    <label class="block text-sm font-medium text-primary mb-1">{ "Certificate Watch Directory" }</label>
                    <Input
                        label={"Watch Dir".to_string()}
                        name={"watch_dir".to_string()}
                        value={(*watch_dir).clone()}
                        on_change={Callback::from(move |v: String| watch_dir.set(v))}
                        placeholder="/etc/ssl/certs/watch (optional)"
                    />
                    <p class="text-xs text-secondary mt-1">{ "Auto-reload certificates when files change" }</p>
                </div>
            </div>

            <div class="flex justify-end">
                <button
                    onclick={on_save}
                    disabled={*saving}
                    class="px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700 disabled:opacity-50"
                >
                    { if *saving { "Saving..." } else { "Save" } }
                </button>
            </div>
        </div>
    }
}

#[function_component]
fn AcmeSection() -> Html {
    let loading = use_state(|| true);
    let saving = use_state(|| false);

    let enabled = use_state(|| false);
    let email = use_state(|| "".to_string());
    let domains = use_state(|| "".to_string());
    let staging = use_state(|| false);
    let cache_dir = use_state(|| "".to_string());
    let terms_of_service_agreed = use_state(|| false);

    use_effect_with((), {
        let loading = loading.clone();
        let enabled = enabled.clone();
        let email = email.clone();
        let staging = staging.clone();
        let cache_dir = cache_dir.clone();
        let terms_of_service_agreed = terms_of_service_agreed.clone();
        move |_| {
            wasm_bindgen_futures::spawn_local(async move {
                let api = ApiService::new();
                let result = api.get_acme_config().await;
                loading.set(false);

                if let Ok(data) = result {
                    if let Some(config) = data.get("config") {
                        if let Some(v) = config.get("enabled").and_then(|v| v.as_bool()) {
                            enabled.set(v);
                        }
                        if let Some(v) = config.get("email").and_then(|v| v.as_str()) {
                            email.set(v.to_string());
                        }
                        if let Some(v) = config.get("staging").and_then(|v| v.as_bool()) {
                            staging.set(v);
                        }
                        if let Some(v) = config.get("cache_dir").and_then(|v| v.as_str()) {
                            cache_dir.set(v.to_string());
                        }
                        if let Some(v) = config
                            .get("terms_of_service_agreed")
                            .and_then(|v| v.as_bool())
                        {
                            terms_of_service_agreed.set(v);
                        }
                    }
                }
            });
            || {}
        }
    });

    if *loading {
        return html! { <LoadingSpinner /> };
    }

    let on_save = {
        let saving = saving.clone();
        let enabled = enabled.clone();
        let email = email.clone();
        let domains = domains.clone();
        let staging = staging.clone();
        let cache_dir = cache_dir.clone();
        let terms_of_service_agreed = terms_of_service_agreed.clone();
        Callback::from(move |_| {
            let domain_list: Vec<String> = domains
                .split(',')
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect();
            let config = serde_json::json!({
                "config": {
                    "enabled": *enabled,
                    "email": (*email).clone(),
                    "domains": domain_list,
                    "staging": *staging,
                    "cache_dir": if (*cache_dir).is_empty() { serde_json::Value::Null } else { serde_json::Value::String((*cache_dir).clone()) },
                    "terms_of_service_agreed": *terms_of_service_agreed,
                }
            });
            let saving = saving.clone();
            saving.set(true);
            wasm_bindgen_futures::spawn_local(async move {
                let api = ApiService::new();
                let _ = api.update_acme_config(&config).await;
                saving.set(false);
                toast_success("ACME configuration saved");
            });
        })
    };

    html! {
        <div class="space-y-6">
            <div class="flex items-center justify-between py-2">
                <div>
                    <p class="text-primary font-medium">{ "Enable ACME" }</p>
                    <p class="text-sm text-secondary">{ "Automatic certificate management via Let's Encrypt" }</p>
                </div>
                <button
                    onclick={{
                        let enabled = enabled.clone();
                        Callback::from(move |_: MouseEvent| {
                            enabled.set(!*enabled);
                        })
                    }}
                    class={format!("relative w-10 h-6 rounded-full {}", if *enabled { "bg-blue-600" } else { "bg-gray-600" })}
                >
                    <span class={format!("absolute top-1 left-1 w-4 h-4 bg-white rounded-full transition-transform {}", if *enabled { "translate-x-5" } else { "translate-x-0" })} />
                </button>
            </div>

            <div class="space-y-4">
                <div>
                    <label class="block text-sm font-medium text-primary mb-1">{ "Email" }</label>
                    <Input
                        label={"Email".to_string()}
                        name={"email".to_string()}
                        value={(*email).clone()}
                        on_change={Callback::from(move |v: String| email.set(v))}
                        placeholder="admin@example.com"
                    />
                    <p class="text-xs text-secondary mt-1">{ "Let's Encrypt will send certificates here" }</p>
                </div>

                <div>
                    <label class="block text-sm font-medium text-primary mb-1">{ "Domains" }</label>
                    <Input
                        label={"Domains".to_string()}
                        name={"domains".to_string()}
                        value={(*domains).clone()}
                        on_change={Callback::from(move |v: String| domains.set(v))}
                        placeholder="example.com, www.example.com (comma-separated)"
                    />
                </div>

                <div>
                    <label class="block text-sm font-medium text-primary mb-1">{ "Cache Directory" }</label>
                    <Input
                        label={"Cache Dir".to_string()}
                        name={"cache_dir".to_string()}
                        value={(*cache_dir).clone()}
                        on_change={Callback::from(move |v: String| cache_dir.set(v))}
                        placeholder="/var/lib/synvoid/acme (optional)"
                    />
                </div>

                <div class="flex items-center justify-between py-2">
                    <div>
                        <p class="text-primary font-medium">{ "Staging Mode" }</p>
                        <p class="text-sm text-secondary">{ "Use Let's Encrypt staging (for testing)" }</p>
                    </div>
                    <button
                        onclick={{
                            let staging = staging.clone();
                            Callback::from(move |_: MouseEvent| {
                                staging.set(!*staging);
                            })
                        }}
                        class={format!("relative w-10 h-6 rounded-full {}", if *staging { "bg-blue-600" } else { "bg-gray-600" })}
                    >
                        <span class={format!("absolute top-1 left-1 w-4 h-4 bg-white rounded-full transition-transform {}", if *staging { "translate-x-5" } else { "translate-x-0" })} />
                    </button>
                </div>

                <div class="flex items-center justify-between py-2">
                    <div>
                        <p class="text-primary font-medium">{ "Agree to Terms of Service" }</p>
                        <p class="text-sm text-secondary">{ "Required to obtain certificates" }</p>
                    </div>
                    <button
                        onclick={{
                            let terms_of_service_agreed = terms_of_service_agreed.clone();
                            Callback::from(move |_: MouseEvent| {
                                terms_of_service_agreed.set(!*terms_of_service_agreed);
                            })
                        }}
                        class={format!("relative w-10 h-6 rounded-full {}", if *terms_of_service_agreed { "bg-blue-600" } else { "bg-gray-600" })}
                    >
                        <span class={format!("absolute top-1 left-1 w-4 h-4 bg-white rounded-full transition-transform {}", if *terms_of_service_agreed { "translate-x-5" } else { "translate-x-0" })} />
                    </button>
                </div>
            </div>

            <div class="flex justify-end">
                <button
                    onclick={on_save}
                    disabled={*saving}
                    class="px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700 disabled:opacity-50"
                >
                    { if *saving { "Saving..." } else { "Save" } }
                </button>
            </div>
        </div>
    }
}

#[function_component]
fn Http3Section() -> Html {
    let loading = use_state(|| true);
    let saving = use_state(|| false);

    let enabled = use_state(|| false);
    let port = use_state(|| "443".to_string());
    let alt_svc_max_age = use_state(|| "86400".to_string());
    let max_request_size = use_state(|| "10485760".to_string());

    use_effect_with((), {
        let loading = loading.clone();
        let enabled = enabled.clone();
        let port = port.clone();
        let alt_svc_max_age = alt_svc_max_age.clone();
        let max_request_size = max_request_size.clone();
        move |_| {
            wasm_bindgen_futures::spawn_local(async move {
                let api = ApiService::new();
                let result = api.get_http3_config().await;
                loading.set(false);

                if let Ok(data) = result {
                    if let Some(config) = data.get("config") {
                        if let Some(v) = config.get("enabled").and_then(|v| v.as_bool()) {
                            enabled.set(v);
                        }
                        if let Some(v) = config.get("port").and_then(|v| v.as_u64()) {
                            port.set(v.to_string());
                        }
                        if let Some(v) = config.get("alt_svc_max_age").and_then(|v| v.as_u64()) {
                            alt_svc_max_age.set(v.to_string());
                        }
                        if let Some(v) = config.get("max_request_size").and_then(|v| v.as_u64()) {
                            max_request_size.set(v.to_string());
                        }
                    }
                }
            });
            || {}
        }
    });

    if *loading {
        return html! { <LoadingSpinner /> };
    }

    let on_save = {
        let saving = saving.clone();
        let enabled = enabled.clone();
        let port = port.clone();
        let alt_svc_max_age = alt_svc_max_age.clone();
        let max_request_size = max_request_size.clone();
        Callback::from(move |_| {
            let config = serde_json::json!({
                "config": {
                    "enabled": *enabled,
                    "port": port.parse::<u16>().unwrap_or(443),
                    "alt_svc_max_age": alt_svc_max_age.parse::<u64>().unwrap_or(86400),
                    "max_request_size": max_request_size.parse::<usize>().unwrap_or(10485760),
                }
            });
            let saving = saving.clone();
            saving.set(true);
            wasm_bindgen_futures::spawn_local(async move {
                let api = ApiService::new();
                let _ = api.update_http3_config(&config).await;
                saving.set(false);
                toast_success("HTTP/3 configuration saved");
            });
        })
    };

    html! {
        <div class="space-y-6">
            <div class="flex items-center justify-between py-2">
                <div>
                    <p class="text-primary font-medium">{ "Enable HTTP/3 (QUIC)" }</p>
                    <p class="text-sm text-secondary">{ "Next-generation protocol over UDP" }</p>
                </div>
                <button
                    onclick={{
                        let enabled = enabled.clone();
                        Callback::from(move |_: MouseEvent| {
                            enabled.set(!*enabled);
                        })
                    }}
                    class={format!("relative w-10 h-6 rounded-full {}", if *enabled { "bg-blue-600" } else { "bg-gray-600" })}
                >
                    <span class={format!("absolute top-1 left-1 w-4 h-4 bg-white rounded-full transition-transform {}", if *enabled { "translate-x-5" } else { "translate-x-0" })} />
                </button>
            </div>

            <div class="space-y-4">
                <div>
                    <label class="block text-sm font-medium text-primary mb-1">{ "Port" }</label>
                    <Input
                        label={"Port".to_string()}
                        name={"port".to_string()}
                        value={(*port).clone()}
                        on_change={Callback::from(move |v: String| port.set(v))}
                        input_type="number"
                    />
                </div>

                <div>
                    <label class="block text-sm font-medium text-primary mb-1">{ "Alt-Svc Max Age (seconds)" }</label>
                    <Input
                        label={"Alt-Svc Max Age".to_string()}
                        name={"alt_svc_max_age".to_string()}
                        value={(*alt_svc_max_age).clone()}
                        on_change={Callback::from(move |v: String| alt_svc_max_age.set(v))}
                        input_type="number"
                    />
                    <p class="text-xs text-secondary mt-1">{ "How long clients remember HTTP/3 is available (default: 86400 = 24h)" }</p>
                </div>

                <div>
                    <label class="block text-sm font-medium text-primary mb-1">{ "Max Request Size (bytes)" }</label>
                    <Input
                        label={"Max Request Size".to_string()}
                        name={"max_request_size".to_string()}
                        value={(*max_request_size).clone()}
                        on_change={Callback::from(move |v: String| max_request_size.set(v))}
                        input_type="number"
                    />
                    <p class="text-xs text-secondary mt-1">{ "Maximum HTTP/3 request body size (default: 10MB)" }</p>
                </div>
            </div>

            <div class="flex justify-end">
                <button
                    onclick={on_save}
                    disabled={*saving}
                    class="px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700 disabled:opacity-50"
                >
                    { if *saving { "Saving..." } else { "Save" } }
                </button>
            </div>
        </div>
    }
}

#[function_component]
fn RateLimitsSection() -> Html {
    let loading = use_state(|| true);
    let saving = use_state(|| false);

    // Rate Limit Memory fields
    let max_ip_entries = use_state(|| "100000".to_string());
    let cleanup_interval_secs = use_state(|| "60".to_string());
    let num_shards = use_state(|| "256".to_string());

    // Proxy Limits fields
    let max_response_size = use_state(|| "10000000".to_string());
    let connection_pool_size = use_state(|| "100".to_string());

    // Blocklist Limits fields
    let max_block_entries = use_state(|| "500000".to_string());
    let persist_interval_secs = use_state(|| "60".to_string());

    // Per-IP Defaults
    let ip_per_second = use_state(|| "10".to_string());
    let ip_per_minute = use_state(|| "60".to_string());
    let ip_per_5min = use_state(|| "200".to_string());
    let ip_per_hour = use_state(|| "500".to_string());
    let ip_per_day = use_state(|| "1000".to_string());
    let ip_burst = use_state(|| "20".to_string());

    // Global Defaults
    let global_per_second = use_state(|| "500".to_string());
    let global_per_minute = use_state(|| "5000".to_string());
    let max_connections = use_state(|| "1000".to_string());

    // Original values
    let original_max_ip_entries = use_state(|| "100000".to_string());
    let original_cleanup_interval_secs = use_state(|| "60".to_string());
    let original_num_shards = use_state(|| "256".to_string());
    let original_max_response_size = use_state(|| "10000000".to_string());
    let original_connection_pool_size = use_state(|| "100".to_string());
    let original_max_block_entries = use_state(|| "500000".to_string());
    let original_persist_interval_secs = use_state(|| "60".to_string());
    let original_ip_per_second = use_state(|| "10".to_string());
    let original_ip_per_minute = use_state(|| "60".to_string());
    let original_ip_per_5min = use_state(|| "200".to_string());
    let original_ip_per_hour = use_state(|| "500".to_string());
    let original_ip_per_day = use_state(|| "1000".to_string());
    let original_ip_burst = use_state(|| "20".to_string());
    let original_global_per_second = use_state(|| "500".to_string());
    let original_global_per_minute = use_state(|| "5000".to_string());
    let original_max_connections = use_state(|| "1000".to_string());

    let is_dirty = *max_ip_entries != *original_max_ip_entries
        || *cleanup_interval_secs != *original_cleanup_interval_secs
        || *num_shards != *original_num_shards
        || *max_response_size != *original_max_response_size
        || *connection_pool_size != *original_connection_pool_size
        || *max_block_entries != *original_max_block_entries
        || *persist_interval_secs != *original_persist_interval_secs
        || *ip_per_second != *original_ip_per_second
        || *ip_per_minute != *original_ip_per_minute
        || *ip_per_5min != *original_ip_per_5min
        || *ip_per_hour != *original_ip_per_hour
        || *ip_per_day != *original_ip_per_day
        || *ip_burst != *original_ip_burst
        || *global_per_second != *original_global_per_second
        || *global_per_minute != *original_global_per_minute
        || *max_connections != *original_max_connections;

    use_effect_with((), {
        let loading = loading.clone();
        let max_ip_entries = max_ip_entries.clone();
        let cleanup_interval_secs = cleanup_interval_secs.clone();
        let num_shards = num_shards.clone();
        let max_response_size = max_response_size.clone();
        let connection_pool_size = connection_pool_size.clone();
        let max_block_entries = max_block_entries.clone();
        let persist_interval_secs = persist_interval_secs.clone();
        let ip_per_second = ip_per_second.clone();
        let ip_per_minute = ip_per_minute.clone();
        let ip_per_5min = ip_per_5min.clone();
        let ip_per_hour = ip_per_hour.clone();
        let ip_per_day = ip_per_day.clone();
        let ip_burst = ip_burst.clone();
        let global_per_second = global_per_second.clone();
        let global_per_minute = global_per_minute.clone();
        let max_connections = max_connections.clone();
        let original_max_ip_entries = original_max_ip_entries.clone();
        let original_cleanup_interval_secs = original_cleanup_interval_secs.clone();
        let original_num_shards = original_num_shards.clone();
        let original_max_response_size = original_max_response_size.clone();
        let original_connection_pool_size = original_connection_pool_size.clone();
        let original_max_block_entries = original_max_block_entries.clone();
        let original_persist_interval_secs = original_persist_interval_secs.clone();
        let original_ip_per_second = original_ip_per_second.clone();
        let original_ip_per_minute = original_ip_per_minute.clone();
        let original_ip_per_5min = original_ip_per_5min.clone();
        let original_ip_per_hour = original_ip_per_hour.clone();
        let original_ip_per_day = original_ip_per_day.clone();
        let original_ip_burst = original_ip_burst.clone();
        let original_global_per_second = original_global_per_second.clone();
        let original_global_per_minute = original_global_per_minute.clone();
        let original_max_connections = original_max_connections.clone();
        move |_| {
            wasm_bindgen_futures::spawn_local(async move {
                let api = ApiService::new();
                let result = api.get_rate_limits_config().await;
                loading.set(false);

                if let Ok(data) = result {
                    // Rate Limit Memory
                    if let Some(rlm) = data.get("rate_limit_memory") {
                        if let Some(v) = rlm.get("max_ip_entries").and_then(|v| v.as_u64()) {
                            let s = v.to_string();
                            max_ip_entries.set(s.clone());
                            original_max_ip_entries.set(s);
                        }
                        if let Some(v) = rlm.get("cleanup_interval_secs").and_then(|v| v.as_u64()) {
                            let s = v.to_string();
                            cleanup_interval_secs.set(s.clone());
                            original_cleanup_interval_secs.set(s);
                        }
                        if let Some(v) = rlm.get("num_shards").and_then(|v| v.as_u64()) {
                            let s = v.to_string();
                            num_shards.set(s.clone());
                            original_num_shards.set(s);
                        }
                    }
                    // Proxy Limits
                    if let Some(pl) = data.get("proxy_limits") {
                        if let Some(v) = pl.get("max_response_size").and_then(|v| v.as_u64()) {
                            let s = v.to_string();
                            max_response_size.set(s.clone());
                            original_max_response_size.set(s);
                        }
                        if let Some(v) = pl.get("connection_pool_size").and_then(|v| v.as_u64()) {
                            let s = v.to_string();
                            connection_pool_size.set(s.clone());
                            original_connection_pool_size.set(s);
                        }
                    }
                    // Blocklist Limits
                    if let Some(bl) = data.get("blocklist_limits") {
                        if let Some(v) = bl.get("max_entries").and_then(|v| v.as_u64()) {
                            let s = v.to_string();
                            max_block_entries.set(s.clone());
                            original_max_block_entries.set(s);
                        }
                        if let Some(v) = bl.get("persist_interval_secs").and_then(|v| v.as_u64()) {
                            let s = v.to_string();
                            persist_interval_secs.set(s.clone());
                            original_persist_interval_secs.set(s);
                        }
                    }
                    // Defaults
                    if let Some(defaults) = data.get("defaults") {
                        if let Some(ip) = defaults.get("ip") {
                            let set_field =
                                |key: &str,
                                 state: &UseStateHandle<String>,
                                 orig: &UseStateHandle<String>| {
                                    if let Some(v) = ip.get(key).and_then(|v| v.as_u64()) {
                                        let s = v.to_string();
                                        state.set(s.clone());
                                        orig.set(s);
                                    }
                                };
                            set_field("per_second", &ip_per_second, &original_ip_per_second);
                            set_field("per_minute", &ip_per_minute, &original_ip_per_minute);
                            set_field("per_5min", &ip_per_5min, &original_ip_per_5min);
                            set_field("per_hour", &ip_per_hour, &original_ip_per_hour);
                            set_field("per_day", &ip_per_day, &original_ip_per_day);
                            set_field("burst", &ip_burst, &original_ip_burst);
                        }
                        if let Some(global) = defaults.get("global") {
                            let set_field =
                                |key: &str,
                                 state: &UseStateHandle<String>,
                                 orig: &UseStateHandle<String>| {
                                    if let Some(v) = global.get(key).and_then(|v| v.as_u64()) {
                                        let s = v.to_string();
                                        state.set(s.clone());
                                        orig.set(s);
                                    }
                                };
                            set_field(
                                "per_second",
                                &global_per_second,
                                &original_global_per_second,
                            );
                            set_field(
                                "per_minute",
                                &global_per_minute,
                                &original_global_per_minute,
                            );
                            set_field(
                                "max_connections",
                                &max_connections,
                                &original_max_connections,
                            );
                        }
                    }
                }
            });
            || {}
        }
    });

    if *loading {
        return html! { <LoadingSpinner /> };
    }

    let on_change = |state: UseStateHandle<String>| -> Callback<String> {
        Callback::from(move |value: String| {
            state.set(value);
        })
    };

    let on_save = {
        let saving = saving.clone();
        let max_ip_entries = max_ip_entries.clone();
        let cleanup_interval_secs = cleanup_interval_secs.clone();
        let num_shards = num_shards.clone();
        let max_response_size = max_response_size.clone();
        let connection_pool_size = connection_pool_size.clone();
        let max_block_entries = max_block_entries.clone();
        let persist_interval_secs = persist_interval_secs.clone();
        let ip_per_second = ip_per_second.clone();
        let ip_per_minute = ip_per_minute.clone();
        let ip_per_5min = ip_per_5min.clone();
        let ip_per_hour = ip_per_hour.clone();
        let ip_per_day = ip_per_day.clone();
        let ip_burst = ip_burst.clone();
        let global_per_second = global_per_second.clone();
        let global_per_minute = global_per_minute.clone();
        let max_connections = max_connections.clone();
        let original_max_ip_entries = original_max_ip_entries.clone();
        let original_cleanup_interval_secs = original_cleanup_interval_secs.clone();
        let original_num_shards = original_num_shards.clone();
        let original_max_response_size = original_max_response_size.clone();
        let original_connection_pool_size = original_connection_pool_size.clone();
        let original_max_block_entries = original_max_block_entries.clone();
        let original_persist_interval_secs = original_persist_interval_secs.clone();
        let original_ip_per_second = original_ip_per_second.clone();
        let original_ip_per_minute = original_ip_per_minute.clone();
        let original_ip_per_5min = original_ip_per_5min.clone();
        let original_ip_per_hour = original_ip_per_hour.clone();
        let original_ip_per_day = original_ip_per_day.clone();
        let original_ip_burst = original_ip_burst.clone();
        let original_global_per_second = original_global_per_second.clone();
        let original_global_per_minute = original_global_per_minute.clone();
        let original_max_connections = original_max_connections.clone();
        Callback::from(move |_| {
            let config = serde_json::json!({
                "rate_limit_memory": {
                    "max_ip_entries": max_ip_entries.parse::<usize>().unwrap_or(100000),
                    "cleanup_interval_secs": cleanup_interval_secs.parse::<u64>().unwrap_or(60),
                    "num_shards": num_shards.parse::<usize>().unwrap_or(256),
                },
                "proxy_limits": {
                    "max_response_size": max_response_size.parse::<usize>().unwrap_or(10000000),
                    "connection_pool_size": connection_pool_size.parse::<usize>().unwrap_or(100),
                },
                "blocklist_limits": {
                    "max_entries": max_block_entries.parse::<usize>().unwrap_or(500000),
                    "persist_interval_secs": persist_interval_secs.parse::<u64>().unwrap_or(60),
                },
                "defaults": {
                    "ip": {
                        "per_second": ip_per_second.parse::<u32>().unwrap_or(10),
                        "per_minute": ip_per_minute.parse::<u32>().unwrap_or(60),
                        "per_5min": ip_per_5min.parse::<u32>().unwrap_or(200),
                        "per_hour": ip_per_hour.parse::<u32>().unwrap_or(500),
                        "per_day": ip_per_day.parse::<u32>().unwrap_or(1000),
                        "burst": ip_burst.parse::<u32>().unwrap_or(20),
                    },
                    "global": {
                        "per_second": global_per_second.parse::<u32>().unwrap_or(500),
                        "per_minute": global_per_minute.parse::<u32>().unwrap_or(5000),
                        "max_connections": max_connections.parse::<u32>().unwrap_or(1000),
                    }
                }
            });
            let saving = saving.clone();
            let max_ip_entries = max_ip_entries.clone();
            let cleanup_interval_secs = cleanup_interval_secs.clone();
            let num_shards = num_shards.clone();
            let max_response_size = max_response_size.clone();
            let connection_pool_size = connection_pool_size.clone();
            let max_block_entries = max_block_entries.clone();
            let persist_interval_secs = persist_interval_secs.clone();
            let ip_per_second = ip_per_second.clone();
            let ip_per_minute = ip_per_minute.clone();
            let ip_per_5min = ip_per_5min.clone();
            let ip_per_hour = ip_per_hour.clone();
            let ip_per_day = ip_per_day.clone();
            let ip_burst = ip_burst.clone();
            let global_per_second = global_per_second.clone();
            let global_per_minute = global_per_minute.clone();
            let max_connections = max_connections.clone();
            let original_max_ip_entries = original_max_ip_entries.clone();
            let original_cleanup_interval_secs = original_cleanup_interval_secs.clone();
            let original_num_shards = original_num_shards.clone();
            let original_max_response_size = original_max_response_size.clone();
            let original_connection_pool_size = original_connection_pool_size.clone();
            let original_max_block_entries = original_max_block_entries.clone();
            let original_persist_interval_secs = original_persist_interval_secs.clone();
            let original_ip_per_second = original_ip_per_second.clone();
            let original_ip_per_minute = original_ip_per_minute.clone();
            let original_ip_per_5min = original_ip_per_5min.clone();
            let original_ip_per_hour = original_ip_per_hour.clone();
            let original_ip_per_day = original_ip_per_day.clone();
            let original_ip_burst = original_ip_burst.clone();
            let original_global_per_second = original_global_per_second.clone();
            let original_global_per_minute = original_global_per_minute.clone();
            let original_max_connections = original_max_connections.clone();
            saving.set(true);
            wasm_bindgen_futures::spawn_local(async move {
                let api = ApiService::new();
                let _ = api.update_rate_limits_config(&config).await;
                saving.set(false);
                original_max_ip_entries.set((*max_ip_entries).clone());
                original_cleanup_interval_secs.set((*cleanup_interval_secs).clone());
                original_num_shards.set((*num_shards).clone());
                original_max_response_size.set((*max_response_size).clone());
                original_connection_pool_size.set((*connection_pool_size).clone());
                original_max_block_entries.set((*max_block_entries).clone());
                original_persist_interval_secs.set((*persist_interval_secs).clone());
                original_ip_per_second.set((*ip_per_second).clone());
                original_ip_per_minute.set((*ip_per_minute).clone());
                original_ip_per_5min.set((*ip_per_5min).clone());
                original_ip_per_hour.set((*ip_per_hour).clone());
                original_ip_per_day.set((*ip_per_day).clone());
                original_ip_burst.set((*ip_burst).clone());
                original_global_per_second.set((*global_per_second).clone());
                original_global_per_minute.set((*global_per_minute).clone());
                original_max_connections.set((*max_connections).clone());
                toast_success("Rate limits configuration saved");
            });
        })
    };

    html! {
        <div class="space-y-6">
            <h3 class="font-semibold text-primary">{ "Rate Limit Memory" }</h3>
            <div class="grid grid-cols-3 gap-4">
                <Input label="Max IP Entries" name="max_ip_entries" input_type="number" value={(*max_ip_entries).clone()} on_change={on_change(max_ip_entries.clone())} />
                <Input label="Cleanup Interval (secs)" name="cleanup_interval_secs" input_type="number" value={(*cleanup_interval_secs).clone()} on_change={on_change(cleanup_interval_secs.clone())} />
                <Input label="Num Shards" name="num_shards" input_type="number" value={(*num_shards).clone()} on_change={on_change(num_shards.clone())} />
            </div>

            <h3 class="font-semibold text-primary mt-6">{ "Proxy Limits" }</h3>
            <div class="grid grid-cols-2 gap-4">
                <Input label="Max Response Size" name="max_response_size" input_type="number" value={(*max_response_size).clone()} on_change={on_change(max_response_size.clone())} />
                <Input label="Connection Pool Size" name="connection_pool_size" input_type="number" value={(*connection_pool_size).clone()} on_change={on_change(connection_pool_size.clone())} />
            </div>

            <h3 class="font-semibold text-primary mt-6">{ "Blocklist Limits" }</h3>
            <div class="grid grid-cols-2 gap-4">
                <Input label="Max Block Entries" name="max_block_entries" input_type="number" value={(*max_block_entries).clone()} on_change={on_change(max_block_entries.clone())} />
                <Input label="Persist Interval (secs)" name="persist_interval_secs" input_type="number" value={(*persist_interval_secs).clone()} on_change={on_change(persist_interval_secs.clone())} />
            </div>

            <h3 class="font-semibold text-primary mt-6">{ "Per-IP Defaults" }</h3>
            <div class="grid grid-cols-3 gap-4">
                <Input label="Per Second" name="ip_per_second" input_type="number" value={(*ip_per_second).clone()} on_change={on_change(ip_per_second.clone())} />
                <Input label="Per Minute" name="ip_per_minute" input_type="number" value={(*ip_per_minute).clone()} on_change={on_change(ip_per_minute.clone())} />
                <Input label="Per 5 Min" name="ip_per_5min" input_type="number" value={(*ip_per_5min).clone()} on_change={on_change(ip_per_5min.clone())} />
                <Input label="Per Hour" name="ip_per_hour" input_type="number" value={(*ip_per_hour).clone()} on_change={on_change(ip_per_hour.clone())} />
                <Input label="Per Day" name="ip_per_day" input_type="number" value={(*ip_per_day).clone()} on_change={on_change(ip_per_day.clone())} />
                <Input label="Burst" name="ip_burst" input_type="number" value={(*ip_burst).clone()} on_change={on_change(ip_burst.clone())} />
            </div>

            <h3 class="font-semibold text-primary mt-6">{ "Global Defaults" }</h3>
            <div class="grid grid-cols-3 gap-4">
                <Input label="Per Second" name="global_per_second" input_type="number" value={(*global_per_second).clone()} on_change={on_change(global_per_second.clone())} />
                <Input label="Per Minute" name="global_per_minute" input_type="number" value={(*global_per_minute).clone()} on_change={on_change(global_per_minute.clone())} />
                <Input label="Max Connections" name="max_connections" input_type="number" value={(*max_connections).clone()} on_change={on_change(max_connections.clone())} />
            </div>

            <div class="flex justify-end">
                <button
                    onclick={on_save}
                    disabled={*saving}
                    class={if is_dirty {
                        "px-4 py-2 bg-yellow-600 text-white rounded-lg hover:bg-yellow-700 disabled:opacity-50"
                    } else {
                        "px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700 disabled:opacity-50"
                    }}
                >
                    { if *saving { "Saving..." } else if is_dirty { "Save*" } else { "Save" } }
                </button>
            </div>
        </div>
    }
}

#[function_component]
fn BandwidthSection() -> Html {
    let loading = use_state(|| true);
    let saving = use_state(|| false);

    let monthly_cap_ingress = use_state(|| "0".to_string());
    let monthly_cap_egress = use_state(|| "0".to_string());
    let action_on_limit = use_state(|| "block".to_string());
    let reset_mode = use_state(|| "rolling_30_days".to_string());
    let fixed_day = use_state(String::new);
    let data_dir = use_state(|| "/var/lib/synvoid".to_string());

    let original_monthly_cap_ingress = use_state(|| "0".to_string());
    let original_monthly_cap_egress = use_state(|| "0".to_string());
    let original_action_on_limit = use_state(|| "block".to_string());
    let original_reset_mode = use_state(|| "rolling_30_days".to_string());
    let original_fixed_day = use_state(String::new);
    let original_data_dir = use_state(|| "/var/lib/synvoid".to_string());

    let is_dirty = *monthly_cap_ingress != *original_monthly_cap_ingress
        || *monthly_cap_egress != *original_monthly_cap_egress
        || *action_on_limit != *original_action_on_limit
        || *reset_mode != *original_reset_mode
        || *fixed_day != *original_fixed_day
        || *data_dir != *original_data_dir;

    use_effect_with((), {
        let loading = loading.clone();
        let monthly_cap_ingress = monthly_cap_ingress.clone();
        let monthly_cap_egress = monthly_cap_egress.clone();
        let action_on_limit = action_on_limit.clone();
        let reset_mode = reset_mode.clone();
        let fixed_day = fixed_day.clone();
        let data_dir = data_dir.clone();
        let original_monthly_cap_ingress = original_monthly_cap_ingress.clone();
        let original_monthly_cap_egress = original_monthly_cap_egress.clone();
        let original_action_on_limit = original_action_on_limit.clone();
        let original_reset_mode = original_reset_mode.clone();
        let original_fixed_day = original_fixed_day.clone();
        let original_data_dir = original_data_dir.clone();
        move |_| {
            wasm_bindgen_futures::spawn_local(async move {
                let api = ApiService::new();
                let result = api.get_traffic_shaping_config().await;
                loading.set(false);

                if let Ok(data) = result {
                    if let Some(config) = data.get("config") {
                        if let Some(bw) = config.get("bandwidth") {
                            if let Some(v) =
                                bw.get("monthly_cap_ingress_gb").and_then(|v| v.as_u64())
                            {
                                let s = v.to_string();
                                monthly_cap_ingress.set(s.clone());
                                original_monthly_cap_ingress.set(s);
                            }
                            if let Some(v) =
                                bw.get("monthly_cap_egress_gb").and_then(|v| v.as_u64())
                            {
                                let s = v.to_string();
                                monthly_cap_egress.set(s.clone());
                                original_monthly_cap_egress.set(s);
                            }
                            if let Some(v) = bw.get("action_on_limit").and_then(|v| v.as_str()) {
                                let s = v.to_string();
                                action_on_limit.set(s.clone());
                                original_action_on_limit.set(s);
                            }
                            if let Some(v) = bw.get("data_dir").and_then(|v| v.as_str()) {
                                let s = v.to_string();
                                data_dir.set(s.clone());
                                original_data_dir.set(s);
                            }
                            if let Some(reset) = bw.get("monthly_reset") {
                                if let Some(v) = reset.get("mode").and_then(|v| v.as_str()) {
                                    let s = v.to_string();
                                    reset_mode.set(s.clone());
                                    original_reset_mode.set(s);
                                }
                                if let Some(v) = reset.get("fixed_day").and_then(|v| v.as_u64()) {
                                    let s = v.to_string();
                                    fixed_day.set(s.clone());
                                    original_fixed_day.set(s);
                                }
                            }
                        }
                    }
                }
            });
            || {}
        }
    });

    if *loading {
        return html! { <LoadingSpinner /> };
    }

    let on_change = |state: UseStateHandle<String>| -> Callback<String> {
        Callback::from(move |value: String| {
            state.set(value);
        })
    };

    let on_save = {
        let saving = saving.clone();
        let monthly_cap_ingress = monthly_cap_ingress.clone();
        let monthly_cap_egress = monthly_cap_egress.clone();
        let action_on_limit = action_on_limit.clone();
        let reset_mode = reset_mode.clone();
        let fixed_day = fixed_day.clone();
        let data_dir = data_dir.clone();
        let original_monthly_cap_ingress = original_monthly_cap_ingress.clone();
        let original_monthly_cap_egress = original_monthly_cap_egress.clone();
        let original_action_on_limit = original_action_on_limit.clone();
        let original_reset_mode = original_reset_mode.clone();
        let original_fixed_day = original_fixed_day.clone();
        let original_data_dir = original_data_dir.clone();
        Callback::from(move |_| {
            let fixed_day_val = fixed_day.parse::<u32>().ok();
            let mut reset_obj = serde_json::json!({
                "mode": (*reset_mode).clone(),
            });
            if let Some(fd) = fixed_day_val {
                reset_obj["fixed_day"] = serde_json::json!(fd);
            }
            let config = serde_json::json!({
                "config": {
                    "bandwidth": {
                        "monthly_cap_ingress_gb": monthly_cap_ingress.parse::<u64>().unwrap_or(0),
                        "monthly_cap_egress_gb": monthly_cap_egress.parse::<u64>().unwrap_or(0),
                        "action_on_limit": (*action_on_limit).clone(),
                        "monthly_reset": reset_obj,
                        "data_dir": (*data_dir).clone(),
                    }
                }
            });
            let saving = saving.clone();
            let monthly_cap_ingress = monthly_cap_ingress.clone();
            let monthly_cap_egress = monthly_cap_egress.clone();
            let action_on_limit = action_on_limit.clone();
            let reset_mode = reset_mode.clone();
            let fixed_day = fixed_day.clone();
            let data_dir = data_dir.clone();
            let original_monthly_cap_ingress = original_monthly_cap_ingress.clone();
            let original_monthly_cap_egress = original_monthly_cap_egress.clone();
            let original_action_on_limit = original_action_on_limit.clone();
            let original_reset_mode = original_reset_mode.clone();
            let original_fixed_day = original_fixed_day.clone();
            let original_data_dir = original_data_dir.clone();
            saving.set(true);
            wasm_bindgen_futures::spawn_local(async move {
                let api = ApiService::new();
                let _ = api.update_traffic_shaping_config(&config).await;
                saving.set(false);
                original_monthly_cap_ingress.set((*monthly_cap_ingress).clone());
                original_monthly_cap_egress.set((*monthly_cap_egress).clone());
                original_action_on_limit.set((*action_on_limit).clone());
                original_reset_mode.set((*reset_mode).clone());
                original_fixed_day.set((*fixed_day).clone());
                original_data_dir.set((*data_dir).clone());
                toast_success("Bandwidth configuration saved");
            });
        })
    };

    html! {
        <div class="space-y-6">
            <h3 class="font-semibold text-primary">{ "Monthly Limits" }</h3>
            <div class="grid grid-cols-2 gap-4">
                <Input
                    label="Monthly Ingress Cap (GB)"
                    name="monthly_cap_ingress_gb"
                    input_type="number"
                    value={(*monthly_cap_ingress).clone()}
                    on_change={on_change(monthly_cap_ingress.clone())}
                    help="Set to 0 for unlimited. For example: 5000 for 5TB"
                />
                <Input
                    label="Monthly Egress Cap (GB)"
                    name="monthly_cap_egress_gb"
                    input_type="number"
                    value={(*monthly_cap_egress).clone()}
                    on_change={on_change(monthly_cap_egress.clone())}
                    help="Set to 0 for unlimited. For example: 5000 for 5TB"
                />
            </div>

            <div class="flex items-center justify-between py-3 border-b border-default">
                <div>
                    <p class="text-primary font-medium">{ "Action on Limit Exceeded" }</p>
                    <p class="text-sm text-secondary">{ "What to do when monthly bandwidth cap is reached" }</p>
                </div>
                <select
                    class="bg-tertiary text-primary px-3 py-2 rounded-lg border border-default"
                    value={(*action_on_limit).clone()}
                    onchange={
                        let action_on_limit = action_on_limit.clone();
                        Callback::from(move |e: Event| {
                            let target: web_sys::HtmlSelectElement = e.target_unchecked_into();
                            action_on_limit.set(target.value());
                        })
                    }
                >
                    <option value="block" selected={*action_on_limit == "block"}>{ "Hard Block (503)" }</option>
                    <option value="throttle" selected={*action_on_limit == "throttle"}>{ "Throttle to Monthly Rate" }</option>
                </select>
            </div>

            <h3 class="font-semibold text-primary mt-6">{ "Reset Configuration" }</h3>
            <div class="flex items-center justify-between py-3 border-b border-default">
                <div>
                    <p class="text-primary font-medium">{ "Reset Mode" }</p>
                    <p class="text-sm text-secondary">{ "How to determine the billing period" }</p>
                </div>
                <select
                    class="bg-tertiary text-primary px-3 py-2 rounded-lg border border-default"
                    value={(*reset_mode).clone()}
                    onchange={
                        let reset_mode = reset_mode.clone();
                        Callback::from(move |e: Event| {
                            let target: web_sys::HtmlSelectElement = e.target_unchecked_into();
                            reset_mode.set(target.value());
                        })
                    }
                >
                    <option value="rolling_30_days" selected={*reset_mode == "rolling_30_days"}>{ "Rolling 30 Days" }</option>
                    <option value="calendar_month" selected={*reset_mode == "calendar_month"}>{ "Calendar Month (1st of each month)" }</option>
                    <option value="fixed_date" selected={*reset_mode == "fixed_date"}>{ "Fixed Day of Month" }</option>
                </select>
            </div>

            <Input
                label="Fixed Day of Month (1-28)"
                name="fixed_day"
                input_type="number"
                value={(*fixed_day).clone()}
                on_change={on_change(fixed_day.clone())}
                help="Day of month to reset bandwidth counters (only for Fixed Date mode)"
            />

            <h3 class="font-semibold text-primary mt-6">{ "Data Persistence" }</h3>
            <Input
                label="Data Directory"
                name="bandwidth_data_dir"
                value={(*data_dir).clone()}
                on_change={on_change(data_dir.clone())}
                help="Directory to store bandwidth counter persistence file"
            />

            <div class="flex justify-end">
                <button
                    onclick={on_save}
                    disabled={*saving}
                    class={if is_dirty {
                        "px-4 py-2 bg-yellow-600 text-white rounded-lg hover:bg-yellow-700 disabled:opacity-50"
                    } else {
                        "px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700 disabled:opacity-50"
                    }}
                >
                    { if *saving { "Saving..." } else if is_dirty { "Save*" } else { "Save" } }
                </button>
            </div>
        </div>
    }
}

#[function_component]
fn BotSection() -> Html {
    let loading = use_state(|| true);
    let saving = use_state(|| false);

    let block_ai_crawlers = use_state(|| true);
    let enable_css_honeypot = use_state(|| true);
    let enable_js_challenge = use_state(|| false);
    let js_difficulty = use_state(|| "6".to_string());

    let original_block_ai_crawlers = use_state(|| true);
    let original_enable_css_honeypot = use_state(|| true);
    let original_enable_js_challenge = use_state(|| false);
    let original_js_difficulty = use_state(|| "6".to_string());

    let is_dirty = *block_ai_crawlers != *original_block_ai_crawlers
        || *enable_css_honeypot != *original_enable_css_honeypot
        || *enable_js_challenge != *original_enable_js_challenge
        || *js_difficulty != *original_js_difficulty;

    use_effect_with((), {
        let loading = loading.clone();
        let block_ai_crawlers = block_ai_crawlers.clone();
        let enable_css_honeypot = enable_css_honeypot.clone();
        let enable_js_challenge = enable_js_challenge.clone();
        let js_difficulty = js_difficulty.clone();
        let original_block_ai_crawlers = original_block_ai_crawlers.clone();
        let original_enable_css_honeypot = original_enable_css_honeypot.clone();
        let original_enable_js_challenge = original_enable_js_challenge.clone();
        let original_js_difficulty = original_js_difficulty.clone();
        move |_| {
            wasm_bindgen_futures::spawn_local(async move {
                let api = ApiService::new();
                let result = api.get_bot_detection_config().await;
                loading.set(false);

                if let Ok(data) = result {
                    if let Some(config) = data.get("config") {
                        if let Some(v) = config.get("block_ai_crawlers").and_then(|v| v.as_bool()) {
                            block_ai_crawlers.set(v);
                            original_block_ai_crawlers.set(v);
                        }
                        if let Some(v) = config.get("enable_css_honeypot").and_then(|v| v.as_bool())
                        {
                            enable_css_honeypot.set(v);
                            original_enable_css_honeypot.set(v);
                        }
                        if let Some(v) = config.get("enable_js_challenge").and_then(|v| v.as_bool())
                        {
                            enable_js_challenge.set(v);
                            original_enable_js_challenge.set(v);
                        }
                        if let Some(v) = config.get("js_difficulty").and_then(|v| v.as_u64()) {
                            let s = v.to_string();
                            js_difficulty.set(s.clone());
                            original_js_difficulty.set(s);
                        }
                    }
                }
            });
            || {}
        }
    });

    if *loading {
        return html! { <LoadingSpinner /> };
    }

    let on_difficulty_change = {
        let js_difficulty = js_difficulty.clone();
        Callback::from(move |value: String| {
            js_difficulty.set(value);
        })
    };

    let on_save = {
        let saving = saving.clone();
        let block_ai_crawlers = block_ai_crawlers.clone();
        let enable_css_honeypot = enable_css_honeypot.clone();
        let enable_js_challenge = enable_js_challenge.clone();
        let js_difficulty = js_difficulty.clone();
        let original_block_ai_crawlers = original_block_ai_crawlers.clone();
        let original_enable_css_honeypot = original_enable_css_honeypot.clone();
        let original_enable_js_challenge = original_enable_js_challenge.clone();
        let original_js_difficulty = original_js_difficulty.clone();
        Callback::from(move |_| {
            let config = serde_json::json!({
                "config": {
                    "block_ai_crawlers": *block_ai_crawlers,
                    "enable_css_honeypot": *enable_css_honeypot,
                    "enable_js_challenge": *enable_js_challenge,
                    "js_difficulty": js_difficulty.parse::<u8>().unwrap_or(6),
                }
            });
            let saving = saving.clone();
            let block_ai_crawlers = block_ai_crawlers.clone();
            let enable_css_honeypot = enable_css_honeypot.clone();
            let enable_js_challenge = enable_js_challenge.clone();
            let js_difficulty = js_difficulty.clone();
            let original_block_ai_crawlers = original_block_ai_crawlers.clone();
            let original_enable_css_honeypot = original_enable_css_honeypot.clone();
            let original_enable_js_challenge = original_enable_js_challenge.clone();
            let original_js_difficulty = original_js_difficulty.clone();
            saving.set(true);
            wasm_bindgen_futures::spawn_local(async move {
                let api = ApiService::new();
                let _ = api.update_bot_detection_config(&config).await;
                saving.set(false);
                original_block_ai_crawlers.set(*block_ai_crawlers);
                original_enable_css_honeypot.set(*enable_css_honeypot);
                original_enable_js_challenge.set(*enable_js_challenge);
                original_js_difficulty.set((*js_difficulty).clone());
                toast_success("Bot detection configuration saved");
            });
        })
    };

    html! {
        <div class="space-y-6">
            <div class="flex items-center justify-between py-2">
                <div>
                    <p class="text-primary font-medium">{ "Block AI Crawlers" }</p>
                    <p class="text-sm text-secondary">{ "Block known AI/ML web crawlers" }</p>
                </div>
                <button
                    onclick={
                        let block_ai_crawlers = block_ai_crawlers.clone();
                        Callback::from(move |_: MouseEvent| {
                            block_ai_crawlers.set(!*block_ai_crawlers);
                        })
                    }
                    class={format!("relative w-10 h-6 rounded-full {}", if *block_ai_crawlers { "bg-blue-600" } else { "bg-gray-600" })}
                >
                    <span class={format!("absolute top-1 left-1 w-4 h-4 bg-white rounded-full transition-transform {}", if *block_ai_crawlers { "translate-x-5" } else { "translate-x-0" })} />
                </button>
            </div>

            <div class="flex items-center justify-between py-2">
                <div>
                    <p class="text-primary font-medium">{ "Enable CSS Honeypot" }</p>
                    <p class="text-sm text-secondary">{ "Use CSS-based bot detection" }</p>
                </div>
                <button
                    onclick={
                        let enable_css_honeypot = enable_css_honeypot.clone();
                        Callback::from(move |_: MouseEvent| {
                            enable_css_honeypot.set(!*enable_css_honeypot);
                        })
                    }
                    class={format!("relative w-10 h-6 rounded-full {}", if *enable_css_honeypot { "bg-blue-600" } else { "bg-gray-600" })}
                >
                    <span class={format!("absolute top-1 left-1 w-4 h-4 bg-white rounded-full transition-transform {}", if *enable_css_honeypot { "translate-x-5" } else { "translate-x-0" })} />
                </button>
            </div>

            <div class="flex items-center justify-between py-2">
                <div>
                    <p class="text-primary font-medium">{ "Enable JS Challenge" }</p>
                    <p class="text-sm text-secondary">{ "Use Proof-of-Work challenges" }</p>
                </div>
                <button
                    onclick={
                        let enable_js_challenge = enable_js_challenge.clone();
                        Callback::from(move |_: MouseEvent| {
                            enable_js_challenge.set(!*enable_js_challenge);
                        })
                    }
                    class={format!("relative w-10 h-6 rounded-full {}", if *enable_js_challenge { "bg-blue-600" } else { "bg-gray-600" })}
                >
                    <span class={format!("absolute top-1 left-1 w-4 h-4 bg-white rounded-full transition-transform {}", if *enable_js_challenge { "translate-x-5" } else { "translate-x-0" })} />
                </button>
            </div>

            <Input
                label="JS Challenge Difficulty"
                name="js_difficulty"
                input_type="number"
                value={(*js_difficulty).clone()}
                on_change={on_difficulty_change}
                help="Higher values = harder challenges (1-10)"
            />

            <div class="flex justify-end">
                <button
                    onclick={on_save}
                    disabled={*saving}
                    class={if is_dirty {
                        "px-4 py-2 bg-yellow-600 text-white rounded-lg hover:bg-yellow-700 disabled:opacity-50"
                    } else {
                        "px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700 disabled:opacity-50"
                    }}
                >
                    { if *saving { "Saving..." } else if is_dirty { "Save*" } else { "Save" } }
                </button>
            </div>
        </div>
    }
}

#[function_component]
fn TarpitSection() -> Html {
    let loading = use_state(|| true);
    let saving = use_state(|| false);

    let enabled = use_state(|| true);
    let max_depth = use_state(|| "10".to_string());
    let links_per_page = use_state(|| "50".to_string());
    let response_delay_ms = use_state(|| "100".to_string());
    let scraper_user_agents = use_state(String::new);
    let content_templates = use_state(String::new);

    let original_enabled = use_state(|| true);
    let original_max_depth = use_state(|| "10".to_string());
    let original_links_per_page = use_state(|| "50".to_string());
    let original_response_delay_ms = use_state(|| "100".to_string());
    let original_scraper_user_agents = use_state(String::new);
    let original_content_templates = use_state(String::new);

    let is_dirty = *enabled != *original_enabled
        || *max_depth != *original_max_depth
        || *links_per_page != *original_links_per_page
        || *response_delay_ms != *original_response_delay_ms
        || *scraper_user_agents != *original_scraper_user_agents
        || *content_templates != *original_content_templates;

    use_effect_with((), {
        let loading = loading.clone();
        let enabled = enabled.clone();
        let max_depth = max_depth.clone();
        let links_per_page = links_per_page.clone();
        let response_delay_ms = response_delay_ms.clone();
        let scraper_user_agents = scraper_user_agents.clone();
        let content_templates = content_templates.clone();
        let original_enabled = original_enabled.clone();
        let original_max_depth = original_max_depth.clone();
        let original_links_per_page = original_links_per_page.clone();
        let original_response_delay_ms = original_response_delay_ms.clone();
        let original_scraper_user_agents = original_scraper_user_agents.clone();
        let original_content_templates = original_content_templates.clone();
        move |_| {
            wasm_bindgen_futures::spawn_local(async move {
                let api = ApiService::new();
                let result = api.get_main_config().await;
                loading.set(false);

                if let Ok(data) = result {
                    if let Some(config) = data.get("config") {
                        if let Some(tarpit) = config.get("tarpit") {
                            if let Some(v) = tarpit.get("enabled").and_then(|v| v.as_bool()) {
                                enabled.set(v);
                                original_enabled.set(v);
                            }
                            if let Some(v) = tarpit.get("max_depth").and_then(|v| v.as_u64()) {
                                let s = v.to_string();
                                max_depth.set(s.clone());
                                original_max_depth.set(s);
                            }
                            if let Some(v) = tarpit.get("links_per_page").and_then(|v| v.as_u64()) {
                                let s = v.to_string();
                                links_per_page.set(s.clone());
                                original_links_per_page.set(s);
                            }
                            if let Some(v) =
                                tarpit.get("response_delay_ms").and_then(|v| v.as_u64())
                            {
                                let s = v.to_string();
                                response_delay_ms.set(s.clone());
                                original_response_delay_ms.set(s);
                            }
                            if let Some(v) =
                                tarpit.get("scraper_user_agents").and_then(|v| v.as_array())
                            {
                                let agents: Vec<String> = v
                                    .iter()
                                    .filter_map(|s| s.as_str().map(|s| s.to_string()))
                                    .collect();
                                let s = agents.join(", ");
                                scraper_user_agents.set(s.clone());
                                original_scraper_user_agents.set(s);
                            }
                            if let Some(v) =
                                tarpit.get("content_templates").and_then(|v| v.as_array())
                            {
                                let templates: Vec<String> = v
                                    .iter()
                                    .filter_map(|s| s.as_str().map(|s| s.to_string()))
                                    .collect();
                                let s = templates.join(", ");
                                content_templates.set(s.clone());
                                original_content_templates.set(s);
                            }
                        }
                    }
                }
            });
            || {}
        }
    });

    if *loading {
        return html! { <LoadingSpinner /> };
    }

    let on_change = |state: UseStateHandle<String>| -> Callback<String> {
        Callback::from(move |value: String| {
            state.set(value);
        })
    };

    let on_save = {
        let saving = saving.clone();
        let enabled = enabled.clone();
        let max_depth = max_depth.clone();
        let links_per_page = links_per_page.clone();
        let response_delay_ms = response_delay_ms.clone();
        let scraper_user_agents = scraper_user_agents.clone();
        let content_templates = content_templates.clone();
        let original_enabled = original_enabled.clone();
        let original_max_depth = original_max_depth.clone();
        let original_links_per_page = original_links_per_page.clone();
        let original_response_delay_ms = original_response_delay_ms.clone();
        let original_scraper_user_agents = original_scraper_user_agents.clone();
        let original_content_templates = original_content_templates.clone();
        Callback::from(move |_| {
            let agents: Vec<String> = scraper_user_agents
                .split(',')
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect();
            let templates: Vec<String> = content_templates
                .split(',')
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect();
            let config = serde_json::json!({
                "config": {
                    "tarpit": {
                        "enabled": *enabled,
                        "max_depth": max_depth.parse::<u32>().unwrap_or(10),
                        "links_per_page": links_per_page.parse::<u32>().unwrap_or(50),
                        "response_delay_ms": response_delay_ms.parse::<u64>().unwrap_or(100),
                        "scraper_user_agents": agents,
                        "content_templates": templates,
                    }
                }
            });
            let saving = saving.clone();
            let enabled = enabled.clone();
            let max_depth = max_depth.clone();
            let links_per_page = links_per_page.clone();
            let response_delay_ms = response_delay_ms.clone();
            let scraper_user_agents = scraper_user_agents.clone();
            let content_templates = content_templates.clone();
            let original_enabled = original_enabled.clone();
            let original_max_depth = original_max_depth.clone();
            let original_links_per_page = original_links_per_page.clone();
            let original_response_delay_ms = original_response_delay_ms.clone();
            let original_scraper_user_agents = original_scraper_user_agents.clone();
            let original_content_templates = original_content_templates.clone();
            saving.set(true);
            wasm_bindgen_futures::spawn_local(async move {
                let api = ApiService::new();
                let _ = api.update_main_config(&config).await;
                saving.set(false);
                original_enabled.set(*enabled);
                original_max_depth.set((*max_depth).clone());
                original_links_per_page.set((*links_per_page).clone());
                original_response_delay_ms.set((*response_delay_ms).clone());
                original_scraper_user_agents.set((*scraper_user_agents).clone());
                original_content_templates.set((*content_templates).clone());
                toast_success("Tarpit configuration saved");
            });
        })
    };

    html! {
        <div class="space-y-6">
            <div class="flex items-center justify-between py-2">
                <div>
                    <p class="text-primary font-medium">{ "Enable Tarpit" }</p>
                    <p class="text-sm text-secondary">{ "Trap scrapers in an infinite maze of fake pages" }</p>
                </div>
                <button
                    onclick={{
                        let enabled = enabled.clone();
                        Callback::from(move |_: MouseEvent| {
                            enabled.set(!*enabled);
                        })
                    }}
                    class={format!("relative w-10 h-6 rounded-full {}", if *enabled { "bg-blue-600" } else { "bg-gray-600" })}
                >
                    <span class={format!("absolute top-1 left-1 w-4 h-4 bg-white rounded-full transition-transform {}", if *enabled { "translate-x-5" } else { "translate-x-0" })} />
                </button>
            </div>

            <div class="grid grid-cols-2 gap-4">
                <Input
                    label="Max Depth"
                    name="max_depth"
                    input_type="number"
                    value={(*max_depth).clone()}
                    on_change={on_change(max_depth.clone())}
                    help="Maximum depth of tarpit pages to generate"
                />
                <Input
                    label="Links Per Page"
                    name="links_per_page"
                    input_type="number"
                    value={(*links_per_page).clone()}
                    on_change={on_change(links_per_page.clone())}
                    help="Number of fake links to generate per tarpit page"
                />
            </div>

            <Input
                label="Response Delay (ms)"
                name="response_delay_ms"
                input_type="number"
                value={(*response_delay_ms).clone()}
                on_change={on_change(response_delay_ms.clone())}
                help="Milliseconds to delay tarpit responses"
            />

            <div>
                <Input
                    label="Scraper User Agents"
                    name="scraper_user_agents"
                    value={(*scraper_user_agents).clone()}
                    on_change={on_change(scraper_user_agents.clone())}
                    help="Comma-separated list of user agent strings to trap"
                />
                <p class="text-xs text-secondary mt-1">{ "Default: scrapy, curl, wget, python-requests, etc." }</p>
            </div>

            <div>
                <Input
                    label="Content Templates"
                    name="content_templates"
                    value={(*content_templates).clone()}
                    on_change={on_change(content_templates.clone())}
                    help="Comma-separated list of content template names"
                />
                <p class="text-xs text-secondary mt-1">{ "Templates used to generate fake page content" }</p>
            </div>

            <div class="flex justify-end">
                <button
                    onclick={on_save}
                    disabled={*saving}
                    class={if is_dirty {
                        "px-4 py-2 bg-yellow-600 text-white rounded-lg hover:bg-yellow-700 disabled:opacity-50"
                    } else {
                        "px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700 disabled:opacity-50"
                    }}
                >
                    { if *saving { "Saving..." } else if is_dirty { "Save*" } else { "Save" } }
                </button>
            </div>
        </div>
    }
}

#[function_component]
fn UploadSection() -> Html {
    let loading = use_state(|| true);
    let saving = use_state(|| false);

    let max_size = use_state(|| "100MB".to_string());
    let memory_threshold = use_state(|| "10MB".to_string());
    let scan_with_yara = use_state(|| true);
    let sandbox_enabled = use_state(|| true);

    let original_max_size = use_state(|| "100MB".to_string());
    let original_memory_threshold = use_state(|| "10MB".to_string());
    let original_scan_with_yara = use_state(|| true);
    let original_sandbox_enabled = use_state(|| true);

    let is_dirty = *max_size != *original_max_size
        || *memory_threshold != *original_memory_threshold
        || *scan_with_yara != *original_scan_with_yara
        || *sandbox_enabled != *original_sandbox_enabled;

    use_effect_with((), {
        let loading = loading.clone();
        let max_size = max_size.clone();
        let memory_threshold = memory_threshold.clone();
        let scan_with_yara = scan_with_yara.clone();
        let sandbox_enabled = sandbox_enabled.clone();
        let original_max_size = original_max_size.clone();
        let original_memory_threshold = original_memory_threshold.clone();
        let original_scan_with_yara = original_scan_with_yara.clone();
        let original_sandbox_enabled = original_sandbox_enabled.clone();
        move |_| {
            wasm_bindgen_futures::spawn_local(async move {
                let api = ApiService::new();
                let result = api.get_main_config().await;
                loading.set(false);

                if let Ok(data) = result {
                    if let Some(config) = data.get("config") {
                        if let Some(defaults) = config.get("defaults") {
                            if let Some(upload) = defaults.get("upload") {
                                if let Some(v) = upload.get("max_size").and_then(|v| v.as_str()) {
                                    let s = v.to_string();
                                    max_size.set(s.clone());
                                    original_max_size.set(s);
                                }
                                if let Some(v) =
                                    upload.get("memory_threshold").and_then(|v| v.as_str())
                                {
                                    let s = v.to_string();
                                    memory_threshold.set(s.clone());
                                    original_memory_threshold.set(s);
                                }
                                if let Some(v) =
                                    upload.get("scan_with_yara").and_then(|v| v.as_bool())
                                {
                                    scan_with_yara.set(v);
                                    original_scan_with_yara.set(v);
                                }
                                if let Some(v) =
                                    upload.get("sandbox_enabled").and_then(|v| v.as_bool())
                                {
                                    sandbox_enabled.set(v);
                                    original_sandbox_enabled.set(v);
                                }
                            }
                        }
                    }
                }
            });
            || {}
        }
    });

    if *loading {
        return html! { <LoadingSpinner /> };
    }

    let on_change = |state: UseStateHandle<String>| -> Callback<String> {
        Callback::from(move |value: String| {
            state.set(value);
        })
    };

    let on_save = {
        let saving = saving.clone();
        let max_size = max_size.clone();
        let memory_threshold = memory_threshold.clone();
        let scan_with_yara = scan_with_yara.clone();
        let sandbox_enabled = sandbox_enabled.clone();
        let original_max_size = original_max_size.clone();
        let original_memory_threshold = original_memory_threshold.clone();
        let original_scan_with_yara = original_scan_with_yara.clone();
        let original_sandbox_enabled = original_sandbox_enabled.clone();
        Callback::from(move |_| {
            let config = serde_json::json!({
                "config": {
                    "defaults": {
                        "upload": {
                            "max_size": (*max_size).clone(),
                            "memory_threshold": (*memory_threshold).clone(),
                            "scan_with_yara": *scan_with_yara,
                            "sandbox_enabled": *sandbox_enabled,
                        }
                    }
                }
            });
            let saving = saving.clone();
            let max_size = max_size.clone();
            let memory_threshold = memory_threshold.clone();
            let scan_with_yara = scan_with_yara.clone();
            let sandbox_enabled = sandbox_enabled.clone();
            let original_max_size = original_max_size.clone();
            let original_memory_threshold = original_memory_threshold.clone();
            let original_scan_with_yara = original_scan_with_yara.clone();
            let original_sandbox_enabled = original_sandbox_enabled.clone();
            saving.set(true);
            wasm_bindgen_futures::spawn_local(async move {
                let api = ApiService::new();
                let _ = api.update_main_config(&config).await;
                saving.set(false);
                original_max_size.set((*max_size).clone());
                original_memory_threshold.set((*memory_threshold).clone());
                original_scan_with_yara.set(*scan_with_yara);
                original_sandbox_enabled.set(*sandbox_enabled);
                toast_success("Upload configuration saved");
            });
        })
    };

    html! {
        <div class="space-y-6">
            <div class="grid grid-cols-2 gap-4">
                <Input
                    label="Max Upload Size"
                    name="upload_max_size"
                    value={(*max_size).clone()}
                    on_change={on_change(max_size.clone())}
                />
                <Input
                    label="Memory Threshold"
                    name="upload_memory_threshold"
                    value={(*memory_threshold).clone()}
                    on_change={on_change(memory_threshold.clone())}
                    help="Files under this threshold are scanned in-memory"
                />
            </div>

            <div class="flex items-center justify-between py-2">
                <div>
                    <p class="text-primary font-medium">{ "Scan with YARA" }</p>
                    <p class="text-sm text-secondary">{ "Scan uploads for malware signatures" }</p>
                </div>
                <button
                    onclick={
                        let scan_with_yara = scan_with_yara.clone();
                        Callback::from(move |_: MouseEvent| {
                            scan_with_yara.set(!*scan_with_yara);
                        })
                    }
                    class={format!("relative w-10 h-6 rounded-full {}", if *scan_with_yara { "bg-blue-600" } else { "bg-gray-600" })}
                >
                    <span class={format!("absolute top-1 left-1 w-4 h-4 bg-white rounded-full transition-transform {}", if *scan_with_yara { "translate-x-5" } else { "translate-x-0" })} />
                </button>
            </div>

            <div class="flex items-center justify-between py-2">
                <div>
                    <p class="text-primary font-medium">{ "Sandbox Files" }</p>
                    <p class="text-sm text-secondary">{ "Isolate uploads before forwarding" }</p>
                </div>
                <button
                    onclick={
                        let sandbox_enabled = sandbox_enabled.clone();
                        Callback::from(move |_: MouseEvent| {
                            sandbox_enabled.set(!*sandbox_enabled);
                        })
                    }
                    class={format!("relative w-10 h-6 rounded-full {}", if *sandbox_enabled { "bg-blue-600" } else { "bg-gray-600" })}
                >
                    <span class={format!("absolute top-1 left-1 w-4 h-4 bg-white rounded-full transition-transform {}", if *sandbox_enabled { "translate-x-5" } else { "translate-x-0" })} />
                </button>
            </div>

            <div class="flex justify-end">
                <button
                    onclick={on_save}
                    disabled={*saving}
                    class={if is_dirty {
                        "px-4 py-2 bg-yellow-600 text-white rounded-lg hover:bg-yellow-700 disabled:opacity-50"
                    } else {
                        "px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700 disabled:opacity-50"
                    }}
                >
                    { if *saving { "Saving..." } else if is_dirty { "Save*" } else { "Save" } }
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
    let preview_html = use_state(String::new);
    let preview_light = use_state(|| false);
    let saving = use_state(|| false);
    let loading = use_state(|| true);
    let original_preset = use_state(|| "default".to_string());
    let original_mode = use_state(|| "auto".to_string());

    let is_dirty = *selected_preset != *original_preset || *selected_mode != *original_mode;

    use_effect_with((), {
        let theme_data = theme_data.clone();
        let selected_preset = selected_preset.clone();
        let selected_mode = selected_mode.clone();
        let preview_html = preview_html.clone();
        let preview_light = preview_light.clone();
        let loading = loading.clone();
        let original_preset = original_preset.clone();
        let original_mode = original_mode.clone();
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
                    original_preset.set(data.preset.clone());
                    original_mode.set(data.mode.clone());

                    if let Ok(css) = css_result {
                        let html = generate_preview_html(&css, &data.colors, use_light);
                        preview_html.set(html);
                    }
                }
                loading.set(false);
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

            if let Some(ref _data) = *theme_data {
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

            if let Some(ref _data) = *theme_data {
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
        let original_preset = original_preset.clone();
        let original_mode = original_mode.clone();
        Callback::from(move |_| {
            let preset = (*selected_preset).clone();
            let mode = (*selected_mode).clone();
            let theme_data = theme_data.clone();
            let preview_html = preview_html.clone();
            let preview_light = *preview_light;
            let saving = saving.clone();
            let original_preset = original_preset.clone();
            let original_mode = original_mode.clone();
            let preset_for_orig = preset.clone();
            let mode_for_orig = mode.clone();

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
                        original_preset.set(preset_for_orig);
                        original_mode.set(mode_for_orig);
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

            if let Some(ref _data) = *theme_data {
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

    let presets = [
        ("default", "Default"),
        ("dark", "Dark"),
        ("light", "Light"),
        ("ocean", "Ocean"),
        ("forest", "Forest"),
        ("sunset", "Sunset"),
    ];

    let modes = [
        ("auto", "Auto (System)"),
        ("dark", "Dark"),
        ("light", "Light"),
    ];

    if *loading {
        return html! { <LoadingSpinner /> };
    }

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
                            <option value={*value}>{*label}</option>
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
                            <option value={*value}>{*label}</option>
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
                    class={if is_dirty {
                        "px-4 py-2 bg-yellow-600 text-white rounded-lg hover:bg-yellow-700 disabled:opacity-50"
                    } else {
                        "px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700 disabled:opacity-50"
                    }}
                >
                    { if *saving { "Saving..." } else if is_dirty { "Save Changes*" } else { "Save Changes" } }
                </button>
            </div>
        </div>
    }
}

#[function_component]
fn SecuritySection() -> Html {
    let loading = use_state(|| true);
    let saving = use_state(|| false);

    let global_security_headers = use_state(|| true);
    let sanitize_forwarded_headers = use_state(|| true);
    let ipc_enforce_signing = use_state(|| true);
    let allow_insecure_ipc_key = use_state(|| false);
    let more_clear_headers = use_state(String::new);

    let original_global_security_headers = use_state(|| true);
    let original_sanitize_forwarded_headers = use_state(|| true);
    let original_ipc_enforce_signing = use_state(|| true);
    let original_allow_insecure_ipc_key = use_state(|| false);
    let original_more_clear_headers = use_state(String::new);

    let is_dirty = *global_security_headers != *original_global_security_headers
        || *sanitize_forwarded_headers != *original_sanitize_forwarded_headers
        || *ipc_enforce_signing != *original_ipc_enforce_signing
        || *allow_insecure_ipc_key != *original_allow_insecure_ipc_key
        || *more_clear_headers != *original_more_clear_headers;

    use_effect_with((), {
        let loading = loading.clone();
        let global_security_headers = global_security_headers.clone();
        let sanitize_forwarded_headers = sanitize_forwarded_headers.clone();
        let ipc_enforce_signing = ipc_enforce_signing.clone();
        let allow_insecure_ipc_key = allow_insecure_ipc_key.clone();
        let more_clear_headers = more_clear_headers.clone();
        let original_global_security_headers = original_global_security_headers.clone();
        let original_sanitize_forwarded_headers = original_sanitize_forwarded_headers.clone();
        let original_ipc_enforce_signing = original_ipc_enforce_signing.clone();
        let original_allow_insecure_ipc_key = original_allow_insecure_ipc_key.clone();
        let original_more_clear_headers = original_more_clear_headers.clone();
        move |_| {
            wasm_bindgen_futures::spawn_local(async move {
                let api = ApiService::new();
                let result = api.get_security_config().await;
                loading.set(false);

                if let Ok(data) = result {
                    if let Some(config) = data.get("config") {
                        if let Some(v) = config
                            .get("global_security_headers")
                            .and_then(|v| v.as_bool())
                        {
                            global_security_headers.set(v);
                            original_global_security_headers.set(v);
                        }
                        if let Some(v) = config
                            .get("sanitize_forwarded_headers")
                            .and_then(|v| v.as_bool())
                        {
                            sanitize_forwarded_headers.set(v);
                            original_sanitize_forwarded_headers.set(v);
                        }
                        if let Some(v) = config.get("ipc_enforce_signing").and_then(|v| v.as_bool())
                        {
                            ipc_enforce_signing.set(v);
                            original_ipc_enforce_signing.set(v);
                        }
                        if let Some(v) = config
                            .get("allow_insecure_ipc_key")
                            .and_then(|v| v.as_bool())
                        {
                            allow_insecure_ipc_key.set(v);
                            original_allow_insecure_ipc_key.set(v);
                        }
                        if let Some(v) = config.get("more_clear_headers").and_then(|v| v.as_array())
                        {
                            let headers: Vec<String> = v
                                .iter()
                                .filter_map(|s| s.as_str().map(|s| s.to_string()))
                                .collect();
                            let s = headers.join(", ");
                            more_clear_headers.set(s.clone());
                            original_more_clear_headers.set(s);
                        }
                    }
                }
            });
            || {}
        }
    });

    if *loading {
        return html! { <LoadingSpinner /> };
    }

    let on_save = {
        let saving = saving.clone();
        let global_security_headers = global_security_headers.clone();
        let sanitize_forwarded_headers = sanitize_forwarded_headers.clone();
        let ipc_enforce_signing = ipc_enforce_signing.clone();
        let allow_insecure_ipc_key = allow_insecure_ipc_key.clone();
        let more_clear_headers = more_clear_headers.clone();
        let _original_global_security_headers = original_global_security_headers.clone();
        let _original_sanitize_forwarded_headers = original_sanitize_forwarded_headers.clone();
        let _original_ipc_enforce_signing = original_ipc_enforce_signing.clone();
        let _original_allow_insecure_ipc_key = original_allow_insecure_ipc_key.clone();
        let _original_more_clear_headers = original_more_clear_headers.clone();
        Callback::from(move |_| {
            let headers: Vec<String> = more_clear_headers
                .split(',')
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect();
            let config = serde_json::json!({
                "config": {
                    "global_security_headers": *global_security_headers,
                    "sanitize_forwarded_headers": *sanitize_forwarded_headers,
                    "ipc_enforce_signing": *ipc_enforce_signing,
                    "allow_insecure_ipc_key": *allow_insecure_ipc_key,
                    "more_clear_headers": headers,
                }
            });
            let saving = saving.clone();
            saving.set(true);
            wasm_bindgen_futures::spawn_local(async move {
                let api = ApiService::new();
                let _ = api.update_security_config(&config).await;
                saving.set(false);
                toast_success("Security configuration saved");
            });
        })
    };

    html! {
        <div class="space-y-6">
            <div class="flex items-center justify-between py-2">
                <div>
                    <p class="text-primary font-medium">{ "Global Security Headers" }</p>
                    <p class="text-sm text-secondary">{ "Enable HSTS, X-Frame-Options, and other security headers globally" }</p>
                </div>
                <button
                    onclick={{
                        let global_security_headers = global_security_headers.clone();
                        Callback::from(move |_: MouseEvent| {
                            global_security_headers.set(!*global_security_headers);
                        })
                    }}
                    class={format!("relative w-10 h-6 rounded-full {}", if *global_security_headers { "bg-blue-600" } else { "bg-gray-600" })}
                >
                    <span class={format!("absolute top-1 left-1 w-4 h-4 bg-white rounded-full transition-transform {}", if *global_security_headers { "translate-x-5" } else { "translate-x-0" })} />
                </button>
            </div>

            <div class="flex items-center justify-between py-2">
                <div>
                    <p class="text-primary font-medium">{ "Sanitize Forwarded Headers" }</p>
                    <p class="text-sm text-secondary">{ "Remove potentially spoofed X-Forwarded-For headers from clients" }</p>
                </div>
                <button
                    onclick={{
                        let sanitize_forwarded_headers = sanitize_forwarded_headers.clone();
                        Callback::from(move |_: MouseEvent| {
                            sanitize_forwarded_headers.set(!*sanitize_forwarded_headers);
                        })
                    }}
                    class={format!("relative w-10 h-6 rounded-full {}", if *sanitize_forwarded_headers { "bg-blue-600" } else { "bg-gray-600" })}
                >
                    <span class={format!("absolute top-1 left-1 w-4 h-4 bg-white rounded-full transition-transform {}", if *sanitize_forwarded_headers { "translate-x-5" } else { "translate-x-0" })} />
                </button>
            </div>

            <div class="flex items-center justify-between py-2">
                <div>
                    <p class="text-primary font-medium">{ "IPC Enforce Signing" }</p>
                    <p class="text-sm text-secondary">{ "Require HMAC signatures on IPC messages between processes" }</p>
                </div>
                <button
                    onclick={{
                        let ipc_enforce_signing = ipc_enforce_signing.clone();
                        Callback::from(move |_: MouseEvent| {
                            ipc_enforce_signing.set(!*ipc_enforce_signing);
                        })
                    }}
                    class={format!("relative w-10 h-6 rounded-full {}", if *ipc_enforce_signing { "bg-blue-600" } else { "bg-gray-600" })}
                >
                    <span class={format!("absolute top-1 left-1 w-4 h-4 bg-white rounded-full transition-transform {}", if *ipc_enforce_signing { "translate-x-5" } else { "translate-x-0" })} />
                </button>
            </div>

            <div class="flex items-center justify-between py-2">
                <div>
                    <p class="text-primary font-medium">{ "Allow Insecure IPC Key" }</p>
                    <p class="text-sm text-secondary">{ "Allow IPC key via environment variable (less secure)" } { restart_badge() }</p>
                </div>
                <button
                    onclick={{
                        let allow_insecure_ipc_key = allow_insecure_ipc_key.clone();
                        Callback::from(move |_: MouseEvent| {
                            allow_insecure_ipc_key.set(!*allow_insecure_ipc_key);
                        })
                    }}
                    class={format!("relative w-10 h-6 rounded-full {}", if *allow_insecure_ipc_key { "bg-blue-600" } else { "bg-gray-600" })}
                >
                    <span class={format!("absolute top-1 left-1 w-4 h-4 bg-white rounded-full transition-transform {}", if *allow_insecure_ipc_key { "translate-x-5" } else { "translate-x-0" })} />
                </button>
            </div>

            <Input
                label="Headers to Clear"
                name="more_clear_headers"
                value={(*more_clear_headers).clone()}
                on_change={Callback::from(move |v: String| more_clear_headers.set(v))}
                help="Comma-separated list of headers to remove from responses"
            />

            <div class="flex justify-end">
                <button
                    onclick={on_save}
                    disabled={*saving}
                    class={if is_dirty {
                        "px-4 py-2 bg-yellow-600 text-white rounded-lg hover:bg-yellow-700 disabled:opacity-50"
                    } else {
                        "px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700 disabled:opacity-50"
                    }}
                >
                    { if *saving { "Saving..." } else if is_dirty { "Save*" } else { "Save" } }
                </button>
            </div>
        </div>
    }
}

#[function_component]
fn TunnelSection() -> Html {
    let loading = use_state(|| true);
    let saving = use_state(|| false);

    let enabled = use_state(|| false);
    let vpn_enabled = use_state(|| false);
    let quic_enabled = use_state(|| false);
    let listen_port = use_state(|| "51820".to_string());

    let original_enabled = use_state(|| false);
    let original_vpn_enabled = use_state(|| false);
    let original_quic_enabled = use_state(|| false);
    let original_listen_port = use_state(|| "51820".to_string());

    let is_dirty = *enabled != *original_enabled
        || *vpn_enabled != *original_vpn_enabled
        || *quic_enabled != *original_quic_enabled
        || *listen_port != *original_listen_port;

    use_effect_with((), {
        let loading = loading.clone();
        let enabled = enabled.clone();
        let vpn_enabled = vpn_enabled.clone();
        let quic_enabled = quic_enabled.clone();
        let listen_port = listen_port.clone();
        let original_enabled = original_enabled.clone();
        let original_vpn_enabled = original_vpn_enabled.clone();
        let original_quic_enabled = original_quic_enabled.clone();
        let original_listen_port = original_listen_port.clone();
        move |_| {
            wasm_bindgen_futures::spawn_local(async move {
                let api = ApiService::new();
                let result = api.get_tunnel_config().await;
                loading.set(false);

                if let Ok(data) = result {
                    if let Some(config) = data.get("config") {
                        if let Some(v) = config.get("enabled").and_then(|v| v.as_bool()) {
                            enabled.set(v);
                            original_enabled.set(v);
                        }
                        if let Some(vpn) = config.get("vpn") {
                            if let Some(v) = vpn.get("enabled").and_then(|v| v.as_bool()) {
                                vpn_enabled.set(v);
                                original_vpn_enabled.set(v);
                            }
                        }
                        if let Some(quic) = config.get("quic") {
                            if let Some(v) = quic.get("enabled").and_then(|v| v.as_bool()) {
                                quic_enabled.set(v);
                                original_quic_enabled.set(v);
                            }
                        }
                        if let Some(v) = config
                            .get("quic")
                            .and_then(|v| v.get("port"))
                            .and_then(|v| v.as_u64())
                        {
                            let s = v.to_string();
                            listen_port.set(s.clone());
                            original_listen_port.set(s);
                        }
                    }
                }
            });
            || {}
        }
    });

    if *loading {
        return html! { <LoadingSpinner /> };
    }

    let on_save = {
        let saving = saving.clone();
        let enabled = enabled.clone();
        let vpn_enabled = vpn_enabled.clone();
        let quic_enabled = quic_enabled.clone();
        let listen_port = listen_port.clone();
        Callback::from(move |_| {
            let config = serde_json::json!({
                "config": {
                    "enabled": *enabled,
                    "vpn": {
                        "enabled": *vpn_enabled,
                    },
                    "quic": {
                        "enabled": *quic_enabled,
                        "port": listen_port.parse::<u16>().unwrap_or(51820),
                    },
                }
            });
            let saving = saving.clone();
            saving.set(true);
            wasm_bindgen_futures::spawn_local(async move {
                let api = ApiService::new();
                let _ = api.update_tunnel_config(&config).await;
                saving.set(false);
                toast_success("Tunnel configuration saved");
            });
        })
    };

    html! {
        <div class="space-y-6">
            <div class="flex items-center justify-between py-2">
                <div>
                    <p class="text-primary font-medium">{ "Enable Tunnel" }</p>
                    <p class="text-sm text-secondary">{ "Enable tunnel/VPN services" }</p>
                </div>
                <button
                    onclick={{
                        let enabled = enabled.clone();
                        Callback::from(move |_: MouseEvent| {
                            enabled.set(!*enabled);
                        })
                    }}
                    class={format!("relative w-10 h-6 rounded-full {}", if *enabled { "bg-blue-600" } else { "bg-gray-600" })}
                >
                    <span class={format!("absolute top-1 left-1 w-4 h-4 bg-white rounded-full transition-transform {}", if *enabled { "translate-x-5" } else { "translate-x-0" })} />
                </button>
            </div>

            <div class="flex items-center justify-between py-2">
                <div>
                    <p class="text-primary font-medium">{ "WireGuard VPN" }</p>
                    <p class="text-sm text-secondary">{ "Enable WireGuard VPN support" }</p>
                </div>
                <button
                    onclick={{
                        let vpn_enabled = vpn_enabled.clone();
                        Callback::from(move |_: MouseEvent| {
                            vpn_enabled.set(!*vpn_enabled);
                        })
                    }}
                    class={format!("relative w-10 h-6 rounded-full {}", if *vpn_enabled { "bg-blue-600" } else { "bg-gray-600" })}
                >
                    <span class={format!("absolute top-1 left-1 w-4 h-4 bg-white rounded-full transition-transform {}", if *vpn_enabled { "translate-x-5" } else { "translate-x-0" })} />
                </button>
            </div>

            <div class="flex items-center justify-between py-2">
                <div>
                    <p class="text-primary font-medium">{ "QUIC Tunnel" }</p>
                    <p class="text-sm text-secondary">{ "Enable QUIC-based tunnel support" }</p>
                </div>
                <button
                    onclick={{
                        let quic_enabled = quic_enabled.clone();
                        Callback::from(move |_: MouseEvent| {
                            quic_enabled.set(!*quic_enabled);
                        })
                    }}
                    class={format!("relative w-10 h-6 rounded-full {}", if *quic_enabled { "bg-blue-600" } else { "bg-gray-600" })}
                >
                    <span class={format!("absolute top-1 left-1 w-4 h-4 bg-white rounded-full transition-transform {}", if *quic_enabled { "translate-x-5" } else { "translate-x-0" })} />
                </button>
            </div>

            <Input
                label="QUIC Listen Port"
                name="listen_port"
                input_type="number"
                value={(*listen_port).clone()}
                on_change={Callback::from(move |v: String| listen_port.set(v))}
                help="Port for QUIC tunnel listener"
                badge={restart_badge()}
            />

            <p class="text-sm text-secondary">{ "Note: Full tunnel configuration requires advanced setup. Configure WireGuard peers, QUIC certificates, and mesh settings via config file." }</p>

            <div class="flex justify-end">
                <button
                    onclick={on_save}
                    disabled={*saving}
                    class={if is_dirty {
                        "px-4 py-2 bg-yellow-600 text-white rounded-lg hover:bg-yellow-700 disabled:opacity-50"
                    } else {
                        "px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700 disabled:opacity-50"
                    }}
                >
                    { if *saving { "Saving..." } else if is_dirty { "Save*" } else { "Save" } }
                </button>
            </div>
        </div>
    }
}

#[function_component]
fn PluginsSection() -> Html {
    let loading = use_state(|| true);
    let saving = use_state(|| false);

    let max_memory_mb = use_state(|| "64".to_string());
    let max_cpu_fuel = use_state(|| "1000000".to_string());
    let timeout_seconds = use_state(|| "30".to_string());

    let original_max_memory_mb = use_state(|| "64".to_string());
    let original_max_cpu_fuel = use_state(|| "1000000".to_string());
    let original_timeout_seconds = use_state(|| "30".to_string());

    let is_dirty = *max_memory_mb != *original_max_memory_mb
        || *max_cpu_fuel != *original_max_cpu_fuel
        || *timeout_seconds != *original_timeout_seconds;

    use_effect_with((), {
        let loading = loading.clone();
        let max_memory_mb = max_memory_mb.clone();
        let max_cpu_fuel = max_cpu_fuel.clone();
        let timeout_seconds = timeout_seconds.clone();
        let original_max_memory_mb = original_max_memory_mb.clone();
        let original_max_cpu_fuel = original_max_cpu_fuel.clone();
        let original_timeout_seconds = original_timeout_seconds.clone();
        move |_| {
            wasm_bindgen_futures::spawn_local(async move {
                let api = ApiService::new();
                let result = api.get_plugins_config().await;
                loading.set(false);

                if let Ok(data) = result {
                    if let Some(config) = data.get("config") {
                        if let Some(wasm) = config.get("wasm") {
                            if let Some(v) = wasm.get("max_memory_mb").and_then(|v| v.as_u64()) {
                                let s = v.to_string();
                                max_memory_mb.set(s.clone());
                                original_max_memory_mb.set(s);
                            }
                            if let Some(v) = wasm.get("max_cpu_fuel").and_then(|v| v.as_u64()) {
                                let s = v.to_string();
                                max_cpu_fuel.set(s.clone());
                                original_max_cpu_fuel.set(s);
                            }
                            if let Some(v) = wasm.get("timeout_seconds").and_then(|v| v.as_u64()) {
                                let s = v.to_string();
                                timeout_seconds.set(s.clone());
                                original_timeout_seconds.set(s);
                            }
                        }
                    }
                }
            });
            || {}
        }
    });

    if *loading {
        return html! { <LoadingSpinner /> };
    }

    let on_change = |state: UseStateHandle<String>| -> Callback<String> {
        Callback::from(move |value: String| {
            state.set(value);
        })
    };

    let on_save = {
        let saving = saving.clone();
        let max_memory_mb = max_memory_mb.clone();
        let max_cpu_fuel = max_cpu_fuel.clone();
        let timeout_seconds = timeout_seconds.clone();
        let original_max_memory_mb = original_max_memory_mb.clone();
        let original_max_cpu_fuel = original_max_cpu_fuel.clone();
        let original_timeout_seconds = original_timeout_seconds.clone();
        Callback::from(move |_| {
            let mem_str = (*max_memory_mb).clone();
            let cpu_str = (*max_cpu_fuel).clone();
            let timeout_str = (*timeout_seconds).clone();
            let config = serde_json::json!({
                "config": {
                    "wasm": {
                        "max_memory_mb": mem_str.parse::<usize>().unwrap_or(64),
                        "max_cpu_fuel": cpu_str.parse::<u64>().unwrap_or(1000000),
                        "timeout_seconds": timeout_str.parse::<u64>().unwrap_or(30),
                    }
                }
            });
            let saving = saving.clone();
            let orig_mem = original_max_memory_mb.clone();
            let orig_cpu = original_max_cpu_fuel.clone();
            let orig_timeout = original_timeout_seconds.clone();
            saving.set(true);
            wasm_bindgen_futures::spawn_local(async move {
                let api = ApiService::new();
                let _ = api.update_plugins_config(&config).await;
                saving.set(false);
                orig_mem.set(mem_str);
                orig_cpu.set(cpu_str);
                orig_timeout.set(timeout_str);
                toast_success("Plugins configuration saved");
            });
        })
    };

    html! {
        <div class="space-y-6">
            <p class="text-sm text-secondary">{ "Configure WASM plugin runtime settings. Individual plugins can override these defaults." }</p>

            <div class="grid grid-cols-3 gap-4">
                <Input
                    label="Max Memory (MB)"
                    name="max_memory_mb"
                    input_type="number"
                    value={(*max_memory_mb).clone()}
                    on_change={on_change(max_memory_mb.clone())}
                    help="Maximum memory per plugin instance"
                />
                <Input
                    label="Max CPU Fuel"
                    name="max_cpu_fuel"
                    input_type="number"
                    value={(*max_cpu_fuel).clone()}
                    on_change={on_change(max_cpu_fuel.clone())}
                    help="CPU fuel limit for plugin execution"
                />
                <Input
                    label="Timeout (seconds)"
                    name="timeout_seconds"
                    input_type="number"
                    value={(*timeout_seconds).clone()}
                    on_change={on_change(timeout_seconds.clone())}
                    help="Maximum execution time per plugin"
                />
            </div>

            <p class="text-sm text-secondary">{ "Note: Plugin instances are configured per-site. Manage plugin instances in site security settings." }</p>

            <div class="flex justify-end">
                <button
                    onclick={on_save}
                    disabled={*saving}
                    class={if is_dirty {
                        "px-4 py-2 bg-yellow-600 text-white rounded-lg hover:bg-yellow-700 disabled:opacity-50"
                    } else {
                        "px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700 disabled:opacity-50"
                    }}
                >
                    { if *saving { "Saving..." } else if is_dirty { "Save*" } else { "Save" } }
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
        <div class="footer">SynVoid</div>
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

#[function_component]
fn YaraSection() -> Html {
    let loading = use_state(|| true);
    let status_data = use_state(|| None::<serde_json::Value>);

    use_effect_with((), {
        let status_data = status_data.clone();
        let loading = loading.clone();
        move |_| {
            wasm_bindgen_futures::spawn_local(async move {
                let api = ApiService::new();
                let result = api.get_yara_status().await;
                loading.set(false);
                if let Ok(data) = result {
                    status_data.set(Some(data));
                }
            });
            || {}
        }
    });

    if *loading {
        return html! { <LoadingSpinner /> };
    }

    html! {
        <div class="space-y-6">
            <p class="text-sm text-secondary">{ "YARA rules management for malware scanning." }</p>
            if let Some(data) = &*status_data {
                <div class="grid grid-cols-2 gap-4">
                    <div class="bg-tertiary p-4 rounded-lg border border-default">
                        <p class="text-secondary text-sm">{"Status"}</p>
                        <p class="text-primary font-medium">{
                            if data.get("enabled").and_then(|v| v.as_bool()).unwrap_or(false) {
                                "Enabled"
                            } else {
                                "Disabled"
                            }
                        }</p>
                    </div>
                    <div class="bg-tertiary p-4 rounded-lg border border-default">
                        <p class="text-secondary text-sm">{"Node Role"}</p>
                        <p class="text-primary font-medium">{ data.get("node_role").and_then(|v| v.as_str()).unwrap_or("Unknown") }</p>
                    </div>
                    <div class="bg-tertiary p-4 rounded-lg border border-default">
                        <p class="text-secondary text-sm">{"Current Version"}</p>
                        <p class="text-primary font-medium">{ data.get("current_version").and_then(|v| v.as_str()).unwrap_or("None") }</p>
                    </div>
                    <div class="bg-tertiary p-4 rounded-lg border border-default">
                        <p class="text-secondary text-sm">{"Pending Submissions"}</p>
                        <p class="text-primary font-medium">{ data.get("pending_submissions").and_then(|v| v.as_u64()).unwrap_or(0) }</p>
                    </div>
                </div>
            } else {
                <p class="text-secondary">{"Unable to load YARA status"}</p>
            }
        </div>
    }
}

#[function_component]
fn ServerlessSection() -> Html {
    let loading = use_state(|| true);
    let health_data = use_state(|| None::<serde_json::Value>);
    let functions_data = use_state(|| None::<serde_json::Value>);

    use_effect_with((), {
        let health_data = health_data.clone();
        let functions_data = functions_data.clone();
        let loading = loading.clone();
        move |_| {
            wasm_bindgen_futures::spawn_local(async move {
                let api = ApiService::new();
                let health = api.get_serverless_health().await;
                let functions = api.get_serverless_functions().await;
                loading.set(false);
                if let Ok(data) = health {
                    health_data.set(Some(data));
                }
                if let Ok(data) = functions {
                    functions_data.set(Some(data));
                }
            });
            || {}
        }
    });

    if *loading {
        return html! { <LoadingSpinner /> };
    }

    html! {
        <div class="space-y-6">
            <p class="text-sm text-secondary">{ "Serverless WASM function configuration." }</p>
            if let Some(data) = &*health_data {
                <div class="grid grid-cols-3 gap-4">
                    <div class="bg-tertiary p-4 rounded-lg border border-default">
                        <p class="text-secondary text-sm">{"Total Functions"}</p>
                        <p class="text-primary font-medium text-xl">{ data.get("total_functions").and_then(|v| v.as_u64()).unwrap_or(0) }</p>
                    </div>
                    <div class="bg-tertiary p-4 rounded-lg border border-default">
                        <p class="text-secondary text-sm">{"Healthy"}</p>
                        <p class="text-primary font-medium text-xl text-green-500">{ data.get("healthy_functions").and_then(|v| v.as_u64()).unwrap_or(0) }</p>
                    </div>
                    <div class="bg-tertiary p-4 rounded-lg border border-default">
                        <p class="text-secondary text-sm">{"Unhealthy"}</p>
                        <p class="text-primary font-medium text-xl text-red-500">{ data.get("unhealthy_functions").and_then(|v| v.as_u64()).unwrap_or(0) }</p>
                    </div>
                </div>
            }
            if let Some(data) = &*functions_data {
                if let Some(functions) = data.get("functions").and_then(|v| v.as_array()) {
                    <div class="mt-4">
                        <h4 class="text-primary font-medium mb-2">{"Registered Functions"}</h4>
                        <div class="space-y-2 max-h-64 overflow-auto">
                            { for functions.iter().take(10).map(|f| {
                                let name = f.get("name").and_then(|v| v.as_str()).unwrap_or("Unknown");
                                let routes = f.get("route_count").and_then(|v| v.as_u64()).unwrap_or(0);
                                html! {
                                    <div class="bg-tertiary p-2 rounded border border-default">
                                        <p class="text-primary font-medium">{ name }</p>
                                        <p class="text-secondary text-sm">{ format!("{} routes", routes) }</p>
                                    </div>
                                }
                            }) }
                        </div>
                    </div>
                }
            }
        </div>
    }
}

#[function_component]
fn ProcessSection() -> Html {
    let loading = use_state(|| true);
    let master_status = use_state(|| None::<serde_json::Value>);
    let workers_status = use_state(|| None::<serde_json::Value>);

    use_effect_with((), {
        let master_status = master_status.clone();
        let workers_status = workers_status.clone();
        let loading = loading.clone();
        move |_| {
            wasm_bindgen_futures::spawn_local(async move {
                let api = ApiService::new();
                let master = api.get_master_status().await;
                let workers = api.get_workers().await;
                loading.set(false);
                if let Ok(data) = master {
                    master_status.set(Some(serde_json::to_value(data).unwrap_or_default()));
                }
                if let Ok(data) = workers {
                    workers_status.set(Some(serde_json::to_value(data).unwrap_or_default()));
                }
            });
            || {}
        }
    });

    if *loading {
        return html! { <LoadingSpinner /> };
    }

    html! {
        <div class="space-y-6">
            <p class="text-sm text-secondary">{ "Process and worker status overview." }</p>
            if let Some(data) = &*master_status {
                <div class="bg-tertiary p-4 rounded-lg border border-default">
                    <h4 class="text-primary font-medium mb-3">{"Master Process"}</h4>
                    <div class="grid grid-cols-2 gap-4">
                        <div>
                            <p class="text-secondary text-sm">{"PID"}</p>
                            <p class="text-primary">{ data.get("pid").and_then(|v| v.as_u64()).unwrap_or(0) }</p>
                        </div>
                        <div>
                            <p class="text-secondary text-sm">{"Version"}</p>
                            <p class="text-primary">{ data.get("version").and_then(|v| v.as_str()).unwrap_or("Unknown") }</p>
                        </div>
                        <div>
                            <p class="text-secondary text-sm">{"Mode"}</p>
                            <p class="text-primary">{ data.get("mode").and_then(|v| v.as_str()).unwrap_or("Unknown") }</p>
                        </div>
                        <div>
                            <p class="text-secondary text-sm">{"Total Requests"}</p>
                            <p class="text-primary">{ data.get("metrics").and_then(|m| m.get("total_requests").and_then(|v| v.as_u64())).unwrap_or(0) }</p>
                        </div>
                    </div>
                </div>
            }
            if let Some(data) = &*workers_status {
                if let Some(workers) = data.as_array() {
                    <div class="bg-tertiary p-4 rounded-lg border border-default">
                        <h4 class="text-primary font-medium mb-3">{"Workers"}</h4>
                        <div class="space-y-2 max-h-48 overflow-auto">
                            { for workers.iter().map(|w| {
                                let id = w.get("id").and_then(|v| v.as_str()).unwrap_or("Unknown");
                                let status = w.get("status").and_then(|v| v.as_str()).unwrap_or("Unknown");
                                let pid = w.get("pid").and_then(|v| v.as_u64()).unwrap_or(0);
                                html! {
                                    <div class="flex justify-between items-center py-2 border-b border-default last:border-0">
                                        <div>
                                            <p class="text-primary font-medium">{ id }</p>
                                            <p class="text-secondary text-sm">{ format!("PID: {}", pid) }</p>
                                        </div>
                                        <span class={format!("px-2 py-1 rounded text-xs {}",
                                            if status == "running" { "bg-green-500/20 text-green-400" } else { "bg-red-500/20 text-red-400" }
                                        )}>{ status }</span>
                                    </div>
                                }
                            }) }
                        </div>
                    </div>
                }
            }
        </div>
    }
}

#[function_component]
fn DefaultsSection() -> Html {
    let loading = use_state(|| true);
    let _saving = use_state(|| false);

    let defaults_data = use_state(|| None::<serde_json::Value>);

    use_effect_with((), {
        let defaults_data = defaults_data.clone();
        let loading = loading.clone();
        move |_| {
            wasm_bindgen_futures::spawn_local(async move {
                let api = ApiService::new();
                let result = api.get_main_config().await;
                loading.set(false);
                if let Ok(data) = result {
                    defaults_data.set(Some(data));
                }
            });
            || {}
        }
    });

    if *loading {
        return html! { <LoadingSpinner /> };
    }

    html! {
        <div class="space-y-6">
            <p class="text-sm text-secondary">{ "Default settings for new sites and global behavior." }</p>
            if let Some(data) = &*defaults_data {
                if let Some(config) = data.get("config") {
                    if let Some(defaults) = config.get("defaults") {
                        <div class="grid grid-cols-2 gap-4">
                            <div class="bg-tertiary p-4 rounded-lg border border-default">
                                <h4 class="text-primary font-medium mb-2">{"Bot Defaults"}</h4>
                                <p class="text-secondary text-sm">{"Block AI Crawlers"}</p>
                                <p class="text-primary">{ if defaults.get("bot").and_then(|b| b.get("block_ai_crawlers").and_then(|v| v.as_bool())).unwrap_or(false) { "Enabled" } else { "Disabled" } }</p>
                            </div>
                            <div class="bg-tertiary p-4 rounded-lg border border-default">
                                <h4 class="text-primary font-medium mb-2">{"Upload Defaults"}</h4>
                                <p class="text-secondary text-sm">{"Max Size"}</p>
                                <p class="text-primary">{ defaults.get("upload").and_then(|u| u.get("max_size").and_then(|v| v.as_str())).unwrap_or("Unknown") }</p>
                            </div>
                        </div>
                    }
                }
            }
        </div>
    }
}

#[function_component]
fn DnsSection() -> Html {
    let loading = use_state(|| true);
    let _saving = use_state(|| false);

    let dns_config = use_state(|| None::<serde_json::Value>);

    use_effect_with((), {
        let dns_config = dns_config.clone();
        let loading = loading.clone();
        move |_| {
            wasm_bindgen_futures::spawn_local(async move {
                let api = ApiService::new();
                let result = api.get_dns_config().await;
                loading.set(false);
                if let Ok(data) = result {
                    dns_config.set(Some(data));
                }
            });
            || {}
        }
    });

    if *loading {
        return html! { <LoadingSpinner /> };
    }

    html! {
        <div class="space-y-6">
            <p class="text-sm text-secondary">{ "DNS server and resolver configuration." }</p>
            if let Some(data) = &*dns_config {
                if let Some(config) = data.get("config") {
                    <div class="grid grid-cols-2 gap-4">
                        <Input
                            label="Upstream Provider"
                            name="upstream_provider"
                            value={config.get("upstream_provider").and_then(|v| v.as_str()).unwrap_or("System").to_string()}
                            on_change={Callback::from(move |_| {})}
                            help="DNS upstream provider"
                        />
                        <Input
                            label="Cache TTL"
                            name="cache_ttl"
                            value={config.get("cache_ttl").and_then(|v| v.as_u64()).unwrap_or(300).to_string()}
                            on_change={Callback::from(move |_| {})}
                            help="DNS cache TTL in seconds"
                        />
                    </div>
                }
            } else {
                <p class="text-secondary">{"DNS configuration not available (requires dns feature)"}</p>
            }
        </div>
    }
}

#[function_component]
fn MimeTypesSection() -> Html {
    let loading = use_state(|| true);
    let saving = use_state(|| false);

    let enabled = use_state(|| true);
    let file = use_state(|| "config/mimes/mime.types".to_string());

    let original_enabled = use_state(|| true);
    let original_file = use_state(|| "config/mimes/mime.types".to_string());

    let is_dirty = *enabled != *original_enabled || *file != *original_file;

    use_effect_with((), {
        let loading = loading.clone();
        let enabled = enabled.clone();
        let file = file.clone();
        let original_enabled = original_enabled.clone();
        let original_file = original_file.clone();
        move |_| {
            wasm_bindgen_futures::spawn_local(async move {
                let api = ApiService::new();
                let result = api.get_mime_types_config().await;
                loading.set(false);

                if let Ok(data) = result {
                    if let Some(config) = data.get("config") {
                        if let Some(v) = config.get("enabled").and_then(|v| v.as_bool()) {
                            enabled.set(v);
                            original_enabled.set(v);
                        }
                        if let Some(v) = config.get("file").and_then(|v| v.as_str()) {
                            let s = v.to_string();
                            file.set(s.clone());
                            original_file.set(s);
                        }
                    }
                }
            });
            || {}
        }
    });

    if *loading {
        return html! { <LoadingSpinner /> };
    }

    let on_toggle_enabled = {
        let enabled = enabled.clone();
        Callback::from(move |_: MouseEvent| {
            enabled.set(!*enabled);
        })
    };

    let on_file_change = {
        let file = file.clone();
        Callback::from(move |value: String| {
            file.set(value);
        })
    };

    let on_save = {
        let saving = saving.clone();
        let enabled = enabled.clone();
        let file = file.clone();
        let original_enabled = original_enabled.clone();
        let original_file = original_file.clone();
        Callback::from(move |_| {
            let config = serde_json::json!({
                "config": {
                    "enabled": *enabled,
                    "file": if (*file).is_empty() { serde_json::Value::Null } else { serde_json::Value::String((*file).clone()) },
                }
            });
            let saving = saving.clone();
            let enabled = enabled.clone();
            let file = file.clone();
            let original_enabled = original_enabled.clone();
            let original_file = original_file.clone();
            saving.set(true);
            wasm_bindgen_futures::spawn_local(async move {
                let api = ApiService::new();
                let _ = api.update_mime_types_config(&config).await;
                saving.set(false);
                original_enabled.set(*enabled);
                original_file.set((*file).clone());
                toast_success("MIME types configuration saved");
            });
        })
    };

    html! {
        <div class="space-y-6">
            <p class="text-sm text-secondary">{ "Configure MIME type mappings for file serving." }</p>

            <div class="flex items-center justify-between py-2">
                <div>
                    <p class="text-primary font-medium">{ "Enable Custom MIME Types" }</p>
                    <p class="text-sm text-secondary">{ "Use custom MIME type definitions from file" }</p>
                </div>
                <button
                    onclick={on_toggle_enabled}
                    class={format!("relative w-10 h-6 rounded-full {}", if *enabled { "bg-blue-600" } else { "bg-gray-600" })}
                >
                    <span class={format!("absolute top-1 left-1 w-4 h-4 bg-white rounded-full transition-transform {}", if *enabled { "translate-x-5" } else { "translate-x-0" })} />
                </button>
            </div>

            <Input
                label="MIME Types File"
                name="mime_file"
                value={(*file).clone()}
                on_change={on_file_change}
                help="Path to MIME types definition file"
            />

            <div class="flex justify-end">
                <button
                    onclick={on_save}
                    disabled={*saving}
                    class={if is_dirty {
                        "px-4 py-2 bg-yellow-600 text-white rounded-lg hover:bg-yellow-700 disabled:opacity-50"
                    } else {
                        "px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700 disabled:opacity-50"
                    }}
                >
                    { if *saving { "Saving..." } else if is_dirty { "Save*" } else { "Save" } }
                </button>
            </div>
        </div>
    }
}

#[function_component]
fn TcpUdpDefaultsSection() -> Html {
    let loading = use_state(|| true);
    let saving = use_state(|| false);

    // TCP fields
    let tcp_enabled = use_state(|| false);
    let tcp_worker_pool_size = use_state(|| "4".to_string());
    let tcp_nodelay = use_state(|| true);
    let tcp_send_buffer_size = use_state(|| "262144".to_string());
    let tcp_recv_buffer_size = use_state(|| "262144".to_string());
    let tcp_syn_rate_per_ip = use_state(|| "50".to_string());
    let tcp_syn_rate_global = use_state(|| "10000".to_string());
    let tcp_connection_rate_per_ip = use_state(|| "100".to_string());
    let tcp_connection_rate_global = use_state(|| "20000".to_string());
    let tcp_half_open_max = use_state(|| "1000".to_string());
    let tcp_half_open_per_ip_max = use_state(|| "10".to_string());

    // UDP fields
    let udp_enabled = use_state(|| false);
    let udp_worker_pool_size = use_state(|| "4".to_string());
    let udp_recv_buffer_size = use_state(|| "131072".to_string());
    let udp_send_buffer_size = use_state(|| "131072".to_string());
    let udp_rate_per_ip = use_state(|| "1000".to_string());
    let udp_rate_global = use_state(|| "100000".to_string());

    // Original values
    let original_tcp_enabled = use_state(|| false);
    let original_tcp_worker_pool_size = use_state(|| "4".to_string());
    let original_tcp_nodelay = use_state(|| true);
    let original_tcp_send_buffer_size = use_state(|| "262144".to_string());
    let original_tcp_recv_buffer_size = use_state(|| "262144".to_string());
    let original_tcp_syn_rate_per_ip = use_state(|| "50".to_string());
    let original_tcp_syn_rate_global = use_state(|| "10000".to_string());
    let original_tcp_connection_rate_per_ip = use_state(|| "100".to_string());
    let original_tcp_connection_rate_global = use_state(|| "20000".to_string());
    let original_tcp_half_open_max = use_state(|| "1000".to_string());
    let original_tcp_half_open_per_ip_max = use_state(|| "10".to_string());
    let original_udp_enabled = use_state(|| false);
    let original_udp_worker_pool_size = use_state(|| "4".to_string());
    let original_udp_recv_buffer_size = use_state(|| "131072".to_string());
    let original_udp_send_buffer_size = use_state(|| "131072".to_string());
    let original_udp_rate_per_ip = use_state(|| "1000".to_string());
    let original_udp_rate_global = use_state(|| "100000".to_string());

    let is_dirty = *tcp_enabled != *original_tcp_enabled
        || *tcp_worker_pool_size != *original_tcp_worker_pool_size
        || *tcp_nodelay != *original_tcp_nodelay
        || *tcp_send_buffer_size != *original_tcp_send_buffer_size
        || *tcp_recv_buffer_size != *original_tcp_recv_buffer_size
        || *tcp_syn_rate_per_ip != *original_tcp_syn_rate_per_ip
        || *tcp_syn_rate_global != *original_tcp_syn_rate_global
        || *tcp_connection_rate_per_ip != *original_tcp_connection_rate_per_ip
        || *tcp_connection_rate_global != *original_tcp_connection_rate_global
        || *tcp_half_open_max != *original_tcp_half_open_max
        || *tcp_half_open_per_ip_max != *original_tcp_half_open_per_ip_max
        || *udp_enabled != *original_udp_enabled
        || *udp_worker_pool_size != *original_udp_worker_pool_size
        || *udp_recv_buffer_size != *original_udp_recv_buffer_size
        || *udp_send_buffer_size != *original_udp_send_buffer_size
        || *udp_rate_per_ip != *original_udp_rate_per_ip
        || *udp_rate_global != *original_udp_rate_global;

    use_effect_with((), {
        let loading = loading.clone();
        let tcp_enabled = tcp_enabled.clone();
        let tcp_worker_pool_size = tcp_worker_pool_size.clone();
        let tcp_nodelay = tcp_nodelay.clone();
        let tcp_send_buffer_size = tcp_send_buffer_size.clone();
        let tcp_recv_buffer_size = tcp_recv_buffer_size.clone();
        let tcp_syn_rate_per_ip = tcp_syn_rate_per_ip.clone();
        let tcp_syn_rate_global = tcp_syn_rate_global.clone();
        let tcp_connection_rate_per_ip = tcp_connection_rate_per_ip.clone();
        let tcp_connection_rate_global = tcp_connection_rate_global.clone();
        let tcp_half_open_max = tcp_half_open_max.clone();
        let tcp_half_open_per_ip_max = tcp_half_open_per_ip_max.clone();
        let udp_enabled = udp_enabled.clone();
        let udp_worker_pool_size = udp_worker_pool_size.clone();
        let udp_recv_buffer_size = udp_recv_buffer_size.clone();
        let udp_send_buffer_size = udp_send_buffer_size.clone();
        let udp_rate_per_ip = udp_rate_per_ip.clone();
        let udp_rate_global = udp_rate_global.clone();
        let original_tcp_enabled = original_tcp_enabled.clone();
        let original_tcp_worker_pool_size = original_tcp_worker_pool_size.clone();
        let original_tcp_nodelay = original_tcp_nodelay.clone();
        let original_tcp_send_buffer_size = original_tcp_send_buffer_size.clone();
        let original_tcp_recv_buffer_size = original_tcp_recv_buffer_size.clone();
        let original_tcp_syn_rate_per_ip = original_tcp_syn_rate_per_ip.clone();
        let original_tcp_syn_rate_global = original_tcp_syn_rate_global.clone();
        let original_tcp_connection_rate_per_ip = original_tcp_connection_rate_per_ip.clone();
        let original_tcp_connection_rate_global = original_tcp_connection_rate_global.clone();
        let original_tcp_half_open_max = original_tcp_half_open_max.clone();
        let original_tcp_half_open_per_ip_max = original_tcp_half_open_per_ip_max.clone();
        let original_udp_enabled = original_udp_enabled.clone();
        let original_udp_worker_pool_size = original_udp_worker_pool_size.clone();
        let original_udp_recv_buffer_size = original_udp_recv_buffer_size.clone();
        let original_udp_send_buffer_size = original_udp_send_buffer_size.clone();
        let original_udp_rate_per_ip = original_udp_rate_per_ip.clone();
        let original_udp_rate_global = original_udp_rate_global.clone();
        move |_| {
            wasm_bindgen_futures::spawn_local(async move {
                let api = ApiService::new();
                let result = api.get_tcp_udp_defaults_config().await;
                loading.set(false);

                if let Ok(data) = result {
                    // TCP config
                    if let Some(tcp) = data.get("tcp") {
                        if let Some(v) = tcp.get("enabled").and_then(|v| v.as_bool()) {
                            tcp_enabled.set(v);
                            original_tcp_enabled.set(v);
                        }
                        if let Some(v) = tcp.get("worker_pool_size").and_then(|v| v.as_u64()) {
                            let s = v.to_string();
                            tcp_worker_pool_size.set(s.clone());
                            original_tcp_worker_pool_size.set(s);
                        }
                        if let Some(v) = tcp.get("nodelay").and_then(|v| v.as_bool()) {
                            tcp_nodelay.set(v);
                            original_tcp_nodelay.set(v);
                        }
                        if let Some(socket) = tcp.get("socket") {
                            if let Some(v) = socket.get("send_buffer_size").and_then(|v| v.as_u64())
                            {
                                let s = v.to_string();
                                tcp_send_buffer_size.set(s.clone());
                                original_tcp_send_buffer_size.set(s);
                            }
                            if let Some(v) = socket.get("recv_buffer_size").and_then(|v| v.as_u64())
                            {
                                let s = v.to_string();
                                tcp_recv_buffer_size.set(s.clone());
                                original_tcp_recv_buffer_size.set(s);
                            }
                        }
                        if let Some(v) = tcp.get("syn_rate_per_ip").and_then(|v| v.as_u64()) {
                            let s = v.to_string();
                            tcp_syn_rate_per_ip.set(s.clone());
                            original_tcp_syn_rate_per_ip.set(s);
                        }
                        if let Some(v) = tcp.get("syn_rate_global").and_then(|v| v.as_u64()) {
                            let s = v.to_string();
                            tcp_syn_rate_global.set(s.clone());
                            original_tcp_syn_rate_global.set(s);
                        }
                        if let Some(v) = tcp.get("connection_rate_per_ip").and_then(|v| v.as_u64())
                        {
                            let s = v.to_string();
                            tcp_connection_rate_per_ip.set(s.clone());
                            original_tcp_connection_rate_per_ip.set(s);
                        }
                        if let Some(v) = tcp.get("connection_rate_global").and_then(|v| v.as_u64())
                        {
                            let s = v.to_string();
                            tcp_connection_rate_global.set(s.clone());
                            original_tcp_connection_rate_global.set(s);
                        }
                        if let Some(v) = tcp.get("half_open_max").and_then(|v| v.as_u64()) {
                            let s = v.to_string();
                            tcp_half_open_max.set(s.clone());
                            original_tcp_half_open_max.set(s);
                        }
                        if let Some(v) = tcp.get("half_open_per_ip_max").and_then(|v| v.as_u64()) {
                            let s = v.to_string();
                            tcp_half_open_per_ip_max.set(s.clone());
                            original_tcp_half_open_per_ip_max.set(s);
                        }
                    }
                    // UDP config
                    if let Some(udp) = data.get("udp") {
                        if let Some(v) = udp.get("enabled").and_then(|v| v.as_bool()) {
                            udp_enabled.set(v);
                            original_udp_enabled.set(v);
                        }
                        if let Some(v) = udp.get("worker_pool_size").and_then(|v| v.as_u64()) {
                            let s = v.to_string();
                            udp_worker_pool_size.set(s.clone());
                            original_udp_worker_pool_size.set(s);
                        }
                        if let Some(socket) = udp.get("socket") {
                            if let Some(v) = socket.get("recv_buffer_size").and_then(|v| v.as_u64())
                            {
                                let s = v.to_string();
                                udp_recv_buffer_size.set(s.clone());
                                original_udp_recv_buffer_size.set(s);
                            }
                            if let Some(v) = socket.get("send_buffer_size").and_then(|v| v.as_u64())
                            {
                                let s = v.to_string();
                                udp_send_buffer_size.set(s.clone());
                                original_udp_send_buffer_size.set(s);
                            }
                        }
                        if let Some(v) = udp.get("rate_per_ip").and_then(|v| v.as_u64()) {
                            let s = v.to_string();
                            udp_rate_per_ip.set(s.clone());
                            original_udp_rate_per_ip.set(s);
                        }
                        if let Some(v) = udp.get("rate_global").and_then(|v| v.as_u64()) {
                            let s = v.to_string();
                            udp_rate_global.set(s.clone());
                            original_udp_rate_global.set(s);
                        }
                    }
                }
            });
            || {}
        }
    });

    if *loading {
        return html! { <LoadingSpinner /> };
    }

    let on_change = |state: UseStateHandle<String>| -> Callback<String> {
        Callback::from(move |value: String| {
            state.set(value);
        })
    };

    let on_toggle_tcp = {
        let tcp_enabled = tcp_enabled.clone();
        Callback::from(move |_: MouseEvent| {
            tcp_enabled.set(!*tcp_enabled);
        })
    };

    let on_toggle_udp = {
        let udp_enabled = udp_enabled.clone();
        Callback::from(move |_: MouseEvent| {
            udp_enabled.set(!*udp_enabled);
        })
    };

    let on_toggle_nodelay = {
        let tcp_nodelay = tcp_nodelay.clone();
        Callback::from(move |_: MouseEvent| {
            tcp_nodelay.set(!*tcp_nodelay);
        })
    };

    let on_save = {
        let saving = saving.clone();
        let tcp_enabled = tcp_enabled.clone();
        let tcp_worker_pool_size = tcp_worker_pool_size.clone();
        let tcp_nodelay = tcp_nodelay.clone();
        let tcp_send_buffer_size = tcp_send_buffer_size.clone();
        let tcp_recv_buffer_size = tcp_recv_buffer_size.clone();
        let tcp_syn_rate_per_ip = tcp_syn_rate_per_ip.clone();
        let tcp_syn_rate_global = tcp_syn_rate_global.clone();
        let tcp_connection_rate_per_ip = tcp_connection_rate_per_ip.clone();
        let tcp_connection_rate_global = tcp_connection_rate_global.clone();
        let tcp_half_open_max = tcp_half_open_max.clone();
        let tcp_half_open_per_ip_max = tcp_half_open_per_ip_max.clone();
        let udp_enabled = udp_enabled.clone();
        let udp_worker_pool_size = udp_worker_pool_size.clone();
        let udp_recv_buffer_size = udp_recv_buffer_size.clone();
        let udp_send_buffer_size = udp_send_buffer_size.clone();
        let udp_rate_per_ip = udp_rate_per_ip.clone();
        let udp_rate_global = udp_rate_global.clone();
        let original_tcp_enabled = original_tcp_enabled.clone();
        let original_tcp_worker_pool_size = original_tcp_worker_pool_size.clone();
        let original_tcp_nodelay = original_tcp_nodelay.clone();
        let original_tcp_send_buffer_size = original_tcp_send_buffer_size.clone();
        let original_tcp_recv_buffer_size = original_tcp_recv_buffer_size.clone();
        let original_tcp_syn_rate_per_ip = original_tcp_syn_rate_per_ip.clone();
        let original_tcp_syn_rate_global = original_tcp_syn_rate_global.clone();
        let original_tcp_connection_rate_per_ip = original_tcp_connection_rate_per_ip.clone();
        let original_tcp_connection_rate_global = original_tcp_connection_rate_global.clone();
        let original_tcp_half_open_max = original_tcp_half_open_max.clone();
        let original_tcp_half_open_per_ip_max = original_tcp_half_open_per_ip_max.clone();
        let original_udp_enabled = original_udp_enabled.clone();
        let original_udp_worker_pool_size = original_udp_worker_pool_size.clone();
        let original_udp_recv_buffer_size = original_udp_recv_buffer_size.clone();
        let original_udp_send_buffer_size = original_udp_send_buffer_size.clone();
        let original_udp_rate_per_ip = original_udp_rate_per_ip.clone();
        let original_udp_rate_global = original_udp_rate_global.clone();
        Callback::from(move |_| {
            let config = serde_json::json!({
                "tcp": {
                    "enabled": *tcp_enabled,
                    "worker_pool_size": tcp_worker_pool_size.parse::<usize>().unwrap_or(4),
                    "nodelay": *tcp_nodelay,
                    "socket": {
                        "send_buffer_size": tcp_send_buffer_size.parse::<usize>().unwrap_or(262144),
                        "recv_buffer_size": tcp_recv_buffer_size.parse::<usize>().unwrap_or(262144),
                    },
                    "syn_rate_per_ip": tcp_syn_rate_per_ip.parse::<u32>().unwrap_or(50),
                    "syn_rate_global": tcp_syn_rate_global.parse::<u32>().unwrap_or(10000),
                    "connection_rate_per_ip": tcp_connection_rate_per_ip.parse::<u32>().unwrap_or(100),
                    "connection_rate_global": tcp_connection_rate_global.parse::<u32>().unwrap_or(20000),
                    "half_open_max": tcp_half_open_max.parse::<u32>().unwrap_or(1000),
                    "half_open_per_ip_max": tcp_half_open_per_ip_max.parse::<u32>().unwrap_or(10),
                },
                "udp": {
                    "enabled": *udp_enabled,
                    "worker_pool_size": udp_worker_pool_size.parse::<usize>().unwrap_or(4),
                    "socket": {
                        "recv_buffer_size": udp_recv_buffer_size.parse::<usize>().unwrap_or(131072),
                        "send_buffer_size": udp_send_buffer_size.parse::<usize>().unwrap_or(131072),
                    },
                    "rate_per_ip": udp_rate_per_ip.parse::<u32>().unwrap_or(1000),
                    "rate_global": udp_rate_global.parse::<u32>().unwrap_or(100000),
                }
            });
            let saving = saving.clone();
            let tcp_enabled = tcp_enabled.clone();
            let tcp_worker_pool_size = tcp_worker_pool_size.clone();
            let tcp_nodelay = tcp_nodelay.clone();
            let tcp_send_buffer_size = tcp_send_buffer_size.clone();
            let tcp_recv_buffer_size = tcp_recv_buffer_size.clone();
            let tcp_syn_rate_per_ip = tcp_syn_rate_per_ip.clone();
            let tcp_syn_rate_global = tcp_syn_rate_global.clone();
            let tcp_connection_rate_per_ip = tcp_connection_rate_per_ip.clone();
            let tcp_connection_rate_global = tcp_connection_rate_global.clone();
            let tcp_half_open_max = tcp_half_open_max.clone();
            let tcp_half_open_per_ip_max = tcp_half_open_per_ip_max.clone();
            let udp_enabled = udp_enabled.clone();
            let udp_worker_pool_size = udp_worker_pool_size.clone();
            let udp_recv_buffer_size = udp_recv_buffer_size.clone();
            let udp_send_buffer_size = udp_send_buffer_size.clone();
            let udp_rate_per_ip = udp_rate_per_ip.clone();
            let udp_rate_global = udp_rate_global.clone();
            let original_tcp_enabled = original_tcp_enabled.clone();
            let original_tcp_worker_pool_size = original_tcp_worker_pool_size.clone();
            let original_tcp_nodelay = original_tcp_nodelay.clone();
            let original_tcp_send_buffer_size = original_tcp_send_buffer_size.clone();
            let original_tcp_recv_buffer_size = original_tcp_recv_buffer_size.clone();
            let original_tcp_syn_rate_per_ip = original_tcp_syn_rate_per_ip.clone();
            let original_tcp_syn_rate_global = original_tcp_syn_rate_global.clone();
            let original_tcp_connection_rate_per_ip = original_tcp_connection_rate_per_ip.clone();
            let original_tcp_connection_rate_global = original_tcp_connection_rate_global.clone();
            let original_tcp_half_open_max = original_tcp_half_open_max.clone();
            let original_tcp_half_open_per_ip_max = original_tcp_half_open_per_ip_max.clone();
            let original_udp_enabled = original_udp_enabled.clone();
            let original_udp_worker_pool_size = original_udp_worker_pool_size.clone();
            let original_udp_recv_buffer_size = original_udp_recv_buffer_size.clone();
            let original_udp_send_buffer_size = original_udp_send_buffer_size.clone();
            let original_udp_rate_per_ip = original_udp_rate_per_ip.clone();
            let original_udp_rate_global = original_udp_rate_global.clone();
            saving.set(true);
            wasm_bindgen_futures::spawn_local(async move {
                let api = ApiService::new();
                let _ = api.update_tcp_udp_defaults_config(&config).await;
                saving.set(false);
                original_tcp_enabled.set(*tcp_enabled);
                original_tcp_worker_pool_size.set((*tcp_worker_pool_size).clone());
                original_tcp_nodelay.set(*tcp_nodelay);
                original_tcp_send_buffer_size.set((*tcp_send_buffer_size).clone());
                original_tcp_recv_buffer_size.set((*tcp_recv_buffer_size).clone());
                original_tcp_syn_rate_per_ip.set((*tcp_syn_rate_per_ip).clone());
                original_tcp_syn_rate_global.set((*tcp_syn_rate_global).clone());
                original_tcp_connection_rate_per_ip.set((*tcp_connection_rate_per_ip).clone());
                original_tcp_connection_rate_global.set((*tcp_connection_rate_global).clone());
                original_tcp_half_open_max.set((*tcp_half_open_max).clone());
                original_tcp_half_open_per_ip_max.set((*tcp_half_open_per_ip_max).clone());
                original_udp_enabled.set(*udp_enabled);
                original_udp_worker_pool_size.set((*udp_worker_pool_size).clone());
                original_udp_recv_buffer_size.set((*udp_recv_buffer_size).clone());
                original_udp_send_buffer_size.set((*udp_send_buffer_size).clone());
                original_udp_rate_per_ip.set((*udp_rate_per_ip).clone());
                original_udp_rate_global.set((*udp_rate_global).clone());
                toast_success("TCP/UDP defaults configuration saved");
            });
        })
    };

    html! {
        <div class="space-y-6">
            <h3 class="font-semibold text-primary">{ "TCP Defaults" }</h3>
            <div class="flex items-center justify-between py-2">
                <div>
                    <p class="text-primary font-medium">{ "Enable TCP Proxy" }</p>
                </div>
                <button
                    onclick={on_toggle_tcp}
                    class={format!("relative w-10 h-6 rounded-full {}", if *tcp_enabled { "bg-blue-600" } else { "bg-gray-600" })}
                >
                    <span class={format!("absolute top-1 left-1 w-4 h-4 bg-white rounded-full transition-transform {}", if *tcp_enabled { "translate-x-5" } else { "translate-x-0" })} />
                </button>
            </div>

            <div class="grid grid-cols-2 gap-4">
                <Input label="Worker Pool Size" name="tcp_worker_pool_size" input_type="number" value={(*tcp_worker_pool_size).clone()} on_change={on_change(tcp_worker_pool_size.clone())} />
                <div class="flex items-center justify-between py-2">
                    <div>
                        <p class="text-primary font-medium">{ "TCP Nodelay" }</p>
                    </div>
                    <button
                        onclick={on_toggle_nodelay}
                        class={format!("relative w-10 h-6 rounded-full {}", if *tcp_nodelay { "bg-blue-600" } else { "bg-gray-600" })}
                    >
                        <span class={format!("absolute top-1 left-1 w-4 h-4 bg-white rounded-full transition-transform {}", if *tcp_nodelay { "translate-x-5" } else { "translate-x-0" })} />
                    </button>
                </div>
            </div>

            <div class="grid grid-cols-2 gap-4">
                <Input label="Send Buffer Size" name="tcp_send_buffer_size" input_type="number" value={(*tcp_send_buffer_size).clone()} on_change={on_change(tcp_send_buffer_size.clone())} />
                <Input label="Recv Buffer Size" name="tcp_recv_buffer_size" input_type="number" value={(*tcp_recv_buffer_size).clone()} on_change={on_change(tcp_recv_buffer_size.clone())} />
            </div>

            <div class="grid grid-cols-2 gap-4">
                <Input label="SYN Rate Per IP" name="tcp_syn_rate_per_ip" input_type="number" value={(*tcp_syn_rate_per_ip).clone()} on_change={on_change(tcp_syn_rate_per_ip.clone())} />
                <Input label="SYN Rate Global" name="tcp_syn_rate_global" input_type="number" value={(*tcp_syn_rate_global).clone()} on_change={on_change(tcp_syn_rate_global.clone())} />
            </div>

            <div class="grid grid-cols-2 gap-4">
                <Input label="Connection Rate Per IP" name="tcp_connection_rate_per_ip" input_type="number" value={(*tcp_connection_rate_per_ip).clone()} on_change={on_change(tcp_connection_rate_per_ip.clone())} />
                <Input label="Connection Rate Global" name="tcp_connection_rate_global" input_type="number" value={(*tcp_connection_rate_global).clone()} on_change={on_change(tcp_connection_rate_global.clone())} />
            </div>

            <div class="grid grid-cols-2 gap-4">
                <Input label="Half Open Max" name="tcp_half_open_max" input_type="number" value={(*tcp_half_open_max).clone()} on_change={on_change(tcp_half_open_max.clone())} />
                <Input label="Half Open Per IP Max" name="tcp_half_open_per_ip_max" input_type="number" value={(*tcp_half_open_per_ip_max).clone()} on_change={on_change(tcp_half_open_per_ip_max.clone())} />
            </div>

            <h3 class="font-semibold text-primary mt-6">{ "UDP Defaults" }</h3>
            <div class="flex items-center justify-between py-2">
                <div>
                    <p class="text-primary font-medium">{ "Enable UDP Proxy" }</p>
                </div>
                <button
                    onclick={on_toggle_udp}
                    class={format!("relative w-10 h-6 rounded-full {}", if *udp_enabled { "bg-blue-600" } else { "bg-gray-600" })}
                >
                    <span class={format!("absolute top-1 left-1 w-4 h-4 bg-white rounded-full transition-transform {}", if *udp_enabled { "translate-x-5" } else { "translate-x-0" })} />
                </button>
            </div>

            <div class="grid grid-cols-2 gap-4">
                <Input label="Worker Pool Size" name="udp_worker_pool_size" input_type="number" value={(*udp_worker_pool_size).clone()} on_change={on_change(udp_worker_pool_size.clone())} />
                <Input label="Recv Buffer Size" name="udp_recv_buffer_size" input_type="number" value={(*udp_recv_buffer_size).clone()} on_change={on_change(udp_recv_buffer_size.clone())} />
            </div>

            <div class="grid grid-cols-2 gap-4">
                <Input label="Send Buffer Size" name="udp_send_buffer_size" input_type="number" value={(*udp_send_buffer_size).clone()} on_change={on_change(udp_send_buffer_size.clone())} />
                <Input label="Rate Per IP" name="udp_rate_per_ip" input_type="number" value={(*udp_rate_per_ip).clone()} on_change={on_change(udp_rate_per_ip.clone())} />
            </div>

            <div class="grid grid-cols-2 gap-4">
                <Input label="Rate Global" name="udp_rate_global" input_type="number" value={(*udp_rate_global).clone()} on_change={on_change(udp_rate_global.clone())} />
            </div>

            <div class="flex justify-end">
                <button
                    onclick={on_save}
                    disabled={*saving}
                    class={if is_dirty {
                        "px-4 py-2 bg-yellow-600 text-white rounded-lg hover:bg-yellow-700 disabled:opacity-50"
                    } else {
                        "px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700 disabled:opacity-50"
                    }}
                >
                    { if *saving { "Saving..." } else if is_dirty { "Save*" } else { "Save" } }
                </button>
            </div>
        </div>
    }
}

#[function_component]
fn FallbackSection() -> Html {
    let loading = use_state(|| true);
    let saving = use_state(|| false);

    let mode = use_state(|| "return_404".to_string());
    let upstream = use_state(String::new);

    let original_mode = use_state(|| "return_404".to_string());
    let original_upstream = use_state(String::new);

    let is_dirty = *mode != *original_mode || *upstream != *original_upstream;

    use_effect_with((), {
        let loading = loading.clone();
        let mode = mode.clone();
        let upstream = upstream.clone();
        let original_mode = original_mode.clone();
        let original_upstream = original_upstream.clone();
        move |_| {
            wasm_bindgen_futures::spawn_local(async move {
                let api = ApiService::new();
                let result = api.get_fallback_config().await;
                loading.set(false);

                if let Ok(data) = result {
                    if let Some(config) = data.get("config") {
                        if let Some(v) = config.get("mode").and_then(|v| v.as_str()) {
                            let s = v.to_string();
                            mode.set(s.clone());
                            original_mode.set(s);
                        }
                        if let Some(v) = config.get("upstream").and_then(|v| v.as_str()) {
                            let s = v.to_string();
                            upstream.set(s.clone());
                            original_upstream.set(s);
                        }
                    }
                }
            });
            || {}
        }
    });

    if *loading {
        return html! { <LoadingSpinner /> };
    }

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

    let on_upstream_change = {
        let upstream = upstream.clone();
        Callback::from(move |value: String| {
            upstream.set(value);
        })
    };

    let on_save = {
        let saving = saving.clone();
        let mode = mode.clone();
        let upstream = upstream.clone();
        let original_mode = original_mode.clone();
        let original_upstream = original_upstream.clone();
        Callback::from(move |_| {
            let config = serde_json::json!({
                "config": {
                    "mode": (*mode).clone(),
                    "upstream": if (*upstream).is_empty() { serde_json::Value::Null } else { serde_json::Value::String((*upstream).clone()) },
                }
            });
            let saving = saving.clone();
            let mode = mode.clone();
            let upstream = upstream.clone();
            let original_mode = original_mode.clone();
            let original_upstream = original_upstream.clone();
            saving.set(true);
            wasm_bindgen_futures::spawn_local(async move {
                let api = ApiService::new();
                let _ = api.update_fallback_config(&config).await;
                saving.set(false);
                original_mode.set((*mode).clone());
                original_upstream.set((*upstream).clone());
                toast_success("Fallback configuration saved");
            });
        })
    };

    html! {
        <div class="space-y-6">
            <p class="text-sm text-secondary">{ "Configure fallback behavior for unmatched requests." }</p>

            <div class="flex items-center justify-between py-3 border-b border-default">
                <div>
                    <p class="text-primary font-medium">{ "Fallback Mode" }</p>
                    <p class="text-sm text-secondary">{ "What to do when no site matches the request" }</p>
                </div>
                <select
                    class="bg-tertiary text-primary px-3 py-2 rounded-lg border border-default"
                    value={(*mode).clone()}
                    onchange={on_mode_change}
                >
                    <option value="return_404" selected={*mode == "return_404"}>{ "Return 404" }</option>
                    <option value="proxy" selected={*mode == "proxy"}>{ "Proxy to Upstream" }</option>
                </select>
            </div>

            if *mode == "proxy" {
                <Input
                    label="Fallback Upstream URL"
                    name="fallback_upstream"
                    value={(*upstream).clone()}
                    on_change={on_upstream_change}
                    help="Upstream URL to proxy requests to when no site matches"
                />
            }

            <div class="flex justify-end">
                <button
                    onclick={on_save}
                    disabled={*saving}
                    class={if is_dirty {
                        "px-4 py-2 bg-yellow-600 text-white rounded-lg hover:bg-yellow-700 disabled:opacity-50"
                    } else {
                        "px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700 disabled:opacity-50"
                    }}
                >
                    { if *saving { "Saving..." } else if is_dirty { "Save*" } else { "Save" } }
                </button>
            </div>
        </div>
    }
}

#[function_component]
fn UpgradeSection() -> Html {
    let loading = use_state(|| true);
    let saving = use_state(|| false);

    let health_check_path = use_state(|| "/health".to_string());
    let health_check_timeout_secs = use_state(|| "5".to_string());
    let validation_retries = use_state(|| "3".to_string());
    let validation_interval_secs = use_state(|| "5".to_string());
    let drain_timeout_secs = use_state(|| "30".to_string());
    let drain_check_interval_ms = use_state(|| "100".to_string());
    let port_swap_cutover_timeout_ms = use_state(|| "500".to_string());
    let keep_old_versions = use_state(|| "2".to_string());
    let staged_dir = use_state(String::new);
    let bin_dir = use_state(String::new);

    let original_health_check_path = use_state(|| "/health".to_string());
    let original_health_check_timeout_secs = use_state(|| "5".to_string());
    let original_validation_retries = use_state(|| "3".to_string());
    let original_validation_interval_secs = use_state(|| "5".to_string());
    let original_drain_timeout_secs = use_state(|| "30".to_string());
    let original_drain_check_interval_ms = use_state(|| "100".to_string());
    let original_port_swap_cutover_timeout_ms = use_state(|| "500".to_string());
    let original_keep_old_versions = use_state(|| "2".to_string());
    let original_staged_dir = use_state(String::new);
    let original_bin_dir = use_state(String::new);

    let is_dirty = *health_check_path != *original_health_check_path
        || *health_check_timeout_secs != *original_health_check_timeout_secs
        || *validation_retries != *original_validation_retries
        || *validation_interval_secs != *original_validation_interval_secs
        || *drain_timeout_secs != *original_drain_timeout_secs
        || *drain_check_interval_ms != *original_drain_check_interval_ms
        || *port_swap_cutover_timeout_ms != *original_port_swap_cutover_timeout_ms
        || *keep_old_versions != *original_keep_old_versions
        || *staged_dir != *original_staged_dir
        || *bin_dir != *original_bin_dir;

    use_effect_with((), {
        let loading = loading.clone();
        let health_check_path = health_check_path.clone();
        let health_check_timeout_secs = health_check_timeout_secs.clone();
        let validation_retries = validation_retries.clone();
        let validation_interval_secs = validation_interval_secs.clone();
        let drain_timeout_secs = drain_timeout_secs.clone();
        let drain_check_interval_ms = drain_check_interval_ms.clone();
        let port_swap_cutover_timeout_ms = port_swap_cutover_timeout_ms.clone();
        let keep_old_versions = keep_old_versions.clone();
        let staged_dir = staged_dir.clone();
        let bin_dir = bin_dir.clone();
        let original_health_check_path = original_health_check_path.clone();
        let original_health_check_timeout_secs = original_health_check_timeout_secs.clone();
        let original_validation_retries = original_validation_retries.clone();
        let original_validation_interval_secs = original_validation_interval_secs.clone();
        let original_drain_timeout_secs = original_drain_timeout_secs.clone();
        let original_drain_check_interval_ms = original_drain_check_interval_ms.clone();
        let original_port_swap_cutover_timeout_ms = original_port_swap_cutover_timeout_ms.clone();
        let original_keep_old_versions = original_keep_old_versions.clone();
        let original_staged_dir = original_staged_dir.clone();
        let original_bin_dir = original_bin_dir.clone();
        move |_| {
            wasm_bindgen_futures::spawn_local(async move {
                let api = ApiService::new();
                let result = api.get_upgrade_config().await;
                loading.set(false);

                if let Ok(data) = result {
                    if let Some(config) = data.get("config") {
                        if let Some(v) = config.get("health_check_path").and_then(|v| v.as_str()) {
                            let s = v.to_string();
                            health_check_path.set(s.clone());
                            original_health_check_path.set(s);
                        }
                        if let Some(v) = config
                            .get("health_check_timeout_secs")
                            .and_then(|v| v.as_u64())
                        {
                            let s = v.to_string();
                            health_check_timeout_secs.set(s.clone());
                            original_health_check_timeout_secs.set(s);
                        }
                        if let Some(v) = config.get("validation_retries").and_then(|v| v.as_u64()) {
                            let s = v.to_string();
                            validation_retries.set(s.clone());
                            original_validation_retries.set(s);
                        }
                        if let Some(v) = config
                            .get("validation_interval_secs")
                            .and_then(|v| v.as_u64())
                        {
                            let s = v.to_string();
                            validation_interval_secs.set(s.clone());
                            original_validation_interval_secs.set(s);
                        }
                        if let Some(v) = config.get("drain_timeout_secs").and_then(|v| v.as_u64()) {
                            let s = v.to_string();
                            drain_timeout_secs.set(s.clone());
                            original_drain_timeout_secs.set(s);
                        }
                        if let Some(v) = config
                            .get("drain_check_interval_ms")
                            .and_then(|v| v.as_u64())
                        {
                            let s = v.to_string();
                            drain_check_interval_ms.set(s.clone());
                            original_drain_check_interval_ms.set(s);
                        }
                        if let Some(v) = config
                            .get("port_swap_cutover_timeout_ms")
                            .and_then(|v| v.as_u64())
                        {
                            let s = v.to_string();
                            port_swap_cutover_timeout_ms.set(s.clone());
                            original_port_swap_cutover_timeout_ms.set(s);
                        }
                        if let Some(v) = config.get("keep_old_versions").and_then(|v| v.as_u64()) {
                            let s = v.to_string();
                            keep_old_versions.set(s.clone());
                            original_keep_old_versions.set(s);
                        }
                        if let Some(v) = config.get("staged_dir").and_then(|v| v.as_str()) {
                            let s = v.to_string();
                            staged_dir.set(s.clone());
                            original_staged_dir.set(s);
                        }
                        if let Some(v) = config.get("bin_dir").and_then(|v| v.as_str()) {
                            let s = v.to_string();
                            bin_dir.set(s.clone());
                            original_bin_dir.set(s);
                        }
                    }
                }
            });
            || {}
        }
    });

    if *loading {
        return html! { <LoadingSpinner /> };
    }

    let on_change = |state: UseStateHandle<String>| -> Callback<String> {
        Callback::from(move |value: String| {
            state.set(value);
        })
    };

    let on_save = {
        let saving = saving.clone();
        let health_check_path = health_check_path.clone();
        let health_check_timeout_secs = health_check_timeout_secs.clone();
        let validation_retries = validation_retries.clone();
        let validation_interval_secs = validation_interval_secs.clone();
        let drain_timeout_secs = drain_timeout_secs.clone();
        let drain_check_interval_ms = drain_check_interval_ms.clone();
        let port_swap_cutover_timeout_ms = port_swap_cutover_timeout_ms.clone();
        let keep_old_versions = keep_old_versions.clone();
        let staged_dir = staged_dir.clone();
        let bin_dir = bin_dir.clone();
        let original_health_check_path = original_health_check_path.clone();
        let original_health_check_timeout_secs = original_health_check_timeout_secs.clone();
        let original_validation_retries = original_validation_retries.clone();
        let original_validation_interval_secs = original_validation_interval_secs.clone();
        let original_drain_timeout_secs = original_drain_timeout_secs.clone();
        let original_drain_check_interval_ms = original_drain_check_interval_ms.clone();
        let original_port_swap_cutover_timeout_ms = original_port_swap_cutover_timeout_ms.clone();
        let original_keep_old_versions = original_keep_old_versions.clone();
        let original_staged_dir = original_staged_dir.clone();
        let original_bin_dir = original_bin_dir.clone();
        Callback::from(move |_| {
            let config = serde_json::json!({
                "config": {
                    "health_check_path": (*health_check_path).clone(),
                    "health_check_timeout_secs": health_check_timeout_secs.parse::<u64>().unwrap_or(5),
                    "validation_retries": validation_retries.parse::<u32>().unwrap_or(3),
                    "validation_interval_secs": validation_interval_secs.parse::<u64>().unwrap_or(5),
                    "drain_timeout_secs": drain_timeout_secs.parse::<u64>().unwrap_or(30),
                    "drain_check_interval_ms": drain_check_interval_ms.parse::<u64>().unwrap_or(100),
                    "port_swap_cutover_timeout_ms": port_swap_cutover_timeout_ms.parse::<u64>().unwrap_or(500),
                    "keep_old_versions": keep_old_versions.parse::<usize>().unwrap_or(2),
                    "staged_dir": if (*staged_dir).is_empty() { serde_json::Value::Null } else { serde_json::Value::String((*staged_dir).clone()) },
                    "bin_dir": if (*bin_dir).is_empty() { serde_json::Value::Null } else { serde_json::Value::String((*bin_dir).clone()) },
                }
            });
            let saving = saving.clone();
            let health_check_path = health_check_path.clone();
            let health_check_timeout_secs = health_check_timeout_secs.clone();
            let validation_retries = validation_retries.clone();
            let validation_interval_secs = validation_interval_secs.clone();
            let drain_timeout_secs = drain_timeout_secs.clone();
            let drain_check_interval_ms = drain_check_interval_ms.clone();
            let port_swap_cutover_timeout_ms = port_swap_cutover_timeout_ms.clone();
            let keep_old_versions = keep_old_versions.clone();
            let staged_dir = staged_dir.clone();
            let bin_dir = bin_dir.clone();
            let original_health_check_path = original_health_check_path.clone();
            let original_health_check_timeout_secs = original_health_check_timeout_secs.clone();
            let original_validation_retries = original_validation_retries.clone();
            let original_validation_interval_secs = original_validation_interval_secs.clone();
            let original_drain_timeout_secs = original_drain_timeout_secs.clone();
            let original_drain_check_interval_ms = original_drain_check_interval_ms.clone();
            let original_port_swap_cutover_timeout_ms =
                original_port_swap_cutover_timeout_ms.clone();
            let original_keep_old_versions = original_keep_old_versions.clone();
            let original_staged_dir = original_staged_dir.clone();
            let original_bin_dir = original_bin_dir.clone();
            saving.set(true);
            wasm_bindgen_futures::spawn_local(async move {
                let api = ApiService::new();
                let _ = api.update_upgrade_config(&config).await;
                saving.set(false);
                original_health_check_path.set((*health_check_path).clone());
                original_health_check_timeout_secs.set((*health_check_timeout_secs).clone());
                original_validation_retries.set((*validation_retries).clone());
                original_validation_interval_secs.set((*validation_interval_secs).clone());
                original_drain_timeout_secs.set((*drain_timeout_secs).clone());
                original_drain_check_interval_ms.set((*drain_check_interval_ms).clone());
                original_port_swap_cutover_timeout_ms.set((*port_swap_cutover_timeout_ms).clone());
                original_keep_old_versions.set((*keep_old_versions).clone());
                original_staged_dir.set((*staged_dir).clone());
                original_bin_dir.set((*bin_dir).clone());
                toast_success("Upgrade configuration saved");
            });
        })
    };

    html! {
        <div class="space-y-6">
            <p class="text-sm text-secondary">{ "Configure zero-downtime upgrade behavior." }</p>

            <h3 class="font-semibold text-primary">{ "Health Check" }</h3>
            <div class="grid grid-cols-2 gap-4">
                <Input
                    label="Health Check Path"
                    name="health_check_path"
                    value={(*health_check_path).clone()}
                    on_change={on_change(health_check_path.clone())}
                    help="Path to check for instance health"
                />
                <Input
                    label="Health Check Timeout (secs)"
                    name="health_check_timeout_secs"
                    input_type="number"
                    value={(*health_check_timeout_secs).clone()}
                    on_change={on_change(health_check_timeout_secs.clone())}
                />
            </div>

            <h3 class="font-semibold text-primary mt-6">{ "Validation" }</h3>
            <div class="grid grid-cols-2 gap-4">
                <Input
                    label="Validation Retries"
                    name="validation_retries"
                    input_type="number"
                    value={(*validation_retries).clone()}
                    on_change={on_change(validation_retries.clone())}
                />
                <Input
                    label="Validation Interval (secs)"
                    name="validation_interval_secs"
                    input_type="number"
                    value={(*validation_interval_secs).clone()}
                    on_change={on_change(validation_interval_secs.clone())}
                />
            </div>

            <h3 class="font-semibold text-primary mt-6">{ "Drain" }</h3>
            <div class="grid grid-cols-2 gap-4">
                <Input
                    label="Drain Timeout (secs)"
                    name="drain_timeout_secs"
                    input_type="number"
                    value={(*drain_timeout_secs).clone()}
                    on_change={on_change(drain_timeout_secs.clone())}
                />
                <Input
                    label="Drain Check Interval (ms)"
                    name="drain_check_interval_ms"
                    input_type="number"
                    value={(*drain_check_interval_ms).clone()}
                    on_change={on_change(drain_check_interval_ms.clone())}
                />
            </div>

            <h3 class="font-semibold text-primary mt-6">{ "Port Swap" }</h3>
            <Input
                label="Port Swap Cutover Timeout (ms)"
                name="port_swap_cutover_timeout_ms"
                input_type="number"
                value={(*port_swap_cutover_timeout_ms).clone()}
                on_change={on_change(port_swap_cutover_timeout_ms.clone())}
            />

            <h3 class="font-semibold text-primary mt-6">{ "Versions" }</h3>
            <div class="grid grid-cols-2 gap-4">
                <Input
                    label="Keep Old Versions"
                    name="keep_old_versions"
                    input_type="number"
                    value={(*keep_old_versions).clone()}
                    on_change={on_change(keep_old_versions.clone())}
                    help="Number of old binary versions to keep"
                />
            </div>

            <h3 class="font-semibold text-primary mt-6">{ "Directories" }</h3>
            <div class="grid grid-cols-2 gap-4">
                <Input
                    label="Staged Directory"
                    name="staged_dir"
                    value={(*staged_dir).clone()}
                    on_change={on_change(staged_dir.clone())}
                    help="Directory for staged upgrade binaries"
                />
                <Input
                    label="Binary Directory"
                    name="bin_dir"
                    value={(*bin_dir).clone()}
                    on_change={on_change(bin_dir.clone())}
                    help="Directory for binary versions"
                />
            </div>

            <div class="flex justify-end">
                <button
                    onclick={on_save}
                    disabled={*saving}
                    class={if is_dirty {
                        "px-4 py-2 bg-yellow-600 text-white rounded-lg hover:bg-yellow-700 disabled:opacity-50"
                    } else {
                        "px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700 disabled:opacity-50"
                    }}
                >
                    { if *saving { "Saving..." } else if is_dirty { "Save*" } else { "Save" } }
                </button>
            </div>
        </div>
    }
}
