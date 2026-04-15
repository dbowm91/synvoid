use yew::prelude::*;

#[function_component]
pub fn TcpUdp() -> Html {
    html! {
        <div>
            <div class="flex justify-between items-center mb-6">
                <h1 class="text-2xl font-bold">{ "TCP/UDP Listeners" }</h1>
                <button class="px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700">
                    { "+ Add Listener" }
                </button>
            </div>

            <div class="bg-secondary rounded-lg border border-default mb-6">
                <div class="p-4 border-b border-default">
                    <h3 class="text-lg font-semibold">{ "Active Listeners" }</h3>
                </div>
                <div class="divide-y divide-default">
                    <ListenerRow
                        port={25}
                        protocol="SMTP"
                        site="example.com"
                        upstream="mail.internal:25"
                        connections={12}
                        enabled=true
                    />
                    <ListenerRow
                        port={587}
                        protocol="SMTP"
                        site="example.com"
                        upstream="mail.internal:587"
                        connections={5}
                        enabled=true
                    />
                    <ListenerRow
                        port={3306}
                        protocol="MySQL"
                        site="api.example.com"
                        upstream="db.internal:3306"
                        connections={23}
                        enabled=true
                    />
                    <ListenerRow
                        port={5432}
                        protocol="PostgreSQL"
                        site="api.example.com"
                        upstream="db.internal:5432"
                        connections={0}
                        enabled=false
                    />
                </div>
            </div>

            <div class="bg-secondary rounded-lg border border-default">
                <div class="p-4 border-b border-default">
                    <h3 class="text-lg font-semibold">{ "Supported Protocols" }</h3>
                </div>
                <div class="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-4 gap-4 p-4">
                    <ProtocolCard name="HTTP" ports="80, 443, 8080" />
                    <ProtocolCard name="SMTP" ports="25, 587, 465" />
                    <ProtocolCard name="IMAP" ports="143, 993" />
                    <ProtocolCard name="POP3" ports="110, 995" />
                    <ProtocolCard name="MySQL" ports="3306" />
                    <ProtocolCard name="PostgreSQL" ports="5432" />
                    <ProtocolCard name="Redis" ports="6379" />
                    <ProtocolCard name="Memcached" ports="11211" />
                </div>
            </div>
        </div>
    }
}

#[derive(Properties, PartialEq)]
struct ListenerRowProps {
    port: u16,
    protocol: String,
    site: String,
    upstream: String,
    connections: usize,
    enabled: bool,
}

#[function_component]
fn ListenerRow(props: &ListenerRowProps) -> Html {
    let status_class = if props.enabled {
        "bg-green-500"
    } else {
        "bg-gray-500"
    };
    let status_text = if props.enabled { "Active" } else { "Disabled" };

    html! {
        <div class="p-4 flex items-center justify-between">
            <div class="flex items-center gap-4">
                <span class={format!("w-3 h-3 rounded-full {}", status_class)} />
                <div>
                    <p class="font-medium text-primary">{ format!("Port {}", props.port) }</p>
                    <p class="text-sm text-secondary">{ &props.protocol }{ " - " }{ &props.site }</p>
                </div>
            </div>

            <div class="text-right">
                <p class="font-mono text-primary">{ &props.upstream }</p>
                <p class="text-sm text-secondary">{ props.connections }{ " connections" }</p>
            </div>

            <div class="flex gap-2">
                <button class="px-3 py-1 text-sm bg-tertiary text-primary rounded hover:opacity-80">
                    { "Edit" }
                </button>
                <button class="px-3 py-1 text-sm bg-red-600 text-white rounded hover:bg-red-700">
                    { "Remove" }
                </button>
            </div>
        </div>
    }
}

#[derive(Properties, PartialEq)]
struct ProtocolCardProps {
    name: String,
    ports: String,
}

#[function_component]
fn ProtocolCard(props: &ProtocolCardProps) -> Html {
    html! {
        <div class="bg-tertiary rounded-lg p-4 border border-default">
            <p class="font-semibold text-primary">{ &props.name }</p>
            <p class="text-sm text-secondary mt-1">{ "Ports: " }{ &props.ports }</p>
        </div>
    }
}
