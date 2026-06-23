---
name: admin_ui
description: Admin UI architecture for the Yew-based WASM frontend communicating with SynVoid backend via REST APIs.
---

# Admin UI Architecture

## Overview

The Admin UI is a Yew-based WASM frontend that communicates with the SynVoid backend via REST APIs. It is located in `admin-ui/` and builds to WASM + JavaScript via Trunk.

## Project Structure

```
admin-ui/
├── src/
│   ├── app.rs              # Router setup, Route enum, main App component
│   ├── lib.rs             # Library root
│   ├── pages/             # Page components (one per route)
│   │   ├── mod.rs         # Page module exports
│   │   ├── alerts.rs      # Alert management
│   │   ├── dashboard.rs   # Dashboard home
│   │   ├── dns.rs         # DNS management
│   │   ├── honeypot.rs    # Honeypot controls
│   │   ├── login.rs       # Login page
│   │   ├── logs.rs        # Log viewer
│   │   ├── mesh.rs        # Mesh network status
│   │   ├── process_management.rs  # Process management
│   │   ├── settings.rs    # Global settings
│   │   ├── sites.rs       # Site list
│   │   ├── system_status.rs  # System status + mesh status + genesis key modal
│   │   ├── threat_level.rs   # Threat level controls
│   │   ├── workers.rs     # Worker management
│   │   └── ...               # Other pages (23 total)
│   ├── services/          # API client
│   │   ├── api.rs         # ApiService with all REST methods
│   │   └── websocket.rs   # WebSocket for realtime updates
│   ├── types/             # Shared TypeScript-like types
│   │   ├── mod.rs         # Type exports
│   │   └── presets.rs     # Preset configurations
│   ├── components/       # Reusable UI components
│   │   ├── layout/sidebar.rs  # Navigation sidebar
│   │   ├── forms/             # Form inputs, selects, toggles
│   │   ├── charts/           # Chart components
│   │   └── tables/           # Data table components
│   ├── hooks/             # Custom React-like hooks
│   │   ├── use_theme.rs      # Theme management
│   │   ├── use_toast.rs      # Toast notifications
│   │   └── use_websocket.rs  # WebSocket hook
│   └── config_docs.rs     # Field documentation (orphaned - not a page)
├── index.html
├── trunk.toml
└── package.json
```

## Key Files

### `app.rs` - Router Setup

Routes are defined via `yew_router` with the `Route` enum:

```rust
#[derive(Clone, Routable, PartialEq)]
pub enum Route {
    #[at("/")]
    Home,
    #[at("/system-status")]
    SystemStatus,
    // ... other routes
}
```

The `switch()` function maps routes to page components.

### `services/api.rs` - API Client

The `ApiService` struct provides all HTTP communication:

```rust
pub struct ApiService {
    base_url: String,  // "/api"
    token: Option<String>,
}
```

Common patterns:
- `get<T: DeserializeOwned>(&self, path: &str)` - GET request
- `post<T, B>(&self, path: &str, body: &B)` - POST with JSON body
- `put<T, B>(&self, path: &str, body: &B)` - PUT with JSON body

All methods return `Result<T, String>` with error messages.

### `types/mod.rs` - Type Definitions

Frontend types mirror backend `Json<T>` response types. Key patterns:

```rust
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SomeResponse {
    pub field1: String,
    pub field2: Option<String>,
    #[serde(default)]  // Optional fields with defaults
    pub optional_vec: Vec<String>,
}
```

## Adding a New API Method

1. **Add method to `api.rs`**:

```rust
pub async fn get_something(&self) -> Result<crate::types::SomethingResponse, String> {
    self.get("/something").await
}

pub async fn update_something(&self, data: &SomethingRequest) -> Result<serde_json::Value, String> {
    self.put("/something", data).await
}
```

2. **Add types to `types/mod.rs`** if not already present:

```rust
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SomethingResponse {
    pub status: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SomethingRequest {
    pub name: String,
}
```

## Adding a New Page

1. **Create page file** in `admin-ui/src/pages/`:
```rust
use yew::prelude::*;

#[function_component]
pub fn MyPage() -> Html {
    html! {
        <div class="space-y-6">
            <h1 class="text-2xl font-bold">{ "My Page" }</h1>
        </div>
    }
}
```

2. **Export from `pages/mod.rs`**:
```rust
pub mod my_page;
// Add to pub use clause:
pub use my_page::MyPage;
```

3. **Add route to `app.rs`**:
```rust
use crate::pages::MyPage;

#[derive(Clone, Routable, PartialEq)]
pub enum Route {
    #[at("/my-page")]
    MyPage,
    // ...
}

// Add to switch():
Route::MyPage => html! { <MyPage /> },
```

## Adding State to a Page

Use Yew's `use_state` for local state:

```rust
let my_state = use_state(|| None as Option<MyData>);
let error = use_state(|| None as Option<String>);

// Set state:
my_state.set(Some(data));
error.set(Some("error".to_string()));

// Read state:
if let Some(data) = &*my_state {
    // use data
}
```

For async data fetching, use `use_effect_with`:

```rust
{
    let my_state = my_state.clone();
    use_effect_with((), move |_| {
        let my_state = my_state.clone();
        wasm_bindgen_futures::spawn_local(async move {
            let api = ApiService::new();
            match api.get_something().await {
                Ok(data) => my_state.set(Some(data)),
                Err(e) => error.set(Some(e)),
            }
        });
    });
}
```

## Modal Dialogs

Modals use a boolean state and conditional rendering:

```rust
let show_modal = use_state(|| false);

// In html:
if *show_modal {
    html! {
        <div class="fixed inset-0 bg-black/50 flex items-center justify-center z-50">
            <div class="bg-secondary rounded-lg border border-default p-6 max-w-md w-full">
                <h3 class="text-lg font-semibold mb-4">{ "Title" }</h3>
                // Modal content
                <button onclick={Callback::from(move |_| show_modal.set(false))}>
                    { "Close" }
                </button>
            </div>
        </div>
    }
}
```

## Form Handling

Use `oninput` and `onchange` callbacks:

```rust
let input_value = use_state(|| String::new());

<input
    type="text"
    class="w-full px-3 py-2 bg-tertiary border border-default rounded-lg"
    value={(*input_value).clone()}
    oninput={Callback::from(move |e: InputEvent| {
        let input = e.target_unchecked_into::<web_sys::HtmlInputElement>();
        input_value.set(input.value());
    })}
/>
```

## Theme/Styling

The UI uses Tailwind CSS classes. Key theme classes:
- `bg-secondary` - Card backgrounds
- `bg-tertiary` - Input backgrounds
- `border-default` - Border color
- `text-primary` - Primary text
- `text-secondary` - Secondary/muted text
- `text-accent` - Accent color

## Backend API Integration

### Mesh Status Example

The `system_status.rs` page demonstrates full API integration:

```rust
// Fetch mesh status
match api.get_mesh_status().await {
    Ok(status) => mesh_status.set(Some(status)),
    Err(_) => {}  // Silently ignore errors for optional data
}

// Call action endpoint
match api.derive_signing_key(&genesis_key_input).await {
    Ok(response) => {
        if response.success {
            // Handle success
        } else {
            derive_error.set(Some(response.message));
        }
    }
    Err(e) => derive_error.set(Some(e)),
}
```

### Error Handling

```rust
match api.call_endpoint().await {
    Ok(data) => data,
    Err(e) => {
        // Option 1: Set error state to display
        error.set(Some(e));
        // Option 2: Silently ignore (for non-critical data)
    }
}
```

## Building

```bash
# Install dependencies (if needed)
npm install

# Build with trunk (outputs to dist/)
trunk build

# Watch mode for development
trunk serve
```

The build outputs:
- `dist/index.html`
- `dist/admin-ui-*.wasm` (WASM binary)
- `dist/admin-ui-*.js` (JS glue code)

## Key Dependencies

- **yew** - Component framework (like React)
- **yew_router** - Routing
- **gloo** - HTTP client
- **serde** - Serialization/deserialization
- **tailwindcss** - Styling

## Common Patterns

### Loading State

```rust
if let Some(data) = &*some_state {
    // Data loaded - render content
    html! { <div>{ &data.value }</div> }
} else {
    // Loading skeleton
    html! {
        <div class="animate-pulse">
            <div class="h-4 bg-tertiary rounded w-3/4"></div>
        </div>
    }
}
```

### List Rendering

```rust
html! {
    <div>
        { for items.iter().map(|item| {
            html! {
                <div class="item">{ item.name }</div>
            }
        }) }
    </div>
}
```

### Conditional Classes

```rust
<span class={if condition { "text-green-500" } else { "text-red-500" }}>
    { "Status" }
</span>
```
