# Application Handlers

SynVoid provides built-in, optimized handlers for various application types, allowing it to serve content directly or interface efficiently with specialized backends.

## 1. Static File Handler

The `StaticFileHandler` is a high-performance engine for serving static assets. It includes features typically found in standalone web servers:

- **Directory Listings:** Automatically generates index pages for directories with configurable themes.
- **Path Normalization:** Protects against path traversal attacks by resolving and validating paths before access.
- **MIME Type Mapping:** Automatic content-type detection based on file extensions.
- **Caching & Compression:** Supports `gzip` and `brotli` pre-compression and integrates with the internal proxy cache.
- **Built-in Minification:** An experimental feature that can automatically minify CSS and JavaScript on the fly using a specialized background worker.

## 2. FastCGI & PHP-FPM

SynVoid handles dynamic PHP applications by interfacing directly with PHP-FPM (or any FastCGI-compliant backend).

- **Unix Socket & TCP Support:** Can connect to PHP-FPM via local Unix domain sockets for maximum performance or over TCP for remote backends.
- **Environment Management:** Automatically populates FastCGI environment variables (e.g., `SCRIPT_FILENAME`, `QUERY_STRING`) required for PHP execution.
- **Response Streaming:** Efficiently streams large responses from the FastCGI backend to the client.

## 3. Python (Granian)

SynVoid includes built-in support for Python ASGI/WSGI applications using the **Granian** application server.

- **Process Management:** The Supervisor process can spawn and manage Granian instances as child processes.
- **Unix Socket IPC:** Communication between the Worker and Granian happens over local Unix sockets, bypassing the overhead of the network stack.
- **Simplified Deployment:** Allows deploying Django, Flask, or FastAPI applications with a single configuration file.

## 4. Serverless WASM (Edge Functions)

For high-performance, sandboxed edge computing, SynVoid integrates a WebAssembly (WASM) runtime.

- **Wasmtime Integration:** Uses the industry-standard `wasmtime` engine for executing WASM modules.
- **Instance Pooling:** Maintains a pool of pre-initialized WASM instances to eliminate cold start latency.
- **Resource Isolation:** Enforces strict limits on CPU time, memory usage, and syscall access for every WASM execution.
- **Mesh Distribution:** (Mesh mode only) WASM modules can be distributed globally across the mesh and executed on the Edge node closest to the user.

## 5. Spin Application Support

SynVoid also supports the **Fermyon Spin** framework, allowing for the execution of Spin-based microservices.

- **Metadata Parsing:** Automatically parses Spin application manifests (`spin.toml`) to determine routes and configurations.
- **Request Mapping:** Maps incoming HTTP requests to specific Spin components and triggers their execution.
