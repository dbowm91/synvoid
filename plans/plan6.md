# Plan 6: Web Application Stack Enhancements

This plan outlines the improvements for the MaluWAF built-in web application stack, focusing on theme unification across the directory viewer and Admin UI, performance hardening for PHP/FastCGI, and robust deployment patterns for WASM and Granian.

## 1. Unified Theme & Directory Viewer
The directory viewer should provide a seamless transition from the Admin UI while remaining lightweight and standalone.

- [ ] **Mobile Responsiveness**: Enhance the `ThemeRenderer` CSS to ensure the directory listing table is fully responsive (horizontal scrolling or card-view on small screens).
- [ ] **Metadata Expansion**: Add support for more file metadata in the `DirectoryEntry` struct (e.g., MIME type icons, SHA256 hashes on demand, and file permissions).
- [ ] **Configurable Themes**: 
    - Expose `ThemePreset` and custom color overrides directly in the `[[site.static.locations]]` configuration.
    - Implement "Theme Inheritance" where a location can inherit the global site theme or define its own.
- [ ] **Admin UI Consistency**: Update the Admin UI to include a "File Manager" view that uses the same backend `JSON` directory listing format for a unified management experience.

## 2. PHP & FastCGI Hardening
Optimize the interaction between the WAF and backend application servers.

- [ ] **Themed Error Pages**: Ensure that when a PHP/FastCGI backend is down or times out, the error page returned matches the site's `ThemeConfig` instead of a plain text error.
- [ ] **Health Check Integration**: 
    - Map FastCGI pool health status to the Admin UI "System Status" dashboard.
    - Implement active background health checks for PHP-FPM sockets to failover quickly.
- [ ] **Environment Variable Injection**: Allow passing custom environment variables to FastCGI backends via the site configuration.

## 3. WASM Application Platform
Move from "Serverless Functions" to "WASM Web Apps".

- [ ] **WASI Support Expansion**: Enable WASI by default for serverless functions to allow file system access (restricted to a sandbox directory).
- [ ] **Streaming Body Support**: Improve the WASM ABI to support streaming request and response bodies to handle large uploads/downloads without buffering everything in guest memory.
- [ ] **Routing Enhancements**: Add support for wildcard routing and path rewriting before passing requests to WASM instances.

## 4. Granian Deployment & Python Ecosystem
Deepen the integration with Python web frameworks.

- [ ] **Virtualenv Management**: Improve the `ensure_granian_installed` logic to automatically create a virtual environment if one doesn't exist.
- [ ] **Log Aggregation**: Pipe Granian's STDOUT/STDERR directly into the MaluWAF unified logging system with proper site-id attribution.
- [ ] **Granian Dashboard**: Add a dedicated section in the Admin UI to view running Granian workers, their CPU/Memory usage, and restart them manually.

## 5. Unified "App Server" Configuration
Simplify how users define their application stack.

- [ ] **Magic Defaults**: Implement "Smart Detection" for the `default_root`. If a `site.php` or `site.granian` is defined without a root, default to `/var/www/[site-id]`.
- [ ] **Multi-App Orchestration**: Allow a single site to route to different "App Stacks" based on path (e.g., `/api` -> WASM, `/blog` -> PHP, `/app` -> Granian).

## Success Criteria
1. The directory viewer is visually indistinguishable from the Admin UI's design language.
2. PHP-FPM failures return a beautifully themed "Gateway Error" page.
3. Granian logs are visible in the unified log viewer.
4. WASM functions can process 1GB files via streaming without exceeding memory limits.
