# MaluWAF Admin UI Improvement Plan

## Overview
This plan addresses critical security gaps, architectural improvements, and UI/UX enhancements for the MaluWAF admin dashboard. Based on code review of the Yew-based SPA (located in `admin-ui/`), this document provides both strategic priorities and specific implementation guidance.

### Current State Summary
- **Framework**: Yew 0.22 with Tailwind CSS
- **Build Tool**: Trunk
- **Architecture**: Single-Page Application with client-side routing
- **Current Issues**: No authentication, hardcoded URLs, no global state, limited accessibility

## Executive Summary of Findings

| Category | Critical Issues | Priority | Timeline |
|----------|----------------|----------|----------|
| Security | No authentication, hardcoded URLs | P0 | 1-2 weeks |
| Architecture | No global state, no error boundaries | P1 | 2-4 weeks |
| UI/UX | Limited accessibility, no form validation | P2 | 3-6 weeks |
| Technical Debt | Large components, no tests | P3 | 4-8 weeks |

## Priority 1: Critical Security Fixes (Immediate Action Required)

### 1.1 Implement Authentication System
**Timeline**: 1-2 weeks
**Status**: Not Started

**Requirements**:
- Login/logout functionality
- Session management with JWT tokens
- Route protection for unauthenticated users
- Token refresh mechanism
- Secure token storage (HttpOnly cookies or secure localStorage)

**Implementation Steps**:
1. Create login page component (`src/pages/login.rs`)
2. Add authentication context provider (`src/contexts/auth.rs`)
3. Implement token management in API service
4. Add route guards for protected routes
5. Create logout functionality
6. Implement session timeout handling

### 1.2 Externalize Configuration
**Timeline**: 2-3 days
**Status**: Not Started

**Changes Required**:
- Move `ws://localhost:8081/api/ws/metrics` to environment variable
- Add configuration file support for API base URL
- Create environment-specific configs (dev, staging, production)

**Files to Modify**:
- `src/pages/dashboard.rs`: Line 128 (WebSocket URL)
- `src/services/api.rs`: Base URL configuration
- `Trunk.toml`: Add environment variable injection
- `index.html`: Add configuration script

### 1.3 Security Headers & CORS
**Timeline**: 3-5 days
**Status**: Not Started

**Requirements**:
- Implement Content Security Policy (CSP)
- Configure CORS headers properly
- Add X-Frame-Options to prevent clickjacking
- Implement CSRF protection

**Implementation**:
1. Add security headers middleware in backend
2. Configure CSP in admin UI HTML meta tags
3. Implement CSRF token in forms

## Technical Implementation Details

### Authentication System Architecture
```rust
// src/contexts/auth.rs
#[derive(Clone, PartialEq)]
pub struct AuthContext {
    pub user: Option<User>,
    pub token: Option<String>,
    pub is_authenticated: bool,
    pub login: Callback<LoginCredentials>,
    pub logout: Callback<()>,
}

// src/pages/login.rs - Login form component
#[function_component]
pub fn Login() -> Html {
    let auth_context = use_context::<AuthContext>();
    // Login form implementation
}

// Route protection
#[function_component]
pub fn ProtectedRoute(props: &ProtectedRouteProps) -> Html {
    let auth_context = use_context::<AuthContext>();
    if auth_context.is_authenticated {
        html! { <>{props.children.clone()}</> }
    } else {
        html! { <Redirect<Route> to={Route::Login} /> }
    }
}
```

### Configuration Management
```rust
// src/config.rs
#[derive(Clone, Debug)]
pub struct AppConfig {
    pub api_base_url: String,
    pub websocket_url: String,
    pub environment: Environment,
}

impl AppConfig {
    pub fn load() -> Self {
        let api_base_url = web_sys::window()
            .and_then(|w| w.location().host().ok())
            .unwrap_or_else(|| "localhost:8081".to_string());
        
        Self {
            api_base_url: format!("http://{}", api_base_url),
            websocket_url: format!("ws://{}/api/ws/metrics", api_base_url),
            environment: Environment::from_str(&env!("ENVIRONMENT")),
        }
    }
}
```

## Priority 2: Architecture Improvements (2-4 Weeks)

### 2.1 Global State Management
**Timeline**: 1-2 weeks
**Status**: Not Started

**Approach**: Implement Yew Context API for shared state

**Components to Create**:
1. `src/contexts/api.rs`: Global API service context
2. `src/contexts/user.rs`: User session context
3. `src/contexts/theme.rs`: Enhanced theme context
4. `src/contexts/websocket.rs`: WebSocket connection manager

**Benefits**:
- Eliminate redundant API calls
- Consistent error handling
- Shared authentication state
- Better performance

**Implementation Example**:
```rust
// src/contexts/api.rs
use yew::prelude::*;
use crate::services::ApiService;

#[derive(Clone, PartialEq)]
pub struct ApiContext {
    pub service: ApiService,
    pub is_loading: bool,
    pub error: Option<String>,
}

#[function_component]
pub fn ApiProvider(props: &ApiProviderProps) -> Html {
    let api_service = use_state(|| ApiService::new());
    let is_loading = use_state(|| false);
    let error = use_state(|| None::<String>);
    
    let context = ApiContext {
        service: (*api_service).clone(),
        is_loading: *is_loading,
        error: (*error).clone(),
    };
    
    html! {
        <ContextProvider<ApiContext> context={context}>
            {props.children.clone()}
        </ContextProvider<ApiContext>>
    }
}
```

**Migration Strategy**:
1. Create context providers
2. Update existing components to use contexts
3. Remove direct API service calls from components
4. Add loading and error states globally

### 2.2 Error Handling System
**Timeline**: 1 week
**Status**: Not Started

**Implementation**:
1. Create error boundary component (`src/components/error_boundary.rs`)
2. Implement global error handler
3. Add error logging service
4. Create user-friendly error pages
5. Add retry mechanisms for failed requests

### 2.3 Data Pagination & Caching
**Timeline**: 1-2 weeks
**Status**: Not Started

**Features**:
- Client-side pagination for logs, sites, workers
- Response caching with TTL
- Optimistic updates for mutations
- Infinite scroll option for logs

**Components**:
- `src/components/pagination.rs`: Reusable pagination
- `src/hooks/use_cache.rs`: Caching hook
- `src/components/infinite_scroll.rs`: Infinite scroll wrapper

## Priority 3: UI/UX Enhancements (3-6 Weeks)

### 3.1 Form Validation System
**Timeline**: 1 week
**Status**: Not Started

**Features**:
- Client-side validation rules
- Real-time validation feedback
- Custom validation messages
- Form submission handling
- Validation decorators for inputs

**Implementation**:
1. Create validation utilities (`src/utils/validation.rs`)
2. Enhance Input component with validation
3. Add form context for validation state
4. Create validation rule library

### 3.2 Accessibility Improvements
**Timeline**: 1-2 weeks
**Status**: Not Started

**Requirements**:
1. **ARIA Labels**: Add to all interactive elements
2. **Keyboard Navigation**: Tab navigation, focus management
3. **Screen Reader Support**: Proper semantic HTML
4. **Color Contrast**: Ensure WCAG AA compliance
5. **Focus Indicators**: Visible focus states

**Components to Update**:
- All form components (Input, Select, Toggle)
- Navigation components (Sidebar, NavItem)
- Interactive elements (buttons, cards)
- Modal and dialog components

### 3.3 Enhanced Dashboard Features
**Timeline**: 1-2 weeks
**Status**: Not Started

**New Features**:
1. **Customizable Widgets**: Drag-and-drop dashboard layout
2. **Time Range Presets**: Quick selection buttons
3. **Export Options**: PDF, Excel, CSV formats
4. **Alert Center**: Centralized notification management
5. **Bulk Operations**: Select multiple items for actions

### 3.4 Search & Filtering
**Timeline**: 1 week
**Status**: Not Started

**Implementation**:
1. Global search across all entities
2. Advanced filtering for logs
3. Saved filter presets
4. Filter combination logic
5. Search highlighting

## Testing Strategy

### Unit Testing Framework
```rust
// Cargo.toml additions
[target.'cfg(target_arch = "wasm32")'.dev-dependencies]
wasm-bindgen-test = "0.3"
wasm-bindgen-futures = "0.4"
gloo-render = "0.2"
gloo-utils = "0.2"

// Example test file: tests/components/input_test.rs
use wasm_bindgen_test::*;
use yew::prelude::*;
use yew::LocalWorker;

wasm_bindgen_test_configure!(run_in_browser);

#[wasm_bindgen_test]
async fn test_input_component() {
    let onchange = Callback::from(|value: String| {
        assert_eq!(value, "test");
    });
    
    let props = InputProps {
        label: "Test".to_string(),
        name: "test".to_string(),
        value: "test".to_string(),
        onchange,
        ..Default::default()
    };
    
    // Test component rendering and behavior
}
```

### Integration Testing Approach
1. **Component Tests**: Test individual components in isolation
2. **Hook Tests**: Test custom hooks with mock data
3. **API Service Tests**: Mock API responses
4. **E2E Tests**: Critical user flows (login, create site, view logs)

### Accessibility Testing
- Use `axe-core` for automated accessibility testing
- Keyboard navigation testing
- Screen reader compatibility testing
- Color contrast verification

## Performance Optimization

### 1. Code Splitting
```javascript
// Trunk.toml configuration for lazy loading
[[hooks]]
stage = "build"
command = "wasm-opt"
command_arguments = ["-Oz", "-o", "output.wasm", "input.wasm"]
```

### 2. Asset Optimization
- Image optimization (WebP format)
- Font subsetting
- CSS purging (Tailwind CSS optimization)
- Gzip compression for WASM files

### 3. Caching Strategy
```rust
// src/services/cache.rs
pub struct ApiCache {
    cache: HashMap<String, CacheEntry>,
    ttl: Duration,
}

impl ApiCache {
    pub fn get_or_fetch<T>(&mut self, key: &str, fetch: impl Future<Output = T>) -> T {
        // Cache implementation with TTL
    }
}
```

### 4. WebSocket Optimization
```rust
// src/hooks/use_websocket.rs improvements
pub struct OptimizedWebSocket {
    connection: WebSocket,
    reconnect_delay: Duration,
    message_queue: VecDeque<String>,
    heartbeat_interval: Interval,
}

impl OptimizedWebSocket {
    pub fn new(url: &str) -> Self {
        // Connection pooling and optimization
    }
}
```

### 4.1.1 Component Refactoring Examples

**Current Issue - Large Component**:
```rust
// src/pages/site_editor.rs - Currently >500 lines
#[function_component]
pub fn SiteEditor(props: &SiteEditorProps) -> Html {
    // Complex logic with multiple responsibilities
    // Should be broken into:
    // 1. SiteForm - Form handling
    // 2. RouteEditor - Route configuration
    // 3. UpstreamSelector - Upstream selection
    // 4. ThemeConfigurator - Theme settings
}
```

**Target Structure**:
```
src/pages/site_editor/
├── mod.rs
├── site_editor.rs (main component)
├── site_form.rs (form handling)
├── route_editor.rs (route configuration)
├── upstream_selector.rs (upstream selection)
├── theme_configurator.rs (theme settings)
└── validation.rs (form validation)
```

### 4.1.2 Hook Extraction Pattern

**Current Pattern** (repeated in multiple components):
```rust
// In multiple components
let stats = use_state(|| None::<SystemStats>);
let loading = use_state(|| false);
let error = use_state(|| None::<String>);

use_effect_with((), move |_| {
    // API call logic repeated in each component
});
```

**Target Hook**:
```rust
// src/hooks/use_api_data.rs
pub fn use_api_data<T, F>(fetch_fn: F) -> UseApiData<T>
where
    T: Clone + 'static,
    F: Fn() -> Future<Output = Result<T, String>> + 'static,
{
    let data = use_state(|| None::<T>);
    let loading = use_state(|| false);
    let error = use_state(|| None::<String>);
    
    // Shared implementation
    UseApiData { data, loading, error }
}
```

### 4.1 Component Refactoring
**Timeline**: 2-3 weeks
**Status**: Not Started

**Approach**:
1. Break large components (site_editor.rs >500 lines)
2. Extract reusable logic to hooks
3. Standardize component patterns
4. Add TypeScript-like documentation

**Target Components**:
- `src/pages/site_editor.rs`: Split into smaller components
- `src/pages/dashboard.rs`: Extract chart components
- `src/pages/settings.rs`: Break into section components

### 4.2 Code Standardization
**Timeline**: 1 week
**Status**: Not Started

**Standards to Implement**:
1. Naming conventions (PascalCase for components, snake_case for functions)
2. File organization (components/, hooks/, services/, types/)
3. Import organization (external, internal, local)
4. Error handling patterns
5. Loading state patterns

### 4.3 Testing Infrastructure
**Timeline**: 2-3 weeks
**Status**: Not Started

**Test Coverage Areas**:
1. Component unit tests
2. Hook tests
3. API service tests
4. Integration tests
5. Accessibility tests

**Tools**:
- `wasm-bindgen-test` for Rust/WASM tests
- `gloo-render` for component testing
- Accessibility testing tools

## Implementation Timeline

### Phase 1: Security & Critical Fixes (Weeks 1-2)
- [ ] Implement authentication system
- [ ] Externalize configuration
- [ ] Add basic error handling
- [ ] Secure token storage

### Phase 2: Architecture Foundation (Weeks 3-4)
- [ ] Implement global state management
- [ ] Add error boundaries
- [ ] Implement data pagination
- [ ] Add caching system

### Phase 3: UI/UX Enhancements (Weeks 5-8)
- [ ] Form validation system
- [ ] Accessibility improvements
- [ ] Enhanced dashboard features
- [ ] Search & filtering

### Phase 4: Technical Debt (Weeks 9-12)
- [ ] Component refactoring
- [ ] Code standardization
- [ ] Testing infrastructure
- [ ] Documentation updates

## Resource Requirements

### Development Team
- **Lead Developer**: 1 FTE for 12 weeks
- **Frontend Specialist**: 0.5 FTE for 8 weeks
- **QA Engineer**: 0.25 FTE for testing phases

### Tools & Libraries
- Yew ecosystem updates
- Testing frameworks
- Accessibility testing tools
- Performance monitoring

## Success Metrics

### Security
- [ ] 100% route protection with authentication
- [ ] Zero hardcoded URLs in production code
- [ ] Secure token handling implemented

### Performance
- [ ] 50% reduction in API calls through caching
- [ ] <100ms initial page load
- [ ] <50ms navigation between pages

### Accessibility
- [ ] WCAG AA compliance score >90%
- [ ] All interactive elements keyboard accessible
- [ ] Screen reader compatibility verified

### Code Quality
- [ ] 80% test coverage
- [ ] Zero large components (>300 lines)
- [ ] Consistent code patterns across codebase

## Risk Assessment

### High Risk
1. **Authentication Implementation**: Complex integration with existing API
   - *Mitigation*: Phased rollout, feature flags
2. **State Management Migration**: May break existing functionality
   - *Mitigation*: Comprehensive testing, incremental migration

### Medium Risk
1. **Accessibility Overhaul**: Extensive component changes
   - *Mitigation*: Automated testing, gradual implementation
2. **Performance Optimizations**: May introduce new bugs
   - *Mitigation*: Performance testing, monitoring

### Low Risk
1. **Code Standardization**: Mostly mechanical changes
   - *Mitigation*: Code reviews, automated formatting

## Dependencies

### External
- Yew framework updates
- Tailwind CSS compatibility
- Trunk build tool compatibility

### Internal
- Backend API authentication endpoints
- Database schema for user management
- Configuration management system

## Monitoring & Rollback Strategy

### Monitoring
- Error tracking with Sentry or similar
- Performance monitoring (Core Web Vitals)
- User feedback collection
- Usage analytics

### Rollback
- Feature flags for new functionality
- Database migration rollback scripts
- Blue-green deployment for major changes
- Version pinning for critical updates

## Migration from Legacy Admin Interface

The codebase contains a legacy admin interface in `src/admin/legacy.rs`. This plan assumes:
1. Legacy interface will be deprecated after new admin UI is complete
2. New admin UI should have feature parity with legacy interface
3. Gradual migration of users from legacy to new interface

### Migration Checklist
- [ ] User management (legacy has user CRUD, new UI needs it)
- [ ] Session management (legacy has session monitoring)
- [ ] Audit logs (legacy has login logs)
- [ ] Role-based access control (if implemented in backend)

## Implementation Checklist

### Phase 1: Security Foundation (Week 1-2)
**Authentication System**
- [ ] Create login page component (`src/pages/login.rs`)
- [ ] Implement authentication context (`src/contexts/auth.rs`)
- [ ] Add token management to API service
- [ ] Create protected route wrapper component
- [ ] Implement logout functionality
- [ ] Add session timeout handling
- [ ] Create password reset flow (if needed)

**Configuration Management**
- [ ] Add environment variable support in Trunk.toml
- [ ] Create configuration module (`src/config.rs`)
- [ ] Update WebSocket URL in dashboard
- [ ] Update API base URL configuration
- [ ] Add environment detection logic

**Security Headers**
- [ ] Configure CSP headers in backend
- [ ] Add security meta tags to index.html
- [ ] Implement CSRF token handling
- [ ] Add X-Frame-Options configuration

### Phase 2: Architecture Improvements (Week 3-4)
**Global State Management**
- [ ] Create API context provider (`src/contexts/api.rs`)
- [ ] Create user context provider (`src/contexts/user.rs`)
- [ ] Create WebSocket context (`src/contexts/websocket.rs`)
- [ ] Migrate dashboard to use global state
- [ ] Migrate logs page to use global state
- [ ] Migrate sites management to use global state
- [ ] Remove redundant API calls

**Error Handling System**
- [ ] Create error boundary component
- [ ] Implement global error handler
- [ ] Add error logging service
- [ ] Create user-friendly error pages
- [ ] Add retry mechanisms for failed requests
- [ ] Implement toast notification system

**Data Management**
- [ ] Implement pagination component
- [ ] Add caching layer
- [ ] Implement optimistic updates
- [ ] Add infinite scroll for logs
- [ ] Create data fetching hooks

### Phase 3: UI/UX Enhancements (Week 5-8)
**Form Validation**
- [ ] Create validation utilities
- [ ] Enhance Input component with validation
- [ ] Add validation rules library
- [ ] Implement real-time validation feedback
- [ ] Add form submission handling
- [ ] Create validation decorators

**Accessibility Improvements**
- [ ] Add ARIA labels to all components
- [ ] Implement keyboard navigation
- [ ] Add focus management
- [ ] Ensure color contrast compliance
- [ ] Add screen reader support
- [ ] Create accessibility testing suite

**Dashboard Enhancements**
- [ ] Implement customizable widgets
- [ ] Add time range presets
- [ ] Create export functionality (PDF, Excel)
- [ ] Build alert center
- [ ] Add bulk operations
- [ ] Implement search and filtering

### Phase 4: Technical Debt (Week 9-12)
**Component Refactoring**
- [ ] Break down site_editor.rs (500+ lines)
- [ ] Split dashboard.rs into smaller components
- [ ] Extract reusable logic to hooks
- [ ] Standardize component patterns
- [ ] Add TypeScript-like documentation

**Code Standardization**
- [ ] Enforce naming conventions
- [ ] Organize imports consistently
- [ ] Standardize error handling patterns
- [ ] Create loading state patterns
- [ ] Add code formatting rules

**Testing Infrastructure**
- [ ] Set up testing framework
- [ ] Write component unit tests
- [ ] Create hook tests
- [ ] Add API service tests
- [ ] Implement integration tests
- [ ] Add accessibility tests

## Risk Mitigation Strategies

### For Authentication Implementation
1. **Phased Rollout**: Implement behind feature flag
2. **Backward Compatibility**: Maintain API compatibility during transition
3. **Testing Strategy**: Comprehensive testing of auth flows
4. **Rollback Plan**: Feature flag to disable authentication if needed

### For State Management Migration
1. **Incremental Migration**: Migrate one component at a time
2. **Testing Coverage**: Ensure tests pass before/after migration
3. **Performance Monitoring**: Track performance impact
4. **User Experience**: Maintain UX during migration

### For Accessibility Improvements
1. **Automated Testing**: Use axe-core for continuous monitoring
2. **Manual Testing**: Regular screen reader testing
3. **User Testing**: Include users with disabilities in testing
4. **Progressive Enhancement**: Ensure basic functionality works without JS

## Success Measurement

### Weekly Metrics
- **Security**: Authentication coverage percentage
- **Performance**: Page load times, API response times
- **Quality**: Test coverage percentage, bug count
- **UX**: Accessibility score, user feedback

### Monthly Metrics
- **Security**: Vulnerability scan results
- **Performance**: Core Web Vitals scores
- **Quality**: Code complexity metrics
- **UX**: User satisfaction surveys

## Resource Allocation

### Development Team
- **Phase 1-2**: 1 senior developer (security focus)
- **Phase 3-4**: 1 senior developer + 0.5 frontend specialist
- **Testing**: 0.25 QA engineer throughout

### Infrastructure
- **Development**: Local development environment
- **Staging**: Staging environment for testing
- **Monitoring**: Performance monitoring tools
- **Testing**: Automated testing infrastructure

## Communication Plan

### Weekly Updates
- Progress against plan
- Blockers and risks
- Resource needs
- Success metrics

### Monthly Reviews
- Phase completion assessment
- Budget and resource review
- Stakeholder feedback
- Plan adjustments

---

**Document Version**: 1.1
**Last Updated**: 2026-03-25
**Next Review**: 2026-04-01
**Author**: AI Assistant
**Approvals Required**: Project Lead, Security Team

## Quick Reference Guide for Developers

### Critical Files to Modify
| File | Current Issue | Required Change |
|------|--------------|-----------------|
| `src/pages/dashboard.rs:128` | Hardcoded WebSocket URL | Use environment variable |
| `src/services/api.rs` | No authentication support | Add token management |
| `src/app.rs` | No route protection | Add authentication guards |
| `src/components/layout/sidebar.rs` | No user info display | Add user menu/logout |
| `Trunk.toml` | No environment config | Add environment variables |

### New Files to Create
| Path | Purpose | Priority |
|------|---------|----------|
| `src/pages/login.rs` | Authentication page | P0 |
| `src/contexts/auth.rs` | Authentication state | P0 |
| `src/config.rs` | Configuration management | P0 |
| `src/components/error_boundary.rs` | Error handling | P1 |
| `src/contexts/api.rs` | Global API state | P1 |
| `src/hooks/use_api_data.rs` | Reusable data fetching | P1 |

### Testing Checklist for Each Feature
- [ ] Unit tests pass
- [ ] Integration tests pass
- [ ] Accessibility tests pass
- [ ] Performance tests pass
- [ ] Security review completed
- [ ] Documentation updated

### Code Review Checklist
- [ ] No hardcoded URLs or secrets
- [ ] Proper error handling implemented
- [ ] Accessibility requirements met
- [ ] TypeScript-like documentation added
- [ ] No console.log statements (use tracing)
- [ ] Loading states implemented
- [ ] Error states implemented
- [ ] Success states implemented

### Performance Budget
- **Initial Load**: < 2MB total (WASM + assets)
- **API Response**: < 100ms average
- **Page Navigation**: < 50ms
- **WebSocket Latency**: < 100ms
- **Memory Usage**: < 100MB for large datasets

### Accessibility Requirements (WCAG AA)
- **Color Contrast**: 4.5:1 for normal text, 3:1 for large text
- **Keyboard Navigation**: All interactive elements accessible
- **Screen Reader**: All content readable
- **Focus Indicators**: Visible focus states
- **Alt Text**: All images have alt text
- **Form Labels**: All inputs have labels

## Appendix: Implementation Examples

### Example 1: Adding Authentication to Existing Component
```rust
// Before (in dashboard.rs)
#[function_component]
pub fn Dashboard() -> Html {
    // Direct API call without authentication
}

// After (with authentication)
#[function_component]
pub fn Dashboard() -> Html {
    let auth_context = use_context::<AuthContext>();
    
    match auth_context {
        None => html! { <Redirect<Route> to={Route::Login} /> },
        Some(auth) => {
            // Use authenticated API service
            let api = auth.service.with_token(auth.token.clone());
            // ... rest of component
        }
    }
}
```

### Example 2: Adding Pagination
```rust
// Create pagination component
#[derive(Properties, PartialEq)]
pub struct PaginationProps {
    pub total: usize,
    pub page: usize,
    pub per_page: usize,
    pub on_change: Callback<usize>,
}

#[function_component]
pub fn Pagination(props: &PaginationProps) -> Html {
    let total_pages = (props.total + props.per_page - 1) / props.per_page;
    
    html! {
        <div class="flex items-center gap-2">
            <button onclick={on_prev} disabled={props.page == 0}>
                {"Previous"}
            </button>
            <span>{format!("Page {} of {}", props.page + 1, total_pages)}</span>
            <button onclick={on_next} disabled={props.page >= total_pages - 1}>
                {"Next"}
            </button>
        </div>
    }
}
```

### Example 3: Form Validation
```rust
// Validation rule
pub trait ValidationRule {
    fn validate(&self, value: &str) -> Result<(), String>;
}

// Required field validation
pub struct RequiredRule;
impl ValidationRule for RequiredRule {
    fn validate(&self, value: &str) -> Result<(), String> {
        if value.trim().is_empty() {
            Err("This field is required".to_string())
        } else {
            Ok(())
        }
    }
}

// Enhanced Input component with validation
#[derive(Properties, PartialEq)]
pub struct ValidatedInputProps {
    #[prop_or_default]
    pub validation_rules: Vec<Box<dyn ValidationRule>>,
    #[prop_or_default]
    pub on_validation: Callback<bool>,
}
```

---

**Document Version**: 1.0
**Last Updated**: 2026-03-25
**Next Review**: 2026-04-01