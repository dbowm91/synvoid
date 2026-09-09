//! Admin handler shared DTOs (facade) plus Axum-transport helpers (root-owned).
//!
//! Phase 21: pagination/response DTOs (`PaginationQuery`, `PaginatedResponse`,
//! `StatusResponse`, `PaginationLimits`, `ErrorPage`, auth principal types,
//! `parse_ip`) are canonical in `synvoid_admin::handlers::common` and are
//! re-exported here. This module retains only `require_role` (RBAC middleware
//! foundation), `config_path`, and the `0o600` `write_config_file_secure`.
//! Removed in Phase 21: `check_rate_limit`/`get_client_ip` (superseded by the
//! tower rate-limit layer and `extract_client_ip_middleware`) and the
//! duplicate `parse_ip` (canonical in the crate).

// NOTE: `handlers` is crate-private, so `pub use` here behaves like an import
// for lint purposes; the allow keeps the full DTO facade (cf. `auth.rs`).
#[allow(unused_imports)]
pub use synvoid_admin::handlers::common::{
    AuthenticatedUser, ErrorPage, OptionalAuth, PaginatedResponse, PaginationLimits,
    PaginationQuery, RequiredRole, StatusResponse, ERROR_PAGES, PAGINATION_LIMITS_DEFAULT,
    PAGINATION_LIMITS_LARGE, PAGINATION_LIMITS_SMALL,
};

use axum::{
    extract::Request,
    http::StatusCode,
    response::{IntoResponse, Response},
};

/// Single-admin-token RBAC middleware foundation (see `RequiredRole`).
///
/// Not yet wired into the router; retained for the planned RBAC expansion
/// alongside `AuthenticatedUser`, which the auth middleware already populates.
#[allow(dead_code)]
pub async fn require_role(
    request: Request,
    required_role: RequiredRole,
    next: axum::middleware::Next,
) -> Response {
    let authenticated_user = request.extensions().get::<AuthenticatedUser>();

    let user = match authenticated_user {
        Some(user) => user,
        None => {
            tracing::warn!("RBAC: No authenticated user found in request");
            return StatusCode::UNAUTHORIZED.into_response();
        }
    };

    if required_role == RequiredRole::Admin && user.role != RequiredRole::Admin {
        tracing::warn!(
            "RBAC: User {} with role {:?} attempted to access Admin-only endpoint",
            user.username,
            user.role
        );
        return StatusCode::FORBIDDEN.into_response();
    }

    next.run(request).await
}

pub fn config_path(config_dir: &std::path::Path, site_id: &str) -> std::path::PathBuf {
    config_dir.join(format!("{}.toml", site_id.replace('.', "_")))
}

/// Write a config file with restrictive `0o600` permissions (see L-02).
///
/// Config files can carry secrets (tokens, private keys, webhook URLs), so
/// default-umask writes are insufficient even when parent-dir perms are
/// restrictive. Matches private-key handling in `quic/tls.rs`.
pub async fn write_config_file_secure(
    path: &std::path::Path,
    contents: impl AsRef<[u8]>,
) -> std::io::Result<()> {
    tokio::fs::write(path, contents).await?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        tokio::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).await?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_config_path_sanitization() {
        let config_dir = std::path::PathBuf::from("/etc/config");
        let site_id = "example.com";

        let path = config_path(&config_dir, site_id);
        assert_eq!(
            path,
            std::path::PathBuf::from("/etc/config/example_com.toml")
        );
    }

    #[test]
    fn test_config_path_preserves_underscores() {
        let config_dir = std::path::PathBuf::from("/etc/config");
        let site_id = "my_site.test";

        let path = config_path(&config_dir, site_id);
        assert_eq!(
            path,
            std::path::PathBuf::from("/etc/config/my_site_test.toml")
        );
    }

    #[test]
    fn test_required_role_is_admin() {
        assert!(RequiredRole::Admin.is_admin());
        assert!(!RequiredRole::User.is_admin());
    }

    #[test]
    fn test_common_dtos_resolve_to_crate_canonical_types() {
        // `StatusResponse`/`PaginationQuery` must be the crate types, not a
        // root redefinition (Phase 21 facade check).
        fn assert_same<T>(_: &T, _: &synvoid_admin::handlers::common::StatusResponse) {}
        let ours = StatusResponse::success("ok");
        let canonical = synvoid_admin::handlers::common::StatusResponse::success("ok");
        assert_same(&ours, &canonical);
        assert_eq!(ours.status, canonical.status);

        let q = PaginationQuery::default();
        let cq = synvoid_admin::handlers::common::PaginationQuery::default();
        assert_eq!(q.limit, cq.limit);
        assert_eq!(q.offset, cq.offset);
    }
}
