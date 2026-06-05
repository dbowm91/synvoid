// Re-export generic schema helpers from synvoid-admin crate.
pub use synvoid_admin::schema::{DateTimeUtc, PathBufWrapper};

use utoipa::openapi::RefOr;
use utoipa::{PartialSchema, ToSchema};

use crate::admin::audit::{AuditLog, ConfigVersion};

impl PartialSchema for AuditLog {
    fn schema() -> RefOr<utoipa::openapi::schema::Schema> {
        utoipa::openapi::ObjectBuilder::new()
            .property("id", <String as PartialSchema>::schema())
            .required("id")
            .property("timestamp", <DateTimeUtc as PartialSchema>::schema())
            .required("timestamp")
            .property("user_id", <Option<String> as PartialSchema>::schema())
            .property("username", <Option<String> as PartialSchema>::schema())
            .property("action", <String as PartialSchema>::schema())
            .required("action")
            .property("target_resource", <String as PartialSchema>::schema())
            .required("target_resource")
            .property("client_ip", <String as PartialSchema>::schema())
            .required("client_ip")
            .property("user_agent", <Option<String> as PartialSchema>::schema())
            .property("details", <Option<String> as PartialSchema>::schema())
            .property("success", <bool as PartialSchema>::schema())
            .required("success")
            .into()
    }
}

impl ToSchema for AuditLog {
    fn name() -> std::borrow::Cow<'static, str> {
        std::borrow::Cow::Borrowed("AuditLog")
    }
    fn schemas(schemas: &mut Vec<(String, RefOr<utoipa::openapi::schema::Schema>)>) {
        schemas.push((Self::name().into(), Self::schema()));
    }
}

impl PartialSchema for ConfigVersion {
    fn schema() -> RefOr<utoipa::openapi::schema::Schema> {
        utoipa::openapi::ObjectBuilder::new()
            .property("id", <String as PartialSchema>::schema())
            .required("id")
            .property("timestamp", <DateTimeUtc as PartialSchema>::schema())
            .required("timestamp")
            .property("description", <Option<String> as PartialSchema>::schema())
            .property("file_path", <PathBufWrapper as PartialSchema>::schema())
            .required("file_path")
            .into()
    }
}

impl ToSchema for ConfigVersion {
    fn name() -> std::borrow::Cow<'static, str> {
        std::borrow::Cow::Borrowed("ConfigVersion")
    }
    fn schemas(schemas: &mut Vec<(String, RefOr<utoipa::openapi::schema::Schema>)>) {
        schemas.push((Self::name().into(), Self::schema()));
    }
}
