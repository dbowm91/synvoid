use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use utoipa::openapi::RefOr;
use utoipa::{PartialSchema, ToSchema};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DateTimeUtc(pub DateTime<Utc>);

impl PartialSchema for DateTimeUtc {
    fn schema() -> RefOr<utoipa::openapi::schema::Schema> {
        utoipa::openapi::ObjectBuilder::new()
            .schema_type(utoipa::openapi::schema::Type::String)
            .format(Some(utoipa::openapi::schema::SchemaFormat::KnownFormat(
                utoipa::openapi::KnownFormat::DateTime,
            )))
            .into()
    }
}

impl ToSchema for DateTimeUtc {
    fn name() -> std::borrow::Cow<'static, str> {
        std::borrow::Cow::Borrowed("DateTime")
    }
    fn schemas(schemas: &mut Vec<(String, RefOr<utoipa::openapi::schema::Schema>)>) {
        schemas.push((Self::name().into(), Self::schema()));
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PathBufWrapper(pub PathBuf);

impl PartialSchema for PathBufWrapper {
    fn schema() -> RefOr<utoipa::openapi::schema::Schema> {
        <String as PartialSchema>::schema()
    }
}

impl ToSchema for PathBufWrapper {
    fn name() -> std::borrow::Cow<'static, str> {
        <String as ToSchema>::name()
    }
    fn schemas(schemas: &mut Vec<(String, RefOr<utoipa::openapi::schema::Schema>)>) {
        schemas.push((Self::name().into(), Self::schema()));
    }
}

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
