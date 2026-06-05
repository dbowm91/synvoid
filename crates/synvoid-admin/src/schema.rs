//! OpenAPI schema helpers for admin API types.

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
