//! Deprecated compatibility shim.
//! Use `synvoid_static_files::image_rights` instead.

pub use crate::image_rights::apply_image_rights_marking as apply_image_poisoning;
pub use crate::image_rights::invalidate_image_rights_cache_for_site as invalidate_image_poison_cache_for_site;
