//! GeoIP lookup, database management, and auto-update.

pub mod lookup;
pub mod manager;
pub mod traits;
pub mod types;
pub mod updater;

pub use lookup::{GeoIpLookup, GeoLocationInfo};
pub use manager::GeoIpManager;
pub use traits::{GeoIpNotificationHandler, NoopNotificationHandler};
pub use types::{AsnInfo, CountryInfo, GeoIpResult, GeoIpStatus};
pub use updater::{DownloadSource, GeoIpUpdater, GeoIpUpdaterError};
/// Leaf crate test comment for selector scenario 2.
