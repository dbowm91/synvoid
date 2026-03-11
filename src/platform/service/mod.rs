#[cfg(windows)]
pub mod windows_service;

#[cfg(windows)]
pub use windows_service::*;

#[cfg(not(windows))]
pub mod stub_service;

#[cfg(not(windows))]
pub use stub_service::*;
