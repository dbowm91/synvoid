use crate::icmp_filter::{config::IcmpFilterConfig, error::Result};
use std::fmt::Debug;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum FilterBackend {
    #[default]
    Nftables,
    Ebpf,
    Pf,
    WindowsFirewall,
    Wfp,
}

#[derive(Debug, Clone)]
pub struct FilterStatus {
    pub enabled: bool,
    pub backend: FilterBackend,
    pub config: IcmpFilterConfig,
}

impl Default for FilterStatus {
    fn default() -> Self {
        Self {
            enabled: false,
            backend: FilterBackend::default(),
            config: IcmpFilterConfig::default(),
        }
    }
}

pub trait IcmpFilter: Debug + Send + Sync {
    fn enable(&mut self) -> Result<()>;
    fn disable(&mut self) -> Result<()>;
    fn is_enabled(&self) -> bool;
    fn backend(&self) -> FilterBackend;
    fn status(&self) -> FilterStatus;
    fn update_config(&mut self, config: IcmpFilterConfig) -> Result<()>;
    fn config(&self) -> &IcmpFilterConfig;
}

pub trait IcmpFilterFactory: Debug + Send + Sync {
    fn create(&self, config: IcmpFilterConfig) -> Result<Box<dyn IcmpFilter>>;
    fn backend(&self) -> FilterBackend;
    fn is_available(&self) -> bool;
}
