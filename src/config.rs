pub use synvoid_config::*;
pub use synvoid_config::limits::BlocklistLimitsConfig as DenyListLimitsConfig;
pub use synvoid_config::main_config::MainConfig;

// Provide 'main' submodule for compatibility with existing imports
pub mod main {
    pub use synvoid_config::main_config::MainConfig;
}

// Provide 'site' submodule for compatibility
pub mod site {
    pub use synvoid_config::site::*;
    pub use synvoid_config::site::proxy::BodyBufferingPolicy;
}

// Provide 'dns' submodule
pub mod dns {
    pub use synvoid_config::dns::*;
}

// Provide 'protection' submodule
pub mod protection {
    pub use synvoid_config::protection::*;
}

// Provide 'traffic' submodule
pub mod traffic {
    pub use synvoid_config::traffic::*;
}
