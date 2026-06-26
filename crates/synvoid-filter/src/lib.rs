pub trait FilterAction: PartialEq {
    fn is_allow(&self) -> bool;
    fn is_drop(&self) -> bool;
}

pub trait Protocol: Send + Sync {
    fn as_str(&self) -> &str;
    fn from_str(s: &str) -> Self
    where
        Self: Sized;
}

#[derive(Clone)]
pub struct BaseFilterConfig {
    pub enabled: bool,
    pub strict_mode: bool,
    pub protocol_allowlist: Vec<String>,
    pub protocol_denylist: Vec<String>,
}

impl BaseFilterConfig {
    pub fn new(
        enabled: bool,
        strict_mode: bool,
        protocol_allowlist: Vec<String>,
        protocol_denylist: Vec<String>,
    ) -> Self {
        Self {
            enabled,
            strict_mode,
            protocol_allowlist,
            protocol_denylist,
        }
    }
}

#[derive(Clone)]
pub struct ProtocolFilterCore<P: Protocol, A: FilterAction> {
    config: BaseFilterConfig,
    _phantom: std::marker::PhantomData<P>,
    _action_phantom: std::marker::PhantomData<A>,
}

impl<P: Protocol, A: FilterAction> ProtocolFilterCore<P, A> {
    pub fn new(config: BaseFilterConfig) -> Self {
        Self {
            config,
            _phantom: std::marker::PhantomData,
            _action_phantom: std::marker::PhantomData,
        }
    }

    pub fn check(
        &self,
        expected_protocol: &str,
        detected_protocol: &P,
        allow_action: A,
        mismatch_action: A,
    ) -> A {
        if !self.config.enabled {
            return allow_action;
        }

        if !self.config.protocol_denylist.is_empty() {
            for denied in &self.config.protocol_denylist {
                if denied.as_str() == detected_protocol.as_str() {
                    return mismatch_action;
                }
            }
        }

        if !self.config.protocol_allowlist.is_empty() {
            let detected_str = detected_protocol.as_str();
            let matches_allowlist = self
                .config
                .protocol_allowlist
                .iter()
                .any(|a| a.as_str() == detected_str);
            if matches_allowlist {
                return allow_action;
            }
            if self.config.strict_mode {
                return mismatch_action;
            }
        }

        if self.config.strict_mode && expected_protocol != detected_protocol.as_str() {
            return mismatch_action;
        }

        allow_action
    }

    pub fn with_allowlist(mut self, allowlist: Vec<String>) -> Self {
        self.config.protocol_allowlist = allowlist;
        self
    }

    pub fn with_denylist(mut self, denylist: Vec<String>) -> Self {
        self.config.protocol_denylist = denylist;
        self
    }

    pub fn with_strict_mode(mut self, strict: bool) -> Self {
        self.config.strict_mode = strict;
        self
    }

    pub fn enabled(&self) -> bool {
        self.config.enabled
    }

    pub fn strict_mode(&self) -> bool {
        self.config.strict_mode
    }
}

pub struct PortConfigBase<P: Protocol, A: FilterAction> {
    pub expected_protocol: P,
    pub action: A,
}

impl<P: Protocol, A: FilterAction> PortConfigBase<P, A> {
    pub fn new(expected_protocol: P, action: A) -> Self {
        Self {
            expected_protocol,
            action,
        }
    }
}

pub fn check_protocol_match<P: Protocol>(expected: &P, actual: &P) -> bool {
    expected.as_str() == actual.as_str()
}
