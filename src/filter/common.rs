pub trait FilterAction: Clone + PartialEq + Eq + std::fmt::Debug + Send + Sync + 'static {
    fn is_allow(&self) -> bool;
    fn is_drop(&self) -> bool;
}

pub trait Protocol: Clone + PartialEq + Eq + std::fmt::Debug + Send + Sync + 'static {
    fn as_str(&self) -> &str;
    fn from_str(s: &str) -> Self;
}

#[derive(Debug, Clone)]
pub struct BaseFilterConfig<P: Protocol> {
    pub enabled: bool,
    pub strict_mode: bool,
    pub protocol_allowlist: Vec<String>,
    pub protocol_denylist: Vec<String>,
    pub(crate) _marker: std::marker::PhantomData<P>,
}

impl<P: Protocol> BaseFilterConfig<P> {
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
            _marker: std::marker::PhantomData,
        }
    }
}

impl<P: Protocol> Default for BaseFilterConfig<P> {
    fn default() -> Self {
        Self {
            enabled: true,
            strict_mode: true,
            protocol_allowlist: vec![],
            protocol_denylist: vec![],
            _marker: std::marker::PhantomData,
        }
    }
}

#[derive(Debug, Clone)]
pub struct ProtocolFilterCore<P: Protocol, A: FilterAction> {
    config: BaseFilterConfig<P>,
    _marker: std::marker::PhantomData<A>,
}

impl<P: Protocol, A: FilterAction> ProtocolFilterCore<P, A> {
    pub fn new(config: BaseFilterConfig<P>) -> Self {
        Self {
            config,
            _marker: std::marker::PhantomData,
        }
    }

    pub fn check(
        &self,
        expected_protocol: &str,
        detected_protocol: &P,
        allow_action: A,
        deny_action: A,
    ) -> A {
        if !self.config.enabled {
            return allow_action;
        }

        if !self.config.protocol_denylist.is_empty() {
            let detected_str = detected_protocol.as_str();
            if self
                .config
                .protocol_denylist
                .iter()
                .any(|p| p.as_str() == detected_str)
            {
                return deny_action;
            }
        }

        if !self.config.protocol_allowlist.is_empty() {
            let detected_str = detected_protocol.as_str();
            if !self
                .config
                .protocol_allowlist
                .iter()
                .any(|p| p.as_str() == detected_str)
            {
                return deny_action;
            }
        }

        let expected = P::from_str(expected_protocol);

        if expected == *detected_protocol {
            return allow_action;
        }

        if self.config.strict_mode {
            return deny_action;
        }

        allow_action
    }

    pub fn with_allowlist(mut self, protocols: Vec<String>) -> Self {
        self.config.protocol_allowlist = protocols;
        self
    }

    pub fn with_denylist(mut self, protocols: Vec<String>) -> Self {
        self.config.protocol_denylist = protocols;
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

#[derive(Debug, Clone)]
pub struct PortConfigBase {
    pub expected_protocol: String,
    pub action: String,
}

impl PortConfigBase {
    pub fn new(expected_protocol: String, action: String) -> Self {
        Self {
            expected_protocol,
            action,
        }
    }
}

pub fn check_protocol_match<P: Protocol>(expected: &str, detected: &P) -> bool {
    let expected_protocol = P::from_str(expected);
    expected_protocol == *detected
}
