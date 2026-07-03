use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

#[derive(Debug, Clone)]
pub struct Dns64Config {
    pub prefix: Ipv6Addr,
    pub fallback_resolver: Option<String>,
    pub enabled: bool,
    pub exclude_aaaa_synthesis: bool,
}

impl Default for Dns64Config {
    fn default() -> Self {
        Self {
            // 64:ff9b:: is the Well-Known prefix (RFC 6052)
            prefix: Ipv6Addr::new(0x0064, 0xff9b, 0, 0, 0, 0, 0, 0),
            fallback_resolver: None,
            enabled: false,
            exclude_aaaa_synthesis: false,
        }
    }
}

impl Dns64Config {
    pub fn new(prefix: Ipv6Addr) -> Self {
        Self {
            prefix,
            fallback_resolver: None,
            enabled: true,
            exclude_aaaa_synthesis: false,
        }
    }

    pub fn synthesize_aaaa(&self, ipv4: Ipv4Addr) -> Ipv6Addr {
        let ipv4_octets = ipv4.octets();
        let prefix_segments = self.prefix.segments();

        Ipv6Addr::new(
            prefix_segments[0],
            prefix_segments[1],
            prefix_segments[2],
            prefix_segments[3],
            prefix_segments[4],
            prefix_segments[5],
            ((ipv4_octets[0] as u16) << 8) | (ipv4_octets[1] as u16),
            ((ipv4_octets[2] as u16) << 8) | (ipv4_octets[3] as u16),
        )
    }

    pub fn is_synthesized_aaaa(&self, ip: Ipv6Addr) -> bool {
        let segments = ip.segments();
        let prefix_segments = self.prefix.segments();

        segments[0] == prefix_segments[0]
            && segments[1] == prefix_segments[1]
            && segments[2] == prefix_segments[2]
            && segments[3] == prefix_segments[3]
            && segments[4] == prefix_segments[4]
            && segments[5] == prefix_segments[5]
    }

    pub fn extract_ipv4_from_aaaa(&self, ip: Ipv6Addr) -> Option<Ipv4Addr> {
        if !self.is_synthesized_aaaa(ip) {
            return None;
        }

        let segments = ip.segments();
        let octets = [
            (segments[6] >> 8) as u8,
            (segments[6] & 0xFF) as u8,
            (segments[7] >> 8) as u8,
            (segments[7] & 0xFF) as u8,
        ];

        Some(Ipv4Addr::new(octets[0], octets[1], octets[2], octets[3]))
    }
}

#[derive(Clone)]
pub struct Dns64Translator {
    config: Dns64Config,
}

impl Dns64Translator {
    pub fn new(config: Dns64Config) -> Self {
        Self { config }
    }

    pub fn config(&self) -> &Dns64Config {
        &self.config
    }

    pub fn translate_aaaa_response(&self, response: &[u8], client_ipv6: Option<IpAddr>) -> Vec<u8> {
        if !self.config.enabled {
            return response.to_vec();
        }

        if let Some(ipv6) = client_ipv6 {
            if ipv6.is_ipv4() {
                return response.to_vec();
            }
        }

        response.to_vec()
    }

    pub fn should_synthesize(&self, qtype: u16, client_ipv6: Option<IpAddr>) -> bool {
        if !self.config.enabled {
            return false;
        }

        if self.config.exclude_aaaa_synthesis {
            return false;
        }

        if qtype != 28 {
            return false;
        }

        if let Some(ip) = client_ipv6 {
            return ip.is_ipv6();
        }

        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_synthesize_aaaa() {
        let config = Dns64Config::default();
        let ipv4 = Ipv4Addr::new(192, 0, 2, 1);
        let aaaa = config.synthesize_aaaa(ipv4);

        assert_eq!(aaaa.to_string(), "64:ff9b::c000:201");
    }

    #[test]
    fn test_extract_ipv4() {
        let config = Dns64Config::default();
        let aaaa = Ipv6Addr::new(0x64, 0xff9b, 0, 0, 0, 0, 0xc000, 0x0201);
        let ipv4 = config.extract_ipv4_from_aaaa(aaaa);

        assert_eq!(ipv4, Some(Ipv4Addr::new(192, 0, 2, 1)));
    }

    #[test]
    fn test_is_synthesized() {
        let config = Dns64Config::default();
        let aaaa = Ipv6Addr::new(0x64, 0xff9b, 0, 0, 0, 0, 0xc000, 0x0201);

        assert!(config.is_synthesized_aaaa(aaaa));

        let regular = Ipv6Addr::new(2001, 0xdb8, 0, 0, 0, 0, 0, 1);
        assert!(!config.is_synthesized_aaaa(regular));
    }

    #[test]
    fn translator_disabled_returns_false() {
        let config = Dns64Config {
            enabled: false,
            ..Default::default()
        };
        let translator = Dns64Translator::new(config);
        let client = Some(IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1)));
        assert!(!translator.should_synthesize(28, client));
    }

    #[test]
    fn translator_ipv4_client_bypass() {
        let config = Dns64Config::new(Ipv6Addr::new(0x0064, 0xff9b, 0, 0, 0, 0, 0, 0));
        let translator = Dns64Translator::new(config);
        let client = Some(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)));
        assert!(!translator.should_synthesize(28, client));
    }

    #[test]
    fn translator_non_aaaa_query_bypass() {
        let config = Dns64Config::new(Ipv6Addr::new(0x0064, 0xff9b, 0, 0, 0, 0, 0, 0));
        let translator = Dns64Translator::new(config);
        let client = Some(IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1)));
        // qtype 1 = A, not AAAA (28)
        assert!(!translator.should_synthesize(1, client));
    }

    #[test]
    fn translator_no_client_info_bypass() {
        let config = Dns64Config::new(Ipv6Addr::new(0x0064, 0xff9b, 0, 0, 0, 0, 0, 0));
        let translator = Dns64Translator::new(config);
        // No client IP provided → should not synthesize
        assert!(!translator.should_synthesize(28, None));
    }

    #[test]
    fn translator_enabled_aaaa_from_ipv6_synthesizes() {
        let config = Dns64Config::new(Ipv6Addr::new(0x0064, 0xff9b, 0, 0, 0, 0, 0, 0));
        let translator = Dns64Translator::new(config);
        let client = Some(IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1)));
        assert!(translator.should_synthesize(28, client));
    }

    #[test]
    fn translator_custom_prefix_synthesis() {
        let custom_prefix = Ipv6Addr::new(0x2001, 0xdb8, 0x64, 0, 0, 0, 0, 0);
        let config = Dns64Config::new(custom_prefix);
        let ipv4 = Ipv4Addr::new(10, 0, 0, 1);
        let aaaa = config.synthesize_aaaa(ipv4);
        assert_eq!(
            aaaa,
            Ipv6Addr::new(0x2001, 0xdb8, 0x64, 0, 0, 0, 0x0a00, 0x0001)
        );
    }
}
