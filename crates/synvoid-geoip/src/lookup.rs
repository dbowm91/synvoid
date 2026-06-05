use std::net::IpAddr;
use std::path::Path;

use maxminddb::{PathElement, Reader};

use crate::types::CountryInfo;

pub struct GeoIpLookup {
    pub reader: Option<Reader<Vec<u8>>>,
}

impl GeoIpLookup {
    pub fn new(path: &str) -> Result<Self, String> {
        if path.is_empty() {
            return Ok(Self { reader: None });
        }

        let path = Path::new(path);
        if !path.exists() {
            return Ok(Self { reader: None });
        }

        let reader = Reader::open_readfile(path)
            .map_err(|e| format!("Failed to parse GeoIP database: {}", e))?;

        Ok(Self {
            reader: Some(reader),
        })
    }

    pub fn load_database_from_slice(data: &[u8]) -> Result<Self, String> {
        let reader = Reader::from_source(data.to_vec())
            .map_err(|e| format!("Failed to parse GeoIP database: {}", e))?;

        Ok(Self {
            reader: Some(reader),
        })
    }

    pub fn lookup_country(&self, ip: IpAddr) -> Option<String> {
        let reader = self.reader.as_ref()?;

        let result = reader.lookup(ip).ok()?;

        let code: Option<String> = result
            .decode_path(&[PathElement::Key("country"), PathElement::Key("iso_code")])
            .ok()
            .flatten();

        code
    }

    pub fn lookup_country_info(&self, ip: IpAddr) -> Option<CountryInfo> {
        let reader = self.reader.as_ref()?;

        let result = reader.lookup(ip).ok()?;

        let code: Option<String> = result
            .decode_path(&[PathElement::Key("country"), PathElement::Key("iso_code")])
            .ok()
            .flatten();

        let name: Option<String> = result
            .decode_path(&[
                PathElement::Key("country"),
                PathElement::Key("names"),
                PathElement::Key("en"),
            ])
            .ok()
            .flatten();

        let code = code?;
        let name = name.unwrap_or_else(|| code.clone());

        Some(CountryInfo {
            code,
            name,
            subdivision: None,
            city: None,
        })
    }

    pub fn lookup_subdivision(&self, ip: IpAddr) -> Option<String> {
        let reader = self.reader.as_ref()?;

        let result = reader.lookup(ip).ok()?;

        let subdivision: Option<String> = result
            .decode_path(&[
                PathElement::Key("subdivisions"),
                PathElement::Index(0),
                PathElement::Key("names"),
                PathElement::Key("en"),
            ])
            .ok()
            .flatten();

        subdivision
    }

    pub fn lookup_city(&self, ip: IpAddr) -> Option<String> {
        let reader = match &self.reader {
            Some(r) => r,
            None => return None,
        };

        let result = reader.lookup(ip).ok()?;

        let city: Option<String> = result
            .decode_path(&[
                PathElement::Key("city"),
                PathElement::Key("names"),
                PathElement::Key("en"),
            ])
            .ok()
            .flatten();

        city
    }

    pub fn lookup_asn(&self, ip: IpAddr) -> Option<(u32, String)> {
        let reader = match &self.reader {
            Some(r) => r,
            None => return None,
        };

        let result = reader.lookup(ip).ok()?;

        let asn_number: Option<u32> = result
            .decode_path(&[PathElement::Key("autonomous_system_number")])
            .ok()
            .flatten();

        let asn_name: Option<String> = result
            .decode_path(&[PathElement::Key("autonomous_system_organization")])
            .ok()
            .flatten();

        let asn_number = asn_number?;
        let asn_name = asn_name.unwrap_or_else(|| "Unknown".to_string());

        Some((asn_number, asn_name))
    }

    pub fn is_loaded(&self) -> bool {
        self.reader.is_some()
    }

    pub fn lookup_location(&self, ip: IpAddr) -> Option<(f64, f64)> {
        let reader = match &self.reader {
            Some(r) => r,
            None => return None,
        };

        let result = reader.lookup(ip).ok()?;

        let latitude: Option<f64> = result
            .decode_path(&[PathElement::Key("location"), PathElement::Key("latitude")])
            .ok()
            .flatten();

        let longitude: Option<f64> = result
            .decode_path(&[PathElement::Key("location"), PathElement::Key("longitude")])
            .ok()
            .flatten();

        match (latitude, longitude) {
            (Some(lat), Some(lon)) => Some((lat, lon)),
            _ => None,
        }
    }

    pub fn lookup_location_info(&self, ip: IpAddr) -> Option<GeoLocationInfo> {
        let reader = match &self.reader {
            Some(r) => r,
            None => return None,
        };

        let result = reader.lookup(ip).ok()?;

        let country: Option<String> = result
            .decode_path(&[PathElement::Key("country"), PathElement::Key("iso_code")])
            .ok()
            .flatten();

        let region: Option<String> = result
            .decode_path(&[
                PathElement::Key("subdivisions"),
                PathElement::Index(0),
                PathElement::Key("names"),
                PathElement::Key("en"),
            ])
            .ok()
            .flatten();

        let latitude: Option<f64> = result
            .decode_path(&[PathElement::Key("location"), PathElement::Key("latitude")])
            .ok()
            .flatten();

        let longitude: Option<f64> = result
            .decode_path(&[PathElement::Key("location"), PathElement::Key("longitude")])
            .ok()
            .flatten();

        match (latitude, longitude) {
            (Some(lat), Some(lon)) => Some(GeoLocationInfo {
                country,
                region,
                latitude: lat,
                longitude: lon,
            }),
            _ => None,
        }
    }

    pub fn reload_from_slice(&mut self, data: Vec<u8>) -> Result<(), String> {
        let reader = Reader::from_source(data)
            .map_err(|e| format!("Failed to parse GeoIP database: {}", e))?;

        self.reader = Some(reader);
        Ok(())
    }
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct GeoLocationInfo {
    pub country: Option<String>,
    pub region: Option<String>,
    pub latitude: f64,
    pub longitude: f64,
}
