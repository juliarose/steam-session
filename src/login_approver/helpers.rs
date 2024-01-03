use lazy_regex::regex_captures;

/// Represents a decoded QR code.
pub struct DecodedQr {
    /// The version of the QR code.
    pub version: u32,
    /// The client ID extracted from the QR code.
    pub client_id: u64,
}

/// Decodes QR url.
pub fn decode_qr_url(url: &str) -> Option<DecodedQr> {
    if let Some((_, version_str, client_id, _)) = regex_captures!(r#"^https?:\/\/s\.team\/q\/(\d+)\/(\d+)(\?|$)"#, url) {
        let version: u32 = version_str.parse::<u32>().ok()?;
        let client_id = client_id.parse::<u64>().ok()?;
        
        return Some(DecodedQr {
            version,
            client_id,
        });
    }
    
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn decodes_qr_url() {
        let url = "https://s.team/q/1/123456789012345678";
        let decoded = decode_qr_url(url).unwrap();
        
        assert_eq!(decoded.version, 1);
        assert_eq!(decoded.client_id, 123456789012345678);
    }
}
