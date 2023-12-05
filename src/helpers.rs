use lazy_regex::regex_replace_all;

pub const USER_AGENT: &str = "linux x86_64"; 

pub struct DecodedQr {
    version: u32,
    client_id: String,
}

pub fn decode_qr_url(url: &str) -> Option<DecodedQr> {
    // if let Some((_, version_str, client_id)) = regex_match!(/^https?:\/\/s\.team\/q\/(\d+)\/(\d+)(\?|$)/) {
        // let version_str = "1";
        // let version: u32 = version_str.try_into().ok()?;
        // return {
        //     client_id,
        //     version,
        // };
    // }

    None
}

#[derive(Debug, thiserror::Error)]
pub enum DecodeError {
    #[error("Invalid JWT")]
    InvalidJWT,
    #[error("Error decoding base64: {}", .0)]
    Base64(#[from] base64::DecodeError),
    #[error("JSON parse error: {}", .0)]
    Json(#[from] serde_json::Error),
    #[error("Invalid SteamID: {}", .0)]
    InvalidSteamID(String),
}

use base64::{Engine as _, engine::general_purpose};
use steamid_ng::SteamID;
use serde::Deserialize;

#[derive(Debug, Deserialize)]
pub struct JWT {
    pub steamid: SteamID,
    pub audience: Vec<String>,
}

pub fn decode_jwt(jwt: &str) -> Result<JWT, DecodeError> {
    let mut parts = jwt.split('.');
    
    parts.next().ok_or(DecodeError::InvalidJWT)?;
    
    let part = parts.next().ok_or(DecodeError::InvalidJWT)?;
    
    parts.next().ok_or(DecodeError::InvalidJWT)?;
    
    if parts.next().is_some() {
        // invalid
        return Err(DecodeError::InvalidJWT);
    }
    
    let mut standard_base64 = String::with_capacity(part.len());
    
    for ch in part.chars() {
        match ch {
            '-' => standard_base64.push('+'),
            '_' => standard_base64.push('/'),
            ch => standard_base64.push(ch),
        }
    }
    
    let decoded = general_purpose::STANDARD_NO_PAD.decode(standard_base64)?;
    let jwt = serde_json::from_slice::<JWT>(&decoded)?;
    
    Ok(jwt)
}

pub fn is_jwt_valid_for_audience(
    jwt: &str,
    audience: &str,
    steamid: Option<&str>,
) -> bool {
    if let Ok(decoded) = decode_jwt(jwt) {
        if let Some(steamid) = steamid {
            if u64::from(decoded.steamid).to_string() != steamid {
                return false;
            }
        }
        
        return decoded.audience.iter().any(|a| a == audience);
    }
    
    false
}