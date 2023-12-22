use base64::{Engine as _, engine::general_purpose};
use reqwest::header::{HeaderMap, HeaderValue, ACCEPT, HeaderName};
use steamid_ng::SteamID;
use serde::Deserialize;
use sha1::{Sha1, Digest};
use bytebuffer_new::{ByteBuffer, Endian};

pub const USER_AGENT: &str = "linux x86_64"; 

pub struct DecodedQr {
    pub version: u32,
    pub client_id: String,
}

/// Generates a random sessionid.
pub fn generate_sessionid() -> String {
    // Should look like "37bf523a24034ec06c60ec61"
    (0..12)
        .map(|_| { 
            let b = rand::random::<u8>();
            
            format!("{b:02x?}")
        })
        .collect()
}

pub fn create_api_headers() -> Result<HeaderMap, crate::authentication_client::Error> {
    let mut headers = HeaderMap::new();
    
    headers.append(ACCEPT, HeaderValue::from_str("application/json, text/plain, */*")?);
    headers.append("sec-fetch-site", HeaderValue::from_str("cross-site")?);
    headers.append("sec-fetch-mode", HeaderValue::from_str("cors")?);
    headers.append("sec-fetch-dest", HeaderValue::from_str("empty")?);
    
    Ok(headers)
}

pub fn decode_qr_url(_url: &str) -> Option<DecodedQr> {
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

#[derive(Debug, Deserialize)]
pub struct JWT {
    #[serde(rename = "sub")]
    pub steamid: SteamID,
    #[serde(rename = "aud")]
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

/// Decodes input from base64.
pub fn decode_base64<I>(input: I) -> Result<Vec<u8>, base64::DecodeError>
where
    I: AsRef<[u8]>
{
    general_purpose::STANDARD_NO_PAD.decode(input)
}

/// Decodes input to base64.
pub fn encode_base64<I>(input: I) -> String
where
    I: AsRef<[u8]>
{
    general_purpose::STANDARD_NO_PAD.encode(input)
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

const CHARS: [char; 26] = [
    'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M',
    'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y' ,'Z'
];

pub fn get_spoofed_hostname() -> String {
    let mut hash = create_sha1(USER_AGENT.as_bytes());
    
    hash.truncate(7);
    
    let mut output = String::from("DESKTOP-");
    
    for n in hash {
        let index = n as usize % CHARS.len();
        
        output.push(CHARS[index]);
    }
    
    output
}

fn create_sha1(input: &[u8]) -> Vec<u8> {
    let mut hasher = Sha1::new();
    
    hasher.update(input);
    hasher.finalize().to_vec()
}

fn bytes_to_hex_string(input: &[u8]) -> String {
    use std::fmt::Write;
    
    let mut s = String::with_capacity(2 * input.len());
    
    for byte in input {
        write!(s, "{:02X}", byte).unwrap();
    }
    
    s
}

fn create_sha1_str(input: &str) -> String {
    let sha_bytes = create_sha1(input.as_bytes());
    
    bytes_to_hex_string(&sha_bytes)
}

pub fn get_machine_id(account_name: &str) -> Vec<u8> {
    fn get_c_string_bytes(input: &str) -> Vec<u8> {
        let mut bytes = input.as_bytes().to_vec();
        
        bytes.push(0);
        bytes
    }
    
    let mut buffer = ByteBuffer::new();
    
    buffer.set_endian(Endian::LittleEndian);
    
    buffer.write_i8(0);
    buffer.write_bytes(&get_c_string_bytes("MessageObject"));
    
    buffer.write_i8(1);
    buffer.write_bytes(&get_c_string_bytes("BB3"));
    buffer.write_bytes(&get_c_string_bytes(&create_sha1_str(&format!("SteamUser Hash BB3 {account_name}"))));
    
    buffer.write_i8(1);
    buffer.write_bytes(&get_c_string_bytes("FF2"));
    buffer.write_bytes(&get_c_string_bytes(&create_sha1_str(&format!("SteamUser Hash FF2 {account_name}"))));
    
    buffer.write_i8(1);
    buffer.write_bytes(&get_c_string_bytes("3B3"));
    buffer.write_bytes(&get_c_string_bytes(&create_sha1_str(&format!("SteamUser Hash 3B3 {account_name}"))));
    
    buffer.write_i8(8);
    buffer.write_i8(8);
    buffer.to_bytes()
}