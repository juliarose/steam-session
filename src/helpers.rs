use base64::{Engine as _, engine::general_purpose};
use reqwest::header::{HeaderMap, HeaderValue, ACCEPT, InvalidHeaderValue};
use serde_json::Value;
use steamid_ng::SteamID;
use serde::Deserialize;
use sha1::{Sha1, Digest};
use sha2::Sha256;
use hmac::{Hmac, Mac};

type HmacSha256 = Hmac<Sha256>;

pub const DEFAULT_USER_AGENT: &str = "linux x86_64";

const CHARS: [char; 26] = [
    'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M',
    'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y' ,'Z'
];

/// Represents a decode error.
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
    #[error("UTF8 error: {}", .0)]
    UTF8(#[from] std::str::Utf8Error),
    #[error("Print error: {}", .0)]
    ProtoDecode(#[from] protobuf_json_mapping::PrintError),
    #[error("HMAC error: {}", .0)]
    HMACInvalidKeyLength(#[from] hmac::digest::InvalidLength),
}

#[derive(Debug, Deserialize)]
/// Represents a JSON Web Token (JWT) payload.
pub struct JwtPayload {
    /// The issuer of the JWT.
    pub iss: String,
    /// The SteamID associated with the JWT.
    #[serde(rename = "sub")]
    pub sub: SteamID,
    /// The audience of the JWT.
    #[serde(rename = "aud")]
    pub aud: Vec<String>,
    /// The expiration time of the JWT.
    pub exp: u64,
    /// The time the JWT was issued.
    pub iat: u64,
    /// The time the JWT was not valid before.
    pub nbf: u64,
    /// The time the JWT was issued.
    pub oat: u64,
    /// The JWT ID.
    pub jti: String,
    /// The permission level of the JWT.
    pub per: u8,
    /// The IP address of the subject.
    pub ip_subject: String,
    /// The IP address of the confirmer.
    pub ip_confirmer: String,
}

/// Converts a value to multipart.
pub fn value_to_multipart(value: Value) -> reqwest::multipart::Form {
    let mut form = reqwest::multipart::Form::new();
    
    if let Value::Object(map) = value {
        for (key, value) in map {
            match value {
                Value::Number(value) => {
                    form = form.text(key, value.to_string());
                },
                Value::Bool(value) => {
                    form = form.text(key, value.to_string());
                },
                Value::String(value) => {
                    form = form.text(key, value);
                },
                _ => {},
            };
        }
    }
    
    form
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

/// Creates API headers.
pub fn create_api_headers() -> Result<HeaderMap, InvalidHeaderValue> {
    let mut headers = HeaderMap::new();
    
    headers.append(ACCEPT, HeaderValue::from_str("application/json, text/plain, */*")?);
    headers.append("sec-fetch-site", HeaderValue::from_str("cross-site")?);
    headers.append("sec-fetch-mode", HeaderValue::from_str("cors")?);
    headers.append("sec-fetch-dest", HeaderValue::from_str("empty")?);
    
    Ok(headers)
}

/// Decodes a JWT for its payload. The string is seperated into three parts by periods. The first 
/// part is the header, the second part is the payload, and the third part is the signature.
/// 
/// A JWT typically looks like the following: `xxxxx.yyyyy.zzzzz`
/// 
/// The header typically consists of two parts: the type of the token, which is JWT, and the 
/// signing algorithm being used, such as HMAC SHA256 or RSA.
///
/// For example:
/// ```json
/// {
///   "alg": "EdDSA",
///   "typ": "JWT"
/// }
/// ```
/// 
/// The second part of the token is the payload, which contains the claims. Claims are statements 
/// about an entity (typically, the user) and additional data. There are three types of claims: 
/// registered, public, and private claims.
/// 
/// Steam uses the following claims:
/// ```json
/// {
///   "iss": "steam",
///   "sub": "76500000000000000",
///   "aud": [
///     "web",
///     "renew",
///     "derive"
///   ],
///   "exp": 1722401188,
///   "nbf": 1695346560,
///   "iat": 1703986560,
///   "jti": "0DD5_23ABCE40_2969F",
///   "oat": 1703986560,
///   "per": 1,
///   "ip_subject": "127.0.0.1",
///   "ip_confirmer": "127.0.0.1"
/// }
/// ```
/// 
/// See https://jwt.io/introduction for more information on JSON web tokens.
pub fn decode_jwt(jwt: &str) -> Result<JwtPayload, DecodeError> {
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
    
    // Decodes a base64 string to bytes.
    let decoded = general_purpose::STANDARD_NO_PAD.decode(standard_base64)?;
    let jwt = serde_json::from_slice::<JwtPayload>(&decoded)?;
    
    Ok(jwt)
}

/// Generates a HMAC signature.
pub fn generate_hmac_signature(
    key: &[u8],
    message: &[u8],
) -> Result<Vec<u8>, DecodeError> {
    let mut mac = HmacSha256::new_from_slice(key)?;
    
    mac.update(message);
    
    let result = mac.finalize();
    let bytes = result.into_bytes().to_vec();
    
    Ok(bytes)
}

/// Decodes a base64 string to bytes.
pub fn decode_base64(base64_str: &str) -> Result<Vec<u8>, DecodeError> {
    let decoded = general_purpose::STANDARD_NO_PAD.decode(base64_str)?;
    
    Ok(decoded)
}

/// Encodes input to base64.
pub fn encode_base64<I>(input: I) -> String
where
    I: AsRef<[u8]>
{
    general_purpose::STANDARD_NO_PAD.encode(input)
}

/// Generates a spoofed hostname.
pub fn get_spoofed_hostname() -> String {
    let mut hash = create_sha1(DEFAULT_USER_AGENT.as_bytes());
    
    hash.truncate(7);
    
    let mut output = String::from("DESKTOP-");
    
    for n in hash {
        let index = n as usize % CHARS.len();
        
        output.push(CHARS[index]);
    }
    
    output
}

pub fn create_sha1(input: &[u8]) -> Vec<u8> {
    let mut hasher = Sha1::new();
    
    hasher.update(input);
    hasher.finalize().to_vec()
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_decode_jwt() {
        let jwt = "eyAidHlwIjogIkpXVCIsICJhbGciOiAiRWREU0EiIH0.eyAiaXNzIjogInN0ZWFtIiwgInN1YiI6ICI3NjUwMDAwMDAwMDAwMDAwMCIsICJhdWQiOiBbICJ3ZWIiLCAicmVuZXciLCAiZGVyaXZlIiBdLCAiZXhwIjogMTcyMjQwMTE4OCwgIm5iZiI6IDE2OTUzNDY1NjAsICJpYXQiOiAxNzAzOTg2NTYwLCAianRpIjogIjBERDVfMjNBQkNFNDBfMjk2OUYiLCAib2F0IjogMTcwMzk4NjU2MCwgInBlciI6IDEsICJpcF9zdWJqZWN0IjogIjEyNy4wLjAuMSIsICJpcF9jb25maXJtZXIiOiAiMTI3LjAuMC4xIiB9.-fsYDOMqkVFveAAbvSCcED5NLpCbacbY6Mq9N1fev56QCh9f6PNaksqASI2dJORZFPLhZj37kK1UwfX53QYVDF";
        let decoded = decode_jwt(jwt).unwrap();
        
        assert!(decoded.aud.iter().any(|a| a == "web"));
        assert_eq!(decoded.sub, SteamID::from(76500000000000000));
        assert_eq!(decoded.iss, "steam");
        assert_eq!(decoded.exp, 1722401188);
        assert_eq!(decoded.nbf, 1695346560);
        assert_eq!(decoded.iat, 1703986560);
        assert_eq!(decoded.jti, "0DD5_23ABCE40_2969F");
        assert_eq!(decoded.oat, 1703986560);
        assert_eq!(decoded.per, 1);
    }
    
    #[test]
    fn test_bad_jwt() {
        let jwt = "Yup, this is a bad JWT. It's not even a JWT. It's just a string. It's not even base64 encoded.";
        let decoded = decode_jwt(jwt).unwrap_err();
        
        assert!(matches!(decoded, DecodeError::InvalidJWT));
    }
}
