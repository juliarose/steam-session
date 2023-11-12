

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

pub fn decode_jwt(jwt: &str) -> Option<u8> {
    let mut parts = jwt.split('.');
    
    parts.next()?;

    let part = parts.next();

    parts.next()?;

    if parts.next().is_some() {
        // invalid
        return None;
    }
//     let standardBase64 = parts[1].replace(/-/g, '+')
//     .replace(/_/g, '/');

//     return JSON.parse(Buffer.from(standardBase64, 'base64').toString('utf8'));

    Some(0)
}

pub fn is_jwt_valid_for_audience(
    jwt: &str,
    audience: &str,
    steamid: Option<&str>,
) -> bool {
    if let Some(decoded_token) = decode_jwt(jwt) {
        // // Check if the steamid matches
        // if (steamId && decodedToken.sub != steamId) {
        //     return false;
        // }

        // return (decodedToken.aud || []).includes(audience);
    }

    

    false
}