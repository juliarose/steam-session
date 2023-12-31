use super::{Error, WebApiTransport};
use crate::enums::EResult;
use crate::net::{ApiRequest, ApiResponse};
use crate::helpers::{encode_base64, create_api_headers};
use std::ops::Deref;
use reqwest::{Client, StatusCode};
use bytes::{BytesMut, Buf};
use lazy_static::lazy_static;

lazy_static! {
    pub static ref DEFAULT_CLIENT: Client = Client::new();
}

/// Gets a response.
pub async fn get_response<Msg>(
    msg: Msg,
    access_token: Option<String>,
) -> Result<Msg::Response, Error>
where
    Msg: ApiRequest,
    <Msg as ApiRequest>::Response: Send,
{
    let pathname = format!(
        "I{}Service/{}/v{}",
        Msg::INTERFACE,
        Msg::METHOD,
        Msg::VERSION,
    );
    let headers = create_api_headers()?;
    let url = WebApiTransport::get_url(&pathname);
    let encoded_message = encode_base64(msg.write_to_bytes()?);
    let request = if is_get_request(&pathname) {
        let mut query = vec![("input_protobuf_encoded", encoded_message.as_str())];
        
        if let Some(access_token) = &access_token {
            query.push(("access_token", access_token.as_str()));
        }
        
        log::debug!("GET {}", url);
        DEFAULT_CLIENT.get(&url)
            .query(&query)
    } else {
        let form = reqwest::multipart::Form::new()
            .text("input_protobuf_encoded", encoded_message);
        
        log::debug!("POST {}", url);
        DEFAULT_CLIENT.post(&url)
            .multipart(form)
    };
    let response = request
        .headers(headers)
        .send()
        .await?;
    
    check_response_for_errors(&response)?;
    
    let response = response
        .bytes()
        .await?;
    let bytes = BytesMut::from(response.deref());
    let mut reader = bytes.reader();
    let response = Msg::Response::parse_from_reader(&mut reader)?;
    
    Ok(response)
}

// Checks response for errors.
fn check_response_for_errors(response: &reqwest::Response) -> Result<(), Error> {
    let headers = response.headers();
    
    if let Some(eresult) = headers.get("x-eresult") {
        if let Ok(Ok(eresult)) = eresult.to_str().map(|s| s.parse::<i32>()) {
            if let Ok(eresult) = EResult::try_from(eresult) {
                if eresult != EResult::OK {
                    return Err(Error::EResultNotOK(eresult));
                }
            } else {
                return Err(Error::UnknownEResult(eresult));
            }
        }
    }
    
    if response.status() != StatusCode::OK {
        
    }
    
    Ok(())
}

/// Checks if the request is a GET request.
fn is_get_request(endpoint: &str) -> bool {
    endpoint == "IAuthenticationService/GetPasswordRSAPublicKey/v1"
}