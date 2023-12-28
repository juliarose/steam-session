mod error;

use std::ops::Deref;

pub use error::Error;

use crate::authentication_client::Error as AuthenticationClientError;
use crate::transports::Transport;
use crate::net::{ApiRequest, ApiResponse};
use crate::helpers::{encode_base64, create_api_headers};
use reqwest::Client;
use bytes::{BytesMut, Buf};
use async_trait::async_trait;
use tokio::sync::oneshot;

const HOSTNAME: &str = "api.steampowered.com";

#[async_trait]
impl Transport for WebApiTransport {
    async fn send_request<Msg>(
        &self,
        msg: Msg,
        access_token: Option<String>,
    ) -> Result<Option<oneshot::Receiver<Result<Msg::Response, AuthenticationClientError>>>, AuthenticationClientError> 
    where
        Msg: ApiRequest,
        <Msg as ApiRequest>::Response: Send,
    {
        let response = self.send(msg, access_token).await?;
        let (tx, rx) = oneshot::channel();
        
        Ok(Some(rx))
    }
}

pub struct WebApiTransport {
    client: Client,
}

impl WebApiTransport {
    pub fn new() -> Self {
        Self {
            client: Client::new(),
        }
    }
    
    fn get_url(pathname: &str) -> String {
        format!("https://{HOSTNAME}/{pathname}")
    }
    
    async fn send<Msg>(
        &self,
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
        let url = Self::get_url(&pathname);
        let encoded_message = encode_base64(msg.write_to_bytes()?);
        let request = if is_get_request(&pathname) {
            let mut query = vec![("input_protobuf_encoded", encoded_message.as_str())];
            
            if let Some(access_token) = &access_token {
                query.push(("access_token", access_token.as_str()));
            }
            
            self.client.get(&url)
                .query(&query)
        } else {
            let form = reqwest::multipart::Form::new()
                .text("input_protobuf_encoded", encoded_message);
            
            self.client.post(&url)
                .multipart(form)
        };
        let response = request
            .headers(headers)
            .send()
            .await?
            .bytes()
            .await?;
        
        // check response for errors...
        
        let bytes = BytesMut::from(response.deref());
        let mut reader = bytes.reader();
        let response = Msg::Response::parse_from_reader(&mut reader)?;
        
        Ok(response)
    }
}

fn is_get_request(endpoint: &str) -> bool {
    endpoint == "IAuthenticationService/GetPasswordRSAPublicKey/v1"
}
