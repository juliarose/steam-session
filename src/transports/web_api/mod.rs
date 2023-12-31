mod error;
mod helpers;

pub use error::Error;

use crate::authentication_client::Error as AuthenticationClientError;
use crate::transports::Transport;
use crate::net::ApiRequest;
use async_trait::async_trait;
use tokio::sync::oneshot;

const HOSTNAME: &str = "api.steampowered.com";

/// Web API transport.
#[derive(Debug)]
pub struct WebApiTransport {}

#[async_trait]
impl Transport for WebApiTransport {
    async fn send_request<Msg>(
        &self,
        msg: Msg,
        access_token: Option<String>,
    ) -> Result<oneshot::Receiver<Result<Msg::Response, AuthenticationClientError>>, AuthenticationClientError> 
    where
        Msg: ApiRequest,
        <Msg as ApiRequest>::Response: Send,
    {
        let (tx, rx) = oneshot::channel();
        
        tokio::spawn(async move {
            let result = helpers::get_response(msg, access_token).await
                .map_err(AuthenticationClientError::WebAPI);
            
            tx.send(result)
        });
        
        Ok(rx)
    }
}

impl WebApiTransport {
    /// Creates a new [`WebApiTransport`].
    pub fn new() -> Self {
        Self {}
    }
    
    /// Gets the URL.
    fn get_url(pathname: &str) -> String {
        format!("https://{HOSTNAME}/{pathname}")
    }
}