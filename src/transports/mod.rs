pub mod web_api;
pub mod websocket;

pub use websocket::WebSocketCMTransport;

use crate::authentication_client::Error as AuthenticationClientError;
use crate::net::ApiRequest;
use tokio::sync::oneshot;

#[async_trait::async_trait]
pub trait Transport: Sync + Send {
    async fn send_request<Msg>(
        &self,
        msg: Msg,
        access_token: Option<String>,
    ) -> Result<oneshot::Receiver<Result<Msg::Response, AuthenticationClientError>>, AuthenticationClientError> 
    where
        Msg: ApiRequest,
        <Msg as ApiRequest>::Response: Send;
}