pub mod web_api;
pub mod websocket;
pub mod cm_server;
pub mod cm_list_cache;

use crate::authentication_client::Error as AuthenticationClientError;
use crate::net::ApiRequest;

pub use websocket::WebSocketCMTransport;
use async_trait::async_trait;
use tokio::sync::oneshot;

#[async_trait]
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