use crate::enums::EResult;

pub mod web_api;
pub mod websocket;
pub mod cm_server;
pub mod cm_list_cache;
pub mod helpers;

use crate::api_method::ApiRequest;

use reqwest::header::HeaderMap;
pub use websocket::WebSocketCMTransport;

#[derive(Debug, Clone)]
pub struct ApiResponse2 {
    pub eresult: Option<EResult>,
    pub error_message: Option<String>,
    pub body: Option<Vec<u8>>,
}

impl ApiResponse2 {
    pub fn into_response<Msg>(self)
    where
        Msg: ApiRequest,
        <Msg as ApiRequest>::Response: Send,
    {

    }
}