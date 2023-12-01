use crate::enums::EResult;

pub mod web_api;
pub mod websocket;
pub mod cm_server;
pub mod cm_list_cache;
pub mod helpers;

use reqwest::header::HeaderMap;
pub use websocket::WebSocketCMTransport;

#[derive(Debug, Clone)]
pub struct ApiResponse2 {
    pub eresult: Option<EResult>,
    pub error_message: Option<String>,
    pub body: Option<Vec<u8>>,
}

pub struct ApiRequest {
    pub interface: String,
    pub method: String,
    pub version: u32,
    pub access_token: Option<String>,
    pub request_data: Option<Vec<u8>>,
    pub headers: HeaderMap,
}

impl ApiRequest {
    pub fn pathname(&self) -> String {
        format!(
            "I{}Service/{}/v{}",
            self.interface,
            self.method,
            self.version
        )
    }
}

pub struct ApiRequest2 {
    pub interface: String,
    pub method: String,
    pub version: u32,
    pub access_token: Option<String>,
    pub headers: Option<HeaderMap>,
}

impl ApiRequest2 {
    pub fn pathname(&self) -> String {
        format!(
            "I{}Service/{}/v{}",
            self.interface,
            self.method,
            self.version
        )
    }
    
    pub fn target_name(&self) -> String {
        format!(
            "{}.{}#{}",
            self.interface,
            self.method,
            self.version,
        )
    }
}