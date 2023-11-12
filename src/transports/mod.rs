
pub mod web_api;
pub mod web_socket_cm;
pub mod cm_server;

pub struct ApiRequest {
    interface: String,
    method: String,
    version: u32,
    access_token: Option<String>,
    // todo proper data type, probably String or Vec<u8>,
    request_data: Option<u8>,
    // todo headers type
    headers: Option<u8>,
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