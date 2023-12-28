use crate::enums::{EResult, EAuthTokenPlatformType};

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("Unsupported platform type: {:?}", .0)]
    UnsupportedPlatformType(EAuthTokenPlatformType),
    #[error("{}", .0)]
    InvalidHeaderValue(#[from] reqwest::header::InvalidHeaderValue),
    #[error("{}", .0)]
    InvalidHeaderName(#[from] reqwest::header::InvalidHeaderName),
    #[error("serde_qs error: {}", .0)]
    SerdeQS(#[from] serde_qs::Error),
    #[error("Decode error: {}", .0)]
    Decode(#[from] crate::helpers::DecodeError),
    #[error("Request does not expect response")]
    NoJob,
    #[error("Receiver error: {}", .0)]
    RecvError(#[from] tokio::sync::oneshot::error::RecvError),
    #[error("Failed to parse int: {}", .0)]
    BadUint(String),
    #[error("RSA error: {}", .0)]
    RSA(#[from] rsa::Error),
    #[error("reqwest error: {}", .0)]
    Reqwest(#[from] reqwest::Error),
    #[error("Websocket CM: {}", .0)]
    WebSocketCM(#[from] crate::transports::websocket::Error),
    #[error("WebAPI: {}", .0)]
    WebAPI(#[from] crate::transports::web_api::Error),
    #[error("Received EResult other than OK: {:?}", .0)]
    EResultNotOK(EResult),
}