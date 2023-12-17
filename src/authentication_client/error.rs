use steam_session_proto::steammessages_auth_steamclient::EAuthTokenPlatformType;

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
    #[error("websocket error: {}", .0)]
    Websocket(#[from] crate::transports::websocket::Error),
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
}