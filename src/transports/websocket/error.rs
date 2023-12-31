use super::cm_list_cache;
use crate::enums::EResult;
use tokio_tungstenite::tungstenite;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("{}", .0)]
    CmServer(#[from] cm_list_cache::Error),
    #[error("IO: {}", .0)]
    OI(#[from] std::io::Error),
    #[error("Invalid URI with websocket: {}", .0)]
    Url(#[from] tungstenite::http::uri::InvalidUri),
    #[error("Parsed URL does not contain hostname")]
    UrlNoHostName,
    #[error("HTTP error with websocket: {}", .0)]
    Http(#[from] tungstenite::http::Error),
    #[error("Connection error with websocket: {}", .0)]
    Connection(#[from] tungstenite::Error),
    #[error("Response error: {}", .0)]
    ResponseError(String),
    #[error("Response returned empty body without an error message")]
    NoBodyInResponse,
    #[error("Received ClientLogOnResponse with result: {:?} (try another CM)", .0)]
    ClientLogOnResponseTryAnotherCM(EResult),
    #[error("Received unexpected non-protobuf message: {}", .0)]
    UnexpectedNonProtobufMessage(u32),
    #[error("Error with protobuf message: {}", .0)]
    Proto(#[from] protobuf::Error),
    #[error("Wrong service method: expected {}; got {}", .0, .1)]
    DifferentServiceMethod(&'static str, String),
    #[error("Response timed out")]
    Timeout,
    #[error("Receiver error: {}", .0)]
    RecvError(#[from] tokio::sync::oneshot::error::RecvError),
    #[error("Unknown EMsg: {}", .0)]
    UnknownEMsg(u32),
    #[error("Unknown EResult: {}", .0)]
    UnknownEResult(i32),
    #[error("Received EResult other than OK: {:?}", .0)]
    EResultNotOK(EResult),
}