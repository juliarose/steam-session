use crate::transports::cm_list_cache;
use protobuf::ProtobufError;
use tokio_tungstenite::tungstenite;
use tokio_tungstenite::tungstenite::http::uri::InvalidUri;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("No CM server available")]
    NoCmServer,
    #[error("{}", .0)]
    CmServer(#[from] cm_list_cache::Error),
    #[error("IO error with websocket: {}", .0)]
    OI(#[from] std::io::Error),
    #[error("HTTP error with websocket: {}", .0)]
    Http(#[from] tokio_tungstenite::tungstenite::http::Error),
    #[error("Invalid URI with websocket: {}", .0)]
    Url(#[from] InvalidUri),
    #[error("Connection error with websocket: {}", .0)]
    Connection(#[from] tungstenite::Error),
    #[error("Received unexpected non-protobuf message: {}", .0)]
    UnexpectedNonProtobufMessage(u32),
    #[error("Error with protobuf message: {}", .0)]
    Proto(#[from] ProtobufError),
    #[error("Unknown EMsg: {}", .0)]
    UnknownEMsg(u32),
    #[error("Unknown EResult: {}", .0)]
    UnknownEResult(i32),
    #[error("No response")]
    NoResponse,
    #[error("Response timed out")]
    Timeout,
    #[error("Wrong service method: expected {}; got {}", .0, .1)]
    DifferentServiceMethod(&'static str, String),
    #[error("Receiver error: {}", .0)]
    RecvError(#[from] tokio::sync::oneshot::error::RecvError),
}