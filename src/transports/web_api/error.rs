
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("Request: {}", .0)]
    Http(#[from] reqwest::Error),
    #[error("Decode error: {}", .0)]
    Decode(#[from] crate::helpers::DecodeError),
    #[error("Protobuf error: {}", .0)]
    Proto(#[from] protobuf::Error),
    #[error("{}", .0)]
    InvalidHeaderValue(#[from] reqwest::header::InvalidHeaderValue),
}