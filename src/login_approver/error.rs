#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("IO error: {}", .0)]
    IO(#[from] std::io::Error),
    #[error("Provided token is a refresh token, not an access token")]
    RefreshToken,
    #[error("Provided token is not valid for MobileApp platform usage")]
    InvalidToken,
    #[error("Invalid QR URL")]
    InvalidQRUrl,
    #[error("Decode error: {}", .0)]
    Decode(#[from] crate::helpers::DecodeError),
    #[error("Authentication client error: {}", .0)]
    AuthenticationClient(#[from] crate::authentication_client::Error),
}