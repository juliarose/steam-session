#[derive(Debug, thiserror::Error)]
pub enum LoginSessionError {
    #[error("Login session has not been started yet")]
    LoginSessionHasNotStarted,
    #[error("Login attempt has been canceled")]
    LoginAttemptCancelled,
    #[error("Cannot use this method with this login scheme")]
    LoginCannotUseMethodWithScheme,
    #[error("No Steam Guard code is needed for this login attempt")]
    LoginAttemptSteamGuardNotRequired,
    #[error("Websocket CM: {}", .0)]
    WebSocketCM(#[from] crate::transports::websocket::Error),
    #[error("Decode error: {}", .0)]
    Decode(#[from] crate::helpers::DecodeError),
    #[error("The provided token is a refresh token, not an access token'")]
    ExpectedAccessToken,
    #[error("Token is for a different account. To work with a different account, create a new LoginSession.")]
    TokenIsForDifferentAccount,
    #[error("This access token belongs to a different account from the set refresh token.")]
    AccessTokenBelongsToOtherAccount,
    #[error("Authentication client error: {}", .0)]
    AuthenticationClient(#[from] crate::authentication_client::Error),
    #[error("A refresh token is required to get web cookies")]
    NoRefreshToken,
}