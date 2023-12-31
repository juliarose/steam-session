use steam_session_proto::steammessages_auth_steamclient::EAuthSessionGuardType;

use crate::enums::EResult;

#[derive(Debug, thiserror::Error)]
pub enum LoginSessionError {
    #[error("{}", .0)]
    Reqwest(#[from] reqwest::Error),
    #[error("{}", .0)]
    Serde(#[from] serde_json::Error),
    #[error("Login session has not been started yet")]
    LoginSessionHasNotStarted,
    #[error("Cannot use this method with this login scheme")]
    LoginCannotUseMethodWithScheme,
    #[error("No Steam Guard code is needed for this login attempt")]
    LoginAttemptSteamGuardNotRequired,
    #[error("Decode error: {}", .0)]
    Decode(#[from] crate::helpers::DecodeError),
    #[error("The provided token is a refresh token, not an access token")]
    ExpectedAccessToken,
    #[error("The provided token is an access token, not a refresh token")]
    ExpectedRefreshToken,
    #[error("Token is for a different account. To work with a different account, create a new LoginSession")]
    TokenIsForDifferentAccount,
    #[error("This token belongs to a different account from the set token")]
    TokenBelongsToOtherAccount,
    #[error("Authentication client error: {}", .0)]
    AuthenticationClient(#[from] crate::authentication_client::Error),
    #[error("{}", .0)]
    InvalidHeaderValue(#[from] reqwest::header::InvalidHeaderValue),
    #[error("A refresh token is required to get web cookies")]
    NoRefreshToken,
    #[error("An access token is required to get web cookies")]
    NoAccessToken,
    #[error("Unknown auth session guard type: {:?}", .0)]
    UnknownGuardType(EAuthSessionGuardType),
    #[error("Token platform type is different from the platform type of this LoginSession instance (required audience \"{}\"", .0)]
    TokenPlatformDifferent(String),
    #[error("Malformed response")]
    MalformedResponse,
    #[error("Received EResult other than OK: {:?}", .0)]
    EResultNotOK(EResult),
    #[error("No cookies were returned in response")]
    NoCookiesInResponse,
    #[error("Receiver error: {}", .0)]
    RecvError(#[from] tokio::sync::oneshot::error::RecvError),
}