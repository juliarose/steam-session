use steam_session_proto::enums::ESessionPersistence;
use steam_session_proto::steammessages_auth_steamclient::EAuthTokenPlatformType;

#[derive(Debug, Clone)]
pub struct StartLoginSessionWithCredentialsDetails {
    pub account_name: String,
    pub password: String,
    pub persistence: Option<ESessionPersistence>,
    pub steam_guard_machine_token: Option<Vec<u8>>,
    pub steam_guard_code: Option<String>,
    pub platform_type: EAuthTokenPlatformType,
    pub machine_id: Option<Vec<u8>>,
    pub user_agent: Option<&'static str>,
}

#[derive(Debug, Clone)]
pub struct StartAuthSessionRequest {
    pub platform_type: EAuthTokenPlatformType,
}

#[derive(Debug, Clone)]
pub struct StartAuthSessionWithCredentialsRequest {
    pub account_name: String,
    pub encrypted_password: String,
    pub encryption_timestamp: u64,
    pub remember_login: bool,
    pub platform_type: EAuthTokenPlatformType,
    pub persistence: ESessionPersistence,
    pub steam_guard_machine_token: Option<Vec<u8>>,
}

#[derive(Debug, Clone)]
pub struct ApproveAuthSessionRequest<'a> {
    pub qr_challenge_url: &'a str,
    pub approve: bool,
    pub persistence: Option<ESessionPersistence>,
}

#[derive(Debug, Clone)]
pub struct MobileConfirmationRequest {
    pub version: i32,
    pub client_id: u64,
    pub steamid: u64,
    pub signature: Vec<u8>,
    pub confirm: bool,
    pub persistence: ESessionPersistence,
}
