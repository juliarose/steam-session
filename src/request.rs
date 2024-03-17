use crate::enums::{ESessionPersistence, EAuthTokenPlatformType};

#[derive(Debug, Clone)]
pub struct StartLoginSessionWithCredentialsDetails {
    pub account_name: String,
    pub password: String,
    pub platform_type: EAuthTokenPlatformType,
    pub persistence: Option<ESessionPersistence>,
    pub steam_guard_machine_token: Option<Vec<u8>>,
    pub steam_guard_code: Option<String>,
    pub machine_id: Option<Vec<u8>>,
    pub user_agent: Option<&'static str>,
}

impl Default for StartLoginSessionWithCredentialsDetails {
    fn default() -> Self {
        Self {
            account_name: String::new(),
            password: String::new(),
            platform_type: EAuthTokenPlatformType::k_EAuthTokenPlatformType_WebBrowser,
            persistence: None,
            steam_guard_machine_token: None,
            steam_guard_code: None,
            machine_id: None,
            user_agent: None,
        }
    }
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
pub struct MobileConfirmationRequest {
    pub version: u16,
    pub client_id: u64,
    pub steamid: u64,
    pub signature: Vec<u8>,
    pub confirm: bool,
    pub persistence: ESessionPersistence,
}

#[derive(Debug)]
pub struct ApproveAuthSessionRequest {
    pub version: u16,
    pub client_id: u64,
    pub steamid: u64,
    pub approve: bool,
    pub persistence: ESessionPersistence,
}