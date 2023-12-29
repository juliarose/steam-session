use crate::enums::EAuthTokenPlatformType;

#[derive(Debug, Clone)]
pub struct EncryptedPassword {
    pub encrypted_password: String,
    pub key_timestamp: u64,
}

#[derive(Debug)]
pub struct LoginSessionOptions {
    pub platform_type: EAuthTokenPlatformType,
    pub user_agent: Option<&'static str>,
    pub machine_id: Option<Vec<u8>>,
}