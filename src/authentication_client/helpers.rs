use crate::enums::{EOSType, EResult};
use crate::proto::steammessages_auth_steamclient::{
    CAuthentication_DeviceDetails,
    EAuthTokenPlatformType,
};
use crate::serializers::from_number_or_string;
use reqwest::Client;
use reqwest::header::HeaderMap;
use serde::Deserialize;

#[derive(Debug, Clone)]
pub struct EncryptedPassword {
    pub encrypted_password: String,
    pub key_timestamp: u64,
}

#[derive(Debug)]
pub struct AuthenticationClientConstructorOptions<T> {
    pub platform_type: EAuthTokenPlatformType,
    pub transport: T,
    pub client: Client,
    pub user_agent: &'static str,
    pub machine_id: Option<Vec<u8>>,
}

#[derive(Debug, Clone)]
pub struct DeviceDetails {
    pub device_friendly_name: String,
    pub platform_type: EAuthTokenPlatformType,
    pub os_type: Option<EOSType>,
    pub gaming_device_type: Option<u32>,
}

impl Into<CAuthentication_DeviceDetails> for DeviceDetails {
    fn into(self) -> CAuthentication_DeviceDetails {
        let mut msg = CAuthentication_DeviceDetails::new();
        
        msg.set_device_friendly_name(self.device_friendly_name);
        msg.set_platform_type(self.platform_type);
        
        if let Some(os_type) = self.os_type {
            msg.set_os_type(os_type as i32);
        }
        
        if let Some(gaming_device_type) = self.gaming_device_type {
            msg.set_gaming_device_type(gaming_device_type);
        }
        
        msg
    }
}

#[derive(Debug, Clone)]
pub struct PlatformData {
    pub website_id: &'static str,
    pub headers: HeaderMap,
    pub device_details: DeviceDetails,
}

#[derive(Debug, Clone, Deserialize)]
pub struct CheckMachineAuthResponse {
    #[serde(default)]
    pub success: bool,
    #[serde(deserialize_with = "from_number_or_string")]
    pub result: EResult,
}