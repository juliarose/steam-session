use crate::enums::{EOSType, EResult};
use crate::proto::steammessages_auth_steamclient::{
    CAuthentication_DeviceDetails,
    EAuthTokenPlatformType,
};
use crate::serializers::from_number_or_string;
use crate::helpers::create_sha1;
use reqwest::Client;
use reqwest::header::HeaderMap;
use serde::Deserialize;
use bytebuffer_new::{ByteBuffer, Endian};

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

impl From<DeviceDetails> for CAuthentication_DeviceDetails {
    fn from(val: DeviceDetails) -> Self {
        let mut msg = CAuthentication_DeviceDetails::new();
        
        msg.set_device_friendly_name(val.device_friendly_name);
        msg.set_platform_type(val.platform_type);
        
        if let Some(os_type) = val.os_type {
            msg.set_os_type(os_type as i32);
        }
        
        if let Some(gaming_device_type) = val.gaming_device_type {
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

/// Generates a machine ID.
pub fn get_machine_id(account_name: &str) -> Vec<u8> {
    fn get_c_string_bytes(input: &str) -> Vec<u8> {
        let mut bytes = input.as_bytes().to_vec();
        
        bytes.push(0);
        bytes
    }
    
    fn create_sha1_str(input: &str) -> String {
        let sha_bytes = create_sha1(input.as_bytes());
        
        bytes_to_hex_string(&sha_bytes)
    }

    fn bytes_to_hex_string(input: &[u8]) -> String {
        use std::fmt::Write;
        
        let mut s = String::with_capacity(2 * input.len());
        
        for byte in input {
            write!(s, "{:02X}", byte).unwrap();
        }
        
        s
    }
    
    let mut buffer = ByteBuffer::new();
    
    buffer.set_endian(Endian::LittleEndian);
    
    buffer.write_i8(0);
    buffer.write_bytes(&get_c_string_bytes("MessageObject"));
    
    buffer.write_i8(1);
    buffer.write_bytes(&get_c_string_bytes("BB3"));
    buffer.write_bytes(&get_c_string_bytes(&create_sha1_str(&format!("SteamUser Hash BB3 {account_name}"))));
    
    buffer.write_i8(1);
    buffer.write_bytes(&get_c_string_bytes("FF2"));
    buffer.write_bytes(&get_c_string_bytes(&create_sha1_str(&format!("SteamUser Hash FF2 {account_name}"))));
    
    buffer.write_i8(1);
    buffer.write_bytes(&get_c_string_bytes("3B3"));
    buffer.write_bytes(&get_c_string_bytes(&create_sha1_str(&format!("SteamUser Hash 3B3 {account_name}"))));
    
    buffer.write_i8(8);
    buffer.write_i8(8);
    buffer.to_bytes()
}