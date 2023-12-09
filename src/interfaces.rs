use crate::enums::{EResult, AuthSessionSecurityHistory, EOSType};
use crate::transports::WebSocketCMTransport;
use std::net::IpAddr;
use steam_session_proto::enums::ESessionPersistence;
use steam_session_proto::steammessages_auth_steamclient::{CAuthentication_DeviceDetails, EAuthTokenPlatformType, EAuthSessionGuardType};
use url::Url;
use reqwest::Client;
use reqwest::header::HeaderMap;

/// The type of connection to be used.
#[derive(Debug, Clone)]
pub enum ConnectionType {
    /// Connect using a local address.
    LocalAddress(IpAddr),
    /// Connect using an HTTP proxy.
    HttpProxy(Url),
    /// Connect using a SOCKS proxy.
    SocksProxy(Url),
    /// Connect using a custom [`Client`].
    Agent(Client),
}

#[derive(Debug, Clone)]
pub struct EncryptedPassword {
    pub encrypted_password: String,
    pub key_timestamp: u64,
}

#[derive(Debug, Clone)]
pub struct DeviceDetails {
    pub device_friendly_name: &'static str,
    pub platform_type: EAuthTokenPlatformType,
    pub os_type: Option<EOSType>,
    pub gaming_device_type: Option<u32>,
}

impl Into<CAuthentication_DeviceDetails> for DeviceDetails {
    fn into(self) -> CAuthentication_DeviceDetails {
        let mut msg = CAuthentication_DeviceDetails::new();

        msg.set_device_friendly_name(self.device_friendly_name.into());
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

#[derive(Debug)]
pub struct LoginSessionOptions {
    // todo use transport
    pub transport: Option<u8>,
    pub connnection_type: Option<ConnectionType>,
    pub user_agent: Option<&'static str>,
    pub machine_id: Option<Vec<u8>>,
}

// unused
#[derive(Debug, Clone)]
pub struct StartSessionResponse<'a> {
    pub action_required: bool,
    pub valid_actions: Option<Vec<StartSessionResponseValidAction>>,
    pub qr_challenge_url: Option<&'a str>,
}

#[derive(Debug, Clone)]
pub struct StartSessionResponseValidAction {
    pub r#type: EAuthSessionGuardType,
    pub detail: Option<String>,
}

#[derive(Debug, Clone)]
pub struct PlatformData {
    pub website_id: &'static str,
    pub headers: HeaderMap,
    pub device_details: DeviceDetails,
}

#[derive(Debug)]
pub struct AuthenticationClientConstructorOptions {
    pub platform_type: EAuthTokenPlatformType,
    pub transport: WebSocketCMTransport,
    pub client: Client,
    pub user_agent: &'static str,
    pub machine_id: Option<Vec<u8>>,
}

#[derive(Debug, Clone)]
pub struct CheckMachineAuthResponse {
    pub success: bool,
    pub result: EResult,
}

#[derive(Debug, Clone)]
pub struct PollLoginStatusResponse {
    pub new_client_id: Option<String>,
    pub new_challenge_url: Option<String>,
    pub refresh_token: Option<String>,
    pub access_token: Option<String>,
    pub had_remote_interaction: Option<bool>,
    pub account_name: Option<String>,
    pub new_steam_guard_machine_auth: Option<String>,
}

#[derive(Debug, Clone)]
pub struct GetAuthSessionInfoResponse {
    pub ip: String,
    pub geoloc: String,
    pub city: String,
    pub state: String,
    pub platform_type: EAuthTokenPlatformType,
    pub device_friendly_name: String,
    pub version: u32,
    pub login_history: AuthSessionSecurityHistory,
    pub location_mismatch: bool,
    pub high_usage_login: bool,
    pub requested_persistence: ESessionPersistence,
}