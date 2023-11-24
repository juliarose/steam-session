use crate::enums::{
    EResult,
    AuthTokenPlatformType,
    AuthSessionGuardType,
    AuthSessionSecurityHistory,
    SessionPersistence,
};
use crate::transports::WebSocketCMTransport;
use std::net::IpAddr;
use steamid_ng::SteamID;
use url::Url;
use reqwest::Client;
use reqwest::header::HeaderMap;

type Buffer = Vec<u8>;

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

// todo
#[derive(Debug, Clone)]
pub struct CAuthentication_DeviceDetails {}

#[derive(Debug)]
pub struct LoginSessionOptions {
    // todo use transport
    pub transport: Option<u8>,
    pub connnection_type: Option<ConnectionType>,
    pub user_agent: Option<String>,
    pub machine_id: Option<Vec<u8>>,
}

#[derive(Debug, Clone)]
pub struct AllowedConfirmation {
	pub r#type: AuthSessionGuardType,
	pub message: Option<String>,
}

#[derive(Debug, Clone)]
pub struct StartAuthSessionResponse {
	pub client_id: String,
	pub request_id: Buffer,
	pub poll_interval: u64,
	pub allowed_confirmations: Vec<AllowedConfirmation>,
    pub steamid: Option<SteamID>,
}

#[derive(Debug, Clone)]
pub struct StartLoginSessionWithCredentialsDetails<'a> {
    pub account_name: &'a str,
    pub password: &'a str,
    pub persistence: Option<SessionPersistence>,
    pub steam_guard_machine_token: Option<&'a str>,
    pub steam_guard_code: Option<&'a str>,
}

#[derive(Debug, Clone)]
pub struct StartSessionResponse<'a> {
    pub action_required: bool,
    pub valid_actions: Option<Vec<StartSessionResponseValidAction>>,
    pub qr_challenge_url: Option<&'a str>,
}

pub struct SubmitSteamGuardCodeRequest {
	pub client_id: String,
	pub steamid_id: String,
	pub auth_code: String,
	pub auth_code_type: AuthSessionGuardType,
}

#[derive(Debug, Clone)]
pub struct StartSessionResponseValidAction {
    pub r#type: AuthSessionGuardType,
    pub detail: Option<String>,
}

#[derive(Debug, Clone)]
pub struct AuthSessionInfo<'a> {
    pub ip: &'a str,
    pub location: Location<'a>,
    pub platform_type: AuthTokenPlatformType,
    pub device_friendly_name: &'a str,
    pub version: u32,
    pub login_history: AuthSessionSecurityHistory,
    pub location_mismatch: bool,
    pub high_usage_login: bool,
    pub requested_persistence: SessionPersistence,
}

#[derive(Debug, Clone)]
pub struct Location<'a> {
    pub geoloc: &'a str,
    pub city: &'a str,
    pub state: &'a str,
}

#[derive(Debug, Clone)]
pub struct ApproveAuthSessionRequest<'a> {
    pub qr_challenge_url: &'a str,
    pub approve: bool,
    pub persistence: Option<SessionPersistence>,
}

#[derive(Debug, Clone)]
pub struct PlatformData {
    pub headers: HeaderMap,
    pub website_id: String,
    pub device_details: CAuthentication_DeviceDetails,
}

#[derive(Debug)]
pub struct AuthenticationClientConstructorOptions {
    pub platform_type: AuthTokenPlatformType,
    pub transport: WebSocketCMTransport,
    pub client: Client,
    pub user_agent: String,
    pub machine_id: Option<Vec<u8>>,
}

#[derive(Debug, Clone)]
pub struct StartAuthSessionRequest {
    pub platform_type: AuthTokenPlatformType,
}

#[derive(Debug, Clone)]
pub struct StartAuthSessionWithCredentialsRequest {
    pub account_name: String,
    pub encrypted_password: String,
    pub key_timestamp: String,
    pub persistence: SessionPersistence,
    pub platform_type: AuthTokenPlatformType,
    pub steam_guard_machine_token: Option<Buffer>,
}

#[derive(Debug, Clone)]
pub struct StartAuthSessionWithCredentialsResponse {
    pub steam_id: String,
    pub weak_token: String,
    pub client_id: String,
    pub request_id: Buffer,
    pub poll_interval: u32,
    pub allowed_confirmations: Vec<AllowedConfirmation>,
}

#[derive(Debug, Clone)]
pub struct StartAuthSessionWithQrResponse {
    pub challenge_url: String,
    pub version: u32,
    pub client_id: String,
    pub request_id: Buffer,
    pub poll_interval: u32,
    pub allowed_confirmations: Vec<AllowedConfirmation>,
}

#[derive(Debug, Clone)]
pub struct CheckMachineAuthRequest {
    pub client_id: String,
    pub steam_id: String,
    pub machine_auth_token: Option<String>,
}

#[derive(Debug, Clone)]
pub struct CheckMachineAuthResponse {
    pub success: bool,
    pub result: EResult,
}

#[derive(Debug, Clone)]
pub struct PollLoginStatusRequest {
    pub client_id: String,
    pub request_id: Buffer,
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
pub struct GetAuthSessionInfoRequest {
    pub client_id: String,
}

#[derive(Debug, Clone)]
pub struct GetAuthSessionInfoResponse {
    pub ip: String,
    pub geoloc: String,
    pub city: String,
    pub state: String,
    pub platform_type: AuthTokenPlatformType,
    pub device_friendly_name: String,
    pub version: u32,
    pub login_history: AuthSessionSecurityHistory,
    pub location_mismatch: bool,
    pub high_usage_login: bool,
    pub requested_persistence: SessionPersistence,
}

#[derive(Debug, Clone)]
pub struct MobileConfirmationRequest {
    pub version: u32,
    pub client_id: String,
    pub steam_id: String,
    pub signature: Buffer,
    pub confirm: bool,
    pub persistence: SessionPersistence,
}
