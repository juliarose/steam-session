mod error;
mod helpers;

pub use error::Error;
pub (crate) use helpers::{EncryptedPassword, AuthenticationClientConstructorOptions};

use helpers::{PlatformData, DeviceDetails, CheckMachineAuthResponse};

use crate::enums::{EOSType, EAuthTokenPlatformType, ETokenRenewalType, EAuthSessionGuardType};
use crate::helpers::{decode_jwt, get_machine_id, encode_base64, get_spoofed_hostname, create_api_headers, DecodeError};
use crate::net::ApiRequest;
use crate::transports::Transport;
use crate::request::{StartAuthSessionWithCredentialsRequest, MobileConfirmationRequest};
use crate::proto::steammessages_auth_steamclient::{
    CAuthentication_DeviceDetails,
    CAuthentication_UpdateAuthSessionWithSteamGuardCode_Request,
    CAuthentication_UpdateAuthSessionWithSteamGuardCode_Response,
    CAuthentication_UpdateAuthSessionWithMobileConfirmation_Request,
    CAuthentication_UpdateAuthSessionWithMobileConfirmation_Response,
    CAuthentication_GetPasswordRSAPublicKey_Request,
    CAuthentication_GetPasswordRSAPublicKey_Response,
    CAuthentication_AccessToken_GenerateForApp_Request,
    CAuthentication_AccessToken_GenerateForApp_Response,
    CAuthentication_GetAuthSessionInfo_Request,
    CAuthentication_GetAuthSessionInfo_Response,
    CAuthentication_BeginAuthSessionViaCredentials_Response,
    CAuthentication_PollAuthSessionStatus_Request,
    CAuthentication_PollAuthSessionStatus_Response,
};
use crate::proto::custom::CAuthentication_BeginAuthSessionViaCredentials_Request_BinaryGuardData;
use reqwest::Client;
use steamid_ng::SteamID;
use reqwest::header::{HeaderMap, HeaderValue, USER_AGENT, ORIGIN, REFERER, COOKIE, CONTENT_TYPE};
use serde::Serialize;
use rsa::{RsaPublicKey, Pkcs1v15Encrypt, BigUint};

/// A client for handling authentication requests.
#[derive(Debug)]
pub struct AuthenticationClient<T> {
    transport: T,
    platform_type: EAuthTokenPlatformType,
    client: Client,
    user_agent: &'static str,
    machine_id: Option<Vec<u8>>,
}

impl<T> AuthenticationClient<T>
where
    T: Transport,
{
    /// Creates a new [`AuthenticationClient`]. 
    pub fn new(
        options: AuthenticationClientConstructorOptions<T>,
    ) -> Self {
        Self {
            transport: options.transport,
            platform_type: options.platform_type,
            client: options.client,
            user_agent: options.user_agent,
            machine_id: options.machine_id,
        }
    }
    
    /// Encrypts `password` for `account_name`.
    pub async fn encrypt_password(
        &self,
        account_name: String,
        password: String,
    ) -> Result<EncryptedPassword, Error> {
        let rsa_info = self.get_rsa_key(account_name).await?;
        let n = BigUint::parse_bytes(rsa_info.publickey_mod().as_bytes(), 16)
            .ok_or_else(|| Error::BadUint(rsa_info.publickey_mod().into()))?;
        let e = BigUint::parse_bytes(rsa_info.publickey_exp().as_bytes(), 16)
            .ok_or_else(|| Error::BadUint(rsa_info.publickey_exp().into()))?;
        let key = RsaPublicKey::new(n, e)?;
        let encrypted_password = key.encrypt(
            &mut rand::thread_rng(),
            Pkcs1v15Encrypt::default(),
            password.as_bytes(),
        )?;
        let key_timestamp = rsa_info.timestamp();
        let encrypted_password = encode_base64(encrypted_password);
        
        Ok(EncryptedPassword {
            encrypted_password,
            key_timestamp,
        })
    }
    
    /// Gets RSA public key for `account_name`.
    pub async fn get_rsa_key(
        &self,
        account_name: String,
    ) -> Result<CAuthentication_GetPasswordRSAPublicKey_Response, Error> {
        let mut msg = CAuthentication_GetPasswordRSAPublicKey_Request::new();
        
        msg.set_account_name(account_name);
        
        self.send_request(
            msg,
            None,
        ).await
    }
    
    /// Starts session with credentials.
    pub async fn start_session_with_credentials(
        &self,
        details: StartAuthSessionWithCredentialsRequest,
    ) -> Result<CAuthentication_BeginAuthSessionViaCredentials_Response, Error> {
        let mut msg: CAuthentication_BeginAuthSessionViaCredentials_Request_BinaryGuardData = CAuthentication_BeginAuthSessionViaCredentials_Request_BinaryGuardData::new();
        let platform_data = self.get_platform_data()?;
        let mut device_details: CAuthentication_DeviceDetails = platform_data.device_details.into();
        
        msg.set_account_name(details.account_name);
        msg.set_encrypted_password(details.encrypted_password);
        msg.set_encryption_timestamp(details.encryption_timestamp);
        msg.set_remember_login(details.remember_login);
        msg.set_persistence(details.persistence);
        msg.set_website_id(platform_data.website_id.into());
        
        if details.platform_type == EAuthTokenPlatformType::k_EAuthTokenPlatformType_SteamClient {
            if let Some(machine_id) = &self.machine_id {
                device_details.set_machine_id(machine_id.clone());
            } else {
                device_details.set_machine_id(get_machine_id(msg.account_name()));
            }
        }
        
        msg.device_details = Some(device_details).into();
        
        if let Some(steam_guard_machine_token) = details.steam_guard_machine_token {
            msg.set_guard_data(steam_guard_machine_token);
        }
		
        self.send_request(msg, None).await
    }
    
    /// Submits steam guard code.
    pub async fn submit_steam_guard_code(
        &self,
        client_id: u64,
        steamid: u64,
        code: String,
        code_type: EAuthSessionGuardType,
    ) -> Result<CAuthentication_UpdateAuthSessionWithSteamGuardCode_Response, Error> {
        let mut msg = CAuthentication_UpdateAuthSessionWithSteamGuardCode_Request::new();
        
        msg.set_client_id(client_id);
        msg.set_steamid(steamid);
        msg.set_code(code);
        msg.set_code_type(code_type);
        
        self.send_request(msg, None).await
    }
    
    /// Checks machine auth or sends email code.
    pub async fn check_machine_auth_or_send_code_email(
        &self,
        client_id: u64,
        steamid: SteamID,
        steam_guard_machine_auth_token: Option<&[u8]>,
    ) -> Result<CheckMachineAuthResponse, Error> {
        let mut headers = create_api_headers()?;
        
        headers.append(CONTENT_TYPE, HeaderValue::from_str("multipart/form-data")?);
        
        if let Some(steam_guard_machine_auth_token) = steam_guard_machine_auth_token {
            let steam_guard_machine_auth_token = std::str::from_utf8(steam_guard_machine_auth_token)
                .map_err(|error| Error::Decode(DecodeError::UTF8(error)))?;
            let cookie = format!("steamMachineAuth{}={steam_guard_machine_auth_token}", u64::from(steamid));
            
            headers.append(COOKIE, HeaderValue::from_str(&cookie)?);
        }
        
        let form = reqwest::multipart::Form::new()
            .text("clientid", client_id.to_string())
            .text("steamid", u64::from(steamid).to_string());
        let response = self.client.post("https://login.steampowered.com/jwt/checkdevice")
            .headers(headers)
            .multipart(form)
            .send()
            .await?
            .json::<CheckMachineAuthResponse>()
            .await?;
        
        Ok(response)
    }
    
    /// Polls the login status.
    pub async fn poll_login_status(
        &self,
        client_id: u64,
        request_id: Vec<u8>,
    ) -> Result<CAuthentication_PollAuthSessionStatus_Response, Error> {
        let mut msg = CAuthentication_PollAuthSessionStatus_Request::new();
        
        msg.set_client_id(client_id);
        msg.set_request_id(request_id);
        
        self.send_request(msg, None).await
    }
    
    /// Gets auth session info.
    pub async fn get_auth_session_info(
        &self,
        client_id: u64,
        access_token: String,
    ) -> Result<CAuthentication_GetAuthSessionInfo_Response, Error> {
        let mut msg = CAuthentication_GetAuthSessionInfo_Request::new();
        
        msg.set_client_id(client_id);
        
        self.send_request(msg, Some(access_token)).await
    }
    
    /// Submits mobile confirmation.
    pub async fn submit_mobile_confirmation(
        &self,
        access_token: String,
        details: MobileConfirmationRequest,
    ) -> Result<CAuthentication_UpdateAuthSessionWithMobileConfirmation_Response, Error> {
        let mut msg = CAuthentication_UpdateAuthSessionWithMobileConfirmation_Request::new();
        
        msg.set_version(details.version as i32);
        msg.set_client_id(details.client_id);
        msg.set_steamid(details.steamid);
        msg.set_signature(details.signature);
        msg.set_confirm(details.confirm);
        msg.set_persistence(details.persistence);
        
        self.send_request(msg, Some(access_token)).await
    }
    
    /// Generates access token for app.
    pub async fn generate_access_token_for_app(
        &self,
        refresh_token: String,
        renew_refresh: bool,
    ) -> Result<CAuthentication_AccessToken_GenerateForApp_Response, Error> {
        let decoded = decode_jwt(&refresh_token)?;
        let mut msg = CAuthentication_AccessToken_GenerateForApp_Request::new();
        let renewal_type = if renew_refresh {
            ETokenRenewalType::k_ETokenRenewalType_Allow
        } else {
            ETokenRenewalType::k_ETokenRenewalType_None
        };
        
        msg.set_refresh_token(refresh_token);
        msg.set_steamid(u64::from(decoded.steamid));
        msg.set_renewal_type(renewal_type);
        
        self.send_request(msg, None).await
    }
    
    /// Sends a request.
    async fn send_request<Msg>(
        &self,
        msg: Msg,
        access_token: Option<String>,
    ) -> Result<Msg::Response, Error>
    where
        Msg: ApiRequest,
        <Msg as ApiRequest>::Response: Send,
    {
        let response = self.transport.send_request(
            msg,
            access_token,
        ).await?.await??;
        
        Ok(response)
    }
    
    fn get_platform_data(
        &self,
    ) -> Result<PlatformData, Error> {
        #[derive(Debug, Serialize)]
        // make all keys uppercase aka screaming snake case
        #[serde(rename_all = "SCREAMING_SNAKE_CASE")]
        struct RefererQuery<'a> {
            pub in_client: &'a str,
            pub website_id: &'a str,
            pub local_hostname: &'a str,
            pub webapi_base_url: &'a str,
            pub store_base_url: &'a str,
            pub use_popups: &'a str,
            pub dev_mode: &'a str,
            pub language: &'a str,
            pub platform: &'a str,
            pub country: &'a str,
            pub launcher_type: &'a str,
            pub in_login: &'a str,
        }
        
        match self.platform_type {
            EAuthTokenPlatformType::k_EAuthTokenPlatformType_SteamClient => {
                let local_hostname = get_spoofed_hostname();
                let referer_query = RefererQuery {
                    in_client: "true",
                    website_id: "Client",
                    local_hostname: &local_hostname,
                    webapi_base_url: "https://api.steampowered.com/",
                    store_base_url: "https://store.steampowered.com/",
                    use_popups: "true",
                    dev_mode: "false",
                    language: "english",
                    platform: "windows",
                    country: "US",
                    launcher_type: "0",
                    in_login: "true"
                };
                let referer_qs = serde_qs::to_string(&referer_query)?;
                let mut headers = HeaderMap::new();
                
                headers.append(USER_AGENT, HeaderValue::from_str("Mozilla/5.0 (Windows; U; Windows NT 10.0; en-US; Valve Steam Client/default/1665786434; ) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/85.0.4183.121 Safari/537.36")?);
                headers.append(ORIGIN, HeaderValue::from_str("https://steamloopback.host")?);
                headers.append(REFERER, HeaderValue::from_str(&format!("https://steamloopback.host/index.html?{}", &referer_qs))?);
                
                Ok(PlatformData {
                    website_id: "Unknown",
                    // Headers are actually not used since this is sent over a CM connection
                    headers,
                    device_details: DeviceDetails {
                        device_friendly_name: local_hostname,
                        platform_type: self.platform_type,
                        os_type: Some(EOSType::Win11),
                        gaming_device_type: Some(1),
                    },
                })
            },
            EAuthTokenPlatformType::k_EAuthTokenPlatformType_WebBrowser => {
                let mut headers = HeaderMap::new();
                
                headers.append(USER_AGENT, HeaderValue::from_str(self.user_agent)?);
                headers.append(ORIGIN, HeaderValue::from_str("https://steamcommunity.com")?);
                headers.append(REFERER, HeaderValue::from_str("https://steamcommunity.com")?);
                
                Ok(PlatformData {
                    website_id: "Community",
                    // Headers are actually not used since this is sent over a CM connection
                    headers,
                    device_details: DeviceDetails {
                        device_friendly_name: self.user_agent.to_string(),
                        platform_type: self.platform_type,
                        os_type: None,
                        gaming_device_type: None,
                    },
                })
            },
            EAuthTokenPlatformType::k_EAuthTokenPlatformType_MobileApp => {
                let mut headers = HeaderMap::new();
                
                headers.append(USER_AGENT, HeaderValue::from_str("okhttp/3.12.12")?);
                headers.append(COOKIE, HeaderValue::from_str("mobileClient=android; mobileClientVersion=777777 3.0.0")?);
                
                Ok(PlatformData {
                    website_id: "Mobile",
                    // Headers are actually not used since this is sent over a CM connection
                    headers,
                    device_details: DeviceDetails {
                        device_friendly_name: String::from("Galaxy S22"),
                        platform_type: self.platform_type,
                        os_type: Some(EOSType::AndroidUnknown),
                        gaming_device_type: Some(528),
                    },
                })
            },
            platform_type => {
                Err(Error::UnsupportedPlatformType(platform_type))
            },
        }
    }
}