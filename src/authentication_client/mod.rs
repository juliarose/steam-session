mod error;

pub use error::Error;

use crate::enums::EOSType;
use crate::helpers::{decode_jwt, get_machine_id, encode_base64};
use crate::api_method::ApiRequest;
use crate::transports::websocket::WebSocketCMTransport;
use crate::interfaces::{
    AuthenticationClientConstructorOptions,
    PlatformData,
    DeviceDetails,
    EncryptedPassword,
};
use crate::request::{
    PollLoginStatusRequest,
    StartAuthSessionWithCredentialsRequest,
    SubmitSteamGuardCodeRequest,
    MobileConfirmationRequest,
};
use steam_session_proto::steammessages_auth_steamclient::{
    EAuthTokenPlatformType,
    ETokenRenewalType,
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
    CAuthentication_PollAuthSessionStatus_Response, EAuthSessionGuardType,
};
use steam_session_proto::custom::CAuthentication_BeginAuthSessionViaCredentials_Request_BinaryGuardData;
use reqwest::header::{HeaderMap, USER_AGENT, HeaderValue, ORIGIN, REFERER, COOKIE};
use serde::Serialize;
use rsa::{RsaPublicKey, Pkcs1v15Encrypt, BigUint};

/// A client for handling authentication requests.
#[derive(Debug)]
pub struct AuthenticationClient {
    transport: WebSocketCMTransport,
    platform_type: EAuthTokenPlatformType,
    user_agent: &'static str,
    machine_id: Option<Vec<u8>>,
}

impl AuthenticationClient {
    /// Creates a new [`AuthenticationClient`]. 
    pub fn new(options: AuthenticationClientConstructorOptions) -> Self {
        Self {
            transport: options.transport,
            platform_type: options.platform_type,
            user_agent: options.user_agent,
            machine_id: options.machine_id,
        }
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
        let _headers = self.get_platform_data()?.headers;
        
        if let Some(rx) = self.transport.send_request(
            msg,
        ).await? {
            let response = rx.await??;
            
            Ok(response)
        } else {
            Err(Error::NoJob)
        }
    }
    
    fn get_platform_data(
        &self,
    ) -> Result<PlatformData, Error> {
        #[derive(Debug, Serialize)]
        // make all keys uppercase aka screaming snake case
        #[serde(rename_all = "SCREAMING_SNAKE_CASE")]
        struct RefererQuery {
            pub in_client: &'static str,
            pub website_id: &'static str,
            pub local_hostname: &'static str,
            pub webapi_base_url: &'static str,
            pub store_base_url: &'static str,
            pub use_popups: &'static str,
            pub dev_mode: &'static str,
            pub language: &'static str,
            pub platform: &'static str,
            pub country: &'static str,
            pub launcher_type: &'static str,
            pub in_login: &'static str,
        }
        
        match self.platform_type {
            EAuthTokenPlatformType::k_EAuthTokenPlatformType_SteamClient => {
                let referer_query = RefererQuery {
                    in_client: "true",
                    website_id: "Client",
                    local_hostname: todo!(),
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
                        device_friendly_name: referer_query.local_hostname,
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
                        device_friendly_name: self.user_agent,
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
                        device_friendly_name: "Galaxy S22",
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
        // todo
    }
    
    /// Encrypts `password` for `account_name`.
    pub async fn encrypt_password(
        &self,
        account_name: String,
        password: String,
    ) -> Result<EncryptedPassword, Error> {
        let rsa_info = self.get_rsa_key(account_name).await?;
        let n = BigUint::parse_bytes(rsa_info.get_publickey_mod().as_bytes(), 16)
            .ok_or_else(|| Error::BadUint(rsa_info.get_publickey_mod().into()))?;
        let e = BigUint::parse_bytes(rsa_info.get_publickey_exp().as_bytes(), 16)
            .ok_or_else(|| Error::BadUint(rsa_info.get_publickey_exp().into()))?;
        let key = RsaPublicKey::new(n, e)?;
        let encrypted_password = key.encrypt(
            &mut rand::thread_rng(),
            Pkcs1v15Encrypt::default(),
            password.as_bytes(),
        )?;
        let key_timestamp = rsa_info.get_timestamp();
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
    
    /// Gets auth session info.
    async fn get_auth_session_info(
        &self,
        client_id: u64,
        access_token: String,
    ) -> Result<CAuthentication_GetAuthSessionInfo_Response, Error> {
        let mut msg = CAuthentication_GetAuthSessionInfo_Request::new();
        
        msg.set_client_id(client_id);

        self.send_request(
            msg,
            Some(access_token),
        ).await
    }
    
    /// Submits mobile confirmation.
    pub async fn submit_mobile_confirmation(
        &self,
        access_token: String,
        details: MobileConfirmationRequest,
    ) -> Result<CAuthentication_UpdateAuthSessionWithMobileConfirmation_Response, Error> {
        let mut msg = CAuthentication_UpdateAuthSessionWithMobileConfirmation_Request::new();
        
        msg.set_version(details.version);
        msg.set_client_id(details.client_id);
        msg.set_steamid(details.steamid);
        msg.set_signature(details.signature);
        msg.set_confirm(details.confirm);
        msg.set_persistence(details.persistence);
        
        self.send_request(
            msg,
            Some(access_token),
        ).await
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
                device_details.set_machine_id(get_machine_id(msg.get_account_name()));
            }
        }

        msg.set_device_details(device_details);

        if let Some(steam_guard_machine_token) = details.steam_guard_machine_token {
            msg.set_guard_data(steam_guard_machine_token);

            // if (typeof details.steamGuardMachineToken == 'string' && isJwtValidForAudience(details.steamGuardMachineToken, 'machine')) {
            //     data.guard_data = Buffer.from(details.steamGuardMachineToken, 'utf8');
            // }
        }

		// return {
		// 	clientId: result.client_id,
		// 	requestId: result.request_id,
		// 	pollInterval: result.interval,
		// 	allowedConfirmations: result.allowed_confirmations.map(c => ({type: c.confirmation_type, message: c.associated_message})),
		// 	steamId: result.steamid,
		// 	weakToken: result.weak_token
		// };
        
        self.send_request(
            msg,
            None,
        ).await
    }
    
    /// Polls the login status.
    pub async fn poll_login_status(
        &self,
        details: PollLoginStatusRequest,
    ) -> Result<CAuthentication_PollAuthSessionStatus_Response, Error> {
        let mut msg = CAuthentication_PollAuthSessionStatus_Request::new();
        
        msg.set_client_id(details.client_id);
        msg.set_request_id(details.request_id);
        
        self.send_request(
            msg,
            None,
        ).await
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

        self.send_request(
            msg,
            None,
        ).await
    }
}