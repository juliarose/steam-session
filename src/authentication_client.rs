use crate::enums::EOSType;
use crate::helpers::{decode_jwt, get_machine_id};
use crate::interfaces::{
    AuthenticationClientConstructorOptions,
    SubmitSteamGuardCodeRequest,
    MobileConfirmationRequest,
    PlatformData,
    DeviceDetails, StartAuthSessionWithCredentialsRequest,
};
use steam_session_proto::steammessages_auth_steamclient::{EAuthTokenPlatformType, CAuthentication_DeviceDetails, CAuthentication_UpdateAuthSessionWithSteamGuardCode_Request, CAuthentication_UpdateAuthSessionWithMobileConfirmation_Request, CAuthentication_GetAuthSessionInfo_Request, CAuthentication_GetPasswordRSAPublicKey_Request};
use crate::api_method::ApiRequest;
use reqwest::Client;
use reqwest::header::{HeaderMap, USER_AGENT, InvalidHeaderValue, HeaderValue, ORIGIN, REFERER, COOKIE};
use serde::Serialize;
use steam_session_proto::custom::CAuthentication_BeginAuthSessionViaCredentials_Request_BinaryGuardData;
use steam_session_proto::steammessages_auth_steamclient::{CAuthentication_AccessToken_GenerateForApp_Request, ETokenRenewalType};
use tokio::task::JoinHandle;
use crate::transports::WebSocketCMTransport;
use crate::transports::websocket::Error as WebSocketCmError;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("Unsupported platform type: {:?}", .0)]
    UnsupportedPlatformType(EAuthTokenPlatformType),
    #[error("{}", .0)]
    InvalidHeaderValue(#[from] InvalidHeaderValue),
    #[error("serde_qs error: {}", .0)]
    SerdeQS(#[from] serde_qs::Error),
    #[error("websocket error: {}", .0)]
    Websocket(#[from] WebSocketCmError),
    #[error("Decode error: {}", .0)]
    Decode(#[from] crate::helpers::DecodeError),
}

#[derive(Debug, Clone)]
pub struct RequestDefinition {
    api_interface: String,
    api_method: String,
    api_version: u32,
    data: Vec<u8>,
    access_token: Option<String>,
}

#[derive(Debug)]
pub struct AuthenticationClient {
    transport: WebSocketCMTransport,
    platform_type: EAuthTokenPlatformType,
    client: Client,
    transport_close_timeout: Option<JoinHandle<()>>,
    user_agent: &'static str,
    machine_id: Option<Vec<u8>>,
}

impl AuthenticationClient {
    pub fn new(options: AuthenticationClientConstructorOptions) -> Self {
        Self {
            transport: options.transport,
            platform_type: options.platform_type,
            client: options.client,
            transport_close_timeout: None,
            user_agent: options.user_agent,
            machine_id: options.machine_id,
        }
    }
    
    async fn get_rsa_key(
        &mut self,
        account_name: String,
    ) -> Result<(), Error> {
        let mut msg = CAuthentication_GetPasswordRSAPublicKey_Request::new();

        msg.set_account_name(account_name);

        let response = self.send_request(msg, None).await?;

        todo!()
    }
    
    async fn send_request<Msg>(
        &mut self,
        msg: Msg,
        access_token: Option<String>,
    ) -> Result<(), Error>
    where
        Msg: ApiRequest,
        <Msg as ApiRequest>::Response: Send,
    {
        let _headers = self.get_platform_data()?.headers;
        let result = self.transport.send_request(
            msg,
        ).await?;
        
        Ok(())
    }
    
    fn close(&mut self) {
        if let Some(handle) = &self.transport_close_timeout {
            handle.abort();
        }
        
        self.transport_close_timeout = Some(tokio::task::spawn(async move {
            // transport.close();
        }));
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
    
    async fn encrypt_password(
        &mut self,
        account_name: String,
        password: String,
    ) -> Result<EncryptedPassword, Error> {
        let rsa_info = self.get_rsa_key(account_name).await?;
		// todo
        // let key = new RSAKey();
		// key.setPublic(rsaInfo.publickey_mod, rsaInfo.publickey_exp);
		
		// return {
		// 	encryptedPassword: hex2b64(key.encrypt(password)),
		// 	keyTimestamp: rsaInfo.timestamp
		// };
        Ok(EncryptedPassword {
            password: String::new(),
            key_timestamp: String::new(),
        })
    }

    async fn get_auth_session_info(
        &mut self,
        access_token: String,
        client_id: u64,
    ) -> Result<(), Error> {
        let mut msg = CAuthentication_GetAuthSessionInfo_Request::new();
        
        msg.set_client_id(client_id);

        let response = self.send_request(msg, Some(access_token)).await?;

        // todo
        Ok(())
    }

    async fn submit_mobile_confirmation(
        &mut self,
        access_token: String,
        details: MobileConfirmationRequest,
    ) -> Result<(), Error> {
        let mut msg = CAuthentication_UpdateAuthSessionWithMobileConfirmation_Request::new();

        msg.set_version(details.version);
        msg.set_client_id(details.client_id);
        msg.set_steamid(details.steamid);
        msg.set_signature(details.signature);
        msg.set_confirm(details.confirm);
        msg.set_persistence(details.persistence);

        let response = self.send_request(msg, Some(access_token)).await?;
        
        // todo
        Ok(())
    }

    async fn generate_access_token_for_app(
        &mut self,
        refresh_token: String,
        renew_refresh: bool,
    ) -> Result<(), Error> {
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

        let response = self.transport.send_request(msg).await?;

        // todo
        Ok(())
    }

    async fn start_session_with_credentials(
        &mut self,
        details: StartAuthSessionWithCredentialsRequest,
    ) -> Result<(), Error> {
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

        let response = self.send_request(msg, None).await?;

		// return {
		// 	clientId: result.client_id,
		// 	requestId: result.request_id,
		// 	pollInterval: result.interval,
		// 	allowedConfirmations: result.allowed_confirmations.map(c => ({type: c.confirmation_type, message: c.associated_message})),
		// 	steamId: result.steamid,
		// 	weakToken: result.weak_token
		// };

        Ok(())
    }

    async fn submit_steam_guard_code(
        &mut self,
        details: SubmitSteamGuardCodeRequest,
    ) -> Result<(), Error> {
        let mut msg = CAuthentication_UpdateAuthSessionWithSteamGuardCode_Request::new();
        
        msg.set_client_id(details.client_id);
        msg.set_steamid(details.steamid);
        msg.set_code(details.code);
        msg.set_code_type(details.code_type);

        let response = self.send_request(msg, None).await?;

        Ok(())
    }
}


#[derive(Debug, Clone)]
pub struct EncryptedPassword {
    password: String,
    key_timestamp: String,
}
