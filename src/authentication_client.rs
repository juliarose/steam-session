use crate::enums::{AuthTokenPlatformType, EOSType};
use crate::interfaces::{
    AuthenticationClientConstructorOptions,
    SubmitSteamGuardCodeRequest,
    StartAuthSessionRequest,
    MobileConfirmationRequest,
    GetAuthSessionInfoRequest,
    PlatformData,
    DeviceDetails,
};
use crate::api_method::{ApiRequest, ApiResponse};
use reqwest::Client;
use reqwest::header::{HeaderMap, USER_AGENT, InvalidHeaderValue, HeaderValue, ORIGIN, REFERER, COOKIE};
use serde::Serialize;
use tokio::task::JoinHandle;
use crate::transports::WebSocketCMTransport;
use crate::transports::websocket::Error as WebSocketCmError;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("Unsupported platform type: {:?}", .0)]
    UnsupportedPlatformType(AuthTokenPlatformType),
    #[error("{}", .0)]
    InvalidHeaderValue(#[from] InvalidHeaderValue),
    #[error("serde_qs error: {}", .0)]
    SerdeQS(#[from] serde_qs::Error),
    #[error("websocket error: {}", .0)]
    Websocket(#[from] WebSocketCmError),
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
    platform_type: AuthTokenPlatformType,
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
        &self,
        account_name: String,
    ) -> Result<(), Error> {
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
        let headers = self.get_platform_data()?.headers;
        let result = self.transport.send_request(
            msg,
            access_token,
            Some(headers),
            Vec::new(),
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
            AuthTokenPlatformType::SteamClient => {
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
            AuthTokenPlatformType::WebBrowser => {
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
            AuthTokenPlatformType::MobileApp => {
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
        &self,
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
        &self,
        access_token: String,
        details: GetAuthSessionInfoRequest,
    ) -> Result<(), Error> {
        let request = RequestDefinition {
            api_interface: "Authentication".into(),
            api_method: "GetAuthSessionInfo".into(),
            api_version: 1,
            data: Vec::new(),
            access_token: Some(access_token),
        };

        // todo
        Ok(())
    }

    async fn submit_mobile_confirmation(
        &self,
        access_token: String,
        details: MobileConfirmationRequest,
    ) -> Result<(), Error> {
        let request = RequestDefinition {
            api_interface: "Authentication".into(),
            api_method: "UpdateAuthSessionWithMobileConfirmation".into(),
            api_version: 1,
            data: Vec::new(),
            access_token: Some(access_token),
        };

        // todo
        Ok(())
    }

    async fn generate_access_token_for_app(
        &mut self,
        refresh_token: String,
        renew_refresh: bool,
    ) -> Result<(), Error> {
        let request = RequestDefinition {
            api_interface: "Authentication".into(),
            api_method: "GenerateAccessTokenForApp".into(),
            api_version: 1,
            data: Vec::new(),
            access_token: None,
        };

        // todo
        Ok(())
    }

    async fn start_session_with_credentials(
        &self,
        details: StartAuthSessionRequest,
    ) -> Result<(), Error> {
		// let {websiteId, deviceDetails} = this._getPlatformData();

		// let data:CAuthentication_BeginAuthSessionViaCredentials_Request_BinaryGuardData = {
		// 	account_name: details.accountName,
		// 	encrypted_password: details.encryptedPassword,
		// 	encryption_timestamp: details.keyTimestamp,
		// 	remember_login: details.persistence == ESessionPersistence.Persistent,
		// 	persistence: details.persistence,
		// 	website_id: websiteId,
		// 	device_details: deviceDetails
		// };

		// if (details.platformType == EAuthTokenPlatformType.SteamClient) {
		// 	// For SteamClient logins, we also need a machine id
		// 	if (this._machineId && Buffer.isBuffer(this._machineId)) {
		// 		data.device_details.machine_id = this._machineId;
		// 	} else if (this._machineId === true) {
		// 		data.device_details.machine_id = createMachineId(details.accountName);
		// 	}
		// }

		// if (details.steamGuardMachineToken) {
		// 	if (Buffer.isBuffer(details.steamGuardMachineToken)) {
		// 		data.guard_data = details.steamGuardMachineToken;
		// 	} else if (typeof details.steamGuardMachineToken == 'string' && isJwtValidForAudience(details.steamGuardMachineToken, 'machine')) {
		// 		data.guard_data = Buffer.from(details.steamGuardMachineToken, 'utf8');
		// 	}
		// }

		// let result:CAuthentication_BeginAuthSessionViaCredentials_Response = await this.sendRequest({
		// 	apiInterface: 'Authentication',
		// 	apiMethod: 'BeginAuthSessionViaCredentials',
		// 	apiVersion: 1,
		// 	data
		// });

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

    async fn submit_steam_guard_code(&self, details: SubmitSteamGuardCodeRequest) -> Result<(), Error> {
        // let data:CAuthentication_UpdateAuthSessionWithSteamGuardCode_Request = {
		// 	client_id: details.clientId,
		// 	steamid: details.steamId,
		// 	code: details.authCode,
		// 	code_type: details.authCodeType
		// };

		// await this.sendRequest({
		// 	apiInterface: 'Authentication',
		// 	apiMethod: 'UpdateAuthSessionWithSteamGuardCode',
		// 	apiVersion: 1,
		// 	data
		// });

        Ok(())
    }
}


#[derive(Debug, Clone)]
pub struct EncryptedPassword {
    password: String,
    key_timestamp: String,
}
