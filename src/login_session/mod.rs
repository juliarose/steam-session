mod error;

pub use error::LoginSessionError;

use crate::interfaces::{
    StartSessionResponseValidAction,
    LoginSessionOptions,
    AuthenticationClientConstructorOptions,
    StartLoginSessionWithCredentialsDetails,
    StartAuthSessionWithCredentialsRequest,
};
use crate::types::DateTime;
use crate::authentication_client::AuthenticationClient;
use crate::helpers::{USER_AGENT, decode_jwt, generate_sessionid};
use crate::transports::WebSocketCMTransport;
use chrono::{Utc, Duration};
use reqwest::Client;
use steam_session_proto::enums::ESessionPersistence;
use steam_session_proto::steammessages_auth_steamclient::{
    EAuthTokenPlatformType,
    EAuthSessionGuardType,
    CAuthentication_BeginAuthSessionViaCredentials_Response,
};
use steamid_ng::SteamID;
use tokio::task::JoinHandle;

const LOGIN_TIMEOUT_SECONDS: i64 = 30;

#[derive(Debug)]
pub struct LoginSession {
    pub login_timeout: Duration,
    account_name: Option<String>,
    access_token: Option<String>,
    refresh_token: Option<String>,
    platform_type: EAuthTokenPlatformType,
    client: Client,
    handler: AuthenticationClient,
    steam_guard_code: Option<String>,
    steam_guard_machine_token: Option<Vec<u8>>,
    start_session_response: Option<CAuthentication_BeginAuthSessionViaCredentials_Response>,
    had_remote_interaction: bool,
    polling_started_time: Option<DateTime>,
    poll_timer: Option<JoinHandle<()>>,
    polling_canceled: bool,
    access_token_set_at: Option<DateTime>,
}

async fn create_handler(
    client: Client,
    platform_type: EAuthTokenPlatformType,
    machine_id: Option<Vec<u8>>,
    user_agent: Option<&'static str>,
) -> Result<AuthenticationClient, LoginSessionError> {
    let transport = WebSocketCMTransport::connect().await?;
    
    Ok(AuthenticationClient::new(AuthenticationClientConstructorOptions {
        platform_type,
        client,
        machine_id,
        transport,
        user_agent: user_agent.unwrap_or(USER_AGENT),
    }))
}

impl LoginSession {
    pub async fn connect(
        platform_type: EAuthTokenPlatformType,
        options: LoginSessionOptions,
    ) -> Result<Self, LoginSessionError> {
        // probably reqwest client
        // let agent:HTTPS.Agent = options.agent || new HTTPS.Agent({keepAlive: true});
		
		// if (options.httpProxy) {
		// 	agent = StdLib.HTTP.getProxyAgent(true, options.httpProxy) as HTTPS.Agent;
		// } else if (options.socksProxy) {
		// 	agent = new SocksProxyAgent(options.socksProxy);
		// }
        
        let client = Client::new();
        let handler = create_handler(
            client.clone(),
            platform_type,
            options.machine_id,
            options.user_agent
        ).await?;
        
        Ok(Self {
            login_timeout: Duration::seconds(LOGIN_TIMEOUT_SECONDS),
            account_name: None,
            refresh_token: None,
            platform_type,
            client,
            handler,
            steam_guard_code: None,
            steam_guard_machine_token: None,
            start_session_response: None,
            had_remote_interaction: false,
            polling_started_time: None,
            poll_timer: None,
            polling_canceled: false,
            access_token: None,
            access_token_set_at: None,
        })
    }
    
    pub async fn start_session_with_credentials(
        details: StartLoginSessionWithCredentialsDetails,
    ) -> Result<Self, LoginSessionError> {        
        let StartLoginSessionWithCredentialsDetails {
            account_name,
            password,
            steam_guard_code,
            steam_guard_machine_token,
            platform_type,
            machine_id,
            user_agent,
            persistence,
        } = details;
        let client = Client::new();
        let mut handler = create_handler(
            client.clone(),
            platform_type,
            machine_id,
            user_agent
        ).await?;
        let encrypted_password = handler.encrypt_password(
            account_name.clone(),
            password.clone(),
        ).await?;
        let start_session_response = handler.start_session_with_credentials(StartAuthSessionWithCredentialsRequest {
            account_name,
            encrypted_password: encrypted_password.encrypted_password,
            encryption_timestamp: encrypted_password.key_timestamp,
            remember_login: true,
            platform_type,
            persistence: persistence.unwrap_or(ESessionPersistence::k_ESessionPersistence_Persistent),
            steam_guard_machine_token: steam_guard_machine_token.clone(),
        }).await?;
        
        Ok(Self {
            login_timeout: Duration::seconds(LOGIN_TIMEOUT_SECONDS),
            account_name: None,
            refresh_token: None,
            platform_type,
            client,
            handler,
            steam_guard_code,
            steam_guard_machine_token,
            start_session_response: Some(start_session_response),
            had_remote_interaction: false,
            polling_started_time: None,
            poll_timer: None,
            polling_canceled: false,
            access_token: None,
            access_token_set_at: None,
        })
    }

    pub fn steamid(&self) -> Option<SteamID> {
        if let Some(start_session_response) = &self.start_session_response {
            return Some(SteamID::from(start_session_response.get_steamid()));
        }

        let token = if let Some(access_token) = &self.access_token {
            // let decodedToken = decodeJwt(this.accessToken);
			// return new SteamID(decodedToken.sub);
            Some(access_token)
        } else if let Some(refresh_token) = &self.refresh_token {
            Some(refresh_token)
        } else {
            None
        };

        if let Some(token) = token {
            // let token = this.accessToken || this.refreshToken;
			// let decodedToken = decodeJwt(token);
			// return new SteamID(decodedToken.sub);
        }

        None
    }

    pub fn get_account_name(&self) -> &Option<String> {
        &self.account_name
    }

    pub fn get_access_token(&self) -> &Option<String> {
        &self.access_token
    }

    pub fn set_access_token(&mut self, access_token: String) -> Result<(), LoginSessionError> {
        if access_token.is_empty() {
            self.access_token = None;
            return Ok(());
        }
        
        let decoded = decode_jwt(&access_token)?;
        
        if decoded.audience.iter().any(|a| a == "derive") {
            return Err(LoginSessionError::ExpectedAccessToken);
        }
        
        if let Some(start_session_response) = &self.start_session_response {
            if start_session_response.get_steamid() != u64::from(decoded.steamid) {
                return Err(LoginSessionError::TokenIsForDifferentAccount);
            }
        }
        
        if let Some(refresh_token) = &self.refresh_token {
            let decoded_refresh_token = decode_jwt(refresh_token)?;
            
            if decoded_refresh_token.steamid != decoded.steamid {
                return Err(LoginSessionError::AccessTokenBelongsToOtherAccount);
            }
        }
        
        self.access_token = Some(access_token);
        self.access_token_set_at = Some(Utc::now());
        
        Ok(())
    }
    
    async fn process_start_session_response(
        &self,
    ) {
        let mut valid_actions: Vec<StartSessionResponseValidAction> = Vec::new();

        if let Some(start_session_response) = &self.start_session_response {
            for allowed_confirmation in start_session_response.get_allowed_confirmations() {
                let confirmation_type = allowed_confirmation.get_confirmation_type();
                
                match confirmation_type {
                    EAuthSessionGuardType::k_EAuthSessionGuardType_None => {

                    },
                    EAuthSessionGuardType::k_EAuthSessionGuardType_EmailCode |
                    EAuthSessionGuardType::k_EAuthSessionGuardType_DeviceCode => {
                        let code_type: String = if confirmation_type == EAuthSessionGuardType::k_EAuthSessionGuardType_EmailCode {
                            "email"
                        } else {
                            "device"
                        }.into();
                        
                    },
                    EAuthSessionGuardType::k_EAuthSessionGuardType_EmailConfirmation |
                    EAuthSessionGuardType::k_EAuthSessionGuardType_DeviceConfirmation => {
                        valid_actions.push(StartSessionResponseValidAction {
                            r#type: confirmation_type,
                            detail: None,
                        })
                    },
                    EAuthSessionGuardType::k_EAuthSessionGuardType_MachineToken => {
                        // Do nothing here since this is handled by _attemptEmailCodeAuth
                    },
                    r#type => {
                        // error unknown guard type
                    },
                }
            }
        }
    }

    async fn attempt_email_code_auth(&self) {
        todo!()
    }

    async fn attempt_totp_code_auth(&mut self) -> bool {
        if let Some(steam_guard_code) = &self.steam_guard_code {
        
        }

        false
    }
    
    /// Once successfully authenticated, you can call this method to get cookies for use on the 
    /// Steam websites. You can also manually set the `refresh_token` and then call this method 
    /// without going through another login attempt if you already have a valid refresh token.
    /// 
    /// Returns an array of strings. Each string contains a cookie, e.g.
    /// `"steamLoginSecure=blahblahblahblah"`.
    async fn get_web_cookies(
        &mut self,
    ) -> Result<(), LoginSessionError> {
        let refresh_token = self.refresh_token.as_ref()
            .ok_or_else(|| LoginSessionError::NoRefreshToken)?;
        let sessionid = generate_sessionid();
        
        // If our platform type is MobileApp or SteamClient, then our access token *is* our 
        // session cookie. The same is likely true for WebBrowser, but we want to mimic official 
        // behavior as closely as possible to avoid any potential future breakage.
        if {
            self.platform_type == EAuthTokenPlatformType::k_EAuthTokenPlatformType_SteamClient ||
            self.platform_type == EAuthTokenPlatformType::k_EAuthTokenPlatformType_MobileApp
        } {
            // Refresh our access token if we either don't have one, or the token we have is 
            // greater than 10 minutes old. Technically we could just decode the JWT and find out 
            // when it expires (or was issued), but let's try to minimize how much we depend on 
            // the access token being a JWT (as Valve may change it at any point).
            if {
                self.access_token.is_none() ||
                self.access_token_set_at
                    .map(|datetime| Utc::now() - datetime > Duration::minutes(10))
                    .unwrap_or(false)
            } {
                self.refresh_access_token().await?;
            }
        }
        
        Ok(())
    }
    
    async fn refresh_access_token(&mut self) -> Result<(), LoginSessionError> {
        let refresh_token = self.refresh_token.as_ref()
            .ok_or_else(|| LoginSessionError::NoRefreshToken)?;
        let access_token = self.handler.generate_access_token_for_app(
            refresh_token.clone(),
            false,
        ).await?;
        
        self.access_token = Some(access_token.get_access_token().to_string());
        
        Ok(())
    }
    
    async fn submit_steam_guard_code(&mut self) -> Result<(), LoginSessionError> {
        self.verify_started(true)?;
        
        if let Some(start_session_response) = &self.start_session_response {
            let needs_email_code = start_session_response.get_allowed_confirmations()
                .iter()
                .any(|allow_confirmation| {
                    allow_confirmation.get_confirmation_type() == EAuthSessionGuardType::k_EAuthSessionGuardType_EmailCode
                });
            let needs_totp_code = start_session_response.allowed_confirmations
                .iter()
                .any(|allow_confirmation| {
                    allow_confirmation.get_confirmation_type()== EAuthSessionGuardType::k_EAuthSessionGuardType_DeviceCode
                });
            
            if !needs_email_code && !needs_totp_code {
                return Err(LoginSessionError::LoginAttemptSteamGuardNotRequired);
            }

            Ok(())
        } else {
            return Err(LoginSessionError::LoginSessionHasNotStarted);
        }
    }
    
    fn total_polling_time(&self) -> chrono::Duration {
        Utc::now() - self.polling_started_time.unwrap_or_else(|| Utc::now())
    }
    
    async fn do_poll(&mut self) {
        if self.polling_canceled {
            return;
        }
        
        if self.polling_started_time.is_none() {
            self.polling_started_time = Some(Utc::now());
        }
        
        let total_polling_time = self.total_polling_time();
        
        if total_polling_time >= self.login_timeout {
            // timeout
        }
    }
    
    /// Cancels polling for an ongoing login attempt. Once canceled, you should no longer interact 
    /// with this [`LoginSession`], and you should create a new one if you want to start a new 
    /// attempt.
    fn cancel_login_attempt(&mut self) {
        self.polling_canceled = true;
    }
    
    fn verify_started(&self, must_have_steamid: bool) -> Result<(), LoginSessionError> {
        if self.start_session_response.is_none() {
            return Err(LoginSessionError::LoginSessionHasNotStarted);
        }
        
        if self.polling_canceled {
            return Err(LoginSessionError::LoginAttemptCancelled);
        }
        
        if must_have_steamid && self.steamid().is_none() {
            return Err(LoginSessionError::LoginCannotUseMethodWithScheme);
        }
        
        Ok(())
    }
}