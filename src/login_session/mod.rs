mod error;

use std::collections::HashMap;

use cookie::Cookie;
pub use error::LoginSessionError;
use futures::StreamExt;
use futures::stream::FuturesOrdered;
use reqwest::header::SET_COOKIE;
use serde::Deserialize;
use serde_json::Value;

use crate::enums::EResult;
use crate::interfaces::{
    LoginSessionOptions,
    AuthenticationClientConstructorOptions, from_number_or_string_option, 
};
use crate::response::{
    StartSessionResponseValidAction,
    StartSessionResponse,
};
use crate::request::{
    StartLoginSessionWithCredentialsDetails,
    StartAuthSessionWithCredentialsRequest,
};
use crate::types::DateTime;
use crate::authentication_client::AuthenticationClient;
use crate::helpers::{USER_AGENT, decode_jwt, generate_sessionid, create_api_headers};
use crate::transports::WebSocketCMTransport;
use chrono::{Utc, Duration};
use reqwest::{Client, RequestBuilder};
use steam_session_proto::enums::ESessionPersistence;
use steam_session_proto::steammessages_auth_steamclient::{
    EAuthTokenPlatformType,
    EAuthSessionGuardType,
    CAuthentication_BeginAuthSessionViaCredentials_Response,
};
use steamid_ng::SteamID;
use tokio::task::JoinHandle;
use url::form_urlencoded;

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
        options: LoginSessionOptions,
    ) -> Result<Self, LoginSessionError> {
        // probably reqwest client
        // let agent:HTTPS.Agent = options.agent || new HTTPS.Agent({keepAlive: true});
		
		// if (options.httpProxy) {
		// 	agent = StdLib.HTTP.getProxyAgent(true, options.httpProxy) as HTTPS.Agent;
		// } else if (options.socksProxy) {
		// 	agent = new SocksProxyAgent(options.socksProxy);
		// }
        
        let platform_type = options.platform_type;
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
        &mut self,
        details: StartLoginSessionWithCredentialsDetails,
    ) -> Result<StartSessionResponse, LoginSessionError> {        
        let StartLoginSessionWithCredentialsDetails {
            account_name,
            password,
            steam_guard_code,
            steam_guard_machine_token,
            platform_type,
            persistence,
            ..
        } = details;
        
        self.steam_guard_code = steam_guard_code;
        
        let encrypted_password = self.handler.encrypt_password(
            account_name.clone(),
            password.clone(),
        ).await?;
        let start_session_response = self.handler.start_session_with_credentials(StartAuthSessionWithCredentialsRequest {
            account_name,
            encrypted_password: encrypted_password.encrypted_password,
            encryption_timestamp: encrypted_password.key_timestamp,
            remember_login: true,
            platform_type,
            persistence: persistence.unwrap_or(ESessionPersistence::k_ESessionPersistence_Persistent),
            steam_guard_machine_token: steam_guard_machine_token.clone(),
        }).await?;
        
        self.start_session_response = Some(start_session_response);
        
        let response = self.process_start_session_response().await?;
        
        Ok(response)
    }
    
    pub fn steamid(&self) -> Option<SteamID> {
        if let Some(start_session_response) = &self.start_session_response {
            return Some(SteamID::from(start_session_response.get_steamid()));
        }
        
        let token = if let Some(access_token) = &self.access_token {
            Some(access_token)
        } else if let Some(refresh_token) = &self.refresh_token {
            Some(refresh_token)
        } else {
            None
        }?;
        let decoded = decode_jwt(token).ok()?;
        
        Some(decoded.steamid)
    }
    
    /// Gets the account name.
    pub fn get_account_name(&self) -> &Option<String> {
        &self.account_name
    }
    
    /// Gets the access token.
    pub fn get_access_token(&self) -> &Option<String> {
        &self.access_token
    }
    
    /// Sets the access token.
    fn set_access_token(&mut self, token: String) -> Result<(), LoginSessionError> {
        if token.is_empty() {
            self.access_token = None;
            return Ok(());
        }
        
        let decoded = decode_jwt(&token)?;
        
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
                return Err(LoginSessionError::TokenBelongsToOtherAccount);
            }
        }
        
        // Everything checks out
        self.access_token = Some(token);
        self.access_token_set_at = Some(Utc::now());
        
        Ok(())
    }
    
    /// Gets the refresh token.
    pub fn get_refresh_token(&self) -> &Option<String> {
        &self.access_token
    }
    
    /// Sets the refresh token.
    fn set_refresh_token(&mut self, token: String) -> Result<(), LoginSessionError> {
        if token.is_empty() {
            self.refresh_token = None;
            return Ok(());
        }
        
        let decoded = decode_jwt(&token)?;
        
        if !decoded.audience.iter().any(|a| a == "derive") {
            return Err(LoginSessionError::ExpectedRefreshToken);
        }
        
        let required_audience = match self.platform_type {
            EAuthTokenPlatformType::k_EAuthTokenPlatformType_SteamClient => "client",
            EAuthTokenPlatformType::k_EAuthTokenPlatformType_MobileApp => "mobile",
            EAuthTokenPlatformType::k_EAuthTokenPlatformType_WebBrowser => "web",
            EAuthTokenPlatformType::k_EAuthTokenPlatformType_Unknown => "unknown",
        };
        
        if !decoded.audience.iter().any(|a| a == required_audience) {
            return Err(LoginSessionError::TokenPlatformDifferent(required_audience.into()));
        }
        
        if let Some(start_session_response) = &self.start_session_response {
            if start_session_response.get_steamid() != u64::from(decoded.steamid) {
                return Err(LoginSessionError::TokenIsForDifferentAccount);
            }
        }
        
        if let Some(access_token) = &self.access_token {
            let decoded_access_token = decode_jwt(access_token)?;
            
            if decoded_access_token.steamid != decoded.steamid {
                return Err(LoginSessionError::TokenBelongsToOtherAccount);
            }
        }
        
        // Everything checks out
        self.refresh_token = Some(token);
        
        Ok(())
    }
    
    /// Process the start session response.
    async fn process_start_session_response(
        &mut self,
    ) -> Result<StartSessionResponse, LoginSessionError> {
        let mut valid_actions: Vec<StartSessionResponseValidAction> = Vec::new();
        let allowed_confirmations = {
            let start_session_response = self.start_session_response.as_ref()
                .ok_or(LoginSessionError::LoginSessionHasNotStarted)?;
            
            // cloning required to avoid borrowing over mutable borrow
            start_session_response.get_allowed_confirmations().clone().to_vec()
        };
        
        for allow_confirmation in allowed_confirmations {
            let confirmation_type = allow_confirmation.get_confirmation_type();
            
            match confirmation_type {
                EAuthSessionGuardType::k_EAuthSessionGuardType_None => {
                    return Ok(StartSessionResponse {
                        action_required: false,
                        valid_actions: Vec::new(),
                        qr_challenge_url: None,
                    });
                },
                EAuthSessionGuardType::k_EAuthSessionGuardType_EmailCode |
                EAuthSessionGuardType::k_EAuthSessionGuardType_DeviceCode => {
                    let is_authed = if confirmation_type == EAuthSessionGuardType::k_EAuthSessionGuardType_EmailCode {
                        self.attempt_email_code_auth().await?
                    } else {
                        self.attempt_totp_code_auth().await?
                    };
                    
                    if is_authed {
                        // We successfully authed already, no action needed
                        return Ok(StartSessionResponse {
                            action_required: false,
                            valid_actions: Vec::new(),
                            qr_challenge_url: None,
                        });
                    } else {
                        // We need a code from the user
                        valid_actions.push(StartSessionResponseValidAction {
                            r#type: confirmation_type,
                            detail: Some(allow_confirmation.get_associated_message().into()),
                        });
                    }
                },
                EAuthSessionGuardType::k_EAuthSessionGuardType_EmailConfirmation |
                EAuthSessionGuardType::k_EAuthSessionGuardType_DeviceConfirmation => {
                    valid_actions.push(StartSessionResponseValidAction {
                        r#type: confirmation_type,
                        detail: None,
                    });
                    // todo perform a poll
                },
                EAuthSessionGuardType::k_EAuthSessionGuardType_MachineToken => {
                    // Do nothing here since this is handled by _attemptEmailCodeAuth
                },
                r#type => {
                    // error unknown guard type
                    return Err(LoginSessionError::UnknownGuardType(confirmation_type));
                },
            }
        }
        
        Ok(StartSessionResponse {
            action_required: true,
            valid_actions,
            qr_challenge_url: None,
        })
    }
    
    pub async fn attempt_steam_guard_code(&mut self) -> Result<bool, LoginSessionError> {
        if let Some(steam_guard_code) = &self.steam_guard_code {
            match self.submit_steam_guard_code(steam_guard_code.clone()).await {
                Ok(_) => {
                    return Ok(true);
                },
                Err(LoginSessionError::WebSocketCM(crate::transports::websocket::Error::EResultNotOK(EResult::TwoFactorCodeMismatch))) => {
                    // nothing
                },
                Err(error) => {
                    return Err(error);
                },
            }
        }
        
        Ok(false)
    }
    
    async fn attempt_email_code_auth(&mut self) -> Result<bool, LoginSessionError> {
        if self.attempt_steam_guard_code().await? {
            return Ok(true);
        }
        
        let start_session_response = self.start_session_response.as_ref()
            .ok_or(LoginSessionError::LoginSessionHasNotStarted)?;
        let has_machine_token_confirmation = start_session_response.get_allowed_confirmations()
            .iter()
            .any(|allowed_confirmation| allowed_confirmation.get_confirmation_type() == EAuthSessionGuardType::k_EAuthSessionGuardType_MachineToken);
        
        if {
            self.platform_type == EAuthTokenPlatformType::k_EAuthTokenPlatformType_WebBrowser &&
            has_machine_token_confirmation
        } {
            // let result = await this._handler.checkMachineAuthOrSendCodeEmail({
            // 	machineAuthToken: this.steamGuardMachineToken,
            // 	...(this._startSessionResponse as StartAuthSessionWithCredentialsResponse)
            // });
            
            // this.emit('debug', `machine auth check response: ${EResult[result.result]}`);
            
            // if (result.result == EResult.OK) {
            // 	// Machine auth succeeded
            // 	setImmediate(() => this._doPoll());
            // 	return true;
            // }
            
            // todo finish this method
            todo!()
        }
        
        Ok(false)
    }
    
    async fn attempt_totp_code_auth(&mut self) -> Result<bool, LoginSessionError> {
        self.attempt_steam_guard_code().await
    }
    
    /// Submits a Steam Guard code. If a Steam Guard code is needed, you can supply it using this 
    /// method.
    /// 
    /// Note that an incorrect email code will fail with EResult value 
    /// [`EResult::InvalidLoginAuthCode`] (65), and an incorrect TOTP code will fail with EResult 
    /// value [`EResult::TwoFactorCodeMismatch`] (88).
    pub async fn submit_steam_guard_code(
        &mut self,
        auth_code: String,
    ) -> Result<(), LoginSessionError> {
        self.verify_started(true)?;
        
        let start_session_response = self.start_session_response.as_ref()
            .ok_or(LoginSessionError::LoginSessionHasNotStarted)?;
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
        
        let code_type = if needs_email_code {
            EAuthSessionGuardType::k_EAuthSessionGuardType_EmailCode
        } else {
            EAuthSessionGuardType::k_EAuthSessionGuardType_DeviceCode
        };
        let client_id = start_session_response.get_client_id();
        let steamid = start_session_response.get_steamid();
        
        self.handler.submit_steam_guard_code(
            client_id,
            steamid,
            auth_code,
            code_type
        ).await?;
        
        Ok(())
    }
    
    /// Once successfully authenticated, you can call this method to get cookies for use on the 
    /// Steam websites. You can also manually set the `refresh_token` and then call this method 
    /// without going through another login attempt if you already have a valid refresh token.
    /// 
    /// Returns an array of strings. Each string contains a cookie, e.g.
    /// `"steamLoginSecure=blahblahblahblah"`.
    pub async fn get_web_cookies(
        &mut self,
    ) -> Result<Vec<String>, LoginSessionError> {
        #[derive(Debug, Deserialize)]
        struct TransferInfo {
            url: String,
            params: HashMap<String, Value>,
        }
        
        #[derive(Debug, Deserialize)]
        struct Response {
            // #[serde(default)]
            // success: bool,
            #[serde(default)]
            #[serde(deserialize_with = "from_number_or_string_option")]
            result: Option<EResult>,
            #[serde(default)]
            transfer_info: Option<Vec<TransferInfo>>,
        }
        
        async fn any_cookie(request: RequestBuilder) -> Option<Vec<String>> {
            let response = request.send().await.ok()?;
            let headers = response.headers();
            let set_cookie = headers.get_all(SET_COOKIE);
            let cookies = set_cookie
                .into_iter()
                .flat_map(|header| {
                    let value = header.to_str().ok()?;
                    let cookie = Cookie::parse(value).ok()?;
                    
                    Some(format!("{}={}", cookie.name(), cookie.value()))
                })
                .collect::<Vec<String>>();
            
            if cookies.is_empty() {
                return None;
            }
            
            if !cookies.iter().any(|cookie| cookie.contains("steamLoginSecure=")) {
                return None;
            }
            
            Some(cookies)
        }
        
        let refresh_token = self.refresh_token.as_ref()
            .ok_or_else(|| LoginSessionError::NoRefreshToken)?;
        let sessionid = generate_sessionid();
        let steamid = self.steamid()
            .ok_or_else(|| LoginSessionError::NoRefreshToken)?;
        
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
            
            let access_token = self.access_token.as_ref()
                .ok_or(LoginSessionError::NoAccessToken)?;
            let steamid = self.steamid()
                .ok_or(LoginSessionError::NoRefreshToken)?;
            let cookie_value = format!("{}||{}", u64::from(steamid), access_token);
            let encoded_cookie_value = form_urlencoded::byte_serialize(cookie_value.as_bytes())
                .collect::<String>();
            
            return Ok(vec![
                format!("steamLoginSecure={}", encoded_cookie_value),
                format!("sessionid={}", sessionid),
            ]);
        }
        
        let headers = create_api_headers()?;
        let form = reqwest::multipart::Form::new()
            .text("nonce", refresh_token.clone())
            .text("sessionid", sessionid.clone())
            .text("redir", "https://steamcommunity.com/login/home/?goto=");
        let response = self.client.post("https://login.steampowered.com/jwt/finalizelogin")
            .headers(headers)
            .multipart(form)
            .send()
            .await?
            .json::<Response>()
            .await?;
        
        if let Some(eresult) = response.result {
            if eresult != EResult::OK {
                return Err(LoginSessionError::EResultNotOK(eresult));
            }
        }
        
        let mut transfers = response.transfer_info
            .ok_or(LoginSessionError::MalformedResponse)?
            .into_iter()
            .map(|transfer_info| {
                let mut form = reqwest::multipart::Form::new()
                    .text("steamID", u64::from(steamid).to_string());
                
                for (key, value) in transfer_info.params {
                    match value {
                        Value::Number(value) => {
                            form = form.text(key, value.to_string());
                        },
                        Value::Bool(value) => {
                            form = form.text(key, value.to_string());
                        },
                        Value::String(value) => {
                            form = form.text(key, value);
                        },
                        _ => {},
                    };
                }
                
                log::debug!("POST {}", transfer_info.url);
                // send a request that will return cookies if it contains cookies
                any_cookie(self.client.post(&transfer_info.url).multipart(form))
            })
            .collect::<FuturesOrdered<_>>();
        
        // todo futures get hung up waiting for other futures to complete
        // we want to stop when the first response containing cookies completes, which is not what 
        // happens here
        while let Some(transfer) = transfers.next().await {
            if let Some(mut cookies) = transfer {
                if !cookies.iter().any(|cookie| cookie.contains("sessionid=")) {
                    cookies.push(format!("sessionid={}", sessionid));
                }
                
                return Ok(cookies);
            }
        }
        
        Err(LoginSessionError::NoCookiesInResponse)
    }
    
    /// Refreshes the access token. As long as a `refresh_token` is set, you can call this method 
    /// to obtain a new access token. 
    async fn refresh_access_token(&mut self) -> Result<(), LoginSessionError> {
        let refresh_token = self.refresh_token.as_ref()
            .ok_or_else(|| LoginSessionError::NoRefreshToken)?;
        let access_token = self.handler.generate_access_token_for_app(
            refresh_token.clone(),
            false,
        ).await?;
        let access_token = access_token.get_access_token().to_string();
        
        self.set_access_token(access_token)?;
        
        Ok(())
    }
    
    /// Does the same thing as `refresh_access_token`, while also attempting to renew your refresh 
    /// token.
    ///
    /// Whether a new refresh token will actually be issued is at the discretion of the Steam 
    /// backend. This method will return true if a new refresh token was issued (which can be 
    /// accessed using the {@link refreshToken} property), or false if no new refresh token was 
    /// issued. Regardless of the return value, the {@link accessToken} property is always 
    /// updated with a fresh access token (unless there was an error).
    async fn renew_refresh_token(&mut self) -> Result<bool, LoginSessionError> {
        let refresh_token = self.refresh_token.as_ref()
            .ok_or_else(|| LoginSessionError::NoRefreshToken)?;
        let response = self.handler.generate_access_token_for_app(refresh_token.clone(), true)
            .await?;
        let access_token = response.get_access_token();
        let refresh_token = response.get_refresh_token();
        
        self.set_access_token(access_token.to_owned())?;
        self.set_refresh_token(refresh_token.to_owned())?;
        
        return Ok(!access_token.is_empty());
    }
    
    fn total_polling_time(&self) -> chrono::Duration {
        Utc::now() - self.polling_started_time.unwrap_or_else(|| Utc::now())
    }
    
    pub async fn do_poll(&mut self) -> Result<(), LoginSessionError> {
        if self.polling_canceled {
            return Ok(());
        }
        
        if self.polling_started_time.is_none() {
            self.polling_started_time = Some(Utc::now());
        }
        
        let total_polling_time = self.total_polling_time();
        
        if total_polling_time >= self.login_timeout {
            // timeout
            self.cancel_login_attempt();
			return Ok(());
        }
        
        let (clientid, request_id, poll_interval) = {
            let start_session_response = self.start_session_response.as_ref()
                .ok_or(LoginSessionError::LoginSessionHasNotStarted)?;
            let clientid = start_session_response.get_client_id();
            let request_id = start_session_response.get_request_id();
            let poll_interval = start_session_response.get_interval();
            
            (clientid, request_id, poll_interval)
        };
        
        match self.handler.poll_login_status(
            clientid,
            request_id.into(),
        ).await {
            Ok(response) => {
                if !response.get_refresh_token().is_empty() {
                    let client_id = response.get_new_client_id();
                    
                    if let Some(start_session_response) = self.start_session_response.as_mut() {
                        start_session_response.set_client_id(client_id);
                    }
                    
                    self.access_token = Some(response.get_access_token().to_owned());
                    self.set_access_token(response.get_access_token().to_owned())?;
                    self.set_refresh_token(response.get_refresh_token().to_owned())?;
                    
                    // On 2023-09-12, Steam stopped issuing access tokens alongside refresh tokens 
                    // for newly authenticated sessions. This won't affect any consumer apps that 
                    // use `getWebCookies()`, since that will acquire an access token if needed.
                    // On 2023-09-22, I noticed that Steam started issuing access tokens again.
                    
                    // Consumers using SteamClient or WebBrowser never had a reason to consume the 
                    // accessToken property directly, since that was only useful as a cookie and 
                    // `getWebCookies()` should be used instead. However, the access token is also 
                    // used as a WebAPI key for MobileApp, so we should probably ensure that we 
                    // have one for that platform.
                    
                    if self.refresh_token.is_none() && self.platform_type == EAuthTokenPlatformType::k_EAuthTokenPlatformType_MobileApp {
                        self.refresh_access_token().await?;
                    }
                    
                    self.cancel_login_attempt();
                } else if !self.polling_canceled {
                    tokio::spawn(async move {
                        // poll again
                        async_std::task::sleep(std::time::Duration::from_secs(poll_interval as u64)).await;
                    });
                }
            },
            Err(error) => {
                if !self.polling_canceled {
                    log::warn!("Error polling: {}", error);
                    self.cancel_login_attempt();
                }
                
                return Ok(());
            },
        }
        
        Ok(())
    }
    
    /// Cancels polling for an ongoing login attempt. Once canceled, you should no longer interact 
    /// with this [`LoginSession`], and you should create a new one if you want to start a new 
    /// attempt.
    fn cancel_login_attempt(&mut self) {
        self.polling_canceled = true;
        // todo
		// this._pollingCanceled = true;
		// this._handler.close();
		
		// if (this._pollTimer) {
		// 	clearTimeout(this._pollTimer);
		// 	return true;
		// }
		
		// return false;
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