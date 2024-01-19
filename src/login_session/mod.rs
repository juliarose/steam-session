mod error;
mod builder;
mod helpers;

pub use error::LoginSessionError;
pub use builder::LoginSessionBuilder;

use helpers::LoginSessionOptions;

use crate::enums::EResult;
use crate::response::{StartSessionResponseValidAction, StartSessionResponse};
use crate::request::{
    StartLoginSessionWithCredentialsDetails,
    StartAuthSessionWithCredentialsRequest,
};
use crate::serializers::from_number_or_string_option;
use crate::transports::web_api::WebApiTransport;
use crate::transports::{Transport, WebSocketCMTransport};
use crate::types::DateTime;
use crate::authentication_client::{AuthenticationClient, Error as AuthenticationClientError};
use crate::helpers::{decode_jwt, generate_sessionid, create_api_headers, value_to_multipart};
use crate::enums::{ESessionPersistence, EAuthTokenPlatformType, EAuthSessionGuardType};

use cookie::Cookie;
use futures::StreamExt;
use futures::stream::FuturesOrdered;
use reqwest::header::SET_COOKIE;
use serde::Deserialize;
use serde_json::Value;
use chrono::{Utc, Duration};
use reqwest::{Client, RequestBuilder};
use steam_session_proto::steammessages_auth_steamclient::CAuthentication_BeginAuthSessionViaCredentials_Response;
use steamid_ng::SteamID;
use url::form_urlencoded;

const LOGIN_TIMEOUT_SECONDS: i64 = 30;

#[derive(Debug)]
pub struct LoginSession<T> {
    login_timeout: Duration,
    account_name: Option<String>,
    refresh_token: Option<String>,
    access_token: Option<String>,
    access_token_set_at: Option<DateTime>,
    platform_type: EAuthTokenPlatformType,
    client: Client,
    handler: AuthenticationClient<T>,
    steam_guard_code: Option<String>,
    steam_guard_machine_token: Option<Vec<u8>>,
    start_session_response: Option<CAuthentication_BeginAuthSessionViaCredentials_Response>,
}

pub async fn connect_ws() -> Result<LoginSession<WebSocketCMTransport>, LoginSessionError> {
    let platform_type = EAuthTokenPlatformType::k_EAuthTokenPlatformType_WebBrowser;
    let transport = WebSocketCMTransport::connect().await
        .map_err(AuthenticationClientError::WebSocketCM)?;
    
    LoginSessionBuilder::new(transport, platform_type)
        .build()
}

pub async fn connect_webapi() -> Result<LoginSession<WebApiTransport>, LoginSessionError> {
    let platform_type = EAuthTokenPlatformType::k_EAuthTokenPlatformType_WebBrowser;
    let transport = WebApiTransport::new();
    
    LoginSessionBuilder::new(transport, platform_type)
        .build()
}

impl<T> LoginSession<T>
where
    T: Transport,
{
    /// Creates a new [`LoginSessionBuilder`].
    pub fn builder(
        transport: T,
        platform_type: EAuthTokenPlatformType,
    ) -> LoginSessionBuilder<T> {
        LoginSessionBuilder::new(transport, platform_type)
    }
    
    /// Creates a new [`LoginSession`] to use for authentication.
    fn new(
        options: LoginSessionOptions<T>,
    ) -> Result<Self, LoginSessionError> {
        let platform_type = options.platform_type;
        let client = Client::new();
        let handler = helpers::create_handler(
            options.transport,
            client.clone(),
            platform_type,
            options.machine_id,
            options.user_agent
        )?;
        
        Ok(Self {
            login_timeout: Duration::seconds(LOGIN_TIMEOUT_SECONDS),
            account_name: None,
            refresh_token: None,
            access_token: None,
            access_token_set_at: None,
            platform_type,
            client,
            handler,
            steam_guard_code: None,
            steam_guard_machine_token: None,
            start_session_response: None,
        })
    }
    
    /// Starts a new login attempt using your account credentials.
    /// 
    /// If you're logging in with [`EAuthTokenPlatformType::k_EAuthTokenPlatformType_SteamClient`], 
    /// you can supply a Buffer containing the SHA-1 hash of your sentry file for
    /// `steam_guard_machine_token`.
    /// 
    /// If you supply a `steam_guard_code` here and you're using email-based Steam Guard, Steam 
    /// will send you a new Steam Guard email if you're using [`EAuthTokenPlatformType::k_EAuthTokenPlatformType_SteamClient`]
    /// or [`EAuthTokenPlatformType::k_EAuthTokenPlatformType_MobileApp`]. You would ideally keep 
    /// your [`LoginSession`] active that generated your first email, and pass the code using
    /// `submit_steam_guard_code` instead of creating a new [`LoginSession`] and supplying the 
    /// code to `start_with_credentials`.
    /// 
    /// On success returns a [`StartSessionResponse`]. Check `allowed_confirmations` for how to 
    /// respond to the response.
    pub async fn start_with_credentials(
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
            return Some(SteamID::from(start_session_response.steamid()));
        }
        
        let token = if let Some(access_token) = &self.access_token {
            Some(access_token)
        } else if let Some(refresh_token) = &self.refresh_token {
            Some(refresh_token)
        } else {
            None
        }?;
        let decoded = decode_jwt(token).ok()?;
        
        Some(decoded.sub)
    }
    
    /// Gets the account name.
    pub fn get_account_name(&self) -> Option<&String> {
        self.account_name.as_ref()
    }
    
    /// A `string` containing your access token. As of 2023-09-12, Steam does not return an access 
    /// token in response to successful authentication. This will be set after you call 
    /// `refresh_access_token` or `renew_refresh_token`. Also, since `get_web_cookies` calls 
    /// `refresh_access_token` internally for 
    /// [`EAuthTokenPlatformType::k_EAuthTokenPlatformType_SteamClient`] or 
    /// [`EAuthTokenPlatformType::k_EAuthTokenPlatformType_MobileApp`], this will also be set after 
    /// calling [`get_web_cookies`] for those platform types.
    pub fn get_access_token(&self) -> Option<&String> {
        self.access_token.as_ref()
    }
    
    /// Sets the access token. Will return an error if:
    /// 
    /// - You set it to a token that isn't well-formed, or
    /// - You set it to a refresh token rather than an access token, or
    /// - You have already called `start_with_credentials` and you set it to a token that doesn't 
    /// belong to the same account, or
    /// - You have already set a refresh token and you set this to a token that doesn't belong to 
    /// the same account as the refresh token
    /// 
    /// Access tokens can't be used for much. You can use them with a few undocumented WebAPIs like 
    /// [IFriendsListService/GetFriendsList](https://steamapi.xpaw.me/#IFriendsListService/GetFriendsList) 
    /// by passing the access token as an access_token query string parameter. For example:
    /// 
    /// https://api.steampowered.com/IFriendsListService/GetFriendsList/v1/?access_token=eyAidHlwIjogIkpXVCIsICJhbGciOiAiRWREU0EiIH0.eyJpc3MiOiJ...
    /// 
    /// As of time of writing (2023-04-24), it appears that you can also use access tokens with regular published API methods,
    /// for example:
    /// 
    /// https://api.steampowered.com/ISteamUserStats/GetNumberOfCurrentPlayers/v1/?appid=440&access_token=eyAidHlwIjogIkpXVCIsICJhbGciOiAiRWREU0EiIH0.eyJpc3MiOiJ...
    fn set_access_token(&mut self, token: String) -> Result<(), LoginSessionError> {
        if token.is_empty() {
            self.access_token = None;
            return Ok(());
        }
        
        let decoded = decode_jwt(&token)?;
        
        if decoded.aud.iter().any(|a| a == "derive") {
            return Err(LoginSessionError::ExpectedAccessToken);
        }
        
        if let Some(start_session_response) = &self.start_session_response {
            if start_session_response.steamid() != u64::from(decoded.sub) {
                return Err(LoginSessionError::TokenIsForDifferentAccount);
            }
        }
        
        if let Some(refresh_token) = &self.refresh_token {
            let decoded_refresh_token = decode_jwt(refresh_token)?;
            
            if decoded_refresh_token.sub != decoded.sub {
                return Err(LoginSessionError::TokenBelongsToOtherAccount);
            }
        }
        
        // Everything checks out
        self.access_token = Some(token);
        self.access_token_set_at = Some(Utc::now());
        
        Ok(())
    }
    
    /// Gets the refresh token. This is populated after authenticatation. You can also assign a 
    /// refresh token calling `set_refresh_token` if you already have one.
    pub fn get_refresh_token(&self) -> Option<&String> {
        self.access_token.as_ref()
    }
    
    /// Sets the refresh token. Will return an error if:
    ///
    /// - You set it to a token that isn't well-formed, or
    /// - You set it to an access token rather than a refresh token, or
    /// - You have already called `start_with_credentials` and you set it to a token that doesn't 
    /// belong to the same account, or
    /// - You have already set an `access_token` and you set this to a token that doesn't belong 
    /// to the same account as the access token
    pub fn set_refresh_token(&mut self, token: String) -> Result<(), LoginSessionError> {
        if token.is_empty() {
            self.refresh_token = None;
            return Ok(());
        }
        
        let decoded = decode_jwt(&token)?;
        
        if !decoded.aud.iter().any(|a| a == "derive") {
            return Err(LoginSessionError::ExpectedRefreshToken);
        }
        
        let required_audience = match self.platform_type {
            EAuthTokenPlatformType::k_EAuthTokenPlatformType_SteamClient => "client",
            EAuthTokenPlatformType::k_EAuthTokenPlatformType_MobileApp => "mobile",
            EAuthTokenPlatformType::k_EAuthTokenPlatformType_WebBrowser => "web",
            EAuthTokenPlatformType::k_EAuthTokenPlatformType_Unknown => "unknown",
        };
        
        if !decoded.aud.iter().any(|a| a == required_audience) {
            return Err(LoginSessionError::TokenPlatformDifferent(required_audience.into()));
        }
        
        if let Some(start_session_response) = &self.start_session_response {
            if start_session_response.steamid() != u64::from(decoded.sub) {
                return Err(LoginSessionError::TokenIsForDifferentAccount);
            }
        }
        
        if let Some(access_token) = &self.access_token {
            let decoded_access_token = decode_jwt(access_token)?;
            
            if decoded_access_token.sub != decoded.sub {
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
            start_session_response.allowed_confirmations.clone()
        };
        
        for confirmation in allowed_confirmations {
            let confirmation_type = confirmation.confirmation_type();
            
            match confirmation_type {
                EAuthSessionGuardType::k_EAuthSessionGuardType_None => {
                    self.do_poll().await?;
                    
                    return Ok(StartSessionResponse::Authenticated);
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
                        return Ok(StartSessionResponse::Authenticated);
                    }
                    
                    // We need a code from the user
                    let detail = if confirmation.associated_message().is_empty() {
                        Some(confirmation.associated_message().to_string())
                    } else {
                        None
                    };
                    
                    valid_actions.push(StartSessionResponseValidAction {
                        r#type: confirmation_type,
                        detail,
                    });
                },
                EAuthSessionGuardType::k_EAuthSessionGuardType_EmailConfirmation |
                EAuthSessionGuardType::k_EAuthSessionGuardType_DeviceConfirmation => {
                    // Probably not necessary
                    self.do_poll().await?;
                    
                    valid_actions.push(StartSessionResponseValidAction {
                        r#type: confirmation_type,
                        detail: None,
                    });
                },
                EAuthSessionGuardType::k_EAuthSessionGuardType_MachineToken => {
                    // Do nothing here since this is handled by attempt_email_code_auth
                },
                r#type => {
                    // error unknown guard type
                    return Err(LoginSessionError::UnknownGuardType(r#type));
                },
            }
        }
        
        Ok(StartSessionResponse::ActionRequired(valid_actions))
    }
    
    /// Attempts steam guard code.
    pub async fn attempt_steam_guard_code(&mut self) -> Result<bool, LoginSessionError> {
        if let Some(steam_guard_code) = &self.steam_guard_code {
            match self.submit_steam_guard_code(steam_guard_code.clone()).await {
                Ok(_) => {
                    return Ok(true);
                },
                Err(LoginSessionError::AuthenticationClient(AuthenticationClientError::EResultNotOK(EResult::TwoFactorCodeMismatch))) => {
                    // nothing
                },
                Err(error) => {
                    return Err(error);
                },
            }
        }
        
        Ok(false)
    }
    
    /// Attempts email code authentication.
    async fn attempt_email_code_auth(&mut self) -> Result<bool, LoginSessionError> {
        if self.attempt_steam_guard_code().await? {
            return Ok(true);
        }
        
        let start_session_response = self.start_session_response.as_ref()
            .ok_or(LoginSessionError::LoginSessionHasNotStarted)?;
        let has_machine_token_confirmation = start_session_response.allowed_confirmations
            .iter()
            .any(|allowed_confirmation| allowed_confirmation.confirmation_type() == EAuthSessionGuardType::k_EAuthSessionGuardType_MachineToken);
        
        if self.platform_type == EAuthTokenPlatformType::k_EAuthTokenPlatformType_WebBrowser &&
        has_machine_token_confirmation {
            let response = self.handler.check_machine_auth_or_send_code_email(
                start_session_response.client_id(),
                start_session_response.steamid().into(),
                self.steam_guard_machine_token.as_deref(),
            ).await?;
            
            if response.result == EResult::OK {
                self.do_poll().await?;
                return Ok(true);
            }
        }
        
        Ok(false)
    }
    
    /// Attemps TOTP code authentication.
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
        let needs_email_code = start_session_response.allowed_confirmations
            .iter()
            .any(|confirmation| {
                confirmation.confirmation_type() == EAuthSessionGuardType::k_EAuthSessionGuardType_EmailCode
            });
        let needs_totp_code = start_session_response.allowed_confirmations
            .iter()
            .any(|confirmation| {
                confirmation.confirmation_type() == EAuthSessionGuardType::k_EAuthSessionGuardType_DeviceCode
            });
        
        if !needs_email_code && !needs_totp_code {
            return Err(LoginSessionError::LoginAttemptSteamGuardNotRequired);
        }
        
        let code_type = if needs_email_code {
            EAuthSessionGuardType::k_EAuthSessionGuardType_EmailCode
        } else {
            EAuthSessionGuardType::k_EAuthSessionGuardType_DeviceCode
        };
        let client_id = start_session_response.client_id();
        let steamid = start_session_response.steamid();
        
        self.handler.submit_steam_guard_code(
            client_id,
            steamid,
            auth_code,
            code_type
        ).await?;
        // should authenticate
        self.do_poll().await?;
        
        Ok(())
    }
    
    /// Once successfully authenticated, you can call this method to get cookies for use on the 
    /// Steam websites. You can also manually set the `refresh_token` and then call this method 
    /// without going through another login attempt if you already have a valid refresh token.
    /// 
    /// Returns an array of strings. Each string contains a cookie, e.g.
    /// `"steamLoginSecure=blahblahblahblah; Path=/; Secure; HttpOnly; SameSite=None; Domain=steamcommunity.com"`.
    pub async fn get_web_cookies(
        &mut self,
    ) -> Result<Vec<String>, LoginSessionError> {
        #[derive(Debug, Deserialize)]
        struct TransferInfo {
            url: String,
            params: Value,
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
        
        async fn get_cookies(request: RequestBuilder) -> Option<Vec<String>> {
            let response = request.send().await.ok()?;
            let headers = response.headers();
            let set_cookie = headers.get_all(SET_COOKIE);
            let cookies = set_cookie
                .into_iter()
                .flat_map(|header| {
                    let value = header.to_str().ok()?;
                    let mut cookie = Cookie::parse(value).ok()?;
                    let domain = response.url().domain()?;
                    
                    cookie.set_domain(domain);
                    
                    let domain = cookie.domain()?;
                    
                    Some(format!("{}={}; Path=/; Secure; HttpOnly; SameSite=None; Domain={}", cookie.name(), cookie.value(), domain))
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
        if self.platform_type == EAuthTokenPlatformType::k_EAuthTokenPlatformType_SteamClient ||
        self.platform_type == EAuthTokenPlatformType::k_EAuthTokenPlatformType_MobileApp {
            // Refresh our access token if we either don't have one, or the token we have is 
            // greater than 10 minutes old. Technically we could just decode the JWT and find out 
            // when it expires (or was issued), but let's try to minimize how much we depend on 
            // the access token being a JWT (as Valve may change it at any point).
            if self.access_token.is_none() ||
            self.access_token_set_at
                .map(|datetime| Utc::now() - datetime > Duration::minutes(10))
                .unwrap_or(false) {
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
                let form = value_to_multipart(transfer_info.params)
                    .text("steamID", u64::from(steamid).to_string());
                let request = self.client.post(&transfer_info.url).multipart(form);
                
                // send a request that will return cookies if it contains cookies
                log::debug!("POST {}", transfer_info.url);
                get_cookies(request)
            })
            .collect::<FuturesOrdered<_>>();
        let mut cookies = Vec::new();
        
        while let Some(transfer) = transfers.next().await {
            if let Some(mut domain_cookies) = transfer {
                cookies.append(&mut domain_cookies);
            }
        }
        
        if cookies.is_empty() {
            return Err(LoginSessionError::NoCookiesInResponse);
        }
        
        let mut cookies = cookies
            .into_iter()
            .filter(|cookie| !cookie.contains("sessionid="))
            .collect::<Vec<_>>();
        
        cookies.push(format!("sessionid={sessionid}"));
        
        Ok(cookies)
    }
    
    /// Refreshes the access token. As long as a `refresh_token` is set, you can call this method 
    /// to obtain a new access token. 
    pub async fn refresh_access_token(&mut self) -> Result<(), LoginSessionError> {
        let refresh_token = self.refresh_token.as_ref()
            .ok_or_else(|| LoginSessionError::NoRefreshToken)?;
        let access_token = self.handler.generate_access_token_for_app(
            refresh_token.clone(),
            false,
        ).await?;
        let access_token = access_token.access_token().to_string();
        
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
    pub async fn renew_refresh_token(&mut self) -> Result<bool, LoginSessionError> {
        let refresh_token = self.refresh_token.as_ref()
            .ok_or_else(|| LoginSessionError::NoRefreshToken)?;
        let response = self.handler.generate_access_token_for_app(refresh_token.clone(), true)
            .await?;
        let access_token = response.access_token();
        let refresh_token = response.refresh_token();
        
        self.set_access_token(access_token.to_owned())?;
        self.set_refresh_token(refresh_token.to_owned())?;
        
        Ok(!access_token.is_empty())
    }
    
    pub async fn poll(&mut self) -> Result<(), LoginSessionError> {
        let polling_started_time = Utc::now();
        let poll_interval = self.start_session_response.as_ref()
            .ok_or(LoginSessionError::LoginSessionHasNotStarted)?
            .interval();
        
        loop {
            let total_polling_time = Utc::now() - polling_started_time;
            
            if total_polling_time >= self.login_timeout {
                return Ok(());
            }
            
            if self.do_poll().await? {
                return Ok(());
            }
            
            // poll again
            async_std::task::sleep(std::time::Duration::from_secs(poll_interval as u64)).await;
        }
    }
    
    /// Performs a poll. Returns true if complete.
    async fn do_poll(&mut self) -> Result<bool, LoginSessionError> {
        let start_session_response = self.start_session_response.as_ref()
            .ok_or(LoginSessionError::LoginSessionHasNotStarted)?;
        let clientid = start_session_response.client_id();
        let request_id = start_session_response.request_id();
        let response = self.handler.poll_login_status(
            clientid,
            request_id.into(),
        ).await?;
        
        if response.had_remote_interaction() {
            
        }
        
        if !response.refresh_token().is_empty() {
            let client_id = response.new_client_id();
            
            if let Some(start_session_response) = self.start_session_response.as_mut() {
                start_session_response.set_client_id(client_id);
            }
            
            self.access_token = Some(response.access_token().to_owned());
            self.set_access_token(response.access_token().to_owned())?;
            self.set_refresh_token(response.refresh_token().to_owned())?;
            
            // On 2023-09-12, Steam stopped issuing access tokens alongside refresh tokens 
            // for newly authenticated sessions. This won't affect any consumer apps that 
            // use `get_web_cookies`, since that will acquire an access token if needed.
            // On 2023-09-22, I noticed that Steam started issuing access tokens again.
            
            // Consumers using SteamClient or WebBrowser never had a reason to consume the 
            // accessToken property directly, since that was only useful as a cookie and 
            // `get_web_cookies` should be used instead. However, the access token is also 
            // used as a WebAPI key for MobileApp, so we should probably ensure that we 
            // have one for that platform.
            if self.refresh_token.is_none() && 
            self.platform_type == EAuthTokenPlatformType::k_EAuthTokenPlatformType_MobileApp {
                self.refresh_access_token().await?;
            }
            
            return Ok(true);
        }
        
        Ok(false)
    }
    
    fn verify_started(&self, must_have_steamid: bool) -> Result<(), LoginSessionError> {
        if self.start_session_response.is_none() {
            return Err(LoginSessionError::LoginSessionHasNotStarted);
        }
        
        if must_have_steamid && self.steamid().is_none() {
            return Err(LoginSessionError::LoginCannotUseMethodWithScheme);
        }
        
        Ok(())
    }
}
