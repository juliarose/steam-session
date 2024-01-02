//! # Login Approver
//! 
//! Can be used to approve a login attempt that was started with a QR code.
//! 
//! ## Examples
//! ```
//! use steam_session::login_approver::{LoginApprover, EAuthTokenPlatformType};
//!
//! let login_approver = LoginApprover::builder("access_token".to_string(), "shared_secret".to_string())
//!     .platform_type(EAuthTokenPlatformType::k_EAuthTokenPlatformType_WebBrowser)
//!     .user_agent("Mozilla/5.0")
//!     .build();
//! ```

mod error;
mod builder;
mod helpers;

pub use error::Error;
pub use builder::LoginApproverBuilder;

use crate::authentication_client::{AuthenticationClient, AuthenticationClientConstructorOptions};
use crate::helpers::{decode_jwt, decode_base64, generate_hmac_signature};
use crate::request::{ApproveAuthSessionRequest, MobileConfirmationRequest};
use crate::transports::web_api::WebApiTransport;
use reqwest::Client;
use steam_session_proto::steammessages_auth_steamclient::{CAuthentication_UpdateAuthSessionWithMobileConfirmation_Response, CAuthentication_GetAuthSessionInfo_Response};
use steamid_ng::SteamID;
use byteorder::{WriteBytesExt, LittleEndian};

/// Can be used to approve a login attempt that was started with a QR code.
#[derive(Debug)]
pub struct LoginApprover {
    shared_secret: String,
    access_token: String,
    handler: AuthenticationClient<WebApiTransport>,
}

impl LoginApprover {
    pub fn builder(
        access_token: String,
        shared_secret: String,
    ) -> LoginApproverBuilder {
        LoginApproverBuilder::new(access_token, shared_secret)
    }
    
    /// Gets the SteamID.
    pub fn steamid(&self) -> Result<SteamID, Error> {
        let decoded_token = decode_jwt(&self.access_token)?;
        
        Ok(decoded_token.sub)
    }
    
    /// Gets the access token.
    pub fn get_access_token(&self) -> &String {
        &self.access_token
    }
    
    /// Sets the access token.
    pub fn set_access_token(
        &mut self,
        access_token: String,
    ) -> Result<(), Error> {
        let decoded = decode_jwt(&access_token)?;
        
        if !decoded.aud.iter().any(|s| s == "derive") {
            return Err(Error::RefreshToken);
        }
        
        if !decoded.aud.iter().any(|s| s == "mobile") {
            return Err(Error::InvalidToken);
        }
        
        self.access_token = access_token;
        Ok(())
    }
    
    /// Gets the login session info.
    pub async fn get_auth_session_info(
        &self,
        qr_challenge_url: &str,
    ) -> Result<CAuthentication_GetAuthSessionInfo_Response, Error> {
        let decoded_qr = helpers::decode_qr_url(qr_challenge_url)
            .ok_or(Error::InvalidQRUrl)?;
        let response = self.handler.get_auth_session_info(
            decoded_qr.client_id,
            self.access_token.clone()
        ).await?;
        
        Ok(response)
    }
    
    /// Approves a login session.
    pub async fn approve_auth_session(
        &self,
        options: ApproveAuthSessionRequest,
    ) -> Result<CAuthentication_UpdateAuthSessionWithMobileConfirmation_Response, Error> {
        let mut buffer: Vec<u8> = Vec::new();
        
        buffer.write_u16::<LittleEndian>(options.version)?;
        buffer.write_u64::<LittleEndian>(options.client_id)?;
        buffer.write_u64::<LittleEndian>(options.steamid)?;
        
        let shared_secret = decode_base64(&self.shared_secret)?;
        let signature = generate_hmac_signature(
            &shared_secret,
            &buffer,
        )?;
        let response = self.handler.submit_mobile_confirmation(self.access_token.clone(), MobileConfirmationRequest {
            version: options.version,
            client_id: options.client_id,
            steamid: options.steamid,
            signature,
            confirm: options.approve,
            persistence: options.persistence,
        }).await?;
        
        Ok(response)
    }
}

impl TryFrom<LoginApproverBuilder> for LoginApprover {
    type Error = Error;
    
    fn try_from(builder: LoginApproverBuilder) -> Result<Self, Self::Error> {
        let client = Client::new();
        let transport = WebApiTransport::new();
        let handler = AuthenticationClient::new(AuthenticationClientConstructorOptions {
            machine_id: builder.machine_id,
            platform_type: builder.platform_type,
            transport,
            client,
            user_agent: builder.user_agent,
        });
        let decoded_access_token = decode_jwt(&builder.access_token)?;
        
        if !decoded_access_token.aud.iter().any(|s| s == "derive") {
            return Err(Error::RefreshToken);
        }
        
        if !decoded_access_token.aud.iter().any(|s| s == "mobile") {
            return Err(Error::InvalidToken);
        }
        
        Ok(Self {
            shared_secret: builder.shared_secret,
            access_token: builder.access_token,
            handler,
        })
    }
}