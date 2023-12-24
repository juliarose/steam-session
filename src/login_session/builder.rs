use super::LoginSessionError;
use super::LoginSession;
use crate::interfaces::LoginSessionOptions;
use steam_session_proto::steammessages_auth_steamclient::EAuthTokenPlatformType;

pub struct LoginSessionBuilder {
    platform_type: EAuthTokenPlatformType,
    user_agent: Option<&'static str>,
    machine_id: Option<Vec<u8>>,
}

impl LoginSessionBuilder {
    pub fn new(platform_type: EAuthTokenPlatformType) -> Self {
        Self {
            platform_type,
            user_agent: None,
            machine_id: None,
        }
    }

    pub fn platform_type(mut self, platform_type: EAuthTokenPlatformType) -> Self {
        self.platform_type = platform_type;
        self
    }

    pub fn user_agent(mut self, user_agent: &'static str) -> Self {
        self.user_agent = Some(user_agent);
        self
    }

    pub fn machine_id(mut self, machine_id: Vec<u8>) -> Self {
        self.machine_id = Some(machine_id);
        self
    }
    
    pub async fn connect(self) -> Result<LoginSession, LoginSessionError> {
        let options = LoginSessionOptions {
            platform_type: self.platform_type,
            user_agent: self.user_agent,
            machine_id: self.machine_id,
        };
        let session = LoginSession::connect(options).await?;
        
        Ok(session)
    }
}