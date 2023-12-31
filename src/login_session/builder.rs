use super::{LoginSessionError, LoginSession};
use super::helpers::LoginSessionOptions;
use crate::transports::Transport;
use steam_session_proto::steammessages_auth_steamclient::EAuthTokenPlatformType;

pub struct LoginSessionBuilder<T> {
    platform_type: EAuthTokenPlatformType,
    transport: T,
    user_agent: Option<&'static str>,
    machine_id: Option<Vec<u8>>,
}

impl<T> LoginSessionBuilder<T>
where
    T: Transport,
{
    pub fn new(
        transport: T,
        platform_type: EAuthTokenPlatformType,
    ) -> Self {
        Self {
            platform_type,
            transport,
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
    
    pub fn build(self) -> Result<LoginSession<T>, LoginSessionError> {
        let session = LoginSession::new(LoginSessionOptions {
            transport: self.transport,
            platform_type: self.platform_type,
            user_agent: self.user_agent,
            machine_id: self.machine_id,
        })?;
        
        Ok(session)
    }
}