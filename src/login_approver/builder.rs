use super::LoginApprover;
use crate::enums::EAuthTokenPlatformType;
use crate::helpers::DEFAULT_USER_AGENT;

/// Builder for creating a [`LoginApprover`].
///
/// # Examples
/// ```
/// use steam_session::login_approver::LoginApprover;
/// use steam_session::enums::EAuthTokenPlatformType;
/// 
/// let login_approver = LoginApprover::builder("access_token".to_string(), "shared_secret".to_string())
///     .platform_type(EAuthTokenPlatformType::k_EAuthTokenPlatformType_WebBrowser)
///     .user_agent("Mozilla/5.0")
///     .build();
/// ```
#[derive(Debug)]
pub struct LoginApproverBuilder {
    pub access_token: String,
    pub shared_secret: String,
    pub platform_type: EAuthTokenPlatformType,
    pub machine_id: Option<Vec<u8>>,
    pub user_agent: &'static str,
}

impl LoginApproverBuilder {
    /// Creates a new [`LoginApproverBuilder`].
    pub fn new(
        access_token: String,
        shared_secret: String,
    ) -> Self {
        Self {
            access_token,
            shared_secret,
            platform_type: EAuthTokenPlatformType::k_EAuthTokenPlatformType_WebBrowser,
            machine_id: None,
            user_agent: DEFAULT_USER_AGENT,
        }
    }
    
    /// Sets the access token.
    pub fn access_token(mut self, access_token: String) -> Self {
        self.access_token = access_token;
        self
    }
    
    /// Sets the shared secret.
    pub fn shared_secret(mut self, shared_secret: String) -> Self {
        self.shared_secret = shared_secret;
        self
    }
    
    /// Sets the platform type. Defaults to 
    /// [`EAuthTokenPlatformType::k_EAuthTokenPlatformType_WebBrowser`].
    pub fn platform_type(mut self, platform_type: EAuthTokenPlatformType) -> Self {
        self.platform_type = platform_type;
        self
    }
    
    /// Sets the machine id. If not set, a random machine id will be generated.
    pub fn machine_id(mut self, machine_id: Option<Vec<u8>>) -> Self {
        self.machine_id = machine_id;
        self
    }
    
    /// Sets the user agent. If not set, the default user agent will be used.
    pub fn user_agent(mut self, user_agent: &'static str) -> Self {
        self.user_agent = user_agent;
        self
    }
    
    /// Builds the [`LoginApprover`]. Returns an error if your `access_token` isn't a well-formed 
    /// JWT, if it's a refresh token rather than an access token, or if it's an access token that 
    /// was not generated using [`EAuthTokenPlatformType::k_EAuthTokenPlatformType_MobileApp`].
    pub fn build(self) -> Result<LoginApprover, super::Error> {
        LoginApprover::try_from(self)
    }
}