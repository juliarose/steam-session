use steam_session_proto::steammessages_auth_steamclient::EAuthSessionGuardType;

#[derive(Debug, Clone)]
pub struct StartSessionResponseValidAction {
    pub r#type: EAuthSessionGuardType,
    pub detail: Option<String>,
}

/// Response when starting a new login session.
#[derive(Debug, Clone)]
pub enum StartSessionResponse {
    /// Successfully authenticated. No further action is needed.
    Authenticated,
    /// Action is required.
    /// 
    /// Here's a list of which guard types might be present in this method's response, and how you 
    /// should proceed:
    ///
    /// - [`EAuthSessionGuardType::k_EAuthSessionGuardType_EmailCode`]: An email was sent to you 
    /// containing a code (`detail` contains your email address' domain, e.g. `gmail.com`). You 
    /// should get that code and either call {@link submitSteamGuardCode}, or create a new 
    /// [`LoginSession`] and supply that code to the `steam_guard_code` property when calling
    /// `start_with_credentials`.
    /// - [`EAuthSessionGuardType::k_EAuthSessionGuardType_DeviceCode`]: You need to supply a TOTP 
    /// code from your mobile authenticator (or by using 
    /// [another-steam-totp](https://crates.io/crates/another-steam-totp)). Get that code and 
    /// either call `submit_steam_guard_code`, or create a new [`LoginSession`] and supply that
    /// code to the `steam_guard_code` property when calling `start_with_credentials`.
    /// - [`EAuthSessionGuardType::k_EAuthSessionGuardType_DeviceConfirmation`]: You need to 
    /// approve the confirmation prompt in your Steam mobile app.
    /// - [`EAuthSessionGuardType::k_EAuthSessionGuardType_EmailConfirmation`]: You need to approve 
    /// the confirmation email sent to you.
    ActionRequired(Vec<StartSessionResponseValidAction>),
    /// Contains a URL to a QR code for authentication.
    QrChallenge(String),
}

impl StartSessionResponse {
    /// Checks if the response requires a device code.
    pub fn requires_device_code(&self) -> bool {
        match self {
            Self::ActionRequired(actions) => {
                actions
                    .iter()
                    .any(|action| action.r#type == EAuthSessionGuardType::k_EAuthSessionGuardType_DeviceCode)
            },
            _ => false,
        }
    }
}