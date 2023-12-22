use steam_session_proto::steammessages_auth_steamclient::EAuthSessionGuardType;

#[derive(Debug, Clone)]
pub struct StartSessionResponse {
    pub action_required: bool,
    pub valid_actions: Vec<StartSessionResponseValidAction>,
    pub qr_challenge_url: Option<String>,
}

impl StartSessionResponse {
    /// Checks if the response requires 2fa.
    pub fn is_2fa(&self) -> bool {
        self.action_required &&
        self.valid_actions
            .iter()
            .any(|action| action.r#type == EAuthSessionGuardType::k_EAuthSessionGuardType_DeviceCode)
    }
}

#[derive(Debug, Clone)]
pub struct StartSessionResponseValidAction {
    pub r#type: EAuthSessionGuardType,
    pub detail: Option<String>,
}