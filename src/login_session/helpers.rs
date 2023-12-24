use super::LoginSessionError;
use crate::authentication_client::AuthenticationClient;
use crate::interfaces::AuthenticationClientConstructorOptions;
use crate::helpers::USER_AGENT;
use crate::transports::WebSocketCMTransport;
use crate::proto::steammessages_auth_steamclient::EAuthTokenPlatformType;
use reqwest::Client;

pub async fn create_handler(
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