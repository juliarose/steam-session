use steam_session::login_session::connect_webapi;
use steam_session::request::StartLoginSessionWithCredentialsDetails;
use steam_session::proto::steammessages_auth_steamclient::EAuthTokenPlatformType;
use another_steam_totp::generate_auth_code;
use log::LevelFilter;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    dotenv::dotenv().ok();
    simple_logging::log_to_stderr(LevelFilter::Debug);
    
    let account_name = std::env::var("ACCOUNT_NAME")?;
    let password = std::env::var("PASSWORD")?;
    let shared_secret = std::env::var("SHARED_SECRET")?;
    let details = StartLoginSessionWithCredentialsDetails {
        account_name,
        password,
        persistence: None,
        steam_guard_machine_token: None,
        steam_guard_code: None,
        platform_type: EAuthTokenPlatformType::k_EAuthTokenPlatformType_WebBrowser,
        machine_id: None,
        user_agent: None,
    };
    let mut session = connect_webapi().await?;
    let response = session.start_with_credentials(details).await?;
    
    if response.requires_device_code() {
        let steam_guard_code = generate_auth_code(shared_secret.clone(), None)?;
        
        if let Err(error) = session.submit_steam_guard_code(steam_guard_code).await {
            panic!("Failed to submit Steam Guard code: {}", error);
        }
    }
    
    let cookies = session.get_web_cookies().await?;
    
    println!("{cookies:?}");
    
    Ok(())
}