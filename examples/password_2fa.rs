use std::sync::Arc;
use steam_session::login_session::connect_webapi;
use steam_session::request::StartLoginSessionWithCredentialsDetails;
use steam_session::proto::steammessages_auth_steamclient::EAuthTokenPlatformType;
use another_steam_totp::generate_auth_code;
use log::LevelFilter;
use reqwest::Client;
use url::Url;
use scraper::{Html, Selector};

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
    
    // Get the cookies
    let cookies = session.get_web_cookies().await?;
    
    println!("Got {} cookies", cookies.len());
    
    // Logging from here on out isn't useful
    simple_logging::log_to_stderr(LevelFilter::Error);
    
    let client = {
        // We need to add the cookies to a cookie jar before we can use them with reqwest
        let jar = reqwest::cookie::Jar::default();
        let url = "https://steamcommunity.com".parse::<Url>()?;
        
        for cookie in cookies {
            jar.add_cookie_str(&cookie, &url)
        }
        
        Client::builder()
            .cookie_provider(Arc::new(jar))
            .build()?
    };
    // Let's give these cookies a test by fetching our profile
    let html = client.get("https://steamcommunity.com/my")
        .send()
        .await?
        .text()
        .await?;
    let fragment = Html::parse_fragment(&html);
    // Take the persona name from the page
    let persona_name_span = fragment.select(&Selector::parse("span.actual_persona_name")?)
        .next()
        .unwrap();
    let persona_name = persona_name_span.text()
        .collect::<Vec<_>>()
        .join("");
    
    println!("Logged in as: {}", persona_name);
    
    Ok(())
}