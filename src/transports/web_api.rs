use reqwest::Client;
use crate::net::ApiRequest;

const HOSTNAME: &str = "api.steampowered.com";

pub struct WebApiTransport {
    client: Client,
}

impl WebApiTransport {
    pub fn new() -> Self {
        Self {
            client: Client::new(),
        }
    }
    
    fn get_url(pathname: &str) -> String {
        format!("https://{HOSTNAME}/{pathname}")
    }

    async fn send<Msg>(&self, msg: Msg)
    where
        Msg: ApiRequest,
    {
        let pathname = format!(
            "I{}Service/{}/v{}",
            Msg::INTERFACE,
            Msg::METHOD,
            Msg::VERSION,
        );
        let url = Self::get_url(&pathname);
        let request = if is_get_request(&pathname) {
            self.client.get(&url)
        } else {
            self.client.post(&url)
        };
        
        
    }
}

fn is_get_request(endpoint: &str) -> bool {
    endpoint == "IAuthenticationService/GetPasswordRSAPublicKey/v1"
}
