use crate::authentication_client::AuthenticationClient;
use crate::interfaces::AuthenticationClientConstructorOptions;
use crate::helpers::USER_AGENT;
use crate::transports::Transport;
use reqwest::Client;
use steamid_ng::SteamID;

type Buffer = Vec<u8>;

#[derive(Debug)]
pub struct LoginApprover<T> {
    access_token: String,
    pub shared_secret: String,
    client: Client,
    handler: AuthenticationClient<T>,
}

impl<T> LoginApprover<T>
where
    T: Transport,
{
    pub fn new(
        access_token: String,
        shared_secret: String,
        options: AuthenticationClientConstructorOptions<T>,
    ) -> Self {
        let client = Client::new();
        let platform_type = options.platform_type;

        Self {
            access_token,
            shared_secret,
            client: client.clone(),
            handler: AuthenticationClient::new(AuthenticationClientConstructorOptions {
                platform_type,
                client,
                machine_id: options.machine_id,
                transport: options.transport,
                user_agent: USER_AGENT.into(),
            }),
        }
    }
    
    pub fn steamid(&self) -> SteamID {
        // let decodedToken = decodeJwt(token);
        // return new SteamID(decodedToken.sub);

        SteamID::default()
    }

    pub fn get_access_token(&self) -> &String {
        &self.access_token
    }

    pub fn set_access_token(&mut self, access_token: String) {
		// let decoded = decodeJwt(token);
		// let aud = decoded.aud || [];

		// // Is it an access token and not a refresh token?
		// if (aud.includes('derive')) {
		// 	throw new Error('Provided token is a refresh token, not an access token');
		// }

		// if (!aud.includes('mobile')) {
		// 	throw new Error('Provided token is not valid for MobileApp platform usage');
		// }

        self.access_token = access_token;
    }
}