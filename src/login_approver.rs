use crate::{authentication_client::AuthenticationClient, interfaces::AuthenticationClientConstructorOptions, helpers::USER_AGENT};
use reqwest::Client;
use steamid_ng::SteamID;

type Buffer = Vec<u8>;

#[derive(Debug)]
pub struct LoginApprover {
    access_token: String,
    pub shared_secret: String,
    client: Client,
    handler: AuthenticationClient,
}

impl LoginApprover {
    pub fn new(
        access_token: String,
        shared_secret: String,
        options: AuthenticationClientConstructorOptions,
    ) -> Self {
        let client = Client::new();

		// let agent:HTTPS.Agent = options.agent || new HTTPS.Agent({keepAlive: true});

		// if (options.httpProxy) {
		// 	agent = StdLib.HTTP.getProxyAgent(true, options.httpProxy) as HTTPS.Agent;
		// } else if (options.socksProxy) {
		// 	agent = new SocksProxyAgent(options.socksProxy);
		// }

		// this._webClient = new HttpClient({
		// 	httpsAgent: agent,
		// 	localAddress: options.localAddress
		// });

        let transport = 0;
        let platform_type = options.platform_type;

        Self {
            access_token,
            shared_secret,
            client: client.clone(),
            handler: AuthenticationClient::new(AuthenticationClientConstructorOptions {
                platform_type,
                client,
                machine_id: options.machine_id,
                transport,
                user_agent: USER_AGENT.into(),
            }),
        }
    }

    // todo
    pub fn steamid(&self) -> SteamID {
        // let token = this.accessToken || this.refreshToken;
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