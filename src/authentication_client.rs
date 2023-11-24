use crate::enums::AuthTokenPlatformType;
use crate::interfaces::{
    AuthenticationClientConstructorOptions,
    SubmitSteamGuardCodeRequest,
    StartAuthSessionRequest,
    MobileConfirmationRequest, GetAuthSessionInfoRequest,
};
use reqwest::Client;
use tokio::task::JoinHandle;
use crate::transports::WebSocketCMTransport;

#[derive(Debug, Clone)]
pub struct RequestDefinition {
    api_interface: String,
    api_method: String,
    api_version: u32,
    data: Vec<u8>,
    access_token: Option<String>,
}

#[derive(Debug)]
pub struct AuthenticationClient {
    transport: WebSocketCMTransport,
    platform_type: AuthTokenPlatformType,
    client: Client,
    transport_close_timeout: Option<JoinHandle<()>>,
    user_agent: String,
    machine_id: Option<Vec<u8>>,
}

impl AuthenticationClient {
    pub fn new(options: AuthenticationClientConstructorOptions) -> Self {
        Self {
            transport: options.transport,
            platform_type: options.platform_type,
            client: options.client,
            transport_close_timeout: None,
            user_agent: options.user_agent,
            machine_id: options.machine_id,
        }
    }

    async fn get_rsa_key(
        &self,
        account_name: String,
    ) -> Result<(), AuthenticationClientError> {
        todo!()
    }

    fn get_platform_data(
        &self,
    ) {
        // todo
    }

    async fn encrypt_password(
        &self,
        account_name: String,
        password: String,
    ) -> Result<EncryptedPassword, AuthenticationClientError> {
        let rsa_info = self.get_rsa_key(account_name).await?;
		// todo
        // let key = new RSAKey();
		// key.setPublic(rsaInfo.publickey_mod, rsaInfo.publickey_exp);
		
		// return {
		// 	encryptedPassword: hex2b64(key.encrypt(password)),
		// 	keyTimestamp: rsaInfo.timestamp
		// };
        Ok(EncryptedPassword {
            password: String::new(),
            key_timestamp: String::new(),
        })
    }

    async fn get_auth_session_info(
        &self,
        access_token: String,
        details: GetAuthSessionInfoRequest,
    ) -> Result<(), AuthenticationClientError> {
        let request = RequestDefinition {
            api_interface: "Authentication".into(),
            api_method: "GetAuthSessionInfo".into(),
            api_version: 1,
            data: Vec::new(),
            access_token: Some(access_token),
        };

        // todo
        Ok(())
    }

    async fn submit_mobile_confirmation(
        &self,
        access_token: String,
        details: MobileConfirmationRequest,
    ) -> Result<(), AuthenticationClientError> {
        let request = RequestDefinition {
            api_interface: "Authentication".into(),
            api_method: "UpdateAuthSessionWithMobileConfirmation".into(),
            api_version: 1,
            data: Vec::new(),
            access_token: Some(access_token),
        };

        // todo
        Ok(())
    }

    async fn generate_access_token_for_app(
        &mut self,
        refresh_token: String,
        renew_refresh: bool,
    ) -> Result<(), AuthenticationClientError> {
        let request = RequestDefinition {
            api_interface: "Authentication".into(),
            api_method: "GenerateAccessTokenForApp".into(),
            api_version: 1,
            data: Vec::new(),
            access_token: None,
        };

        // todo
        Ok(())
    }

    async fn send_request(
        &self,
        request: RequestDefinition,
    ) -> Result<(), AuthenticationClientError> {
        Ok(())
    }

    fn close(&mut self) {
        if let Some(handle) = &self.transport_close_timeout {
            handle.abort();
        }

        self.transport_close_timeout = Some(tokio::task::spawn(async move {
            // transport.close();
        }));
    }

    async fn start_session_with_credentials(
        &self,
        details: StartAuthSessionRequest,
    ) -> Result<(), AuthenticationClientError> {
		// let {websiteId, deviceDetails} = this._getPlatformData();

		// let data:CAuthentication_BeginAuthSessionViaCredentials_Request_BinaryGuardData = {
		// 	account_name: details.accountName,
		// 	encrypted_password: details.encryptedPassword,
		// 	encryption_timestamp: details.keyTimestamp,
		// 	remember_login: details.persistence == ESessionPersistence.Persistent,
		// 	persistence: details.persistence,
		// 	website_id: websiteId,
		// 	device_details: deviceDetails
		// };

		// if (details.platformType == EAuthTokenPlatformType.SteamClient) {
		// 	// For SteamClient logins, we also need a machine id
		// 	if (this._machineId && Buffer.isBuffer(this._machineId)) {
		// 		data.device_details.machine_id = this._machineId;
		// 	} else if (this._machineId === true) {
		// 		data.device_details.machine_id = createMachineId(details.accountName);
		// 	}
		// }

		// if (details.steamGuardMachineToken) {
		// 	if (Buffer.isBuffer(details.steamGuardMachineToken)) {
		// 		data.guard_data = details.steamGuardMachineToken;
		// 	} else if (typeof details.steamGuardMachineToken == 'string' && isJwtValidForAudience(details.steamGuardMachineToken, 'machine')) {
		// 		data.guard_data = Buffer.from(details.steamGuardMachineToken, 'utf8');
		// 	}
		// }

		// let result:CAuthentication_BeginAuthSessionViaCredentials_Response = await this.sendRequest({
		// 	apiInterface: 'Authentication',
		// 	apiMethod: 'BeginAuthSessionViaCredentials',
		// 	apiVersion: 1,
		// 	data
		// });

		// return {
		// 	clientId: result.client_id,
		// 	requestId: result.request_id,
		// 	pollInterval: result.interval,
		// 	allowedConfirmations: result.allowed_confirmations.map(c => ({type: c.confirmation_type, message: c.associated_message})),
		// 	steamId: result.steamid,
		// 	weakToken: result.weak_token
		// };

        Ok(())
    }

    async fn submit_steam_guard_code(&self, details: SubmitSteamGuardCodeRequest) -> Result<(), AuthenticationClientError> {
        // let data:CAuthentication_UpdateAuthSessionWithSteamGuardCode_Request = {
		// 	client_id: details.clientId,
		// 	steamid: details.steamId,
		// 	code: details.authCode,
		// 	code_type: details.authCodeType
		// };

		// await this.sendRequest({
		// 	apiInterface: 'Authentication',
		// 	apiMethod: 'UpdateAuthSessionWithSteamGuardCode',
		// 	apiVersion: 1,
		// 	data
		// });

        Ok(())
    }
}


#[derive(Debug, Clone)]
pub struct EncryptedPassword {
    password: String,
    key_timestamp: String,
}

#[derive(Debug, thiserror::Error)]
pub enum AuthenticationClientError {

}