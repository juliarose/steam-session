
use crate::proto::steammessages_clientserver_login::CMsgClientHello;
use crate::proto::custom::CAuthentication_BeginAuthSessionViaCredentials_Request_BinaryGuardData;
use crate::proto::steammessages_auth_steamclient::{
    CAuthentication_BeginAuthSessionViaCredentials_Response,
    CAuthentication_UpdateAuthSessionWithSteamGuardCode_Request,
    CAuthentication_UpdateAuthSessionWithSteamGuardCode_Response,
    CAuthentication_UpdateAuthSessionWithMobileConfirmation_Response,
    CAuthentication_UpdateAuthSessionWithMobileConfirmation_Request,
    CAuthentication_GetAuthSessionInfo_Request,
    CAuthentication_GetAuthSessionInfo_Response,
    CAuthentication_GetPasswordRSAPublicKey_Request,
    CAuthentication_GetPasswordRSAPublicKey_Response,
    CAuthentication_PollAuthSessionStatus_Request,
    CAuthentication_PollAuthSessionStatus_Response,
};
use crate::proto::steammessages_auth_steamclient::{
    CAuthentication_AccessToken_GenerateForApp_Request,
    CAuthentication_AccessToken_GenerateForApp_Response,
};
use std::io::Read;

pub trait ApiRequest: Sized + protobuf::Message + protobuf::MessageFull {
    const INTERFACE: &'static str;
    const METHOD: &'static str;
    const VERSION: u32;
    const NAME: &'static str;
    type Response: ApiResponse;
}

pub trait ApiResponse: Sized {
    fn parse_from_reader(reader: &mut dyn Read) -> protobuf::Result<Self>;
}

impl ApiResponse for () {
    fn parse_from_reader(_reader: &mut dyn Read) -> protobuf::Result<Self> {
        Ok(())
    }
}

macro_rules! api_method {
    (($interface:literal, $method:literal, $version:expr) => $req:path, $res:path) => {
        impl ApiRequest for $req {
            const INTERFACE: &'static str = $interface;
            const METHOD: &'static str = $method;
            const VERSION: u32 = $version;
            const NAME: &'static str = concat!($interface, ".", $method, "#", $version);
            type Response = $res;
        }
        
        impl ApiResponse for $res {
            fn parse_from_reader(reader: &mut dyn Read) -> protobuf::Result<Self> {
                <Self as protobuf::Message>::parse_from_reader(reader)
            }
        }
    };
    (($interface:literal, $method:literal, $version:expr) => $req:path) => {
        impl ApiRequest for $req {
            const INTERFACE: &'static str = $interface;
            const METHOD: &'static str = $method;
            const VERSION: u32 = $version;
            const NAME: &'static str = concat!($interface, ".", $method, "#", $version);
            type Response = ();
        }
    };
}

api_method!(("Client", "Hello", 1) => CMsgClientHello);
api_method!(("Authentication", "GenerateAccessTokenForApp", 1) => CAuthentication_AccessToken_GenerateForApp_Request, CAuthentication_AccessToken_GenerateForApp_Response);
api_method!(("Authentication", "BeginAuthSessionViaCredentials", 1) => CAuthentication_BeginAuthSessionViaCredentials_Request_BinaryGuardData, CAuthentication_BeginAuthSessionViaCredentials_Response);
api_method!(("Authentication", "UpdateAuthSessionWithSteamGuardCode", 1) => CAuthentication_UpdateAuthSessionWithSteamGuardCode_Request, CAuthentication_UpdateAuthSessionWithSteamGuardCode_Response);
api_method!(("Authentication", "UpdateAuthSessionWithMobileConfirmation", 1) => CAuthentication_UpdateAuthSessionWithMobileConfirmation_Request, CAuthentication_UpdateAuthSessionWithMobileConfirmation_Response);
api_method!(("Authentication", "GetAuthSessionInfo", 1) => CAuthentication_GetAuthSessionInfo_Request, CAuthentication_GetAuthSessionInfo_Response);
api_method!(("Authentication", "GetPasswordRSAPublicKey", 1) => CAuthentication_GetPasswordRSAPublicKey_Request, CAuthentication_GetPasswordRSAPublicKey_Response);
api_method!(("Authentication", "PollAuthSessionStatus", 1) => CAuthentication_PollAuthSessionStatus_Request, CAuthentication_PollAuthSessionStatus_Response);

