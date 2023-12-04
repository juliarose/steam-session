use protobuf::{Message, ProtobufResult};
use steam_session_proto::steammessages_clientserver_login::CMsgClientHello;
use std::fmt::Debug;
use std::io::Read;
use crate::proto::steammessages_auth_steamclient::{
    CAuthentication_AccessToken_GenerateForApp_Request,
    CAuthentication_AccessToken_GenerateForApp_Response,
};

pub trait ApiRequest: Debug + Message {
    const INTERFACE: &'static str;
    const METHOD: &'static str;
    const VERSION: u32;
    const NAME: &'static str;
    type Response: ApiResponse;
}

pub trait ApiResponse: Debug + Sized {
    fn parse_from_reader(reader: &mut dyn Read) -> ProtobufResult<Self>;
}

impl ApiResponse for () {
    fn parse_from_reader(_reader: &mut dyn Read) -> ProtobufResult<Self> {
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
            fn parse_from_reader(reader: &mut dyn Read) -> ProtobufResult<Self> {
                <Self as Message>::parse_from_reader(reader)
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
api_method!(("Authentication", "GenerateForAppAccessToken", 1) => CAuthentication_AccessToken_GenerateForApp_Request, CAuthentication_AccessToken_GenerateForApp_Response);