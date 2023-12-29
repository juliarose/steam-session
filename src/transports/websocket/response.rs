use super::Error;
use crate::enums::EResult;
use crate::net::{ApiRequest, ApiResponse};
use bytes::BytesMut;
use bytes::Buf;

#[derive(Debug, Clone)]
pub struct ApiResponseBody {
    pub eresult: Option<EResult>,
    pub error_message: Option<String>,
    pub body: Option<Vec<u8>>,
}

impl ApiResponseBody {
    pub fn into_response<Msg>(self) -> Result<Msg::Response, Error>
    where
        Msg: ApiRequest,
        <Msg as ApiRequest>::Response: Send,
    {
        if let Some(body) = self.body {
            let bytes = BytesMut::from(body.as_slice());
            let mut reader = bytes.reader();
            let response = Msg::Response::parse_from_reader(&mut reader)?;
            
            Ok(response)
        } else if let Some(eresult) = self.eresult {
            Err(Error::EResultNotOK(eresult))
        } else if let Some(message) = self.error_message {
            Err(Error::ResponseError(message))
        } else {
            Err(Error::NoBodyInResponse)
        }
    }
}