use crate::api_method::{ApiRequest, ApiResponse};
use crate::transports::websocket::Error;
use bytes::{Buf, BytesMut};

#[derive(Debug)]
pub struct ApiRequestMessage {
    job_name: String,
    body: BytesMut,
}

impl ApiRequestMessage {
    pub fn into_message<Request: ApiRequest>(
        self,
    ) -> Result<Request, Error> {
        if self.job_name == Request::NAME {
            let response = Request::parse_from_reader(&mut self.body.reader())?;
            // .map_err(|e| MalformedBody(Self::NAME, e.into()))?,
            
            Ok(response)
        } else {
            Err(Error::DifferentServiceMethod(
                Request::NAME,
                self.job_name,
            ))
        }
    }
}

#[derive(Debug)]
pub struct ApiResponseMessage {
    job_name: String,
    body: BytesMut,
}

impl ApiResponseMessage {
    pub fn into_response<Request: ApiRequest>(
        self,
    ) -> Result<Request::Response, Error> {
        if self.job_name == Request::NAME {
            let response = Request::Response::parse_from_reader(&mut self.body.reader())?;
            
            Ok(response)
        } else {
            Err(Error::DifferentServiceMethod(
                Request::NAME,
                self.job_name,
            ))
        }
    }
}
