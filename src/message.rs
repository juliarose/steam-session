use crate::api_method::{ApiRequest, ApiResponse};
use crate::enums::EMsg;
use crate::transports::websocket::Error;
use bytes::{Buf, BytesMut};

pub trait NetMessage {
}

// #[derive(Debug, Clone)]
// pub struct RawNetMessage {
//     pub data: BytesMut,
// }

// impl RawNetMessage {
//     pub fn into_message<T: NetMessage>(self) -> Result<T, Error> {
//         if self.kind == T::KIND {
//             log::debug!(
//                 "reading body of {:?} message({} bytes)",
//                 self.kind,
//                 self.data.len()
//             );
//             let body = T::read_body(self.data, &self.header)?;
//             Ok(body)
//         } else {
//             Err(NetworkError::DifferentMessage(T::KIND, self.kind))
//         }
//     }
// }

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
