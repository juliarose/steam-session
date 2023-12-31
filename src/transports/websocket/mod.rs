pub mod cm_server;
pub mod cm_list_cache;

mod error;
mod message_filter;
mod message;
mod response;
mod helpers;

pub use cm_list_cache::Error as CmListError;
pub use error::Error;

use cm_list_cache::CmListCache;
use message_filter::MessageFilter;
use steam_session_proto::steammessages_clientserver_login::CMsgClientHello;

use crate::enums::EMsg;
use crate::net::ApiRequest;
use crate::proto::steammessages_base::CMsgProtoBufHeader;
use crate::transports::Transport;
use crate::authentication_client::Error as AuthenticationClientError;
use std::io::Cursor;
use std::sync::Arc;
use std::sync::atomic::{AtomicI32, Ordering};
use futures::stream::{SplitSink, SplitStream};
use futures::SinkExt;
use tokio::net::TcpStream;
use tokio::sync::{Mutex, oneshot};
use tokio_tungstenite::tungstenite;
use tokio_tungstenite::{WebSocketStream, MaybeTlsStream};
use protobuf::Message as ProtoMessage;
use byteorder::{BigEndian, LittleEndian, ReadBytesExt, WriteBytesExt};
use rand::Rng;
use async_trait::async_trait;
use lazy_static::lazy_static;

pub const PROTOCOL_VERSION: u32 = 65580;
pub const PROTO_MASK: u32 = 0x80000000;

lazy_static! {
    pub static ref DEFAULT_CM_LIST: Arc<Mutex<CmListCache>> = Arc::new(tokio::sync::Mutex::new(CmListCache::new()));
}

/// Represents a WebSocket CM transport.
#[derive(Debug)]
pub struct WebSocketCMTransport {
    websocket_write: tokio::sync::Mutex<SplitSink<WebSocketStream<MaybeTlsStream<TcpStream>>, tungstenite::Message>>,
    filter: Arc<MessageFilter>,
    client_sessionid: Arc<AtomicI32>,
}

#[async_trait]
impl Transport for WebSocketCMTransport {
    async fn send_request<Msg>(
        &self,
        msg: Msg,
        _access_token: Option<String>,
    ) -> Result<oneshot::Receiver<Result<Msg::Response, AuthenticationClientError>>, AuthenticationClientError> 
    where
        Msg: ApiRequest,
        <Msg as ApiRequest>::Response: Send,
    {
        if let Some(jobid) = self.send_message(
            <Msg as ApiRequest>::KIND,
            msg,
            Some(<Msg as ApiRequest>::NAME),
        ).await? {
            let filter_rx = self.filter.on_job_id(jobid);
            let (
                tx,
                rx,
            ) = oneshot::channel::<Result<Msg::Response, AuthenticationClientError>>();
            
            tokio::spawn(async move {
                tx.send(helpers::wait_for_response::<Msg>(filter_rx).await).ok();
            });
            
            Ok(rx)
        } else {
            Err(AuthenticationClientError::NoJob)
        }
    }
}

impl WebSocketCMTransport {
    /// Connects to a CM server.
    pub async fn connect() -> Result<WebSocketCMTransport, Error> {
        let transport = helpers::connect_to_cm(&DEFAULT_CM_LIST).await?;
        let mut hello = CMsgClientHello::new();
        
        hello.set_protocol_version(PROTOCOL_VERSION);
        transport.send_message(
            EMsg::ClientHello,
            hello,
            None,
        ).await?;
        
        Ok(transport)
    }
    
    /// Creates a new [`WebSocketCMTransport`].
    fn new(
        source: SplitStream<WebSocketStream<MaybeTlsStream<TcpStream>>>,
        websocket_write: SplitSink<WebSocketStream<MaybeTlsStream<TcpStream>>, tungstenite::Message>,
    ) -> Self {
        let client_sessionid = Arc::new(AtomicI32::new(0));
        let (filter, _rest) = MessageFilter::new(
            source,
            client_sessionid.clone(),
        );
        
        Self {
            websocket_write: tokio::sync::Mutex::new(websocket_write),
            filter: Arc::new(filter),
            client_sessionid,
        }
    }
    
    /// Sends a message to the CM server.
    async fn send_message<'a, Msg>(
        &self,
        emsg: EMsg,
        msg: Msg,
        service_method_name: Option<&'static str>,
    ) -> Result<Option<u64>, Error>
    where
        Msg: ApiRequest,
    {
        let mut body = msg.write_to_bytes()?;
        let mut proto_header = CMsgProtoBufHeader::default();
        let client_sessionid = if emsg != EMsg::ServiceMethodCallFromClientNonAuthed {
            self.client_sessionid.load(Ordering::Relaxed)
        } else {
            0
        };
        
        proto_header.set_steamid(0);
        proto_header.set_client_sessionid(client_sessionid);
        
        let jobid = if emsg == EMsg::ServiceMethodCallFromClientNonAuthed {
            let mut jobid_buffer = rand::thread_rng().gen::<[u8; 8]>();
            
            jobid_buffer[0] &= 0x7f;
            
            if let Some(target_job_name) = service_method_name {
                proto_header.set_target_job_name(target_job_name.to_string());
            }
            
            proto_header.set_realm(1);
            
            let mut jobid_buffer_reader = Cursor::new(jobid_buffer);
            let jobid = jobid_buffer_reader.read_u64::<BigEndian>()?;
            
            proto_header.set_jobid_source(jobid);
            
            Some(jobid)
        } else {
            None
        };
        let mut encoded_proto_header = Vec::new();
        
        proto_header.write_to_vec(&mut encoded_proto_header)?;
        
        let mut header: Vec<u8> = Vec::new();
        let header_length = encoded_proto_header.len() as u32;
        
        header.write_u32::<LittleEndian>(emsg as u32 | PROTO_MASK)?; // 4
        header.write_u32::<LittleEndian>(header_length)?; // 8
        
        if let Some(jobid) = jobid {
            log::debug!("Send {emsg:?} ({}; jobid {jobid})", service_method_name.unwrap_or("unnamed"));
        } else {
            log::debug!("Send {emsg:?} ({})", service_method_name.unwrap_or("unnamed"));
        }
        
        let mut message: Vec<u8> = Vec::new();
        
        message.append(&mut header);
        message.append(&mut encoded_proto_header);
        message.append(&mut body);
        
        let message = tungstenite::Message::binary(message);
        
        self.websocket_write.lock().await.send(message).await?;
        
        Ok(jobid)
    }
}