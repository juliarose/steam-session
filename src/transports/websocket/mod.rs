mod error;
mod message_filter;
mod message;
mod response;

use response::ApiResponseBody;
use message_filter::MessageFilter;
pub use error::Error;
use steam_session_proto::steammessages_clientserver_login::CMsgClientHello;

use crate::enums::EMsg;
use crate::net::ApiRequest;
use crate::proto::steammessages_base::CMsgProtoBufHeader;
use crate::transports::cm_list_cache::CmListCache;
use crate::transports::Transport;
use crate::authentication_client::Error as AuthenticationClientError;
use std::io::Cursor;
use std::sync::Arc;
use std::sync::atomic::{AtomicI32, Ordering};
use protobuf::Message as ProtoMessage;
use futures::stream::{SplitSink, SplitStream};
use futures::{SinkExt, StreamExt};
use rand::Rng;
use byteorder::{BigEndian, LittleEndian, ReadBytesExt, WriteBytesExt};
use tokio::time::timeout;
use tokio::net::TcpStream;
use tokio::sync::oneshot;
use tokio_tungstenite::{tungstenite, connect_async};
use tokio_tungstenite::{WebSocketStream, MaybeTlsStream};
use tokio_tungstenite::tungstenite::http::uri::Uri;
use tokio_tungstenite::tungstenite::http::request::Request;
use async_trait::async_trait;

pub const PROTOCOL_VERSION: u32 = 65580;
pub const PROTO_MASK: u32 = 0x80000000;

// const CONNECTION_TIMEOUT_SECONDS: i64 = 10;

async fn wait_for_response<Msg>(
    rx: oneshot::Receiver<Result<ApiResponseBody, Error>>,
) -> Result<Msg::Response, AuthenticationClientError>
where
    Msg: ApiRequest,
    <Msg as ApiRequest>::Response: Send,
{
    match timeout(std::time::Duration::from_secs(5), rx).await {
        Ok(response) => {
            let body = response??;
            let response = body.into_response::<Msg>()?;
            
            Ok(response)
        },
        Err(_error) => {
            log::debug!("Timed out waiting for response from {}", <Msg as ApiRequest>::NAME);
            Err(Error::Timeout.into())
        },
    }
}

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
    ) -> Result<Option<oneshot::Receiver<Result<Msg::Response, AuthenticationClientError>>>, AuthenticationClientError> 
    where
        Msg: ApiRequest,
        <Msg as ApiRequest>::Response: Send,
    {
        if let Some(jobid) = self.send_message(
            EMsg::ServiceMethodCallFromClientNonAuthed,
            msg,
            Some(<Msg as ApiRequest>::NAME),
        ).await? {
            let filter_rx = self.filter.on_job_id(jobid);
            let (
                tx,
                rx,
            ) = oneshot::channel::<Result<Msg::Response, AuthenticationClientError>>();
            
            tokio::spawn(async move {
                tx.send(wait_for_response::<Msg>(filter_rx).await).ok();
            });
            
            Ok(Some(rx))
        } else {
            Ok(None)
        }
    }
}

impl WebSocketCMTransport {
    pub async fn connect() -> Result<WebSocketCMTransport, Error> {
        let cm_list = Arc::new(tokio::sync::Mutex::new(CmListCache::new()));
        let transport = connect_to_cm(&cm_list).await?;
        let mut hello = CMsgClientHello::new();
        
        hello.set_protocol_version(PROTOCOL_VERSION);
        
        transport.send_message(
            EMsg::ClientHello,
            hello,
            None,
        ).await?;
        
        Ok(transport)
    }
    
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
            
            jobid_buffer[0] = jobid_buffer[0] & 0x7f;
            
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
        
        header.write_u32::<LittleEndian>((emsg as u32 | PROTO_MASK) >> 0)?; // 4
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

/// Generate a random key for the `Sec-WebSocket-Key` header.
fn generate_key() -> String {
    // a base64-encoded (see Section 4 of [RFC4648]) value that,
    // when decoded, is 16 bytes in length (RFC 6455)
    let r: [u8; 16] = rand::random();
    data_encoding::BASE64.encode(&r)
}

async fn connect_to_cm(cm_list: &Arc<tokio::sync::Mutex<CmListCache>>) -> Result<WebSocketCMTransport, Error> {
    let cm_server = {
        let mut cm_list = cm_list.lock().await;
        
        cm_list.update().await?;
        // pick a random server
        cm_list.pick_random_websocket_server()
    }.ok_or(Error::NoCmServer)?;
    let connect_addr = format!("wss://{}/cmsocket/", cm_server.endpoint);
    // let connect_timeout = Duration::seconds(CONNECTION_TIMEOUT_SECONDS);
    let uri = connect_addr.parse::<Uri>()?;
    let authority = uri.authority()
        .ok_or(Error::UrlNoHostName)?.as_str();
    let host = authority
        .find('@')
        .map(|idx| authority.split_at(idx + 1).1)
        .unwrap_or_else(|| authority);
    let request = Request::builder()
        .header("batch-test", "true")
        .header("Host", host)
        .header("Connection", "Upgrade")
        .header("Upgrade", "websocket")
        .header("Sec-WebSocket-Version", "13")
        .header("Sec-WebSocket-Key", generate_key())
        .uri(uri)
        .body(())?;
    // todo use timeout when connecting
    let (ws_stream, _) = connect_async(request).await?;
    let (ws_write, ws_read) = ws_stream.split();
    let transport = WebSocketCMTransport::new(
        ws_read,
        ws_write,
    );
    
    Ok(transport)
}