mod error;
mod message_filter;
mod message;

use message_filter::MessageFilter;
pub use error::Error;
pub use message::Message;

use crate::message::ApiResponseMessage;
use crate::enums::EMsg;
use crate::proto::steammessages_base::CMsgProtoBufHeader;
use crate::api_method::ApiRequest;
use crate::transports::cm_list_cache::CmListCache;
use crate::transports::ApiResponse2;
use std::io::Cursor;
use std::sync::Arc;
use std::sync::atomic::{AtomicI32, Ordering};
use chrono::Duration;
use protobuf::Message as ProtoMessage;
use futures::stream::{SplitSink, SplitStream};
use futures::{SinkExt, StreamExt};
use reqwest::Client;
use tokio::net::TcpStream;
use tokio::sync::oneshot;
use tokio::sync::mpsc;
use rand::Rng;
use byteorder::{BigEndian, LittleEndian, ReadBytesExt, WriteBytesExt};
use tokio::time::timeout;
use tokio_tungstenite::{tungstenite, connect_async};
use tokio_tungstenite::{WebSocketStream, MaybeTlsStream};
use tokio_tungstenite::tungstenite::http::uri::Uri;
use tokio_tungstenite::tungstenite::http::request::Request;

pub const PROTOCOL_VERSION: u32 = 65580;
pub const PROTO_MASK: u32 = 0x80000000;

async fn wait_for_response<Msg>(
    rx: oneshot::Receiver<Result<ApiResponse2, Error>>,
) -> Result<Msg::Response, Error>
where
    Msg: ApiRequest,
    <Msg as ApiRequest>::Response: Send,
{
    // timeout(std::time::Duration::from_secs(5), rx)
    //     .await
    //     .map_err(|_| Error::Timeout)???
    //     .into_message::<ApiResponseMessage>()?
    //     .into_response::<Msg>()
    todo!()
}

#[derive(Debug)]
struct Agent {}

#[derive(Debug)]
pub struct WebSocketCMTransport {
    connection_timeout: Duration,
    client: Client,
    agent: Agent,
    local_address: Option<String>,
    websocket_write: SplitSink<WebSocketStream<MaybeTlsStream<TcpStream>>, tungstenite::Message>,
    writer: tokio::sync::mpsc::Sender<Message>,
    filter: Arc<MessageFilter>,
    client_sessionid: Arc<AtomicI32>,
}

impl WebSocketCMTransport {
    pub async fn connect() -> Result<WebSocketCMTransport, Error> {
        let cm_list = Arc::new(tokio::sync::Mutex::new(CmListCache::new()));
        let transport = connect_to_cm(&cm_list).await?;
        
        Ok(transport)
    }
    
    pub fn new(
        source: SplitStream<WebSocketStream<MaybeTlsStream<TcpStream>>>,
        writer: tokio::sync::mpsc::Sender<Message>,
        websocket_write: SplitSink<WebSocketStream<MaybeTlsStream<TcpStream>>, tungstenite::Message>,
    ) -> Self {
        let client_sessionid = Arc::new(AtomicI32::new(0));
        let (filter, _rest) = MessageFilter::new(
            source,
            client_sessionid.clone(),
        );
        
        Self {
            connection_timeout: Duration::seconds(10),
            client: Client::new(),
            agent: Agent {},
            local_address: None,
            websocket_write,
            writer,
            filter: Arc::new(filter),
            client_sessionid,
        }
    }
    
    pub async fn send_request<'a, Msg>(
        &mut self,
        msg: Msg,
        body: Vec<u8>,
    ) -> Result<Option<()>, Error> 
    where
        Msg: ApiRequest,
        <Msg as ApiRequest>::Response: Send,
    {
        let mut attempts = 0;
        // todo handle errors
        if let Some(jobid) = self.send_message(
            EMsg::ServiceMethodCallFromClientNonAuthed,
            msg,
            body,
            Some(Msg::NAME),
        ).await? {
            let filter_rx = self.filter.on_job_id(jobid);
            let (
                tx,
                rx,
            ) = oneshot::channel::<Result<Msg::Response, Error>>();
            
            tokio::spawn(async move {
                tx.send(wait_for_response::<Msg>(filter_rx).await).ok();
            });
            
            Ok(Some(()))
        } else {
            Ok(None)
        }
    }
    
    async fn send_message<'a, Msg>(
        &mut self,
        emsg: EMsg,
        msg: Msg,
        mut body: Vec<u8>,
        service_method_name: Option<&'static str>,
    ) -> Result<Option<u64>, Error>
    where
        Msg: ApiRequest,
    {
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
            
            // let timeout = tokio::spawn(async_std::task::sleep(std::time::Duration::from_secs(5)));
            
            // self.jobs.insert(jobid, (tx, timeout));
            Some(jobid)
        } else {
            // There's no response
            // todo maybe propogate this error
            // let _  = tx.send(Err(Error::NoResponse));
            None
        };
        let mut encoded_proto_header = Vec::new();
        
        proto_header.write_to_vec(&mut encoded_proto_header)?;
        
        let mut header: Vec<u8> = Vec::new();
        let emsg = (emsg as u32 | PROTO_MASK) >> 0;
        let header_length = encoded_proto_header.len() as u32;
        
        header.write_u32::<LittleEndian>(emsg)?; // 4
        header.write_u32::<LittleEndian>(header_length)?; // 8
        
        log::debug!("Send {emsg:?}");
        
        let mut message: Vec<u8> = Vec::new();
        
        message.append(&mut header);
        message.append(&mut encoded_proto_header);
        message.append(&mut body);
        
        let message = tungstenite::Message::binary(message);
        
        self.websocket_write.send(message).await?;
        
        Ok(jobid)
    }
}

async fn connect_to_cm(cm_list: &Arc<tokio::sync::Mutex<CmListCache>>) -> Result<WebSocketCMTransport, Error> {
    let cm_server = {
        let mut cm_list = cm_list.lock().await;
        
        cm_list.update().await?;
        // pick a random server
        cm_list.pick_random_websocket_server()
    }.ok_or(Error::NoCmServer)?;
    let uri = format!("wss://{}/cmsocket/", cm_server.endpoint).parse::<Uri>()?;
    let request = Request::builder()
        .uri(uri)
        .body(())?;
    let (ws_stream, _) = connect_async(request).await?;
    let (ws_write, ws_read) = ws_stream.split();
    let (write, read) = mpsc::channel::<Message>(100);
    let transport = WebSocketCMTransport::new(
        ws_read,
        write,
        ws_write,
    );
    
    Ok(transport)
}