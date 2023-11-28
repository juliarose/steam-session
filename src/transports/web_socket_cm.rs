use crate::enums::{EMsg, EResult};
use crate::proto::steammessages_base::{CMsgProtoBufHeader, CMsgMulti};
use crate::proto::steammessages_clientserver_login::CMsgClientLogonResponse;
use crate::api_method::ApiRequest;
use super::cm_list_cache::CmListCache;
use super::{ApiResponse2, cm_list_cache};
use std::collections::HashMap;
use std::io::{Cursor, Read};
use std::convert::TryFrom;
use std::sync::Arc;
use std::sync::atomic::{AtomicI32, Ordering};
use chrono::Duration;
use protobuf::{ProtobufError, Message as ProtoMessage};
use futures::stream::{SplitSink, SplitStream};
use reqwest::Client;
use reqwest::header::HeaderMap;
use tokio::net::TcpStream;
use tokio::task::JoinHandle;
use tokio::sync::oneshot;
use tokio::sync::mpsc;
use dashmap::DashMap;
use rand::Rng;
use byteorder::{BigEndian, LittleEndian, ReadBytesExt, WriteBytesExt};
use futures::StreamExt;
use tokio_tungstenite::{tungstenite, connect_async};
use tokio_tungstenite::{WebSocketStream, MaybeTlsStream};
use tokio_tungstenite::tungstenite::http::uri::{Uri, InvalidUri};
use tokio_tungstenite::tungstenite::http::request::Request;

#[derive(Debug)]
struct Agent {}

const PROTOCOL_VERSION: u32 = 65580;
const PROTO_MASK: u32 = 0x80000000;

pub type ResponseSender = oneshot::Sender<Result<ApiResponse2, Error>>;
pub type ResponseReceiver = oneshot::Receiver<Result<ApiResponse2, Error>>;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("No CM server available")]
    NoCmServer,
    #[error("{}", .0)]
    CmServer(#[from] cm_list_cache::Error),
    #[error("IO error with websocket: {}", .0)]
    OI(#[from] std::io::Error),
    #[error("HTTP error with websocket: {}", .0)]
    Http(#[from] tokio_tungstenite::tungstenite::http::Error),
    #[error("Invalid URI with websocket: {}", .0)]
    Url(#[from] InvalidUri),
    #[error("Connection error with websocket: {}", .0)]
    Connection(#[from] tungstenite::Error),
    #[error("Received unexpected non-protobuf message: {}", .0)]
    UnexpectedNonProtobufMessage(u32),
    #[error("Error with protobuf message: {}", .0)]
    Proto(#[from] ProtobufError),
    #[error("Unknown EMsg: {}", .0)]
    UnknownEMsg(u32),
    #[error("Unknown EResult: {}", .0)]
    UnknownEResult(i32),
    #[error("No response")]
    NoResponse,
}

#[derive(Debug, Clone)]
struct MessageFilter {
    job_id_filters: Arc<DashMap<u64, oneshot::Sender<Result<ApiResponse2, Error>>>>,
    client_sessionid: Arc<AtomicI32>,
}

impl MessageFilter {
    pub fn new(
        mut source: SplitStream<WebSocketStream<MaybeTlsStream<TcpStream>>>,
        client_sessionid: Arc<AtomicI32>,
    ) -> (Self, mpsc::Receiver<Result<Message, Error>>) {
        let (rest_tx, rx) = mpsc::channel::<Result<Message, Error>>(16);
        let filter = MessageFilter {
            job_id_filters: Default::default(),
            client_sessionid,
        };
        let filter_send = filter.clone();
        
        tokio::spawn(async move {
            while let Some(res) = source.next().await {
                match res {
                    Ok(message) => match message {
                        tungstenite::Message::Binary(buffer) => {
                            // if let Some((_, tx)) = filter_send
                            //     .job_id_filters
                            //     .remove(&message.header.target_job_id)
                            // {
                            //     tx.send(message).ok();
                            // } else {
                            //     rest_tx.send(Ok(message)).await.ok();
                            // }
                            if let Err(error) = rest_tx.send(Ok(Message { })).await {
                                break;
                            }
                        },
                        other => {
                            // log::debug!("Websocket received message with type other than binary from {}", cm_server_read.endpoint);
                        },
                    },
                    Err(error) => {
                        
                    },
                }
            }
        });
        
        (filter, rx)
    }
}

#[derive(Debug)]
pub struct WebSocketCMTransport {
    connection_timeout: Duration,
    client: Client,
    agent: Agent,
    local_address: Option<String>,
    // todo tungsten websocket
    websocket: u8,
    writer: Option<SplitSink<WebSocketStream<MaybeTlsStream<TcpStream>>, tungstenite::Message>>,
    reader_task: Option<JoinHandle<()>>,
    jobs: HashMap<u64, (ResponseSender, JoinHandle<()>)>,
    // filter: Arc<MessageFilter>,
    client_sessionid: Arc<AtomicI32>,
    cm_list: Arc<tokio::sync::Mutex<CmListCache>>,
}

pub struct Message {
    
}

impl WebSocketCMTransport {
    pub fn new() -> Self {
        Self {
            connection_timeout: Duration::seconds(10),
            client: Client::new(),
            agent: Agent {},
            local_address: None,
            websocket: 0,
            writer: None,
            reader_task: None,
            jobs: HashMap::new(),
            // filter: Arc::new(MessageFilter::new()),
            client_sessionid: Arc::new(AtomicI32::new(0)),
            cm_list: Arc::new(tokio::sync::Mutex::new(CmListCache::new()))
        }
    }
    
    pub async fn send_request<'a, Msg>(
        &mut self,
        msg: Msg,
        access_token: Option<String>,
        headers: Option<HeaderMap>,
        body: &'a [u8],
    ) -> Result<Vec<u8>, Error> 
    where
        Msg: ApiRequest,
        <Msg as ApiRequest>::Response: Send,
    {
        let mut attempts = 0;
        // todo handle errors
        self.send_message(
            EMsg::ServiceMethodCallFromClientNonAuthed,
            msg,
            body,
            Some(Msg::NAME),
        ).await
    }
    
    async fn send_message<'a, Msg>(
        &mut self,
        emsg: EMsg,
        msg: Msg,
        body: &'a [u8],
        service_method_name: Option<&'static str>,
    ) -> Result<Vec<u8>, Error>
    where
        Msg: ApiRequest,
        <Msg as ApiRequest>::Response: Send,
    {
        // make sure websocket is connected
        
        let mut proto_header = CMsgProtoBufHeader::default();
        let client_sessionid = if emsg != EMsg::ServiceMethodCallFromClientNonAuthed {
            self.client_sessionid.load(Ordering::Relaxed)
        } else {
            0
        };
        
        proto_header.set_steamid(0);
        proto_header.set_client_sessionid(client_sessionid);

        let (tx, rx) = oneshot::channel();
        
        if emsg == EMsg::ServiceMethodCallFromClientNonAuthed {
            let mut jobid_buffer = rand::thread_rng().gen::<[u8; 8]>();
            
            jobid_buffer[0] = jobid_buffer[0] & 0x7f;
            
            if let Some(target_job_name) = service_method_name {
                proto_header.set_target_job_name(target_job_name.to_string());
            }
            
            proto_header.set_realm(1);
            
            let mut jobid_buffer_reader = Cursor::new(jobid_buffer);
            let jobid = jobid_buffer_reader.read_u64::<BigEndian>()?;
            
            proto_header.set_jobid_source(jobid);
            
            let timeout = tokio::spawn(async_std::task::sleep(std::time::Duration::from_secs(5)));
            
            self.jobs.insert(jobid, (tx, timeout));
        } else {
            // There's no response
            // todo maybe propogate this error
            let _  = tx.send(Err(Error::NoResponse));
        }

        let mut encoded_proto_header = Vec::new();
        
        proto_header.write_to_vec(&mut encoded_proto_header)?;
        
        let mut header: Vec<u8> = Vec::new();
        let emsg = (emsg as u32 | PROTO_MASK) >> 0;
        let header_length = encoded_proto_header.len() as u32;
        
        // 4
        header.write_u32::<LittleEndian>(emsg)?;
        // 8
        header.write_u32::<LittleEndian>(header_length)?;
        
        log::debug!("Send {emsg:?}");
        
        
        Ok(Vec::new())
    }
    
    async fn connect_to_cm(&mut self) -> Result<mpsc::Receiver<Message>, Error> {
        let cm_server = {
            let mut cm_list = self.cm_list.lock().await;
            
            cm_list.update().await?;
            // pick a random server
            cm_list.pick_random_websocket_server()
        }.ok_or(Error::NoCmServer)?;
        let uri = format!("wss://{}/cmsocket/", cm_server.endpoint).parse::<Uri>()?;
        let request = Request::builder()
            .uri(uri)
            .body(())?;
        let (ws_stream, _) = connect_async(request).await?;
        let (ws_write, mut ws_read) = ws_stream.split();
        let (write, read) = mpsc::channel::<Message>(100);
        // clone to move into reader task
        let cm_server_read = cm_server.clone();
        
        self.writer = Some(ws_write);
        self.reader_task = Some(tokio::spawn(async move {
            while let Some(result) = ws_read.next().await {
                match result {
                    Ok(message) => match message {
                        tungstenite::Message::Binary(buffer) => {
                            if let Err(error) = write.send(Message { }).await {
                                break;
                            }
                        },
                        other => {
                            log::debug!("Websocket received message with type other than binary from {}", cm_server_read.endpoint);
                        },
                    },
                    Err(error) => {
                        
                    },
                }
            }
        }));
        
        Ok(read)
    }
    
    fn handle_ws_message(&mut self, msg: Vec<u8>) -> Result<(), Error> {
        let mut cursor = Cursor::new(msg.as_slice());
        let raw_emsg = cursor.read_u32::<LittleEndian>()?;
        let header_length = cursor.read_u32::<LittleEndian>()?;
        let mut header_buffer: Vec<u8> = vec![0; header_length as usize];

        cursor.read(&mut header_buffer)?;

        let mut body_buffer: Vec<u8> = Vec::new();

        cursor.read_to_end(&mut body_buffer)?;

        if raw_emsg & PROTO_MASK == 0 {
            return Err(Error::UnexpectedNonProtobufMessage(raw_emsg));
        }

        let header = CMsgProtoBufHeader::parse_from_bytes(&header_buffer)?;
        let client_sessionid = header.get_client_sessionid();
        
        if client_sessionid != 0 && client_sessionid != self.client_sessionid.load(Ordering::Relaxed) {

        }

        let emsg = EMsg::try_from(raw_emsg)
            .map_err(|_| Error::UnknownEMsg(raw_emsg))?;
        let jobid_target = header.get_jobid_target();

        // I'm not sure when this would be 0
        log::debug!("handle_ws_message jobid {jobid_target}");

        if jobid_target != 0 {
            if let Some((sender, job)) = self.jobs.remove(&jobid_target) {
                job.abort();
                
                let eresult =  EResult::try_from(header.get_eresult())
                    .map_err(|_| Error::UnknownEResult(header.get_eresult()))?;
                // todo maybe handle propogate the error
                let _ = sender.send(Ok(ApiResponse2 {
                    eresult: Some(eresult),
                    error_message: None,
                    body: Some(body_buffer),
                }));

                return Ok(());
            }
        }

        // this isn't a response message, so figure out what it is
        match emsg {
            // The only time we expect to receive ClientLogOnResponse is when the CM is telling us to try another CM
            EMsg::ClientLogOnResponse => {
                let logon_response = CMsgClientLogonResponse::parse_from_bytes(&body_buffer)?;
                let eresult =  EResult::try_from(logon_response.get_eresult())
                    .map_err(|_| Error::UnknownEResult(logon_response.get_eresult()))?;

                log::debug!("Received ClientLogOnResponse with result: {eresult:?}");

                // todo abort all pending jobs
                // for (let i in this._jobs) {
				// 	let {reject, timeout} = this._jobs[i];
				// 	clearTimeout(timeout);
				// 	reject(eresultError(logOnResponse.eresult));
				// }
            },
            EMsg::Multi => {
            
            },
            emsg => {
                log::debug!("Received unexpected message: {emsg:?}");
            },
        }
        
        todo!()
    }
    
    pub async fn process_multi_message(&mut self, body_buffer: &Vec<u8>) -> Result<(), Error> {
        let body = CMsgMulti::parse_from_bytes(body_buffer)?;
        let payload = body.get_message_body();
        
        if body.get_size_unzipped() != 0 {
            // todo decompress from zlib
            // We need to decompress it
            // payload = await new Promise((resolve, reject) => {
			// 	Zlib.gunzip(payload, (err, unzipped) => {
			// 		if (err) {
			// 			return reject(err);
			// 		}
			
			// 		resolve(unzipped);
			// 	});
			// });
        }
        
        let mut cursor = Cursor::new(payload);
        
        while let Ok(chunk_size) = cursor.read_u32::<LittleEndian>() {
            let mut chunk_buffer: Vec<u8> = vec![0; chunk_size as usize];
            
            cursor.read(&mut chunk_buffer)?;
            
            self.handle_ws_message(chunk_buffer)?;
        }
        
        Ok(())
    }
}