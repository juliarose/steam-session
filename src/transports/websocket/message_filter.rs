use super::{Error, Message};
use super::PROTO_MASK;
use crate::enums::{EMsg, EResult};
use crate::proto::steammessages_base::{CMsgProtoBufHeader, CMsgMulti};
use crate::proto::steammessages_clientserver_login::CMsgClientLogonResponse;
use crate::transports::ApiResponseBody;
use std::io::{Cursor, Read};
use std::sync::Arc;
use std::sync::atomic::{AtomicI32, Ordering};
use protobuf::Message as ProtoMessage;
use futures::stream::SplitStream;
use futures::StreamExt;
use tokio::net::TcpStream;
use tokio::sync::oneshot;
use tokio::sync::mpsc;
use dashmap::DashMap;
use byteorder::{LittleEndian, ReadBytesExt};
use tokio_tungstenite::tungstenite;
use tokio_tungstenite::{WebSocketStream, MaybeTlsStream};

pub type ResponseSender = oneshot::Sender<Result<ApiResponseBody, Error>>;
pub type ResponseReceiver = oneshot::Receiver<Result<ApiResponseBody, Error>>;

#[derive(Debug, Clone)]
pub struct MessageFilter {
    job_id_filters: Arc<DashMap<u64, oneshot::Sender<Result<ApiResponseBody, Error>>>>,
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
                            handle_ws_message(&filter_send, buffer);
                            // if let Err(error) = rest_tx.send(Ok(Message { })).await {
                            //     break;
                            // }
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
    
    pub fn on_job_id(&self, id: u64) -> oneshot::Receiver<Result<ApiResponseBody, Error>> {
        let (tx, rx) = oneshot::channel();
        self.job_id_filters.insert(id, tx);
        rx
    }
}

async fn process_multi_message(filter: &MessageFilter, body_buffer: &Vec<u8>) -> Result<(), Error> {
    let body = CMsgMulti::parse_from_bytes(body_buffer)?;
    let payload: &[u8] = body.get_message_body();
    
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
        
        // handle_ws_message(filter, chunk_buffer).await?;
    }
    
    Ok(())
}

#[derive(Debug)]
struct MessageData {
    eresult: EResult,
    emsg: EMsg,
    body: Vec<u8>,
    header: CMsgProtoBufHeader,
    jobid_target: u64,
    client_sessionid: i32,
}

async fn handle_ws_message(filter: &MessageFilter, msg: Vec<u8>) -> Result<(), Error> {
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
    
    if client_sessionid != 0 && client_sessionid != filter.client_sessionid.load(Ordering::Relaxed) {
        log::debug!("Got new client sessionid: {client_sessionid}");
        filter.client_sessionid.store(client_sessionid, Ordering::Relaxed);
    }
    
    let emsg = EMsg::try_from(raw_emsg)
        .map_err(|_| Error::UnknownEMsg(raw_emsg))?;
    let jobid_target = header.get_jobid_target();
    let eresult =  EResult::try_from(header.get_eresult())
        .map_err(|_| Error::UnknownEResult(header.get_eresult()))?;
    
    // I'm not sure when this would be 0
    log::debug!("handle_ws_message jobid {jobid_target}");
    
    if jobid_target != 0 {
        if let Some((_, tx)) = filter
            .job_id_filters
            .remove(&jobid_target)
        {
            // todo maybe propogate the error
            let _ = tx.send(Ok(ApiResponseBody {
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
            // websocket connection should be closed
            
            return Err(Error::ClientLogOnResponseTryAnotherCM(eresult));
        },
        EMsg::Multi => {
            process_multi_message(filter, &body_buffer).await?;
        },
        emsg => {
            log::debug!("Received unexpected message: {emsg:?}");
        },
    }
    
    todo!()
}