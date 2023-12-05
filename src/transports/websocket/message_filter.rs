use super::{Error, Message};
use super::PROTO_MASK;
use crate::enums::{EMsg, EResult};
use crate::proto::steammessages_base::{CMsgProtoBufHeader, CMsgMulti};
use crate::proto::steammessages_clientserver_login::CMsgClientLogonResponse;
use crate::transports::ApiResponseBody;
use std::io::{Cursor, Read};
use std::sync::Arc;
use std::sync::atomic::{AtomicI32, Ordering};
use futures::stream::SplitStream;
use futures::StreamExt;
use tokio::net::TcpStream;
use tokio::sync::{oneshot, mpsc};
use tokio_tungstenite::tungstenite;
use tokio_tungstenite::{WebSocketStream, MaybeTlsStream};
use dashmap::DashMap;
use protobuf::Message as ProtoMessage;
use byteorder::{LittleEndian, ReadBytesExt};
use flate2::read::GzDecoder;

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
        let (
            _rest_tx,
            rx,
        ) = mpsc::channel::<Result<Message, Error>>(16);
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
                            if let Err(error) = handle_ws_message(&filter_send, buffer) {
                                log::warn!("Error handling websocket message: {}", error);
                            }
                        },
                        _ => {
                            log::debug!("Websocket received message with type other than binary");
                        },
                    },
                    Err(error) => {
                        log::warn!("Error received from websocket connection {}", error);
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

fn process_multi_message(
    filter: &MessageFilter,
    body_buffer: &Vec<u8>,
) -> Result<(), Error> {
    let message = CMsgMulti::parse_from_bytes(body_buffer)?;
    let payload = message.get_message_body();
    let mut s = String::new();
    let payload = if message.get_size_unzipped() != 0 {
        GzDecoder::new(payload).read_to_string(&mut s)?;
        
        s.as_bytes()
    } else {
        payload
    };
    let mut cursor = Cursor::new(payload);
    
    while let Ok(chunk_size) = cursor.read_u32::<LittleEndian>() {
        let mut chunk_buffer: Vec<u8> = vec![0; chunk_size as usize];
        
        cursor.read(&mut chunk_buffer)?;
        
        check_ws_message(filter, chunk_buffer)?;
    }
    
    Ok(())
}

#[derive(Debug)]
struct MessageData {
    eresult: EResult,
    emsg: EMsg,
    body: Vec<u8>,
    jobid_target: u64,
    client_sessionid: i32,
}

fn parse_message(msg: Vec<u8>) -> Result<MessageData, Error> {
    let mut cursor = Cursor::new(msg.as_slice());
    let raw_emsg = cursor.read_u32::<LittleEndian>()?;
    let header_length = cursor.read_u32::<LittleEndian>()?;
    let mut header_buffer: Vec<u8> = vec![0; header_length as usize];
    
    cursor.read(&mut header_buffer)?;
    
    let mut body: Vec<u8> = Vec::new();
    
    cursor.read_to_end(&mut body)?;
    
    if raw_emsg & PROTO_MASK == 0 {
        return Err(Error::UnexpectedNonProtobufMessage(raw_emsg));
    }
    
    let header = CMsgProtoBufHeader::parse_from_bytes(&header_buffer)?;
    let client_sessionid = header.get_client_sessionid();
    let emsg = EMsg::try_from(raw_emsg)
        .map_err(|_| Error::UnknownEMsg(raw_emsg))?;
    let jobid_target = header.get_jobid_target();
    let eresult =  EResult::try_from(header.get_eresult())
        .map_err(|_| Error::UnknownEResult(header.get_eresult()))?;
    
    Ok(MessageData {
        eresult,
        emsg,
        jobid_target,
        client_sessionid,
        body,
    })
}

fn check_ws_message(filter: &MessageFilter, msg: Vec<u8>) -> Result<Option<(EMsg, Vec<u8>)>, Error> {
    let MessageData {
        eresult,
        emsg,
        jobid_target,
        client_sessionid,
        body,
    } = parse_message(msg)?;
    
    if client_sessionid != 0 && client_sessionid != filter.client_sessionid.load(Ordering::Relaxed) {
        log::debug!("Got new client sessionid: {client_sessionid}");
        filter.client_sessionid.store(client_sessionid, Ordering::Relaxed);
    }
    
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
                body: Some(body),
            }));
            
            return Ok(None);
        }
    }
    
    Ok(Some((emsg, body)))
}

fn handle_ws_message(filter: &MessageFilter, msg: Vec<u8>) -> Result<(), Error> {
    if let Some((emsg, body)) = check_ws_message(filter, msg)? {
        // this isn't a response message, so figure out what it is
        match emsg {
            // The only time we expect to receive ClientLogOnResponse is when the CM is telling us to try another CM
            EMsg::ClientLogOnResponse => {
                let logon_response = CMsgClientLogonResponse::parse_from_bytes(&body)?;
                let eresult =  EResult::try_from(logon_response.get_eresult())
                    .map_err(|_| Error::UnknownEResult(logon_response.get_eresult()))?;
                
                log::debug!("Received ClientLogOnResponse with result: {eresult:?}");
                // websocket connection should be closed
                
                return Err(Error::ClientLogOnResponseTryAnotherCM(eresult));
            },
            EMsg::Multi => {
                process_multi_message(filter, &body)?;
            },
            emsg => {
                log::debug!("Received unexpected message: {emsg:?}");
            },
        }
    }
    
    Ok(())
}