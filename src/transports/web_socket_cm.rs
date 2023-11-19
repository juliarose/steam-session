use crate::enums::Msg;
use crate::proto::steammessages_base::CMsgProtoBufHeader;

use super::ApiRequest2;
use super::cm_server::CmServer;
use std::collections::HashMap;
use std::io::Cursor;
use chrono::Duration;
use futures::stream::SplitSink;
use reqwest::Client;
use reqwest::header::{HeaderMap, HeaderValue, InvalidHeaderValue};
use reqwest::header::{USER_AGENT, ACCEPT_CHARSET, ACCEPT};
use tokio::net::TcpStream;
use tokio::sync::mpsc::error::SendError;
use tokio::task::JoinHandle;
use serde::{Serialize, Deserialize};
use serde::de::DeserializeOwned;
use rand::Rng;
use rand::seq::SliceRandom;
use byteorder::{BigEndian, ReadBytesExt};
use futures::StreamExt;
use tokio::sync::mpsc;
use tokio_tungstenite::{tungstenite, connect_async};
use tokio_tungstenite::{WebSocketStream, MaybeTlsStream};
use tokio_tungstenite::tungstenite::http::uri::{Uri, InvalidUri};
use tokio_tungstenite::tungstenite::http::request::Request;

struct Agent {}

const PROTOCOL_VERSION: u32 = 65580;
const PROTO_MASK: u32 = 0x80000000;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("{}", .0)]
    Reqwest(#[from] reqwest::Error),
    #[error("{}", .0)]
    InvalidHeaderValue(#[from] InvalidHeaderValue),
    #[error("No CM server available")]
    NoCmServer,
    #[error("The request returned a response without a list of servers")]
    NoCmServerList,
    #[error("CM server returned an error with message: {}", .0)]
    CmServerListResponseMessage(String),
    #[error("IO error with websocket: {}", .0)]
    OI(#[from] std::io::Error),
    #[error("HTTP error with websocket: {}", .0)]
    Http(#[from] tokio_tungstenite::tungstenite::http::Error),
    #[error("Invalid URI with websocket: {}", .0)]
    Url(#[from] InvalidUri),
    #[error("Connection error with websocket: {}", .0)]
    Connection(#[from] tungstenite::Error),
    #[error("Error parsing VDF body: {}", .0)]
    VdfParse(#[from]  keyvalues_serde::error::Error),
}

pub struct WebSocketCMTransport {
    connection_timeout: Duration,
    client: Client,
    agent: Agent,
    local_address: Option<String>,
    // todo tungsten websocket
    websocket: u8,
    writer: Option<SplitSink<WebSocketStream<MaybeTlsStream<TcpStream>>, tungstenite::Message>>,
    reader_task: Option<JoinHandle<()>>,
    jobs: HashMap<i64, JoinHandle<()>>,
    client_session_id: i32,
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
            client_session_id: 0,
        }
    }
    
    async fn send_request<T, D>(
        &self,
        request: ApiRequest2,
        body: &T,
    ) -> Result<D, Error>
    where
        T: Serialize,
        D: DeserializeOwned,
    {
        // todo handle errors
        self.send_message(
            Msg::ServiceMethodCallFromClientNonAuthed,
            body,
            Some(request.target_name()),
        ).await
    }
    
    async fn send_message<T, D>(
        &self,
        msg: Msg,
        body: &T,
        service_method_name: Option<String>,
    ) -> Result<D, Error>
    where
        T: Serialize,
        D: DeserializeOwned,
    {
        // make sure websocket is connected
        
        let mut proto_header = CMsgProtoBufHeader::default();
        let client_sessionid = if msg != Msg::ServiceMethodCallFromClientNonAuthed {
            self.client_session_id
        } else {
            0
        };
        
        proto_header.set_steamid(0);
        proto_header.set_client_sessionid(client_sessionid);
        
        if msg == Msg::ServiceMethodCallFromClientNonAuthed {
            let mut jobid_buffer = rand::thread_rng().gen::<[u8; 8]>();
            
            jobid_buffer[0] = jobid_buffer[0] & 0x7f;
            
            if let Some(service_method_name) = service_method_name {
                proto_header.set_target_job_name(service_method_name);
            }
            
            proto_header.set_realm(1);
            
            let mut jobid_buffer_reader = Cursor::new(jobid_buffer);
            let jobid = jobid_buffer_reader.read_i64::<BigEndian>()?;
            
        } else {
            // There's no response
        }
        
        todo!()
    }
    
    async fn connect_to_cm(&mut self) -> Result<mpsc::Receiver<Message>, Error> {
        // todo connect to ws
        let mut cm_list = self.get_cm_list().await?
            .into_iter()
            .filter(|cm_server| {
                cm_server.r#type == "websockets" &&
                cm_server.realm == "steamglobal"
            })
            .collect::<Vec<_>>();
        let upper_bound = std::cmp::min(20, cm_list.len());
        
        cm_list.truncate(upper_bound);
        
        // pick a random server
        let cm_server = cm_list
            .choose(&mut rand::thread_rng())
            .ok_or(Error::NoCmServer)?;
        let uri = format!("wss://{}/cmsocket/", cm_server.endpoint);
        // let uri = uri.parse::<Uri>()?;
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
    
    fn handle_ws_message(&self, msg: Vec<u8>) -> Result<(), Error> {
        todo!()
    }

    async fn get_cm_list(&self) -> Result<Vec<CmServer>, Error> {
        // todo handle errors
        self.fetch_cm_list().await
    }
    
    async fn fetch_cm_list(&self) -> Result<Vec<CmServer>, Error> {
        let url = "https://api.steampowered.com/ISteamDirectory/GetCMListForConnect/v0001/?cellid=0&format=vdf";
        let mut headers = HeaderMap::new();
        
        headers.append(USER_AGENT, HeaderValue::from_str("Valve/Steam HTTP Client 1.0")?);
        headers.append(ACCEPT_CHARSET,HeaderValue::from_str("ISO-8859-1,utf-8,*;q=0.7")?);
        headers.append(ACCEPT, HeaderValue::from_str("text/html,*/*;q=0.9")?);
        
        let text = self.client.get(url)
            .headers(headers)
            .send().await?
            .text().await?;
        
        parse_cm_list(&text)
    }
}

// todo test the deserialize from fixture
#[derive(Deserialize)]
struct CmBody {
    #[serde(default)]
    serverlist: Option<HashMap<usize, CmServer>>,
    #[serde(default)]
    success: i32,
    #[serde(default)]
    message: String,
}

fn parse_cm_list(text: &str) -> Result<Vec<CmServer>, Error> {
    let body = keyvalues_serde::from_str::<CmBody>(&text)?;
    
    if body.success != 1 {
        return Err(Error::CmServerListResponseMessage(body.message));
    }
    
    // there is probably a better way to get these into a vec without having to sort them...
    let mut serverlist = body.serverlist
        .ok_or(Error::NoCmServerList)?
        .into_iter()
        .collect::<Vec<_>>();
    
    serverlist.sort_by(|(a, _), (b, _)| a.cmp(b));
    
    let serverlist = serverlist
        .into_iter()
        .map(|(_, cmserver)| cmserver)
        .collect::<Vec<_>>();
    
    if serverlist.is_empty() {
        return Err(Error::NoCmServerList);
    }
    
    Ok(serverlist)
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn parse_vdf() {
        let text = include_str!("./fixtures/cmlist.vdf");
        let serverlist = parse_cm_list(&text).unwrap();
        
        assert_eq!(serverlist.first().unwrap().endpoint, "ext1-ord1.steamserver.net:27017");
    }
}