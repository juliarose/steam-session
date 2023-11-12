use super::cm_server::CmServer;
use std::collections::HashMap;
use chrono::Duration;
use reqwest::Client;
use reqwest::header::{HeaderMap, HeaderValue, InvalidHeaderValue};
use reqwest::header::{USER_AGENT, ACCEPT_CHARSET, ACCEPT};
use tokio::task::JoinHandle;

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
}

pub struct WebSocketCMTransport {
    connection_timeout: Duration,
    client: Client,
    agent: Agent,
    local_address: Option<String>,
    // todo tungsten websocket
    websocket: u8,
    jobs: HashMap<u32, JoinHandle<()>>,
    client_session_id: u32,
}

impl WebSocketCMTransport {
    pub fn new() -> Self {
        Self {
            connection_timeout: Duration::seconds(10),
            client: Client::new(),
            agent: Agent {},
            local_address: None,
            websocket: 0,
            jobs: HashMap::new(),
            client_session_id: 0,
        }
    }

    async fn connect_to_cm(&self) -> Result<(), Error> {
        // todo connect to ws
        let cm_list = self.get_cm_list().await?
            .into_iter()
            .filter(|cm_server| {
                cm_server.r#type == "websockets" &&
                cm_server.realm == "steamglobal"
            })
            .collect::<Vec<_>>();
        // pick a random server
        let cm_server = cm_list.first()
            .ok_or(Error::NoCmServer)?;
        let url = format!("wss://{}/cmsocket/", cm_server.endpoint);

        Ok(())
    }

    fn handle_ws_message(msg: Vec<u8>) {

    }

    async fn get_cm_list(&self) -> Result<Vec<CmServer>, Error> {
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

        // todo
        Ok(Vec::new())
    }
}