use bytes::Buf;
use steam_session::login_session::connect_ws;
use log::LevelFilter;
use steam_session::transports::Transport;
use steam_vent::{Connection, RawNetMessage, NetMessage};
use steam_session::authentication_client::Error;
use tokio::sync::{mpsc, oneshot};
use steam_vent::proto::steammessages_clientserver_login::CMsgClientLogon;
use steam_session::net::{ApiRequest, ApiResponse};
use async_trait::async_trait;
use steam_vent::proto::enums_clientserver::EMsg;

#[derive(Debug)]
pub struct Message {
    name: &'static str,
    buffer: Vec<u8>,
}

impl NetMessage for Message {
    const KIND: EMsg = EMsg::k_EMsgServiceMethodCallFromClientNonAuthed;
}

pub struct ClientTransport {
    sender: mpsc::Sender<(Message, oneshot::Sender<RawNetMessage>)>,
}

#[async_trait]
impl Transport for ClientTransport {
    async fn send_request<Msg>(
        &self,
        msg: Msg,
        _access_token: Option<String>,
    ) -> Result<oneshot::Receiver<Result<Msg::Response, Error>>, Error> 
    where
        Msg: ApiRequest,
        <Msg as ApiRequest>::Response: Send,
    {
        let (tx, rx) = oneshot::channel::<Result<Msg::Response, Error>>();
        let (conn_tx, conn_rx) = oneshot::channel::<RawNetMessage>();
        let mut buffer = Vec::new();
        
        msg.write_to_vec(&mut buffer).unwrap();
        
        let message = Message {
            name: <Msg as ApiRequest>::NAME,
            buffer,
        };
        
        self.sender.send((message, conn_tx)).await.unwrap();
        
        tokio::spawn(async move {
            let message = conn_rx.await.unwrap();
            let bytes = message.data;
            let mut reader = bytes.reader();
            let response = Msg::Response::parse_from_reader(&mut reader).unwrap();
            let _ = tx.send(Ok(response));
        });
        
        Ok(rx)
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    dotenv::dotenv().ok();
    simple_logging::log_to_stderr(LevelFilter::Debug);
    
    // let (_connection, _rx) = Connection::login(CMsgClientLogon::new()).await?;
    let (_main_tx, mut main_rx) = mpsc::channel::<Message>(10);
    let _session = connect_ws().await?;
    
    tokio::spawn(async move {
        while let Some(_message) = main_rx.recv().await {
            // act on message
        }
    });
    
    Ok(())
}