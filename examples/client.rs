use steam_session::login_session::connect_ws;
use log::LevelFilter;
use steam_session::transports::Transport;
use steam_vent::connection::Connection;
use steam_session::authentication_client::Error;
use tokio::sync::{mpsc, oneshot};
use steam_vent::proto::steammessages_clientserver_login::CMsgClientLogon;
use steam_session::net::ApiRequest;
use async_trait::async_trait;

pub struct Message {
    msg: i32,
}

pub struct ClientTransport {
    sender: mpsc::Sender<Message>,
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
        let (_tx, rx) = oneshot::channel::<Result<Msg::Response, Error>>();
        
        Ok(rx)
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    dotenv::dotenv().ok();
    simple_logging::log_to_stderr(LevelFilter::Debug);
    
    let (connection, rx) = Connection::login(CMsgClientLogon::new()).await?;
    let (main_tx, mut main_rx) = mpsc::channel::<Message>(10);
    let session = connect_ws().await?;
    
    tokio::spawn(async move {
        
    });
    
    while let Some(message) = main_rx.recv().await {
        
    }
    
    Ok(())
}