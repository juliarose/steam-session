use super::{Error, CmListError, WebSocketCMTransport, CmListCache};
use super::response::ApiResponseBody;
use crate::net::ApiRequest;
use crate::authentication_client::Error as AuthenticationClientError;
use std::sync::Arc;
use futures::StreamExt;
use tokio::sync::oneshot;
use tokio::time::timeout;
use tokio_tungstenite::tungstenite::http::uri::Uri;
use tokio_tungstenite::tungstenite::http::request::Request;
use tokio_tungstenite::connect_async;

/// Generate a random key for the `Sec-WebSocket-Key` header.
fn generate_key() -> String {
    // a base64-encoded (see Section 4 of [RFC4648]) value that,
    // when decoded, is 16 bytes in length (RFC 6455)
    let r: [u8; 16] = rand::random();
    data_encoding::BASE64.encode(&r)
}

pub async fn connect_to_cm(cm_list: &Arc<tokio::sync::Mutex<CmListCache>>) -> Result<WebSocketCMTransport, Error> {
    let cm_server = {
        let mut cm_list = cm_list.lock().await;
        
        cm_list.update().await?;
        // pick a random server
        cm_list.pick_random_websocket_server()
    }.ok_or(Error::CmServer(CmListError::NoCmServer))?;
    let connect_addr = format!("wss://{}/cmsocket/", cm_server.endpoint);
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
    // let connect_timeout = Duration::seconds(CONNECTION_TIMEOUT_SECONDS);
    let (ws_stream, _) = connect_async(request).await?;
    let (ws_write, ws_read) = ws_stream.split();
    let transport = WebSocketCMTransport::new(
        ws_read,
        ws_write,
    );
    
    Ok(transport)
}

pub async fn wait_for_response<Msg>(
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