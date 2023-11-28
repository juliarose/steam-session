use super::cm_server::CmServer;
use std::ops::{Deref, DerefMut};
use std::fmt;
use std::collections::HashMap;
use chrono::{Duration, Utc};
use rand::seq::SliceRandom;
use serde::Deserialize;
use reqwest::Client;
use reqwest::header::{HeaderMap, HeaderValue, InvalidHeaderValue};
use reqwest::header::{USER_AGENT, ACCEPT_CHARSET, ACCEPT};
use lazy_static::lazy_static;

lazy_static! {
    pub static ref DEFAULT_CLIENT: Client = {
        Client::new()
    };
}

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("{}", .0)]
    Reqwest(#[from] reqwest::Error),
    #[error("HTTP request returned with response status: {}", .0.status())]
    ReqwestResponseNotOk(reqwest::Response),
    #[error("{}", .0)]
    InvalidHeaderValue(#[from] InvalidHeaderValue),
    #[error("The request returned a response without a list of servers")]
    NoCmServerList,
    #[error("CM server returned an error with message: {}", .0)]
    CmServerListResponseMessage(String),
    #[error("Error parsing VDF body: {}", .0)]
    VdfParse(#[from] keyvalues_serde::error::Error),
}

/// A container for a list of cached [`CmServer`].
#[derive(Debug)]
pub struct CmListCache {
    inner: Vec<CmServer>,
    expiry_duration: Duration,
    last_cached: Option<chrono::DateTime<Utc>>,
}

impl CmListCache {
    /// Creates a new [`CmListCache`]`.
    pub fn new() -> Self {
        Self {
            inner: Vec::new(),
            expiry_duration: Duration::minutes(5),
            last_cached: None,
        }
    }
    
    pub fn pick_random_websocket_server(&self) -> Option<CmServer> {
        self.pick_random(&|cm_server| {
            cm_server.r#type == "websockets" &&
            cm_server.realm == "steamglobal"
        })
    }
    
    pub fn pick_random(&self, filter: &dyn Fn(&&CmServer) -> bool) -> Option<CmServer> {
        let mut servers = self.inner
            .iter()
            .filter(filter)
            .collect::<Vec<_>>();
        
        servers.truncate(20);
        
        let server = servers.choose(&mut rand::thread_rng());
        
        server.map(|server| (*server).clone())
    }
    
    /// Updates the list of servers, if they are oudated.
    pub async fn update(&mut self) -> Result<(), Error> {
        let now = chrono::offset::Utc::now();
        let is_expired = if let Some(last_cached) = self.last_cached {
            let difference = now - last_cached;
            
            difference > self.expiry_duration
        } else {
            // never cached
            true
        };
        
        if !is_expired {
            // no need to update
            return Ok(())
        }
        
        self.inner = get_cm_list().await?;
        self.last_cached = Some(now);
        
        Ok(())
    }
    
    /// Gets a reference to the inner value.
    pub fn get(&self) -> &Vec<CmServer> {
        self.inner.as_ref()
    }
}

impl fmt::Display for CmListCache {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{:?}", self.inner)
    }
}

impl Deref for CmListCache {
    type Target = Vec<CmServer>;
    
    fn deref(&self) -> &Vec<CmServer> {
        &self.inner
    }
}

impl DerefMut for CmListCache {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.inner
    }
}
    
async fn get_cm_list() -> Result<Vec<CmServer>, Error> {
    // todo handle errors
    fetch_cm_list().await
}

async fn fetch_cm_list() -> Result<Vec<CmServer>, Error> {
    let url = "https://api.steampowered.com/ISteamDirectory/GetCMListForConnect/v0001/?cellid=0&format=vdf";
    let mut headers = HeaderMap::new();
    
    headers.append(USER_AGENT, HeaderValue::from_str("Valve/Steam HTTP Client 1.0")?);
    headers.append(ACCEPT_CHARSET,HeaderValue::from_str("ISO-8859-1,utf-8,*;q=0.7")?);
    headers.append(ACCEPT, HeaderValue::from_str("text/html,*/*;q=0.9")?);
    
    let response = DEFAULT_CLIENT.get(url)
        .headers(headers)
        .send().await?;
    let text = check_response_ok(response).await?
        .text().await?;
    
    parse_cm_list(&text)
}

/// Checks if the response is OK.
async fn check_response_ok(response: reqwest::Response) -> Result<reqwest::Response, Error> {
    match response.status().as_u16() {
        300..=399 => Err(Error::ReqwestResponseNotOk(response)),
        400..=499 => Err(Error::ReqwestResponseNotOk(response)),
        500..=599 => Err(Error::ReqwestResponseNotOk(response)),
        _ => Ok(response),
    }
}

fn parse_cm_list(text: &str) -> Result<Vec<CmServer>, Error> {
    #[derive(Debug, Deserialize)]
    struct CmBody {
        #[serde(default)]
        serverlist: Option<HashMap<usize, CmServer>>,
        #[serde(default)]
        success: i32,
        #[serde(default)]
        message: String,
    }
    
    let body = keyvalues_serde::from_str::<CmBody>(&text)?;
    
    if body.success != 1 {
        return Err(Error::CmServerListResponseMessage(body.message));
    }
    
    let mut serverlist = body.serverlist
        .ok_or(Error::NoCmServerList)?
        .into_iter()
        .map(|(_, cmserver)| cmserver)
        .collect::<Vec<_>>();
    
    if serverlist.is_empty() {
        return Err(Error::NoCmServerList);
    }
    
    // lowest to highest by wtd_load (closest servers will appear first)
    serverlist.sort_by(|a, b| a.wtd_load.cmp(&b.wtd_load));
    
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