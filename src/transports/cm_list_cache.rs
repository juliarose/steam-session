use std::ops::{Deref, DerefMut};
use std::fmt;
use std::sync::{Arc, Mutex};
use super::cm_server::CmServer;

pub type SharedCmListCache = Arc<Mutex<CmListCache>>;

/// A container for a list of cached [`CmServer`].
#[derive(Debug, Default)]
pub struct CmListCache {
    inner: Vec<CmServer>,
}

impl CmListCache {
    /// Updates the list of servers.
    pub fn update(&mut self, cm_servers: Vec<CmServer>) {
        self.inner = cm_servers;
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