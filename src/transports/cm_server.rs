use serde::{Serialize, Deserialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CmServer {
    pub endpoint: String,
    pub legacy_endpoint: Option<String>,
    pub r#type: String,
    pub dc: Option<String>,
    pub realm: String,
    pub load: Option<String>,
    pub wtd_load: Option<String>,
}