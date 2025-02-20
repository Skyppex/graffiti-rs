use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
pub struct Request<T> {
    pub id: Option<String>,
    pub method: String,
    pub params: Option<T>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Response<T> {
    pub id: Option<String>,
    pub result: Option<T>,
    // pub error: (),
}

#[derive(Debug, Serialize, Deserialize)]
pub struct InitializeRequest {
    #[serde(rename = "processId")]
    pub process_id: Option<i32>,
    #[serde(rename = "clientInfo")]
    pub client_info: Option<ClientInfo>,
    #[serde(rename = "rootPath")]
    pub root_path: Option<String>,
    // #[serde(rename = "initializeOptions")]
    // initialize_options: Option<InitializeOptions>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ClientInfo {
    pub name: String,
    pub version: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct InitializeResponse {
    pub server_info: Option<ServerInfo>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ServerInfo {
    pub name: String,
    pub version: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct InitializedNotification {
    pub params: (),
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ShutdownRequest;

#[derive(Debug, Serialize, Deserialize)]
pub struct ShutdownResponse;
