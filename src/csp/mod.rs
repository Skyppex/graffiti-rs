use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
pub struct Request<T> {
    pub id: Option<String>,
    pub method: String,
    pub params: Option<T>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Response<T> {
    pub id: String,
    pub result: Option<T>,
    // pub error: (),
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Notification<T> {
    pub method: String,
    pub params: Option<T>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct InitializeRequest {
    pub process_id: Option<i32>,
    pub client_info: Option<ClientInfo>,
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
pub struct InitializedNotification;

#[derive(Debug, Serialize, Deserialize)]
pub struct ShutdownRequest;

#[derive(Debug, Serialize, Deserialize)]
pub struct ShutdownResponse;

#[derive(Debug, Serialize, Deserialize)]
pub struct CursorMovedNotification {
    pub client_id: String,
    pub location: DocumentLocation,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct DocumentLocation {
    pub uri: String,
    pub line: i32,
    pub column: i32,
}
