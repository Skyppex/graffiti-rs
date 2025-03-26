use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use crate::{ppp, utility_types::*};

#[derive(Debug, Serialize, Deserialize)]
pub struct Request<T> {
    pub id: Option<RequestId>,
    pub method: Method,
    pub params: Option<T>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Response<T> {
    pub id: RequestId,
    pub result: Option<T>,
    // pub error: (),
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Notification<T> {
    pub method: Method,
    pub params: Option<T>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct InitializeRequest {
    pub process_id: Option<i32>,
    pub client_info: Option<ClientInfo>,
    pub root_path: Option<String>,
    pub initialize_options: Option<InitializeOptions>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ClientInfo {
    pub name: String,
    pub version: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct InitializeOptions {
    pub client_projects_root: Option<PathBuf>,
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
pub struct FingerprintGeneratedNotification {
    pub fingerprint: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ShutdownRequest;

#[derive(Debug, Serialize, Deserialize)]
pub struct ShutdownResponse;

#[derive(Debug, Serialize, Deserialize)]
pub struct ExitNotification;

#[derive(Debug, Serialize, Deserialize)]
pub struct FingerprintRequest;

#[derive(Debug, Serialize, Deserialize)]
pub struct FingerprintResponse {
    pub fingerprint: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct MoveCursorNotification {
    pub location: DocumentLocation,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CursorMovedNotification {
    pub client_id: ClientId,
    pub location: DocumentLocation,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DocumentLocation {
    pub uri: PathBuf,
    pub line: u32,
    pub column: u32,
}

impl From<ppp::DocumentLocation> for DocumentLocation {
    fn from(location: ppp::DocumentLocation) -> Self {
        Self {
            uri: location.uri,
            line: location.line,
            column: location.column,
        }
    }
}
