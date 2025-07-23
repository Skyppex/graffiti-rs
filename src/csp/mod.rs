use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use crate::ppp;

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
    pub editor_info: Option<EditorInfo>,
    pub root_path: Option<String>,
    pub initialize_options: Option<InitializeOptions>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct EditorInfo {
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
    pub client_id: String,
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
pub struct InitialFileUriRequest {
    pub cwd: PathBuf,
    pub initial_file_uri: PathBuf,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct MoveCursorNotification {
    pub location: DocumentLocation,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CursorMovedNotification {
    pub client_id: String,
    pub location: DocumentLocation,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DocumentLocation {
    pub uri: PathBuf,
    pub pos: DocumentPosition,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DocumentPosition {
    pub line: u32,
    pub column: u32,
}

impl DocumentLocation {
    pub fn exists(&self) -> bool {
        self.uri.is_file()
    }
}

impl From<ppp::DocumentLocation> for DocumentLocation {
    fn from(location: ppp::DocumentLocation) -> Self {
        Self {
            uri: location.uri,
            pos: location.pos.into(),
        }
    }
}

impl From<ppp::DocumentPosition> for DocumentPosition {
    fn from(pos: ppp::DocumentPosition) -> Self {
        Self {
            line: pos.line,
            column: pos.column,
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct LocationRequest;

#[derive(Debug, Serialize, Deserialize)]
pub struct LocationResponse {
    pub location: DocumentLocation,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct DocumentEditModeNotification {
    pub mode: DocumentEditMode,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct DocumentEditFull {
    pub uri: PathBuf,
    pub content: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct DocumentEditIncremental {
    pub uri: PathBuf,
    pub start: DocumentPosition,
    pub end: DocumentPosition,
    pub content: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct DocumentEditedFull {
    pub client_id: String,
    pub mode: DocumentEditMode,
    pub uri: PathBuf,
    pub content: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct DocumentEditedIncremental {
    pub client_id: String,
    pub mode: DocumentEditMode,
    pub uri: PathBuf,
    pub start: DocumentPosition,
    pub end: DocumentPosition,
    pub content: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub enum DocumentEditMode {
    #[serde(rename = "full")]
    Full,
    #[serde(rename = "incremental")]
    Incremental,
}
