pub mod receive;
pub mod send;

use futures_util::stream::SplitSink;
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio_tungstenite::{tungstenite::Message, WebSocketStream};

use crate::csp;

pub type WsWriter<S> = SplitSink<WebSocketStream<S>, Message>;

pub trait AsyncStream: AsyncWrite + AsyncRead + Unpin {}

impl<S: AsyncWrite + AsyncRead + Unpin> AsyncStream for S {}

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
    pub host_info: Option<HostInfo>,
    // client id generated by the host.
    // used to identify the client in subsequent messages
    pub client_id: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct HostInfo {
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

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DocumentLocation {
    pub uri: String,
    pub line: u32,
    pub column: u32,
}

impl From<csp::DocumentLocation> for DocumentLocation {
    fn from(location: csp::DocumentLocation) -> Self {
        Self {
            uri: location.uri,
            line: location.line,
            column: location.column,
        }
    }
}
