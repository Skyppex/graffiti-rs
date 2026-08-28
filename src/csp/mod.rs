use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use crate::{
    id::next_request_id,
    ppp, rpc,
    session::editor::{CspNotification, CspRequest, CspResponse, EditorInbound, EditorOutbound},
    DynResult,
};

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
    /// The session's out-of-band token: a token the editor shows the
    /// user to hand to whoever wants to join.
    pub token: Option<String>,
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
pub struct ExitNotification;

#[derive(Debug, Serialize, Deserialize)]
pub struct SessionTokenRequest;

#[derive(Debug, Serialize, Deserialize)]
pub struct SessionTokenResponse {
    pub token: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ClientIdChangedNotification {
    pub client_id: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ChangeCwdRequest {
    pub cwd: PathBuf,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct InitialFileUriRequest {
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

// ─── wire codec ──────────────────────────────────────────────────────────
// The editor endpoint task in main.rs is the only caller: it decodes every
// message read from stdin into a typed EditorInbound before it reaches the
// session, and encodes every EditorOutbound the session emits onto stdout.

pub fn decode(message: &rpc::MessageInfo) -> DynResult<EditorInbound> {
    let req_id = || {
        message
            .id
            .clone()
            .ok_or::<crate::DynError>("request id is missing".into())
    };

    Ok(match message.method.as_str() {
        "initialize" => EditorInbound::Initialize {
            req_id: req_id()?,
            params: rpc::decode_params(&message.content)?,
        },
        "initialized" => EditorInbound::Initialized,
        "move_cursor" => {
            let params: MoveCursorNotification = rpc::decode_params(&message.content)?;
            EditorInbound::MoveCursor {
                location: params.location,
            }
        }
        "document/edit" => {
            let mode: DocumentEditModeNotification = rpc::decode_params(&message.content)?;

            match mode.mode {
                DocumentEditMode::Full => {
                    let params: DocumentEditFull = rpc::decode_params(&message.content)?;
                    EditorInbound::DocumentEditFull {
                        uri: params.uri,
                        content: params.content,
                    }
                }
                DocumentEditMode::Incremental => {
                    todo!("incremental edits not implemented yet")
                }
            }
        }
        "document/location" => {
            let params: LocationResponse = rpc::decode_params(&message.content)?;
            EditorInbound::DocumentLocation {
                location: params.location,
            }
        }
        "cwd_changed" => EditorInbound::CwdChanged,
        "request_session_token" => EditorInbound::RequestSessionToken { req_id: req_id()? },
        "shutdown" => EditorInbound::Shutdown { req_id: req_id()? },
        "exit" => EditorInbound::Exit,
        other => EditorInbound::Unknown {
            method: other.to_string(),
        },
    })
}

pub fn encode(message: EditorOutbound) -> DynResult<Vec<u8>> {
    match message {
        EditorOutbound::Response { req_id, response } => match response {
            CspResponse::Initialize { client_id, token } => {
                rpc::encode(Response::<InitializeResponse> {
                    id: req_id,
                    result: Some(InitializeResponse {
                        server_info: Some(ServerInfo {
                            name: "graffiti-rs".to_string(),
                            version: Some("0.1.0".to_string()),
                        }),
                        client_id,
                        token,
                    }),
                })
            }
            CspResponse::Shutdown => rpc::encode(Response::<ShutdownResponse> {
                id: req_id,
                result: None,
            }),
            CspResponse::SessionToken { token } => rpc::encode(Response::<SessionTokenResponse> {
                id: req_id,
                result: Some(SessionTokenResponse { token }),
            }),
        },
        EditorOutbound::Request(request) => match request {
            CspRequest::Location => rpc::encode(Request::<LocationRequest> {
                id: Some(next_request_id()),
                method: "document/location".into(),
                params: None,
            }),
            CspRequest::Shutdown => rpc::encode(Request::<ShutdownRequest> {
                id: None,
                method: "shutdown".into(),
                params: None,
            }),
            CspRequest::ChangeCwd { cwd } => rpc::encode(Request::<ChangeCwdRequest> {
                id: Some(next_request_id()),
                method: "change_cwd".into(),
                params: Some(ChangeCwdRequest { cwd }),
            }),
            CspRequest::InitialFileUri { initial_file_uri } => {
                rpc::encode(Request::<InitialFileUriRequest> {
                    id: Some(next_request_id()),
                    method: "initial_file_uri".into(),
                    params: Some(InitialFileUriRequest { initial_file_uri }),
                })
            }
        },
        EditorOutbound::Notification(notification) => match notification {
            CspNotification::ClientIdChanged { client_id } => {
                rpc::encode(Notification::<ClientIdChangedNotification> {
                    method: "client_id_changed".into(),
                    params: Some(ClientIdChangedNotification { client_id }),
                })
            }
            CspNotification::CursorMoved {
                client_id,
                location,
            } => rpc::encode(Notification::<CursorMovedNotification> {
                method: "cursor_moved".into(),
                params: Some(CursorMovedNotification {
                    client_id,
                    location,
                }),
            }),
            CspNotification::DocumentEdited {
                client_id,
                uri,
                content,
            } => rpc::encode(Notification::<DocumentEditedFull> {
                method: "document/edited".into(),
                params: Some(DocumentEditedFull {
                    client_id,
                    mode: DocumentEditMode::Full,
                    uri,
                    content,
                }),
            }),
        },
        EditorOutbound::UnknownMethod => rpc::encode("unknown method"),
    }
}
