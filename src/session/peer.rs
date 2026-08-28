use tokio::sync::mpsc;

use crate::ppp::{self, method};

/// What the session knows about one connected link.
pub struct Peer {
    /// sends messages to this peer's link task, which writes them to the wire
    pub link_sender: mpsc::Sender<PeerMessage>,
    pub initialized: bool,
}

/// Identity of a link, not an author. On the host this is the client_id
/// allocated when the connection is accepted; on the client there is exactly
/// one link: the host.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum PeerId {
    Host,           // The peer which is hosting the session and "owns" the repo
    Client(String), // The peer which is connecting and downloading the repo from the host
}

/// A typed PPP message. Direction is implicit: arriving in
/// SessionEvent::FromPeer it was read from the link; pushed into
/// Peer::link_sender it will be written to the link.
#[derive(Debug, Clone)]
pub enum PeerMessage {
    Request {
        req_id: String,
        request: PppRequest,
    },
    Response {
        req_id: String,
        response: PppResponse,
    },
    Notification(PppNotification),
}

impl PeerMessage {
    /// The wire method name this message carries, straight from the ppp
    /// vocabulary the codec speaks.
    pub fn method(&self) -> &'static str {
        match self {
            PeerMessage::Request { request, .. } => request.method(),
            PeerMessage::Response { response, .. } => response.method(),
            PeerMessage::Notification(notification) => notification.method(),
        }
    }
}

#[derive(Debug, Clone)]
pub enum PppRequest {
    Initialize(ppp::InitializeRequest),
}

impl PppRequest {
    pub fn method(&self) -> &'static str {
        match self {
            PppRequest::Initialize(_) => method::INITIALIZE,
        }
    }
}

#[derive(Debug, Clone)]
pub enum PppResponse {
    Initialize(ppp::InitializeResponse),
}

impl PppResponse {
    pub fn method(&self) -> &'static str {
        match self {
            PppResponse::Initialize(_) => method::INITIALIZE,
        }
    }
}

#[derive(Debug, Clone)]
pub enum PppNotification {
    Initialized(ppp::InitializedNotification),
    DirectoriesUpload(ppp::DirectoriesUploadNotification),
    InitialFileUri(ppp::InitialFileNotification),
    CursorMoved(ppp::CursorMovedNotification),
    DocumentEditFull(ppp::DocumentEditFullNotification),
}

impl PppNotification {
    pub fn method(&self) -> &'static str {
        match self {
            PppNotification::Initialized(_) => method::INITIALIZED,
            PppNotification::DirectoriesUpload(_) => method::DIRECTORIES_UPLOAD,
            PppNotification::InitialFileUri(_) => method::INITIAL_FILE_URI,
            PppNotification::CursorMoved(_) => method::CURSOR_MOVED,
            PppNotification::DocumentEditFull(_) => method::DOCUMENT_EDIT,
        }
    }
}
