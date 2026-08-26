use tokio::sync::mpsc;

use crate::ppp;

/// What the session knows about one connected link.
pub struct Peer {
    pub tx: mpsc::Sender<PeerMessage>,
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
/// SessionEvent::FromPeer it was read from the link; pushed into Peer::tx it
/// will be written to the link.
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

#[derive(Debug, Clone)]
pub enum PppRequest {
    Initialize(ppp::InitializeRequest),
}

#[derive(Debug, Clone)]
pub enum PppResponse {
    Initialize(ppp::InitializeResponse),
}

#[derive(Debug, Clone)]
pub enum PppNotification {
    Initialized(ppp::InitializedNotification),
    DirectoriesUpload(ppp::DirectoriesUploadNotification),
    InitialFileUri(ppp::InitialFileNotification),
    CursorMoved(ppp::CursorMovedNotification),
    DocumentEditFull(ppp::DocumentEditFullNotification),
}
