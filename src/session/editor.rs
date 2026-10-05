use std::path::PathBuf;

use crate::{
    csp::{
        self, ChangeCwdRequest, ClientIdChangedNotification, CursorMovedNotification,
        DocumentEditedFull, InitialFileUriRequest, MoveCursorNotification,
        PeerConnectedNotification, PeerDisconnectedNotification,
    },
    ppp::PeerExistsNotification,
    session::Configuration,
};

/// A decoded CSP message from the editor. Produced by csp::decode in the
/// editor endpoint task; the session only ever sees these.
pub enum EditorInbound {
    // requests
    Initialize {
        req_id: String,
        params: csp::InitializeRequest,
    },
    RequestSessionToken {
        req_id: String,
    },
    Shutdown {
        req_id: String,
    },

    // responses
    Configuration(Configuration),
    DocumentEditFull {
        uri: PathBuf,
        content: String,
    },
    DocumentLocation(csp::DocumentLocation),

    // notifications
    MoveCursor(MoveCursorNotification),
    Initialized,
    CwdChanged,
    Exit,
    Unknown {
        method: String,
    },
}

/// A typed CSP message for the editor. The session emits these; the editor
/// endpoint task encodes them with csp::encode. Wire concerns (methods,
/// generated request ids, constant server info) live in the codec.
#[derive(Debug)]
pub enum EditorOutbound {
    // requests
    LocationRequest,
    ShutdownRequest,
    InitialFileUri(InitialFileUriRequest),
    ChangeCwd(ChangeCwdRequest),
    Configuration,

    // response
    Response {
        req_id: String,
        response: CspResponse,
    },

    // notifications
    PeerConnected(PeerConnectedNotification),
    PeerExists(PeerExistsNotification),
    PeerDisconnected(PeerDisconnectedNotification),
    ClientIdChanged(ClientIdChangedNotification),
    CursorMoved(CursorMovedNotification),
    DocumentEditedFull(DocumentEditedFull),
    /// the legacy reply to a method we don't recognize
    UnknownMethod,
}

#[derive(Debug)]
pub enum CspResponse {
    Initialize {
        client_id: usize,
        token: Option<String>,
    },
    Shutdown,
    SessionToken {
        token: String,
    },
}
