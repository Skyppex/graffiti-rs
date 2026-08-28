use std::path::PathBuf;

use crate::csp;

/// A decoded CSP message from the editor. Produced by csp::decode in the
/// editor endpoint task; the session only ever sees these.
pub enum EditorInbound {
    Initialize {
        req_id: String,
        params: csp::InitializeRequest,
    },
    Initialized,
    MoveCursor {
        location: csp::DocumentLocation,
    },
    DocumentEditFull {
        uri: PathBuf,
        content: String,
    },
    DocumentLocation {
        location: csp::DocumentLocation,
    },
    CwdChanged,
    RequestFingerprint {
        req_id: String,
    },
    Shutdown {
        req_id: String,
    },
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
    Response {
        req_id: String,
        response: CspResponse,
    },
    Request(CspRequest),
    Notification(CspNotification),
    /// the legacy reply to a method we don't recognize
    UnknownMethod,
}

#[derive(Debug)]
pub enum CspRequest {
    Location,
    Shutdown,
    InitialFileUri { initial_file_uri: PathBuf },
    ChangeCwd { cwd: PathBuf },
}

#[derive(Debug)]
pub enum CspResponse {
    Initialize { client_id: String },
    Shutdown,
    Fingerprint { fingerprint: String },
}

#[derive(Debug)]
pub enum CspNotification {
    FingerprintGenerated {
        fingerprint: String,
    },
    ClientIdChanged {
        client_id: String,
    },
    CursorMoved {
        client_id: String,
        location: csp::DocumentLocation,
    },
    DocumentEdited {
        client_id: String,
        uri: PathBuf,
        content: String,
    },
}
