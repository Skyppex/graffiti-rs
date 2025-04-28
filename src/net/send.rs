use std::{fmt::Display, path::PathBuf};

use crate::ppp::DocumentLocation;

#[derive(Debug, Clone, PartialEq)]
pub enum Message {
    #[allow(dead_code)]
    Ping(String),

    // local client-server only messages
    Shutdown(Option<String>),
    Fingerprint(String),

    // peer generated messages
    ClientInitialized(String),
    InitialFileUri {
        uri: PathBuf,
    },
    CursorMoved {
        client_id: String,
        location: DocumentLocation,
    },
    DocumentEditedFull {
        client_id: String,
        uri: PathBuf,
        content: String,
    },
}

impl Display for Message {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Message::Shutdown(id) => write!(f, "shutdown: {:?}", id),
            Message::Ping(value) => write!(f, "ping: {}", value),
            Message::Fingerprint(value) => write!(f, "fingerprint: {}", value),
            Message::ClientInitialized(client_id) => {
                write!(f, "client initialized: {}", client_id)
            }
            Message::InitialFileUri { uri } => {
                write!(f, "initial file uri: {:?}", uri)
            }
            Message::CursorMoved {
                client_id,
                location,
            } => write!(f, "cursor moved: {} {:?}", client_id, location),
            Message::DocumentEditedFull {
                client_id,
                uri,
                content,
            } => write!(
                f,
                "document edit full: {} {:?}: {}",
                client_id, uri, content
            ),
        }
    }
}
