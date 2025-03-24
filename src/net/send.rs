use std::fmt::Display;

use crate::ppp::DocumentLocation;

#[derive(Debug, Clone, PartialEq)]
pub enum Message {
    Shutdown(Option<String>),
    Ping(String),
    Fingerprint(String),
    CursorMoved {
        client_id: String,
        location: DocumentLocation,
    },
}

impl Display for Message {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Message::Shutdown(id) => write!(f, "shutdown: {:?}", id),
            Message::Ping(value) => write!(f, "ping: {}", value),
            Message::Fingerprint(value) => write!(f, "fingerprint: {}", value),
            Message::CursorMoved {
                client_id,
                location,
            } => write!(f, "cursor moved: {} {:?}", client_id, location),
        }
    }
}
