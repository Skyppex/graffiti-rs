use std::fmt::Display;

use crate::{
    ppp::DocumentLocation,
    utility_types::{ClientId, RequestId},
};

#[derive(Debug, Clone, PartialEq)]
pub enum Message {
    Shutdown(Option<RequestId>),
    Ping(String),
    Fingerprint(String),
    ClientInitialized(ClientId),
    CursorMoved {
        client_id: ClientId,
        location: DocumentLocation,
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
            Message::CursorMoved {
                client_id,
                location,
            } => write!(f, "cursor moved: {} {:?}", client_id, location),
        }
    }
}
