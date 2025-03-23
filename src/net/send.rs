use std::fmt::Display;

#[derive(Debug, Clone, PartialEq)]
pub enum Message {
    Shutdown(Option<String>),
    Ping(String),
    Fingerprint(String),
}

impl Display for Message {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Message::Shutdown(id) => write!(f, "shutdown: {:?}", id),
            Message::Ping(value) => write!(f, "ping: {}", value),
            Message::Fingerprint(value) => write!(f, "fingerprint: {}", value),
        }
    }
}
