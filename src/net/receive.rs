use std::{fmt::Display, sync::Arc};

use tokio::sync::Mutex;

use crate::{
    ppp::{self, AsyncStream, DocumentLocation},
    DynResult, Logger,
};

use super::WsWriter;

#[derive(Debug, Clone, PartialEq)]
pub enum Message {
    Shutdown(String),
    CursorMoved {
        client_id: String,
        location: DocumentLocation,
    },
}

impl Display for Message {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Message::Shutdown(id) => write!(f, "shutdown: {}", id),
            Message::CursorMoved {
                client_id,
                location,
            } => write!(f, "cursor moved: {} {:?}", client_id, location),
        }
    }
}

pub async fn handle_message<S: AsyncStream>(
    message: Message,
    writer: &mut WsWriter<S>,
    logger: Arc<Mutex<Logger>>,
) -> DynResult<()> {
    match message {
        Message::Shutdown(id) => {
            unreachable!("should be handled before reaching here: {}", id);
        }
        Message::CursorMoved {
            client_id,
            location,
        } => {
            ppp::send::cursor_moved(writer, client_id, location, logger).await?;
            Ok(())
        }
    }
}
