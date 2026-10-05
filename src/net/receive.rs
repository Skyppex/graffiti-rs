use std::{fmt::Display, path::PathBuf, sync::Arc};

use tokio::sync::Mutex;

use crate::{
    net::connection::ConnectionWriter,
    ppp::{self, DocumentLocation},
    state::State,
    DynResult,
};

#[derive(Debug, Clone, PartialEq)]
pub enum Message {
    Shutdown(String),
    CursorMoved { location: DocumentLocation },
    DocumentEditFull { uri: PathBuf, content: String },
}

impl Display for Message {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Message::Shutdown(id) => write!(f, "shutdown: {}", id),
            Message::CursorMoved { location } => {
                write!(f, "cursor moved: {:?}", location)
            }
            Message::DocumentEditFull { uri, content } => {
                write!(f, "document edit full: {:?}: {}", uri, content)
            }
        }
    }
}

pub async fn handle_message(
    message: Message,
    state: Arc<Mutex<State>>,
    writer: &mut ConnectionWriter,
) -> DynResult<()> {
    match message {
        Message::Shutdown(id) => {
            unreachable!("should be handled before reaching here: {}", id);
        }
        Message::CursorMoved { location } => {
            if !location.exists() {
                return Ok(());
            }

            ppp::send::cursor_moved(writer, state.lock().await.client_id.clone(), location).await
        }
        Message::DocumentEditFull { uri, content } => {
            if !uri.exists() {
                return Ok(());
            }

            ppp::send::document_edit_full(
                writer,
                state.lock().await.client_id.clone(),
                uri,
                content,
            )
            .await
        }
    }
}
