use std::sync::Arc;

use futures_util::SinkExt;
use tokio::sync::Mutex;
use tokio_tungstenite::tungstenite::{Message, Utf8Bytes};

use crate::{rpc, DynResult, Log, Logger};

use super::{
    AsyncStream, ClientInfo, CursorMovedNotification, DocumentLocation, InitializeRequest,
    Notification, Request, WsWriter,
};

pub async fn initialize<S: AsyncStream>(writer: &mut WsWriter<S>) -> DynResult<()> {
    let request = rpc::encode(Request::<InitializeRequest> {
        id: Some("1".to_string()),
        method: "initialize".to_string(),
        params: Some(InitializeRequest {
            process_id: None,
            client_info: Some(ClientInfo {
                name: "ppp".to_string(),
                version: Some("0.1.0".to_string()),
            }),
            root_path: None,
        }),
    })?;

    writer
        .send(Message::Text(Utf8Bytes::try_from(request)?))
        .await?;

    Ok(())
}

pub async fn cursor_moved<S: AsyncStream>(
    writer: &mut WsWriter<S>,
    client_id: String,
    location: DocumentLocation,
    mut logger: Arc<Mutex<Logger>>,
) -> DynResult<()> {
    logger.log("sending cursor moved").await?;

    let request = rpc::encode(Notification::<CursorMovedNotification> {
        method: "cursor_moved".to_string(),
        params: Some(CursorMovedNotification {
            client_id,
            location,
        }),
    })?;

    writer
        .send(Message::Text(Utf8Bytes::try_from(request)?))
        .await?;

    Ok(())
}
