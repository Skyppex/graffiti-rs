use std::sync::Arc;

use futures_util::SinkExt;
use tokio::sync::{mpsc::Sender, Mutex};
use tokio_tungstenite::tungstenite::{Message, Utf8Bytes};

use crate::{net, rpc, DynResult, Log, Logger};

use super::{
    AsyncStream, CursorMovedNotification, HostInfo, InitializeResponse, InitializedNotification,
    Notification, Response, WsWriter,
};

pub async fn handle_message<S: AsyncStream>(
    msg: Message,
    writer: &mut WsWriter<S>,
    sender: &Sender<net::send::Message>,
    mut logger: Arc<Mutex<Logger>>,
) -> DynResult<()> {
    if let Message::Text(text) = msg {
        logger.log(&format!("Received message: {}", text)).await?;

        let decoded = rpc::decode_message(text.to_string()).await?;

        let id = decoded.id;
        let method = decoded.method;

        logger.log(&format!("Method: {:?}", method)).await?;

        match (id, method) {
            (Some(id), Some(method)) => {
                handle_request(id, &method, decoded.content, writer).await?
            }
            (Some(id), None) => handle_response(id, decoded.content, sender, writer).await?,
            (None, Some(method)) => {
                handle_notification(&method, decoded.content, sender, writer).await?
            }
            _ => Err("Id and/or method is required for a message")?,
        }
    }

    Ok(())
}

async fn handle_request<S: AsyncStream>(
    id: String,
    method: &str,
    _content: Vec<u8>,
    writer: &mut WsWriter<S>,
) -> DynResult<()> {
    if method == "initialize" {
        let response = rpc::encode(Response::<InitializeResponse> {
            id,
            result: Some(InitializeResponse {
                host_info: Some(HostInfo {
                    name: "graffiti-rs".to_string(),
                    version: Some("0.1.0".to_string()),
                }),
                client_id: "1".to_string(),
            }),
        })?;

        writer
            .send(Message::Text(Utf8Bytes::try_from(response)?))
            .await?;
    }

    Ok(())
}

async fn handle_response<S: AsyncStream>(
    _id: String,
    _content: Vec<u8>,
    sender: &Sender<net::send::Message>,
    writer: &mut WsWriter<S>,
) -> DynResult<()> {
    let initialized = rpc::encode(Notification::<InitializedNotification> {
        method: "initialized".to_string(),
        params: Some(InitializedNotification {}),
    })?;

    writer
        .send(Message::Text(Utf8Bytes::try_from(initialized)?))
        .await?;

    Ok(())
}

async fn handle_notification<S: AsyncStream>(
    method: &str,
    content: Vec<u8>,
    sender: &Sender<net::send::Message>,
    writer: &mut WsWriter<S>,
) -> DynResult<()> {
    if method == "cursor_moved" {
        let params = rpc::decode_params::<CursorMovedNotification>(&content)?;

        sender
            .send(net::send::Message::CursorMoved {
                client_id: params.client_id,
                location: params.location,
            })
            .await?;
    }

    Ok(())
}
