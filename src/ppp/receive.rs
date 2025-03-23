use std::sync::Arc;

use futures_util::SinkExt;
use tokio::{io::{AsyncRead, AsyncWrite}, sync::Mutex};
use tokio_tungstenite::tungstenite::{Message, Utf8Bytes};

use crate::{rpc, DynResult, Log, Logger};

use super::{
    HostInfo, InitializeResponse, InitializedNotification, Notification, Response, WsWriter,
};

pub async fn handle_message<S: AsyncWrite + AsyncRead + Unpin>(
    msg: Message,
    write: &mut WsWriter<S>,
    mut logger: Arc<Mutex<Logger>>,
) -> DynResult<()> {
    if let Message::Text(text) = msg {
        logger.log(&format!("Received message: {}", text)).await?;

        let decoded = rpc::decode_message(text.to_string()).await?;

        let id = decoded.id;
        let method = decoded.method;

        logger.log(&format!("Method: {:?}", method)).await?;

        match (id, method) {
            (Some(id), Some(method)) => handle_request(id, &method, decoded.content, write).await?,
            (Some(id), None) => handle_response(id, decoded.content, write).await?,
            (None, Some(method)) => handle_notification(&method, decoded.content).await?,
            _ => Err("Id and/or method is required for a message")?,
        }
    }

    Ok(())
}

async fn handle_request<S: AsyncWrite + AsyncRead + Unpin>(
    id: String,
    method: &str,
    _content: Vec<u8>,
    write: &mut WsWriter<S>,
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

        write
            .send(Message::Text(Utf8Bytes::try_from(response)?))
            .await?;
    }

    Ok(())
}

async fn handle_response<S: AsyncWrite + AsyncRead + Unpin>(
    _id: String,
    _content: Vec<u8>,
    write: &mut WsWriter<S>,
) -> DynResult<()> {
    let initialized = rpc::encode(Notification::<InitializedNotification> {
        method: "initialized".to_string(),
        params: Some(InitializedNotification {}),
    })?;

    write
        .send(Message::Text(Utf8Bytes::try_from(initialized)?))
        .await?;

    Ok(())
}

async fn handle_notification(_method: &str, _content: Vec<u8>) -> DynResult<()> {
    Ok(())
}
