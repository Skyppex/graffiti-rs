use std::sync::Arc;

use futures_util::SinkExt;
use tokio::sync::{mpsc::Sender, Mutex};
use tokio_tungstenite::tungstenite::{Message, Utf8Bytes};

use crate::{net::send, rpc, state::State, utility_types::RequestId, DynResult, Log, Logger};

use super::{
    AsyncStream, CursorMovedNotification, HostInfo, InitializeResponse, InitializedNotification,
    Notification, Response, WsWriter,
};

pub async fn handle_message<S: AsyncStream>(
    msg: Message,
    state: Arc<Mutex<State>>,
    writer: &mut WsWriter<S>,
    sender: &Sender<send::Message>,
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
                handle_request(id, &method, decoded.content, state, writer, logger).await?
            }
            (Some(id), None) => {
                handle_response(id, decoded.content, state, sender, writer, logger).await?
            }
            (None, Some(method)) => {
                handle_notification(&method, decoded.content, state, sender, writer, logger).await?
            }
            _ => Err("Id and/or method is required for a message")?,
        }
    }

    Ok(())
}

async fn handle_request<S: AsyncStream>(
    id: RequestId,
    method: &str,
    _content: Vec<u8>,
    state: Arc<Mutex<State>>,
    writer: &mut WsWriter<S>,
    mut logger: Arc<Mutex<Logger>>,
) -> DynResult<()> {
    if method == "initialize" {
        let response = rpc::encode(Response::<InitializeResponse> {
            id,
            result: Some(InitializeResponse {
                host_info: Some(HostInfo {
                    name: "graffiti-rs".to_string(),
                    version: Some("0.1.0".to_string()),
                }),
                client_id: "1".into(),
            }),
        })?;

        writer
            .send(Message::Text(Utf8Bytes::try_from(response)?))
            .await?;
    }

    Ok(())
}

async fn handle_response<S: AsyncStream>(
    id: RequestId,
    _content: Vec<u8>,
    state: Arc<Mutex<State>>,
    sender: &Sender<send::Message>,
    writer: &mut WsWriter<S>,
    mut logger: Arc<Mutex<Logger>>,
) -> DynResult<()> {
    if let Some(request) = state.lock().await.get_net_req(&id) {
        match request.method().as_str() {
            "initialize" => {
                let initialized = rpc::encode(Notification::<InitializedNotification> {
                    method: "initialized".into(),
                    params: Some(InitializedNotification {
                        client_id: "1".into(),
                    }),
                })?;

                writer
                    .send(Message::Text(Utf8Bytes::try_from(initialized)?))
                    .await?;
            }
            other => Err(format!("unknown method: {}", other))?,
        }
    }

    Ok(())
}

async fn handle_notification<S: AsyncStream>(
    method: &str,
    content: Vec<u8>,
    state: Arc<Mutex<State>>,
    sender: &Sender<send::Message>,
    writer: &mut WsWriter<S>,
    mut logger: Arc<Mutex<Logger>>,
) -> DynResult<()> {
    match method {
        "initialized" => {
            let params = rpc::decode_params::<InitializedNotification>(&content)?;

            sender
                .send(send::Message::ClientInitialized(params.client_id))
                .await?;
        }
        "cursor_moved" => {
            let params = rpc::decode_params::<CursorMovedNotification>(&content)?;

            sender
                .send(send::Message::CursorMoved {
                    client_id: params.client_id.into(),
                    location: params.location,
                })
                .await?;
        }
        other => Err(format!("unknown method: {}", other))?,
    }

    Ok(())
}
