use std::{path::PathBuf, sync::Arc};

use futures_util::SinkExt;
use tokio::sync::Mutex;
use tokio_tungstenite::tungstenite::{Message, Utf8Bytes};

use crate::{rpc, state::State, utils::generate_id, DynResult, Log, Logger};

use super::{
    AsyncStream, ClientInfo, CursorMovedNotification, DirectoriesUploadNotification, Directory,
    DocumentEditFullNotification, DocumentEditMode, DocumentLocation, InitialFileNotification,
    InitializeRequest, InitializedNotification, Notification, Request, WsWriter,
};

pub async fn initialize<S: AsyncStream>(
    state: Arc<Mutex<State>>,
    writer: &mut WsWriter<S>,
    mut logger: Arc<Mutex<Logger>>,
) -> DynResult<()> {
    logger.log("sending initialize to host").await?;

    let request = Request::<InitializeRequest> {
        id: generate_id(),
        method: "initialize".into(),
        params: Some(InitializeRequest {
            process_id: None,
            client_info: Some(ClientInfo {
                name: "ppp".to_string(),
                version: Some("0.1.0".to_string()),
            }),
            root_path: None,
        }),
    };

    let encoded = rpc::encode(request.clone())?;

    state.lock().await.add_net_req(Box::new(request));

    writer
        .send(Message::Text(Utf8Bytes::try_from(encoded)?))
        .await?;

    Ok(())
}

pub async fn initialized<S: AsyncStream>(
    writer: &mut WsWriter<S>,
    mut logger: Arc<Mutex<Logger>>,
) -> DynResult<()> {
    logger.log("sending initialized to host").await?;

    let request = rpc::encode(Notification::<InitializedNotification> {
        method: "initialized".into(),
        params: Some(InitializedNotification {
            client_id: "1".into(),
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
    logger.log("sending cursor_moved").await?;

    let request = rpc::encode(Notification::<CursorMovedNotification> {
        method: "cursor_moved".into(),
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

pub async fn document_edit_full<S: AsyncStream>(
    writer: &mut WsWriter<S>,
    client_id: String,
    uri: PathBuf,
    content: String,
    mut logger: Arc<Mutex<Logger>>,
) -> DynResult<()> {
    logger.log("sending document_edit_full").await?;

    let notification = rpc::encode(Notification::<DocumentEditFullNotification> {
        method: "document/edit".into(),
        params: Some(DocumentEditFullNotification {
            client_id,
            mode: DocumentEditMode::Full,
            uri,
            content,
        }),
    })?;

    writer
        .send(Message::Text(Utf8Bytes::try_from(notification)?))
        .await?;

    Ok(())
}

pub async fn directories_upload<S: AsyncStream>(
    writer: &mut WsWriter<S>,
    client_id: String,
    directories: Vec<Directory>,
    mut logger: Arc<Mutex<Logger>>,
) -> DynResult<()> {
    logger.log("sending directories/upload").await?;

    let notification = rpc::encode(Notification::<DirectoriesUploadNotification> {
        method: "directories/upload".into(),
        params: Some(DirectoriesUploadNotification {
            client_id,
            directories,
        }),
    })?;

    writer
        .send(Message::Text(Utf8Bytes::try_from(notification)?))
        .await?;

    Ok(())
}

pub async fn initial_file_uri<S: AsyncStream>(
    writer: &mut WsWriter<S>,
    uri: PathBuf,
    mut logger: Arc<Mutex<Logger>>,
) -> DynResult<()> {
    logger.log("sending initial_file_uri").await?;

    let notification = rpc::encode(Notification::<InitialFileNotification> {
        method: "initial_file_uri".into(),
        params: Some(InitialFileNotification { uri }),
    })?;

    writer
        .send(Message::Text(Utf8Bytes::try_from(notification)?))
        .await?;

    Ok(())
}
