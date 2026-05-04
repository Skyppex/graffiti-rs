use std::{path::PathBuf, sync::Arc};

use tokio::sync::Mutex;

use crate::{
    id::{next_client_id, next_request_id},
    net::connection::{ConnectionWriter, Message},
    ppp::{HostInfo, InitializeResponse, Response},
    rpc,
    state::State,
    DynResult, Log, Logger,
};

use super::{
    ClientInfo, CursorMovedNotification, DirectoriesUploadNotification, Directory,
    DocumentEditFullNotification, DocumentEditMode, DocumentLocation, InitialFileNotification,
    InitializeRequest, InitializedNotification, Notification, Request,
};

pub async fn initialize(
    state: Arc<Mutex<State>>,
    writer: &mut ConnectionWriter,
    mut logger: Arc<Mutex<Logger>>,
) -> DynResult<()> {
    logger.log("sending initialize to host").await?;

    let request = Request::<InitializeRequest> {
        id: next_request_id(),
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

    writer.send(Message::Data(encoded)).await?;

    Ok(())
}

pub async fn initialize_response(
    id: String,
    state: Arc<Mutex<State>>,
    writer: &mut ConnectionWriter,
    mut logger: Arc<Mutex<Logger>>,
) -> DynResult<()> {
    let response = rpc::encode(Response::<InitializeResponse> {
        id,
        result: Some(InitializeResponse {
            host_info: Some(HostInfo {
                name: "graffiti-rs".to_string(),
                version: Some("0.1.0".to_string()),
            }),
            client_id: next_client_id(),
            project_dir_name: PathBuf::from(
                state
                    .lock()
                    .await
                    .get_cwd()
                    .file_name()
                    .expect("Unable to get project directory name"),
            ),
        }),
    })?;

    logger.log("sending initialize response to client").await?;
    logger
        .log(&format!(
            "response: {}",
            String::from_utf8(response.clone()).unwrap()
        ))
        .await?;

    writer.send(Message::Data(response)).await?;

    logger.log("sent initialize response to client").await?;

    Ok(())
}

pub async fn initialized(
    writer: &mut ConnectionWriter,
    mut logger: Arc<Mutex<Logger>>,
) -> DynResult<()> {
    logger.log("sending initialized to host").await?;

    let request = rpc::encode(Notification::<InitializedNotification> {
        method: "initialized".into(),
        params: Some(InitializedNotification {
            client_id: "1".into(),
        }),
    })?;

    writer.send(Message::Data(request)).await?;

    Ok(())
}

pub async fn cursor_moved(
    writer: &mut ConnectionWriter,
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

    writer.send(Message::Data(request)).await?;

    Ok(())
}

pub async fn document_edit_full(
    writer: &mut ConnectionWriter,
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

    writer.send(Message::Data(notification)).await?;

    Ok(())
}

pub async fn directories_upload(
    writer: &mut ConnectionWriter,
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

    writer.send(Message::Data(notification)).await?;

    Ok(())
}

pub async fn initial_file_uri(
    writer: &mut ConnectionWriter,
    uri: PathBuf,
    mut logger: Arc<Mutex<Logger>>,
) -> DynResult<()> {
    logger.log("sending initial_file_uri").await?;

    let notification = rpc::encode(Notification::<InitialFileNotification> {
        method: "initial_file_uri".into(),
        params: Some(InitialFileNotification { uri }),
    })?;

    writer.send(Message::Data(notification)).await?;

    Ok(())
}
