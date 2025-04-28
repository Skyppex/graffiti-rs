use futures_util::SinkExt;
use ignore::WalkBuilder;
use std::{path::PathBuf, sync::Arc};
use tokio::{
    io::AsyncWriteExt,
    sync::{mpsc::Sender, Mutex},
};
use tokio_tungstenite::tungstenite::{Message, Utf8Bytes};

use crate::{
    net::send,
    ppp::{self, DirectoriesUploadNotification, Directory, DirectoryType},
    rpc,
    state::{self, State},
    DynResult, Log, Logger,
};

use super::{
    AsyncStream, CursorMovedNotification, DocumentEditFullNotification,
    DocumentEditModeNotification, HostInfo, InitialFileNotification, InitializeResponse,
    InitializedNotification, Response, WsWriter,
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
    id: String,
    method: &str,
    _content: Vec<u8>,
    state: Arc<Mutex<State>>,
    writer: &mut WsWriter<S>,
    mut logger: Arc<Mutex<Logger>>,
) -> DynResult<()> {
    if method == "initialize" {
        logger
            .log("received initialize request from client")
            .await?;

        let response = rpc::encode(Response::<InitializeResponse> {
            id,
            result: Some(InitializeResponse {
                host_info: Some(HostInfo {
                    name: "graffiti-rs".to_string(),
                    version: Some("0.1.0".to_string()),
                }),
                client_id: "1".into(),
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
        writer
            .send(Message::Text(Utf8Bytes::try_from(response)?))
            .await?;
        logger.log("sent initialize response to client").await?;
    }

    Ok(())
}

async fn handle_response<S: AsyncStream>(
    id: String,
    content: Vec<u8>,
    state: Arc<Mutex<State>>,
    _sender: &Sender<send::Message>,
    writer: &mut WsWriter<S>,
    mut logger: Arc<Mutex<Logger>>,
) -> DynResult<()> {
    let mut state = state.lock().await;

    if let Some(request) = state.remove_net_req(&id) {
        logger
            .log(format!("request-method: {}", request.method().as_str()).as_str())
            .await?;

        match request.method().as_str() {
            "initialize" => {
                logger.log("Received initialize response from host").await?;
                let result = rpc::decode_result::<InitializeResponse>(&content)?;
                state.set_cwd_from_remote_projects_path(&result.project_dir_name);
                tokio::fs::create_dir_all(state.get_cwd()).await?;
                ppp::send::initialized(writer, logger).await?;
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
            logger
                .log("received initialized notification from client")
                .await?;
            let params = rpc::decode_params::<InitializedNotification>(&content)?;

            sender
                .send(send::Message::ClientInitialized(params.client_id.clone()))
                .await?;

            let cwd = state.lock().await.get_cwd();

            let home = dirs::home_dir().expect("home dir not found");

            let path_to_option = |path: PathBuf| -> Option<PathBuf> {
                if path.exists() {
                    Some(path.clone())
                } else {
                    None
                }
            };

            let custom_ignore = state.lock().await.get_ignore_file();
            let cwd_ignore = path_to_option(cwd.join(".graffitiignore"));
            let home_ignore = path_to_option(home.join(".graffitiignore"));
            let first_ignore = custom_ignore.or(cwd_ignore).or(home_ignore);

            let mut walker = &mut WalkBuilder::new(&cwd);

            if let Some(ignore) = first_ignore {
                walker = walker.add_custom_ignore_filename(ignore);
            }

            let dirs = walker
                .standard_filters(false)
                .skip_stdout(true)
                .build()
                .filter_map(Result::ok)
                .filter(|entry| entry.path() != cwd)
                .filter_map(|entry| {
                    entry
                        .into_path()
                        .strip_prefix(&cwd)
                        .ok()
                        .map(|p| p.to_path_buf())
                })
                .collect::<Vec<_>>();

            let mut page = 0;
            const PAGE_SIZE: usize = 16;

            loop {
                let batch = dirs
                    .iter()
                    .skip(PAGE_SIZE * page)
                    .take(PAGE_SIZE)
                    .collect::<Vec<_>>();

                logger.log(&format!("sending batch: {}", page)).await?;

                page += 1;

                if batch.is_empty() {
                    break;
                }

                let mut directories = Vec::new();

                for path in batch {
                    let (type_, content) = if path.is_dir() {
                        (DirectoryType::Directory, vec![])
                    } else {
                        (DirectoryType::File, tokio::fs::read(path).await?)
                    };

                    directories.push(Directory {
                        uri: path.to_path_buf(),
                        type_,
                        content,
                    });
                }

                ppp::send::directories_upload(
                    writer,
                    params.client_id.clone(),
                    directories,
                    logger.clone(),
                )
                .await?;
            }

            let state = state.lock().await;
            let location = state.get_my_location();

            if let Some(state::DocumentLocation { uri, .. }) = location {
                logger
                    .log(&format!("100 Sending initial file URI: {:?}", uri))
                    .await?;

                ppp::send::initial_file_uri(writer, uri.clone(), logger).await?;
            } else {
                logger.log("No initial file URI found").await?;
            }
        }
        "directories/upload" => {
            logger
                .log("Received directories/upload notification")
                .await?;

            let params = rpc::decode_params::<DirectoriesUploadNotification>(&content)?;

            logger.log("100").await?;

            let directories = params.directories;

            for dir in directories {
                logger.log(&format!("101 dir: {:?}", dir)).await?;
                let full_uri = state.lock().await.get_cwd().join(&dir.uri);
                logger.log(&format!("full_uri: {:?}", full_uri)).await?;

                match dir.type_ {
                    DirectoryType::Directory => {
                        logger.log("102").await?;
                        if !full_uri.exists() {
                            logger.log("103").await?;
                            tokio::fs::create_dir_all(&full_uri).await?;
                        }
                    }
                    DirectoryType::File => {
                        logger.log("104").await?;
                        if !full_uri.exists() {
                            logger.log("105").await?;
                            tokio::fs::create_dir_all(full_uri.parent().unwrap()).await?;
                        }

                        logger.log("106").await?;
                        let mut file = tokio::fs::File::create(&full_uri).await?;
                        logger.log("107").await?;
                        file.write_all(&dir.content).await?;
                        logger.log("108").await?;
                    }
                }
            }
        }
        "initial_file_uri" => {
            logger.log("Received initial_file_uri notification").await?;
            let params = rpc::decode_params::<InitialFileNotification>(&content)?;

            sender
                .send(send::Message::InitialFileUri { uri: params.uri })
                .await?;
        }
        "cursor_moved" => {
            let params = rpc::decode_params::<CursorMovedNotification>(&content)?;

            state
                .lock()
                .await
                .set_client_location(params.client_id.clone(), params.location.clone().into());

            sender
                .send(send::Message::CursorMoved {
                    client_id: params.client_id,
                    location: params.location,
                })
                .await?;
        }
        "document/edit" => {
            logger.log("Received document/edit notification").await?;
            let params = rpc::decode_params::<DocumentEditModeNotification>(&content)?;

            match params.mode {
                ppp::DocumentEditMode::Full => {
                    let params = rpc::decode_params::<DocumentEditFullNotification>(&content)?;
                    let client_id = params.client_id;
                    let uri = params.uri;
                    let content = params.content;

                    logger.log(&format!("uri: {:?}", uri)).await?;

                    let mut state = state.lock().await;

                    if let Some(true) = state.file_equals(&uri, &content) {
                        return Ok(());
                    }

                    state.set_file(uri.clone(), &content);

                    sender
                        .send(send::Message::DocumentEditedFull {
                            client_id,
                            uri,
                            content,
                        })
                        .await?;
                }
                ppp::DocumentEditMode::Incremental => {
                    todo!("incremental edits not implemented yet")
                }
            }
        }
        other => Err(format!("unknown method: {}", other))?,
    }

    Ok(())
}
