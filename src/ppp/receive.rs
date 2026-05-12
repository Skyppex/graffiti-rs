use futures_util::TryFutureExt;
use ignore::WalkBuilder;
use std::{path::PathBuf, sync::Arc};
use tokio::{
    io::AsyncWriteExt,
    sync::{mpsc::Sender, Mutex},
};
use tracing::info;

use crate::{
    net::{
        connection::{ConnectionWriter, Message},
        send,
    },
    ppp::{self, DirectoriesUploadNotification, Directory, DirectoryType},
    rpc,
    state::{self, State},
    DynResult,
};

use super::{
    CursorMovedNotification, DocumentEditFullNotification, DocumentEditModeNotification,
    InitialFileNotification, InitializeResponse, InitializedNotification,
};

pub async fn handle_message(
    msg: Message,
    state: Arc<Mutex<State>>,
    writer: &mut ConnectionWriter,
    sender: &Sender<send::Message>,
) -> DynResult<()> {
    if let Message::Data(data) = msg {
        info!("Received network message");
        info!("data: {:?}", &data);

        let decoded = rpc::decode_message(&data).await;

        info!("{:?}", decoded);

        let decoded = decoded?;

        let id = decoded.id;
        let method = decoded.method;

        info!("Method: {:?}", method);

        match (id, method) {
            (Some(id), Some(method)) => {
                handle_request(id, &method, decoded.content, state, writer).await?
            }
            (Some(id), None) => handle_response(id, decoded.content, state, sender, writer).await?,
            (None, Some(method)) => {
                handle_notification(&method, decoded.content, state, sender, writer).await?
            }
            _ => Err("Id and/or method is required for a message")?,
        }
    }

    Ok(())
}

async fn handle_request(
    id: String,
    method: &str,
    _content: Vec<u8>,
    state: Arc<Mutex<State>>,
    writer: &mut ConnectionWriter,
) -> DynResult<()> {
    if method == "initialize" {
        info!("received initialize request from client");

        ppp::send::initialize_response(id, state, writer).await?;
    }

    Ok(())
}

async fn handle_response(
    id: String,
    content: Vec<u8>,
    state: Arc<Mutex<State>>,
    sender: &Sender<send::Message>,
    writer: &mut ConnectionWriter,
) -> DynResult<()> {
    let mut state = state.lock().await;

    if let Some(request) = state.remove_net_req(&id) {
        info!("request-method: {}", request.method());

        match request.method().as_str() {
            "initialize" => {
                info!("Received initialize response from host");
                let result = rpc::decode_result::<InitializeResponse>(&content)?;
                let new_cwd = state.get_cwd_from_remote_projects_path(&result.project_dir_name);

                info!("moving to directory: {}", new_cwd.to_string_lossy());

                tokio::fs::create_dir_all(&new_cwd).await?;
                state.set_cwd(new_cwd);
                state.set_client_id(result.client_id);

                info!("my client id is {}", state.client_id);

                tokio::try_join!(
                    sender
                        .send(send::Message::Initialized(state.client_id.clone()))
                        .map_err(|e| e.into()),
                    ppp::send::initialized(writer)
                )?;
            }
            other => Err(format!("unknown method: {}", other))?,
        }
    }

    Ok(())
}

async fn handle_notification(
    method: &str,
    content: Vec<u8>,
    state: Arc<Mutex<State>>,
    sender: &Sender<send::Message>,
    writer: &mut ConnectionWriter,
) -> DynResult<()> {
    match method {
        "initialized" => {
            info!("received initialized notification from client");
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

                info!("sending batch: {}", page);

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

                ppp::send::directories_upload(writer, params.client_id.clone(), directories)
                    .await?;
            }

            let state = state.lock().await;
            let location = state.get_my_location();

            if let Some(state::DocumentLocation { uri, .. }) = location {
                info!("100 Sending initial file URI: {:?}", uri);

                ppp::send::initial_file_uri(writer, uri.clone()).await?;
            } else {
                info!("No initial file URI found");
            }
        }
        "directories/upload" => {
            info!("Received directories/upload notification");

            let params = rpc::decode_params::<DirectoriesUploadNotification>(&content)?;

            let directories = params.directories;

            for dir in directories {
                let full_uri = state.lock().await.get_cwd().join(&dir.uri);

                match dir.type_ {
                    DirectoryType::Directory => {
                        if !full_uri.exists() {
                            tokio::fs::create_dir_all(&full_uri).await?;
                        }
                    }
                    DirectoryType::File => {
                        if !full_uri.exists() {
                            tokio::fs::create_dir_all(full_uri.parent().unwrap()).await?;
                        }

                        let mut file = tokio::fs::File::create(&full_uri).await?;
                        file.write_all(&dir.content).await?;
                    }
                }
            }
        }
        "initial_file_uri" => {
            info!("Received initial_file_uri notification");
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
            info!("Received document/edit notification");
            let params = rpc::decode_params::<DocumentEditModeNotification>(&content)?;

            match params.mode {
                ppp::DocumentEditMode::Full => {
                    let params = rpc::decode_params::<DocumentEditFullNotification>(&content)?;
                    let client_id = params.client_id;
                    let uri = params.uri;
                    let content = params.content;

                    info!("uri: {:?}", uri);

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
