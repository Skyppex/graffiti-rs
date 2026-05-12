mod cli;
mod csp;
mod id;
mod log;
mod net;
mod path_utils;
mod ppp;
mod rpc;
mod state;

use std::{error::Error, process, sync::Arc};

use csp::{
    FingerprintGeneratedNotification, InitializeOptions, InitializeResponse, LocationRequest,
    Notification, Request, Response, ShutdownRequest, ShutdownResponse,
};

use clap::Parser;
use cli::{Cli, Commands};
use id::next_client_id;
use net::{run_client, run_host};
use state::State;
use tokio::{
    io::{self, AsyncRead, AsyncWrite, AsyncWriteExt, BufReader},
    sync::{
        mpsc::{self, Sender},
        Mutex,
    },
};
use tracing::info;

use crate::{id::next_request_id, net::send::Message};

type DynError = Box<dyn Error + Send + Sync>;
type DynResult<T> = Result<T, DynError>;

#[tokio::main]
async fn main() -> DynResult<()> {
    let cli = Cli::parse();

    log::init(cli.log_file.clone(), cli.log_to_stderr);

    info!("Starting graffiti-rs");

    let is_host = matches!(cli.command, Commands::Host { .. });

    let (send_to_main, mut receive_from_thread) = mpsc::channel::<net::send::Message>(8);
    let (send_to_thread, receive_from_main) = mpsc::channel::<net::receive::Message>(8);

    let cwd = std::env::current_dir()?;

    info!("Current working directory: {:?}", cwd);

    let next_client_id = next_client_id();

    info!("next_client_id = {}", next_client_id);

    let state = State::new(cwd, cli.graffitiignore, is_host, next_client_id);

    info!("my client id is {}", state.lock().await.client_id);

    let network_handle = match cli.command {
        Commands::Host { authorized_keys } => {
            info!("Starting host mode");
            tokio::spawn(run_host(
                state.clone(),
                send_to_main,
                receive_from_main,
                authorized_keys,
            ))
        }
        Commands::Connect { sha, client_key } => {
            info!("Starting client mode");
            tokio::spawn(run_client(
                sha,
                state.clone(),
                send_to_main,
                receive_from_main,
                client_key,
            ))
        }
    };

    let stdin = io::stdin();
    let mut scanner = BufReader::new(stdin);

    let mut writer = io::stdout();

    info!("Entering main message loop");

    let mut shutting_down = false;

    loop {
        tokio::select! {
            // Handle messages from the network thread
            Some(message) = receive_from_thread.recv() => {
                let result = handle_network_message(message, &mut writer, state.clone()).await?;

                if result.should_shutdown {
                    shutting_down = true;
                }
            }

            // Handle stdin
            Ok(HandledMessage {
                should_exit,
            }) = handle_input(&mut scanner, &mut writer, &send_to_thread, state.clone()) => {
                if should_exit {
                    break;
                }
            }

            else => {
                continue;
            }
        }

        info!("Finished select iteration");
    }

    match network_handle.await? {
        Ok(_) => {}
        Err(e) => {
            info!("Network thread exited with error: {}", e);
        }
    }

    if !shutting_down {
        info!("Exiting without shutdown message");
        process::exit(1);
    } else {
        info!("Exiting");
        process::exit(0);
    }
}

async fn handle_input(
    scanner: &mut BufReader<impl AsyncRead + Unpin>,
    writer: &mut (impl AsyncWrite + Unpin),
    sender: &Sender<net::receive::Message>,
    state: Arc<Mutex<State>>,
) -> DynResult<HandledMessage> {
    info!("Handling input from editor");
    let decoded = rpc::decode(scanner).await?;

    info!("Handling editor method: {}", decoded.method);

    info!("Content: {:?}", String::from_utf8(decoded.content.clone()));

    handle_message(
        decoded.id,
        &decoded.method,
        &decoded.content,
        writer,
        sender,
        state,
    )
    .await
}

async fn handle_message(
    id: Option<String>,
    method: &str,
    content: &[u8],
    writer: &mut (impl AsyncWrite + Unpin),
    sender: &Sender<net::receive::Message>,
    state: Arc<Mutex<State>>,
) -> DynResult<HandledMessage> {
    match method {
        "initialize" => {
            let params = rpc::decode_params::<csp::InitializeRequest>(content)?;

            let mut state = state.lock().await;

            if let Some(InitializeOptions {
                client_projects_root: Some(client_projects_root),
            }) = params.initialize_options
            {
                if state.is_client() {
                    state.set_cwd(client_projects_root);
                }
            }

            info!("Received initialize message from editor");

            let response = rpc::encode(Response::<InitializeResponse> {
                id: id.expect("Request ID is missing"),
                result: Some(InitializeResponse {
                    server_info: Some(csp::ServerInfo {
                        name: "graffiti-rs".to_string(),
                        version: Some("0.1.0".to_string()),
                    }),
                    client_id: state.client_id.clone(),
                }),
            })?;

            writer.write_all(&response).await?;

            Ok(HandledMessage { should_exit: false })
        }
        "move_cursor" => {
            info!("Received move_cursor message from editor");

            let params = rpc::decode_params::<csp::MoveCursorNotification>(content)?;

            if !params.location.exists() {
                return Ok(HandledMessage { should_exit: false });
            }

            state.lock().await.set_my_location(params.location.clone());

            sender
                .send(net::receive::Message::CursorMoved {
                    location: params.location.into(),
                })
                .await?;

            Ok(HandledMessage { should_exit: false })
        }
        "document/edit" => {
            info!("Received document/edit message from editor");

            let request = rpc::decode_params::<csp::DocumentEditModeNotification>(content)?;

            match request.mode {
                csp::DocumentEditMode::Full => {
                    let params = rpc::decode_params::<csp::DocumentEditFull>(content);

                    let params = params?;

                    let mut state = state.lock().await;

                    if let Ok(true) = tokio::fs::try_exists(state.get_cwd().join(&params.uri)).await
                    {
                        if let Some(true) = state.file_equals(&params.uri, &params.content) {
                            return Ok(HandledMessage { should_exit: false });
                        } else {
                            state.set_file(params.uri.clone(), &params.content);
                        }

                        sender
                            .send(net::receive::Message::DocumentEditFull {
                                uri: params.uri,
                                content: params.content,
                            })
                            .await?;
                    } else {
                        info!("153 File doesn't exist");
                    }
                }
                csp::DocumentEditMode::Incremental => {
                    todo!("154 incremental edits not implemented yet")
                }
            }

            Ok(HandledMessage { should_exit: false })
        }
        "initialized" => {
            info!("Received initialized message from editor");

            let request = rpc::encode(Request::<LocationRequest> {
                id: Some(next_request_id()),
                method: "document/location".into(),
                params: None,
            })?;

            writer.write_all(&request).await?;

            Ok(HandledMessage { should_exit: false })
        }
        "document/location" => {
            info!("Received document/location message from editor");

            let params = rpc::decode_params::<csp::LocationResponse>(content)?;
            info!("50 {:?}", params);

            state.lock().await.set_my_location(params.location);

            Ok(HandledMessage { should_exit: false })
        }
        "cwd_changed" => {
            info!("Received cwd_changed message from editor");

            Ok(HandledMessage { should_exit: false })
        }
        "request_fingerprint" => {
            info!("Received fingerprint message from editor");

            let response = rpc::encode(Response::<csp::FingerprintResponse> {
                id: id.expect("Request ID is missing"),
                result: Some(csp::FingerprintResponse {
                    fingerprint: state
                        .lock()
                        .await
                        .fingerprint
                        .clone()
                        .unwrap_or("No fingerprint".to_string()),
                }),
            })?;

            writer.write_all(&response).await?;

            Ok(HandledMessage { should_exit: false })
        }
        "shutdown" => {
            info!("Received shutdown message from editor");

            sender
                .send(net::receive::Message::Shutdown(
                    id.expect("Request ID is missing"),
                ))
                .await?;

            info!("Sent shutdown message through channel");

            Ok(HandledMessage { should_exit: false })
        }
        "exit" => {
            info!("Received shutdown message from editor");
            Ok(HandledMessage { should_exit: true })
        }
        _ => {
            info!("Received unknown message from editor");
            let response = rpc::encode("unknown method").unwrap();
            writer.write_all(&response).await.unwrap();
            writer.flush().await.unwrap();

            Ok(HandledMessage { should_exit: false })
        }
    }
}

async fn handle_network_message(
    message: Message,
    writer: &mut (impl AsyncWrite + Unpin),
    state: Arc<Mutex<State>>,
) -> DynResult<HandledNetworkMessage> {
    info!("Received from network: {}", message);

    match message {
        net::send::Message::Shutdown(Some(id)) => {
            let response = rpc::encode(Response::<ShutdownResponse> { id, result: None })?;

            info!("Sending shutdown response to editor");
            writer.write_all(&response).await?;
            info!("Sent shutdown response to editor");

            Ok(HandledNetworkMessage {
                should_shutdown: true,
            })
        }
        net::send::Message::Shutdown(None) => {
            let request = rpc::encode(Request::<ShutdownRequest> {
                id: None,
                method: "shutdown".into(),
                params: None,
            })?;

            info!("Sending shutdown request to editor");
            writer.write_all(&request).await?;
            info!("Sent shutdown request to editor");

            Ok(HandledNetworkMessage {
                should_shutdown: true,
            })
        }
        net::send::Message::Fingerprint(fingerprint) => {
            state.lock().await.set_fingerprint(fingerprint.clone());

            let notification = rpc::encode(Notification::<FingerprintGeneratedNotification> {
                method: "fingerprint_generated".into(),
                params: Some(FingerprintGeneratedNotification { fingerprint }),
            })?;

            writer.write_all(&notification).await?;

            Ok(HandledNetworkMessage {
                should_shutdown: false,
            })
        }
        net::send::Message::InitialFileUri { uri } => {
            info!(
                "200 Received initial file URI: {:?} CWD: {:?}",
                uri,
                state.lock().await.get_cwd()
            );

            let request = rpc::encode(Request::<csp::InitialFileUriRequest> {
                id: Some(next_request_id()),
                method: "initial_file_uri".into(),
                params: Some(csp::InitialFileUriRequest {
                    cwd: state.lock().await.get_cwd(),
                    initial_file_uri: uri,
                }),
            })?;

            writer.write_all(&request).await?;

            Ok(HandledNetworkMessage {
                should_shutdown: false,
            })
        }
        net::send::Message::ClientInitialized(client_id) => {
            let state = state.lock().await;

            if state.is_client() {
                info!("client initialized received on client: {}", client_id);
            }

            Ok(HandledNetworkMessage {
                should_shutdown: false,
            })
        }
        net::send::Message::Initialized(client_id) => {
            let state = state.lock().await;

            if state.is_client() {
                info!("initialized received on client: {}", client_id);

                let notification = rpc::encode(Notification::<csp::ClientIdChangedNotification> {
                    method: "client_id_changed".into(),
                    params: Some(csp::ClientIdChangedNotification { client_id }),
                })?;

                writer.write_all(&notification).await?;
            }

            Ok(HandledNetworkMessage {
                should_shutdown: false,
            })
        }
        net::send::Message::CursorMoved {
            client_id,
            location,
        } => {
            let notification = rpc::encode(Notification::<csp::CursorMovedNotification> {
                method: "cursor_moved".into(),
                params: Some(csp::CursorMovedNotification {
                    client_id,
                    location: location.into(),
                }),
            })?;

            writer.write_all(&notification).await?;

            Ok(HandledNetworkMessage {
                should_shutdown: false,
            })
        }
        net::send::Message::DocumentEditedFull {
            client_id,
            uri,
            content,
        } => {
            let uri = state.lock().await.get_cwd().join(uri);
            let notification = rpc::encode(Notification::<csp::DocumentEditedFull> {
                method: "document/edited".into(),
                params: Some(csp::DocumentEditedFull {
                    client_id,
                    mode: csp::DocumentEditMode::Full,
                    uri,
                    content,
                }),
            })?;

            writer.write_all(&notification).await?;

            Ok(HandledNetworkMessage {
                should_shutdown: false,
            })
        }
        _ => Ok(HandledNetworkMessage {
            should_shutdown: false,
        }),
    }
}

pub struct HandledMessage {
    should_exit: bool,
}

pub struct HandledNetworkMessage {
    should_shutdown: bool,
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::*;
    use fluid::prelude::*;

    use crate::{
        csp::{InitializeRequest, InitializeResponse, Request, Response},
        rpc,
    };

    async fn test_message(message: Vec<u8>) -> Vec<u8> {
        let mut reader = BufReader::new(&message[..]);
        let decoded = rpc::decode(&mut reader).await.expect("invalid request");

        let id = decoded.id;
        let method = decoded.method;
        let content = decoded.content;

        let mut writer = Vec::new();
        let (sender, _) = mpsc::channel(8);

        handle_message(
            id,
            &method,
            &content,
            &mut writer,
            &sender,
            State::new(PathBuf::new(), None, true, next_client_id()),
        )
        .await
        .unwrap();

        writer
    }

    #[tokio::test]
    async fn handle_initialize() {
        // arrange
        let initialize = Request::<InitializeRequest> {
            id: Some("1".into()),
            method: "initialize".into(),
            params: Some(InitializeRequest {
                process_id: Some(123),
                editor_info: Some(crate::csp::EditorInfo {
                    name: "test-client".to_string(),
                    version: Some("0.1.0".to_string()),
                }),
                root_path: Some(".".to_string()),
                initialize_options: None,
            }),
        };

        // act
        let response = test_message(rpc::encode(initialize).expect("Failed to encode")).await;

        // assert
        assert_message_eq(
            response,
            Response::<InitializeResponse> {
                id: "1".into(),
                result: Some(InitializeResponse {
                    client_id: "0".to_string(),
                    server_info: Some(crate::csp::ServerInfo {
                        name: "graffiti-rs".to_string(),
                        version: Some("0.1.0".to_string()),
                    }),
                }),
            },
        )
    }

    fn assert_message_eq<T: serde::Serialize>(message: Vec<u8>, expected: T) {
        let mut bytes = rpc::encode(expected).expect("Failed to encode");
        bytes.push(b'\n');
        message.should().be_equal_to(bytes);
    }
}
