mod cli;
mod csp;
mod net;
mod path_utils;
mod ppp;
mod rpc;
mod state;
mod utils;

use std::{error::Error, process, sync::Arc};

use chrono::Local;
use csp::{
    FingerprintGeneratedNotification, InitializeOptions, InitializeResponse, LocationRequest,
    Notification, Request, Response, ShutdownRequest, ShutdownResponse,
};

use clap::Parser;
use cli::{Cli, Commands};
use net::{run_client, run_host};
use state::State;
use tokio::{
    io::{self, AsyncRead, AsyncWrite, AsyncWriteExt, BufReader},
    sync::{
        mpsc::{self, Sender},
        Mutex,
    },
};
use utils::generate_id;

type DynError = Box<dyn Error + Send + Sync>;
type DynResult<T> = Result<T, DynError>;

#[tokio::main]
async fn main() -> DynResult<()> {
    let cli = Cli::parse();

    let mut logger = Arc::new(Mutex::new(get_logger(&cli).await?));
    logger.log("Starting graffiti-rs").await?;

    let is_host = matches!(cli.command, Commands::Host);

    let (send_to_main, mut receive_from_thread) = mpsc::channel::<net::send::Message>(8);
    let (send_to_thread, receive_from_main) = mpsc::channel::<net::receive::Message>(8);

    let cwd = std::env::current_dir()?;

    logger
        .log(format!("Current working directory: {:?}", cwd).as_str())
        .await?;

    let state = State::new(cwd, cli.graffitiignore, is_host, "0".into());

    let network_handle = match cli.command {
        Commands::Host => {
            logger.log("Starting host mode").await?;
            tokio::spawn(run_host(
                state.clone(),
                send_to_main,
                receive_from_main,
                logger.clone(),
            ))
        }
        Commands::Connect { sha } => {
            logger.log("Starting client mode").await?;
            tokio::spawn(run_client(
                sha,
                state.clone(),
                send_to_main,
                receive_from_main,
                logger.clone(),
            ))
        }
    };

    let stdin = io::stdin();
    let mut scanner = BufReader::new(stdin);

    let mut writer = io::stdout();

    logger.log("Entering main message loop").await?;

    let mut shutting_down = false;

    loop {
        tokio::select! {
            // Handle messages from the network thread
            Some(message) = {
                logger.log("Waiting for message from network").await?;
                receive_from_thread.recv()
            } => {
                logger.log(&format!("Received from network: {}", message)).await?;
                // Handle the message here
                // You might want to send responses back using send_thread
                match message {
                    net::send::Message::Shutdown(Some(id)) => {
                        let response = rpc::encode(Response::<ShutdownResponse> {
                            id,
                            result: None,
                        })?;

                        logger.log("Sending shutdown response to editor").await?;
                        writer.write_all(&response).await?;
                        logger.log("Sent shutdown response to editor").await?;
                        shutting_down = true;
                    }
                    net::send::Message::Shutdown(None) => {
                        let request = rpc::encode(Request::<ShutdownRequest> {
                            id: None,
                            method: "shutdown".into(),
                            params: None,
                        })?;

                        logger.log("Sending shutdown request to editor").await?;
                        writer.write_all(&request).await?;
                        logger.log("Sent shutdown request to editor").await?;
                        shutting_down = true;
                    }
                    net::send::Message::Fingerprint(fingerprint) => {
                        state.lock().await.set_fingerprint(fingerprint.clone());

                        let notification = rpc::encode(Notification::<FingerprintGeneratedNotification> {
                            method: "fingerprint_generated".into(),
                            params: Some(FingerprintGeneratedNotification {
                                fingerprint,
                            }),
                        })?;

                        writer.write_all(&notification).await?;
                    }
                    net::send::Message::InitialFileUri { uri } => {
                        logger.log(&format!("200 Received initial file URI: {:?} CWD: {:?}", uri, state.lock().await.get_cwd())).await?;

                        let request = rpc::encode(Request::<csp::InitialFileUriRequest> {
                            id: Some(generate_id()),
                            method: "initial_file_uri".into(),
                            params: Some(csp::InitialFileUriRequest {
                                cwd: state.lock().await.get_cwd(),
                                initial_file_uri: uri,
                            }),
                        })?;

                        writer.write_all(&request).await?;
                    }
                    net::send::Message::ClientInitialized(client_id) => {
                        let state = state.lock().await;

                        if state.is_client() {
                            logger.log(&format!("client initialized received on client: {}", client_id)).await?;
                            continue;
                        }
                    }
                    net::send::Message::CursorMoved { client_id, location } => {
                        let notification = rpc::encode(Notification::<csp::CursorMovedNotification> {
                            method: "cursor_moved".into(),
                            params: Some(csp::CursorMovedNotification {
                                client_id,
                                location: location.into(),
                            }),
                        })?;

                        writer.write_all(&notification).await?;
                    }
                    net::send::Message::DocumentEditedFull { client_id, uri, content } => {
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
                    }
                    _ => {}
                }
            }

            // Handle stdin
            Ok(HandledMessage {
                should_exit,
            }) = {
                logger.log("Waiting for input from editor").await?;
                handle_input(&mut scanner, &mut writer, &send_to_thread, state.clone(), logger.clone())
            } => {
                logger.log("Handled input").await?;

                if should_exit {
                    break;
                }
            }

            else => {
                // Just restart the loop so we stay responsive to new messages
                continue; // continue to avoid log
            }
        }

        logger.log("Finished select iteration").await?;
    }

    match network_handle.await? {
        Ok(_) => {}
        Err(e) => {
            logger
                .log(&format!("Network thread exited with error: {}", e))
                .await?;
        }
    }

    if !shutting_down {
        logger.log("Exiting without shutdown message").await?;
        process::exit(1);
    } else {
        logger.log("Exiting").await?;
        process::exit(0);
    }
}

async fn handle_input(
    scanner: &mut BufReader<impl AsyncRead + Unpin>,
    writer: &mut (impl AsyncWrite + Unpin),
    sender: &Sender<net::receive::Message>,
    state: Arc<Mutex<State>>,
    mut logger: Arc<Mutex<Logger>>,
) -> DynResult<HandledMessage> {
    logger.log("Handling input from editor").await?;
    let decoded = rpc::decode(scanner).await?;

    logger
        .log(format!("Handling method: {}", decoded.method).as_str())
        .await?;

    logger
        .log(format!("Content: {:?}", String::from_utf8(decoded.content.clone())).as_str())
        .await?;

    handle_message(
        decoded.id,
        &decoded.method,
        &decoded.content,
        writer,
        sender,
        state,
        logger,
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
    mut logger: Arc<Mutex<Logger>>,
) -> DynResult<HandledMessage> {
    match method {
        "initialize" => {
            let params = rpc::decode_params::<csp::InitializeRequest>(content)?;

            let mut state = state.lock().await;

            if let Some(InitializeOptions {
                client_projects_root: Some(client_projects_root),
            }) = &params.initialize_options
            {
                if state.is_client() {
                    state.set_cwd(client_projects_root);
                }
            }

            logger
                .log("Received initialize message from editor")
                .await?;

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
            logger
                .log("Received move_cursor message from editor")
                .await?;

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
            logger
                .log("Received document/edit message from editor")
                .await?;

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
                        logger.log("153 File doesn't exist").await?;
                    }
                }
                csp::DocumentEditMode::Incremental => {
                    todo!("154 incremental edits not implemented yet")
                }
            }

            Ok(HandledMessage { should_exit: false })
        }
        "initialized" => {
            logger
                .log("Received initialized message from editor")
                .await?;

            let request = rpc::encode(Request::<LocationRequest> {
                id: Some(generate_id()),
                method: "document/location".into(),
                params: None,
            })?;

            writer.write_all(&request).await?;

            Ok(HandledMessage { should_exit: false })
        }
        "document/location" => {
            logger
                .log("Received document/location message from editor")
                .await?;

            let params = rpc::decode_params::<csp::LocationResponse>(content)?;
            logger.log(&format!("50 {:?}", params)).await?;

            state.lock().await.set_my_location(params.location);

            Ok(HandledMessage { should_exit: false })
        }
        "cwd_changed" => {
            logger
                .log("Received cwd_changed message from editor")
                .await?;

            Ok(HandledMessage { should_exit: false })
        }
        "request_fingerprint" => {
            logger
                .log("Received fingerprint message from editor")
                .await?;

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
            logger.log("Received shutdown message from editor").await?;

            sender
                .send(net::receive::Message::Shutdown(
                    id.expect("Request ID is missing"),
                ))
                .await?;

            logger.log("Sent shutdown message through channel").await?;

            Ok(HandledMessage { should_exit: false })
        }
        "exit" => {
            logger.log("Received shutdown message from editor").await?;
            Ok(HandledMessage { should_exit: true })
        }
        _ => {
            logger.log("Received unknown message from editor").await?;
            let response = rpc::encode("unknown method").unwrap();
            writer.write_all(&response).await.unwrap();
            writer.flush().await.unwrap();

            Ok(HandledMessage { should_exit: false })
        }
    }
}

async fn get_logger(cli: &Cli) -> DynResult<Logger> {
    if cli.log_to_stderr {
        return Ok(Logger::new(Box::new(io::stderr())));
    }

    if let Some(log_file) = &cli.log_file {
        let file = tokio::fs::File::create(log_file).await?;
        return Ok(Logger::new(Box::new(file)));
    }

    Ok(Logger::empty())
}

pub trait Log {
    fn log(&mut self, message: &str) -> impl std::future::Future<Output = DynResult<()>>;
}

pub struct Logger {
    writer: Option<Box<dyn AsyncWrite + Unpin + Send>>,
}

impl Logger {
    fn empty() -> Logger {
        Logger { writer: None }
    }

    fn new(writer: Box<dyn AsyncWrite + Unpin + Send>) -> Logger {
        Logger {
            writer: Some(writer),
        }
    }
}

impl Log for Logger {
    async fn log(&mut self, message: &str) -> DynResult<()> {
        if let Some(ref mut writer) = self.writer {
            writer
                .write_all(
                    format!(
                        "[{}] {}\n",
                        Local::now().format("%Y-%m-%d %H:%M:%S%.3f"),
                        message
                    )
                    .as_bytes(),
                )
                .await?;
        }

        Ok(())
    }
}

impl Log for Arc<Mutex<Logger>> {
    async fn log(&mut self, message: &str) -> DynResult<()> {
        self.lock().await.log(message).await
    }
}

pub struct HandledMessage {
    should_exit: bool,
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::*;
    use fluid::prelude::*;

    use crate::{
        csp::{InitializeRequest, InitializeResponse, Request, Response},
        rpc, Logger,
    };

    async fn test_message(message: Vec<u8>) -> Vec<u8> {
        let mut reader = BufReader::new(&message[..]);
        let decoded = rpc::decode(&mut reader).await.expect("invalid request");

        let id = decoded.id;
        let method = decoded.method;
        let content = decoded.content;

        let mut writer = Vec::new();
        let (sender, _) = mpsc::channel(8);
        let logger = Arc::new(Mutex::new(Logger::empty()));

        handle_message(
            id,
            &method,
            &content,
            &mut writer,
            &sender,
            State::new(PathBuf::new(), None, true, "0".into()),
            logger,
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
