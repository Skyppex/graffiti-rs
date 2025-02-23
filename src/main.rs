mod cli;
mod csp;
mod net;
mod path_utils;
mod rpc;

use std::{
    error::Error,
    io::{self, BufReader, Read, Write},
    process,
    sync::{Arc, Mutex},
};

use chrono::Local;
use csp::{InitializeResponse, Response, ShutdownResponse};

use clap::Parser;
use cli::{Cli, Commands};
use net::{run_client, run_host};

type DynResult<T> = Result<T, Box<dyn Error + Send + Sync>>;

#[tokio::main]
async fn main() -> DynResult<()> {
    let cli = Cli::parse();

    let mut logger = Arc::new(Mutex::new(get_logger(&cli)?));
    logger.log("Starting graffiti-rs")?;

    let network_handle = match cli.command {
        Commands::Host => {
            logger.log("Starting host mode")?;
            tokio::spawn(run_host(logger.clone()))
        }
        Commands::Connect => {
            logger.log("Starting client mode")?;
            tokio::spawn(run_client(logger.clone()))
        }
    };

    let stdin = io::stdin();
    let reader = stdin.lock();
    let mut scanner = BufReader::new(reader);

    let mut writer = io::stdout();

    let mut shutting_down = false;

    loop {
        match handle_input(&mut scanner, &mut writer, logger.clone()) {
            Ok(HandledMessage {
                shutdown_received,
                should_exit,
            }) => {
                if shutdown_received {
                    shutting_down = true;
                }

                if should_exit {
                    break;
                }
            }
            Err(err) => {
                logger.log(&err.to_string())?;
            }
        }
    }

    network_handle.abort();

    if !shutting_down {
        logger.log("Exiting without shutdown message")?;
        process::exit(1);
    } else {
        process::exit(0);
    }
}

fn handle_input(
    scanner: &mut BufReader<impl Read>,
    writer: &mut impl Write,
    logger: Arc<Mutex<Logger>>,
) -> DynResult<HandledMessage> {
    let decoded = rpc::decode(scanner)?;

    handle_message(
        decoded.id,
        &decoded.method,
        &decoded.content,
        writer,
        logger,
    )
}

fn handle_message(
    id: Option<String>,
    method: &str,
    _content: &[u8],
    writer: &mut impl Write,
    _logger: Arc<Mutex<Logger>>,
) -> DynResult<HandledMessage> {
    match method {
        "initialize" => {
            // let params = rpc::decode_params::<csp::InitializeRequest>(content)?;

            let response = rpc::encode(Response::<InitializeResponse> {
                id: id.expect("Request ID is missing"),
                result: Some(InitializeResponse {
                    server_info: Some(csp::ServerInfo {
                        name: "graffiti-rs".to_string(),
                        version: Some("0.1.0".to_string()),
                    }),
                }),
            })?;

            writer.write_all(&response)?;
            writeln!(writer)?;

            Ok(HandledMessage {
                should_exit: false,
                shutdown_received: false,
            })
        }
        "cursor_moved" => {
            // let params = rpc::decode_params::<csp::CursorMovedNotification>(content)?;

            Ok(HandledMessage {
                should_exit: false,
                shutdown_received: false,
            })
        }
        "initialized" => Ok(HandledMessage {
            should_exit: false,
            shutdown_received: false,
        }),
        "shutdown" => {
            let response = rpc::encode(Response::<ShutdownResponse> {
                id: id.expect("Request ID is missing"),
                result: None,
            })?;

            writer.write_all(&response)?;
            writeln!(writer)?;

            Ok(HandledMessage {
                should_exit: false,
                shutdown_received: true,
            })
        }
        "exit" => Ok(HandledMessage {
            should_exit: true,
            shutdown_received: false,
        }),
        _ => {
            let response = rpc::encode("unknown method").unwrap();
            writer.write_all(&response).unwrap();
            writer.flush().unwrap();

            Ok(HandledMessage {
                should_exit: false,
                shutdown_received: false,
            })
        }
    }
}

fn get_logger(cli: &Cli) -> DynResult<Logger> {
    if cli.log_to_stderr {
        return Ok(Logger::new(Box::new(io::stderr())));
    }

    if let Some(log_file) = &cli.log_file {
        let file = std::fs::File::create(log_file)?;
        return Ok(Logger::new(Box::new(file)));
    }

    Ok(Logger::empty())
}

pub trait Log {
    fn log(&mut self, message: &str) -> DynResult<()>;
}

pub struct Logger {
    writer: Option<Box<dyn Write + Send>>,
}

impl Logger {
    fn empty() -> Logger {
        Logger { writer: None }
    }

    fn new(writer: Box<dyn Write + Send>) -> Logger {
        Logger {
            writer: Some(writer),
        }
    }
}

impl Log for Logger {
    fn log(&mut self, message: &str) -> DynResult<()> {
        if let Some(ref mut writer) = self.writer {
            return writeln!(
                writer,
                "[{}] {}",
                Local::now().format("%Y-%m-%d %H:%M:%S%.3f"),
                message
            )
            .map_err(|e| e.into());
        }

        Ok(())
    }
}

impl Log for Arc<Mutex<Logger>> {
    fn log(&mut self, message: &str) -> DynResult<()> {
        self.lock().unwrap().log(message)
    }
}

pub struct HandledMessage {
    should_exit: bool,
    shutdown_received: bool,
}

#[cfg(test)]
mod tests {
    use super::*;
    use fluid::prelude::*;

    use crate::{
        csp::{InitializeRequest, InitializeResponse, Request, Response},
        rpc, Logger,
    };

    fn test_message(message: Vec<u8>) -> Vec<u8> {
        let mut reader = BufReader::new(&message[..]);
        let decoded = rpc::decode(&mut reader).expect("invalid request");

        let id = decoded.id;
        let method = decoded.method;
        let content = decoded.content;

        let mut writer = Vec::new();
        let logger = Arc::new(Mutex::new(Logger::empty()));

        handle_message(id, &method, &content, &mut writer, logger).unwrap();

        writer
    }

    #[test]
    fn handle_initialize() {
        // arrange
        let initialize = Request::<InitializeRequest> {
            id: Some("1".to_string()),
            method: "initialize".to_string(),
            params: Some(InitializeRequest {
                process_id: Some(123),
                client_info: Some(crate::csp::ClientInfo {
                    name: "test-client".to_string(),
                    version: Some("0.1.0".to_string()),
                }),
                root_path: Some(".".to_string()),
            }),
        };

        // act
        let response = test_message(rpc::encode(initialize).expect("Failed to encode"));

        // assert
        assert_message_eq(
            response,
            Response::<InitializeResponse> {
                id: "1".to_string(),
                result: Some(InitializeResponse {
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
