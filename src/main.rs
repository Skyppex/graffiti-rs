mod cli;
mod csp;
mod path_utils;
mod rpc;

use std::{
    error::Error,
    fs::File,
    io::{self, BufRead, BufReader, Read, Write},
    process,
};

use chrono::Local;
use csp::{InitializeResponse, Response};

use clap::Parser;
use cli::Cli;
use path_utils::get_path;

type DynResult<T> = Result<T, Box<dyn Error>>;

fn main() -> DynResult<()> {
    let cli = Cli::parse();

    let mut logger = get_logger(&cli)?;
    logger.log("Starting graffiti-rs")?;

    let stdin = io::stdin();
    let reader = stdin.lock();
    let mut scanner = BufReader::new(reader);

    let mut writer = io::stdout();

    let mut shutting_down = false;

    loop {
        match handle_input(&mut scanner, &mut writer, &mut logger) {
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
    logger: &mut Logger,
) -> DynResult<HandledMessage> {
    // Try to read headers
    match read_headers(scanner) {
        Ok(content_length) => {
            // Read exact content
            let mut buffer = vec![0; content_length];
            scanner.read_exact(&mut buffer)?;
            let message =
                String::from_utf8(buffer).map_err(|_| "Invalid UTF-8 in message content")?;

            process_message(&message, writer, logger)
        }
        Err(e) => Err(e),
    }
}

fn read_headers(scanner: &mut BufReader<impl Read>) -> DynResult<usize> {
    let mut content_length = None;

    // Read all headers
    loop {
        let mut line = String::new();
        scanner.read_line(&mut line)?;
        eprintln!("{}", &line);

        // Empty line (just \r\n) marks end of headers
        if line == "\r\n" {
            eprintln!("empty line");
            break;
        }

        eprintln!("found header");
        // Parse content-length if we find it
        if line.to_lowercase().starts_with("content-length: ") {
            content_length = Some(
                line[15..]
                    .trim()
                    .parse()
                    .map_err(|_| "Invalid content-length value")?,
            );
        }
    }

    eprintln!("content_length is {:?}", content_length);
    content_length.ok_or("No content-length header found".into())
}

fn process_message(
    message: &str,
    writer: &mut impl Write,
    logger: &mut Logger,
) -> DynResult<HandledMessage> {
    logger.log(message)?;

    let decoded = match rpc::decode(message) {
        Ok(d) => d,
        Err(err) => {
            logger.log(&err.to_string())?;
            return Ok(HandledMessage {
                shutdown_received: false,
                should_exit: false,
            });
        }
    };

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
    content: &[u8],
    writer: &mut dyn Write,
    _logger: &mut Logger,
) -> DynResult<HandledMessage> {
    match method {
        "initialize" => {
            let params = rpc::decode_params::<csp::InitializeRequest>(content)?;

            dbg!(params);

            let response = rpc::encode(Response::<InitializeResponse> {
                id,
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
            let params = rpc::decode_params::<csp::CursorMovedNotification>(content)?;

            dbg!(params);

            Ok(HandledMessage {
                should_exit: false,
                shutdown_received: false,
            })
        }
        "initialized" => Ok(HandledMessage {
            should_exit: false,
            shutdown_received: false,
        }),
        "shutdown" => Ok(HandledMessage {
            should_exit: false,
            shutdown_received: true,
        }),
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

pub struct Logger {
    writer: Option<Box<dyn Write>>,
}

impl Logger {
    fn empty() -> Logger {
        Logger { writer: None }
    }

    fn new(writer: Box<dyn Write>) -> Logger {
        Logger {
            writer: Some(writer),
        }
    }

    pub fn log(&mut self, message: &str) -> DynResult<()> {
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
        let decoded = rpc::decode(&String::from_utf8(message).expect("request is invalid utf-8"))
            .expect("invalid request");

        let id = decoded.id;
        let method = decoded.method;
        let content = decoded.content;

        let mut writer = Vec::new();
        let mut logger = Logger::empty();

        handle_message(id, &method, &content, &mut writer, &mut logger).unwrap();

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
                id: Some("1".to_string()),
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
        message
            .should()
            .be_equal_to(rpc::encode(expected).expect("Failed to encode"));
    }
}
