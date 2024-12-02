mod cli;
mod rpc;

use std::{
    error::Error,
    io::{self, BufRead, BufReader, Write},
    process,
};

use clap::Parser;
use cli::Cli;

fn main() -> Result<(), Box<dyn Error>> {
    let cli = Cli::parse();

    let mut logger = get_logger(&cli)?;
    logger.log("Starting proof")?;

    let stdin = io::stdin();
    let reader = stdin.lock();
    let scanner = BufReader::new(reader);

    let writer = io::stdout();

    let mut shutting_down = false;

    for line in scanner.lines() {
        match line {
            Ok(bytes) => {
                let decoded = rpc::decode(&bytes);

                if let Err(err) = decoded {
                    logger.log(&err.to_string())?;
                    continue;
                }

                let decoded = decoded.unwrap();
                let method = decoded.method;
                let content = decoded.content;

                let (should_exit, shutdown_received) =
                    handle_message(&method, &content, &writer, &mut logger);

                if should_exit {
                    break;
                }

                if shutdown_received {
                    shutting_down = true;
                }
            }
            Err(err) => {
                logger.log(&err.to_string())?;
                continue;
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

fn handle_message(
    _method: &str,
    _content: &[u8],
    _writer: &dyn Write,
    _logger: &mut Logger,
) -> (bool, bool) {
    (false, false)
}

fn get_logger(cli: &Cli) -> Result<Logger, Box<dyn Error>> {
    match &cli.log_file {
        None => Ok(Logger::empty()),
        Some(log_file) => {
            let file = std::fs::File::create(log_file)?;
            Ok(Logger::new(Box::new(file)))
        }
    }
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

    pub fn log(&mut self, message: &str) -> Result<(), Box<dyn Error>> {
        if let Some(ref mut writer) = self.writer {
            return write!(writer, "[{:?}] {}", std::time::SystemTime::now(), message)
                .map_err(|e| e.into());
        }

        Ok(())
    }
}
