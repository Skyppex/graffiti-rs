use std::sync::LazyLock;

use chrono::Local;
use clap::Parser;
use tokio::io::{AsyncWrite, AsyncWriteExt};

static LOGGER: LazyLock<Logger, fn() -> Logger> = LazyLock::new(init_logger);

fn init_logger() -> Logger {
    let runtime = tokio::runtime::Handle::current();
    let cli = crate::cli::Cli::parse();
    let (sender, receiver) = tokio::sync::mpsc::channel(1024);

    let writer: Option<Box<dyn AsyncWrite + Send + Unpin>> =
        match (&cli.log_to_stderr, &cli.log_file) {
            (true, _) => Some(Box::new(tokio::io::stderr())),
            (_, Some(log_file)) => {
                let file = runtime.block_on(tokio::fs::File::create(log_file));
                match file {
                    Ok(f) => Some(Box::new(f) as Box<dyn AsyncWrite + Send + Unpin>),
                    Err(_) => None,
                }
            }
            _ => None,
        };

    runtime.spawn(async_logger(receiver, writer));

    Logger { sender }
}

async fn async_logger(
    mut receiver: tokio::sync::mpsc::Receiver<String>,
    mut writer: Option<Box<dyn AsyncWrite + Send + Unpin>>,
) {
    while let Some(msg) = receiver.recv().await {
        if let Some(ref mut w) = writer {
            let _ = w.write_all(msg.as_bytes()).await;
        }
    }
}

pub struct Logger {
    sender: tokio::sync::mpsc::Sender<String>,
}

impl Logger {
    pub fn log(message: &str) {
        let logger = &LOGGER;
        let _ = logger.sender.try_send(format!(
            "[{}] {}\n",
            Local::now().format("%Y-%m-%d %H:%M:%S%.3f"),
            message
        ));
    }
}
