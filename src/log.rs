use std::io;
use std::path::PathBuf;
use std::sync::Mutex;
use std::{fs::OpenOptions, io::IsTerminal};
use tracing_subscriber::{fmt, layer::SubscriberExt, util::SubscriberInitExt, EnvFilter, Layer};

pub fn init(log_file: Option<PathBuf>, log_to_stderr: bool) {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("debug"));

    let layer: Box<dyn Layer<_> + Send + Sync> = if let Some(path) = log_file {
        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)
            .expect("Failed to open log file");
        fmt::layer()
            .with_writer(Mutex::new(file))
            .with_ansi(true)
            .boxed()
    } else if log_to_stderr {
        fmt::layer()
            .with_writer(io::stderr)
            .with_ansi(io::stderr().is_terminal())
            .boxed()
    } else {
        fmt::layer().with_writer(io::sink).boxed()
    };

    tracing_subscriber::registry()
        .with(filter)
        .with(layer)
        .init();
}
