use std::io;
use std::path::PathBuf;
use std::sync::Mutex;
use std::{fs::OpenOptions, io::IsTerminal};
use tracing::level_filters::LevelFilter;
use tracing_subscriber::{fmt, layer::SubscriberExt, util::SubscriberInitExt, EnvFilter, Layer};

use crate::cli::Cli;

pub struct LoggingConfig {
    log_file: Option<PathBuf>,
    log_to_stderr: bool,
    log_level: LevelFilter,
    log_filter: Option<String>,
}

impl From<&Cli> for LoggingConfig {
    fn from(cli: &Cli) -> Self {
        LoggingConfig {
            log_file: cli.log_file.clone(),
            log_to_stderr: cli.log_to_stderr,
            log_level: cli.log_level,
            log_filter: cli.log_filter.clone(),
        }
    }
}

pub fn init(config: LoggingConfig) {
    // imported crates stay at warn; our own logs follow --log-level. RUST_LOG,
    // if set, replaces those defaults, and --log-filter directives are applied
    // on top of either — later directives win for the same target.
    let mut directives = std::env::var("RUST_LOG")
        .unwrap_or_else(|_| format!("warn,graffiti_rs={}", config.log_level));

    if let Some(log_filter) = config.log_filter {
        directives = format!("{directives},{log_filter}");
    }

    let filter = EnvFilter::try_new(&directives)
        .unwrap_or_else(|e| panic!("invalid log filter '{directives}': {e}"));

    let layer: Box<dyn Layer<_> + Send + Sync> = if let Some(path) = config.log_file {
        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)
            .expect("Failed to open log file");
        fmt::layer()
            .with_writer(Mutex::new(file))
            .with_ansi(true)
            .boxed()
    } else if config.log_to_stderr {
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
